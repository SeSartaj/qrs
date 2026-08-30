"""DRF API views for QRS Enterprise.

The views are **synchronous** so DRF's built-in authentication (Token /
Session) works correctly. The async service layer is invoked via
``asgiref.sync.async_to_sync`` at the call boundary.
"""
from __future__ import annotations

from asgiref.sync import async_to_sync
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import ApiKey, AuditLog, ManagedTcert, SdocRecord, TcertGrant
from .permissions import (
    CanBlockSdoc,
    CanRevokeTcert,
    CanSignTcert,
    CanUnblockSdoc,
    IsAdmin,
    _is_admin,
)
from .serializers import (
    ApiKeyCreateSerializer,
    ApiKeySerializer,
    AuditLogSerializer,
    AttestSerializer,
    BlockSerializer,
    CreateTcertSerializer,
    GrantCreateSerializer,
    GrantSerializer,
    ManagedTcertSerializer,
    RevokeSerializer,
    SdocRecordSerializer,
    SignSdocSerializer,
    UserSerializer,
)
from .services import EnterpriseService, QrsEnterpriseError

User = get_user_model()


def _client_ip(request) -> str | None:
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def _run(coro_func, *args, **kwargs):
    """Run an async service method synchronously from a sync view."""
    return async_to_sync(coro_func)(*args, **kwargs)


def _render_qr_png(payload: str) -> str:
    """Render a QR code for ``payload`` and return it as a base64 PNG."""
    import base64
    import io

    import qrcode

    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
@authentication_classes([TokenAuthentication])
def login_view(request):
    username = request.data.get("username")
    password = request.data.get("password")
    user = User.objects.filter(username=username).first()
    if user is None or not user.check_password(password) or not user.is_active:
        return Response({"detail": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
    token, _ = Token.objects.get_or_create(user=user)
    return Response({"token": token.key, "user": UserSerializer(user).data})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_view(request):
    Token.objects.filter(user=request.user).delete()
    return Response({"detail": "Logged out"})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def me_view(request):
    return Response(UserSerializer(request.user).data)


# ---------------------------------------------------------------------------
# TCerts
# ---------------------------------------------------------------------------
class TcertListCreateView(APIView):
    """List TCerts (visible to the user) and create a new one (admin only)."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        if IsAdmin().has_permission(request, self):
            tcerts = ManagedTcert.objects.all()
        else:
            granted = TcertGrant.objects.filter(user=request.user).values_list("tcert_id", flat=True)
            tcerts = ManagedTcert.objects.filter(id__in=granted)
        return Response(ManagedTcertSerializer(tcerts, many=True).data)

    def post(self, request):
        if not IsAdmin().has_permission(request, self):
            return Response({"detail": "Admin required"}, status=status.HTTP_403_FORBIDDEN)
        serializer = CreateTcertSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        svc = EnterpriseService()
        try:
            tcert = _run(
                svc.create_tcert_with_audit,
                user=request.user,
                ip_address=_client_ip(request),
                **serializer.validated_data,
            )
        except QrsEnterpriseError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(ManagedTcertSerializer(tcert).data, status=status.HTTP_201_CREATED)


class TcertDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        try:
            return ManagedTcert.objects.get(pk=pk)
        except ManagedTcert.DoesNotExist:
            return None

    def get(self, request, pk):
        tcert = self.get_object(pk)
        if tcert is None:
            return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(ManagedTcertSerializer(tcert).data)


class TcertGrantView(APIView):
    """Manage grants (who may sign with a TCert). Admin only."""

    permission_classes = [IsAdmin]

    def get(self, request, pk):
        tcert = ManagedTcert.objects.filter(pk=pk).first()
        if tcert is None:
            return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        grants = TcertGrant.objects.filter(tcert=tcert)
        return Response(GrantSerializer(grants, many=True).data)

    def post(self, request, pk):
        tcert = ManagedTcert.objects.filter(pk=pk).first()
        if tcert is None:
            return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = GrantCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.filter(pk=serializer.validated_data["user_id"]).first()
        if user is None:
            return Response({"detail": "User not found"}, status=status.HTTP_400_BAD_REQUEST)
        grant, created = TcertGrant.objects.get_or_create(user=user, tcert=tcert)
        return Response(GrantSerializer(grant).data, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)

    def delete(self, request, pk, grant_id):
        TcertGrant.objects.filter(pk=grant_id, tcert_id=pk).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class TcertSignView(APIView):
    """Sign an SDoc with a TCert. Requires a grant (or admin)."""

    permission_classes = [IsAuthenticated, CanSignTcert]

    def post(self, request, pk):
        tcert = ManagedTcert.objects.filter(pk=pk).first()
        if tcert is None:
            return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        self.check_object_permissions(request, tcert)
        serializer = SignSdocSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        svc = EnterpriseService()
        try:
            record = _run(
                svc.sign_sdoc,
                tcert_id=tcert.tcert_id,
                values=serializer.validated_data["values"],
                user=request.user,
                ip_address=_client_ip(request),
            )
        except QrsEnterpriseError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(SdocRecordSerializer(record).data, status=status.HTTP_201_CREATED)


class ExternalSignView(APIView):
    """Sign an SDoc for an external system (via API key).

    The external system submits field values for a TCert and receives the signed
    SDoc plus a QR PNG (base64). The TCert is identified by its ``tcert_id``
    (``<keyId>:<certNumber>``). The API key must have the ``can_sign`` permission
    (or the owner must have a grant for the TCert).

    Methods:
      * ``OPTIONS`` / ``GET`` — return the TCert's field schema (so the caller
        knows how to encode ``values`` before signing).
      * ``POST`` — sign an SDoc with the given ``values`` and return the signed
        SDoc + QR PNG.
    """

    permission_classes = [IsAuthenticated]

    def _get_tcert(self, request):
        tcert_id = (request.data or {}).get("tcert_id") or (request.query_params or {}).get("tcert_id")
        if not tcert_id:
            return None, Response(
                {"detail": "tcert_id required"}, status=status.HTTP_400_BAD_REQUEST
            )
        tcert = ManagedTcert.objects.filter(tcert_id=tcert_id).first()
        if tcert is None:
            return None, Response({"detail": "TCert not found"}, status=status.HTTP_404_NOT_FOUND)
        return tcert, None

    def _authorize(self, request, tcert):
        """Return None if allowed, else an error Response.

        For an API key, the key must have ``can_sign`` AND its owner must have a
        grant for the TCert (or be an admin). This enforces "an account may only
        sign with the one or two TCerts it is granted."
        """
        api_key = getattr(request, "api_key", None)
        if api_key is not None:
            if not api_key.has_perm("enterprise.can_sign"):
                return Response(
                    {"detail": "API key lacks can_sign permission"},
                    status=status.HTTP_403_FORBIDDEN,
                )
            owner = api_key.owner
            if owner is None:
                return Response(
                    {"detail": "API key has no owner"}, status=status.HTTP_403_FORBIDDEN
                )
            if not (
                _is_admin(owner)
                or TcertGrant.objects.filter(user=owner, tcert=tcert).exists()
            ):
                return Response(
                    {"detail": "API key owner has no grant for this TCert"},
                    status=status.HTTP_403_FORBIDDEN,
                )
        elif not (
            IsAdmin().has_permission(request, self)
            or TcertGrant.objects.filter(user=request.user, tcert=tcert).exists()
        ):
            return Response(
                {"detail": "No grant to sign with this TCert"}, status=status.HTTP_403_FORBIDDEN
            )
        return None

    def options(self, request, *args, **kwargs):
        tcert, err = self._get_tcert(request)
        if err:
            return err
        auth_err = self._authorize(request, tcert)
        if auth_err:
            return auth_err
        return Response(
            {
                "tcert_id": tcert.tcert_id,
                "name": tcert.name,
                "algorithm": tcert.algorithm,
                "schema": tcert.schema,
            },
            status=status.HTTP_200_OK,
        )

    def get(self, request, *args, **kwargs):
        return self.options(request, *args, **kwargs)

    def post(self, request):
        tcert, err = self._get_tcert(request)
        if err:
            return err
        values = (request.data or {}).get("values")
        if not isinstance(values, dict):
            return Response(
                {"detail": "values (object) required"}, status=status.HTTP_400_BAD_REQUEST
            )
        auth_err = self._authorize(request, tcert)
        if auth_err:
            return auth_err

        svc = EnterpriseService()
        try:
            record = _run(
                svc.sign_sdoc,
                tcert_id=tcert.tcert_id,
                values=values,
                user=request.user,
                ip_address=_client_ip(request),
            )
        except QrsEnterpriseError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        # Build the QR payload and render a PNG (base64) for the external system.
        qr_payload = f"qrs://v1/sdoc/{record.sdoc_b64}"
        qr_png_b64 = _render_qr_png(qr_payload)
        return Response(
            {
                "sdoc_id": record.sdoc_id,
                "sdoc_b64": record.sdoc_b64,
                "issued_at": record.issued_at,
                "qr_payload": qr_payload,
                "qr_png_b64": qr_png_b64,
            },
            status=status.HTTP_201_CREATED,
        )


class TcertAttestView(APIView):
    """Attest a target TCert using this TCert as a CA."""

    permission_classes = [IsAuthenticated, CanSignTcert]

    def post(self, request, pk):
        tcert = ManagedTcert.objects.filter(pk=pk).first()
        if tcert is None:
            return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        if not tcert.is_ca:
            return Response({"detail": "TCert is not a CA"}, status=status.HTTP_400_BAD_REQUEST)
        self.check_object_permissions(request, tcert)
        serializer = AttestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        svc = EnterpriseService()
        try:
            result = _run(
                svc.attest,
                ca_tcert_id=tcert.tcert_id,
                target_tcert_id=serializer.validated_data["target_tcert_id"],
                claims=serializer.validated_data.get("claims"),
                user=request.user,
                ip_address=_client_ip(request),
            )
        except QrsEnterpriseError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(result, status=status.HTTP_201_CREATED)


class TcertRevokeView(APIView):
    """Revoke a TCert. Requires the ``can_revoke_tcert`` permission."""

    permission_classes = [IsAuthenticated, CanRevokeTcert]

    def post(self, request, pk):
        tcert = ManagedTcert.objects.filter(pk=pk).first()
        if tcert is None:
            return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = RevokeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        svc = EnterpriseService()
        try:
            result = _run(
                svc.revoke_tcert,
                signer_key_id=tcert.key.key_id,
                target_tcert_id=serializer.validated_data["target_tcert_id"],
                reason=serializer.validated_data.get("reason"),
                user=request.user,
                ip_address=_client_ip(request),
            )
        except QrsEnterpriseError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(result, status=status.HTTP_201_CREATED)


class SdocBlockView(APIView):
    """Block an SDoc. Requires the ``can_block_sdoc`` permission."""

    permission_classes = [IsAuthenticated, CanBlockSdoc]

    def post(self, request):
        serializer = BlockSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        svc = EnterpriseService()
        try:
            result = _run(
                svc.block_sdoc,
                signer_key_id=request.data.get("signer_key_id", ""),
                target_sdoc_id=serializer.validated_data["target_sdoc_id"],
                reason=serializer.validated_data.get("reason"),
                user=request.user,
                ip_address=_client_ip(request),
            )
        except QrsEnterpriseError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(result, status=status.HTTP_201_CREATED)


class SdocUnblockView(APIView):
    """Unblock an SDoc. Requires the ``can_unblock_sdoc`` permission."""

    permission_classes = [IsAuthenticated, CanUnblockSdoc]

    def post(self, request):
        serializer = BlockSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        svc = EnterpriseService()
        try:
            result = _run(
                svc.unblock_sdoc,
                signer_key_id=request.data.get("signer_key_id", ""),
                target_sdoc_id=serializer.validated_data["target_sdoc_id"],
                reason=serializer.validated_data.get("reason"),
                user=request.user,
                ip_address=_client_ip(request),
            )
        except QrsEnterpriseError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(result, status=status.HTTP_201_CREATED)


# ---------------------------------------------------------------------------
# SDocs
# ---------------------------------------------------------------------------
class SdocListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if IsAdmin().has_permission(request, self):
            sdocs = SdocRecord.objects.all()
        else:
            granted = TcertGrant.objects.filter(user=request.user).values_list("tcert_id", flat=True)
            sdocs = SdocRecord.objects.filter(tcert_id__in=granted)
        return Response(SdocRecordSerializer(sdocs, many=True).data)


class SdocDetailView(APIView):
    """Fetch a single SDoc by its sdoc_id."""

    permission_classes = [IsAuthenticated]

    def get(self, request, sdoc_id):
        sdoc = SdocRecord.objects.filter(sdoc_id=sdoc_id).first()
        if sdoc is None:
            return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(SdocRecordSerializer(sdoc).data)


class SdocVerifyView(APIView):
    """Verify an SDoc's cryptographic signature and TCert linkage."""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        sdoc_b64 = (request.data or {}).get("sdoc_b64")
        if not sdoc_b64:
            return Response({"detail": "sdoc_b64 required"}, status=status.HTTP_400_BAD_REQUEST)
        svc = EnterpriseService()
        try:
            verdict = _run(svc.verify, sdoc_b64)
        except QrsEnterpriseError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(verdict)


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
class AuditLogListView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        logs = AuditLog.objects.all()
        return Response(AuditLogSerializer(logs, many=True).data)


# ---------------------------------------------------------------------------
# API keys (scoped to the owning user; admins see all)
# ---------------------------------------------------------------------------
class ApiKeyListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if IsAdmin().has_permission(request, self):
            keys = ApiKey.objects.all()
        else:
            keys = ApiKey.objects.filter(owner=request.user)
        return Response(ApiKeySerializer(keys, many=True).data)

    def post(self, request):
        serializer = ApiKeyCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        api_key, raw_key = ApiKey.generate(
            name=serializer.validated_data["name"],
            owner=request.user,
            permissions=serializer.validated_data.get("permissions", []),
            expires_at=serializer.validated_data.get("expires_at"),
        )
        return Response(
            {**ApiKeySerializer(api_key).data, "key": raw_key},
            status=status.HTTP_201_CREATED,
        )


class ApiKeyDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        key = ApiKey.objects.filter(pk=pk).first()
        if key is None:
            return Response({"detail": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        # Users may only delete their own keys; admins may delete any.
        if not IsAdmin().has_permission(request, self) and key.owner_id != request.user.id:
            return Response({"detail": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)
        key.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
