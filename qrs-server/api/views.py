"""HTTP API.

All "write" operations require the host to first solve a proof-of-work challenge
and obtain a short-lived token. Statements are additionally verified
cryptographically against the TCert's public key before being stored. Read
operations are public — a verifier finds this server via the TCert's
`online_endpoint` and fetches data, but still verifies everything client-side.
"""
import hashlib
import secrets
from datetime import timedelta

from django.conf import settings
from django.http import FileResponse
from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from . import proof_of_work
from .models import (
    AttachmentBlob,
    AttachmentReference,
    SignedObject,
    SupportedTcert,
    TcertAttestation,
    TcertChallenge,
    TcertToken,
)
from .verifier import decode_qrs_file, describe_tcert, verify_object

ALLOWED_STATEMENT_ACTIONS = {"attest", "addTcert", "revokeTcert", "blockSdoc", "unblockSdoc"}


def register_tcert_bytes(bytes_b64: str) -> tuple[dict | None, str | None]:
    """Register a TCert from its base64url bytes (self-verifies first).

    Returns ``(summary, None)`` on success or ``(None, error)`` on failure.
    """
    info = describe_tcert(bytes_b64)
    if not info.get("ok") or info.get("type") != "tcert":
        return None, info.get("error") or "TCert failed self-signature verification"
    key_id = info["keyId"]
    cert_number = info.get("certificateNumber") or 1
    tcert_id = f"{key_id}:{cert_number}"
    # Key by the full tcert_id: one key may own several TCerts (one per document
    # type), and re-registering must not overwrite a sibling certificate.
    defaults = {
        "key_id": key_id,
        "certificate_number": cert_number,
        "algorithm": info.get("algorithm") or "Ed25519",
        "name": info.get("name") or "",
        "public_key": info.get("publicKey") or {},
        "online_endpoint": info.get("onlineEndpoint") or "",
        "tcert_b64": bytes_b64,
    }
    SupportedTcert.objects.update_or_create(
        tcert_id=tcert_id,
        defaults=defaults,
    )
    return (
        {
            "keyId": key_id,
            "tcertId": tcert_id,
            "issuerName": info.get("issuerName"),
            "documentName": info.get("documentName"),
            "onlineEndpoint": info.get("onlineEndpoint"),
        },
        None,
    )


def _extract_qrs_text(request) -> str | None:
    """Read a `.qrs` file's text from a multipart `file` field, a JSON `{"qrs": ...}`
    body, or a raw `text/plain` body."""
    uploaded = request.FILES.get("file")
    if uploaded is not None:
        text = uploaded.read().decode("utf-8", errors="replace")
        return text or None
    try:
        data = request.data or {}
    except Exception:  # noqa: BLE001 - no parser matched the content type
        data = {}
    qrs_field = data.get("qrs") if hasattr(data, "get") else None
    if qrs_field:
        return str(qrs_field)
    body = request.body or b""
    if body.strip():
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            return None
    return None


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _bearer_token(request) -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer ") :].strip()
    return None


def _valid_token(request, key_id: str) -> TcertToken | None:
    raw = _bearer_token(request)
    if not raw:
        return None
    try:
        token = TcertToken.objects.get(token=raw, key_id=key_id, expires_at__gt=timezone.now())
        return token
    except TcertToken.DoesNotExist:
        return None


def _is_attested_tcert(tcert: SupportedTcert) -> bool:
    """A non-CA TCert is admitted only through at least one enrolled CA attestation."""
    return tcert.is_ca or TcertAttestation.objects.filter(target=tcert, ca__is_ca=True).exists()


def _authorized_ca(request, ca_tcert_id: str) -> tuple[SupportedTcert | None, Response | None]:
    try:
        ca = SupportedTcert.objects.get(tcert_id=ca_tcert_id, is_ca=True)
    except SupportedTcert.DoesNotExist:
        return None, Response({"error": "trusted CA not found on this server"}, status=status.HTTP_404_NOT_FOUND)
    if _valid_token(request, ca.key_id) is None:
        return None, Response({"error": "valid bearer token for the CA required"}, status=status.HTTP_401_UNAUTHORIZED)
    return ca, None


def _statement_payload(request):
    return (request.data or {}).get("bytesB64")


class TcertList(APIView):
    """Public TCert registration is disabled; CA bootstrap is an admin action."""

    throttle_scope = "register"

    def post(self, request):
        return Response(
            {"error": "public TCert registration is disabled; a server admin must bootstrap CAs, and CAs enroll targets with an attestation"},
            status=status.HTTP_403_FORBIDDEN,
        )


class ImportTcertView(APIView):
    """POST /api/tcerts/import/ — upload a `.qrs` file (single TCert or a bundle)
    to register every TCert it contains. The server self-verifies each TCert."""

    throttle_scope = "register"

    def post(self, request):
        return Response(
            {"error": "public TCert import is disabled; use the server admin only to bootstrap a CA"},
            status=status.HTTP_403_FORBIDDEN,
        )


class SyncView(APIView):
    """Legacy global sync endpoint, deliberately disabled."""

    throttle_scope = "anon"

    def post(self, request):
        return Response(
            {"error": "global sync is disabled; sync one trusted CA through /api/cas/<caTcertId>/sync/"},
            status=status.HTTP_410_GONE,
        )


class CaAttestationUpload(APIView):
    """Atomically admit one target TCert and the attestation from a trusted CA."""

    throttle_scope = "register"

    def post(self, request, ca_tcert_id):
        ca, error = _authorized_ca(request, ca_tcert_id)
        if error:
            return error
        if not ca.allow_attestation:
            return Response({"error": "attestation service is disabled for this CA"}, status=status.HTTP_403_FORBIDDEN)
        if not ca.allow_tcert_enrollment:
            return Response({"error": "TCert enrollment service is disabled for this CA"}, status=status.HTTP_403_FORBIDDEN)
        data = request.data or {}
        target_b64 = data.get("targetTcertB64")
        attestation_b64 = data.get("attestationB64")
        if not target_b64 or not attestation_b64:
            return Response(
                {"error": "targetTcertB64 and attestationB64 required"}, status=status.HTTP_400_BAD_REQUEST
            )
        target_info = describe_tcert(target_b64)
        if not target_info.get("ok") or target_info.get("type") != "tcert":
            return Response({"error": target_info.get("error") or "target TCert failed verification"}, status=status.HTTP_400_BAD_REQUEST)
        target_id = f"{target_info['keyId']}:{target_info.get('certificateNumber') or 1}"
        verified = verify_object(ca.tcert_b64, attestation_b64)
        if not verified.get("ok"):
            return Response({"error": verified.get("error") or "attestation signature verification failed"}, status=status.HTTP_400_BAD_REQUEST)
        if (
            verified.get("objectType") != "statement"
            or verified.get("action") != "attest"
            or verified.get("signerKeyId") != ca.key_id
            or verified.get("targetKind") != "tcert"
            or verified.get("targetKeyId") != target_info["keyId"]
            or verified.get("targetCertificateNumber") != (target_info.get("certificateNumber") or 1)
            or verified.get("targetTcertHash") != target_info.get("tcertHash")
        ):
            return Response(
                {"error": "attestation does not bind this exact target TCert"}, status=status.HTTP_400_BAD_REQUEST
            )
        existing = SupportedTcert.objects.filter(tcert_id=target_id).first()
        # A CA may not be reattested by another CA; a plain target may be attested
        # by any number of independent trusted CAs in parallel (each CA owns its
        # own attestation, and one CA's revocation does not bind another).
        if existing and existing.is_ca:
            return Response(
                {"error": "target TCert is a trusted CA and cannot be reattested"},
                status=status.HTTP_409_CONFLICT,
            )
        statement_id = verified.get("statementId") or _sha256_hex(attestation_b64.encode("ascii"))[:32]
        with transaction.atomic():
            summary, register_error = register_tcert_bytes(target_b64)
            if register_error:
                return Response({"error": register_error}, status=status.HTTP_400_BAD_REQUEST)
            target = SupportedTcert.objects.get(tcert_id=target_id)
            SignedObject.objects.update_or_create(
                tcert=ca,
                statement_id=statement_id,
                defaults={
                    "action": "attest",
                    "signed_at": int(verified.get("signedAt") or 0),
                    "bytes_b64": attestation_b64,
                },
            )
            # Record the independent (CA → target) attestation so multiple CAs can
            # concurrently attest the same target without overwriting one another.
            TcertAttestation.objects.get_or_create(
                ca=ca,
                target=target,
                statement_id=statement_id,
                defaults={
                    "tcert_hash": verified.get("targetTcertHash") or "",
                    "signed_at": int(verified.get("signedAt") or 0),
                    "bytes_b64": attestation_b64,
                },
            )
        return Response(
            {"tcert": summary, "statementId": statement_id, "caTcertId": ca.tcert_id}, status=status.HTTP_201_CREATED
        )


class CaStatementUpload(APIView):
    """Upload a non-enrollment statement authored by one exact trusted CA."""

    def post(self, request, ca_tcert_id):
        ca, error = _authorized_ca(request, ca_tcert_id)
        if error:
            return error
        bytes_b64 = (request.data or {}).get("bytesB64")
        if not bytes_b64:
            return Response({"error": "bytesB64 required"}, status=status.HTTP_400_BAD_REQUEST)
        verified = verify_object(ca.tcert_b64, bytes_b64)
        if not verified.get("ok"):
            return Response({"error": verified.get("error") or "signature verification failed"}, status=status.HTTP_400_BAD_REQUEST)
        if (
            verified.get("objectType") != "statement"
            or verified.get("signerKeyId") != ca.key_id
            or verified.get("action") not in ALLOWED_STATEMENT_ACTIONS - {"attest", "addTcert"}
        ):
            return Response(
                {"error": "attestations must use the atomic CA enrollment endpoint; unsupported statement action"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        action = verified["action"]
        if action == "blockSdoc" and not ca.allow_sdoc_block:
            return Response({"error": "SDoc block service is disabled for this CA"}, status=status.HTTP_403_FORBIDDEN)
        if action == "unblockSdoc" and not ca.allow_sdoc_unblock:
            return Response({"error": "SDoc unblock service is disabled for this CA"}, status=status.HTTP_403_FORBIDDEN)
        statement_id = verified.get("statementId") or _sha256_hex(bytes_b64.encode("ascii"))[:32]
        SignedObject.objects.update_or_create(
            tcert=ca,
            statement_id=statement_id,
            defaults={
                "action": verified["action"],
                "signed_at": int(verified.get("signedAt") or 0),
                "bytes_b64": bytes_b64,
            },
        )
        return Response({"statementId": statement_id, "action": verified["action"], "type": "statement"}, status=status.HTTP_201_CREATED)


class TcertStatementUpload(APIView):
    """Upload block/unblock statements from a registered TCert."""

    def post(self, request, key_id):
        tcert = SupportedTcert.objects.filter(key_id=key_id).order_by("-certificate_number").first()
        if not tcert:
            return Response({"error": "TCert key is not registered"}, status=status.HTTP_404_NOT_FOUND)
        if _valid_token(request, key_id) is None:
            return Response({"error": "valid bearer token required"}, status=status.HTTP_401_UNAUTHORIZED)
        bytes_b64 = _statement_payload(request)
        if not bytes_b64:
            return Response({"error": "bytesB64 required"}, status=status.HTTP_400_BAD_REQUEST)
        verified = verify_object(tcert.tcert_b64, bytes_b64)
        action = verified.get("action")
        if not verified.get("ok") or verified.get("objectType") != "statement" or verified.get("signerKeyId") != key_id:
            return Response({"error": verified.get("error") or "statement signature verification failed"}, status=status.HTTP_400_BAD_REQUEST)
        if action == "blockSdoc" and not tcert.allow_sdoc_block:
            return Response({"error": "SDoc block service is disabled for this TCert"}, status=status.HTTP_403_FORBIDDEN)
        if action == "unblockSdoc" and not tcert.allow_sdoc_unblock:
            return Response({"error": "SDoc unblock service is disabled for this TCert"}, status=status.HTTP_403_FORBIDDEN)
        if action == "revokeTcert":
            target = verified.get("targetKeyId") or verified.get("targetTcertId") or ""
            if not tcert.allow_self_revocation or not (target == key_id or str(target).startswith(f"{key_id}:")):
                return Response({"error": "only an enabled self-revocation is allowed here"}, status=status.HTTP_403_FORBIDDEN)
        elif action not in {"blockSdoc", "unblockSdoc"}:
            return Response({"error": "only SDoc block/unblock statements are allowed here"}, status=status.HTTP_403_FORBIDDEN)
        statement_id = verified.get("statementId") or _sha256_hex(bytes_b64.encode("ascii"))[:32]
        SignedObject.objects.update_or_create(tcert=tcert, statement_id=statement_id, defaults={"action": action, "signed_at": int(verified.get("signedAt") or 0), "bytes_b64": bytes_b64})
        return Response({"statementId": statement_id, "action": action, "type": "statement"}, status=status.HTTP_201_CREATED)


class SelfRevocationUpload(APIView):
    """Accept irreversible self-revocation by a registered non-CA TCert."""

    def post(self, request, key_id):
        tcert = SupportedTcert.objects.filter(key_id=key_id).order_by("-certificate_number").first()
        if not tcert:
            return Response({"error": "TCert key is not registered"}, status=status.HTTP_404_NOT_FOUND)
        if tcert.is_ca:
            return Response({"error": "CA self-revocation is not allowed at this endpoint"}, status=status.HTTP_403_FORBIDDEN)
        if not tcert.allow_self_revocation:
            return Response({"error": "self-revocation service is disabled for this TCert"}, status=status.HTTP_403_FORBIDDEN)
        if _valid_token(request, key_id) is None:
            return Response({"error": "valid bearer token required"}, status=status.HTTP_401_UNAUTHORIZED)
        bytes_b64 = _statement_payload(request) or ""
        verified = verify_object(tcert.tcert_b64, bytes_b64)
        if not verified.get("ok") or verified.get("objectType") != "statement" or verified.get("action") != "revokeTcert" or verified.get("signerKeyId") != key_id:
            return Response({"error": "valid self-revocation statement required"}, status=status.HTTP_400_BAD_REQUEST)
        if verified.get("targetKeyId") != key_id and not str(verified.get("targetTcertId") or "").startswith(f"{key_id}:"):
            return Response({"error": "self-revocation must target the signing key or its TCert"}, status=status.HTTP_403_FORBIDDEN)
        statement_id = verified.get("statementId") or _sha256_hex(bytes_b64.encode("ascii"))[:32]
        SignedObject.objects.update_or_create(tcert=tcert, statement_id=statement_id, defaults={"action": "revokeTcert", "signed_at": int(verified.get("signedAt") or 0), "bytes_b64": bytes_b64})
        return Response({"statementId": statement_id, "action": "revokeTcert", "type": "statement", "irreversible": True}, status=status.HTTP_201_CREATED)


class CaSyncView(APIView):
    """Read-only sync for exactly one server-trusted CA and its enrolled targets."""

    throttle_scope = "anon"

    def post(self, request, ca_tcert_id):
        try:
            ca = SupportedTcert.objects.get(tcert_id=ca_tcert_id, is_ca=True)
        except SupportedTcert.DoesNotExist:
            return Response({"error": "trusted CA not found on this server"}, status=status.HTTP_404_NOT_FOUND)
        # All targets enrolled by this CA, via the many-to-many attestation
        # relation.
        target_ids = TcertAttestation.objects.filter(ca=ca).values_list("target_id", flat=True)
        targets = SupportedTcert.objects.filter(id__in=target_ids).order_by("created_at")
        return Response(
            {
                "caTcertId": ca.tcert_id,
                "tcerts": [
                    {"keyId": t.key_id, "tcertId": t.tcert_id, "bytesB64": t.tcert_b64}
                    for t in targets
                ],
                "attestations": [
                    {
                        "statementId": a.statement_id,
                        "targetTcertId": a.target.tcert_id,
                        "tcertHash": a.tcert_hash,
                        "signedAt": a.signed_at,
                        "bytesB64": a.bytes_b64,
                    }
                    for a in ca.enrolled_targets.all().select_related("target")
                ],
                "objects": [
                    {
                        "type": "statement",
                        "statementId": s.statement_id,
                        "action": s.action,
                        "signedAt": s.signed_at,
                        "bytesB64": s.bytes_b64,
                    }
                    for s in ca.statements.all()
                ],
            }
        )


class ChallengeView(APIView):
    """POST /api/tcerts/<keyId>/challenge/ — issue a proof-of-work challenge."""

    throttle_scope = "challenge"
    def post(self, request, key_id):
        TcertChallenge.objects.filter(
            created_at__lte=timezone.now() - timedelta(seconds=proof_of_work.CHALLENGE_TTL_SECONDS)
        ).delete()
        difficulty = min(proof_of_work.DEFAULT_DIFFICULTY, proof_of_work.MAX_DIFFICULTY)
        nonce = proof_of_work.generate_nonce()
        TcertChallenge.objects.create(key_id=key_id, nonce=nonce, difficulty=difficulty)
        return Response({"keyId": key_id, "nonce": nonce, "difficulty": difficulty})


class TokenView(APIView):
    """POST /api/tcerts/<keyId>/token/ — redeem a solved challenge for a token."""

    throttle_scope = "challenge"

    def post(self, request, key_id):
        nonce = (request.data or {}).get("nonce")
        counter = (request.data or {}).get("counter")
        if nonce is None or counter is None:
            return Response({"error": "nonce and counter required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            challenge = TcertChallenge.objects.get(key_id=key_id, nonce=nonce)
        except TcertChallenge.DoesNotExist:
            return Response({"error": "unknown or expired challenge"}, status=status.HTTP_400_BAD_REQUEST)
        if not proof_of_work.verify(challenge.nonce, challenge.difficulty, int(counter)):
            return Response({"error": "proof-of-work not satisfied"}, status=status.HTTP_400_BAD_REQUEST)
        challenge.delete()

        token = secrets.token_hex(24)
        expires_at = timezone.now() + timedelta(seconds=settings.QRS_TOKEN_TTL_SECONDS)
        TcertToken.objects.create(key_id=key_id, token=token, expires_at=expires_at)
        return Response({"token": token, "expiresAt": int(expires_at.timestamp())})


class ObjectsView(APIView):
    """POST /api/tcerts/<keyId>/objects/ — upload a signed statement/attachment (token required).
    GET  /api/tcerts/<keyId>/objects/ — list hosted objects (public read)."""

    def get(self, request, key_id):
        tcerts = SupportedTcert.objects.filter(key_id=key_id)
        if not tcerts.exists():
            return Response({"error": "TCert not supported"}, status=status.HTTP_404_NOT_FOUND)
        statements = []
        attachments = []
        for t in tcerts:
            statements += [
                {
                    "type": "statement",
                    "statementId": s.statement_id,
                    "action": s.action,
                    "signedAt": s.signed_at,
                    "bytesB64": s.bytes_b64,
                }
                for s in t.statements.all()
            ]
            attachments += [
                {
                    "type": "attachment",
                    "id": a.blob_id,
                    "contentType": a.blob.content_type,
                    "contentHash": a.blob.content_hash,
                }
                for a in t.attachments.all()
            ]
        return Response({"keyId": key_id, "objects": statements + attachments})

    def post(self, request, key_id):
        return Response(
            {"error": "use the exact CA statement or CA attestation endpoint"}, status=status.HTTP_410_GONE
        )


class AttachmentUpload(APIView):
    """Upload a normal file for a registered TCert with attachment permission.

    The attachment ID is derived by the server from the uploaded file. The
    protocol carries only the truncated SHA-256 ID in the signed SDoc.
    """

    throttle_scope = "register"

    def post(self, request):
        data = request.data or {}
        tcert_id = str(data.get("tcertId") or "").strip()
        field_name = str(data.get("fieldName") or "").strip()
        uploaded = request.FILES.get("file")
        if uploaded is None or not tcert_id or not field_name:
            return Response(
                {"error": "file, tcertId and fieldName required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            tcert = SupportedTcert.objects.get(tcert_id=tcert_id)
        except SupportedTcert.DoesNotExist:
            return Response({"error": "TCert has not been added to this server"}, status=status.HTTP_404_NOT_FOUND)
        if not tcert.allow_attachment_upload:
            return Response({"error": "attachment service is disabled for this TCert"}, status=status.HTTP_403_FORBIDDEN)
        if _valid_token(request, tcert.key_id) is None:
            return Response({"error": "valid bearer token for the registered TCert required"}, status=status.HTTP_401_UNAUTHORIZED)
        info = describe_tcert(tcert.tcert_b64)
        if not info.get("ok"):
            return Response({"error": "could not read TCert schema"}, status=status.HTTP_400_BAD_REQUEST)
        attachment_field = next(
            (
                field
                for field in info.get("schema", [])
                if field.get("type") == "attachment" and field.get("name") == field_name
            ),
            None,
        )
        if attachment_field is None:
            return Response({"error": "attachment field not found in TCert schema"}, status=status.HTTP_400_BAD_REQUEST)
        declared_content_type = str(
            (attachment_field.get("inputRules") or {}).get("contentType") or "application/octet-stream"
        ).strip().lower()
        uploaded_content_type = str(getattr(uploaded, "content_type", "") or "").strip().lower()
        # Keep a concrete MIME type for wildcard schemas. Native clients need
        # image/png (or image/jpeg, etc.) to render the returned bytes; the
        # schema's image/* is only an acceptance rule.
        content_type = (
            uploaded_content_type
            if declared_content_type.endswith("/*")
            and uploaded_content_type.startswith(declared_content_type[:-1])
            else declared_content_type
        )
        if uploaded.size is not None and uploaded.size > 100 * 1024 * 1024:
            return Response({"error": "attachment exceeds the 100 MB limit"}, status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
        digest = hashlib.sha256()
        total_size = 0
        for chunk in uploaded.chunks():
            digest.update(chunk)
            total_size += len(chunk)
        computed = digest.hexdigest()
        hash_hex = computed[:32]
        uploaded.seek(0)
        existing = AttachmentBlob.objects.filter(id=hash_hex).first()
        if existing is not None and existing.content_hash != computed:
            return Response({"error": "attachment ID collision"}, status=status.HTTP_409_CONFLICT)
        if existing is None:
            attachment = AttachmentBlob(
                id=hash_hex,
                content_type=content_type,
                content_hash=computed,
                size=total_size,
            )
            attachment.file.save(f"{hash_hex}.bin", uploaded, save=False)
            attachment.save()
        else:
            attachment = existing
            # An attachment row may have been created by an older server
            # version (or by a partially completed upload) without a stored
            # file. Re-uploading the same content must repair that row rather
            # than treating the metadata record as a complete upload.
            if not attachment.file.name or attachment.size != total_size:
                attachment.file.save(f"{hash_hex}.bin", uploaded, save=False)
                attachment.size = total_size
                attachment.content_type = content_type
                attachment.content_hash = computed
                attachment.save(update_fields=["file", "size", "content_type", "content_hash"])
        AttachmentReference.objects.get_or_create(
            tcert=tcert,
            blob=attachment,
            field_name=field_name,
        )
        return Response(
            {"id": hash_hex, "size": attachment.size, "contentType": content_type, "contentHash": computed, "type": "attachment"},
            status=status.HTTP_201_CREATED,
        )


class AttachmentDetail(APIView):
    """GET /api/attachments/<hash>/ — RAW file download (public).

    Returns metadata only by default ({ id, contentType, size, contentHash }) so
    a verifier can show the size WITHOUT downloading the file. Pass `?content=1`
    to get the raw file body.
    """

    def get(self, request, attachment_id):
        try:
            att = AttachmentBlob.objects.get(id=attachment_id)
        except AttachmentBlob.DoesNotExist:
            return Response({"error": "attachment not found"}, status=status.HTTP_404_NOT_FOUND)
        meta = {
            "id": att.id,
            "hash": att.content_hash or att.id,
            "contentHash": att.content_hash or att.id,
            "contentType": att.content_type,
            "size": att.size,
        }
        if request.query_params.get("content") not in (None, "0", "false"):
            response = FileResponse(att.file.open("rb"), content_type=att.content_type)
            response["Content-Length"] = str(att.size)
            response["Content-Disposition"] = f'inline; filename="{att.id}"'
            response["ETag"] = f'"{att.content_hash}"'
            return response
        return Response(meta)

    def head(self, request, attachment_id):
        try:
            att = AttachmentBlob.objects.get(id=attachment_id)
        except AttachmentBlob.DoesNotExist:
            return Response({"error": "attachment not found"}, status=status.HTTP_404_NOT_FOUND)
        return Response(
            {
                "id": att.id,
                "contentType": att.content_type,
                "size": att.size,
                "contentHash": att.content_hash,
            }
        )
