"""Enterprise service layer — wraps qrs-core-python operations.

The qrs-core service methods are async, and Django supports async views, so the
service layer is **async-native**: every method is a coroutine and uses Django's
async ORM methods (``aget`` / ``asave`` / ``acreate``). This keeps business logic
out of the views and makes it directly testable with ``pytest.mark.asyncio`` /
``TransactionTestCase`` without any endpoint complexity.

Views call these methods with ``await``. If a caller needs a synchronous entry
point, use ``asgiref.sync.async_to_sync`` at the call site.
"""
from __future__ import annotations

from typing import Any

from qrs.fields import FieldSchema
from qrs.id import from_base64url, to_base64url
from qrs.services.certificateService import CreateTcertParams
from qrs.services.revocationService import BlockSdocParams, RevokeTcertParams
from qrs.services.signingService import IssueSdocParams
from qrs.services.trustService import AttestParams

from .distribution import (
    DistributionError,
    DistributionUnavailableError,
    publish_attestation,
    publish_statement,
)
from .models import AuditLog, ManagedKey, ManagedTcert, SdocRecord
from .qrs.runtime import build_runtime


class QrsEnterpriseError(Exception):
    """Base error for enterprise service failures."""


class TcertNotFoundError(QrsEnterpriseError):
    pass


class KeyNotFoundError(QrsEnterpriseError):
    pass


class SigningNotAllowedError(QrsEnterpriseError):
    pass


class EnterpriseService:
    """High-level operations backed by qrs-core-python."""

    def __init__(self, runtime=None) -> None:
        self._runtime = runtime or build_runtime()

    # -- TCert management ---------------------------------------------------
    async def create_tcert(
        self,
        *,
        algorithm: str,
        name: str,
        fields: list[dict[str, Any]],
        is_ca: bool = False,
        online_endpoint: str | None = None,
        hash_algorithm: str | None = None,
        sdoc_max_age_seconds: int | None = None,
    ) -> ManagedTcert:
        # Normalize snake_case API field names to the camelCase qrs-core schema.
        normalized = []
        for f in fields:
            nf = dict(f)
            if "input_rules" in nf and "inputRules" not in nf:
                nf["inputRules"] = nf.pop("input_rules")
            if "verify_rules" in nf and "verifyRules" not in nf:
                nf["verifyRules"] = nf.pop("verify_rules")
            normalized.append(nf)
        schema = [FieldSchema.from_json(f) for f in normalized]
        params = CreateTcertParams(
            algorithm=algorithm,
            name=name,
            fields=schema,
            hash_algorithm=hash_algorithm,
            sdoc_max_age_seconds=sdoc_max_age_seconds,
            online_endpoint=online_endpoint,
        )
        result = await self._runtime.certificates.create_tcert(params)

        key = await ManagedKey.objects.aget(key_id=result.key_id)
        tcert = ManagedTcert(
            key=key,
            tcert_id=result.tcert_id,
            certificate_number=result.certificate_number,
            name=name,
            algorithm=algorithm,
            is_ca=is_ca,
            schema=fields,
            tcert_b64=to_base64url(result.bytes),
            online_endpoint=online_endpoint or "",
        )
        await tcert.asave()

        # Register CA authority in the trust store so attest/revoke work.
        if is_ca:
            await self._runtime.trust.add_ca(result.tcert_id)
        return tcert

    async def create_tcert_with_audit(
        self,
        *,
        user,
        ip_address=None,
        **kwargs,
    ) -> ManagedTcert:
        """Create a TCert and record an audit entry."""
        tcert = await self.create_tcert(**kwargs)
        await log_audit(
            user=user,
            action=AuditLog.ACTION_CREATE_TCERT,
            tcert=tcert,
            target=tcert.tcert_id,
            ip_address=ip_address,
            detail={"name": tcert.name, "is_ca": tcert.is_ca},
        )
        return tcert

    # -- Signing ------------------------------------------------------------
    async def sign_sdoc(
        self, *, tcert_id: str, values: dict[str, Any], user=None, ip_address=None
    ) -> SdocRecord:
        tcert = await self._get_tcert(tcert_id)
        if not tcert.has_schema:
            raise SigningNotAllowedError("TCert has no document schema and cannot sign SDocs")

        result = await self._runtime.signing.issue_sdoc(
            IssueSdocParams(tcert_id=tcert_id, values=values)
        )
        # qrs-core's issue_sdoc already persisted the raw bytes via the document
        # store; enrich that record with the issuing TCert and signer.
        record = await SdocRecord.objects.aget(sdoc_id=result.sdoc_id)
        record.tcert = tcert
        record.signed_by = user
        record.issued_at = result.issued_at
        await record.asave()

        await log_audit(
            user=user,
            action=AuditLog.ACTION_SIGN,
            tcert=tcert,
            target=record.sdoc_id,
            ip_address=ip_address,
            detail={"sdoc_id": record.sdoc_id},
        )
        return record

    # -- CA operations ------------------------------------------------------
    async def attest(
        self,
        *,
        ca_tcert_id: str,
        target_tcert_id: str,
        claims: dict[str, Any] | None = None,
        user=None,
        ip_address=None,
    ) -> dict[str, Any]:
        result = await self._runtime.trust.attest(
            AttestParams(ca_tcert_id=ca_tcert_id, target_tcert_id=target_tcert_id, claims=claims)
        )
        ca = await self._get_tcert(ca_tcert_id)
        statement_b64 = to_base64url(result["bytes"])
        # Publish the attestation (and enroll the target) to qrs-server.
        target = await self._get_tcert(target_tcert_id)
        await self._publish_attestation(
            ca_tcert_id=ca_tcert_id,
            target_tcert_b64=target.tcert_b64,
            attestation_b64=statement_b64,
        )
        await log_audit(
            user=user,
            action=AuditLog.ACTION_ATTEST,
            tcert=ca,
            target=target_tcert_id,
            ip_address=ip_address,
            statement_b64=statement_b64,
        )
        return {"statement_id": result["statement_id"], "bytes_b64": statement_b64}

    async def revoke_tcert(
        self,
        *,
        signer_key_id: str,
        target_tcert_id: str,
        reason: str | None = None,
        user=None,
        ip_address=None,
    ) -> dict[str, Any]:
        result = await self._runtime.revocation.revoke_tcert(
            RevokeTcertParams(
                signer_key_id=signer_key_id,
                target_tcert_id=target_tcert_id,
                type="retrospective",
                reason=reason,
            )
        )
        statement_b64 = to_base64url(result.bytes)
        # Publish the revocation statement to the signer's qrs-server endpoint.
        signer = await self._get_key(signer_key_id)
        ca_tcert = await ManagedTcert.objects.filter(key=signer, is_ca=True).afirst()
        if ca_tcert is not None:
            await self._publish_statement(ca_tcert_id=ca_tcert.tcert_id, statement_b64=statement_b64)
        await log_audit(
            user=user,
            action=AuditLog.ACTION_REVOKE,
            target=target_tcert_id,
            ip_address=ip_address,
            statement_b64=statement_b64,
        )
        return {"statement_id": result.statement_id, "bytes_b64": statement_b64}

    async def block_sdoc(
        self,
        *,
        signer_key_id: str,
        target_sdoc_id: str,
        reason: str | None = None,
        user=None,
        ip_address=None,
    ) -> dict[str, Any]:
        result = await self._runtime.revocation.block_sdoc(
            BlockSdocParams(signer_key_id=signer_key_id, target_sdoc_id=target_sdoc_id, reason=reason)
        )
        statement_b64 = to_base64url(result.bytes)
        # Publish the block statement to the signer's qrs-server endpoint.
        signer = await self._get_key(signer_key_id)
        ca_tcert = await ManagedTcert.objects.filter(key=signer, is_ca=True).afirst()
        if ca_tcert is not None:
            await self._publish_statement(ca_tcert_id=ca_tcert.tcert_id, statement_b64=statement_b64)
        await log_audit(
            user=user,
            action=AuditLog.ACTION_BLOCK,
            target=target_sdoc_id,
            ip_address=ip_address,
            statement_b64=statement_b64,
        )
        return {"statement_id": result.statement_id, "bytes_b64": statement_b64}

    async def unblock_sdoc(
        self,
        *,
        signer_key_id: str,
        target_sdoc_id: str,
        reason: str | None = None,
        user=None,
        ip_address=None,
    ) -> dict[str, Any]:
        result = await self._runtime.revocation.unblock_sdoc(
            BlockSdocParams(signer_key_id=signer_key_id, target_sdoc_id=target_sdoc_id, reason=reason)
        )
        statement_b64 = to_base64url(result.bytes)
        # Publish the unblock statement to the signer's qrs-server endpoint.
        signer = await self._get_key(signer_key_id)
        ca_tcert = await ManagedTcert.objects.filter(key=signer, is_ca=True).afirst()
        if ca_tcert is not None:
            await self._publish_statement(ca_tcert_id=ca_tcert.tcert_id, statement_b64=statement_b64)
        await log_audit(
            user=user,
            action=AuditLog.ACTION_UNBLOCK,
            target=target_sdoc_id,
            ip_address=ip_address,
            statement_b64=statement_b64,
        )
        return {"statement_id": result.statement_id, "bytes_b64": statement_b64}

    # -- Verification -------------------------------------------------------
    async def verify(self, sdoc_b64: str) -> dict[str, Any]:
        result = await self._runtime.verification.verify(from_base64url(sdoc_b64))
        return {
            "overall": result.overall,
            "cryptographic": result.cryptographic,
            "tcert": result.tcert,
            "trust": result.trust,
            "revocation": result.revocation,
            "schema": result.schema,
        }

    # -- helpers ------------------------------------------------------------
    async def _publish_statement(self, *, ca_tcert_id: str, statement_b64: str) -> dict[str, Any] | None:
        """Publish a statement to the CA's configured qrs-server endpoint.

        Returns the server response, or ``None`` if no endpoint is configured.
        Raises ``DistributionError`` if publishing fails.
        """
        ca = await self._get_tcert(ca_tcert_id)
        if not ca.online_endpoint:
            return None
        return await publish_statement(
            endpoint=ca.online_endpoint,
            ca_tcert_id=ca.tcert_id,
            ca_key_id=ca.key.key_id,
            statement_b64=statement_b64,
        )

    async def _publish_attestation(
        self, *, ca_tcert_id: str, target_tcert_b64: str, attestation_b64: str
    ) -> dict[str, Any] | None:
        """Publish a CA attestation (and enroll the target) to qrs-server."""
        ca = await self._get_tcert(ca_tcert_id)
        if not ca.online_endpoint:
            return None
        return await publish_attestation(
            endpoint=ca.online_endpoint,
            ca_tcert_id=ca.tcert_id,
            ca_key_id=ca.key.key_id,
            target_tcert_b64=target_tcert_b64,
            attestation_b64=attestation_b64,
        )

    async def _get_tcert(self, tcert_id: str) -> ManagedTcert:
        try:
            return await ManagedTcert.objects.aget(tcert_id=tcert_id)
        except ManagedTcert.DoesNotExist as exc:
            raise TcertNotFoundError(f"TCert not found: {tcert_id}") from exc

    async def _get_key(self, key_id: str) -> ManagedKey:
        try:
            return await ManagedKey.objects.aget(key_id=key_id)
        except ManagedKey.DoesNotExist as exc:
            raise KeyNotFoundError(f"Key not found: {key_id}") from exc


async def log_audit(
    *,
    user,
    action: str,
    tcert=None,
    target: str = "",
    ip_address=None,
    statement_b64: str = "",
    detail: dict[str, Any] | None = None,
) -> AuditLog:
    """Record an audit entry (async)."""
    return await AuditLog.objects.acreate(
        user=user,
        action=action,
        tcert=tcert,
        target=target,
        ip_address=ip_address,
        statement_b64=statement_b64,
        detail=detail or {},
    )