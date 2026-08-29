"""RevocationService: revocation, blocking, and lifecycle checks.

Revocation works through signed statements (offline-friendly):

- ``revokeTcert`` targets a TCert (prospective/retrospective) or a key (target
  kind ``key``, which invalidates all TCerts of that key).
- ``blockSdoc`` / ``unblockSdoc`` target a single SDoc by its id.

Checks distinguish prospective vs retrospective, and always evaluate key
revocation before TCert revocation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..crypto.providers import KeyPairMaterial
from ..deps import ServiceDeps
from ..envelope import parse_signed_object, split_tcert_id, tcert_id_of
from ..errors import QrsAuthorizationError, QrsCryptoError, QrsNotFoundError
from ..id import to_hex
from .statement import StatementOptions, StatementTarget, build_statement, verify_statement
from ..storage.interfaces import RevocationEntry

__all__ = [
    "RevocationService",
    "RevocationCheck",
    "RevokeTcertParams",
    "RevokeKeyParams",
    "BlockSdocParams",
    "StatementResult",
]


@dataclass
class RevocationCheck:
    state: str  # 'valid' | 'invalid'
    message: str | None = None


@dataclass
class RevokeTcertParams:
    signer_key_id: str
    target_tcert_id: str
    type: str  # 'prospective' | 'retrospective'
    reason: str | None = None
    issued_at: int | None = None


@dataclass
class RevokeKeyParams:
    signer_key_id: str
    target_key_id: str
    reason: str | None = None
    issued_at: int | None = None


@dataclass
class BlockSdocParams:
    signer_key_id: str
    target_sdoc_id: str
    reason: str | None = None
    issued_at: int | None = None


@dataclass
class StatementResult:
    statement_id: str
    bytes: bytes


class RevocationService:
    def __init__(self, deps: ServiceDeps) -> None:
        self._deps = deps

    async def revoke_tcert(self, params: RevokeTcertParams) -> StatementResult:
        target = split_tcert_id(params.target_tcert_id)
        authorized = params.signer_key_id == target[0] or await self.is_authorized_ca(
            params.signer_key_id, params.target_tcert_id
        )
        if not authorized:
            raise QrsAuthorizationError("Signer is not authorized to revoke this TCert")
        issued_at = params.issued_at if params.issued_at is not None else self._deps.clock.now()
        built = await self._sign_statement(
            params.signer_key_id,
            "revokeTcert",
            StatementTarget(kind="tcert", key_id=target[0], certificate_number=target[1]),
            issued_at,
            StatementOptions(reason=params.reason, revocation_type=params.type),
        )
        await self._deps.revocation_store.add_revoked_tcert(
            params.target_tcert_id,
            RevocationEntry(type=params.type, issued_at=issued_at, reason=params.reason),
        )
        return built

    async def revoke_key(self, params: RevokeKeyParams) -> StatementResult:
        if params.signer_key_id != params.target_key_id:
            raise QrsAuthorizationError("Only the key owner may revoke its own key")
        issued_at = params.issued_at if params.issued_at is not None else self._deps.clock.now()
        built = await self._sign_statement(
            params.signer_key_id,
            "revokeTcert",
            StatementTarget(kind="key", key_id=params.target_key_id),
            issued_at,
            StatementOptions(reason=params.reason, revocation_type="retrospective"),
        )
        await self._deps.revocation_store.add_revoked_key(
            params.target_key_id,
            RevocationEntry(type="retrospective", issued_at=issued_at, reason=params.reason),
        )
        return built

    async def block_sdoc(self, params: BlockSdocParams) -> StatementResult:
        sdoc_bytes = await self._deps.document_store.get(params.target_sdoc_id)
        if not sdoc_bytes:
            raise QrsNotFoundError(f"SDoc not found: {params.target_sdoc_id}")
        parsed = parse_signed_object(sdoc_bytes)
        tcert_key_id = to_hex(parsed.data["tcertKeyId"])
        tcert_id = tcert_id_of(tcert_key_id, parsed.data["tcertNumber"])
        authorized = params.signer_key_id == tcert_key_id or await self.is_authorized_ca(
            params.signer_key_id, tcert_id
        )
        if not authorized:
            raise QrsAuthorizationError("Signer is not authorized to block this SDoc")
        issued_at = params.issued_at if params.issued_at is not None else self._deps.clock.now()
        built = await self._sign_statement(
            params.signer_key_id,
            "blockSdoc",
            StatementTarget(kind="sdoc", sdoc_id=params.target_sdoc_id),
            issued_at,
            StatementOptions(reason=params.reason),
        )
        await self._deps.revocation_store.add_blocked_sdoc(
            params.target_sdoc_id, {"issued_at": issued_at, "reason": params.reason}
        )
        return built

    async def unblock_sdoc(self, params: BlockSdocParams) -> StatementResult:
        sdoc_bytes = await self._deps.document_store.get(params.target_sdoc_id)
        if not sdoc_bytes:
            raise QrsNotFoundError(f"SDoc not found: {params.target_sdoc_id}")
        parsed = parse_signed_object(sdoc_bytes)
        tcert_key_id = to_hex(parsed.data["tcertKeyId"])
        tcert_id = tcert_id_of(tcert_key_id, parsed.data["tcertNumber"])
        authorized = params.signer_key_id == tcert_key_id or await self.is_authorized_ca(
            params.signer_key_id, tcert_id
        )
        if not authorized:
            raise QrsAuthorizationError("Signer is not authorized to unblock this SDoc")
        issued_at = params.issued_at if params.issued_at is not None else self._deps.clock.now()
        built = await self._sign_statement(
            params.signer_key_id,
            "unblockSdoc",
            StatementTarget(kind="sdoc", sdoc_id=params.target_sdoc_id),
            issued_at,
            StatementOptions(reason=params.reason),
        )
        await self._deps.revocation_store.remove_blocked_sdoc(params.target_sdoc_id)
        return built

    async def check_revocation(self, tcert_id: str, key_id: str, issued_at: int, sdoc_id: str) -> RevocationCheck:
        key_entry = await self._deps.revocation_store.get_revoked_key(key_id)
        if key_entry:
            return RevocationCheck(
                state="invalid",
                message=f"issuer key revoked ({key_entry.reason or 'key compromised'})",
            )
        tcert_entry = await self._deps.revocation_store.get_revoked_tcert(tcert_id)
        if tcert_entry:
            if tcert_entry.type == "retrospective":
                return RevocationCheck(state="invalid", message="TCert retrospectively revoked")
            if issued_at >= tcert_entry.issued_at:
                return RevocationCheck(
                    state="invalid",
                    message="TCert prospectively revoked for documents issued at/after revocation",
                )
            return RevocationCheck(state="valid", message="document issued before prospective revocation")
        block = await self._deps.revocation_store.get_blocked_sdoc(sdoc_id)
        if block:
            return RevocationCheck(state="invalid", message="SDoc is blocked")
        return RevocationCheck(state="valid")

    async def is_authorized_ca(self, signer_key_id: str, target_tcert_id: str) -> bool:
        attestations = await self._deps.trust_store.get_attestations(target_tcert_id)
        for att in attestations:
            if att.ca_key_id != signer_key_id:
                continue
            ca_bytes = await self._deps.certificate_store.get(att.ca_tcert_id)
            if not ca_bytes:
                continue
            try:
                parse_signed_object(ca_bytes)
            except Exception:
                continue
            if await self._deps.revocation_store.get_revoked_tcert(att.ca_tcert_id):
                continue
            if await self._deps.revocation_store.get_revoked_key(signer_key_id):
                continue
            if await self._deps.trust_store.is_distrusted(att.ca_tcert_id):
                continue
            if not await self._deps.trust_store.is_pinned(att.ca_tcert_id) and not await self._deps.trust_store.is_ca(
                att.ca_tcert_id
            ):
                continue
            return True
        return False

    async def _sign_statement(
        self,
        signer_key_id: str,
        action: str,
        target: StatementTarget,
        issued_at: int,
        options: StatementOptions,
    ) -> StatementResult:
        priv = await self._deps.private_key_store.load(signer_key_id)
        if not priv:
            raise QrsNotFoundError(f"Signer private key not available: {signer_key_id}")
        pub = await self._deps.public_key_store.load(signer_key_id)
        if not pub:
            raise QrsNotFoundError(f"Signer public key not found: {signer_key_id}")
        provider = self._deps.crypto_registry.get(pub["algorithm"])
        key_pair = KeyPairMaterial(
            algorithm=pub["algorithm"],
            public_jwk=pub["public_jwk"],
            private_jwk=priv["private_jwk"],
        )
        built = build_statement(action, target, issued_at, options, key_pair, provider)
        if not verify_statement(built.parsed, pub["public_jwk"], provider):
            raise QrsCryptoError("Statement failed signature verification")
        return StatementResult(statement_id=built.statement_id, bytes=built.bytes)