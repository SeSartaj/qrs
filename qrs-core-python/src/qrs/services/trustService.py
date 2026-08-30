"""TrustService: pinning, CA roles, attestations, and trust resolution.

Trust model (v1): two levels.

- Pinned TCert: the verifier explicitly trusts the TCert.
- CA-issued TCert: a TCert granted CA authority has signed an ``attest``
  statement about the target TCert.

A TCert can be trusted through both mechanisms at once (dual endorsement). The
CA is not a special object type — it is an ordinary TCert the verifier has
configured with CA authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..crypto.providers import KeyPairMaterial
from ..deps import ServiceDeps
from ..envelope import (
    parse_signed_object,
    split_tcert_id,
    tcert_hash_of,
    tcert_id_of,
    verify_parsed_signed_object,
)
from ..errors import QrsAuthorizationError, QrsCryptoError, QrsNotFoundError, QrsValidationError
from .statement import StatementOptions, StatementTarget, build_statement, parse_statement, verify_statement
from ..storage.interfaces import AttestationRecord

__all__ = ["TrustService", "TrustResolution", "AttestParams", "AddTcertParams"]


@dataclass
class TrustResolution:
    state: str  # 'valid' | 'invalid' | 'cannotVerify'
    pinned: bool = False
    ca: dict[str, str | None] | None = None
    message: str | None = None


@dataclass
class AttestParams:
    ca_tcert_id: str
    target_tcert_id: str
    claims: dict[str, Any] | None = None
    issued_at: int | None = None


@dataclass
class AddTcertParams(AttestParams):
    tcert_bytes: bytes | None = None


class TrustService:
    def __init__(self, deps: ServiceDeps) -> None:
        self._deps = deps

    async def pin(self, tcert_id: str) -> None:
        await self._ensure_tcert(tcert_id)
        await self._deps.trust_store.add_pinned(tcert_id)

    async def unpin(self, tcert_id: str) -> None:
        await self._deps.trust_store.remove_pinned(tcert_id)

    async def add_ca(self, tcert_id: str) -> None:
        await self._ensure_tcert(tcert_id)
        await self._deps.trust_store.add_ca(tcert_id)

    async def remove_ca(self, tcert_id: str) -> None:
        await self._deps.trust_store.remove_ca(tcert_id)

    async def distrust(self, tcert_id: str) -> None:
        await self._deps.trust_store.add_distrusted(tcert_id)

    async def trust_again(self, tcert_id: str) -> None:
        await self._deps.trust_store.remove_distrusted(tcert_id)

    async def attest(self, params: AttestParams) -> dict[str, Any]:
        if not await self._deps.trust_store.is_ca(params.ca_tcert_id):
            raise QrsAuthorizationError(f"TCert {params.ca_tcert_id} is not configured as a CA")
        # Prevent duplicate attestations: the same CA must not attest the same target twice.
        existing = await self._deps.trust_store.get_attestations(params.target_tcert_id)
        if any(record.ca_tcert_id == params.ca_tcert_id for record in existing):
            raise QrsValidationError(
                f"TCert {params.target_tcert_id} is already attested by {params.ca_tcert_id}"
            )
        ca = await self._key_info_of(params.ca_tcert_id)
        priv = await self._deps.private_key_store.load(ca["key_id"])
        if not priv:
            raise QrsNotFoundError(f"CA private key not available: {ca['key_id']}")

        target = split_tcert_id(params.target_tcert_id)
        # The attestation binds the content hash of the specific TCert being attested.
        target_bytes = await self._deps.certificate_store.get(params.target_tcert_id)
        if not target_bytes:
            raise QrsNotFoundError(f"TCert not found: {params.target_tcert_id}")
        target_parsed = parse_signed_object(target_bytes)
        tcert_hash = tcert_hash_of(target_parsed)
        issued_at = params.issued_at if params.issued_at is not None else self._deps.clock.now()
        key_pair = KeyPairMaterial(
            algorithm=ca["algorithm"],
            public_jwk=ca["public_jwk"],
            private_jwk=priv["private_jwk"],
        )
        built = build_statement(
            "attest",
            StatementTarget(
                kind="tcert",
                key_id=target[0],
                certificate_number=target[1],
                tcert_hash=tcert_hash,
            ),
            issued_at,
            StatementOptions(claims=params.claims),
            key_pair,
            self._deps.crypto_registry.get(ca["algorithm"]),
        )
        if not verify_statement(built.parsed, ca["public_jwk"], self._deps.crypto_registry.get(ca["algorithm"])):
            raise QrsCryptoError("Attestation statement failed verification")
        record = AttestationRecord(
            target_tcert_id=params.target_tcert_id,
            ca_tcert_id=params.ca_tcert_id,
            ca_key_id=ca["key_id"],
            tcert_hash=tcert_hash,
            claims=params.claims,
            issued_at=issued_at,
            statement_bytes=built.bytes,
        )
        await self._deps.trust_store.add_attestation(record)
        return {"statement_id": built.statement_id, "bytes": built.bytes}

    async def add_tcert(self, params: AddTcertParams) -> dict[str, Any]:
        if params.tcert_bytes:
            parsed = parse_signed_object(params.tcert_bytes)
            if parsed.type != "tcert":
                raise QrsValidationError("Provided object is not a TCert")
            tcert_id = tcert_id_of(parsed.signer_key_id, parsed.data["certificateNumber"])
            if tcert_id != params.target_tcert_id:
                raise QrsValidationError("Provided TCert bytes do not match the target tcert id")
            await self._deps.certificate_store.save(tcert_id, params.tcert_bytes)
        return await self.attest(AttestParams(
            ca_tcert_id=params.ca_tcert_id,
            target_tcert_id=params.target_tcert_id,
            claims=params.claims,
            issued_at=params.issued_at,
        ))

    async def resolve_trust(self, tcert_id: str, parsed: Any = None) -> TrustResolution:
        if await self._deps.trust_store.is_distrusted(tcert_id):
            return TrustResolution(state="invalid", pinned=False, message="TCert is locally distrusted")
        pinned = await self._deps.trust_store.is_pinned(tcert_id)
        attestations = await self._deps.trust_store.get_attestations(tcert_id)
        ca: dict[str, str | None] | None = None
        for att in attestations:
            if await self._is_valid_attestation(att):
                ca = {
                    "ca_tcert_id": att.ca_tcert_id,
                    "ca_name": att.claims.get("name") if att.claims else None,
                }
                break
        if pinned:
            return TrustResolution(state="valid", pinned=True, ca=ca)
        if ca:
            return TrustResolution(state="valid", pinned=False, ca=ca)
        return TrustResolution(
            state="cannotVerify",
            pinned=False,
            message="no trust path: TCert is neither pinned nor attested by a trusted CA",
        )

    async def is_trusted_ca(self, ca_tcert_id: str) -> bool:
        if await self._deps.trust_store.is_distrusted(ca_tcert_id):
            return False
        if await self._deps.revocation_store.get_revoked_tcert(ca_tcert_id):
            return False
        pinned = await self._deps.trust_store.is_pinned(ca_tcert_id)
        is_ca = await self._deps.trust_store.is_ca(ca_tcert_id)
        return pinned or is_ca

    async def _is_valid_attestation(self, att: AttestationRecord) -> bool:
        ca_bytes = await self._deps.certificate_store.get(att.ca_tcert_id)
        if not ca_bytes:
            return False
        try:
            ca_parsed = parse_signed_object(ca_bytes)
        except Exception:
            return False
        if ca_parsed.type != "tcert":
            return False
        provider = self._deps.crypto_registry.get(ca_parsed.algorithm)
        ca_pub = ca_parsed.data["publicKey"]
        if not verify_parsed_signed_object(ca_parsed, provider, ca_pub):
            return False
        if not await self.is_trusted_ca(att.ca_tcert_id):
            return False
        if await self._deps.revocation_store.get_revoked_key(att.ca_key_id):
            return False

        try:
            stmt = parse_statement(att.statement_bytes)
        except Exception:
            return False
        if stmt.action != "attest":
            return False
        if stmt.target.kind != "tcert":
            return False
        if tcert_id_of(stmt.target.key_id or "", stmt.target.certificate_number or 0) != att.target_tcert_id:
            return False
        if stmt.signer_key_id != att.ca_key_id:
            return False

        # The attestation must bind the exact content hash of the TCert it is about.
        target_bytes = await self._deps.certificate_store.get(att.target_tcert_id)
        if not target_bytes:
            return False
        try:
            target_parsed = parse_signed_object(target_bytes)
        except Exception:
            return False
        if tcert_hash_of(target_parsed) != att.tcert_hash:
            return False
        if stmt.target.tcert_hash != att.tcert_hash:
            return False

        return verify_statement(stmt.parsed, ca_pub, provider)

    async def _ensure_tcert(self, tcert_id: str) -> None:
        data = await self._deps.certificate_store.get(tcert_id)
        if not data:
            raise QrsNotFoundError(f"TCert not found: {tcert_id}")

    async def _key_info_of(self, tcert_id: str) -> dict[str, Any]:
        data = await self._deps.certificate_store.get(tcert_id)
        if not data:
            raise QrsNotFoundError(f"TCert not found: {tcert_id}")
        parsed = parse_signed_object(data)
        return {
            "key_id": parsed.signer_key_id,
            "algorithm": parsed.data["algorithm"],
            "public_jwk": parsed.data["publicKey"],
        }