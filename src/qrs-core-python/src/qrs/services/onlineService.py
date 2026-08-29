"""OnlineService: applying signed objects fetched from distribution servers.

The distribution server is never trusted. A verifier that downloads a signed
statement (an attestation, a revocation, a block) applies it to its local stores only after
the statement's signature verifies against the signer's TCert public key. This is
what makes server-hosted "revocation lists", attestations and attested
certificates usable offline and tamper-evident.

Importing a statement is idempotent at the store level (records are keyed by
target + signer); re-importing a statement the device already holds is a no-op.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..deps import ServiceDeps
from ..envelope import parse_signed_object, tcert_hash_of, tcert_id_of, verify_parsed_signed_object
from ..errors import QrsParseError
from ..signed_object import is_action
from .statement import parse_statement, verify_statement
from ..storage.interfaces import AttestationRecord, BlockEntry, RevocationEntry

__all__ = ["OnlineService", "ImportedStatement"]


@dataclass
class ImportedStatement:
    applied: bool
    reason: str | None = None
    action: str | None = None
    target: str | None = None
    statement_id: str | None = None


class OnlineService:
    def __init__(self, deps: ServiceDeps) -> None:
        self._deps = deps

    async def import_statement(self, data: bytes) -> ImportedStatement:
        try:
            stmt = parse_statement(data)
        except Exception as exc:
            return ImportedStatement(
                applied=False,
                reason="malformed statement" if isinstance(exc, QrsParseError) else "unsupported statement",
            )
        if not is_action(stmt.action):
            return ImportedStatement(
                applied=False,
                reason=f"unsupported action: {stmt.action}",
                statement_id=stmt.statement_id,
            )

        # The signer must be a TCert we hold locally; verify the statement against
        # its public key. Prefer a CA-configured TCert of the signer key when one exists.
        signer_tcerts = await self._deps.certificate_store.find_by_key_id(stmt.signer_key_id)
        ca_preferred: str | None = None
        fallback: str | None = None
        for tcert_id, tcert_bytes in signer_tcerts:
            try:
                parsed = parse_signed_object(tcert_bytes)
            except Exception:
                continue
            if parsed.type != "tcert":
                continue
            pub = parsed.data["publicKey"]
            provider = self._deps.crypto_registry.get(parsed.algorithm)
            if verify_statement(stmt.parsed, pub, provider):
                if await self._deps.trust_store.is_ca(tcert_id):
                    ca_preferred = tcert_id
                if fallback is None:
                    fallback = tcert_id
        signer_tcert_id = ca_preferred or fallback
        if signer_tcert_id is None:
            return ImportedStatement(
                applied=False,
                reason="no signer TCert locally or signature invalid",
                statement_id=stmt.statement_id,
            )

        issued_at = stmt.issued_at
        if stmt.action == "attest":
            if stmt.target.kind != "tcert":
                return ImportedStatement(
                    applied=False,
                    reason=f"unsupported target for {stmt.action}",
                    statement_id=stmt.statement_id,
                )
            target_tcert_id = tcert_id_of(
                stmt.target.key_id or "", stmt.target.certificate_number or 0
            )
            # The attestation binds the exact TCert content hash. When the target
            # TCert is available locally, verify the binding before applying; when
            # it is not yet available (offline-first, order-independent import),
            # apply with the statement's bound hash so the binding is checked later.
            target_bytes = await self._deps.certificate_store.get(target_tcert_id)
            tcert_hash = stmt.target.tcert_hash or ""
            if target_bytes:
                try:
                    target_parsed = parse_signed_object(target_bytes)
                except Exception:
                    return ImportedStatement(
                        applied=False, reason="malformed target TCert", statement_id=stmt.statement_id
                    )
                computed = tcert_hash_of(target_parsed)
                if stmt.target.tcert_hash is not None and stmt.target.tcert_hash != computed:
                    return ImportedStatement(
                        applied=False,
                        reason="attestation TCert hash mismatch",
                        statement_id=stmt.statement_id,
                    )
                tcert_hash = computed
            await self._deps.trust_store.add_attestation(
                AttestationRecord(
                    target_tcert_id=target_tcert_id,
                    ca_tcert_id=signer_tcert_id,
                    ca_key_id=stmt.signer_key_id,
                    tcert_hash=tcert_hash,
                    claims=stmt.claims,
                    issued_at=issued_at,
                    statement_bytes=data,
                )
            )
            return ImportedStatement(
                applied=True, action="attest", target=target_tcert_id, statement_id=stmt.statement_id
            )

        if stmt.action == "revokeTcert":
            entry = RevocationEntry(
                type=stmt.revocation_type or "retrospective",
                issued_at=issued_at,
                reason=stmt.reason,
            )
            if stmt.target.kind == "tcert":
                target_tcert_id = tcert_id_of(
                    stmt.target.key_id or "", stmt.target.certificate_number or 0
                )
                await self._deps.revocation_store.add_revoked_tcert(target_tcert_id, entry)
                return ImportedStatement(
                    applied=True, action="revokeTcert", target=target_tcert_id, statement_id=stmt.statement_id
                )
            if stmt.target.kind == "key":
                await self._deps.revocation_store.add_revoked_key(stmt.target.key_id or "", entry)
                return ImportedStatement(
                    applied=True, action="revokeTcert", target=stmt.target.key_id, statement_id=stmt.statement_id
                )
            return ImportedStatement(
                applied=False,
                reason=f"unsupported target for {stmt.action}",
                statement_id=stmt.statement_id,
            )

        if stmt.action == "blockSdoc":
            if stmt.target.kind != "sdoc":
                return ImportedStatement(
                    applied=False,
                    reason=f"unsupported target for {stmt.action}",
                    statement_id=stmt.statement_id,
                )
            await self._deps.revocation_store.add_blocked_sdoc(
                stmt.target.sdoc_id or "",
                BlockEntry(issued_at=issued_at, reason=stmt.reason),
            )
            return ImportedStatement(
                applied=True, action="blockSdoc", target=stmt.target.sdoc_id, statement_id=stmt.statement_id
            )

        if stmt.action == "unblockSdoc":
            if stmt.target.kind != "sdoc":
                return ImportedStatement(
                    applied=False,
                    reason=f"unsupported target for {stmt.action}",
                    statement_id=stmt.statement_id,
                )
            await self._deps.revocation_store.remove_blocked_sdoc(stmt.target.sdoc_id or "")
            return ImportedStatement(
                applied=True, action="unblockSdoc", target=stmt.target.sdoc_id, statement_id=stmt.statement_id
            )

        return ImportedStatement(
            applied=False, reason=f"unsupported action: {stmt.action}", statement_id=stmt.statement_id
        )

    async def import_tcert(self, data: bytes) -> dict[str, Any]:
        """Verify a TCert object (downloaded from a server) and store it locally."""
        try:
            parsed = parse_signed_object(data)
            if parsed.type != "tcert":
                return {"imported": False, "reason": "not a TCert"}
            key_id = parsed.signer_key_id
            certificate_number = parsed.data["certificateNumber"]
            tcert_id = tcert_id_of(key_id, certificate_number)
            provider = self._deps.crypto_registry.get(parsed.algorithm)
            pub = parsed.data["publicKey"]
            if not verify_parsed_signed_object(parsed, provider, pub):
                return {"imported": False, "reason": "TCert self-signature invalid"}
            if provider.key_id(pub) != key_id:
                return {"imported": False, "reason": "TCert key id mismatch"}
            await self._deps.certificate_store.save(tcert_id, data)
            return {"imported": True, "tcert_id": tcert_id}
        except Exception:
            return {"imported": False, "reason": "malformed TCert"}