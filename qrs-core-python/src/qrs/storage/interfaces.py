"""Storage interfaces (the IoC seam).

The core only ever depends on these interfaces — it never calls platform APIs. The
default wiring uses in-memory implementations; the CLI uses JSON-file-backed ones.
A consumer may implement them (e.g. on a database, a secure vault, or an HSM) and
inject them into ``create_qrs`` — the rest of the package is completely unaware.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

# Identifier / type aliases (informational; kept minimal to avoid import cycles).
KeyId = str  # hex, 32 chars (128-bit truncated SHA-256 of the canonical public key)
TcertId = str  # f"{keyId}:{certificateNumber}"
SdocId = str  # hex, 32 chars (128-bit truncated SHA-256 of the signed SDoc)
StatementId = str  # hex, 32 chars (random)
AlgorithmId = str  # 'Ed25519' | 'ECDSA-P256'
RevocationType = str  # 'prospective' | 'retrospective'

__all__ = [
    "IPrivateKeyStore",
    "IPublicKeyStore",
    "ICertificateStore",
    "IDocumentStore",
    "IRevocationStore",
    "ITrustStore",
    "IEndpointConfigStore",
    "AttestationRecord",
    "RevocationEntry",
    "BlockEntry",
]


@dataclass
class RevocationEntry:
    type: RevocationType
    issued_at: int  # epoch seconds (statement issuance time)
    reason: str | None = None


@dataclass
class BlockEntry:
    issued_at: int
    reason: str | None = None


@dataclass
class AttestationRecord:
    target_tcert_id: TcertId
    ca_tcert_id: TcertId
    ca_key_id: KeyId
    tcert_hash: str  # NEW — content hash of the attested TCert
    claims: dict[str, Any] | None = None
    issued_at: int = 0
    statement_bytes: bytes = b""


class IPrivateKeyStore(Protocol):
    async def save(self, key_id: KeyId, algorithm: AlgorithmId, private_jwk: dict[str, Any]) -> None: ...

    async def load(self, key_id: KeyId) -> dict[str, Any] | None: ...

    async def has(self, key_id: KeyId) -> bool: ...

    async def all(self) -> list[dict[str, Any]]: ...


class IPublicKeyStore(Protocol):
    async def save(self, key_id: KeyId, algorithm: AlgorithmId, public_jwk: dict[str, Any]) -> None: ...

    async def load(self, key_id: KeyId) -> dict[str, Any] | None: ...

    async def has(self, key_id: KeyId) -> bool: ...

    async def all(self) -> list[dict[str, Any]]: ...


class ICertificateStore(Protocol):
    async def save(self, tcert_id: TcertId, data: bytes) -> None: ...

    async def get(self, tcert_id: TcertId) -> bytes | None: ...

    async def find_by_key_id(self, key_id: KeyId) -> list[tuple[TcertId, bytes]]: ...

    async def all(self) -> list[tuple[TcertId, bytes]]: ...

    async def remove(self, tcert_id: TcertId) -> None: ...


class IDocumentStore(Protocol):
    async def save(self, sdoc_id: SdocId, data: bytes) -> None: ...

    async def get(self, sdoc_id: SdocId) -> bytes | None: ...

    async def all(self) -> list[tuple[SdocId, bytes]]: ...

    async def remove(self, sdoc_id: SdocId) -> None: ...


class IRevocationStore(Protocol):
    async def add_revoked_tcert(self, tcert_id: TcertId, entry: RevocationEntry) -> None: ...

    async def get_revoked_tcert(self, tcert_id: TcertId) -> RevocationEntry | None: ...

    async def list_revoked_tcerts(self) -> list[tuple[TcertId, RevocationEntry]]: ...

    async def add_revoked_key(self, key_id: KeyId, entry: RevocationEntry) -> None: ...

    async def get_revoked_key(self, key_id: KeyId) -> RevocationEntry | None: ...

    async def list_revoked_keys(self) -> list[tuple[KeyId, RevocationEntry]]: ...

    async def add_blocked_sdoc(self, sdoc_id: SdocId, entry: BlockEntry) -> None: ...

    async def get_blocked_sdoc(self, sdoc_id: SdocId) -> BlockEntry | None: ...

    async def list_blocked_sdocs(self) -> list[tuple[SdocId, BlockEntry]]: ...

    async def remove_blocked_sdoc(self, sdoc_id: SdocId) -> None: ...


class ITrustStore(Protocol):
    async def add_pinned(self, tcert_id: TcertId) -> None: ...

    async def remove_pinned(self, tcert_id: TcertId) -> None: ...

    async def is_pinned(self, tcert_id: TcertId) -> bool: ...

    async def list_pinned(self) -> list[TcertId]: ...

    async def add_ca(self, tcert_id: TcertId) -> None: ...

    async def remove_ca(self, tcert_id: TcertId) -> None: ...

    async def is_ca(self, tcert_id: TcertId) -> bool: ...

    async def list_ca(self) -> list[TcertId]: ...

    async def add_attestation(self, record: AttestationRecord) -> None: ...

    async def get_attestations(self, target_tcert_id: TcertId) -> list[AttestationRecord]: ...

    async def add_distrusted(self, tcert_id: TcertId) -> None: ...

    async def remove_distrusted(self, tcert_id: TcertId) -> None: ...

    async def is_distrusted(self, tcert_id: TcertId) -> bool: ...


class IEndpointConfigStore(Protocol):
    """Mutable, app-local mirror endpoints for a TCert (distribution convenience,
    NOT part of the signed protocol data). The signed ``onlineEndpoint`` is the fixed
    default; this store holds extra mirrors. Servers are untrusted mirrors:
    everything downloaded is still verified cryptographically."""

    async def get_endpoints(self, tcert_id: TcertId) -> list[str]: ...

    async def set_endpoints(self, tcert_id: TcertId, endpoints: list[str]) -> None: ...

    async def add_endpoint(self, tcert_id: TcertId, endpoint: str) -> None: ...

    async def remove_endpoint(self, tcert_id: TcertId, endpoint: str) -> None: ...