"""Default in-memory and JSON-file-backed store implementations.

Everything the CLI persists lives here. A consumer who wants a database or a key
vault simply implements the interfaces in :mod:`qrs.storage.interfaces` and
injects them into ``create_qrs``.
"""

from __future__ import annotations

import json
import os
from typing import Any

from ..id import from_base64url, to_base64url
from .interfaces import (
    AttestationRecord,
    BlockEntry,
    IEndpointConfigStore,
    ICertificateStore,
    IDocumentStore,
    IPrivateKeyStore,
    IPublicKeyStore,
    IRevocationStore,
    ITrustStore,
    RevocationEntry,
)

__all__ = [
    "InMemoryPrivateKeyStore",
    "InMemoryPublicKeyStore",
    "InMemoryCertificateStore",
    "InMemoryDocumentStore",
    "InMemoryRevocationStore",
    "InMemoryTrustStore",
    "InMemoryEndpointConfigStore",
    "create_in_memory_stores",
    "FilePrivateKeyStore",
    "FilePublicKeyStore",
    "FileCertificateStore",
    "FileDocumentStore",
    "FileRevocationStore",
    "FileTrustStore",
    "FileEndpointConfigStore",
    "create_file_stores",
]


class InMemoryPrivateKeyStore(IPrivateKeyStore):
    def __init__(self) -> None:
        self._map: dict[str, dict[str, Any]] = {}

    async def save(self, key_id: str, algorithm: str, private_jwk: dict[str, Any]) -> None:
        self._map[key_id] = {"algorithm": algorithm, "private_jwk": private_jwk}

    async def load(self, key_id: str) -> dict[str, Any] | None:
        return self._map.get(key_id)

    async def has(self, key_id: str) -> bool:
        return key_id in self._map

    async def all(self) -> list[dict[str, Any]]:
        return [{"key_id": key_id, "algorithm": v["algorithm"]} for key_id, v in self._map.items()]


class InMemoryPublicKeyStore(IPublicKeyStore):
    def __init__(self) -> None:
        self._map: dict[str, dict[str, Any]] = {}

    async def save(self, key_id: str, algorithm: str, public_jwk: dict[str, Any]) -> None:
        self._map[key_id] = {"algorithm": algorithm, "public_jwk": public_jwk}

    async def load(self, key_id: str) -> dict[str, Any] | None:
        return self._map.get(key_id)

    async def has(self, key_id: str) -> bool:
        return key_id in self._map

    async def all(self) -> list[dict[str, Any]]:
        return [{"key_id": key_id, **v} for key_id, v in self._map.items()]


class InMemoryCertificateStore(ICertificateStore):
    def __init__(self) -> None:
        self._map: dict[str, bytes] = {}

    async def save(self, tcert_id: str, data: bytes) -> None:
        self._map[tcert_id] = data

    async def get(self, tcert_id: str) -> bytes | None:
        return self._map.get(tcert_id)

    async def find_by_key_id(self, key_id: str) -> list[tuple[str, bytes]]:
        return [(t, b) for t, b in self._map.items() if t.startswith(f"{key_id}:")]

    async def all(self) -> list[tuple[str, bytes]]:
        return list(self._map.items())

    async def remove(self, tcert_id: str) -> None:
        self._map.pop(tcert_id, None)


class InMemoryDocumentStore(IDocumentStore):
    def __init__(self) -> None:
        self._map: dict[str, bytes] = {}

    async def save(self, sdoc_id: str, data: bytes) -> None:
        self._map[sdoc_id] = data

    async def get(self, sdoc_id: str) -> bytes | None:
        return self._map.get(sdoc_id)

    async def all(self) -> list[tuple[str, bytes]]:
        return list(self._map.items())

    async def remove(self, sdoc_id: str) -> None:
        self._map.pop(sdoc_id, None)


class InMemoryRevocationStore(IRevocationStore):
    def __init__(self) -> None:
        self._revoked_tcerts: dict[str, RevocationEntry] = {}
        self._revoked_keys: dict[str, RevocationEntry] = {}
        self._blocked_sdocs: dict[str, BlockEntry] = {}

    async def add_revoked_tcert(self, tcert_id: str, entry: RevocationEntry) -> None:
        self._revoked_tcerts[tcert_id] = entry

    async def get_revoked_tcert(self, tcert_id: str) -> RevocationEntry | None:
        return self._revoked_tcerts.get(tcert_id)

    async def list_revoked_tcerts(self) -> list[tuple[str, RevocationEntry]]:
        return list(self._revoked_tcerts.items())

    async def add_revoked_key(self, key_id: str, entry: RevocationEntry) -> None:
        self._revoked_keys[key_id] = entry

    async def get_revoked_key(self, key_id: str) -> RevocationEntry | None:
        return self._revoked_keys.get(key_id)

    async def list_revoked_keys(self) -> list[tuple[str, RevocationEntry]]:
        return list(self._revoked_keys.items())

    async def add_blocked_sdoc(self, sdoc_id: str, entry: BlockEntry) -> None:
        self._blocked_sdocs[sdoc_id] = entry

    async def get_blocked_sdoc(self, sdoc_id: str) -> BlockEntry | None:
        return self._blocked_sdocs.get(sdoc_id)

    async def list_blocked_sdocs(self) -> list[tuple[str, BlockEntry]]:
        return list(self._blocked_sdocs.items())

    async def remove_blocked_sdoc(self, sdoc_id: str) -> None:
        self._blocked_sdocs.pop(sdoc_id, None)


class InMemoryTrustStore(ITrustStore):
    def __init__(self) -> None:
        self._pinned: set[str] = set()
        self._cas: set[str] = set()
        self._distrusted: set[str] = set()
        self._attestations: dict[str, list[AttestationRecord]] = {}

    async def add_pinned(self, tcert_id: str) -> None:
        self._pinned.add(tcert_id)

    async def remove_pinned(self, tcert_id: str) -> None:
        self._pinned.discard(tcert_id)

    async def is_pinned(self, tcert_id: str) -> bool:
        return tcert_id in self._pinned

    async def list_pinned(self) -> list[str]:
        return list(self._pinned)

    async def add_ca(self, tcert_id: str) -> None:
        self._cas.add(tcert_id)

    async def remove_ca(self, tcert_id: str) -> None:
        self._cas.discard(tcert_id)

    async def is_ca(self, tcert_id: str) -> bool:
        return tcert_id in self._cas

    async def list_ca(self) -> list[str]:
        return list(self._cas)

    async def add_attestation(self, record: AttestationRecord) -> None:
        records = self._attestations.setdefault(record.target_tcert_id, [])
        records.append(record)

    async def get_attestations(self, target_tcert_id: str) -> list[AttestationRecord]:
        return self._attestations.get(target_tcert_id, [])

    async def add_distrusted(self, tcert_id: str) -> None:
        self._distrusted.add(tcert_id)

    async def remove_distrusted(self, tcert_id: str) -> None:
        self._distrusted.discard(tcert_id)

    async def is_distrusted(self, tcert_id: str) -> bool:
        return tcert_id in self._distrusted


class InMemoryEndpointConfigStore(IEndpointConfigStore):
    def __init__(self) -> None:
        self._map: dict[str, list[str]] = {}

    async def get_endpoints(self, tcert_id: str) -> list[str]:
        return list(self._map.get(tcert_id, []))

    async def set_endpoints(self, tcert_id: str, endpoints: list[str]) -> None:
        self._map[tcert_id] = list(dict.fromkeys(endpoints))

    async def add_endpoint(self, tcert_id: str, endpoint: str) -> None:
        endpoints = self._map.setdefault(tcert_id, [])
        if endpoint not in endpoints:
            endpoints.append(endpoint)

    async def remove_endpoint(self, tcert_id: str, endpoint: str) -> None:
        endpoints = self._map.get(tcert_id, [])
        if endpoint in endpoints:
            self._map[tcert_id] = [e for e in endpoints if e != endpoint]


def create_in_memory_stores() -> dict[str, Any]:
    """All default in-memory stores as one dict (convenience)."""
    return {
        "private_key_store": InMemoryPrivateKeyStore(),
        "public_key_store": InMemoryPublicKeyStore(),
        "certificate_store": InMemoryCertificateStore(),
        "document_store": InMemoryDocumentStore(),
        "revocation_store": InMemoryRevocationStore(),
        "trust_store": InMemoryTrustStore(),
        "endpoint_config_store": InMemoryEndpointConfigStore(),
    }


class _JsonFileStore:
    """A minimal JSON-file-backed key→value store (synchronous, atomic-ish writes)."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._map: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path, "r", encoding="utf-8") as handle:
                parsed = json.load(handle)
            if isinstance(parsed, dict):
                self._map = parsed
        except (OSError, ValueError):
            self._map = {}

    def _persist(self) -> None:
        directory = os.path.dirname(self._path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as handle:
            json.dump(self._map, handle, ensure_ascii=False, sort_keys=True)

    def get(self, key: str) -> Any | None:
        return self._map.get(key)

    def set(self, key: str, value: Any) -> None:
        self._map[key] = value
        self._persist()

    def delete(self, key: str) -> None:
        if key in self._map:
            del self._map[key]
            self._persist()

    def entries(self) -> list[tuple[str, Any]]:
        return list(self._map.items())


def _bytes_encode(value: bytes) -> str:
    return to_base64url(value)


def _bytes_decode(raw: Any) -> bytes:
    return from_base64url(str(raw))


class FilePrivateKeyStore(IPrivateKeyStore):
    def __init__(self, directory: str) -> None:
        self._store = _JsonFileStore(os.path.join(directory, "private-keys.json"))

    async def save(self, key_id: str, algorithm: str, private_jwk: dict[str, Any]) -> None:
        self._store.set(key_id, {"algorithm": algorithm, "private_jwk": private_jwk})

    async def load(self, key_id: str) -> dict[str, Any] | None:
        return self._store.get(key_id)

    async def has(self, key_id: str) -> bool:
        return self._store.get(key_id) is not None

    async def all(self) -> list[dict[str, Any]]:
        return [{"key_id": k, "algorithm": v["algorithm"]} for k, v in self._store.entries()]


class FilePublicKeyStore(IPublicKeyStore):
    def __init__(self, directory: str) -> None:
        self._store = _JsonFileStore(os.path.join(directory, "public-keys.json"))

    async def save(self, key_id: str, algorithm: str, public_jwk: dict[str, Any]) -> None:
        self._store.set(key_id, {"algorithm": algorithm, "public_jwk": public_jwk})

    async def load(self, key_id: str) -> dict[str, Any] | None:
        return self._store.get(key_id)

    async def has(self, key_id: str) -> bool:
        return self._store.get(key_id) is not None

    async def all(self) -> list[dict[str, Any]]:
        return [{"key_id": k, **v} for k, v in self._store.entries()]


class FileCertificateStore(ICertificateStore):
    def __init__(self, directory: str) -> None:
        self._store = _JsonFileStore(os.path.join(directory, "certificates.json"))

    async def save(self, tcert_id: str, data: bytes) -> None:
        self._store.set(tcert_id, _bytes_encode(data))

    async def get(self, tcert_id: str) -> bytes | None:
        raw = self._store.get(tcert_id)
        return _bytes_decode(raw) if raw is not None else None

    async def find_by_key_id(self, key_id: str) -> list[tuple[str, bytes]]:
        return [(t, _bytes_decode(raw)) for t, raw in self._store.entries() if t.startswith(f"{key_id}:")]

    async def all(self) -> list[tuple[str, bytes]]:
        return [(t, _bytes_decode(raw)) for t, raw in self._store.entries()]

    async def remove(self, tcert_id: str) -> None:
        self._store.delete(tcert_id)


class FileDocumentStore(IDocumentStore):
    def __init__(self, directory: str) -> None:
        self._store = _JsonFileStore(os.path.join(directory, "documents.json"))

    async def save(self, sdoc_id: str, data: bytes) -> None:
        self._store.set(sdoc_id, _bytes_encode(data))

    async def get(self, sdoc_id: str) -> bytes | None:
        raw = self._store.get(sdoc_id)
        return _bytes_decode(raw) if raw is not None else None

    async def all(self) -> list[tuple[str, bytes]]:
        return [(s, _bytes_decode(raw)) for s, raw in self._store.entries()]

    async def remove(self, sdoc_id: str) -> None:
        self._store.delete(sdoc_id)


class FileRevocationStore(IRevocationStore):
    def __init__(self, directory: str) -> None:
        self._revoked_tcerts = _JsonFileStore(os.path.join(directory, "revoked-tcerts.json"))
        self._revoked_keys = _JsonFileStore(os.path.join(directory, "revoked-keys.json"))
        self._blocked_sdocs = _JsonFileStore(os.path.join(directory, "blocked-sdocs.json"))

    async def add_revoked_tcert(self, tcert_id: str, entry: RevocationEntry) -> None:
        self._revoked_tcerts.set(tcert_id, _entry_to_json(entry))

    async def get_revoked_tcert(self, tcert_id: str) -> RevocationEntry | None:
        raw = self._revoked_tcerts.get(tcert_id)
        return _entry_from_json(raw) if raw else None

    async def list_revoked_tcerts(self) -> list[tuple[str, RevocationEntry]]:
        return [(t, _entry_from_json(raw)) for t, raw in self._revoked_tcerts.entries()]

    async def add_revoked_key(self, key_id: str, entry: RevocationEntry) -> None:
        self._revoked_keys.set(key_id, _entry_to_json(entry))

    async def get_revoked_key(self, key_id: str) -> RevocationEntry | None:
        raw = self._revoked_keys.get(key_id)
        return _entry_from_json(raw) if raw else None

    async def list_revoked_keys(self) -> list[tuple[str, RevocationEntry]]:
        return [(k, _entry_from_json(raw)) for k, raw in self._revoked_keys.entries()]

    async def add_blocked_sdoc(self, sdoc_id: str, entry: BlockEntry) -> None:
        self._blocked_sdocs.set(sdoc_id, {"issuedAt": entry.issued_at, "reason": entry.reason})

    async def get_blocked_sdoc(self, sdoc_id: str) -> BlockEntry | None:
        raw = self._blocked_sdocs.get(sdoc_id)
        if not raw:
            return None
        return BlockEntry(issued_at=raw["issuedAt"], reason=raw.get("reason"))

    async def list_blocked_sdocs(self) -> list[tuple[str, BlockEntry]]:
        return [
            (s, BlockEntry(issued_at=raw["issuedAt"], reason=raw.get("reason")))
            for s, raw in self._blocked_sdocs.entries()
        ]

    async def remove_blocked_sdoc(self, sdoc_id: str) -> None:
        self._blocked_sdocs.delete(sdoc_id)


def _entry_to_json(entry: RevocationEntry) -> dict[str, Any]:
    out: dict[str, Any] = {"type": entry.type, "issuedAt": entry.issued_at}
    if entry.reason is not None:
        out["reason"] = entry.reason
    return out


def _entry_from_json(raw: dict[str, Any]) -> RevocationEntry:
    return RevocationEntry(type=raw["type"], issued_at=raw["issuedAt"], reason=raw.get("reason"))


class FileTrustStore(ITrustStore):
    def __init__(self, directory: str) -> None:
        self._pinned = _JsonFileStore(os.path.join(directory, "trust-pinned.json"))
        self._cas = _JsonFileStore(os.path.join(directory, "trust-cas.json"))
        self._distrusted = _JsonFileStore(os.path.join(directory, "trust-distrusted.json"))
        self._attestations = _JsonFileStore(os.path.join(directory, "trust-attestations.json"))

    async def add_pinned(self, tcert_id: str) -> None:
        self._pinned.set(tcert_id, True)

    async def remove_pinned(self, tcert_id: str) -> None:
        self._pinned.delete(tcert_id)

    async def is_pinned(self, tcert_id: str) -> bool:
        return self._pinned.get(tcert_id) is not None

    async def list_pinned(self) -> list[str]:
        return [k for k, _ in self._pinned.entries()]

    async def add_ca(self, tcert_id: str) -> None:
        self._cas.set(tcert_id, True)

    async def remove_ca(self, tcert_id: str) -> None:
        self._cas.delete(tcert_id)

    async def is_ca(self, tcert_id: str) -> bool:
        return self._cas.get(tcert_id) is not None

    async def list_ca(self) -> list[str]:
        return [k for k, _ in self._cas.entries()]

    async def add_attestation(self, record: AttestationRecord) -> None:
        key = f"{record.target_tcert_id}|{record.ca_tcert_id}|{record.issued_at}"
        self._attestations.set(key, _attestation_to_json(record))

    async def get_attestations(self, target_tcert_id: str) -> list[AttestationRecord]:
        return [
            _attestation_from_json(raw)
            for _, raw in self._attestations.entries()
            if _attestation_from_json(raw).target_tcert_id == target_tcert_id
        ]

    async def add_distrusted(self, tcert_id: str) -> None:
        self._distrusted.set(tcert_id, True)

    async def remove_distrusted(self, tcert_id: str) -> None:
        self._distrusted.delete(tcert_id)

    async def is_distrusted(self, tcert_id: str) -> bool:
        return self._distrusted.get(tcert_id) is not None


def _attestation_to_json(record: AttestationRecord) -> dict[str, Any]:
    out: dict[str, Any] = {
        "targetTcertId": record.target_tcert_id,
        "caTcertId": record.ca_tcert_id,
        "caKeyId": record.ca_key_id,
        "tcertHash": record.tcert_hash,
        "issuedAt": record.issued_at,
        "statementBytes": _bytes_encode(record.statement_bytes),
    }
    if record.claims is not None:
        out["claims"] = record.claims
    return out


def _attestation_from_json(raw: dict[str, Any]) -> AttestationRecord:
    return AttestationRecord(
        target_tcert_id=raw["targetTcertId"],
        ca_tcert_id=raw["caTcertId"],
        ca_key_id=raw["caKeyId"],
        tcert_hash=raw.get("tcertHash", ""),
        issued_at=raw["issuedAt"],
        statement_bytes=_bytes_decode(raw["statementBytes"]),
        claims=raw.get("claims"),
    )


class FileEndpointConfigStore(IEndpointConfigStore):
    def __init__(self, directory: str) -> None:
        self._store = _JsonFileStore(os.path.join(directory, "endpoint-config.json"))

    async def get_endpoints(self, tcert_id: str) -> list[str]:
        raw = self._store.get(tcert_id)
        return list(raw) if isinstance(raw, list) else []

    async def set_endpoints(self, tcert_id: str, endpoints: list[str]) -> None:
        self._store.set(tcert_id, list(dict.fromkeys(endpoints)))

    async def add_endpoint(self, tcert_id: str, endpoint: str) -> None:
        endpoints = await self.get_endpoints(tcert_id)
        if endpoint not in endpoints:
            endpoints.append(endpoint)
            self._store.set(tcert_id, endpoints)

    async def remove_endpoint(self, tcert_id: str, endpoint: str) -> None:
        endpoints = await self.get_endpoints(tcert_id)
        if endpoint in endpoints:
            self._store.set(tcert_id, [e for e in endpoints if e != endpoint])


def create_file_stores(directory: str) -> dict[str, Any]:
    """JSON-file-backed stores under *directory* (like the reference CLI)."""
    return {
        "private_key_store": FilePrivateKeyStore(directory),
        "public_key_store": FilePublicKeyStore(directory),
        "certificate_store": FileCertificateStore(directory),
        "document_store": FileDocumentStore(directory),
        "revocation_store": FileRevocationStore(directory),
        "trust_store": FileTrustStore(directory),
        "endpoint_config_store": FileEndpointConfigStore(directory),
    }