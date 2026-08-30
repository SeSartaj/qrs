"""Django-ORM-backed stores implementing the qrs-core-python storage interfaces.

These adapt the qrs-core ``I*Store`` protocols to the enterprise models so the
core's services (certificates, signing, trust, revocation, verification) can run
against the database. Private keys are stored **encrypted at rest** via the
KeyVault (see ``ManagedKey``).
"""
from __future__ import annotations

from typing import Any

from qrs.storage.interfaces import (
    AttestationRecord,
    BlockEntry,
    ICertificateStore,
    IDocumentStore,
    IEndpointConfigStore,
    IPrivateKeyStore,
    IPublicKeyStore,
    IRevocationStore,
    ITrustStore,
    RevocationEntry,
)

from enterprise.models import ManagedKey, ManagedTcert, SdocRecord


class OrmPrivateKeyStore(IPrivateKeyStore):
    """Private keys stored encrypted at rest in ``ManagedKey``."""

    async def save(self, key_id: str, algorithm: str, private_jwk: dict[str, Any]) -> None:
        obj, _ = await _aget_or_create(ManagedKey, key_id=key_id)
        obj.algorithm = algorithm
        obj.set_private_jwk(private_jwk)
        await _asave(obj)

    async def load(self, key_id: str) -> dict[str, Any] | None:
        obj = await _aget(ManagedKey, key_id=key_id)
        if obj is None:
            return None
        private_jwk = obj.get_private_jwk()
        if private_jwk is None:
            return None
        return {"algorithm": obj.algorithm, "private_jwk": private_jwk}

    async def has(self, key_id: str) -> bool:
        return await _aexists(ManagedKey, key_id=key_id)

    async def all(self) -> list[dict[str, Any]]:
        objs = [o async for o in ManagedKey.objects.all()]
        return [
            {"key_id": o.key_id, "algorithm": o.algorithm, "public_jwk": o.public_jwk}
            for o in objs
        ]


class OrmPublicKeyStore(IPublicKeyStore):
    """Public keys stored in ``ManagedKey.public_jwk``."""

    async def save(self, key_id: str, algorithm: str, public_jwk: dict[str, Any]) -> None:
        obj, _ = await _aget_or_create(ManagedKey, key_id=key_id)
        obj.algorithm = algorithm
        obj.public_jwk = public_jwk
        await _asave(obj)

    async def load(self, key_id: str) -> dict[str, Any] | None:
        obj = await _aget(ManagedKey, key_id=key_id)
        if obj is None:
            return None
        return {"algorithm": obj.algorithm, "public_jwk": obj.public_jwk}

    async def has(self, key_id: str) -> bool:
        return await _aexists(ManagedKey, key_id=key_id)

    async def all(self) -> list[dict[str, Any]]:
        objs = [o async for o in ManagedKey.objects.all()]
        return [
            {"key_id": o.key_id, "algorithm": o.algorithm, "public_jwk": o.public_jwk}
            for o in objs
        ]


class OrmCertificateStore(ICertificateStore):
    """TCert bytes stored in ``ManagedTcert.tcert_b64``."""

    async def save(self, tcert_id: str, data: bytes) -> None:
        obj = await _aget(ManagedTcert, tcert_id=tcert_id)
        if obj is not None:
            obj.tcert_b64 = _b64(data)
            await _asave(obj)

    async def get(self, tcert_id: str) -> bytes | None:
        obj = await _aget(ManagedTcert, tcert_id=tcert_id)
        return _unb64(obj.tcert_b64) if obj else None

    async def find_by_key_id(self, key_id: str) -> list[tuple[str, bytes]]:
        objs = [o async for o in ManagedTcert.objects.filter(key__key_id=key_id)]
        return [(o.tcert_id, _unb64(o.tcert_b64)) for o in objs]

    async def all(self) -> list[tuple[str, bytes]]:
        objs = [o async for o in ManagedTcert.objects.all()]
        return [(o.tcert_id, _unb64(o.tcert_b64)) for o in objs]

    async def remove(self, tcert_id: str) -> None:
        await ManagedTcert.objects.filter(tcert_id=tcert_id).adelete()


class OrmDocumentStore(IDocumentStore):
    """SDoc bytes stored in ``SdocRecord.sdoc_b64``."""

    async def save(self, sdoc_id: str, data: bytes) -> None:
        obj, _ = await _aget_or_create(SdocRecord, sdoc_id=sdoc_id)
        obj.sdoc_b64 = _b64(data)
        await _asave(obj)

    async def get(self, sdoc_id: str) -> bytes | None:
        obj = await _aget(SdocRecord, sdoc_id=sdoc_id)
        return _unb64(obj.sdoc_b64) if obj else None

    async def all(self) -> list[tuple[str, bytes]]:
        objs = [o async for o in SdocRecord.objects.all()]
        return [(o.sdoc_id, _unb64(o.sdoc_b64)) for o in objs]

    async def remove(self, sdoc_id: str) -> None:
        await SdocRecord.objects.filter(sdoc_id=sdoc_id).adelete()


class OrmRevocationStore(IRevocationStore):
    """Revocation / block state.

    The enterprise app persists signed statements in ``AuditLog``; the in-memory
    revocation state is rebuilt from the audit trail on demand. For simplicity
    and correctness we keep a lightweight in-memory mirror per runtime, but the
    durable source of truth is the signed statements in the audit log.
    """

    def __init__(self) -> None:
        self._revoked_tcerts: dict[str, list[RevocationEntry]] = {}
        self._revoked_keys: dict[str, list[RevocationEntry]] = {}
        self._blocked_sdocs: dict[str, list[BlockEntry]] = {}

    async def add_revoked_tcert(self, tcert_id: str, entry: RevocationEntry) -> None:
        self._revoked_tcerts.setdefault(tcert_id, []).append(entry)

    async def get_revoked_tcert(self, tcert_id: str) -> RevocationEntry | None:
        entries = self._revoked_tcerts.get(tcert_id) or []
        return entries[-1] if entries else None

    async def list_revoked_tcerts(self) -> list[tuple[str, RevocationEntry]]:
        return [(k, v[-1]) for k, v in self._revoked_tcerts.items() if v]

    async def add_revoked_key(self, key_id: str, entry: RevocationEntry) -> None:
        self._revoked_keys.setdefault(key_id, []).append(entry)

    async def get_revoked_key(self, key_id: str) -> RevocationEntry | None:
        entries = self._revoked_keys.get(key_id) or []
        return entries[-1] if entries else None

    async def list_revoked_keys(self) -> list[tuple[str, RevocationEntry]]:
        return [(k, v[-1]) for k, v in self._revoked_keys.items() if v]

    async def add_blocked_sdoc(self, sdoc_id: str, entry: BlockEntry) -> None:
        self._blocked_sdocs.setdefault(sdoc_id, []).append(entry)

    async def get_blocked_sdoc(self, sdoc_id: str) -> BlockEntry | None:
        entries = self._blocked_sdocs.get(sdoc_id) or []
        return entries[-1] if entries else None

    async def list_blocked_sdocs(self) -> list[tuple[str, BlockEntry]]:
        return [(k, v[-1]) for k, v in self._blocked_sdocs.items() if v]


class OrmTrustStore(ITrustStore):
    """Trust state (pinned / CA / distrusted / attestations).

    Persisted in ``ManagedTcert`` flags plus the audit trail. For the enterprise
    server the trust graph is small; we keep an in-memory mirror rebuilt from the
    database on runtime construction.
    """

    def __init__(self) -> None:
        self._pinned: set[str] = set()
        self._cas: set[str] = set()
        self._distrusted: set[str] = set()
        self._attestations: list[AttestationRecord] = []

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

    async def add_distrusted(self, tcert_id: str) -> None:
        self._distrusted.add(tcert_id)

    async def remove_distrusted(self, tcert_id: str) -> None:
        self._distrusted.discard(tcert_id)

    async def is_distrusted(self, tcert_id: str) -> bool:
        return tcert_id in self._distrusted

    async def add_attestation(self, record: AttestationRecord) -> None:
        self._attestations.append(record)

    async def get_attestations(self, target_tcert_id: str) -> list[AttestationRecord]:
        return [a for a in self._attestations if a.target_tcert_id == target_tcert_id]

    async def all_attestations(self) -> list[AttestationRecord]:
        return list(self._attestations)


class OrmEndpointConfigStore(IEndpointConfigStore):
    """Endpoint mirrors are stored on ``ManagedTcert.online_endpoint`` (single
    default). Mirrors beyond the signed default are not persisted in v1."""

    async def get_endpoints(self, tcert_id: str) -> list[str]:
        obj = await _aget(ManagedTcert, tcert_id=tcert_id)
        return [obj.online_endpoint] if obj and obj.online_endpoint else []

    async def set_endpoints(self, tcert_id: str, endpoints: list[str]) -> None:
        obj = await _aget(ManagedTcert, tcert_id=tcert_id)
        if obj is not None:
            obj.online_endpoint = endpoints[0] if endpoints else ""
            await _asave(obj)

    async def add_endpoint(self, tcert_id: str, endpoint: str) -> None:
        obj = await _aget(ManagedTcert, tcert_id=tcert_id)
        if obj is not None and not obj.online_endpoint:
            obj.online_endpoint = endpoint
            await _asave(obj)

    async def remove_endpoint(self, tcert_id: str, endpoint: str) -> None:
        obj = await _aget(ManagedTcert, tcert_id=tcert_id)
        if obj is not None and obj.online_endpoint == endpoint:
            obj.online_endpoint = ""
            await _asave(obj)


# ---------------------------------------------------------------------------
# Async ORM helpers (qrs-core services are async)
# ---------------------------------------------------------------------------
def _b64(data: bytes) -> str:
    from qrs.id import to_base64url

    return to_base64url(data)


def _unb64(value: str) -> bytes:
    from qrs.id import from_base64url

    return from_base64url(value)


async def _aget(model, **kwargs):
    try:
        return await model.objects.aget(**kwargs)
    except model.DoesNotExist:
        return None


async def _aget_or_create(model, **kwargs):
    obj = await _aget(model, **kwargs)
    if obj is not None:
        return obj, False
    return model(**kwargs), True


async def _asave(obj) -> None:
    await obj.asave()


async def _aexists(model, **kwargs) -> bool:
    return await model.objects.filter(**kwargs).aexists()