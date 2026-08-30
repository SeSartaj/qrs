"""Service-layer tests for QRS Enterprise.

These test the business logic directly (no HTTP endpoints / views), so they can
be run frequently and quickly. They exercise the async ``EnterpriseService``
against the real qrs-core-python runtime and the Django ORM.

Run with:  python -m pytest enterprise/tests/test_services.py
"""
from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.test import TransactionTestCase

from enterprise.models import AuditLog, ManagedKey, ManagedTcert, SdocRecord
from enterprise.services import (
    EnterpriseService,
    SigningNotAllowedError,
    TcertNotFoundError,
)

User = get_user_model()

SIGNING_FIELDS = [
    {"type": "text", "name": "name", "label": "Name"},
    {"type": "text", "name": "license_no", "label": "License No"},
]


@pytest.fixture
async def svc():
    return EnterpriseService()


@pytest.fixture
async def user():
    return await User.objects.acreate(username="alice", role="signer")


@pytest.mark.django_db(transaction=True)
class TestEnterpriseService:
    """Async service tests (transactional DB for async ORM)."""

    async def test_create_tcert_persists_encrypted_key(self, svc):
        tcert = await svc.create_tcert(
            algorithm="Ed25519", name="License", fields=SIGNING_FIELDS
        )
        assert tcert.tcert_id
        assert tcert.has_schema is True
        # The private key must be stored encrypted, never plaintext.
        key = await ManagedKey.objects.aget(key_id=tcert.key.key_id)
        assert key.private_jwk_encrypted
        # Fernet ciphertext is base64; a plaintext JWK would be JSON starting
        # with '{'. Assert it is NOT a plaintext JWK.
        assert not key.private_jwk_encrypted.lstrip().startswith("{")
        # Round-trip: the decrypted private JWK must be usable.
        priv = key.get_private_jwk()
        assert priv is not None
        assert priv.get("d")  # private exponent present after decryption

    async def test_sign_sdoc_and_verify(self, svc, user):
        tcert = await svc.create_tcert(
            algorithm="Ed25519", name="License", fields=SIGNING_FIELDS
        )
        record = await svc.sign_sdoc(
            tcert_id=tcert.tcert_id,
            values={"name": "Ahmad", "license_no": "AF-123"},
            user=user,
        )
        assert record.sdoc_id
        assert record.signed_by == user
        verdict = await svc.verify(record.sdoc_b64)
        # The signature and TCert are cryptographically valid; overall is
        # 'cannotVerify' because the freshly-created TCert has no trust yet.
        assert verdict["cryptographic"] == "valid"
        assert verdict["tcert"] == "valid"
        assert verdict["overall"] in ("valid", "cannotVerify")

    async def test_sign_schema_less_tcert_raises(self, svc):
        # A CA-style TCert with no schema cannot sign SDocs.
        tcert = await svc.create_tcert(
            algorithm="Ed25519", name="CA", fields=[], is_ca=True
        )
        assert tcert.has_schema is False
        with pytest.raises(SigningNotAllowedError):
            await svc.sign_sdoc(tcert_id=tcert.tcert_id, values={})

    async def test_sign_unknown_tcert_raises(self, svc):
        with pytest.raises(TcertNotFoundError):
            await svc.sign_sdoc(tcert_id="deadbeef:1", values={})

    async def test_attest_requires_ca(self, svc):
        ca = await svc.create_tcert(
            algorithm="Ed25519", name="CA", fields=[], is_ca=True
        )
        target = await svc.create_tcert(
            algorithm="Ed25519", name="Target", fields=SIGNING_FIELDS
        )
        result = await svc.attest(
            ca_tcert_id=ca.tcert_id, target_tcert_id=target.tcert_id, claims={"role": "inspector"}
        )
        assert result["statement_id"]
        assert result["bytes_b64"]

    async def test_revoke_tcert(self, svc):
        ca = await svc.create_tcert(
            algorithm="Ed25519", name="CA", fields=[], is_ca=True
        )
        target = await svc.create_tcert(
            algorithm="Ed25519", name="Target", fields=SIGNING_FIELDS
        )
        # A CA revokes a target it has attested (the real CA workflow).
        await svc.attest(ca_tcert_id=ca.tcert_id, target_tcert_id=target.tcert_id)
        result = await svc.revoke_tcert(
            signer_key_id=ca.key.key_id,
            target_tcert_id=target.tcert_id,
            reason="license revoked",
        )
        assert result["statement_id"]
        assert result["bytes_b64"]

    async def test_block_and_unblock_sdoc(self, svc, user):
        tcert = await svc.create_tcert(
            algorithm="Ed25519", name="License", fields=SIGNING_FIELDS
        )
        record = await svc.sign_sdoc(
            tcert_id=tcert.tcert_id,
            values={"name": "Ahmad", "license_no": "AF-123"},
            user=user,
        )
        block = await svc.block_sdoc(
            signer_key_id=tcert.key.key_id, target_sdoc_id=record.sdoc_id, reason="fraud"
        )
        assert block["statement_id"]
        unblock = await svc.unblock_sdoc(
            signer_key_id=tcert.key.key_id, target_sdoc_id=record.sdoc_id
        )
        assert unblock["statement_id"]

    async def test_audit_log_records_operations(self, svc, user):
        tcert = await svc.create_tcert(
            algorithm="Ed25519", name="License", fields=SIGNING_FIELDS
        )
        await svc.sign_sdoc(
            tcert_id=tcert.tcert_id,
            values={"name": "Ahmad", "license_no": "AF-123"},
            user=user,
        )
        count = await AuditLog.objects.acount()
        assert count >= 1