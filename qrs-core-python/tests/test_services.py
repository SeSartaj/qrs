"""End-to-end tests for the protocol services (certificates, signing, trust,
revocation, verification)."""

from __future__ import annotations

import pytest

from qrs.context import DummyContextProvider
from qrs.crypto.providers import KeyPairMaterial
from qrs.fields import FieldSchema
from qrs.runtime import QrsDependencies, create_qrs
from qrs.services.certificateService import CreateTcertParams
from qrs.services.revocationService import RevokeTcertParams
from qrs.services.signingService import IssueSdocParams
from qrs.services.trustService import AttestParams
from qrs.storage.interfaces import AttestationRecord


def make_qrs(secrets: dict[str, str] | None = None):
    return create_qrs(
        QrsDependencies(
            context_provider=DummyContextProvider(secrets=secrets or {}),
        )
    )


async def make_tcert(qrs, name="AFDA License", fields=None):
    fields = fields or [
        FieldSchema(type="text", name="license_no", label="License number"),
        FieldSchema(type="date", name="expiry", label="Expiry date"),
        FieldSchema(type="secretInput", name="pin", label="PIN"),
    ]
    return await qrs.certificates.create_tcert(
        CreateTcertParams(algorithm="Ed25519", name=name, fields=fields)
    )


@pytest.mark.asyncio
async def test_full_flow_valid():
    qrs = make_qrs(secrets={"pin": "s3cret"})
    tcert = await make_tcert(qrs)
    await qrs.trust.pin(tcert.tcert_id)

    issued = await qrs.signing.issue_sdoc(
        IssueSdocParams(
            tcert_id=tcert.tcert_id,
            values={"license_no": "AFDA-123", "expiry": "2027-01-01", "pin": "s3cret"},
        )
    )
    result = await qrs.verification.verify(issued.bytes)
    assert result.overall == "valid"
    assert result.cryptographic == "valid"
    assert result.tcert == "valid"
    assert result.trust == "valid"
    assert result.revocation == "valid"
    assert result.schema == "valid"


@pytest.mark.asyncio
async def test_wrong_secret_fails_cryptographically():
    qrs = make_qrs(secrets={"pin": "s3cret"})
    tcert = await make_tcert(qrs)
    await qrs.trust.pin(tcert.tcert_id)

    # Issue with a different secret than the verifier knows.
    issued = await qrs.signing.issue_sdoc(
        IssueSdocParams(
            tcert_id=tcert.tcert_id,
            values={"license_no": "AFDA-123", "expiry": "2027-01-01", "pin": "other"},
        )
    )
    result = await qrs.verification.verify(issued.bytes)
    assert result.overall == "invalid"
    assert result.cryptographic == "invalid"


@pytest.mark.asyncio
async def test_missing_secret_is_cannot_verify():
    qrs = make_qrs()  # no secrets configured
    tcert = await make_tcert(qrs)
    await qrs.trust.pin(tcert.tcert_id)
    issued = await qrs.signing.issue_sdoc(
        IssueSdocParams(
            tcert_id=tcert.tcert_id,
            values={"license_no": "AFDA-123", "expiry": "2027-01-01", "pin": "s3cret"},
        )
    )
    result = await qrs.verification.verify(issued.bytes)
    assert result.overall == "cannotVerify"
    assert result.context == "missing"


@pytest.mark.asyncio
async def test_untrusted_is_cannot_verify():
    qrs = make_qrs(secrets={"pin": "s3cret"})
    tcert = await make_tcert(qrs)
    # Do NOT pin the TCert.
    issued = await qrs.signing.issue_sdoc(
        IssueSdocParams(
            tcert_id=tcert.tcert_id,
            values={"license_no": "AFDA-123", "expiry": "2027-01-01", "pin": "s3cret"},
        )
    )
    result = await qrs.verification.verify(issued.bytes)
    assert result.overall == "cannotVerify"
    assert result.trust == "cannotVerify"


@pytest.mark.asyncio
async def test_revocation_invalidates():
    qrs = make_qrs(secrets={"pin": "s3cret"})
    tcert = await make_tcert(qrs)
    await qrs.trust.pin(tcert.tcert_id)
    issued = await qrs.signing.issue_sdoc(
        IssueSdocParams(
            tcert_id=tcert.tcert_id,
            values={"license_no": "AFDA-123", "expiry": "2027-01-01", "pin": "s3cret"},
        )
    )
    # Revoke the TCert retrospectively.
    await qrs.revocation.revoke_tcert(
        RevokeTcertParams(
            signer_key_id=tcert.key_id,
            target_tcert_id=tcert.tcert_id,
            type="retrospective",
        )
    )
    result = await qrs.verification.verify(issued.bytes)
    assert result.overall == "invalid"
    assert result.revocation == "invalid"


@pytest.mark.asyncio
async def test_ca_attestation_trust_path():
    qrs = make_qrs(secrets={"pin": "s3cret"})
    ca = await make_tcert(qrs, name="CA")
    target = await make_tcert(qrs, name="Target")
    await qrs.trust.add_ca(ca.tcert_id)
    await qrs.trust.attest(
        AttestParams(ca_tcert_id=ca.tcert_id, target_tcert_id=target.tcert_id)
    )
    # Target is now trusted via the CA (not pinned).
    issued = await qrs.signing.issue_sdoc(
        IssueSdocParams(
            tcert_id=target.tcert_id,
            values={"license_no": "AFDA-123", "expiry": "2027-01-01", "pin": "s3cret"},
        )
    )
    result = await qrs.verification.verify(issued.bytes)
    assert result.overall == "valid"
    assert result.trust == "valid"
    # The CA-attestation path resolves trust to "valid" (without pinning).
    resolution = await qrs.trust.resolve_trust(target.tcert_id)
    assert resolution.state == "valid"
    assert resolution.ca is not None


@pytest.mark.asyncio
async def test_attestation_hash_binding_rejects_tampered():
    """An attestation whose stored tcert_hash does not match the actual target
    TCert content hash must NOT resolve trust through the CA."""
    from qrs.envelope import parse_signed_object, tcert_hash_of, tcert_id_of, split_tcert_id
    from qrs.services.statement import StatementOptions, StatementTarget, build_statement

    qrs = make_qrs(secrets={"pin": "s3cret"})
    ca = await make_tcert(qrs, name="CA")
    target = await make_tcert(qrs, name="Target")
    await qrs.trust.add_ca(ca.tcert_id)

    # Build a real attestation statement (without auto-adding a record), then
    # store it with a tampered tcert_hash.
    ca_key = await qrs.deps.public_key_store.load(ca.key_id)
    ca_priv = await qrs.deps.private_key_store.load(ca.key_id)
    provider = qrs.deps.crypto_registry.get(ca_key["algorithm"])
    target_key_id, target_num = split_tcert_id(target.tcert_id)
    target_bytes = await qrs.deps.certificate_store.get(target.tcert_id)
    real_hash = tcert_hash_of(parse_signed_object(target_bytes))
    built = build_statement(
        "attest",
        StatementTarget(kind="tcert", key_id=target_key_id, certificate_number=target_num, tcert_hash=real_hash),
        1,
        StatementOptions(claims={"name": "x"}),
        KeyPairMaterial(algorithm=ca_key["algorithm"], public_jwk=ca_key["public_jwk"], private_jwk=ca_priv["private_jwk"]),
        provider,
    )
    await qrs.deps.trust_store.add_attestation(
        AttestationRecord(
            target_tcert_id=target.tcert_id,
            ca_tcert_id=ca.tcert_id,
            ca_key_id=ca.key_id,
            tcert_hash="deadbeef",  # tampered — does not match the real target hash
            claims={"name": "x"},
            issued_at=1,
            statement_bytes=built.bytes,
        )
    )

    resolution = await qrs.trust.resolve_trust(target.tcert_id)
    assert resolution.state == "cannotVerify"
    assert resolution.ca is None