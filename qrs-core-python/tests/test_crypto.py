"""Tests for the crypto providers (Ed25519 + ECDSA-P256)."""

from __future__ import annotations

import pytest

from qrs.crypto.ecdsaP256 import EcdsaP256Provider
from qrs.crypto.ed25519 import Ed25519Provider
from qrs.crypto.registry import create_default_crypto_registry


@pytest.mark.parametrize("provider", [Ed25519Provider(), EcdsaP256Provider()])
def test_sign_verify_roundtrip(provider):
    pair = provider.generate_key_pair()
    data = b"hello world"
    sig = provider.sign(data, pair.private_jwk)
    assert provider.verify(data, sig, pair.public_jwk) is True
    # Tampered data must fail.
    assert provider.verify(b"tampered", sig, pair.public_jwk) is False


@pytest.mark.parametrize("provider", [Ed25519Provider(), EcdsaP256Provider()])
def test_derive_public_matches(provider):
    pair = provider.generate_key_pair()
    derived = provider.derive_public(pair.private_jwk)
    assert derived["x"] == pair.public_jwk["x"]
    assert derived["kty"] == pair.public_jwk["kty"]


def test_key_id_is_32_hex():
    provider = Ed25519Provider()
    pair = provider.generate_key_pair()
    key_id = provider.key_id(pair.public_jwk)
    assert len(key_id) == 32
    assert all(c in "0123456789abcdef" for c in key_id)


def test_default_registry_has_both_algorithms():
    registry = create_default_crypto_registry()
    assert registry.has("Ed25519")
    assert registry.has("ECDSA-P256")


def test_ecdsa_signature_is_64_bytes_raw():
    provider = EcdsaP256Provider()
    pair = provider.generate_key_pair()
    sig = provider.sign(b"data", pair.private_jwk)
    assert len(sig) == 64  # raw r||s (IEEE P1363)