"""Crypto-provider abstraction (SOLID: one algorithm, one provider; the registry
makes providers interchangeable, which is what enables cryptographic agility).

A provider knows how to generate key pairs, sign, verify, and derive the
protocol ``key_id`` for its algorithm. The core never calls cryptographic
primitives directly — it always goes through a provider obtained from a
:class:`~qrs.crypto.registry.CryptoRegistry`.

``key_id`` derivation (shared by all providers): ``trunc_sha256(canonical CBOR
of the public JWK, 16 bytes)`` — the same derivation as the reference
implementation, so identifiers are portable across languages.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..cbor import cbor_encode
from ..id import to_hex, trunc_sha256

__all__ = [
    "ICryptoProvider",
    "KeyPairMaterial",
    "compute_key_id",
    "COSE_ALGORITHM_TO_ID",
    "algorithm_from_cose_algorithm",
]


@dataclass
class KeyPairMaterial:
    """Decoded key material used for signing and verification."""

    algorithm: str
    public_jwk: dict[str, Any]
    private_jwk: dict[str, Any] | None = None

    @property
    def public_key_id(self) -> str:
        return compute_key_id_for(self.public_jwk)


class ICryptoProvider(ABC):
    """Interface implemented by every algorithm provider."""

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """Algorithm identifier used by the protocol (e.g. 'Ed25519')."""

    @property
    @abstractmethod
    def cose_algorithm_id(self) -> int:
        """COSE algorithm identifier (RFC 9053 registry), used in protected headers."""

    @abstractmethod
    def generate_key_pair(self) -> KeyPairMaterial:
        """Generate a fresh key pair (public + private JWK)."""

    @abstractmethod
    def derive_public(self, private_jwk: dict[str, Any]) -> dict[str, Any]:
        """Derive the public JWK from a private JWK."""

    @abstractmethod
    def sign(self, data: bytes, private_jwk: dict[str, Any]) -> bytes:
        """Sign raw bytes with the private JWK; return the raw signature."""

    @abstractmethod
    def verify(self, data: bytes, signature: bytes, public_jwk: dict[str, Any]) -> bool:
        """Verify a raw signature against the public JWK."""

    @abstractmethod
    def canonical_public_key(self, public_jwk: dict[str, Any]) -> bytes:
        """Deterministic canonical bytes of a public key."""

    def key_id(self, public_jwk: dict[str, Any]) -> str:
        """Derive the protocol ``key_id`` for a public key."""
        return compute_key_id(self, public_jwk)


def canonical_public_key_bytes(jwk: dict[str, Any]) -> bytes:
    """Deterministic canonical bytes of a public key.

    The canonical form is the canonical CBOR encoding of the public JWK with
    sorted keys ``kty, crv, x`` (plus ``y`` for EC keys).
    """
    sorted_jwk: dict[str, str] = {"kty": jwk["kty"], "crv": jwk["crv"], "x": jwk["x"]}
    if jwk.get("y") is not None:
        sorted_jwk["y"] = jwk["y"]  # type: ignore[assignment]
    return cbor_encode(sorted_jwk)


def compute_key_id(provider: ICryptoProvider, public_jwk: dict[str, Any]) -> str:
    """Standard implementation of ``key_id`` derivation shared by all providers."""
    return to_hex(trunc_sha256(provider.canonical_public_key(public_jwk)))


def compute_key_id_for(public_jwk: dict[str, Any]) -> str:
    """Derive the protocol ``key_id`` for a public JWK (algorithm-agnostic)."""
    return to_hex(trunc_sha256(canonical_public_key_bytes(public_jwk)))


COSE_ALGORITHM_TO_ID: dict[int, str] = {
    -8: "Ed25519",  # EdDSA
    -7: "ECDSA-P256",  # ES256
}


def algorithm_from_cose_algorithm(alg: int) -> str | None:
    """Map a COSE algorithm identifier to the protocol algorithm identifier."""
    return COSE_ALGORITHM_TO_ID.get(alg)