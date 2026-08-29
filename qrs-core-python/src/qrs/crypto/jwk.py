"""JSON Web Key (JWK) helpers.

Keys are represented as JWK objects (the native format Node's crypto can import
and export), and the *canonical public key bytes* used for ``key_id`` derivation
is the canonical CBOR encoding of the public JWK with sorted keys. This keeps
the public key representation deterministic and language-neutral.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..cbor import cbor_encode
from ..errors import QrsValidationError

__all__ = [
    "canonical_public_key_bytes",
    "assert_public_jwk",
    "assert_private_jwk",
    "PublicJwk",
    "PrivateJwk",
]

# Structural typing aliases (informational).
PublicJwk = dict[str, Any]
PrivateJwk = dict[str, Any]


def canonical_public_key_bytes(jwk: Mapping[str, Any]) -> bytes:
    """Deterministic canonical bytes of a public key (used for ``key_id`` derivation)."""
    sorted_jwk: dict[str, str] = {"kty": jwk["kty"], "crv": jwk["crv"], "x": jwk["x"]}
    if jwk.get("y") is not None:
        sorted_jwk["y"] = jwk["y"]  # type: ignore[assignment]
    return cbor_encode(sorted_jwk)


def assert_public_jwk(value: Any) -> None:
    """Raise :class:`QrsValidationError` if *value* is not a public JWK."""
    if not isinstance(value, dict):
        raise QrsValidationError("Expected a public JWK object")
    if value.get("kty") not in ("OKP", "EC"):
        raise QrsValidationError("Unsupported JWK kty")
    if not isinstance(value.get("crv"), str) or not isinstance(value.get("x"), str):
        raise QrsValidationError("JWK must contain crv and x")


def assert_private_jwk(value: Any) -> None:
    """Raise :class:`QrsValidationError` if *value* is not a private JWK."""
    assert_public_jwk(value)
    if not isinstance(value.get("d"), str):
        raise QrsValidationError("JWK must contain a private key (d)")