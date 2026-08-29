"""Ed25519 provider (RFC 8032). 32-byte public keys, 64-byte signatures.

This provider uses the Python `cryptography` library (the audited, maintained
library for digital signatures in Python).
"""

from __future__ import annotations

import base64
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from ..errors import QrsError
from .providers import ICryptoProvider, KeyPairMaterial, compute_key_id

__all__ = ["Ed25519Provider"]


def _b64url(data: bytes) -> str:
    """Base64url (no padding) encoding — the JWK field format."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _from_b64url(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise QrsError(f"Invalid base64url in JWK: {exc}") from exc


class Ed25519Provider(ICryptoProvider):
    """Ed25519 signatures per RFC 8032 (COSE alg id -8, "EdDSA")."""

    algorithm = "Ed25519"
    cose_algorithm_id = -8

    def generate_key_pair(self) -> KeyPairMaterial:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return KeyPairMaterial(
            algorithm=self.algorithm,
            public_jwk={
                "kty": "OKP",
                "crv": "Ed25519",
                "x": _b64url(public_key.public_bytes_raw()),
            },
            private_jwk={
                "kty": "OKP",
                "crv": "Ed25519",
                "x": _b64url(public_key.public_bytes_raw()),
                "d": _b64url(private_key.private_bytes_raw()),
            },
        )

    def derive_public(self, private_jwk: dict[str, Any]) -> dict[str, Any]:
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
            _from_b64url(private_jwk["d"])
        )
        public_key = private_key.public_key()
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64url(public_key.public_bytes_raw()),
        }

    def sign(self, data: bytes, private_jwk: dict[str, Any]) -> bytes:
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
            _from_b64url(private_jwk["d"])
        )
        return private_key.sign(data)

    def verify(self, data: bytes, signature: bytes, public_jwk: dict[str, Any]) -> bool:
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(
                _from_b64url(public_jwk["x"])
            )
            public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False
        except Exception:  # noqa: BLE001 - any decode/format error means "cannot verify"
            return False

    def canonical_public_key(self, public_jwk: dict[str, Any]) -> bytes:
        """The canonical bytes are the JWK fields — see ``canonical_public_key_bytes``."""
        from .providers import canonical_public_key_bytes as _canon

        return _canon(public_jwk)

    def key_id(self, public_jwk: dict[str, Any]) -> str:
        return compute_key_id(self, public_jwk)