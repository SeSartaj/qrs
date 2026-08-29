"""ECDSA P-256 (ES256) provider. 64-byte signatures (raw r||s via IEEE P1363),
65-byte uncompressed public keys. Uses the Python `cryptography` library.
"""

from __future__ import annotations

import base64
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from ..errors import QrsError
from .providers import ICryptoProvider, KeyPairMaterial, compute_key_id

__all__ = ["EcdsaP256Provider"]

_CURVE = ec.SECP256R1()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _from_b64url(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise QrsError(f"Invalid base64url in JWK: {exc}") from exc


def _public_jwk(public_key: ec.EllipticCurvePublicKey) -> dict[str, Any]:
    numbers = public_key.public_numbers()
    x = numbers.x.to_bytes(32, "big")
    y = numbers.y.to_bytes(32, "big")
    return {"kty": "EC", "crv": "P-256", "x": _b64url(x), "y": _b64url(y)}


def _private_jwk(private_key: ec.EllipticCurvePrivateKey) -> dict[str, Any]:
    numbers = private_key.private_numbers()
    jwk = _public_jwk(private_key.public_key())
    jwk["d"] = _b64url(numbers.private_value.to_bytes(32, "big"))
    return jwk


def _der_to_ieee_p1363(der_signature: bytes) -> bytes:
    """Decode a DER-encoded ECDSA signature into raw 32+32-byte r||s."""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _encode_dss_signature(r: int, s: int) -> bytes:
    """Encode raw r||s into a DER-encoded ECDSA signature (for verification)."""
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    return encode_dss_signature(r, s)


class EcdsaP256Provider(ICryptoProvider):
    """ECDSA with curve P-256 (COSE alg id -7, "ES256"), SHA-256 hashing.

    Signatures use the raw IEEE-P1363 encoding (r||s, 64 bytes total) to match
    the reference implementation and WebCrypto.
    """

    algorithm = "ECDSA-P256"
    cose_algorithm_id = -7

    def generate_key_pair(self) -> KeyPairMaterial:
        private_key = ec.generate_private_key(_CURVE)
        return KeyPairMaterial(
            algorithm=self.algorithm,
            public_jwk=_public_jwk(private_key.public_key()),
            private_jwk=_private_jwk(private_key),
        )

    def derive_public(self, private_jwk: dict[str, Any]) -> dict[str, Any]:
        private_key = ec.derive_private_key(
            int.from_bytes(_from_b64url(private_jwk["d"]), "big"), _CURVE
        )
        return _public_jwk(private_key.public_key())

    def sign(self, data: bytes, private_jwk: dict[str, Any]) -> bytes:
        private_key = ec.derive_private_key(
            int.from_bytes(_from_b64url(private_jwk["d"]), "big"), _CURVE
        )
        der_signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        return _der_to_ieee_p1363(der_signature)

    def verify(self, data: bytes, signature: bytes, public_jwk: dict[str, Any]) -> bool:
        try:
            if len(signature) != 64:
                return False
            x = int.from_bytes(_from_b64url(public_jwk["x"]), "big")
            y = int.from_bytes(_from_b64url(public_jwk["y"]), "big")
            public_key = ec.EllipticCurvePublicNumbers(x, y, _CURVE).public_key()
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            der_signature = _encode_dss_signature(r, s)
            public_key.verify(der_signature, data, ec.ECDSA(hashes.SHA256()))
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