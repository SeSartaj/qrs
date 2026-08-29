"""Identifier and encoding helpers.

All protocol identifiers are 128-bit truncated SHA-256 digests. This module is
deliberately platform-agnostic and delegates every cryptographic operation to
Python's standard library (:mod:`hashlib`, :mod:`secrets`) rather than
hand-rolled code.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from typing import Final

from .errors import QrsError, QrsParseError

# Number of identifier bytes used for all truncated identifiers.
ID_BYTES: Final = 16

_HEX_RE = re.compile(r"^[0-9a-fA-F]*$")

__all__ = [
    "ID_BYTES",
    "sha256",
    "sha384",
    "sha3_512",
    "hash_for",
    "is_hash_algorithm",
    "trunc_sha256",
    "constant_time_equal",
    "to_hex",
    "from_hex",
    "to_base64url",
    "from_base64url",
    "random_bytes",
    "random_id",
    "uint8_to_int",
    "int_to_uint8",
    "concat_bytes",
]


def sha256(data: bytes) -> bytes:
    """Full SHA-256 digest of arbitrary bytes."""
    return hashlib.sha256(data).digest()


def sha384(data: bytes) -> bytes:
    """Full SHA-384 digest of arbitrary bytes."""
    return hashlib.sha384(data).digest()


def sha3_512(data: bytes) -> bytes:
    """Full SHA3-512 digest of arbitrary bytes."""
    return hashlib.sha3_512(data).digest()


def is_hash_algorithm(value: object) -> bool:
    """True when *value* is one of the supported hash-algorithm names."""
    return value in ("SHA-256", "SHA-384", "SHA3-512")


def hash_for(alg: str | None, data: bytes) -> bytes:
    """Hash arbitrary bytes with the given algorithm (defaults to SHA-256)."""
    if alg == "SHA-384":
        return sha384(data)
    if alg == "SHA3-512":
        return sha3_512(data)
    return sha256(data)


def trunc_sha256(data: bytes, length: int = ID_BYTES) -> bytes:
    """Truncated SHA-256 digest (defaults to the 128-bit protocol identifier)."""
    return sha256(data)[:length]


def constant_time_equal(a: str, b: str) -> bool:
    """Constant-time string equality (used for bound-value comparisons)."""
    if len(a) != len(b):
        return False
    import hmac

    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def to_hex(data: bytes) -> str:
    """Hex-encode bytes (lowercase)."""
    return data.hex()


def from_hex(hex_string: str) -> bytes:
    """Hex-decode a string; raises :class:`QrsParseError` on malformed input."""
    if not isinstance(hex_string, str) or not _HEX_RE.match(hex_string) or len(hex_string) % 2 != 0:
        raise QrsParseError("Invalid hex string")
    return bytes.fromhex(hex_string)


def to_base64url(data: bytes) -> str:
    """Base64url (no padding) encode bytes."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def from_base64url(value: str) -> bytes:
    """Base64url decode; tolerates standard base64 characters and padding."""
    normalized = value.replace("+", "-").replace("/", "_").rstrip("=")
    try:
        # urlsafe_b64decode accepts unpadded input.
        return base64.urlsafe_b64decode(normalized + "=" * (-len(normalized) % 4))
    except Exception as exc:  # noqa: BLE001 - normalize any decoding failure
        raise QrsParseError("Invalid base64url string") from exc


def random_bytes(length: int) -> bytes:
    """Generate *length* cryptographically secure random bytes."""
    return secrets.token_bytes(length)


def random_id(num_bytes: int = ID_BYTES) -> str:
    """Generate a random hex identifier (defaults to 16 bytes)."""
    return to_hex(random_bytes(num_bytes))


def uint8_to_int(data: bytes) -> int:
    """Interpret bytes as a big-endian unsigned integer."""
    return int.from_bytes(data, "big")


def int_to_uint8(value: int, length: int = 8) -> bytes:
    """Encode an integer as big-endian bytes of *length* bytes."""
    return value.to_bytes(length, "big")


def concat_bytes(*parts: bytes) -> bytes:
    """Concatenate byte strings."""
    return b"".join(parts)


def require_secure_random() -> None:
    """Raise if the platform cannot provide secure randomness (never happens on CPython)."""
    try:
        secrets.token_bytes(1)
    except NotImplementedError as exc:  # pragma: no cover - exotic platforms only
        raise QrsError("No secure random source available") from exc