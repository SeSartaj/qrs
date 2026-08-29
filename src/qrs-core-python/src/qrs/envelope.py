"""The SignedObject envelope.

Every protocol object (TCert, SDoc, Statement) is a COSE_Sign1 message whose
signed payload is the canonical CBOR array:

    [ protocolVersion, type, dataBytes ]

where ``dataBytes`` is the canonical CBOR encoding of the type-specific data map.
The decoder reads version, then type, then dispatches to the type-specific parser.
It never guesses the meaning of a payload from its content.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .cbor import cbor_decode, cbor_encode
from .constants import PROTOCOL_VERSION
from .cose import CoseSign1, decode_cose_sign1, sign_cose_sign1, verify_cose_sign1
from .crypto.providers import (
    ICryptoProvider,
    KeyPairMaterial,
    algorithm_from_cose_algorithm,
)
from .errors import QrsParseError, QrsUnsupportedError
from .id import from_hex, hash_for, is_hash_algorithm, to_hex, trunc_sha256
from .signed_object import assert_valid_object_data, is_signed_object_type

__all__ = [
    "ParsedSignedObject",
    "build_signed_object",
    "parse_signed_object",
    "verify_parsed_signed_object",
    "tcert_id_of",
    "sdoc_id_of",
    "tcert_hash_of",
    "split_tcert_id",
    "key_id_to_bytes",
]


@dataclass
class ParsedSignedObject:
    """A parsed but not yet verified signed object."""

    version: int
    type: str
    algorithm: str
    signer_key_id: str
    payload: bytes
    data_bytes: bytes
    data: dict[str, Any]
    signature: bytes
    cose: CoseSign1


def build_signed_object(
    obj_type: str,
    data: dict[str, Any],
    key_pair: KeyPairMaterial,
    provider: ICryptoProvider,
    external_aad: bytes = b"",
) -> bytes:
    """Build the bytes of a signed object of the given type."""
    data_bytes = cbor_encode(data)
    payload = cbor_encode([PROTOCOL_VERSION, obj_type, data_bytes])
    return sign_cose_sign1(
        payload, provider.key_id(key_pair.public_jwk), key_pair, provider, external_aad
    ).bytes


def parse_signed_object(data: bytes) -> ParsedSignedObject:
    """Parse a signed object from its wire bytes and dispatch on its type."""
    cose = decode_cose_sign1(data)

    inner = cbor_decode(cose.payload)
    if not isinstance(inner, list) or len(inner) != 3:
        raise QrsParseError("SignedObject payload must be [version, type, data]")
    version, obj_type, data_bytes = inner
    if version != PROTOCOL_VERSION:
        raise QrsUnsupportedError(f"Unsupported protocol version: {version!r}")
    if not isinstance(obj_type, str) or not is_signed_object_type(obj_type):
        raise QrsUnsupportedError(f"Unknown signed object type: {obj_type!r}")
    if not isinstance(data_bytes, bytes):
        raise QrsParseError("SignedObject data must be a byte string")

    algorithm = algorithm_from_cose_algorithm(cose.protected_headers.get(1, 0))
    if algorithm is None:
        raise QrsUnsupportedError(f"Unsupported algorithm identifier: {cose.protected_headers.get(1)}")

    data_obj = cbor_decode(data_bytes)
    if not isinstance(data_obj, dict):
        raise QrsParseError("SignedObject data must be a map with text keys")

    assert_valid_object_data(obj_type, data_obj)

    return ParsedSignedObject(
        version=version,
        type=obj_type,
        algorithm=algorithm,
        signer_key_id=to_hex(cose.protected_headers.get(4, b"")),
        payload=cose.payload,
        data_bytes=data_bytes,
        data=data_obj,
        signature=cose.signature,
        cose=cose,
    )


def verify_parsed_signed_object(
    parsed: ParsedSignedObject,
    provider: ICryptoProvider,
    public_jwk: dict[str, Any],
    external_aad: bytes = b"",
) -> bool:
    """Verify a parsed signed object using the signer's public key."""
    return verify_cose_sign1(parsed.cose, provider, public_jwk, external_aad)


def tcert_id_of(key_id: str, certificate_number: int) -> str:
    """TCert id: ``<keyId>:<certificateNumber>``."""
    return f"{key_id}:{certificate_number}"


def sdoc_id_of(data: bytes) -> str:
    """SDoc id: truncated SHA-256 of the signed SDoc bytes."""
    return to_hex(trunc_sha256(data))


def tcert_hash_of(parsed: ParsedSignedObject) -> str:
    """Content hash of a TCert (hex), used to bind attestation statements to a
    specific TCert object. Uses the protocol hash function (`hash_for` — SHA-256
    by default, or the TCert's declared `hashAlgorithm`)."""
    declared = parsed.data.get("hashAlgorithm")
    alg = declared if isinstance(declared, str) and is_hash_algorithm(declared) else None
    return to_hex(hash_for(alg, parsed.payload))


def split_tcert_id(tcert_id: str) -> tuple[str, int]:
    """Parse a TCert id back into ``(key_id, certificate_number)``."""
    parts = tcert_id.split(":", 1)
    if len(parts) != 2 or not parts[0]:
        raise QrsParseError(f"Malformed tcert id: {tcert_id}")
    key_id, cert_part = parts
    try:
        certificate_number = int(cert_part)
    except ValueError:
        raise QrsParseError(f"Malformed tcert certificate number: {tcert_id}") from None
    if certificate_number < 1 or certificate_number > 255:
        raise QrsParseError(f"Malformed tcert certificate number: {tcert_id}")
    return key_id, certificate_number


def key_id_to_bytes(key_id: str) -> bytes:
    """Convenience: key bytes as hex (for TCert data fields)."""
    return from_hex(key_id)


assert KeyPairMaterial  # unused import guard (typing only)