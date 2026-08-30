"""COSE_Sign1 (RFC 9052) support — the signed-object cryptographic structure.

Wire format (canonical CBOR array of four elements):

    [ protected, unprotected, payload, signature ]

The signature is computed over the Sig_structure:

    ["Signature1", protected, external_aad, payload]

``external_aad`` is how secret-bound fields are kept OUT of the stored payload
while still being covered by the signature (see the secretInput field engine).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .cbor import cbor_decode, cbor_encode
from .constants import COSE_HDR_ALG, COSE_HDR_KID, COSE_HDR_TCERT_NUMBER
from .errors import QrsParseError, QrsUnsupportedError
from .id import from_hex

if TYPE_CHECKING:
    from .crypto.providers import ICryptoProvider, KeyPairMaterial

__all__ = [
    "CoseSign1",
    "sign_cose_sign1",
    "decode_cose_sign1",
    "verify_cose_sign1",
    "assert_supported_algorithm",
]

_CONTEXT = "Signature1"


@dataclass
class CoseSign1:
    """A parsed COSE_Sign1 message."""

    protected_bytes: bytes
    protected_headers: dict[int, Any]
    unprotected_bytes: bytes
    payload: bytes
    signature: bytes


@dataclass
class SignedCose:
    cose: CoseSign1
    bytes: bytes


def sign_cose_sign1(
    payload: bytes,
    key_id: str,
    key_pair: "KeyPairMaterial",
    provider: "ICryptoProvider",
    external_aad: bytes = b"",
    tcert_number: int | None = None,
) -> SignedCose:
    """Sign a payload into a COSE_Sign1 message.

    ``external_aad`` is additional authenticated bytes (e.g. secrets),
    NOT stored in the message.

    ``tcert_number`` is an optional public header carrying the TCert
    certificate number (1..255), mirroring the reference implementation's
    ``tcertNumber`` protected header.
    """
    if tcert_number is not None and (
        not isinstance(tcert_number, int) or isinstance(tcert_number, bool) or tcert_number < 1 or tcert_number > 255
    ):
        raise QrsParseError("TCert number must be an integer in the range 1..255")
    protected = {
        COSE_HDR_ALG: provider.cose_algorithm_id,
        COSE_HDR_KID: from_hex(key_id),
    }
    if tcert_number is not None:
        protected[COSE_HDR_TCERT_NUMBER] = tcert_number
    protected_bytes = cbor_encode(protected)
    unprotected_bytes = cbor_encode({})

    sig_structure = cbor_encode([_CONTEXT, protected_bytes, external_aad, payload])
    if key_pair.private_jwk is None:
        raise QrsParseError("Cannot sign without a private key")
    signature = provider.sign(sig_structure, key_pair.private_jwk)

    headers: dict[int, Any] = {
        COSE_HDR_ALG: provider.cose_algorithm_id,
        COSE_HDR_KID: from_hex(key_id),
    }
    if tcert_number is not None:
        headers[COSE_HDR_TCERT_NUMBER] = tcert_number
    cose = CoseSign1(
        protected_bytes=protected_bytes,
        protected_headers=headers,
        unprotected_bytes=unprotected_bytes,
        payload=payload,
        signature=signature,
    )
    return SignedCose(cose=cose, bytes=cbor_encode([protected_bytes, unprotected_bytes, payload, signature]))


def decode_cose_sign1(data: bytes) -> CoseSign1:
    """Parse a COSE_Sign1 message from its wire bytes."""
    decoded = cbor_decode(data)
    if not isinstance(decoded, list) or len(decoded) != 4:
        raise QrsParseError("COSE_Sign1 must be an array of exactly 4 elements")
    protected_bytes, unprotected_bytes, payload, signature = decoded
    if not isinstance(protected_bytes, bytes) or not isinstance(unprotected_bytes, bytes):
        raise QrsParseError("COSE_Sign1 elements must all be byte strings")
    if not isinstance(payload, bytes) or not isinstance(signature, bytes):
        raise QrsParseError("COSE_Sign1 elements must all be byte strings")

    headers = cbor_decode(protected_bytes)
    if not isinstance(headers, dict):
        raise QrsParseError("COSE_Sign1 protected headers must be a map")
    alg = headers.get(COSE_HDR_ALG)
    kid = headers.get(COSE_HDR_KID)
    tcert_number = headers.get(COSE_HDR_TCERT_NUMBER)
    if not isinstance(alg, int):
        raise QrsParseError("COSE_Sign1 protected headers must contain an algorithm")
    if not isinstance(kid, bytes):
        raise QrsParseError("COSE_Sign1 protected headers must contain a key id")
    if tcert_number is not None and (
        not isinstance(tcert_number, int) or isinstance(tcert_number, bool) or tcert_number < 1 or tcert_number > 255
    ):
        raise QrsParseError("COSE_Sign1 protected TCert number must be an integer in the range 1..255")

    protected_headers = {COSE_HDR_ALG: alg, COSE_HDR_KID: kid}
    if tcert_number is not None:
        protected_headers[COSE_HDR_TCERT_NUMBER] = tcert_number
    return CoseSign1(
        protected_bytes=protected_bytes,
        protected_headers=protected_headers,
        unprotected_bytes=unprotected_bytes,
        payload=payload,
        signature=signature,
    )


def verify_cose_sign1(
    cose: CoseSign1,
    provider: "ICryptoProvider",
    public_jwk: dict[str, Any],
    external_aad: bytes = b"",
) -> bool:
    """Verify a COSE_Sign1 message.

    ``external_aad`` must be the same externally-supplied bytes used at signing time.
    """
    sig_structure = cbor_encode([_CONTEXT, cose.protected_bytes, external_aad, cose.payload])
    try:
        return provider.verify(sig_structure, cose.signature, public_jwk)
    except Exception:  # noqa: BLE001 - a failed verification never raises
        return False


def assert_supported_algorithm(alg: int) -> None:
    """Only algorithm identifiers this profile understands may be used."""
    if alg != -8 and alg != -7:
        raise QrsUnsupportedError(f"Unsupported COSE algorithm identifier: {alg}")