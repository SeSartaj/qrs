"""Transfer envelope.

QR codes are the offline medium for moving signed objects (TCert, SDoc,
Statement) between devices — desktop to mobile, or vice-versa. The payload is a
small, scannable, self-describing string so the receiving app knows what it is
and what to do with it before parsing:

    qrs://v1/<type>/<base64url-bytes>

This is a *transport* format only: the receiving app still performs the full
protocol steps (parse, verify signature, resolve trust, check revocation).

Multiple objects can travel together in a *bundle* (e.g. a CA shares an
attestation *with* the complete attested TCert so the verifier can fully
process it offline):

    qrs://v1/bundle/<base64url-json>
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .constants import QRS_FILE_EXTENSION, TRANSFER_SCHEME, TRANSFER_VERSION
from .id import from_base64url, to_base64url

__all__ = [
    "TRANSFER_SCHEME",
    "TRANSFER_VERSION",
    "QRS_FILE_EXTENSION",
    "TRANSFER_OBJECT_TYPES",
    "is_transfer_object_type",
    "encode_transfer_payload",
    "decode_transfer_payload",
    "encode_bundle",
    "decode_bundle",
    "encode_qrs_file",
    "encode_qrs_bundle_file",
    "decode_qrs_file",
]

TRANSFER_OBJECT_TYPES: tuple[str, ...] = ("tcert", "sdoc", "statement")


def is_transfer_object_type(value: Any) -> bool:
    return value in TRANSFER_OBJECT_TYPES


@dataclass
class DecodedTransferPayload:
    type: str
    bytes_b64: str


@dataclass
class BundleObject:
    type: str
    bytes_b64: str


@dataclass
class DecodedBundle:
    objects: list[BundleObject]


def encode_transfer_payload(obj_type: str, bytes_b64: str) -> str:
    """Build a transfer payload for a signed object's base64url bytes."""
    return f"{TRANSFER_SCHEME}://{TRANSFER_VERSION}/{obj_type}/{bytes_b64}"


def decode_transfer_payload(payload: str) -> DecodedTransferPayload | None:
    """Parse a transfer payload. Returns ``None`` when it is not one of ours."""
    prefix = f"{TRANSFER_SCHEME}://{TRANSFER_VERSION}/"
    if not payload.startswith(prefix):
        return None
    rest = payload[len(prefix):]
    slash = rest.find("/")
    if slash == -1:
        return None
    obj_type = rest[:slash]
    bytes_b64 = rest[slash + 1:]
    if not is_transfer_object_type(obj_type):
        return None
    if len(bytes_b64) == 0:
        return None
    return DecodedTransferPayload(type=obj_type, bytes_b64=bytes_b64)


def encode_bundle(objects: list[BundleObject]) -> str:
    """Encode several signed objects as one scannable payload (e.g. TCert + attestation).

    Accepts either :class:`BundleObject` instances or plain dicts with
    ``type``/``bytes_b64`` (or ``bytesB64``) keys, mirroring the reference
    implementation's ergonomics.
    """
    entries = []
    for o in objects:
        if isinstance(o, BundleObject):
            entries.append({"type": o.type, "bytesB64": o.bytes_b64})
        elif isinstance(o, dict):
            obj_type = o.get("type")
            bytes_b64 = o.get("bytes_b64", o.get("bytesB64"))
            entries.append({"type": obj_type, "bytesB64": bytes_b64})
        else:
            raise TypeError(f"Unsupported bundle object: {type(o).__name__}")
    json_text = json.dumps(
        {"v": TRANSFER_VERSION, "objects": entries},
        separators=(",", ":"),
    )
    b64 = to_base64url(json_text.encode("utf-8"))
    return f"{TRANSFER_SCHEME}://{TRANSFER_VERSION}/bundle/{b64}"


def decode_bundle(payload: str) -> DecodedBundle | None:
    """Parse a bundle payload. Returns ``None`` when the payload is not a bundle."""
    prefix = f"{TRANSFER_SCHEME}://{TRANSFER_VERSION}/bundle/"
    if not payload.startswith(prefix):
        return None
    b64 = payload[len(prefix):]
    try:
        decoded = json.loads(from_base64url(b64).decode("utf-8"))
    except Exception:  # noqa: BLE001 - malformed bundle is simply "not a bundle"
        return None
    if not isinstance(decoded, dict) or not isinstance(decoded.get("objects"), list):
        return None
    objects: list[BundleObject] = []
    for o in decoded["objects"]:
        if not isinstance(o, dict):
            continue
        obj_type = o.get("type")
        bytes_b64 = o.get("bytesB64")
        if not isinstance(obj_type, str) or not isinstance(bytes_b64, str):
            continue
        if not is_transfer_object_type(obj_type):
            continue
        objects.append(BundleObject(type=obj_type, bytes_b64=bytes_b64))
    return DecodedBundle(objects=objects)


def encode_qrs_file(obj_type: str, bytes_b64: str) -> bytes:
    """Build the UTF-8 bytes of a ``.qrs`` file holding a single signed object."""
    return encode_transfer_payload(obj_type, bytes_b64).encode("utf-8")


def encode_qrs_bundle_file(objects: list[BundleObject]) -> bytes:
    """Build the UTF-8 bytes of a ``.qrs`` file holding a bundle of signed objects."""
    return encode_bundle(objects).encode("utf-8")


# DecodedQrsFile is a tagged union: ``kind`` is "object" or "bundle".
DecodedQrsFile = dict[str, Any]


def decode_qrs_file(text: str) -> DecodedQrsFile | None:
    """Parse the text content of a ``.qrs`` file back into an object or a bundle."""
    trimmed = text.strip()
    if not trimmed:
        return None
    bundle = decode_bundle(trimmed)
    if bundle is not None:
        return {"kind": "bundle", "objects": bundle.objects}
    payload = decode_transfer_payload(trimmed)
    if payload is not None:
        return {"kind": "object", "payload": payload}
    return None