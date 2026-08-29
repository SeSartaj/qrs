"""AttachmentService: attachments as independent signed objects.

An Attachment is a signed object of type ``attachment`` whose data follows an
**app-defined static schema** (not a TCert schema):

    { id, contentType, contentHash, content, issuedAt }

- ``contentHash`` is the sha256 of ``content`` (hex).
- ``id`` is the truncated content hash (``contentHash[:32]``) — a single
  content-addressed handle that uniquely identifies the attachment on a
  distribution server and in a signed SDoc.

A document's ``attachment`` field stores **only** that ``id``. The verifier
fetches the signed attachment object by ``id``, verifies its signature against
the issuing TCert, and checks the ``contentHash`` binding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..constants import ATTACHMENT_HASH_HEX
from ..crypto.providers import KeyPairMaterial
from ..deps import ServiceDeps
from ..envelope import (
    build_signed_object,
    parse_signed_object,
    verify_parsed_signed_object,
)
from ..errors import QrsNotFoundError, QrsParseError
from ..id import hash_for, is_hash_algorithm, to_hex

__all__ = [
    "ATTACHMENT_ID_HEX",
    "attachment_id_of",
    "build_attachment",
    "parse_attachment",
    "verify_attachment",
    "AttachmentService",
    "BuildAttachmentParams",
    "BuiltAttachment",
    "ParsedAttachment",
]

ATTACHMENT_ID_HEX = ATTACHMENT_HASH_HEX


def attachment_id_of(content_hash_hex: str) -> str:
    """Content-addressed id for a content hash (first 128 bits)."""
    return content_hash_hex.lower()[:ATTACHMENT_ID_HEX]


@dataclass
class BuildAttachmentParams:
    key_id: str
    content_type: str
    content: bytes
    issued_at: int | None = None
    hash_algorithm: str | None = None


@dataclass
class BuiltAttachment:
    attachment_id: str
    content_hash: str
    issued_at: int
    bytes: bytes
    parsed: Any


@dataclass
class ParsedAttachment:
    attachment_id: str
    content_type: str
    content_hash: str
    content: bytes
    issued_at: int
    signer_key_id: str
    parsed: Any
    bytes: bytes


async def build_attachment(params: BuildAttachmentParams, deps: ServiceDeps) -> BuiltAttachment:
    """Build and sign an attachment object with a TCert's key."""
    priv_rec = await deps.private_key_store.load(params.key_id)
    if not priv_rec:
        raise QrsNotFoundError(f"Issuer private key not available: {params.key_id}")
    pub_rec = await deps.public_key_store.load(params.key_id)
    if not pub_rec:
        raise QrsNotFoundError(f"Public key not found: {params.key_id}")

    provider = deps.crypto_registry.get(pub_rec["algorithm"])
    hash_algorithm = params.hash_algorithm
    if hash_algorithm is None:
        # Infer the hash algorithm from the signer TCert when the caller did not
        # specify it explicitly.
        certs = await deps.certificate_store.find_by_key_id(params.key_id)
        for _, cert_bytes in certs:
            try:
                parsed = parse_signed_object(cert_bytes)
                declared = parsed.data.get("hashAlgorithm")
                if isinstance(declared, str) and is_hash_algorithm(declared):
                    hash_algorithm = declared
                    break
            except Exception:
                continue
        hash_algorithm = hash_algorithm or "SHA-256"

    content_hash = to_hex(hash_for(hash_algorithm, params.content))
    attachment_id = attachment_id_of(content_hash)
    issued_at = params.issued_at if params.issued_at is not None else deps.clock.now()

    data: dict[str, Any] = {
        "id": attachment_id,
        "contentType": params.content_type,
        "contentHash": content_hash,
        "content": params.content,
        "issuedAt": issued_at,
    }
    key_pair = KeyPairMaterial(
        algorithm=pub_rec["algorithm"],
        public_jwk=pub_rec["public_jwk"],
        private_jwk=priv_rec["private_jwk"],
    )
    bytes_out = build_signed_object("attachment", data, key_pair, provider)
    parsed = parse_signed_object(bytes_out)
    return BuiltAttachment(
        attachment_id=attachment_id,
        content_hash=content_hash,
        issued_at=issued_at,
        bytes=bytes_out,
        parsed=parsed,
    )


def parse_attachment(data: bytes) -> ParsedAttachment:
    """Parse an attachment object and return its fields."""
    parsed = parse_signed_object(data)
    if parsed.type != "attachment":
        raise QrsParseError("Not an attachment")
    d = parsed.data
    if (
        not isinstance(d.get("id"), str)
        or not isinstance(d.get("contentType"), str)
        or not isinstance(d.get("contentHash"), str)
        or not isinstance(d.get("content"), bytes)
        or not isinstance(d.get("issuedAt"), int)
    ):
        raise QrsParseError("Malformed attachment")
    return ParsedAttachment(
        attachment_id=d["id"],
        content_type=d["contentType"],
        content_hash=d["contentHash"],
        content=d["content"],
        issued_at=d["issuedAt"],
        signer_key_id=parsed.signer_key_id,
        parsed=parsed,
        bytes=data,
    )


def verify_attachment(parsed: Any, public_jwk: dict[str, Any], provider: Any) -> bool:
    """Verify an attachment's signature with the signer's public key."""
    return verify_parsed_signed_object(parsed, provider, public_jwk)


class AttachmentService:
    """Runtime-facing attachment service. Stateless: delegates to the standalone
    functions, injecting the runtime's stores and crypto registry."""

    def __init__(self, deps: ServiceDeps) -> None:
        self._deps = deps

    async def build(self, params: BuildAttachmentParams) -> BuiltAttachment:
        return await build_attachment(params, self._deps)