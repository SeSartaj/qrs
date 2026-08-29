"""Statement helper: the unified signed authority action (attest, revoke, block, ...).

A Statement is a signed object of type ``statement``. Its data map is:

    { statementId, action, target, issuedAt, validity?, reason?, revocationType?, claims? }

``target`` is a map with a ``kind`` discriminator:

    { kind: 'tcert', keyId, certificateNumber }
    { kind: 'key',   keyId }
    { kind: 'sdoc',  sdocId }
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..cbor import cbor_encode
from ..crypto.providers import ICryptoProvider, KeyPairMaterial
from ..envelope import (
    build_signed_object,
    parse_signed_object,
    verify_parsed_signed_object,
)
from ..errors import QrsParseError
from ..id import from_hex, random_id, to_hex
from ..signed_object import is_action, is_revocation_type

__all__ = [
    "StatementTarget",
    "StatementOptions",
    "BuiltStatement",
    "ParsedStatement",
    "encode_target",
    "decode_target",
    "build_statement",
    "parse_statement",
    "verify_statement",
]


@dataclass
class StatementTarget:
    kind: str  # 'tcert' | 'key' | 'sdoc'
    key_id: str | None = None
    certificate_number: int | None = None
    sdoc_id: str | None = None
    tcert_hash: str | None = None  # content hash of the attested TCert (attest only)


@dataclass
class StatementOptions:
    reason: str | None = None
    revocation_type: str | None = None
    claims: dict[str, Any] | None = None
    validity: dict[str, int] | None = None


@dataclass
class BuiltStatement:
    statement_id: str
    bytes: bytes
    parsed: Any


@dataclass
class ParsedStatement:
    statement_id: str
    action: str
    target: StatementTarget
    issued_at: int
    validity: dict[str, int] | None = None
    reason: str | None = None
    revocation_type: str | None = None
    claims: dict[str, Any] | None = None
    signer_key_id: str = ""
    parsed: Any = None
    bytes: bytes = b""


def encode_target(target: StatementTarget) -> dict[str, Any]:
    if target.kind == "tcert":
        out: dict[str, Any] = {
            "kind": "tcert",
            "keyId": from_hex(target.key_id or ""),
            "certificateNumber": target.certificate_number,
        }
        if target.tcert_hash:
            out["tcertHash"] = target.tcert_hash
        return out
    if target.kind == "key":
        return {"kind": "key", "keyId": from_hex(target.key_id or "")}
    if target.kind == "sdoc":
        return {"kind": "sdoc", "sdocId": from_hex(target.sdoc_id or "")}
    raise QrsParseError("Malformed statement target")


def decode_target(raw: dict[str, Any]) -> StatementTarget:
    kind = raw.get("kind")
    if kind == "tcert" and isinstance(raw.get("keyId"), bytes) and isinstance(raw.get("certificateNumber"), int):
        tcert_hash = raw.get("tcertHash")
        return StatementTarget(
            kind="tcert",
            key_id=to_hex(raw["keyId"]),
            certificate_number=raw["certificateNumber"],
            tcert_hash=tcert_hash if isinstance(tcert_hash, str) and tcert_hash else None,
        )
    if kind == "key" and isinstance(raw.get("keyId"), bytes):
        return StatementTarget(kind="key", key_id=to_hex(raw["keyId"]))
    if kind == "sdoc" and isinstance(raw.get("sdocId"), bytes):
        return StatementTarget(kind="sdoc", sdoc_id=to_hex(raw["sdocId"]))
    raise QrsParseError("Malformed statement target")


def build_statement(
    action: str,
    target: StatementTarget,
    issued_at: int,
    options: StatementOptions,
    key_pair: KeyPairMaterial,
    provider: ICryptoProvider,
) -> BuiltStatement:
    statement_id = random_id()
    data: dict[str, Any] = {
        "statementId": from_hex(statement_id),
        "action": action,
        "target": encode_target(target),
        "issuedAt": issued_at,
    }
    if options.reason is not None:
        data["reason"] = options.reason
    if options.revocation_type is not None:
        data["revocationType"] = options.revocation_type
    if options.claims is not None:
        data["claims"] = options.claims
    if options.validity is not None:
        data["validity"] = options.validity

    bytes_out = build_signed_object("statement", data, key_pair, provider)
    parsed = parse_signed_object(bytes_out)
    return BuiltStatement(statement_id=statement_id, bytes=bytes_out, parsed=parsed)


def parse_statement(data: bytes) -> ParsedStatement:
    parsed = parse_signed_object(data)
    if parsed.type != "statement":
        raise QrsParseError("Not a statement")
    d = parsed.data
    action = d.get("action")
    if not isinstance(action, str) or not is_action(action):
        raise QrsParseError("Unknown statement action")
    target_raw = d.get("target")
    if not isinstance(target_raw, dict):
        raise QrsParseError("Statement missing target")
    target = decode_target(target_raw)
    if not isinstance(d.get("issuedAt"), int):
        raise QrsParseError("Statement missing issuedAt")
    revocation_type = d.get("revocationType")
    if revocation_type is not None and (not isinstance(revocation_type, str) or not is_revocation_type(revocation_type)):
        raise QrsParseError("Invalid revocationType")
    return ParsedStatement(
        statement_id=to_hex(d["statementId"]),
        action=action,
        target=target,
        issued_at=d["issuedAt"],
        validity=d.get("validity"),
        reason=d.get("reason") if isinstance(d.get("reason"), str) else None,
        revocation_type=revocation_type,
        claims=d.get("claims"),
        signer_key_id=parsed.signer_key_id,
        parsed=parsed,
        bytes=data,
    )


def verify_statement(parsed: Any, public_jwk: dict[str, Any], provider: ICryptoProvider) -> bool:
    """Verify a statement with the signer's public key (cryptographic check only)."""
    return verify_parsed_signed_object(parsed, provider, public_jwk)