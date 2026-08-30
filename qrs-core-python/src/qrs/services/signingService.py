"""SigningService: issue an SDoc (a signed document) under a TCert.

Secret inputs (binding ``stripped``) are signed into the COSE external AAD but are
NOT stored in the SDoc. At verification time the same secret must be supplied to
reconstruct the signed bytes — the comparison is cryptographic and bit-exact.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..cbor import cbor_encode
from ..crypto.providers import KeyPairMaterial
from ..date_rules import resolve_field_default
from ..deps import ServiceDeps
from ..envelope import (
    build_signed_object,
    parse_signed_object,
    sdoc_id_of,
    verify_parsed_signed_object,
)
from ..errors import QrsCryptoError, QrsNotFoundError, QrsValidationError
from ..fields import FieldSchema, is_stripped_binding
from ..id import to_hex
from ..signed_object import is_field_type

__all__ = ["SigningService", "IssueSdocParams", "IssueSdocResult"]


@dataclass
class IssueSdocParams:
    tcert_id: str
    values: dict[str, Any]
    issued_at: int | None = None


@dataclass
class IssueSdocResult:
    sdoc_id: str
    bytes: bytes
    issued_at: int


class SigningService:
    def __init__(self, deps: ServiceDeps) -> None:
        self._deps = deps

    async def issue_sdoc(self, params: IssueSdocParams) -> IssueSdocResult:
        tcert_bytes = await self._deps.certificate_store.get(params.tcert_id)
        if not tcert_bytes:
            raise QrsNotFoundError(f"TCert not found: {params.tcert_id}")

        parsed = parse_signed_object(tcert_bytes)
        if parsed.type != "tcert":
            raise QrsValidationError("Object is not a TCert")

        data = parsed.data
        key_id = to_hex(data["keyId"])
        certificate_number = data["certificateNumber"]
        algorithm = data["algorithm"]
        public_jwk = data["publicKey"]

        provider = self._deps.crypto_registry.get(algorithm)
        if not verify_parsed_signed_object(parsed, provider, public_jwk):
            raise QrsCryptoError("Stored TCert failed self-signature verification")

        # Issue-time validity check: never sign a document that cannot be verified.
        tcert_validity = data.get("validity") or {}
        now = params.issued_at if params.issued_at is not None else self._deps.clock.now()
        if tcert_validity:
            if tcert_validity.get("validAfter") is not None and now < tcert_validity["validAfter"]:
                raise QrsValidationError("TCert is not yet valid")
            if tcert_validity.get("validBefore") is not None and now >= tcert_validity["validBefore"]:
                raise QrsValidationError("TCert has expired")

        raw_schema = data.get("schema")
        if not isinstance(raw_schema, list) or len(raw_schema) == 0:
            raise QrsValidationError("TCert has no document schema and cannot issue documents")
        fields = [FieldSchema.from_json(f) for f in raw_schema]

        stored_values: list[Any] = []
        secrets: dict[str, str] = {}

        for field in fields:
            if not is_field_type(field.type):
                raise QrsValidationError(f"Unsupported field type: {field.type}")
            engine = self._deps.field_registry.get(field.type)
            value = params.values.get(field.name)

            # Auto-fill a declared default (e.g. a hidden datetime field defaulting to now).
            if value is None and field.default is not None:
                value = resolve_field_default(field, now)

            if value is None:
                required = bool((field.input_rules or {}).get("required"))
                if required:
                    raise QrsValidationError(f"Missing required value for field '{field.name}'")
                stored_values.append(None)
                continue

            input_error = engine.validate_input(field, value)
            if input_error:
                raise QrsValidationError(f"Field '{field.name}': {input_error.message}")

            if is_stripped_binding(field):
                secrets[field.name] = str(value)
                stored_values.append(None)
            else:
                stored_values.append(engine.encode(field, value))

        issued_at = params.issued_at if params.issued_at is not None else self._deps.clock.now()
        # The TCert linkage (keyId + certificate number) is carried in the COSE
        # protected headers (kid + tcertNumber), NOT in the data — matching the
        # reference implementation and keeping the SDoc minimal for QR transfer.
        sdoc_data: dict[str, Any] = {
            "issuedAt": issued_at,
            "fields": stored_values,
        }

        priv_rec = await self._deps.private_key_store.load(key_id)
        if not priv_rec:
            raise QrsNotFoundError(f"Issuer private key not available: {key_id}")

        external_aad = cbor_encode(secrets) if secrets else b""
        key_pair = KeyPairMaterial(
            algorithm=algorithm,
            public_jwk=public_jwk,
            private_jwk=priv_rec["private_jwk"],
        )
        bytes_out = build_signed_object("sdoc", sdoc_data, key_pair, provider, external_aad, certificate_number)
        sdoc_id = sdoc_id_of(bytes_out)

        await self._deps.document_store.save(sdoc_id, bytes_out)
        return IssueSdocResult(sdoc_id=sdoc_id, bytes=bytes_out, issued_at=issued_at)