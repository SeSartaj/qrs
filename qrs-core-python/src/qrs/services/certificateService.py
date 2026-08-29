"""CertificateService: key generation and TCert creation.

A TCert combines an issuer identity and the schema of one document type. It is
always self-signed, and its ``key_id`` is derived from its public key. A single
key pair may own several TCerts (one per document type), distinguished by their
certificate number.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..cbor import cbor_encode
from ..crypto.providers import KeyPairMaterial
from ..deps import ServiceDeps
from ..envelope import (
    build_signed_object,
    parse_signed_object,
    tcert_id_of,
    verify_parsed_signed_object,
)
from ..errors import QrsCryptoError, QrsNotFoundError, QrsValidationError
from ..fields import FieldSchema
from ..id import from_hex, is_hash_algorithm, to_hex
from ..signed_object import assert_valid_object_data, is_field_type

__all__ = ["CertificateService", "CreateTcertParams", "CreateTcertResult"]


@dataclass
class CreateTcertParams:
    algorithm: str
    name: str
    fields: list[FieldSchema]
    key_id: str | None = None
    valid_after: int | None = None
    valid_before: int | None = None
    sdoc_max_age_seconds: int | None = None
    hash_algorithm: str | None = None
    online_endpoint: str | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class CreateTcertResult:
    key_id: str
    tcert_id: str
    certificate_number: int
    bytes: bytes
    parsed: Any


class CertificateService:
    def __init__(self, deps: ServiceDeps) -> None:
        self._deps = deps

    async def generate_key_pair(self, algorithm: str) -> str:
        provider = self._deps.crypto_registry.get(algorithm)
        pair = provider.generate_key_pair()
        key_id = provider.key_id(pair.public_jwk)
        await self._deps.private_key_store.save(key_id, algorithm, pair.private_jwk)
        await self._deps.public_key_store.save(key_id, algorithm, pair.public_jwk)
        return key_id

    async def create_tcert(self, params: CreateTcertParams) -> CreateTcertResult:
        for field in params.fields:
            if not is_field_type(field.type):
                raise QrsValidationError(f"Unsupported field type: {field.type}")
            if not field.name or not field.label:
                raise QrsValidationError("Each field must have a name and a label")
            if not self._deps.field_registry.has(field.type):
                raise QrsValidationError(f"No field engine registered for type: {field.type}")

        key_id = params.key_id
        if not key_id:
            key_id = await self.generate_key_pair(params.algorithm)

        pub_rec = await self._deps.public_key_store.load(key_id)
        if not pub_rec:
            raise QrsNotFoundError(f"Public key not found: {key_id}")
        priv_rec = await self._deps.private_key_store.load(key_id)
        if not priv_rec:
            raise QrsNotFoundError(f"Private key not available for signing: {key_id}")

        provider = self._deps.crypto_registry.get(pub_rec["algorithm"])

        # Pick the lowest unused certificate number (1..255) for this key.
        existing = await self._deps.certificate_store.find_by_key_id(key_id)
        used = {int(tcert_id.split(":")[1]) for tcert_id, _ in existing}
        certificate_number = 0
        for n in range(1, 256):
            if n not in used:
                certificate_number = n
                break
        if certificate_number == 0:
            raise QrsValidationError("No certificate numbers left for this key")

        data: dict[str, Any] = {
            "keyId": from_hex(key_id),
            "certificateNumber": certificate_number,
            "algorithm": provider.algorithm,
            "publicKey": pub_rec["public_jwk"],
            "identity": {"name": params.name},
            "schema": [f.to_json() for f in params.fields],
        }
        validity: dict[str, Any] = {}
        if params.valid_after is not None:
            validity["validAfter"] = params.valid_after
        if params.valid_before is not None:
            validity["validBefore"] = params.valid_before
        if params.sdoc_max_age_seconds is not None:
            validity["sdocMaxAgeSeconds"] = params.sdoc_max_age_seconds
        if validity:
            data["validity"] = validity
        if params.hash_algorithm is not None:
            if not is_hash_algorithm(params.hash_algorithm):
                raise QrsValidationError(f"Unsupported hash algorithm: {params.hash_algorithm}")
            data["hashAlgorithm"] = params.hash_algorithm
        if params.online_endpoint:
            data["onlineEndpoint"] = params.online_endpoint
        if params.metadata:
            data["metadata"] = params.metadata

        key_pair = KeyPairMaterial(
            algorithm=provider.algorithm,
            public_jwk=pub_rec["public_jwk"],
            private_jwk=priv_rec["private_jwk"],
        )
        data_bytes = cbor_encode(data)
        payload = cbor_encode([1, "tcert", data_bytes])
        bytes_out = build_signed_object("tcert", data, key_pair, provider)
        parsed = parse_signed_object(bytes_out)
        assert_valid_object_data("tcert", parsed.data)

        if not verify_parsed_signed_object(parsed, provider, pub_rec["public_jwk"]):
            raise QrsCryptoError("TCert self-signature verification failed")

        tcert_id = tcert_id_of(key_id, certificate_number)
        await self._deps.certificate_store.save(tcert_id, bytes_out)
        return CreateTcertResult(
            key_id=key_id,
            tcert_id=tcert_id,
            certificate_number=certificate_number,
            bytes=bytes_out,
            parsed=parsed,
        )

    async def get_tcert(self, tcert_id: str) -> tuple[bytes, Any]:
        data = await self._deps.certificate_store.get(tcert_id)
        if not data:
            raise QrsNotFoundError(f"TCert not found: {tcert_id}")
        return data, parse_signed_object(data)

    async def public_key_of(self, tcert_id: str) -> tuple[str, dict[str, Any]]:
        _, parsed = await self.get_tcert(tcert_id)
        return parsed.data["algorithm"], parsed.data["publicKey"]