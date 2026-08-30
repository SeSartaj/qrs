"""VerificationService: the verification pipeline.

Pipeline:

1. parse the SDoc
2. resolve and verify the TCert (self-signature, id, validity)
3. resolve trust (pinning or CA attestation)
4. evaluate revocation (key, TCert, SDoc block)
5. collect secret inputs, rebuild the COSE external AAD, verify the signature
6. validate the payload against the schema (including contextual fields)
7. produce a structured VerificationResult

The result deliberately distinguishes ``valid``, ``invalid`` and
``cannotVerify`` (e.g. GPS unavailable is NOT the same as "outside the
permitted area").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..cbor import cbor_encode
from ..deps import ServiceDeps
from ..envelope import (
    parse_signed_object,
    sdoc_id_of,
    tcert_id_of,
    tcert_number_of,
    verify_parsed_signed_object,
)
from ..errors import QrsValidationError
from ..fields import (
    FieldResult,
    FieldSchema,
    effective_binding,
    is_bound_field,
    is_stripped_binding,
)
from ..id import to_hex

__all__ = ["VerificationService", "VerificationResult", "VerifyOptions", "VerificationServiceDeps"]


@dataclass
class VerificationServiceDeps:
    """Dependencies for the verification pipeline.

    ``trust_service`` and ``revocation_service`` are injected separately because
    verification composes them (and they in turn depend on the same stores).
    """

    crypto_registry: Any
    field_registry: Any
    certificate_store: Any
    endpoint_config_store: Any
    context_provider: Any
    clock: Any
    trust_service: Any
    revocation_service: Any

    @classmethod
    def from_service_deps(cls, deps: ServiceDeps, trust_service: Any, revocation_service: Any) -> "VerificationServiceDeps":
        return cls(
            crypto_registry=deps.crypto_registry,
            field_registry=deps.field_registry,
            certificate_store=deps.certificate_store,
            endpoint_config_store=deps.endpoint_config_store,
            context_provider=deps.context_provider,
            clock=deps.clock,
            trust_service=trust_service,
            revocation_service=revocation_service,
        )


@dataclass
class VerificationResult:
    overall: str = "cannotVerify"
    cryptographic: str = "cannotVerify"
    tcert: str = "cannotVerify"
    trust: str = "cannotVerify"
    revocation: str = "cannotVerify"
    schema: str = "cannotVerify"
    fields: list[FieldResult] = field(default_factory=list)
    context: str = "satisfied"
    warnings: list[str] = field(default_factory=list)
    sdoc_id: str | None = None
    tcert_id: str | None = None
    message: str | None = None


@dataclass
class VerifyOptions:
    current_time: int | None = None


class VerificationService:
    def __init__(self, deps: VerificationServiceDeps) -> None:
        self._deps = deps

    async def verify(self, data: bytes, options: VerifyOptions | None = None) -> VerificationResult:
        options = options or VerifyOptions()
        result = VerificationResult()

        try:
            parsed = parse_signed_object(data)
        except Exception as exc:
            result.cryptographic = "invalid"
            result.message = str(exc) if isinstance(exc, Exception) else "malformed signed object"
            return self._finalize(result)

        if parsed.type != "sdoc":
            result.cryptographic = "invalid"
            result.message = f"expected an SDoc, got {parsed.type}"
            return self._finalize(result)
        result.sdoc_id = sdoc_id_of(data)

        # ---------- TCert ----------
        # The TCert linkage comes from the COSE protected headers: keyId from
        # `kid`, certificate number from the protocol-private `tcertNumber`
        # header. This matches the reference implementation.
        key_id = parsed.signer_key_id
        try:
            tcert_number = tcert_number_of(parsed)
        except Exception:
            result.tcert = "invalid"
            result.message = "SDoc has no valid tcertNumber"
            return self._finalize(result)
        tcert_id = tcert_id_of(key_id, tcert_number)
        result.tcert_id = tcert_id

        tcert_bytes = await self._deps.certificate_store.get(tcert_id)
        if not tcert_bytes:
            result.tcert = "cannotVerify"
            result.message = "TCert not found locally"
            return self._finalize(result)
        try:
            tcert_parsed = parse_signed_object(tcert_bytes)
        except Exception:
            result.tcert = "invalid"
            result.message = "stored TCert is malformed"
            return self._finalize(result)
        tcert_provider = self._deps.crypto_registry.get(tcert_parsed.algorithm)
        tcert_pub = tcert_parsed.data["publicKey"]
        self_ok = verify_parsed_signed_object(tcert_parsed, tcert_provider, tcert_pub)
        key_id_ok = tcert_provider.key_id(tcert_pub) == to_hex(tcert_parsed.data["keyId"])
        if not self_ok or not key_id_ok:
            result.tcert = "invalid"
            result.message = "TCert self-signature invalid"
            return self._finalize(result)

        now = options.current_time if options.current_time is not None else self._deps.clock.now()
        validity = tcert_parsed.data.get("validity") or {}
        if validity:
            if validity.get("validAfter") is not None and now < validity["validAfter"]:
                result.tcert = "invalid"
                result.message = "TCert is not yet valid"
                return self._finalize(result)
            if validity.get("validBefore") is not None and now >= validity["validBefore"]:
                result.tcert = "invalid"
                result.message = "TCert has expired"
                return self._finalize(result)
            if validity.get("sdocMaxAgeSeconds") is not None:
                sdoc_issued_at = parsed.data.get("issuedAt")
                if isinstance(sdoc_issued_at, int) and now - sdoc_issued_at > validity["sdocMaxAgeSeconds"]:
                    result.schema = "invalid"
                    result.message = "SDoc exceeds the validity duration set by its TCert"
                    return self._finalize(result)
        result.tcert = "valid"

        # ---------- Trust ----------
        trust = await self._deps.trust_service.resolve_trust(tcert_id, tcert_parsed)
        result.trust = trust.state
        if trust.message:
            result.message = trust.message
        if trust.state == "invalid":
            return self._finalize(result)

        # ---------- Revocation ----------
        issued_at = parsed.data.get("issuedAt")
        if not isinstance(issued_at, int):
            result.revocation = "invalid"
            result.message = "SDoc has no valid issuedAt"
            return self._finalize(result)
        revocation = await self._deps.revocation_service.check_revocation(
            tcert_id, key_id, issued_at, result.sdoc_id or ""
        )
        result.revocation = revocation.state
        if revocation.message:
            result.message = revocation.message
        if revocation.state == "invalid":
            return self._finalize(result)

        # ---------- Secrets + signature ----------
        raw_schema = tcert_parsed.data.get("schema")
        if not isinstance(raw_schema, list) or len(raw_schema) == 0:
            result.schema = "invalid"
            result.message = "signer TCert has no document schema"
            return self._finalize(result)
        fields = [FieldSchema.from_json(f) for f in raw_schema]
        secret_values: dict[str, str] = {}
        missing_secret = False
        for field in fields:
            if is_stripped_binding(field):
                secret = await self._deps.context_provider.request_secret(field)
                if secret is None:
                    missing_secret = True
                    result.warnings.append(f"missing bound value '{field.name}'")
                else:
                    secret_values[field.name] = secret
        if missing_secret:
            result.cryptographic = "cannotVerify"
            result.context = "missing"
            result.message = "missing required secret input"
            return self._finalize(result)
        external_aad = cbor_encode(secret_values) if secret_values else b""
        provider = self._deps.crypto_registry.get(parsed.algorithm)
        sig_ok = verify_parsed_signed_object(parsed, provider, tcert_pub, external_aad)
        if not sig_ok:
            result.cryptographic = "invalid"
            result.message = "SDoc signature verification failed (tampered data or incorrect secret)"
            return self._finalize(result)
        result.cryptographic = "valid"

        # ---------- Schema + fields ----------
        stored_values = parsed.data.get("fields") or []
        result.schema = "valid"
        ctx = self._deps.context_provider.build_context()
        for i, field in enumerate(fields):
            if is_stripped_binding(field):
                result.fields.append(
                    FieldResult(name=field.name, state="valid", message="covered by signature (not stored)", label=field.label)
                )
                continue
            engine = self._deps.field_registry.get(field.type)
            encoded = stored_values[i] if i < len(stored_values) else None
            if encoded is None:
                required = bool((field.input_rules or {}).get("required"))
                if required:
                    result.schema = "invalid"
                    result.fields.append(
                        FieldResult(name=field.name, state="invalid", message="missing required field", label=field.label)
                    )
                else:
                    result.fields.append(
                        FieldResult(name=field.name, state="valid", message="absent (optional)", label=field.label)
                    )
                continue

            # Inline-bound fields: the verifier must re-enter the exact stored value.
            if is_bound_field(field) and effective_binding(field) == "inline":
                bound = await self._deps.context_provider.request_secret(field)
                if bound is None:
                    result.fields.append(
                        FieldResult(name=field.name, state="cannotVerify", message="bound value not provided", label=field.label)
                    )
                    result.context = "missing"
                    continue
                presentable = str(engine.decode(field, encoded))
                if bound.strip() != presentable.strip():
                    result.schema = "invalid"
                    result.fields.append(
                        FieldResult(name=field.name, state="invalid", message="binding value mismatch", label=field.label)
                    )
                    continue

            try:
                field_result = await engine.validate_field(field, encoded, ctx)
            except Exception as exc:
                result.schema = "invalid"
                result.fields.append(
                    FieldResult(name=field.name, state="malformed", message=str(exc), label=field.label)
                )
                continue
            result.fields.append(field_result)
            if field_result.state == "invalid":
                result.schema = "invalid"
            if field_result.state in ("cannotVerify", "missingContext"):
                result.context = "missing"
            if field_result.state == "contextDenied":
                result.context = "denied"

        return self._finalize(result)

    def _finalize(self, result: VerificationResult) -> VerificationResult:
        components = [result.cryptographic, result.tcert, result.trust, result.revocation, result.schema]
        if "invalid" in components:
            result.overall = "invalid"
        elif "cannotVerify" in components or result.context in ("missing", "denied"):
            result.overall = "cannotVerify"
        else:
            result.overall = "valid"
        return result