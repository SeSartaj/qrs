"""Static data schemas for the signed-object types (TCert, SDoc, Statement,
Attachment).

Every signed object's decoded data MUST conform to the static schema of its type
before the object is accepted. This is the protocol's "each signed object type has
a static schema" guarantee: the decoder never guesses, it validates against a
known shape.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from .errors import QrsParseError, QrsUnsupportedError

__all__ = [
    "FieldKind",
    "DataFieldSpec",
    "ObjectDataSchema",
    "OBJECT_DATA_SCHEMAS",
    "SIGNED_OBJECT_TYPES",
    "STATIC_SIGNED_OBJECT_TYPES",
    "is_signed_object_type",
    "FIELD_TYPES",
    "is_field_type",
    "ACTIONS",
    "is_action",
    "REVOCATION_TYPES",
    "is_revocation_type",
    "validate_object_data",
    "assert_valid_object_data",
]

FieldKind = Literal["text", "int", "bytes", "map", "array", "bool"]


@dataclass(frozen=True)
class DataFieldSpec:
    kind: FieldKind
    required: bool = False


@dataclass(frozen=True)
class ObjectDataSchema:
    fields: dict[str, DataFieldSpec]


OBJECT_DATA_SCHEMAS: dict[str, ObjectDataSchema] = {
    "tcert": ObjectDataSchema(
        fields={
            "keyId": DataFieldSpec(kind="bytes", required=True),
            "certificateNumber": DataFieldSpec(kind="int", required=True),
            "algorithm": DataFieldSpec(kind="text", required=True),
            "publicKey": DataFieldSpec(kind="map", required=True),
            "identity": DataFieldSpec(kind="map", required=True),
            # Schema is optional: a TCert without one is a meta/CA certificate
            # that issues statements (attestation/revocation/blocking) rather than SDocs.
            "schema": DataFieldSpec(kind="array"),
            "hashAlgorithm": DataFieldSpec(kind="text"),
            "validity": DataFieldSpec(kind="map"),
            "metadata": DataFieldSpec(kind="map"),
            "onlineEndpoint": DataFieldSpec(kind="text"),
        }
    ),
    "sdoc": ObjectDataSchema(
        fields={
            "tcertKeyId": DataFieldSpec(kind="bytes", required=True),
            "tcertNumber": DataFieldSpec(kind="int", required=True),
            "issuedAt": DataFieldSpec(kind="int", required=True),
            # Values are stored as a schema-indexed array (no field names/labels).
            "fields": DataFieldSpec(kind="array", required=True),
        }
    ),
    "statement": ObjectDataSchema(
        fields={
            "statementId": DataFieldSpec(kind="bytes", required=True),
            "action": DataFieldSpec(kind="text", required=True),
            "target": DataFieldSpec(kind="map", required=True),
            "issuedAt": DataFieldSpec(kind="int", required=True),
            "validity": DataFieldSpec(kind="map"),
            "reason": DataFieldSpec(kind="text"),
            "revocationType": DataFieldSpec(kind="text"),
            "claims": DataFieldSpec(kind="map"),
        }
    ),
    "attachment": ObjectDataSchema(
        fields={
            # Content-addressed id (truncated content hash) — the handle a
            # verifier uses to fetch the attachment from a distribution server.
            "id": DataFieldSpec(kind="text", required=True),
            "contentType": DataFieldSpec(kind="text", required=True),
            "contentHash": DataFieldSpec(kind="text", required=True),
            "content": DataFieldSpec(kind="bytes", required=True),
            "issuedAt": DataFieldSpec(kind="int", required=True),
        }
    ),
}

SIGNED_OBJECT_TYPES: tuple[str, ...] = ("tcert", "sdoc", "statement", "attachment")

# Signed-object types governed by an app-defined static schema (not a TCert schema).
STATIC_SIGNED_OBJECT_TYPES: tuple[str, ...] = ("statement", "attachment")


def is_signed_object_type(value: Any) -> bool:
    return value in SIGNED_OBJECT_TYPES


FIELD_TYPES: tuple[str, ...] = (
    "text",
    "textarea",
    "select",
    "selectv2",
    "number",
    "date",
    "datetime",
    "datetimeEpoch",
    "location",
    "secretInput",
    "attachment",
)


def is_field_type(value: Any) -> bool:
    return value in FIELD_TYPES


ACTIONS: tuple[str, ...] = ("attest", "addTcert", "revokeTcert", "blockSdoc", "unblockSdoc")


def is_action(value: Any) -> bool:
    return value in ACTIONS


REVOCATION_TYPES: tuple[str, ...] = ("prospective", "retrospective")


def is_revocation_type(value: Any) -> bool:
    return value in REVOCATION_TYPES


def _check_kind(value: Any, spec: DataFieldSpec) -> bool:
    kind = spec.kind
    if kind == "text":
        return isinstance(value, str)
    if kind == "int":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "bytes":
        return isinstance(value, bytes)
    if kind == "map":
        return isinstance(value, dict)
    if kind == "array":
        return isinstance(value, list)
    if kind == "bool":
        return isinstance(value, bool)
    return False


def validate_object_data(obj_type: str, data: Any) -> list[str]:
    """Validate decoded object data against the static schema of its type.

    Returns a list of human-readable errors (empty when valid).
    """
    schema = OBJECT_DATA_SCHEMAS.get(obj_type)
    if schema is None:
        raise QrsUnsupportedError(f"No schema for object type {obj_type}")
    if not isinstance(data, dict):
        return ["object data must be a map"]
    errors: list[str] = []
    for name, spec in schema.fields.items():
        present = name in data
        if not present:
            if spec.required:
                errors.append(f"missing required field '{name}'")
            continue
        if not _check_kind(data[name], spec):
            errors.append(f"field '{name}' must be a {spec.kind}")
    return errors


def assert_valid_object_data(obj_type: str, data: Any) -> None:
    """Assert that decoded object data conforms to its static schema or throw."""
    errors = validate_object_data(obj_type, data)
    if errors:
        raise QrsParseError(f"Invalid {obj_type} data: {'; '.join(errors)}")