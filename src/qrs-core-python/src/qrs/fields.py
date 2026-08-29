"""Field-model types and the field-engine interface.

A *field engine* implements the semantics of one field type (SOLID: one type, one
engine). Engines are interchangeable and pluggable via a registry. The schema is
defined in a TCert; the verification context supplies whatever external
information a field needs (time, location, secrets, online objects).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

__all__ = [
    "ContextRequirement",
    "FieldResultState",
    "FieldSchema",
    "FieldResult",
    "FieldInputError",
    "VerificationContext",
    "IFieldEngine",
    "is_bound_field",
    "effective_binding",
    "is_stripped_binding",
    "BINDING_FIELD_TYPES",
    "read_number_rule",
    "read_bool_rule",
    "read_string_array_rule",
]

ContextRequirement = Literal["location", "clock", "secret", "onlineObject"]

FieldResultState = Literal[
    "valid",
    "invalid",
    "cannotVerify",
    "missingContext",
    "contextDenied",
    "notSupported",
    "malformed",
    "unavailable",
]


@dataclass
class FieldSchema:
    """Declarative description of one document field (part of the signed TCert schema)."""

    type: str
    name: str
    label: str
    options: list[str] | None = None
    input_rules: dict[str, Any] | None = None
    verify_rules: dict[str, Any] | None = None
    default: Any = None
    binding: Literal["inline", "stripped"] | None = None

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "type": self.type,
            "name": self.name,
            "label": self.label,
        }
        if self.options is not None:
            out["options"] = self.options
        if self.input_rules is not None:
            out["inputRules"] = self.input_rules
        if self.verify_rules is not None:
            out["verifyRules"] = self.verify_rules
        if self.default is not None:
            out["default"] = self.default
        if self.binding is not None:
            out["binding"] = self.binding
        return out

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "FieldSchema":
        return cls(
            type=data["type"],
            name=data["name"],
            label=data.get("label", data["name"]),
            options=data.get("options"),
            input_rules=data.get("inputRules"),
            verify_rules=data.get("verifyRules"),
            default=data.get("default"),
            binding=data.get("binding"),
        )


@dataclass
class FieldResult:
    name: str
    state: FieldResultState
    message: str | None = None
    label: str | None = None


@dataclass
class FieldInputError:
    message: str


class VerificationContext(Protocol):
    """External inputs a field engine may consume during verification.

    The core protocol never calls platform APIs; the application supplies this
    context through its providers (IoC).
    """

    def get_current_time(self) -> int: ...

    async def get_location(self) -> dict[str, float] | None: ...

    async def get_secret(self, field_name: str) -> str | None: ...

    async def get_object(
        self, object_id: str, online_endpoints: list[str] | None = None
    ) -> bytes | None: ...


class IFieldEngine(Protocol):
    """A field engine implements the semantics of one field type."""

    type: str

    def validate_input(self, field: FieldSchema, value: Any) -> FieldInputError | None: ...

    def encode(self, field: FieldSchema, value: Any) -> Any: ...

    def decode(self, field: FieldSchema, encoded: Any) -> Any: ...

    def get_context_requirements(self, field: FieldSchema) -> list[ContextRequirement]: ...

    async def validate_field(
        self, field: FieldSchema, encoded: Any, ctx: VerificationContext
    ) -> FieldResult: ...


# Field types that participate in value binding (verifier re-enters the value).
BINDING_FIELD_TYPES: frozenset[str] = frozenset({"secretInput", "text", "select", "number", "date"})


def is_bound_field(field: FieldSchema) -> bool:
    """Whether a field participates in binding (a verifier prompt is required)."""
    if field.type not in BINDING_FIELD_TYPES:
        return False
    # secretInput is always a bound secret; other types only when binding is declared.
    return field.type == "secretInput" or field.binding is not None


def effective_binding(field: FieldSchema) -> Literal["inline", "stripped"]:
    """Resolve the effective binding mode (defaults per type)."""
    if field.binding is not None:
        return field.binding
    return "stripped" if field.type == "secretInput" else "inline"


def is_stripped_binding(field: FieldSchema) -> bool:
    """Whether the field's value is signed-but-not-stored (carried in the COSE AAD)."""
    return is_bound_field(field) and effective_binding(field) == "stripped"


def read_number_rule(rules: dict[str, Any] | None, key: str, fallback: float) -> float:
    value = rules.get(key) if rules else None
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else fallback


def read_bool_rule(rules: dict[str, Any] | None, key: str, default: bool) -> bool:
    value = rules.get(key) if rules else None
    return value if isinstance(value, bool) else default


def read_string_array_rule(rules: dict[str, Any] | None, key: str) -> list[str]:
    value = rules.get(key) if rules else None
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return value
    return []