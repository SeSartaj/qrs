"""Field registry: maps field types to field engines.

The registry is what makes the scheme extendible — a consumer can register a new
field engine without touching the core. The reference registry ships the eight
engines from :mod:`qrs.field_engines`.
"""

from __future__ import annotations

from .errors import QrsUnsupportedError
from .field_engines import (
    AttachmentField,
    DateField,
    DateTimeField,
    DatetimeEpochField,
    LocationField,
    NumberField,
    SecretInputField,
    SelectField,
    SelectV2Field,
    TextField,
    TextareaField,
)
from .fields import IFieldEngine

__all__ = ["FieldRegistry", "create_default_field_registry"]


class FieldRegistry:
    """Registry of field engines keyed by field type."""

    def __init__(self, engines: list[IFieldEngine] | None = None) -> None:
        self._engines: dict[str, IFieldEngine] = {}
        for engine in engines or []:
            self.register(engine)

    def register(self, engine: IFieldEngine) -> "FieldRegistry":
        self._engines[engine.type] = engine
        return self

    def get(self, field_type: str) -> IFieldEngine:
        try:
            return self._engines[field_type]
        except KeyError:
            raise QrsUnsupportedError(f"Unsupported field type: {field_type}") from None

    def has(self, field_type: str) -> bool:
        return field_type in self._engines

    def list(self) -> list[IFieldEngine]:
        return list(self._engines.values())


def create_default_field_registry() -> FieldRegistry:
    """The reference field engines the implementation ships with."""
    return FieldRegistry(
        [
            TextField(),
            TextareaField(),
            SelectField(),
            SelectV2Field(),
            NumberField(),
            DateField(),
            DateTimeField(),
            DatetimeEpochField(),
            LocationField(),
            SecretInputField(),
            AttachmentField(),
        ]
    )