"""Reference field engines.

Each engine implements the semantics of one declarative field type, mirroring the
reference implementation: text, select, number, date, datetime, location,
secretInput and attachment. Engines are pluggable — add a new field type by
implementing :class:`~qrs.fields.IFieldEngine` and registering it.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .cbor import cbor_encode
from .constants import MICRODEGREES
from .date_rules import DateRuleInput, evaluate_date_expressions
from .errors import QrsValidationError
from .fields import (
    FieldInputError,
    FieldResult,
    FieldSchema,
    IFieldEngine,
    VerificationContext,
    read_bool_rule,
    read_number_rule,
    read_string_array_rule,
)

__all__ = [
    "TextField",
    "TextareaField",
    "SelectField",
    "SelectV2Field",
    "NumberField",
    "DateField",
    "DateTimeField",
    "DatetimeEpochField",
    "LocationField",
    "SecretInputField",
    "AttachmentField",
    "code_point_length",
    "canonical_decimal_string",
    "is_valid_calendar_date",
    "is_valid_utc_datetime",
    "haversine_distance",
    "evaluate_date_expressions",
    "date_rules",
]


def code_point_length(value: str) -> int:
    """Length of a string in Unicode code points (language-agnostic semantics)."""
    return len(value)


class TextField(IFieldEngine):
    type = "text"

    def validate_input(self, field: FieldSchema, value: Any) -> FieldInputError | None:
        if not isinstance(value, str):
            return FieldInputError(message=f"{field.name} must be a string")
        rules = field.input_rules or {}
        required = read_bool_rule(rules, "required", False)
        min_length = int(read_number_rule(rules, "minLength", 0))
        max_rule = read_number_rule(rules, "maxLength", float("inf"))
        max_length = int(max_rule) if math.isfinite(max_rule) else float("inf")
        length = code_point_length(value)
        if required and length == 0:
            return FieldInputError(message=f"{field.label} is required")
        if length < min_length:
            return FieldInputError(message=f"{field.label} must be at least {min_length} characters")
        if max_length != float("inf") and length > max_length:
            return FieldInputError(message=f"{field.label} must be at most {int(max_length)} characters")
        return None

    def encode(self, field: FieldSchema, value: Any) -> Any:
        # NFC normalization keeps the canonical representation deterministic.
        return _normalize_nfc(str(value))

    def decode(self, field: FieldSchema, encoded: Any) -> Any:
        return encoded

    def get_context_requirements(self, field: FieldSchema) -> list[str]:
        return []

    async def validate_field(self, field: FieldSchema, encoded: Any, ctx: VerificationContext) -> FieldResult:
        err = self.validate_input(field, encoded)
        return (
            FieldResult(name=field.name, state="invalid", message=err.message, label=field.label)
            if err
            else FieldResult(name=field.name, state="valid", label=field.label)
        )


class TextareaField(IFieldEngine):
    """Multi-line text. Semantically identical to ``text`` but for longer content."""

    type = "textarea"

    def validate_input(self, field: FieldSchema, value: Any) -> FieldInputError | None:
        if not isinstance(value, str):
            return FieldInputError(message=f"{field.name} must be a string")
        rules = field.input_rules or {}
        required = read_bool_rule(rules, "required", False)
        min_length = int(read_number_rule(rules, "minLength", 0))
        max_rule = read_number_rule(rules, "maxLength", float("inf"))
        max_length = int(max_rule) if math.isfinite(max_rule) else float("inf")
        length = code_point_length(value)
        if required and length == 0:
            return FieldInputError(message=f"{field.label} is required")
        if length < min_length:
            return FieldInputError(message=f"{field.label} must be at least {min_length} characters")
        if max_length != float("inf") and length > max_length:
            return FieldInputError(message=f"{field.label} must be at most {int(max_length)} characters")
        return None

    def encode(self, field: FieldSchema, value: Any) -> Any:
        return _normalize_nfc(str(value))

    def decode(self, field: FieldSchema, encoded: Any) -> Any:
        return encoded

    def get_context_requirements(self, field: FieldSchema) -> list[str]:
        return []

    async def validate_field(self, field: FieldSchema, encoded: Any, ctx: VerificationContext) -> FieldResult:
        err = self.validate_input(field, encoded)
        return (
            FieldResult(name=field.name, state="invalid", message=err.message, label=field.label)
            if err
            else FieldResult(name=field.name, state="valid", label=field.label)
        )


class SelectField(IFieldEngine):
    type = "select"

    def validate_input(self, field: FieldSchema, value: Any) -> FieldInputError | None:
        if not isinstance(value, str):
            return FieldInputError(message=f"{field.name} must be a string")
        rules = field.input_rules or {}
        required = read_bool_rule(rules, "required", False)
        options = read_string_array_rule(rules, "options")
        if not options:
            options = list(field.options or [])
        if required and len(value) == 0:
            return FieldInputError(message=f"{field.label} is required")
        if options and value not in options:
            return FieldInputError(message=f"{field.label} must be one of: {', '.join(options)}")
        return None

    def encode(self, field: FieldSchema, value: Any) -> Any:
        return value

    def decode(self, field: FieldSchema, encoded: Any) -> Any:
        return encoded

    def get_context_requirements(self, field: FieldSchema) -> list[str]:
        return []

    async def validate_field(self, field: FieldSchema, encoded: Any, ctx: VerificationContext) -> FieldResult:
        err = self.validate_input(field, encoded)
        return (
            FieldResult(name=field.name, state="invalid", message=err.message, label=field.label)
            if err
            else FieldResult(name=field.name, state="valid", label=field.label)
        )


class SelectV2Field(IFieldEngine):
    """A select whose options may carry an optional color.

    For QR size optimization, only the *index* of the selected option is stored
    in the SDoc; the full option details (label/value/color) live in the TCert
    schema and are reconstructed at presentation time.
    """

    type = "selectv2"

    def _read_options(self, field: FieldSchema) -> list[dict[str, Any]]:
        raw = (field.input_rules or {}).get("options")
        if isinstance(raw, list):
            out: list[dict[str, Any]] = []
            for option in raw:
                if isinstance(option, str):
                    out.append({"label": option, "value": option})
                elif isinstance(option, dict):
                    label = option.get("label")
                    value = option.get("value")
                    label = label if isinstance(label, str) else str(value if value is not None else "")
                    value = value if isinstance(value, str) else label
                    color = option.get("color")
                    out.append({"label": label, "value": value, "color": color if isinstance(color, str) else None})
            return out
        return [{"label": o, "value": o} for o in (field.options or [])]

    def validate_input(self, field: FieldSchema, value: Any) -> FieldInputError | None:
        if isinstance(value, bool) or not isinstance(value, int):
            return FieldInputError(message=f"{field.name} must be an option index (integer)")
        options = self._read_options(field)
        required = read_bool_rule(field.input_rules, "required", False)
        if required and len(options) == 0:
            return FieldInputError(message=f"{field.label} has no options")
        if value < 0 or value >= len(options):
            return FieldInputError(message=f"{field.label} must be a valid option index (0..{len(options) - 1})")
        return None

    def encode(self, field: FieldSchema, value: Any) -> Any:
        return value

    def decode(self, field: FieldSchema, encoded: Any) -> Any:
        return encoded

    def get_context_requirements(self, field: FieldSchema) -> list[str]:
        return []

    async def validate_field(self, field: FieldSchema, encoded: Any, ctx: VerificationContext) -> FieldResult:
        err = self.validate_input(field, encoded)
        return (
            FieldResult(name=field.name, state="invalid", message=err.message, label=field.label)
            if err
            else FieldResult(name=field.name, state="valid", label=field.label)
        )


def canonical_decimal_string(value: float) -> str:
    """Canonical string form of a decimal value.

    Two floats with the same semantic value always produce the same string
    (e.g. 12.50 → "12.5"), so a decimal can never have two cryptographically
    distinct encodings.
    """
    fixed = f"{value:.10f}".rstrip("0").rstrip(".")
    return "0" if fixed == "-0" else fixed


class NumberField(IFieldEngine):
    type = "number"

    def validate_input(self, field: FieldSchema, value: Any) -> FieldInputError | None:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or math.isnan(value):
            return FieldInputError(message=f"{field.name} must be a number")
        rules = field.input_rules or {}
        minimum = rules.get("min")
        maximum = rules.get("max")
        if isinstance(minimum, (int, float)) and value < minimum:
            return FieldInputError(message=f"{field.label} must be >= {minimum}")
        if isinstance(maximum, (int, float)) and value > maximum:
            return FieldInputError(message=f"{field.label} must be <= {maximum}")
        return None

    def encode(self, field: FieldSchema, value: Any) -> Any:
        num = value
        if isinstance(num, int) and not isinstance(num, bool):
            return num
        return canonical_decimal_string(float(num))

    def decode(self, field: FieldSchema, encoded: Any) -> Any:
        if isinstance(encoded, bool):
            return encoded
        if isinstance(encoded, int):
            return encoded
        if isinstance(encoded, str):
            try:
                return float(encoded)
            except ValueError:
                return encoded
        return encoded

    def get_context_requirements(self, field: FieldSchema) -> list[str]:
        return []

    async def validate_field(self, field: FieldSchema, encoded: Any, ctx: VerificationContext) -> FieldResult:
        err = self.validate_input(field, self.decode(field, encoded))
        return (
            FieldResult(name=field.name, state="invalid", message=err.message, label=field.label)
            if err
            else FieldResult(name=field.name, state="valid", label=field.label)
        )


_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")


def is_valid_calendar_date(value: str) -> bool:
    """Validate a calendar date and its component values."""
    m = _DATE_RE.match(value)
    if not m:
        return False
    year, month, day = (int(g) for g in m.groups())
    try:
        datetime(year, month, day)
        return True
    except ValueError:
        return False


class DateField(IFieldEngine):
    type = "date"

    def validate_input(self, field: FieldSchema, value: Any) -> FieldInputError | None:
        if not isinstance(value, str) or not is_valid_calendar_date(value):
            return FieldInputError(message=f"{field.label} must be a valid date in YYYY-MM-DD form")
        return None

    def encode(self, field: FieldSchema, value: Any) -> Any:
        return value

    def decode(self, field: FieldSchema, encoded: Any) -> Any:
        return encoded

    def get_context_requirements(self, field: FieldSchema) -> list[str]:
        return []

    async def validate_field(self, field: FieldSchema, encoded: Any, ctx: VerificationContext) -> FieldResult:
        err = self.validate_input(field, encoded)
        if err:
            return FieldResult(name=field.name, state="invalid", message=err.message, label=field.label)
        expressions = read_string_array_rule(field.verify_rules, "expressions")
        if expressions:
            try:
                year, month, day = (int(part) for part in str(encoded).split("-")[:3])
            except ValueError:
                return FieldResult(name=field.name, state="invalid", message="malformed date value", label=field.label)
            result = evaluate_date_expressions(
                expressions,
                DateRuleInput(
                    now=datetime.fromtimestamp(ctx.get_current_time(), tz=timezone.utc),
                    field_year=year,
                    field_month=month,
                    field_day=day,
                    field_time=None,
                ),
            )
            if not result.ok:
                return FieldResult(
                    name=field.name, state="invalid", message=result.message, label=field.label
                )
        return FieldResult(name=field.name, state="valid", label=field.label)


_DATETIME_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$")


def is_valid_utc_datetime(value: str) -> bool:
    """Validate a canonical UTC datetime string (YYYY-MM-DDTHH:mm:ssZ)."""
    m = _DATETIME_RE.match(value)
    if not m:
        return False
    try:
        datetime(
            *(int(g) for g in m.groups()), tzinfo=timezone.utc
        )
        return True
    except ValueError:
        return False


class DateTimeField(IFieldEngine):
    type = "datetime"

    def validate_input(self, field: FieldSchema, value: Any) -> FieldInputError | None:
        if not isinstance(value, str) or not is_valid_utc_datetime(value):
            return FieldInputError(
                message=f"{field.label} must be a valid UTC datetime in YYYY-MM-DDTHH:mm:ssZ form"
            )
        return None

    def encode(self, field: FieldSchema, value: Any) -> Any:
        return value

    def decode(self, field: FieldSchema, encoded: Any) -> Any:
        return encoded

    def get_context_requirements(self, field: FieldSchema) -> list[str]:
        return []

    async def validate_field(self, field: FieldSchema, encoded: Any, ctx: VerificationContext) -> FieldResult:
        err = self.validate_input(field, encoded)
        if err:
            return FieldResult(name=field.name, state="invalid", message=err.message, label=field.label)
        expressions = read_string_array_rule(field.verify_rules, "expressions")
        if expressions:
            m = _DATETIME_RE.match(str(encoded))
            if not m:
                return FieldResult(name=field.name, state="invalid", message="malformed datetime value", label=field.label)
            dt = datetime(*(int(g) for g in m.groups()), tzinfo=timezone.utc)
            result = evaluate_date_expressions(
                expressions,
                DateRuleInput(
                    now=datetime.fromtimestamp(ctx.get_current_time(), tz=timezone.utc),
                    field_year=dt.year,
                    field_month=dt.month,
                    field_day=dt.day,
                    field_time={"hour": dt.hour, "minute": dt.minute},
                    field_epoch=int(dt.timestamp()),
                ),
            )
            if not result.ok:
                return FieldResult(
                    name=field.name, state="invalid", message=result.message, label=field.label
                )
        return FieldResult(name=field.name, state="valid", label=field.label)


class DatetimeEpochField(IFieldEngine):
    """Stores a UTC epoch (integer seconds) directly.

    Compact (a single integer) and timezone-agnostic on the wire; converted to a
    human-readable local date/time only at presentation time.
    """

    type = "datetimeEpoch"

    def validate_input(self, field: FieldSchema, value: Any) -> FieldInputError | None:
        if isinstance(value, bool) or not isinstance(value, int):
            return FieldInputError(message=f"{field.label} must be an integer epoch (seconds)")
        return None

    def encode(self, field: FieldSchema, value: Any) -> Any:
        return value

    def decode(self, field: FieldSchema, encoded: Any) -> Any:
        return encoded

    def get_context_requirements(self, field: FieldSchema) -> list[str]:
        return []

    async def validate_field(self, field: FieldSchema, encoded: Any, ctx: VerificationContext) -> FieldResult:
        if isinstance(encoded, bool) or not isinstance(encoded, int):
            return FieldResult(
                name=field.name, state="invalid", message="must be an integer epoch (seconds)", label=field.label
            )
        expressions = read_string_array_rule(field.verify_rules, "expressions")
        if expressions:
            dt = datetime.fromtimestamp(encoded, tz=timezone.utc)
            result = evaluate_date_expressions(
                expressions,
                DateRuleInput(
                    now=datetime.fromtimestamp(ctx.get_current_time(), tz=timezone.utc),
                    field_year=dt.year,
                    field_month=dt.month,
                    field_day=dt.day,
                    field_time={"hour": dt.hour, "minute": dt.minute},
                    field_epoch=encoded,
                ),
            )
            if not result.ok:
                return FieldResult(
                    name=field.name, state="invalid", message=result.message, label=field.label
                )
        return FieldResult(name=field.name, state="valid", label=field.label)


def haversine_distance(a: dict[str, float], b: dict[str, float]) -> float:
    """Great-circle distance in metres between two {lat, lon} points."""
    to_rad = math.radians
    radius = 6_371_000.0
    d_lat = to_rad(b["lat"] - a["lat"])
    d_lon = to_rad(b["lon"] - a["lon"])
    h = (
        math.sin(d_lat / 2) ** 2
        + math.cos(to_rad(a["lat"])) * math.cos(to_rad(b["lat"])) * math.sin(d_lon / 2) ** 2
    )
    return 2 * radius * math.asin(math.sqrt(h))


class LocationField(IFieldEngine):
    type = "location"

    def validate_input(self, field: FieldSchema, value: Any) -> FieldInputError | None:
        if not isinstance(value, dict):
            return FieldInputError(message=f"{field.label} must be an object with lat and lon")
        lat = value.get("lat")
        lon = value.get("lon")
        if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
            return FieldInputError(message=f"{field.label} must be an object with lat and lon")
        if math.isnan(lat) or lat < -90 or lat > 90:
            return FieldInputError(message=f"{field.label} lat must be in [-90, 90]")
        if math.isnan(lon) or lon < -180 or lon > 180:
            return FieldInputError(message=f"{field.label} lon must be in [-180, 180]")
        return None

    def encode(self, field: FieldSchema, value: Any) -> dict[str, int]:
        return {"lat": round(float(value["lat"]) * MICRODEGREES), "lon": round(float(value["lon"]) * MICRODEGREES)}

    def decode(self, field: FieldSchema, encoded: Any) -> dict[str, float]:
        if not isinstance(encoded, dict) or not isinstance(encoded.get("lat"), int) or not isinstance(encoded.get("lon"), int):
            raise QrsValidationError("Stored location must contain integer microdegree lat/lon")
        return {"lat": encoded["lat"] / MICRODEGREES, "lon": encoded["lon"] / MICRODEGREES}

    def get_context_requirements(self, field: FieldSchema) -> list[str]:
        return ["location"]

    async def validate_field(self, field: FieldSchema, encoded: Any, ctx: VerificationContext) -> FieldResult:
        current = await ctx.get_location()
        if current is None:
            return FieldResult(name=field.name, state="cannotVerify", message="location unavailable at verification time", label=field.label)
        stored = self.decode(field, encoded)
        max_radius = read_number_rule(field.verify_rules, "maxRadius", 0)
        distance = haversine_distance(current, stored)
        if distance <= max_radius:
            return FieldResult(name=field.name, state="valid", message=f"within {int(max_radius)}m ({round(distance)}m)", label=field.label)
        return FieldResult(
            name=field.name,
            state="invalid",
            message=f"outside permitted area ({round(distance)}m > {int(max_radius)}m)",
            label=field.label,
        )


class SecretInputField(IFieldEngine):
    type = "secretInput"

    def validate_input(self, field: FieldSchema, value: Any) -> FieldInputError | None:
        if not isinstance(value, str):
            return FieldInputError(message=f"{field.name} must be a string")
        rules = field.input_rules or {}
        required = read_bool_rule(rules, "required", True)
        min_length = rules.get("minLength")
        if required and len(value) == 0:
            return FieldInputError(message=f"{field.label} is required")
        if isinstance(min_length, (int, float)) and len(value) < min_length:
            return FieldInputError(message=f"{field.label} must be at least {int(min_length)} characters")
        return None

    def encode(self, field: FieldSchema, value: Any) -> Any:
        return value

    def decode(self, field: FieldSchema, encoded: Any) -> Any:
        return encoded

    def get_context_requirements(self, field: FieldSchema) -> list[str]:
        return ["secret"]

    def is_stripped(self, field: FieldSchema) -> bool:
        return (field.binding or "stripped") == "stripped"

    async def validate_field(self, field: FieldSchema, encoded: Any, ctx: VerificationContext) -> FieldResult:
        if self.is_stripped(field):
            return FieldResult(name=field.name, state="valid", message="covered by signature (not stored)", label=field.label)
        err = self.validate_input(field, encoded)
        return (
            FieldResult(name=field.name, state="invalid", message=err.message, label=field.label)
            if err
            else FieldResult(name=field.name, state="valid", label=field.label)
        )


_ATTACHMENT_HASH_RE = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)


def attachment_reference(content: bytes) -> dict[str, Any]:
    """Build the compact, content-addressed reference stored in an SDoc/QR.

    ``hash`` is the first 128 bits of SHA-256; ``size`` the byte length.
    """
    from .id import sha256, to_hex

    return {"hash": to_hex(sha256(content))[:32], "size": len(content)}


def verify_attachment_reference(reference: dict[str, Any], content: bytes) -> bool:
    """Verify downloaded bytes against the compact reference signed into the SDoc."""
    actual = attachment_reference(content)
    return actual["hash"] == reference["hash"].lower() and actual["size"] == reference["size"]


class AttachmentField(IFieldEngine):
    type = "attachment"

    def validate_input(self, field: FieldSchema, value: Any) -> FieldInputError | None:
        if not isinstance(value, dict):
            return FieldInputError(message=f"{field.label} must be an attachment reference {{ hash, size }}")
        hash_value = value.get("hash")
        size_value = value.get("size")
        if not isinstance(hash_value, str) or not _ATTACHMENT_HASH_RE.match(hash_value):
            return FieldInputError(
                message=f"{field.label} must have a valid content hash (128-bit, 32 hex chars)"
            )
        if isinstance(size_value, bool) or not isinstance(size_value, int) or size_value < 0:
            return FieldInputError(message=f"{field.label} must have a non-negative integer size")
        return None

    def encode(self, field: FieldSchema, value: Any) -> Any:
        return value

    def decode(self, field: FieldSchema, encoded: Any) -> Any:
        return encoded

    def get_context_requirements(self, field: FieldSchema) -> list[str]:
        return []

    async def validate_field(self, field: FieldSchema, encoded: Any, ctx: VerificationContext) -> FieldResult:
        err = self.validate_input(field, encoded)
        return (
            FieldResult(name=field.name, state="invalid", message=err.message, label=field.label)
            if err
            else FieldResult(name=field.name, state="valid", label=field.label)
        )


def _normalize_nfc(value: str) -> str:
    import unicodedata

    return unicodedata.normalize("NFC", value)