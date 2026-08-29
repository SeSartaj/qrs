"""Date / datetime verification rules.

A date or datetime field in the schema may carry ``verify_rules.expressions`` —
a list of small, human-readable rules evaluated at verification time against the
field's value and the verifier's current time. All rules must pass (AND).

Supported expressions (one per array entry):

  ``<today()``  ``<=today()``  ``>today()``  ``>=today()``  ``==today()``
      — the field's date is before/on/after today (UTC calendar date).
  ``day() == 'friday'``  ``day() != 'friday'``
      — the field's weekday (lowercase english: monday..sunday).
  ``daytime == 'day'``  ``daytime == 'night'``
      — the field's time-of-day (day = 06:00–17:59, night = 18:00–05:59).
        Requires a datetime field.
  ``16:00 < x < 23:00``  ``x >= 09:00``
      — the field's clock time in a window. Requires a datetime field.
  ``age() <= 14d``  ``age() >= 2w``  ``age() < 1m``  ``age() == 0h``
      — how old the field's datetime is at verification time (units: m/h/d/w).
        Requires a datetime field (the age is measured against the UTC epoch).

This lets a verifier express things like "the document's expiry date must still
be in the future" (``>today()``), "valid only on Fridays"
(``day() == 'friday'``), or "issued no more than two weeks ago"
(``age() <= 14d``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .fields import FieldSchema

__all__ = ["DateRuleInput", "DateRuleResult", "evaluate_date_expressions"]


@dataclass
class DateRuleInput:
    now: datetime
    field_year: int
    field_month: int  # 1..12
    field_day: int
    field_time: dict[str, int] | None = None  # {"hour": .., "minute": ..}
    field_epoch: int | None = None  # UTC epoch seconds (used by age())


@dataclass
class DateRuleResult:
    ok: bool
    message: str | None = None


_WEEKDAYS = [
    "sunday",
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
]

_RE_TODAY = re.compile(r"^(<=|>=|<|>|==|!=)\s*today\(\)$")
_RE_DAY = re.compile(r"^day\(\)\s*(==|!=)\s*'([a-z]+)'$")
_RE_DAYTIME = re.compile(r"^daytime\s*==\s*'(day|night)'$")
_RE_TWO = re.compile(r"^(\d{1,2}):(\d{2})\s*(<=|>=|<|>)\s*x\s*(<=|>=|<|>)\s*(\d{1,2}):(\d{2})$")
_RE_ONE = re.compile(r"^x\s*(<=|>=|<|>)\s*(\d{1,2}):(\d{2})$")
_RE_AGE = re.compile(r"^age\(\)\s*(<=|>=|<|>|==)\s*(\d+)\s*(m|h|d|w)$")

_UNIT_SECONDS = {"m": 60, "h": 3600, "d": 86_400, "w": 604_800}


def _pad(n: int) -> str:
    return str(n).zfill(2)


def _date_key(year: int, month: int, day: int) -> str:
    return f"{year}-{_pad(month)}-{_pad(day)}"


def _today_key(dt: datetime) -> str:
    return _date_key(dt.year, dt.month, dt.day)


def _cmp(a: float, b: float, op: str) -> bool:
    if op == "<":
        return a < b
    if op == "<=":
        return a <= b
    if op == ">":
        return a > b
    if op == ">=":
        return a >= b
    if op == "==":
        return a == b
    if op == "!=":
        return a != b
    return False


def _flip(op: str) -> str:
    return {"<": ">", "<=": ">=", ">": "<", ">=": "<="}.get(op, op)


def evaluate_date_expressions(expressions: list[str], input: DateRuleInput) -> DateRuleResult:
    """Evaluate a list of expressions (all must pass)."""
    for raw in expressions:
        expr = raw.strip()
        if not expr:
            continue
        result = _evaluate_one(expr, input)
        if not result.ok:
            return result
    return DateRuleResult(ok=True)


def _evaluate_one(expr: str, input: DateRuleInput) -> DateRuleResult:
    m_today = _RE_TODAY.match(expr)
    if m_today:
        a = _date_key(input.field_year, input.field_month, input.field_day)
        b = _today_key(input.now)
        a_key = a  # strings compare lexicographically for ISO dates
        cmp_value = 0 if a_key == b else (-1 if a_key < b else 1)
        if not _cmp(cmp_value, 0, m_today.group(1)):
            return DateRuleResult(ok=False, message=f"rule '{expr}' failed: field {a} vs today {b}")
        return DateRuleResult(ok=True)

    m_day = _RE_DAY.match(expr)
    if m_day:
        expected = m_day.group(2)
        actual = _WEEKDAYS[datetime(input.field_year, input.field_month, input.field_day).weekday()]
        eq = actual == expected
        if (m_day.group(1) == "==" and not eq) or (m_day.group(1) == "!=" and eq):
            return DateRuleResult(ok=False, message=f"rule '{expr}' failed: field falls on {actual}")
        return DateRuleResult(ok=True)

    m_daytime = _RE_DAYTIME.match(expr)
    if m_daytime:
        if input.field_time is None:
            return DateRuleResult(ok=False, message=f"rule '{expr}' requires a datetime field")
        actual = "day" if 6 <= input.field_time["hour"] < 18 else "night"
        if actual != m_daytime.group(1):
            return DateRuleResult(ok=False, message=f"rule '{expr}' failed: it is {actual}")
        return DateRuleResult(ok=True)

    m_two = _RE_TWO.match(expr)
    if m_two:
        if input.field_time is None:
            return DateRuleResult(ok=False, message=f"rule '{expr}' requires a datetime field")
        x = input.field_time["hour"] * 60 + input.field_time["minute"]
        lo = int(m_two.group(1)) * 60 + int(m_two.group(2))
        hi = int(m_two.group(5)) * 60 + int(m_two.group(6))
        if not _cmp(x, lo, _flip(m_two.group(3))) or not _cmp(x, hi, m_two.group(4)):
            h, mi = _pad(input.field_time["hour"]), _pad(input.field_time["minute"])
            return DateRuleResult(ok=False, message=f"rule '{expr}' failed: time is {h}:{mi}")
        return DateRuleResult(ok=True)

    m_one = _RE_ONE.match(expr)
    if m_one:
        if input.field_time is None:
            return DateRuleResult(ok=False, message=f"rule '{expr}' requires a datetime field")
        x = input.field_time["hour"] * 60 + input.field_time["minute"]
        bound = int(m_one.group(2)) * 60 + int(m_one.group(3))
        if not _cmp(x, bound, m_one.group(1)):
            h, mi = _pad(input.field_time["hour"]), _pad(input.field_time["minute"])
            return DateRuleResult(ok=False, message=f"rule '{expr}' failed: time is {h}:{mi}")
        return DateRuleResult(ok=True)

    m_age = _RE_AGE.match(expr)
    if m_age:
        if input.field_epoch is None:
            return DateRuleResult(ok=False, message=f"rule '{expr}' requires a datetime field")
        unit_secs = _UNIT_SECONDS[m_age.group(3)]
        now_secs = int(input.now.timestamp())
        age_units = (now_secs - input.field_epoch) / unit_secs
        bound = int(m_age.group(2))
        if not _cmp(age_units, bound, m_age.group(1)):
            return DateRuleResult(
                ok=False,
                message=f"rule '{expr}' failed: document is {age_units:.1f} {m_age.group(3)} old",
            )
        return DateRuleResult(ok=True)

    return DateRuleResult(ok=False, message=f"unknown date rule '{expr}'")


def resolve_field_default(field: FieldSchema, now_epoch: int) -> Any:
    """Resolve a field's declared default into a concrete value at signing time."""
    default = field.default
    if isinstance(default, dict) and default.get("kind") == "now":
        dt = datetime.fromtimestamp(now_epoch, tz=timezone.utc).replace(tzinfo=None)
        if field.type == "date":
            return f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}"
        return (
            f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}"
            f"T{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}Z"
        )
    return default