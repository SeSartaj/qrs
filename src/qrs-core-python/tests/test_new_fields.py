"""Tests for the new field engines: textarea, datetimeEpoch, selectv2."""

from __future__ import annotations

import pytest

from qrs.fields import FieldSchema
from qrs.field_engines import (
    DatetimeEpochField,
    SelectV2Field,
    TextareaField,
)


def test_textarea_validates_and_normalizes():
    engine = TextareaField()
    field = FieldSchema(type="textarea", name="notes", label="Notes", input_rules={"required": True, "minLength": 2})
    assert engine.validate_input(field, "") is not None
    assert engine.validate_input(field, "a") is not None
    assert engine.validate_input(field, "line1\nline2") is None
    assert engine.validate_input(field, 5) is not None
    assert engine.encode(field, "\u0065\u0301") == "\u00e9"


def test_datetime_epoch_validates_integer():
    engine = DatetimeEpochField()
    field = FieldSchema(type="datetimeEpoch", name="t", label="T")
    assert engine.validate_input(field, 1_700_000_000) is None
    assert engine.validate_input(field, 1.5) is not None
    assert engine.validate_input(field, "x") is not None


@pytest.mark.asyncio
async def test_datetime_epoch_date_expressions():
    engine = DatetimeEpochField()
    field = FieldSchema(type="datetimeEpoch", name="t", label="T", verify_rules={"expressions": ["age() <= 14d"]})

    class Ctx:
        def get_current_time(self):
            return 0

        async def get_location(self):
            return None

        async def get_secret(self, name):
            return None

        async def get_object(self, oid, online_endpoints=None):
            return None

    ctx = Ctx()
    assert (await engine.validate_field(field, 0, ctx)).state == "valid"
    assert (await engine.validate_field(field, -2_000_000, ctx)).state == "invalid"


def test_selectv2_stores_only_index():
    engine = SelectV2Field()
    field = FieldSchema(
        type="selectv2",
        name="status",
        label="Status",
        input_rules={
            "options": [
                {"label": "Active", "value": "active", "color": "#34c98f"},
                {"label": "Expired", "value": "expired", "color": "#ef6a6a"},
            ]
        },
    )
    assert engine.validate_input(field, 0) is None
    assert engine.validate_input(field, 1) is None
    assert engine.validate_input(field, 2) is not None
    assert engine.validate_input(field, -1) is not None
    assert engine.validate_input(field, "active") is not None


def test_selectv2_accepts_plain_string_options():
    engine = SelectV2Field()
    field = FieldSchema(type="selectv2", name="s", label="S", options=["a", "b"])
    assert engine.validate_input(field, 0) is None
    assert engine.validate_input(field, 1) is None
    assert engine.validate_input(field, 2) is not None