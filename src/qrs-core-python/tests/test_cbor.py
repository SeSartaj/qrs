"""Tests for canonical CBOR encoding/decoding."""

from __future__ import annotations

import pytest

from qrs.cbor import cbor_decode, cbor_encode
from qrs.errors import QrsParseError


def test_roundtrip_scalars():
    for value in [None, True, False, 0, 1, -1, 255, 256, 65535, 65536, 2**32, 2**64 - 1, "hello", b"bytes"]:
        assert cbor_decode(cbor_encode(value)) == value


def test_roundtrip_nested():
    value = {"a": 1, "b": [1, 2, 3], "c": {"d": "x", "e": None}, "f": b"\x00\x01"}
    assert cbor_decode(cbor_encode(value)) == value


def test_map_keys_sorted_canonically():
    # Canonical encoding sorts map keys by their encoded bytes.
    a = cbor_encode({"b": 1, "a": 2})
    b = cbor_encode({"a": 2, "b": 1})
    assert a == b


def test_shortest_form_integers():
    # 24 must use the 1-byte form (0x18 0x18), not the 2-byte form.
    assert cbor_encode(24) == b"\x18\x18"
    assert cbor_encode(23) == b"\x17"
    assert cbor_encode(0) == b"\x00"


def test_floats_rejected():
    with pytest.raises(QrsParseError):
        cbor_encode(1.5)


def test_trailing_data_rejected():
    with pytest.raises(QrsParseError):
        cbor_decode(b"\x01\x02")


def test_indefinite_length_rejected():
    # 0x9f is an indefinite-length array start.
    with pytest.raises(QrsParseError):
        cbor_decode(b"\x9f\x01\xff")


def test_negative_integers():
    assert cbor_decode(cbor_encode(-1)) == -1
    assert cbor_decode(cbor_encode(-100)) == -100
    assert cbor_decode(cbor_encode(-2**63)) == -(2**63)