"""Canonical (deterministic) CBOR encoding and decoding — the wire format of the protocol.

Rules (RFC 8949 §4.2.1 "Core Deterministic Encoding Requirements"):

- definite-length items only (never indefinite);
- integers encoded in the shortest possible form;
- string lengths in the shortest possible form;
- map keys sorted in bytewise lexicographic order of their encoded form;
- floats are NOT produced (regulated decimals use canonical strings instead);
- text strings are UTF-8; map keys are compared by their encoded bytes.

Python object mapping:

- ``dict`` (str keys) → CBOR map; ``bytes`` → CBOR byte string; ``list``/``tuple``
  → CBOR array; ``int`` → CBOR integer; ``str`` → CBOR text; ``bool``/``None`` →
  CBOR simple values.
- Decoding maps with text keys → ``dict``; maps with non-text keys → ``dict`` of
  ``(key, value)`` pairs as-is (protocol data never uses non-text keys).

This mirrors the canonical profile of the TypeScript reference implementation
(qrs-core), so signed objects are byte-identical across languages.
"""

from __future__ import annotations

from typing import Any

from .errors import QrsParseError, QrsUnsupportedError

MT_UINT = 0
MT_NINT = 1
MT_BYTES = 2
MT_TEXT = 3
MT_ARRAY = 4
MT_MAP = 5
MT_TAG = 6
MT_SIMPLE = 7

__all__ = ["cbor_encode", "cbor_decode", "compare_bytes"]


def _encode_head(major: int, value: int) -> bytes:
    initial = major << 5
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise QrsParseError("Integer out of CBOR range")
    if value < 24:
        return bytes([initial | value])
    if value <= 0xFF:
        return bytes([initial | 24, value])
    if value <= 0xFFFF:
        return bytes([initial | 25, (value >> 8) & 0xFF, value & 0xFF])
    if value <= 0xFFFFFFFF:
        return bytes(
            [initial | 26, (value >> 24) & 0xFF, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF]
        )
    return bytes([initial | 27]) + value.to_bytes(8, "big")


def _encode_int(value: int) -> bytes:
    if value >= 0:
        return _encode_head(MT_UINT, value)
    return _encode_head(MT_NINT, -value - 1)


def _encode_value(value: Any) -> bytes:
    if value is None:
        return b"\xf6"
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return _encode_int(value)
    if isinstance(value, float):
        raise QrsParseError(
            "Floating point values are not allowed by the canonical profile; "
            "use integers or canonical decimal strings"
        )
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _encode_head(MT_TEXT, len(raw)) + raw
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        return _encode_head(MT_BYTES, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        parts = [_encode_head(MT_ARRAY, len(value))]
        for item in value:
            parts.append(_encode_value(item))
        return b"".join(parts)
    if isinstance(value, dict):
        entries: list[tuple[bytes, bytes]] = []
        for key, val in value.items():
            entries.append((_encode_value(key), _encode_value(val)))
        entries.sort(key=lambda pair: pair[0])
        parts = [_encode_head(MT_MAP, len(entries))]
        for key_bytes, val_bytes in entries:
            parts.append(key_bytes)
            parts.append(val_bytes)
        return b"".join(parts)
    raise QrsUnsupportedError(f"Unsupported CBOR value type: {type(value).__name__}")


def compare_bytes(a: bytes, b: bytes) -> int:
    """Bytewise lexicographic comparison (used for canonical map key ordering)."""
    if a == b:
        return 0
    return -1 if a < b else 1


def cbor_encode(value: Any) -> bytes:
    """Deterministically encode a value to canonical CBOR bytes."""
    return _encode_value(value)


class _Decoder:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def _read_byte(self) -> int:
        if self._pos >= len(self._data):
            raise QrsParseError("Unexpected end of CBOR input")
        value = self._data[self._pos]
        self._pos += 1
        return value

    def _read_bytes(self, n: int) -> bytes:
        if self._pos + n > len(self._data):
            raise QrsParseError("Unexpected end of CBOR input")
        out = self._data[self._pos : self._pos + n]
        self._pos += n
        return out

    def _read_head(self) -> tuple[int, int, int]:
        b = self._read_byte()
        major = b >> 5
        info = b & 0x1F
        if major == MT_SIMPLE and info in (25, 26, 27):
            return major, info, 0
        if info < 24:
            return major, info, info
        if info == 24:
            return major, info, self._read_byte()
        if info == 25:
            raw = self._read_bytes(2)
            return major, info, int.from_bytes(raw, "big")
        if info == 26:
            raw = self._read_bytes(4)
            return major, info, int.from_bytes(raw, "big")
        if info == 27:
            raw = self._read_bytes(8)
            return major, info, int.from_bytes(raw, "big")
        raise QrsParseError("Indefinite-length items are not supported by the canonical profile")

    def _decode_float(self, info: int) -> float:
        if info == 25:
            bits = int.from_bytes(self._read_bytes(2), "big")
            sign = -1.0 if bits >> 15 else 1.0
            exp = (bits >> 10) & 0x1F
            frac = bits & 0x3FF
            if exp == 0:
                return sign * (2.0**-14) * (frac / 1024.0)
            if exp == 31:
                return sign * float("inf") if frac == 0 else float("nan")
            return sign * (2.0 ** (exp - 15)) * (1 + frac / 1024.0)
        if info == 26:
            import struct

            return struct.unpack(">f", self._read_bytes(4))[0]
        if info == 27:
            import struct

            return struct.unpack(">d", self._read_bytes(8))[0]
        raise QrsParseError("Unsupported simple value")

    def _read_value(self) -> Any:
        major, info, value = self._read_head()
        if major == MT_UINT:
            return value
        if major == MT_NINT:
            return -1 - value
        if major == MT_BYTES:
            return self._read_bytes(value)
        if major == MT_TEXT:
            return self._read_bytes(value).decode("utf-8")
        if major == MT_ARRAY:
            return [self._read_value() for _ in range(value)]
        if major == MT_MAP:
            out: dict[Any, Any] = {}
            for _ in range(value):
                key = self._read_value()
                val = self._read_value()
                out[key] = val
            return out
        if major == MT_TAG:
            # The protocol profile does not use tags; unwrap and return the inner value.
            return self._read_value()
        if major == MT_SIMPLE:
            if info == 25 or info == 26 or info == 27:
                return self._decode_float(info)
            if info == 20:
                return False
            if info == 21:
                return True
            if info == 22:
                return None
            raise QrsParseError(f"Unsupported simple value: {info}")
        raise QrsParseError(f"Unsupported CBOR major type: {major}")


def cbor_decode(data: bytes) -> Any:
    """Decode canonical CBOR bytes into Python objects.

    Raises :class:`QrsParseError` if the input is not a single well-formed item.
    """
    decoder = _Decoder(data)
    value = decoder._read_value()
    if decoder._pos != len(data):
        raise QrsParseError("Trailing data after CBOR item")
    return value