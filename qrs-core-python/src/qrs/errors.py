"""Exception hierarchy for the qrs core.

All errors raised by the package derive from :class:`QrsError`, so a consumer can
catch one base type and still distinguish the specific failure modes.
"""

from __future__ import annotations

__all__ = [
    "QrsError",
    "QrsParseError",
    "QrsUnsupportedError",
    "QrsValidationError",
    "QrsCryptoError",
    "QrsNotFoundError",
    "QrsAuthorizationError",
]


class QrsError(Exception):
    """Base class for all qrs errors."""


class QrsParseError(QrsError):
    """A value could not be parsed (malformed CBOR, COSE, hex, ...)."""


class QrsUnsupportedError(QrsError):
    """A feature/algorithm/type is not supported by this profile."""


class QrsValidationError(QrsError):
    """An input value failed validation (schema, rules, ...)."""


class QrsCryptoError(QrsError):
    """A cryptographic operation failed (signature invalid, key mismatch, ...)."""


class QrsNotFoundError(QrsError):
    """A requested object (key, TCert, SDoc, ...) was not found."""


class QrsAuthorizationError(QrsError):
    """The caller is not authorized to perform the requested operation."""