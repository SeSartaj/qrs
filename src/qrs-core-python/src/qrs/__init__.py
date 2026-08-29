"""qrs — SDoc Verification Protocol v1 core (Python).

A portable, stateless, extendible protocol framework. The core never calls
platform APIs directly; every external input (time, location, secrets, online
objects) and every persistence concern is injected through interfaces. This is
what makes the same core usable from Django, FastAPI, Electron, React Native, or
a plain script.

The core is deliberately minimal: most behaviour lives in pluggable *field
engines* and *crypto providers*. Add a new field type or algorithm by
implementing the corresponding interface and registering it — no core change
needed. Protocol-version bumps are reserved for changes to the core wire format
itself.

Public API (mirrors the reference ``qrs-core`` npm package):

- ``create_qrs()`` — build a runtime with reference providers + in-memory stores.
- ``qrs.certificates`` / ``qrs.signing`` / ``qrs.trust`` / ``qrs.revocation`` /
  ``qrs.verification`` / ``qrs.attachments`` / ``qrs.online`` / ``qrs.endpoints``
  — the high-level services.
- ``qrs.cbor`` / ``qrs.cose`` / ``qrs.envelope`` — the wire format.
- ``qrs.fields`` / ``qrs.field_engines`` / ``qrs.field_registry`` — the field model.
- ``qrs.crypto`` — crypto providers + registry.
- ``qrs.storage`` — storage interfaces + in-memory / file implementations.
- ``qrs.context`` — context-provider abstraction + a headless dummy provider.
"""

from .constants import (
    ACTIONS,
    ALGORITHM_IDS,
    ATTACHMENT_HASH_HEX,
    COSE_ALG_EDDSA,
    COSE_ALG_ES256,
    COSE_HDR_ALG,
    COSE_HDR_KID,
    FIELD_TYPES,
    HASH_ALGORITHMS,
    ID_BYTES,
    MICRODEGREES,
    PROTOCOL_VERSION,
    QRS_FILE_EXTENSION,
    REVOCATION_TYPES,
    SIGNED_OBJECT_TYPES,
    TRANSFER_SCHEME,
    TRANSFER_VERSION,
    __version__,
)
from .errors import (
    QrsAuthorizationError,
    QrsCryptoError,
    QrsError,
    QrsNotFoundError,
    QrsParseError,
    QrsUnsupportedError,
    QrsValidationError,
)
from .id import (
    constant_time_equal,
    from_base64url,
    from_hex,
    hash_for,
    is_hash_algorithm,
    random_bytes,
    random_id,
    sha256,
    sha384,
    sha3_512,
    to_base64url,
    to_hex,
    trunc_sha256,
)
from .runtime import QrsDependencies, QrsRuntime, create_qrs

__all__ = [
    # version / protocol constants
    "__version__",
    "PROTOCOL_VERSION",
    "SIGNED_OBJECT_TYPES",
    "ALGORITHM_IDS",
    "FIELD_TYPES",
    "ACTIONS",
    "REVOCATION_TYPES",
    "HASH_ALGORITHMS",
    "ID_BYTES",
    "ATTACHMENT_HASH_HEX",
    "MICRODEGREES",
    "COSE_ALG_EDDSA",
    "COSE_ALG_ES256",
    "COSE_HDR_ALG",
    "COSE_HDR_KID",
    "TRANSFER_SCHEME",
    "TRANSFER_VERSION",
    "QRS_FILE_EXTENSION",
    # errors
    "QrsError",
    "QrsParseError",
    "QrsUnsupportedError",
    "QrsValidationError",
    "QrsCryptoError",
    "QrsNotFoundError",
    "QrsAuthorizationError",
    # identifiers / hashing
    "sha256",
    "sha384",
    "sha3_512",
    "hash_for",
    "is_hash_algorithm",
    "trunc_sha256",
    "to_hex",
    "from_hex",
    "to_base64url",
    "from_base64url",
    "random_id",
    "random_bytes",
    # runtime
    "create_qrs",
    "QrsRuntime",
    "QrsDependencies",
]