"""SDoc Verification Protocol v1 — core package.

The core is a *portable, stateless, extendible* protocol framework. It never
calls platform APIs directly; every external input (time, location, secrets,
online objects) and every persistence concern is injected through interfaces
(``IContextProvider``, the storage protocols). This is what makes the same core
usable from Django, Electron, React Native, or a plain script.

The package is deliberately split so that the *core* stays minimal and most
behaviour lives in pluggable *field engines* and *crypto providers*:

- ``qrs.cbor`` — canonical (deterministic) CBOR encoding/decoding.
- ``qrs.cose`` — COSE_Sign1 (RFC 9052) signed-object envelope.
- ``qrs.crypto`` — crypto-provider abstraction + Ed25519 / ECDSA-P256 providers.
- ``qrs.fields`` — declarative field engines (text, select, number, date, ...).
- ``qrs.signed_object`` — the SignedObject envelope + static data schemas.
- ``qrs.services`` — the high-level services (certificates, signing, trust,
  revocation, verification, online import, endpoints).
- ``qrs.storage`` — storage interfaces + in-memory / JSON-file implementations.
- ``qrs.context`` — context-provider abstraction + a headless dummy provider.
- ``qrs.runtime`` — the IoC container that wires everything together.

The public API is re-exported from :mod:`qrs` (see ``qrs/__init__.py``).
"""

__version__ = "0.1.0"

# Protocol version implemented by this package.
PROTOCOL_VERSION = 1

# The four signed-object types defined by protocol version 1.
SIGNED_OBJECT_TYPES = ("tcert", "sdoc", "statement", "attachment")

# Algorithms supported by the reference implementation.
ALGORITHM_IDS = ("Ed25519", "ECDSA-P256")

# Declarative field types understood by the reference field engines.
FIELD_TYPES = (
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

# Statement actions defined by protocol version 1. This set is closed.
ACTIONS = ("attest", "addTcert", "revokeTcert", "blockSdoc", "unblockSdoc")

# Revocation scope for a TCert revocation statement.
REVOCATION_TYPES = ("prospective", "retrospective")

# Hash algorithms supported for TCert-bound content hashing (attachments).
HASH_ALGORITHMS = ("SHA-256", "SHA-384", "SHA3-512")

# Number of identifier bytes used for all truncated identifiers.
ID_BYTES = 16

# Attachment references use the same 128-bit identifier size as other QRS IDs.
ATTACHMENT_HASH_HEX = 32

# Microdegrees per degree: coordinates are stored as fixed-point integers.
MICRODEGREES = 1_000_000

# COSE algorithm identifiers (RFC 9053 registry) used in protected headers.
COSE_ALG_EDDSA = -8  # Ed25519
COSE_ALG_ES256 = -7  # ECDSA-P256

# COSE header labels (RFC 9052 §3).
COSE_HDR_ALG = 1
COSE_HDR_KID = 4

# Transfer envelope scheme/version (QR medium between devices).
TRANSFER_SCHEME = "qrs"
TRANSFER_VERSION = 1
QRS_FILE_EXTENSION = "qrs"

__all__ = [
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
]