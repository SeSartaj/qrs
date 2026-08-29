"""Storage: interfaces + in-memory / JSON-file-backed implementations.

The core only ever depends on the interfaces in :mod:`qrs.storage.interfaces`.
The reference wiring uses the in-memory stores (see
:func:`qrs.storage.memory_stores.create_in_memory_stores`); file-backed stores
(``create_file_stores``) are provided for the CLI and for simple apps.
"""

from .interfaces import (
    AttestationRecord,
    BlockEntry,
    IEndpointConfigStore,
    ICertificateStore,
    IDocumentStore,
    IPrivateKeyStore,
    IPublicKeyStore,
    IRevocationStore,
    ITrustStore,
    RevocationEntry,
)
from .memory_stores import (
    FileCertificateStore,
    FileDocumentStore,
    FileEndpointConfigStore,
    FilePrivateKeyStore,
    FilePublicKeyStore,
    FileRevocationStore,
    FileTrustStore,
    InMemoryCertificateStore,
    InMemoryDocumentStore,
    InMemoryEndpointConfigStore,
    InMemoryPrivateKeyStore,
    InMemoryPublicKeyStore,
    InMemoryRevocationStore,
    InMemoryTrustStore,
    create_file_stores,
    create_in_memory_stores,
)

__all__ = [
    "AttestationRecord",
    "BlockEntry",
    "RevocationEntry",
    "IEndpointConfigStore",
    "ICertificateStore",
    "IDocumentStore",
    "IPrivateKeyStore",
    "IPublicKeyStore",
    "IRevocationStore",
    "ITrustStore",
    "FileCertificateStore",
    "FileDocumentStore",
    "FileEndpointConfigStore",
    "FilePrivateKeyStore",
    "FilePublicKeyStore",
    "FileRevocationStore",
    "FileTrustStore",
    "InMemoryCertificateStore",
    "InMemoryDocumentStore",
    "InMemoryEndpointConfigStore",
    "InMemoryPrivateKeyStore",
    "InMemoryPublicKeyStore",
    "InMemoryRevocationStore",
    "InMemoryTrustStore",
    "create_file_stores",
    "create_in_memory_stores",
]