"""qrs-core-python runtime factory for the enterprise app.

Builds a ``create_qrs`` runtime wired to the Django ORM stores. The core's
service methods are async; the enterprise service layer runs them via
``asgiref.sync.async_to_sync`` so they can be called from synchronous Django
views.
"""
from __future__ import annotations

from qrs import QrsDependencies, create_qrs
from qrs.context import DummyContextProvider

from .stores import (
    OrmCertificateStore,
    OrmDocumentStore,
    OrmEndpointConfigStore,
    OrmPrivateKeyStore,
    OrmPublicKeyStore,
    OrmRevocationStore,
    OrmTrustStore,
)


def build_runtime():
    """Build a qrs-core runtime backed by the Django ORM stores.

    A fresh runtime is cheap to construct; callers may cache it per-process.
    """
    deps = QrsDependencies(
        private_key_store=OrmPrivateKeyStore(),
        public_key_store=OrmPublicKeyStore(),
        certificate_store=OrmCertificateStore(),
        document_store=OrmDocumentStore(),
        revocation_store=OrmRevocationStore(),
        trust_store=OrmTrustStore(),
        endpoint_config_store=OrmEndpointConfigStore(),
        context_provider=DummyContextProvider(),
    )
    return create_qrs(deps)