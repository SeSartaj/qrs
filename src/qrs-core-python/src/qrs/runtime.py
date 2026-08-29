"""Runtime factory (IoC container).

``create_qrs`` wires the services together from a fully-injectable dependency
bundle. The reference implementation uses the default (Ed25519 + ECDSA-P256)
crypto providers and in-memory stores; every dependency can be overridden.

This module is the Python counterpart of the reference implementation's
``createQrs``/``QrsRuntime``. The runtime itself is *stateless* — all state lives
in the injected stores — and the services are pure, so a Django, FastAPI or CLI
consumer can build one runtime per request (or reuse one) and swap stores freely.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .clock import IClock, SystemClock
from .context import DummyContextProvider, IContextProvider
from .crypto.registry import CryptoRegistry, create_default_crypto_registry
from .deps import ServiceDeps
from .field_registry import FieldRegistry, create_default_field_registry
from .services.attachmentService import AttachmentService
from .services.certificateService import CertificateService
from .services.endpointService import EndpointService
from .services.onlineService import OnlineService
from .services.revocationService import RevocationService
from .services.signingService import SigningService
from .services.trustService import TrustService
from .services.verificationService import VerificationService, VerificationServiceDeps
from .storage.interfaces import (
    ICertificateStore,
    IDocumentStore,
    IEndpointConfigStore,
    IPrivateKeyStore,
    IPublicKeyStore,
    IRevocationStore,
    ITrustStore,
)
from .storage.memory_stores import create_in_memory_stores

__all__ = ["QrsDependencies", "QrsRuntime", "create_qrs"]


@dataclass
class QrsDependencies:
    """Every dependency the runtime needs, with sane defaults.

    Override any field to change behaviour (e.g. swap in a Django ORM-backed
    certificate store, a hardware key vault, or a custom context provider).
    """

    crypto_registry: CryptoRegistry = field(default_factory=create_default_crypto_registry)
    field_registry: FieldRegistry = field(default_factory=create_default_field_registry)
    private_key_store: IPrivateKeyStore | None = None
    public_key_store: IPublicKeyStore | None = None
    certificate_store: ICertificateStore | None = None
    document_store: IDocumentStore | None = None
    revocation_store: IRevocationStore | None = None
    trust_store: ITrustStore | None = None
    endpoint_config_store: IEndpointConfigStore | None = None
    context_provider: IContextProvider | None = None
    clock: IClock | None = None


class QrsRuntime:
    """The protocol runtime (dependency container)."""

    def __init__(self, deps: ServiceDeps) -> None:
        self.deps = deps
        self.trust = TrustService(deps)
        self.revocation = RevocationService(deps)
        self.certificates = CertificateService(deps)
        self.signing = SigningService(deps)
        self.attachments = AttachmentService(deps)
        self.online = OnlineService(deps)
        self.endpoints = EndpointService(deps)
        self.verification = VerificationService(
            VerificationServiceDeps.from_service_deps(deps, self.trust, self.revocation)
        )


def create_qrs(deps: QrsDependencies | None = None) -> QrsRuntime:
    """Create a runtime with the reference crypto/field providers and in-memory defaults.

    Example::

        qrs = create_qrs()
        key_id = await qrs.certificates.generate_key_pair("Ed25519")
        result = await qrs.certificates.create_tcert(CreateTcertParams(...))
    """
    deps = deps or QrsDependencies()
    defaults = create_in_memory_stores()
    full = ServiceDeps(
        crypto_registry=deps.crypto_registry,
        field_registry=deps.field_registry,
        private_key_store=deps.private_key_store or defaults["private_key_store"],
        public_key_store=deps.public_key_store or defaults["public_key_store"],
        certificate_store=deps.certificate_store or defaults["certificate_store"],
        document_store=deps.document_store or defaults["document_store"],
        revocation_store=deps.revocation_store or defaults["revocation_store"],
        trust_store=deps.trust_store or defaults["trust_store"],
        endpoint_config_store=deps.endpoint_config_store or defaults["endpoint_config_store"],
        context_provider=deps.context_provider or DummyContextProvider(),
        clock=deps.clock or SystemClock(),
    )
    return QrsRuntime(full)