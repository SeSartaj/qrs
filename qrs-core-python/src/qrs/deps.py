"""The dependency bundle shared by all services.

Services depend on this interface, never on concrete implementations — this is
what makes the whole package inversion-of-control friendly: swap any store or
provider and the services are unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .clock import IClock, SystemClock
from .context import IContextProvider
from .crypto.registry import CryptoRegistry
from .field_registry import FieldRegistry
from .storage.interfaces import (
    ICertificateStore,
    IDocumentStore,
    IEndpointConfigStore,
    IPrivateKeyStore,
    IPublicKeyStore,
    IRevocationStore,
    ITrustStore,
)

__all__ = ["ServiceDeps"]


@dataclass
class ServiceDeps:
    """The dependency bundle every service receives."""

    crypto_registry: CryptoRegistry
    field_registry: FieldRegistry
    private_key_store: IPrivateKeyStore
    public_key_store: IPublicKeyStore
    certificate_store: ICertificateStore
    document_store: IDocumentStore
    revocation_store: IRevocationStore
    trust_store: ITrustStore
    endpoint_config_store: IEndpointConfigStore
    context_provider: IContextProvider
    clock: IClock = field(default_factory=SystemClock)