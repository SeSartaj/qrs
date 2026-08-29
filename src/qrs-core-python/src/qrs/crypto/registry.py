"""Crypto registry: maps algorithm identifiers to providers.

The registry is what makes the scheme cryptographically agile — a consumer can
register a provider for a new algorithm without touching the core. The reference
registry ships the Ed25519 and ECDSA-P256 providers.
"""

from __future__ import annotations

from .ecdsaP256 import EcdsaP256Provider
from .ed25519 import Ed25519Provider
from ..errors import QrsUnsupportedError
from .providers import COSE_ALGORITHM_TO_ID, ICryptoProvider

__all__ = [
    "CryptoRegistry",
    "create_default_crypto_registry",
    "COSE_ALGORITHM_TO_ID",
    "algorithm_from_cose_algorithm",
]


class CryptoRegistry:
    """A registry of crypto providers by algorithm identifier."""

    def __init__(self, providers: list[ICryptoProvider] | None = None) -> None:
        self._providers: dict[str, ICryptoProvider] = {}
        for provider in providers or []:
            self.register(provider)

    def register(self, provider: ICryptoProvider) -> "CryptoRegistry":
        self._providers[provider.algorithm] = provider
        return self

    def get(self, algorithm: str) -> ICryptoProvider:
        try:
            return self._providers[algorithm]
        except KeyError:
            raise QrsUnsupportedError(f"Unsupported algorithm: {algorithm}") from None

    def has(self, algorithm: str) -> bool:
        return algorithm in self._providers

    def list(self) -> list[ICryptoProvider]:
        return list(self._providers.values())


def create_default_crypto_registry() -> CryptoRegistry:
    """The reference registry: Ed25519 + ECDSA-P256 providers."""
    return CryptoRegistry([Ed25519Provider(), EcdsaP256Provider()])


def algorithm_from_cose_algorithm(alg: int) -> str | None:
    """Map a COSE algorithm identifier to the protocol algorithm identifier."""
    return COSE_ALGORITHM_TO_ID.get(alg)