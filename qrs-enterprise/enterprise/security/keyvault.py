"""KeyVault — encrypted-at-rest storage for private key material.

The KeyVault is the single seam through which private JWKs are persisted. It
guarantees that a private key is **never written to disk in plaintext**: the
vault stores only the Fernet-encrypted ciphertext, and the plaintext JWK exists
only in memory for the duration of a signing operation.

The interface is deliberately small so a hardware-backed backend (YubiHSM, a
KMS, or an HSM PKCS#11 module) can be dropped in later without touching the rest
of the application.
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

__all__ = ["KeyVault", "FernetKeyVault", "KeyVaultError", "KeyVaultUnavailableError"]


class KeyVaultError(Exception):
    """Base error for KeyVault failures."""


class KeyVaultUnavailableError(KeyVaultError):
    """Raised when the vault is not configured (no encryption key set)."""


class KeyVault(ABC):
    """Interface for encrypting/decrypting private key material at rest."""

    @abstractmethod
    def encrypt(self, plaintext: bytes) -> str:
        """Encrypt ``plaintext`` and return a portable (base64) ciphertext string."""

    @abstractmethod
    def decrypt(self, ciphertext: str) -> bytes:
        """Decrypt a ciphertext string produced by :meth:`encrypt`."""


class FernetKeyVault(KeyVault):
    """Fernet (AES-128-CBC + HMAC-SHA256) vault backed by a dedicated env key.

    The key is read from ``settings.KEY_ENC_KEY`` (a base64 Fernet key). It is
    deliberately **separate** from Django's ``SECRET_KEY`` so that a compromise
    of ``SECRET_KEY`` does not expose the private keys.
    """

    def __init__(self, key: str | None = None) -> None:
        self._key = key
        self._fernet: Fernet | None = None
        if key:
            try:
                self._fernet = Fernet(key.encode("ascii"))
            except (ValueError, TypeError) as exc:
                raise KeyVaultError(f"Invalid Fernet key: {exc}") from exc

    @classmethod
    def from_settings(cls) -> "FernetKeyVault":
        from django.conf import settings

        return cls(settings.KEY_ENC_KEY or None)

    @property
    def available(self) -> bool:
        return self._fernet is not None

    def encrypt(self, plaintext: bytes) -> str:
        if self._fernet is None:
            raise KeyVaultUnavailableError(
                "QRS_ENTERPRISE_KEY_ENC_KEY is not set; cannot encrypt private keys"
            )
        return self._fernet.encrypt(plaintext).decode("ascii")

    def decrypt(self, ciphertext: str) -> bytes:
        if self._fernet is None:
            raise KeyVaultUnavailableError(
                "QRS_ENTERPRISE_KEY_ENC_KEY is not set; cannot decrypt private keys"
            )
        try:
            return self._fernet.decrypt(ciphertext.encode("ascii"))
        except InvalidToken as exc:
            raise KeyVaultError("Failed to decrypt private key (wrong key or corrupt data)") from exc


def encode_private_jwk(jwk: dict[str, Any]) -> bytes:
    """Serialize a private JWK dict to canonical JSON bytes."""
    return json.dumps(jwk, sort_keys=True, separators=(",", ":")).encode("utf-8")


def decode_private_jwk(data: bytes) -> dict[str, Any]:
    """Deserialize a private JWK dict from JSON bytes."""
    return json.loads(data.decode("utf-8"))