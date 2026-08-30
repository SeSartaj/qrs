"""QRS Enterprise models.

These models persist the server-managed signing state:

- ``User`` — application user with a role (admin / signer / CA) plus custom
  Django permissions for the sensitive CA operations.
- ``ManagedKey`` — a key pair whose private JWK is stored **encrypted at rest**
  via the KeyVault (never plaintext on disk).
- ``ManagedTcert`` — a server-managed TCert (self-signed certificate + document
  schema). May be a signing TCert (has a schema) or a CA TCert (``is_ca``).
- ``TcertGrant`` — grants a user access to sign with a specific TCert.
- ``SdocRecord`` — a signed SDoc produced by the server.
- ``AuditLog`` — an immutable log of every signing / CA operation.
- ``ApiKey`` — a scoped API key for external systems.
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Any

from django.conf import settings
from django.contrib.auth.models import AbstractUser, Permission
from django.db import models
from django.utils import timezone

from .security.keyvault import (
    FernetKeyVault,
    KeyVaultUnavailableError,
    decode_private_jwk,
    encode_private_jwk,
)


class User(AbstractUser):
    """Application user with a role.

    Roles are a convenience layer on top of Django's permission system:
    - ``admin`` — full control (create TCerts, manage grants, manage API keys).
    - ``signer`` — can sign with TCerts they are granted.
    - ``ca`` — can perform CA operations (attest / revoke / block / unblock)
      subject to the Django permissions below.
    """

    ROLE_ADMIN = "admin"
    ROLE_SIGNER = "signer"
    ROLE_CA = "ca"
    ROLE_CHOICES = [
        (ROLE_ADMIN, "Admin"),
        (ROLE_SIGNER, "Signer"),
        (ROLE_CA, "CA"),
    ]

    role = models.CharField(max_length=16, choices=ROLE_CHOICES, default=ROLE_SIGNER)

    class Meta(AbstractUser.Meta):
        permissions = [
            ("can_sign", "Can sign an SDoc via API"),
            ("can_revoke_tcert", "Can revoke a TCert"),
            ("can_block_sdoc", "Can block an SDoc"),
            ("can_unblock_sdoc", "Can unblock an SDoc"),
        ]


class ManagedKey(models.Model):
    """A server-managed key pair.

    The private JWK is stored as Fernet ciphertext in ``private_jwk_encrypted``.
    The plaintext private JWK is only ever materialized in memory during a
    signing operation and is never persisted.
    """

    key_id = models.CharField(max_length=64, unique=True, db_index=True)
    algorithm = models.CharField(max_length=32)
    public_jwk = models.JSONField(default=dict)
    private_jwk_encrypted = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self) -> str:
        return f"{self.algorithm} key {self.key_id[:12]}…"

    # -- KeyVault-backed private key access ---------------------------------
    def set_private_jwk(self, private_jwk: dict[str, Any]) -> None:
        """Encrypt and store a private JWK (never plaintext)."""
        vault = FernetKeyVault.from_settings()
        if not vault.available:
            raise KeyVaultUnavailableError(
                "QRS_ENTERPRISE_KEY_ENC_KEY is not set; refusing to store a plaintext private key"
            )
        self.private_jwk_encrypted = vault.encrypt(encode_private_jwk(private_jwk))

    def get_private_jwk(self) -> dict[str, Any] | None:
        """Decrypt and return the private JWK (in memory only)."""
        if not self.private_jwk_encrypted:
            return None
        vault = FernetKeyVault.from_settings()
        return decode_private_jwk(vault.decrypt(self.private_jwk_encrypted))


class ManagedTcert(models.Model):
    """A server-managed TCert.

    ``tcert_b64`` holds the canonical signed TCert bytes (base64url). The
    ``schema`` is a JSON copy of the signed field schema for convenient display
    and form rendering. ``is_ca`` marks a CA TCert (used for attest / revoke /
    block / unblock). A signing TCert must have a non-empty schema.
    """

    key = models.ForeignKey(ManagedKey, on_delete=models.CASCADE, related_name="tcerts")
    tcert_id = models.CharField(max_length=80, unique=True, db_index=True)
    certificate_number = models.IntegerField()
    name = models.CharField(max_length=255, blank=True, default="")
    algorithm = models.CharField(max_length=32)
    is_ca = models.BooleanField(default=False)
    schema = models.JSONField(default=list)
    tcert_b64 = models.TextField()
    online_endpoint = models.CharField(max_length=500, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]
        permissions = [
            ("can_revoke_tcert", "Can revoke a TCert"),
        ]

    def __str__(self) -> str:
        return self.name or self.tcert_id

    @property
    def has_schema(self) -> bool:
        return bool(self.schema)


class TcertGrant(models.Model):
    """Grants a user the right to sign with a specific TCert."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="tcert_grants"
    )
    tcert = models.ForeignKey(ManagedTcert, on_delete=models.CASCADE, related_name="grants")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("user", "tcert")
        ordering = ["created_at"]

    def __str__(self) -> str:
        return f"{self.user} → {self.tcert}"


class SdocRecord(models.Model):
    """A signed SDoc produced by the server.

    ``tcert`` is nullable because qrs-core's ``issue_sdoc`` persists the raw
    bytes via the document store before the enterprise service enriches the
    record with the issuing TCert and signer.
    """

    sdoc_id = models.CharField(max_length=64, unique=True, db_index=True)
    tcert = models.ForeignKey(
        ManagedTcert, on_delete=models.SET_NULL, null=True, related_name="sdocs"
    )
    signed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="signed_sdocs"
    )
    sdoc_b64 = models.TextField()
    issued_at = models.BigIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.sdoc_id


class AuditLog(models.Model):
    """Immutable audit trail of every signing / CA operation."""

    ACTION_SIGN = "sign"
    ACTION_CREATE_TCERT = "create_tcert"
    ACTION_ATTEST = "attest"
    ACTION_REVOKE = "revoke"
    ACTION_BLOCK = "block"
    ACTION_UNBLOCK = "unblock"
    ACTION_CHOICES = [
        (ACTION_SIGN, "Sign SDoc"),
        (ACTION_CREATE_TCERT, "Create TCert"),
        (ACTION_ATTEST, "Attest"),
        (ACTION_REVOKE, "Revoke"),
        (ACTION_BLOCK, "Block SDoc"),
        (ACTION_UNBLOCK, "Unblock SDoc"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="audit_logs"
    )
    action = models.CharField(max_length=32, choices=ACTION_CHOICES)
    tcert = models.ForeignKey(
        ManagedTcert, on_delete=models.SET_NULL, null=True, related_name="audit_logs"
    )
    target = models.CharField(max_length=255, blank=True, default="")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    statement_b64 = models.TextField(blank=True, default="")
    detail = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["user", "action"])]

    def __str__(self) -> str:
        return f"{self.user} {self.action} {self.target}"


class ApiKey(models.Model):
    """A scoped API key for external systems.

    Only the SHA-256 hash of the key is stored. The plaintext key is shown once
    at creation time. Permissions are a ``ManyToManyField`` to Django's
    ``Permission`` model (e.g. ``enterprise.can_revoke_tcert``), giving a proper
    multiselect widget in the Django admin.
    """

    name = models.CharField(max_length=255)
    key_hash = models.CharField(max_length=64, unique=True, db_index=True)
    key_prefix = models.CharField(max_length=16, blank=True, default="")
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="api_keys"
    )
    permissions = models.ManyToManyField(
        Permission, blank=True, related_name="api_keys", verbose_name="Permissions"
    )
    is_active = models.BooleanField(default=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def hash_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    @classmethod
    def generate(
        cls,
        name: str,
        owner,
        permissions: list[str] | None = None,
        expires_at=None,
    ) -> tuple["ApiKey", str]:
        """Create an ApiKey and return (instance, plaintext_key).

        ``permissions`` is a list of permission codenames (e.g.
        ``"enterprise.can_sign"``). They are resolved to ``Permission`` rows and
        attached via the M2M relation.
        """
        raw_key = f"qrs_{secrets.token_urlsafe(32)}"
        instance = cls(
            name=name,
            owner=owner,
            key_hash=cls.hash_key(raw_key),
            key_prefix=raw_key[:12],
            expires_at=expires_at,
        )
        instance.full_clean()
        instance.save()
        if permissions:
            perms = Permission.objects.filter(codename__in=[p.split(".")[-1] for p in permissions])
            instance.permissions.set(perms)
        return instance, raw_key

    def has_perm(self, codename: str) -> bool:
        if not self.is_active:
            return False
        if self.expires_at and self.expires_at <= timezone.now():
            return False
        return self.permissions.filter(codename=codename.split(".")[-1]).exists()
