from django.db import models


class SupportedTcert(models.Model):
    """A TCert the server agrees to host distribution for.

    The server stores only public data (the TCert's public key, identity and
    `online_endpoint`). It never stores private keys and is never trusted by
    verifiers — it is a distribution cache whose contents are always
    cryptographically checked against the TCert's public key.
    """

    key_id = models.CharField(max_length=64, db_index=True)  # hex key id (one key may own several TCerts)
    certificate_number = models.IntegerField()
    tcert_id = models.CharField(max_length=80, unique=True)  # "<keyId>:<certNumber>"
    algorithm = models.CharField(max_length=32)
    name = models.CharField(max_length=255, blank=True, default="")
    public_key = models.JSONField(default=dict)  # JWK
    online_endpoint = models.CharField(max_length=500, blank=True)
    tcert_b64 = models.TextField()  # original TCert (base64url)
    created_at = models.DateTimeField(auto_now_add=True)

    # --- New online-server spec (2026-08-25) ---
    # A TCert the server admin has explicitly trusted and added as a CA. CA-only
    # services require this flag; attachment upload only requires registration
    # plus its own permission flag.
    is_ca = models.BooleanField(default=False)
    # Server-admin capability policy. CA-only capabilities are also gated by
    # is_ca in the API, so these flags can safely be enabled by default.
    allow_attestation = models.BooleanField(default=True)
    allow_tcert_enrollment = models.BooleanField(default=True)
    allow_attachment_upload = models.BooleanField(default=True)
    allow_sdoc_block = models.BooleanField(default=True)
    allow_sdoc_unblock = models.BooleanField(default=True)
    allow_self_revocation = models.BooleanField(default=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"TCert {self.tcert_id}"


class TcertAttestation(models.Model):
    """One independent (CA → target TCert) attestation.

    A target TCert may be attested by any number of trusted CAs, and each CA is
    independent: CA-A revoking (or withholding) an attestation must not affect
    CA-B's valid attestation of the same TCert. This mirrors qrs-core's
    `getAttestations()` / `resolveTrust()`, which accept a TCert when any one
    CA's attestation verifies.
    """

    ca = models.ForeignKey(
        "SupportedTcert", on_delete=models.CASCADE, related_name="enrolled_targets"
    )
    target = models.ForeignKey(
        "SupportedTcert", on_delete=models.CASCADE, related_name="attestations"
    )
    statement_id = models.CharField(max_length=64)
    tcert_hash = models.CharField(max_length=64, blank=True, default="")
    signed_at = models.IntegerField(default=0)
    bytes_b64 = models.TextField()  # the CA-signed attestation statement
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        # A CA attests a given target at most once; each (ca, target, statement)
        # pair is unique so replayed attestations are idempotent.
        unique_together = (("ca", "target", "statement_id"),)
        ordering = ["created_at"]

    def __str__(self):
        return f"{self.ca.tcert_id} → {self.target.tcert_id} ({self.statement_id})"


class TcertChallenge(models.Model):
    """A pending proof-of-work challenge for a TCert host (DDoS defense)."""

    key_id = models.CharField(max_length=64, db_index=True)
    nonce = models.CharField(max_length=64, unique=True)
    difficulty = models.IntegerField(default=4)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"challenge {self.nonce}"


class TcertToken(models.Model):
    """A short-lived bearer token proving the host solved a challenge."""

    key_id = models.CharField(max_length=64, db_index=True)
    token = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"token {self.key_id}"


class SignedObject(models.Model):
    """A signed statement (attest / revokeTcert / blockSdoc / unblockSdoc) uploaded
    by the TCert host and verified by the server against the TCert's public key."""

    tcert = models.ForeignKey(SupportedTcert, on_delete=models.CASCADE, related_name="statements")
    statement_id = models.CharField(max_length=64)
    action = models.CharField(max_length=32)
    signed_at = models.BigIntegerField(default=0)  # epoch seconds (statement issuedAt)
    bytes_b64 = models.TextField()
    received_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["signed_at"]
        constraints = [
            models.UniqueConstraint(fields=["tcert", "statement_id"], name="unique_statement_per_tcert")
        ]

    def __str__(self):
        return f"{self.action} {self.statement_id}"


class AttachmentBlob(models.Model):
    """One physical content-addressed file.

    FileField delegates persistence to Django's storage backend, so this model
    can later use S3-compatible storage such as RustFS without API changes.
    """

    id = models.CharField(max_length=32, primary_key=True)  # first 128 bits of SHA-256
    content_type = models.CharField(max_length=128, default="application/octet-stream")
    content_hash = models.CharField(max_length=64, blank=True)  # full hash hex
    size = models.BigIntegerField(default=0)  # file size in bytes
    file = models.FileField(upload_to="attachments/blobs/")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"attachment blob {self.id}"


class AttachmentReference(models.Model):
    """A TCert's logical use of an attachment blob."""

    tcert = models.ForeignKey(SupportedTcert, on_delete=models.CASCADE, related_name="attachments")
    blob = models.ForeignKey(AttachmentBlob, on_delete=models.CASCADE, related_name="references")
    field_name = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["tcert", "blob", "field_name"],
                name="unique_attachment_reference_per_field",
            )
        ]

    def __str__(self):
        return f"{self.tcert.tcert_id} attachment {self.blob_id} ({self.field_name})"


# Compatibility alias for existing management scripts. New code should use the
# explicit AttachmentBlob or AttachmentReference names.
Attachment = AttachmentBlob
