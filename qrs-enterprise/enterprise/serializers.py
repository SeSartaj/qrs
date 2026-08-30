"""DRF serializers for QRS Enterprise."""
from __future__ import annotations

from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import ApiKey, AuditLog, ManagedTcert, SdocRecord, TcertGrant

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name", "role", "is_active"]


class FieldSchemaSerializer(serializers.Serializer):
    """A single field schema entry (mirrors qrs-core FieldSchema)."""

    type = serializers.CharField()
    name = serializers.CharField()
    label = serializers.CharField()
    options = serializers.ListField(child=serializers.CharField(), required=False)
    input_rules = serializers.DictField(required=False)
    verify_rules = serializers.DictField(required=False)
    default = serializers.JSONField(required=False)
    binding = serializers.ChoiceField(
        choices=["inline", "stripped"], required=False, allow_null=True
    )


class CreateTcertSerializer(serializers.Serializer):
    algorithm = serializers.ChoiceField(choices=["Ed25519", "ECDSA-P256"])
    name = serializers.CharField(max_length=255)
    fields = FieldSchemaSerializer(many=True, required=False, default=list)
    is_ca = serializers.BooleanField(default=False)
    online_endpoint = serializers.CharField(max_length=500, required=False, allow_blank=True)
    hash_algorithm = serializers.ChoiceField(
        choices=["SHA-256", "SHA-384", "SHA3-512"], required=False, allow_null=True
    )
    sdoc_max_age_seconds = serializers.IntegerField(required=False, allow_null=True)


class ManagedTcertSerializer(serializers.ModelSerializer):
    key_id = serializers.CharField(source="key.key_id", read_only=True)
    has_schema = serializers.BooleanField(read_only=True)

    class Meta:
        model = ManagedTcert
        fields = [
            "id",
            "tcert_id",
            "key_id",
            "certificate_number",
            "name",
            "algorithm",
            "is_ca",
            "schema",
            "has_schema",
            "online_endpoint",
            "created_at",
        ]


class SignSdocSerializer(serializers.Serializer):
    values = serializers.DictField()


class SdocRecordSerializer(serializers.ModelSerializer):
    tcert_id = serializers.CharField(source="tcert.tcert_id", read_only=True)
    signed_by = serializers.CharField(source="signed_by.username", read_only=True, allow_null=True)

    class Meta:
        model = SdocRecord
        fields = ["id", "sdoc_id", "tcert_id", "signed_by", "sdoc_b64", "issued_at", "created_at"]


class GrantSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)

    class Meta:
        model = TcertGrant
        fields = ["id", "user", "username", "tcert", "created_at"]
        read_only_fields = ["id", "username", "created_at"]


class GrantCreateSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()


class AttestSerializer(serializers.Serializer):
    target_tcert_id = serializers.CharField()
    claims = serializers.DictField(required=False)


class RevokeSerializer(serializers.Serializer):
    target_tcert_id = serializers.CharField()
    reason = serializers.CharField(required=False, allow_blank=True)


class BlockSerializer(serializers.Serializer):
    target_sdoc_id = serializers.CharField()
    reason = serializers.CharField(required=False, allow_blank=True)


class AuditLogSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True, allow_null=True)
    tcert_id = serializers.CharField(source="tcert.tcert_id", read_only=True, allow_null=True)

    class Meta:
        model = AuditLog
        fields = [
            "id",
            "username",
            "action",
            "tcert_id",
            "target",
            "ip_address",
            "detail",
            "created_at",
        ]


class ApiKeySerializer(serializers.ModelSerializer):
    owner = serializers.CharField(source="owner.username", read_only=True, allow_null=True)
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = ApiKey
        fields = [
            "id",
            "name",
            "key_prefix",
            "owner",
            "permissions",
            "is_active",
            "expires_at",
            "created_at",
            "last_used_at",
        ]
        read_only_fields = ["id", "key_prefix", "owner", "created_at", "last_used_at"]

    def get_permissions(self, obj) -> list[str]:
        return [f"{p.content_type.app_label}.{p.codename}" for p in obj.permissions.all()]


# The only permissions an API key may carry.
API_KEY_PERM_CODENAMES = ("can_sign", "can_block_sdoc", "can_unblock_sdoc")


class ApiKeyCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=255)
    permissions = serializers.ListField(child=serializers.CharField(), required=False, default=list)
    expires_at = serializers.DateTimeField(required=False, allow_null=True)

    def validate_permissions(self, value):
        allowed = {f"enterprise.{c}" for c in API_KEY_PERM_CODENAMES}
        bad = [p for p in value if p not in allowed]
        if bad:
            raise serializers.ValidationError(
                f"Unsupported permission(s): {', '.join(bad)}. "
                f"Allowed: {', '.join(sorted(allowed))}"
            )
        return value