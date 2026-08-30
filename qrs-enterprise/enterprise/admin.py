"""Django admin for QRS Enterprise models."""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import ApiKey, AuditLog, ManagedKey, ManagedTcert, SdocRecord, TcertGrant, User


@admin.register(User)
class EnterpriseUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (
        ("QRS Enterprise", {"fields": ("role",)}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        ("QRS Enterprise", {"fields": ("role",)}),
    )
    list_display = ("username", "email", "role", "is_staff", "is_active")


@admin.register(ManagedKey)
class ManagedKeyAdmin(admin.ModelAdmin):
    list_display = ("key_id", "algorithm", "created_at")
    search_fields = ("key_id",)
    readonly_fields = ("key_id", "algorithm", "public_jwk", "private_jwk_encrypted", "created_at")


@admin.register(ManagedTcert)
class ManagedTcertAdmin(admin.ModelAdmin):
    list_display = ("name", "tcert_id", "algorithm", "is_ca", "has_schema", "created_at")
    list_filter = ("is_ca", "algorithm")
    search_fields = ("name", "tcert_id", "key__key_id")
    readonly_fields = (
        "key",
        "tcert_id",
        "certificate_number",
        "name",
        "algorithm",
        "schema",
        "tcert_b64",
        "created_at",
    )


@admin.register(TcertGrant)
class TcertGrantAdmin(admin.ModelAdmin):
    list_display = ("user", "tcert", "created_at")
    list_filter = ("tcert",)


@admin.register(SdocRecord)
class SdocRecordAdmin(admin.ModelAdmin):
    list_display = ("sdoc_id", "tcert", "signed_by", "issued_at", "created_at")
    search_fields = ("sdoc_id",)
    readonly_fields = ("sdoc_id", "tcert", "signed_by", "sdoc_b64", "issued_at", "created_at")


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("user", "action", "target", "ip_address", "created_at")
    list_filter = ("action",)
    search_fields = ("user__username", "target")
    readonly_fields = (
        "user",
        "action",
        "tcert",
        "target",
        "ip_address",
        "statement_b64",
        "detail",
        "created_at",
    )


# The only permissions an API key may carry.
API_KEY_PERM_CODENAMES = (
    "can_sign",  # sign SDocs
    "can_block_sdoc",  # block SDocs
    "can_unblock_sdoc",  # unblock SDocs
)


@admin.register(ApiKey)
class ApiKeyAdmin(admin.ModelAdmin):
    list_display = ("name", "key_prefix", "owner", "is_active", "expires_at", "created_at")
    list_filter = ("is_active", "owner", "permissions")
    search_fields = ("name", "key_prefix", "owner__username")
    readonly_fields = ("key_hash", "key_prefix", "created_at", "last_used_at")
    fields = (
        "name",
        "owner",
        "permissions",
        "is_active",
        "expires_at",
        "key_hash",
        "key_prefix",
        "created_at",
        "last_used_at",
    )
    autocomplete_fields = ("owner",)
    filter_horizontal = ("permissions",)

    def formfield_for_manytomany(self, db_field, request, **kwargs):
        """Restrict the permissions multiselect to the API-key permissions only."""
        if db_field.name == "permissions":
            kwargs["queryset"] = db_field.remote_field.model.objects.filter(
                content_type__app_label="enterprise", codename__in=API_KEY_PERM_CODENAMES
            )
        return super().formfield_for_manytomany(db_field, request, **kwargs)
