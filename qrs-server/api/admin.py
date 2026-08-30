from django.contrib import admin, messages
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect, render
from django.urls import path

from .models import AttachmentBlob, AttachmentReference, SignedObject, SupportedTcert, TcertChallenge, TcertToken
from .views import decode_qrs_file, register_tcert_bytes


@admin.register(SupportedTcert)
class SupportedTcertAdmin(admin.ModelAdmin):
    list_display = ("tcert_id", "name", "algorithm", "is_ca", "enrollment_summary", "online_endpoint", "created_at")
    list_filter = ("is_ca", "allow_attestation", "allow_tcert_enrollment", "allow_attachment_upload", "allow_sdoc_block", "allow_sdoc_unblock", "allow_self_revocation")
    search_fields = ("key_id", "tcert_id", "name")
    actions = ["mark_as_ca", "unmark_as_ca"]
    # Everything is cryptographically signed — admins must never edit it by hand.
    readonly_fields = (
        "tcert_id",
        "key_id",
        "certificate_number",
        "algorithm",
        "name",
        "public_key",
        "online_endpoint",
        "tcert_b64",
        "created_at",
    )
    fieldsets = (
        ("Identity (signed; read-only)", {"fields": readonly_fields}),
        ("Service permissions", {"fields": ("is_ca", "allow_attestation", "allow_tcert_enrollment", "allow_attachment_upload", "allow_sdoc_block", "allow_sdoc_unblock", "allow_self_revocation")}),
    )
    change_list_template = "admin/api/supportedtcert_changelist.html"

    @admin.action(description="Mark selected as trusted CA")
    def mark_as_ca(self, request, queryset):
        updated = queryset.update(is_ca=True)
        self.message_user(request, f"Marked {updated} TCert(s) as trusted CA.")

    @admin.action(description="Unmark selected as trusted CA")
    def unmark_as_ca(self, request, queryset):
        updated = queryset.update(is_ca=False)
        self.message_user(request, f"Unmarked {updated} TCert(s) as trusted CA.")

    @admin.display(description="Enrolled by (CA)")
    def enrollment_summary(self, obj):
        if obj.is_ca:
            return "— (trusted CA)"
        return ", ".join(a.ca.tcert_id for a in obj.attestations.select_related("ca")[:5]) or "(unattested)"

    def get_urls(self):
        urls = super().get_urls()
        custom = [
            path(
                "import-qrs/",
                self.admin_site.admin_view(self.import_qrs_view),
                name="api_supportedtcert_import_qrs",
            ),
        ]
        return custom + urls

    def import_qrs_view(self, request):
        """Upload a `.qrs` file (single TCert or bundle) to register its TCerts."""
        if not self.has_add_permission(request):
            raise PermissionDenied

        if request.method == "POST":
            qrs_text = None
            uploaded = request.FILES.get("file")
            if uploaded is not None:
                qrs_text = uploaded.read().decode("utf-8", errors="replace")
            elif request.POST.get("qrs"):
                qrs_text = request.POST["qrs"]
            if not qrs_text:
                messages.error(request, "Choose a .qrs file or paste its text.")
                return redirect("admin:api_supportedtcert_import_qrs")

            decoded = decode_qrs_file(qrs_text)
            if not decoded.get("ok"):
                messages.error(request, decoded.get("error") or "Not a valid .qrs file.")
                return redirect("admin:api_supportedtcert_import_qrs")

            imported = []
            skipped = []
            for obj in decoded.get("objects") or []:
                if obj.get("type") != "tcert":
                    skipped.append(f"{obj.get('type')} (not a TCert)")
                    continue
                summary, error = register_tcert_bytes(obj.get("bytesB64") or "")
                if error:
                    skipped.append(f"TCert: {error}")
                else:
                    imported.append(summary["tcertId"])

            if imported:
                messages.success(request, f"Imported {len(imported)} TCert(s): {', '.join(imported)}.")
            if skipped:
                messages.warning(request, f"Skipped: {'; '.join(skipped)}.")
            if not imported:
                messages.error(request, "No TCert was imported from the file.")
            return redirect("admin:api_supportedtcert_changelist")

        context = {
            **self.admin_site.each_context(request),
            "title": "Import TCert from .qrs file",
            "opts": self.model._meta,
            "has_permission": self.has_add_permission(request),
        }
        return render(request, "admin/api/supportedtcert_import.html", context)


@admin.register(TcertToken)
class TcertTokenAdmin(admin.ModelAdmin):
    list_display = ("key_id", "token", "expires_at", "created_at")


@admin.register(SignedObject)
class SignedObjectAdmin(admin.ModelAdmin):
    list_display = ("action", "statement_id", "tcert", "received_at")


@admin.register(AttachmentBlob)
class AttachmentBlobAdmin(admin.ModelAdmin):
    list_display = ("id", "content_type", "content_hash", "size", "created_at")


@admin.register(AttachmentReference)
class AttachmentReferenceAdmin(admin.ModelAdmin):
    list_display = ("tcert", "blob", "field_name", "created_at")


@admin.register(TcertChallenge)
class TcertChallengeAdmin(admin.ModelAdmin):
    list_display = ("key_id", "nonce", "difficulty", "created_at")
