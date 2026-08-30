from django.db import migrations, models
import django.db.models.deletion


def create_references_from_legacy_rows(apps, schema_editor):
    AttachmentBlob = apps.get_model("api", "AttachmentBlob")
    AttachmentReference = apps.get_model("api", "AttachmentReference")
    for blob in AttachmentBlob.objects.exclude(tcert_id=None).iterator():
        AttachmentReference.objects.get_or_create(
            tcert_id=blob.tcert_id,
            blob_id=blob.pk,
            field_name="",
        )


class Migration(migrations.Migration):
    dependencies = [("api", "0011_attachment_file_storage")]

    operations = [
        migrations.RenameModel(
            old_name="Attachment",
            new_name="AttachmentBlob",
        ),
        migrations.CreateModel(
            name="AttachmentReference",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("field_name", models.CharField(blank=True, default="", max_length=255)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "blob",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="references",
                        to="api.attachmentblob",
                    ),
                ),
                (
                    "tcert",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="attachments",
                        to="api.supportedtcert",
                    ),
                ),
            ],
            options={
                "constraints": [
                    models.UniqueConstraint(
                        fields=("tcert", "blob", "field_name"),
                        name="unique_attachment_reference_per_field",
                    )
                ],
            },
        ),
        migrations.RunPython(create_references_from_legacy_rows, migrations.RunPython.noop),
        migrations.RemoveField(model_name="attachmentblob", name="tcert"),
        migrations.RemoveField(model_name="attachmentblob", name="key_id"),
        migrations.AlterField(
            model_name="attachmentblob",
            name="file",
            field=models.FileField(upload_to="attachments/blobs/"),
        ),
    ]
