from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("api", "0010_tcert_service_permissions")]

    operations = [
        migrations.AddField(
            model_name="attachment",
            name="file",
            field=models.FileField(default="", upload_to="attachments/"),
            preserve_default=False,
        ),
        migrations.RemoveField(model_name="attachment", name="content"),
        migrations.RemoveField(model_name="attachment", name="object_b64"),
        migrations.RemoveField(model_name="attachment", name="signed_at"),
    ]
