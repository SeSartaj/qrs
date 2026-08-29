from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("api", "0009_tcertattestation")]

    operations = [
        migrations.AddField("supportedtcert", "allow_attestation", models.BooleanField(default=True)),
        migrations.AddField("supportedtcert", "allow_tcert_enrollment", models.BooleanField(default=True)),
        migrations.AddField("supportedtcert", "allow_attachment_upload", models.BooleanField(default=True)),
        migrations.AddField("supportedtcert", "allow_sdoc_block", models.BooleanField(default=True)),
        migrations.AddField("supportedtcert", "allow_sdoc_unblock", models.BooleanField(default=True)),
        migrations.AddField("supportedtcert", "allow_self_revocation", models.BooleanField(default=True)),
    ]
