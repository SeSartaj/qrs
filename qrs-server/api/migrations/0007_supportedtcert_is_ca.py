# Generated manually for the new online-server spec (2026-08-25).

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0006_alter_attachment_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='supportedtcert',
            name='is_ca',
            field=models.BooleanField(default=False),
        ),
    ]
