from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0007_supportedtcert_is_ca"),
    ]

    operations = [
        migrations.AddField(
            model_name="attachment",
            name="object_b64",
            field=models.TextField(blank=True, default=""),
        ),
    ]
