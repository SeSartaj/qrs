"""Generate a Fernet key for the KeyVault (QRS_ENTERPRISE_KEY_ENC_KEY)."""
from cryptography.fernet import Fernet
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Generate a Fernet key for QRS_ENTERPRISE_KEY_ENC_KEY and print it."

    def handle(self, *args, **options):
        key = Fernet.generate_key().decode("ascii")
        self.stdout.write(key)
        self.stdout.write(
            self.style.SUCCESS(
                "Set this as QRS_ENTERPRISE_KEY_ENC_KEY. Store it securely; "
                "private keys encrypted with it cannot be recovered without it."
            )
        )