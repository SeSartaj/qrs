"""Pytest fixtures for QRS Enterprise.

Sets up the KeyVault encryption key (generated at session start) so service
tests can create TCerts without depending on a real ``QRS_ENTERPRISE_KEY_ENC_KEY``
environment variable.
"""
import pytest
from cryptography.fernet import Fernet


@pytest.fixture(autouse=True)
def _set_key_enc_key(settings):
    settings.KEY_ENC_KEY = Fernet.generate_key().decode("ascii")
    yield