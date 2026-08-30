"""API-level tests for QRS Enterprise.

These exercise the DRF endpoints (login, TCert creation, grants, signing,
CA operations, API keys) including authorization. They use Django's test client
with the async service layer invoked via the sync views.
"""
from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from enterprise.models import ApiKey, ManagedTcert, TcertGrant

User = get_user_model()

SIGNING_FIELDS = [
    {"type": "text", "name": "name", "label": "Name"},
    {"type": "text", "name": "license_no", "label": "License No"},
]


@pytest.fixture
def admin_user(db):
    return User.objects.create_user(username="admin", password="pw", role="admin", is_staff=True)


@pytest.fixture
def signer_user(db):
    return User.objects.create_user(username="signer", password="pw", role="signer")


@pytest.fixture

def admin_client(admin_user):
    token, _ = Token.objects.get_or_create(user=admin_user)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
    return client


@pytest.fixture
def signer_client(signer_user):
    token, _ = Token.objects.get_or_create(user=signer_user)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
    return client


@pytest.mark.django_db
class TestAuth:
    def test_login_returns_token(self, admin_user):
        client = APIClient()
        res = client.post("/api/auth/login/", {"username": "admin", "password": "pw"})
        assert res.status_code == 200
        assert "token" in res.json()
        assert res.json()["user"]["username"] == "admin"

    def test_login_bad_credentials(self):
        client = APIClient()
        res = client.post("/api/auth/login/", {"username": "nobody", "password": "wrong"})
        assert res.status_code == 400

    def test_me_requires_auth(self):
        res = APIClient().get("/api/auth/me/")
        assert res.status_code in (401, 403)


@pytest.mark.django_db
class TestTcertApi:
    def test_admin_creates_tcert(self, admin_client):
        res = admin_client.post(
            "/api/tcerts/",
            {"algorithm": "Ed25519", "name": "License", "fields": SIGNING_FIELDS},
            content_type="application/json",
        )
        assert res.status_code == 201
        data = res.json()
        assert data["tcert_id"]
        assert data["has_schema"] is True

    def test_signer_cannot_create_tcert(self, signer_client):
        res = signer_client.post(
            "/api/tcerts/",
            {"algorithm": "Ed25519", "name": "License", "fields": SIGNING_FIELDS},
            content_type="application/json",
        )
        assert res.status_code == 403

    def test_signer_cannot_sign_without_grant(self, admin_client, signer_client):
        res = admin_client.post(
            "/api/tcerts/",
            {"algorithm": "Ed25519", "name": "License", "fields": SIGNING_FIELDS},
            content_type="application/json",
        )
        tcert_id = res.json()["id"]
        sign_res = signer_client.post(
            f"/api/tcerts/{tcert_id}/sign/",
            {"values": {"name": "Ahmad", "license_no": "AF-1"}},
            content_type="application/json",
        )
        assert sign_res.status_code == 403

    def test_signer_signs_after_grant(self, admin_client, signer_client, signer_user):
        res = admin_client.post(
            "/api/tcerts/",
            {"algorithm": "Ed25519", "name": "License", "fields": SIGNING_FIELDS},
            content_type="application/json",
        )
        tcert_id = res.json()["id"]
        grant_res = admin_client.post(
            f"/api/tcerts/{tcert_id}/grants/",
            {"user_id": signer_user.id},
            content_type="application/json",
        )
        assert grant_res.status_code == 201
        sign_res = signer_client.post(
            f"/api/tcerts/{tcert_id}/sign/",
            {"values": {"name": "Ahmad", "license_no": "AF-1"}},
            content_type="application/json",
        )
        assert sign_res.status_code == 201
        assert sign_res.json()["sdoc_id"]


@pytest.mark.django_db
class TestApiKey:
    def test_admin_creates_api_key(self, admin_client):
        res = admin_client.post(
            "/api/api-keys/",
            {"name": "external", "permissions": ["enterprise.can_block_sdoc"]},
            content_type="application/json",
        )
        assert res.status_code == 201
        data = res.json()
        assert data["key"].startswith("qrs_")
        assert data["key_prefix"]

    def test_api_key_authenticates(self, admin_client, admin_user):
        res = admin_client.post(
            "/api/api-keys/",
            {"name": "external", "permissions": ["enterprise.can_block_sdoc"]},
            content_type="application/json",
        )
        raw_key = res.json()["key"]
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"ApiKey {raw_key}")
        me = client.get("/api/auth/me/")
        assert me.status_code == 200
        assert me.json()["username"] == "admin"

    def test_api_key_scope_denies_unpermitted(self, admin_client):
        res = admin_client.post(
            "/api/api-keys/",
            {"name": "readonly", "permissions": []},
            content_type="application/json",
        )
        raw_key = res.json()["key"]
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"ApiKey {raw_key}")
        # Blocking requires can_block_sdoc permission, which this key lacks.
        block = client.post(
            "/api/sdocs/block/",
            {"target_sdoc_id": "deadbeef", "signer_key_id": "x"},
            content_type="application/json",
        )
        assert block.status_code == 403

    def test_api_key_rejects_unsupported_permission(self, admin_client):
        res = admin_client.post(
            "/api/api-keys/",
            {"name": "bad", "permissions": ["enterprise.can_revoke_tcert"]},
            content_type="application/json",
        )
        assert res.status_code == 400
        assert "Unsupported permission" in str(res.json())


@pytest.mark.django_db
class TestExternalSign:
    """External-system signing via /api/sign/ (OPTIONS schema + POST sign)."""

    def _make_tcert(self, admin_client):
        res = admin_client.post(
            "/api/tcerts/",
            {"algorithm": "Ed25519", "name": "License", "fields": SIGNING_FIELDS},
            content_type="application/json",
        )
        assert res.status_code == 201
        return res.json()

    def _api_client(self, raw_key):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"ApiKey {raw_key}")
        return client

    def test_options_returns_schema(self, admin_client, admin_user):
        tcert = self._make_tcert(admin_client)
        res = admin_client.post(
            "/api/api-keys/",
            {"name": "ext", "permissions": ["enterprise.can_sign"]},
            content_type="application/json",
        )
        raw_key = res.json()["key"]
        client = self._api_client(raw_key)
        # OPTIONS returns the schema for the TCert.
        opts = client.options(
            "/api/sign/", {"tcert_id": tcert["tcert_id"]}, content_type="application/json"
        )
        assert opts.status_code == 200
        body = opts.json()
        assert body["tcert_id"] == tcert["tcert_id"]
        assert body["schema"] == SIGNING_FIELDS

    def test_get_returns_schema(self, admin_client, admin_user):
        tcert = self._make_tcert(admin_client)
        res = admin_client.post(
            "/api/api-keys/",
            {"name": "ext", "permissions": ["enterprise.can_sign"]},
            content_type="application/json",
        )
        raw_key = res.json()["key"]
        client = self._api_client(raw_key)
        get = client.get(f"/api/sign/?tcert_id={tcert['tcert_id']}")
        assert get.status_code == 200
        assert get.json()["schema"] == SIGNING_FIELDS

    def test_post_signs_sdoc(self, admin_client, admin_user):
        tcert = self._make_tcert(admin_client)
        res = admin_client.post(
            "/api/api-keys/",
            {"name": "ext", "permissions": ["enterprise.can_sign"]},
            content_type="application/json",
        )
        raw_key = res.json()["key"]
        client = self._api_client(raw_key)
        sign = client.post(
            "/api/sign/",
            {"tcert_id": tcert["tcert_id"], "values": {"name": "Ahmad", "license_no": "AF-1"}},
            content_type="application/json",
        )
        assert sign.status_code == 201
        body = sign.json()
        assert body["sdoc_id"]
        assert body["sdoc_b64"]
        assert body["qr_payload"].startswith("qrs://v1/sdoc/")
        assert body["qr_png_b64"]

    def test_post_denied_without_can_sign(self, admin_client, admin_user):
        tcert = self._make_tcert(admin_client)
        res = admin_client.post(
            "/api/api-keys/",
            {"name": "ext", "permissions": []},
            content_type="application/json",
        )
        raw_key = res.json()["key"]
        client = self._api_client(raw_key)
        sign = client.post(
            "/api/sign/",
            {"tcert_id": tcert["tcert_id"], "values": {"name": "Ahmad"}},
            content_type="application/json",
        )
        assert sign.status_code == 403

    def test_post_denied_when_owner_lacks_grant(self, admin_client, signer_user):
        """API key owner must have a grant for the TCert."""
        tcert = self._make_tcert(admin_client)
        # Create an API key owned by signer_user (who has no grant).
        key, raw_key = ApiKey.generate(
            name="ext", owner=signer_user, permissions=["enterprise.can_sign"]
        )
        client = self._api_client(raw_key)
        sign = client.post(
            "/api/sign/",
            {"tcert_id": tcert["tcert_id"], "values": {"name": "Ahmad"}},
            content_type="application/json",
        )
        assert sign.status_code == 403

    def test_post_allowed_when_owner_has_grant(self, admin_client, signer_user):
        tcert = self._make_tcert(admin_client)
        # Grant signer_user the TCert, then create an API key owned by them.
        grant = admin_client.post(
            f"/api/tcerts/{tcert['id']}/grants/",
            {"user_id": signer_user.id},
            content_type="application/json",
        )
        assert grant.status_code == 201
        key, raw_key = ApiKey.generate(
            name="ext", owner=signer_user, permissions=["enterprise.can_sign"]
        )
        client = self._api_client(raw_key)
        sign = client.post(
            "/api/sign/",
            {"tcert_id": tcert["tcert_id"], "values": {"name": "Ahmad", "license_no": "AF-1"}},
            content_type="application/json",
        )
        assert sign.status_code == 201
        assert sign.json()["sdoc_id"]