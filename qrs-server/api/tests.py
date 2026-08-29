import json
import shutil
import subprocess
from pathlib import Path

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from . import proof_of_work
from .models import Attachment, SupportedTcert, TcertToken

BASE = Path(__file__).resolve().parent.parent
NODE = shutil.which("node") or "node"


def load_fixtures() -> dict:
    """Generate a TCert + signed statements via the qrs-core Node bridge."""
    proc = subprocess.run(
        [NODE, str(BASE / "verify" / "make_fixtures.mjs")], capture_output=True, text=True, timeout=60
    )
    return json.loads(proc.stdout)


class ProofOfWorkTest(TestCase):
    def test_verify(self):
        nonce = "aabbcc"
        counter = proof_of_work.solve(nonce, 4)
        self.assertTrue(proof_of_work.verify(nonce, 4, counter))
        self.assertFalse(proof_of_work.verify(nonce, 4, counter + 1))
        self.assertFalse(proof_of_work.verify(nonce, 0, counter))  # difficulty out of range
        self.assertFalse(proof_of_work.verify(nonce, 12, counter))  # difficulty too high


class ApiFlowTest(TestCase):
    def setUp(self):
        self.fx = load_fixtures()
        self.client = APIClient()

    def test_full_flow(self):
        c = self.client
        fx = self.fx

        # 1. Bootstrap the CA (admin action) and admit the target via a CA
        #    attestation. The CA is the fixture's `tcert`; the target is `target`.
        ca = SupportedTcert.objects.create(
            key_id=fx["tcertId"].split(":")[0], certificate_number=1, tcert_id=fx["tcertId"],
            algorithm="Ed25519", name="License", public_key={}, online_endpoint="",
            tcert_b64=fx["tcertB64"], is_ca=True,
        )
        key = ca.key_id
        TcertToken.objects.create(
            key_id=key, token="ca-tok",
            expires_at=timezone.now() + timezone.timedelta(minutes=5),
        )
        r = c.post(
            f"/api/cas/{ca.tcert_id}/attestations/",
            {"targetTcertB64": fx["targetB64"], "attestationB64": fx["attestB64"]},
            format="json",
            HTTP_AUTHORIZATION="Bearer ca-tok",
        )
        self.assertEqual(r.status_code, 201, r.content)

        # 2. Discovery (public) — CA-scoped sync returns full TCert bytes so
        #    attested certs are shareable.
        r = c.post(f"/api/cas/{ca.tcert_id}/sync/", {}, format="json")
        self.assertEqual(r.status_code, 200, r.content)
        discovered = [t for t in r.json()["tcerts"] if t["keyId"] == key]
        self.assertTrue(discovered)
        self.assertEqual(discovered[0]["bytesB64"], fx["targetB64"])

        # 3. Challenge → solve PoW → token.
        r = c.post(f"/api/tcerts/{key}/challenge/", {}, format="json")
        self.assertEqual(r.status_code, 200, r.content)
        nonce = r.json()["nonce"]
        difficulty = r.json()["difficulty"]
        counter = proof_of_work.solve(nonce, difficulty)
        r = c.post(f"/api/tcerts/{key}/token/", {"nonce": nonce, "counter": counter}, format="json")
        self.assertEqual(r.status_code, 200, r.content)
        token = r.json()["token"]

        # 4. The CA uploads a signed statement via the CA statement endpoint.
        r = c.post(
            f"/api/cas/{ca.tcert_id}/statements/",
            {"bytesB64": fx["revokeB64"]},
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        self.assertEqual(r.status_code, 201, r.content)
        self.assertEqual(r.json()["action"], "revokeTcert")

        # 5. A tampered statement is rejected (signature check).
        bad = fx["attestB64"][:-1] + ("B" if not fx["attestB64"].endswith("B") else "A")
        r = c.post(
            f"/api/cas/{ca.tcert_id}/statements/",
            {"bytesB64": bad},
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        self.assertEqual(r.status_code, 400, r.content)

        # 6. Upload without a token → 401.
        r = c.post(
            f"/api/cas/{ca.tcert_id}/statements/",
            {"bytesB64": fx["revokeB64"]},
            format="json",
        )
        self.assertEqual(r.status_code, 401)

        # 7. Public read: the statement is listed (verifier fetches + verifies client-side).
        r = c.get(f"/api/tcerts/{key}/objects/")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(any(o["action"] == "revokeTcert" for o in r.json()["objects"]))

        # 8. Attachments: upload a normal file; the server calculates its ID.
        raw_attachment = b"fake-png-bytes"
        import hashlib
        att_id = hashlib.sha256(raw_attachment).hexdigest()[:32]
        r = c.post(
            "/api/attachments/",
            {
                "tcertId": fx["tcertId"],
                "fieldName": "photo",
                "file": SimpleUploadedFile("photo.png", raw_attachment, content_type="image/png"),
            },
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        self.assertEqual(r.status_code, 201, r.content)
        self.assertEqual(r.json()["id"], att_id)

        # Metadata-only GET (no body) — lets the verifier show size without downloading.
        r = c.get(f"/api/attachments/{att_id}/")
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual(r.json()["contentType"], "image/png")
        self.assertNotIn("contentB64", r.json())

        # A field absent from the signed schema cannot host an attachment.
        r = c.post(
            "/api/attachments/",
            {
                "tcertId": fx["tcertId"],
                "fieldName": "not-a-field",
                "file": SimpleUploadedFile("photo.png", raw_attachment, content_type="image/png"),
            },
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        self.assertEqual(r.status_code, 400, r.content)

        # ?content=1 returns the raw file body, not base64 JSON.
        r = c.get(f"/api/attachments/{att_id}/?content=1")
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual(r.content, raw_attachment)

        # Re-uploading the same attachment repairs a metadata-only row left by
        # an older/partial upload.
        Attachment.objects.filter(id=att_id).update(file="")
        r = c.post(
            "/api/attachments/",
            {
                "tcertId": fx["tcertId"],
                "fieldName": "photo",
                "file": SimpleUploadedFile("photo.png", raw_attachment, content_type="image/png"),
            },
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        self.assertEqual(r.status_code, 201, r.content)
        r = c.get(f"/api/attachments/{att_id}/?content=1")
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual(r.content, raw_attachment)

    def test_scoped_sync(self):
        c = self.client
        fx = self.fx

        # Bootstrap the CA and admit the target via a CA attestation.
        ca = SupportedTcert.objects.create(
            key_id=fx["tcertId"].split(":")[0], certificate_number=1, tcert_id=fx["tcertId"],
            algorithm="Ed25519", name="License", public_key={}, online_endpoint="",
            tcert_b64=fx["tcertB64"], is_ca=True,
        )
        ca_key = ca.key_id
        TcertToken.objects.create(
            key_id=ca_key, token="ca-tok",
            expires_at=timezone.now() + timezone.timedelta(minutes=5),
        )
        r = c.post(
            f"/api/cas/{ca.tcert_id}/attestations/",
            {"targetTcertB64": fx["targetB64"], "attestationB64": fx["attestB64"]},
            format="json",
            HTTP_AUTHORIZATION="Bearer ca-tok",
        )
        self.assertEqual(r.status_code, 201, r.content)

        # Scoped sync for the CA returns only the certs it enrolled + the
        # statements it issued (never the whole hosted inventory).
        r = c.post(f"/api/cas/{ca.tcert_id}/sync/", {}, format="json")
        self.assertEqual(r.status_code, 200, r.content)
        body = r.json()
        self.assertEqual({t["keyId"] for t in body["tcerts"]}, {ca_key})
        self.assertEqual(len(body["tcerts"]), 1)  # the attested target cert
        self.assertTrue(any(a["targetTcertId"] == fx["targetTcertId"] for a in body["attestations"]))
        self.assertIn(fx["targetB64"], {t["bytesB64"] for t in body["tcerts"]})

        # Unknown CA → 404 (nothing unrelated is returned).
        r = c.post("/api/cas/deadbeef/sync/", {}, format="json")
        self.assertEqual(r.status_code, 404, r.content)

    def test_rejects_unsupported_tcert(self):
        c = self.client
        r = c.post("/api/tcerts/abc/challenge/", {}, format="json")
        self.assertEqual(r.status_code, 200)  # challenges are not scoped to a registered TCert

    def test_non_ca_tcert_cannot_upload(self):
        """New spec: a TCert that is neither a trusted CA nor attested by one
        cannot upload statements or attachments."""
        c = self.client
        fx = self.fx

        # Register a TCert directly (admin bootstrap) but do NOT mark it as a CA
        # and do NOT attest it.
        tcert = SupportedTcert.objects.create(
            key_id=fx["tcertId"].split(":")[0], certificate_number=1, tcert_id=fx["tcertId"],
            algorithm="Ed25519", name="License", public_key={}, online_endpoint="",
            tcert_b64=fx["tcertB64"],
        )
        key = tcert.key_id

        # Solve PoW to get a token.
        r = c.post(f"/api/tcerts/{key}/challenge/", {}, format="json")
        self.assertEqual(r.status_code, 200, r.content)
        counter = proof_of_work.solve(r.json()["nonce"], r.json()["difficulty"])
        r = c.post(
            f"/api/tcerts/{key}/token/",
            {"nonce": r.json()["nonce"], "counter": counter},
            format="json",
        )
        self.assertEqual(r.status_code, 200, r.content)
        token = r.json()["token"]

        # Statement upload is forbidden (403) for a non-CA, non-attested TCert.
        r = c.post(
            f"/api/cas/{tcert.tcert_id}/statements/",
            {"bytesB64": fx["revokeB64"]},
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        self.assertEqual(r.status_code, 404, r.content)  # not a trusted CA

        # Attachment upload is forbidden too (not attested).
        r = c.post(
            "/api/attachments/",
            {
                "tcertId": fx["tcertId"],
                "fieldName": "photo",
                "file": SimpleUploadedFile("photo.png", b"fake-png-bytes", content_type="image/png"),
            },
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        self.assertEqual(r.status_code, 403, r.content)

    def test_independent_cas_attest_same_target(self):
        """Two independent trusted CAs may both attest the same target TCert.

        Regression: the server used to store a single CA link and
        rejected a second CA with a 409 ('already controlled by a different CA').
        The protocol models attestation as many-to-many, so a revocation by one
        CA must not prevent another CA from independently attesting the target.
        """
        c = self.client
        fx = self.fx

        def mint_token(key_id):
            TcertToken.objects.create(
                key_id=key_id,
                token=key_id + "-tok",
                expires_at=timezone.now() + timezone.timedelta(minutes=5),
            )

        # CA-A (fx key) is already registered + a trusted CA; CA-B is a second,
        # fully independent CA. The target is admitted via CA-A's attestation.
        ca_a = SupportedTcert.objects.create(
            key_id=fx["tcertId"].split(":")[0], certificate_number=1, tcert_id=fx["tcertId"],
            algorithm="Ed25519", name="CA A", public_key={}, online_endpoint="",
            tcert_b64=fx["tcertB64"], is_ca=True,
        )
        ca_b = SupportedTcert.objects.create(
            key_id=fx["caBTcertId"].split(":")[0], certificate_number=1, tcert_id=fx["caBTcertId"],
            algorithm="Ed25519", name="CA B", public_key={}, online_endpoint="",
            tcert_b64=fx["caBB64"], is_ca=True,
        )
        target = SupportedTcert.objects.create(
            key_id=fx["targetTcertId"].split(":")[0], certificate_number=1, tcert_id=fx["targetTcertId"],
            algorithm="Ed25519", name="Target", public_key={}, online_endpoint="",
            tcert_b64=fx["targetB64"],
        )
        mint_token(ca_a.key_id)
        mint_token(ca_b.key_id)

        # CA-A attests the target → first enrollment succeeds.
        r = c.post(
            f"/api/cas/{ca_a.tcert_id}/attestations/",
            {"targetTcertB64": fx["targetB64"], "attestationB64": fx["attestB64"]},
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {ca_a.key_id}-tok",
        )
        self.assertEqual(r.status_code, 201, r.content)

        # CA-B attests the SAME target → must NOT 409 anymore. It records an
        # independent attestation alongside CA-A's.
        r = c.post(
            f"/api/cas/{ca_b.tcert_id}/attestations/",
            {"targetTcertB64": fx["targetB64"], "attestationB64": fx["attestBB64"]},
            format="json",
            HTTP_AUTHORIZATION=f"Bearer {ca_b.key_id}-tok",
        )
        self.assertEqual(r.status_code, 201, r.content)

        # The target now is attested by at least one trusted CA (admitted).
        self.assertFalse(target.is_ca)
        from .models import TcertAttestation
        self.assertEqual(
            TcertAttestation.objects.filter(target=target).count(), 2,
            "both independent CAs should hold an attestation for the target",
        )
        self.assertEqual(
            set(TcertAttestation.objects.filter(target=target).values_list("ca__tcert_id", flat=True)),
            {ca_a.tcert_id, ca_b.tcert_id},
        )

        # Each CA's scoped sync lists the target but only its own attestation.
        r = c.post(f"/api/cas/{ca_a.tcert_id}/sync/", {}, format="json")
        self.assertEqual(r.status_code, 200, r.content)
        self.assertIn(target.tcert_id, {t["tcertId"] for t in r.json()["tcerts"]})
        self.assertEqual(
            [a["targetTcertId"] for a in r.json().get("attestations", [])],
            [target.tcert_id],
        )

    def test_import_qrs_file_multipart(self):
        """Public .qrs import is disabled; only the admin can bootstrap CAs."""
        c = self.client
        fx = self.fx
        r = c.post(
            "/api/tcerts/import/",
            {
                "file": SimpleUploadedFile(
                    "tcert.qrs", fx["qrsFileText"].encode("utf-8"), content_type="text/plain"
                )
            },
            format="multipart",
        )
        self.assertEqual(r.status_code, 403, r.content)

    def test_import_qrs_file_json(self):
        c = self.client
        fx = self.fx
        r = c.post("/api/tcerts/import/", {"qrs": fx["qrsFileText"]}, format="json")
        self.assertEqual(r.status_code, 403, r.content)

    def test_import_qrs_bundle_registers_every_tcert(self):
        c = self.client
        fx = self.fx
        r = c.post("/api/tcerts/import/", {"qrs": fx["qrsBundleText"]}, format="json")
        self.assertEqual(r.status_code, 403, r.content)

    def test_import_qrs_skips_non_tcert_objects(self):
        c = self.client
        fx = self.fx
        r = c.post("/api/tcerts/import/", {"qrs": fx["qrsStatementText"]}, format="json")
        self.assertEqual(r.status_code, 403, r.content)

    def test_import_qrs_rejects_garbage(self):
        c = self.client
        r = c.post("/api/tcerts/import/", {"qrs": "not-a-qrs-file"}, format="json")
        self.assertEqual(r.status_code, 403, r.content)


class AdminImportTest(TestCase):
    def setUp(self):
        self.fx = load_fixtures()
        self.user = User.objects.create_superuser("admin", "admin@example.com", "admin1234")
        self.client = APIClient()
        self.client.force_login(self.user, backend="django.contrib.auth.backends.ModelBackend")

    def test_import_qrs_page_renders(self):
        r = self.client.get("/admin/api/supportedtcert/import-qrs/")
        self.assertEqual(r.status_code, 200, r.content)
        self.assertContains(r, "Import TCert from .qrs file")

    def test_import_qrs_via_admin_file_upload(self):
        r = self.client.post(
            "/admin/api/supportedtcert/import-qrs/",
            {
                "file": SimpleUploadedFile(
                    "tcert.qrs", self.fx["qrsFileText"].encode("utf-8"), content_type="text/plain"
                )
            },
        )
        self.assertEqual(r.status_code, 302, r.content)
        self.assertTrue(SupportedTcert.objects.filter(tcert_id=self.fx["tcertId"]).exists())

    def test_import_qrs_via_admin_pasted_text(self):
        r = self.client.post("/admin/api/supportedtcert/import-qrs/", {"qrs": self.fx["qrsFileText"]})
        self.assertEqual(r.status_code, 302, r.content)
        self.assertTrue(SupportedTcert.objects.filter(tcert_id=self.fx["tcertId"]).exists())

    def test_import_qrs_via_admin_rejects_garbage(self):
        r = self.client.post("/admin/api/supportedtcert/import-qrs/", {"qrs": "not-a-qrs-file"})
        self.assertEqual(r.status_code, 302, r.content)  # redirects back to the changelist with an error message
        self.assertFalse(SupportedTcert.objects.exists())
