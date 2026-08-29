"""Bridge to the Node verifier.

Every cryptographic operation (parsing canonical CBOR/COSE, verifying Ed25519 /
ECDSA signatures) is delegated to `qrs-core` via small Node scripts. The Python
server never re-implements crypto, so verification is byte-identical to the
reference implementation used by the desktop/mobile apps.
"""
import json
import logging
import shutil
import subprocess
from pathlib import Path

from django.conf import settings

logger = logging.getLogger(__name__)

NODE = shutil.which("node") or "node"
SCRIPTS = Path(__file__).resolve().parent.parent / "verify"


def _run(script: str, payload: dict) -> dict:
    script_path = SCRIPTS / script
    try:
        proc = subprocess.run(
            [NODE, str(script_path)],
            # Pass the payload via stdin (JSON) instead of argv: base64url blobs for
            # real documents overflow ARG_MAX ("Argument list too long", E2BIG).
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=settings.QRS_VERIFY_TIMEOUT,
            cwd=str(SCRIPTS.parent),
        )
        if proc.returncode != 0:
            return {"ok": False, "error": proc.stderr.strip() or "verify script failed"}
        return json.loads(proc.stdout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "verify timeout"}
    except (json.JSONDecodeError, OSError) as exc:  # noqa: BLE001
        logger.exception("verify bridge error")
        return {"ok": False, "error": str(exc)}


def describe_tcert(tcert_b64: str) -> dict:
    """Parse + self-verify a TCert; return its public fields."""
    return _run("describe.mjs", {"tcert": tcert_b64})


def verify_object(tcert_b64: str, object_b64: str) -> dict:
    """Verify a signed object's signature against the TCert's public key."""
    return _run("verify_object.mjs", {"tcert": tcert_b64, "object": object_b64})


def decode_qrs_file(qrs_text: str) -> dict:
    """Decode a `.qrs` file's text content into its signed objects via the Node bridge."""
    return _run("decode_qrs.mjs", {"qrs": qrs_text})
