#!/usr/bin/env python3
"""Cross-language verifier bridge (Python side).

Reads a JSON request on stdin and prints a JSON verdict on stdout. Used by the
TypeScript conformance tests to verify objects produced by the JS reference
implementation inside the Python core.

Request:  {"bytesB64": "<base64url signed object>", "type": "tcert|sdoc", "secret": "<optional>"}
Response: {"ok": true, "type": "...", "algorithm": "...", "signerKeyId": "...", "verified": bool}
          or {"ok": false, "error": "..."}
"""

from __future__ import annotations

import base64
import json
import sys

from qrs.cbor import cbor_decode, cbor_encode
from qrs.cose import decode_cose_sign1
from qrs.crypto.registry import create_default_crypto_registry
from qrs.envelope import parse_signed_object, verify_parsed_signed_object
from qrs.id import from_base64url


def _b64_to_bytes(value: str) -> bytes:
    return from_base64url(value)


def main() -> None:
    raw = sys.stdin.read()
    try:
        req = json.loads(raw)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "error": f"bad request json: {exc}"}))
        return

    try:
        obj_bytes = _b64_to_bytes(req["bytesB64"])
        parsed = parse_signed_object(obj_bytes)
        registry = create_default_crypto_registry()
        provider = registry.get(parsed.algorithm)
        # For a TCert the public key is self-contained; for an SDoc/statement the
        # signer's public key must be supplied (it lives in the issuing TCert).
        public_jwk = req.get("publicKey") or parsed.data.get("publicKey")
        if public_jwk is None:
            print(json.dumps({"ok": False, "error": "no public key available for verification"}))
            return
        # Rebuild the COSE external AAD from any stripped-secret values, exactly
        # as the signing/verification services do.
        secret = req.get("secret")
        external_aad = cbor_encode(secret) if secret else b""
        verified = verify_parsed_signed_object(parsed, provider, public_jwk, external_aad)
        print(
            json.dumps(
                {
                    "ok": True,
                    "type": parsed.type,
                    "algorithm": parsed.algorithm,
                    "signerKeyId": parsed.signer_key_id,
                    "verified": verified,
                }
            )
        )
    except Exception as exc:  # noqa: BLE001 - report any parse/verify failure
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}))


if __name__ == "__main__":
    main()