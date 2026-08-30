#!/usr/bin/env node
/**
 * Cross-language verifier bridge (TypeScript side).
 *
 * Reads a JSON request on stdin and prints a JSON verdict on stdout. Used by the
 * Python conformance tests to verify objects produced by the Python core inside
 * the reference JS implementation.
 *
 * Request:  {"bytesB64": "<base64url signed object>", "type": "tcert|sdoc", "secret": "<optional>"}
 * Response: {"ok": true, "type": "...", "algorithm": "...", "signerKeyId": "...", "verified": bool}
 *           or {"ok": false, "error": "..."}
 */
import { parseSignedObject, verifyParsedSignedObject } from '../qrs-core-js/dist/signedObject/signedObject.js';
import { createDefaultCryptoRegistry } from '../qrs-core-js/dist/crypto/nodeRegistry.js';
import { fromBase64Url } from '../qrs-core-js/dist/id.js';
import { cborEncode } from '../qrs-core-js/dist/cbor/canonical.js';

function main() {
  let raw = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => {
    raw += chunk;
  });
  process.stdin.on('end', async () => {
    let req;
    try {
      req = JSON.parse(raw);
    } catch (exc) {
      console.log(JSON.stringify({ ok: false, error: `bad request json: ${exc.message}` }));
      return;
    }
    try {
      const bytes = fromBase64Url(req.bytesB64);
      const parsed = parseSignedObject(bytes);
      const registry = createDefaultCryptoRegistry();
      const provider = registry.get(parsed.algorithm);
      // For a TCert the public key is self-contained; for an SDoc/statement the
      // signer's public key must be supplied (it lives in the issuing TCert).
      const publicJwk = req.publicKey ?? parsed.data.publicKey;
      if (!publicJwk) {
        console.log(JSON.stringify({ ok: false, error: 'no public key available for verification' }));
        return;
      }
      // Rebuild the COSE external AAD from any stripped-secret values, exactly
      // as the signing/verification services do.
      const secret = req.secret;
      const externalAad = secret && Object.keys(secret).length > 0 ? cborEncode(secret) : new Uint8Array(0);
      const verified = await verifyParsedSignedObject(parsed, provider, publicJwk, externalAad);
      console.log(
        JSON.stringify({
          ok: true,
          type: parsed.type,
          algorithm: parsed.algorithm,
          signerKeyId: parsed.signerKeyId,
          verified,
        })
      );
    } catch (exc) {
      console.log(JSON.stringify({ ok: false, error: `${exc.constructor?.name ?? 'Error'}: ${exc.message}` }));
    }
  });
}

main();