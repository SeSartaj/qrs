#!/usr/bin/env node
/**
 * Verifies a signed object against a TCert's embedded public key.
 *
 * The Python server delegates every cryptographic verification here so it reuses
 * the exact, audited qrs-core implementation (canonical CBOR + COSE + Ed25519 /
 * ECDSA) instead of re-implementing crypto in Python.
 *
 * The TCert and object (both base64url) are passed on stdin as JSON
 * `{"tcert": "...", "object": "..."}` (argv is too small for real documents).
 * Legacy argv usage `node verify_object.mjs <tcertB64> <objectB64>` is accepted.
 *
 * Prints a single JSON object:
 *   { ok: bool, objectType, algorithm, action?, statementId?, signedAt?,
 *     id?, contentType?, contentHash?, error? }
 */
import { createDefaultCryptoRegistry, fromBase64Url, hashFor, parseSignedObject, toBase64Url, toHex, verifyParsedSignedObject } from 'qrs-core';

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

async function readInput() {
  const args = process.argv.slice(2);
  if (args.length >= 2) return { tcert: args[0], object: args[1] };
  const raw = await readStdin();
  return JSON.parse(raw.trim());
}

const { tcert: tcertB64, object: objectB64 } = await readInput();

try {
  if (!tcertB64 || !objectB64) throw new Error('missing TCert/object');
  const registry = createDefaultCryptoRegistry();

  const tcert = parseSignedObject(fromBase64Url(tcertB64));
  if (tcert.type !== 'tcert') throw new Error('not a TCert');

  const object = parseSignedObject(fromBase64Url(objectB64));
  const provider = registry.get(tcert.algorithm);
  const publicJwk = tcert.data.publicKey;

  // Verify the object's COSE signature against the TCert's public key.
  const ok = await verifyParsedSignedObject(object, provider, publicJwk);

  const out = {
    ok,
    objectType: object.type,
    algorithm: object.algorithm,
    signerKeyId: object.signerKeyId,
    error: undefined,
  };
  if (object.type === 'statement') {
    const data = object.data ?? {};
    out.action = data.action;
    out.signedAt = data.issuedAt;
    if (data.statementId instanceof Uint8Array) out.statementId = toHex(data.statementId);
    const target = data.target;
    if (target && typeof target === 'object') {
      out.targetKind = target.kind;
      if (target.keyId instanceof Uint8Array) out.targetKeyId = toHex(target.keyId);
      if (typeof target.certificateNumber === 'number') out.targetCertificateNumber = target.certificateNumber;
      if (typeof target.tcertHash === 'string') out.targetTcertHash = target.tcertHash;
    }
  }
  if (object.type === 'attachment') {
    const data = object.data ?? {};
    out.id = data.id;
    out.contentType = data.contentType;
    out.contentHash = data.contentHash;
    out.signedAt = data.issuedAt;
    if (data.content instanceof Uint8Array) out.contentB64 = toBase64Url(data.content);
    // Defense-in-depth: recompute the content hash with the TCert's declared
    // hash algorithm so a mis-labelled algorithm is rejected on the server too.
    if (data.content instanceof Uint8Array) {
      const alg = tcert.data.hashAlgorithm ?? 'SHA-256';
      const recomputed = toHex(hashFor(alg, data.content)).toLowerCase();
      if (recomputed !== String(data.contentHash ?? '').toLowerCase()) {
        out.ok = false;
        out.error = 'attachment content hash does not match its declared algorithm';
      }
    }
  }
  console.log(JSON.stringify(out));
} catch (error) {
  console.log(JSON.stringify({ ok: false, error: error instanceof Error ? error.message : String(error) }));
}
