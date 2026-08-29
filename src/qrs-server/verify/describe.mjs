#!/usr/bin/env node
/**
 * Describes + self-verifies a TCert so the Python side never parses CBOR itself.
 *
 * The TCert (base64url) is passed on stdin as JSON `{"tcert": "..."}` (argv is
 * too small for real TCerts). Legacy argv usage `node describe.mjs <tcertB64>`
 * is still accepted.
 * Prints { ok, type, keyId, certificateNumber, algorithm, name,
 *          onlineEndpoint, hashAlgorithm, schema, publicKey, error? }
 */
import { createDefaultCryptoRegistry, fromBase64Url, parseSignedObject, tcertHashOf, toHex, verifyParsedSignedObject } from 'qrs-core';

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

async function readTcertB64() {
  const args = process.argv.slice(2);
  if (args.length >= 1) return args[0];
  const raw = await readStdin();
  try {
    const parsed = JSON.parse(raw);
    return parsed.tcert ?? raw;
  } catch {
    return raw;
  }
}

const tcertB64 = await readTcertB64();
try {
  if (!tcertB64) throw new Error('missing TCert');
  const tcert = parseSignedObject(fromBase64Url(tcertB64));
  if (tcert.type !== 'tcert') throw new Error('not a TCert');
  const registry = createDefaultCryptoRegistry();
  const provider = registry.get(tcert.algorithm);
  const data = tcert.data;
  const ok = await verifyParsedSignedObject(tcert, provider, data.publicKey);
  console.log(
    JSON.stringify({
      ok,
      type: tcert.type,
      algorithm: data.algorithm,
      keyId: tcert.signerKeyId,
      certificateNumber: data.certificateNumber,
      tcertHash: tcertHashOf(tcert),
      name: data.identity?.name,
      onlineEndpoint: data.onlineEndpoint ?? '',
      hashAlgorithm: data.hashAlgorithm ?? 'SHA-256',
      schema: data.schema ?? [],
      publicKey: data.publicKey,
      error: undefined,
    })
  );
} catch (error) {
  console.log(JSON.stringify({ ok: false, error: error instanceof Error ? error.message : String(error) }));
}
