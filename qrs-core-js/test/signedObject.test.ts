import { describe, expect, it } from 'vitest';
import { cborEncode, type CborValue } from '../src/cbor/canonical.js';
import { signCoseSign1 } from '../src/cose/cose.js';
import { Ed25519Provider } from '../src/crypto/ed25519.js';
import type { ICryptoProvider } from '../src/crypto/providers.js';
import { QrsParseError, QrsUnsupportedError } from '../src/errors.js';
import {
  buildSignedObject,
  parseSignedObject,
  sdocIdOf,
  splitTcertId,
  tcertNumberOf,
  tcertIdOf,
  verifyParsedSignedObject,
} from '../src/signedObject/signedObject.js';

const provider = new Ed25519Provider();
const keyPair = await provider.generateKeyPair();
const keyId = provider.keyId(keyPair.publicJwk);

function tcertData(): Record<string, unknown> {
  return {
    keyId: new Uint8Array([1, 2, 3]),
    certificateNumber: 1,
    algorithm: 'Ed25519',
    publicKey: keyPair.publicJwk,
    identity: { name: 'AFDA', document: 'Pharmacy License' },
    schema: [],
  };
}

describe('SignedObject', () => {
  it('builds and parses a TCert and verifies its signature', async () => {
    const bytes = await buildSignedObject('tcert', tcertData(), keyPair, provider);
    const parsed = parseSignedObject(bytes);
    expect(parsed.type).toBe('tcert');
    expect(parsed.version).toBe(1);
    expect(parsed.algorithm).toBe('Ed25519');
    expect(parsed.signerKeyId).toBe(keyId);
    expect(await verifyParsedSignedObject(parsed, provider, keyPair.publicJwk)).toBe(true);
  });

  it('rejects a tampered signature', async () => {
    const bytes = await buildSignedObject('tcert', tcertData(), keyPair, provider);
    const parsed = parseSignedObject(bytes);
    parsed.signature[0] = (parsed.signature[0] ?? 0) ^ 0xff;
    expect(await verifyParsedSignedObject(parsed, provider, keyPair.publicJwk)).toBe(false);
  });

  it('rejects an unsupported protocol version', async () => {
    const payload = cborEncode([2, 'tcert', cborEncode(tcertData() as unknown as CborValue)]);
    const { bytes } = await signCoseSign1(payload, keyId, keyPair, provider);
    expect(() => parseSignedObject(bytes)).toThrow(QrsUnsupportedError);
  });

  it('rejects an unknown object type', async () => {
    const payload = cborEncode([1, 'bogus', cborEncode({})]);
    const { bytes } = await signCoseSign1(payload, keyId, keyPair, provider);
    expect(() => parseSignedObject(bytes)).toThrow(QrsUnsupportedError);
  });

  it('rejects an unknown algorithm identifier', async () => {
    // A provider that behaves like Ed25519 but reports an unknown COSE algorithm id.
    const fakeProvider: ICryptoProvider = {
      algorithm: 'Ed25519',
      coseAlgorithmId: 99,
      generateKeyPair: provider.generateKeyPair.bind(provider),
      derivePublic: provider.derivePublic.bind(provider),
      sign: provider.sign.bind(provider),
      verify: provider.verify.bind(provider),
      canonicalPublicKey: provider.canonicalPublicKey.bind(provider),
      keyId: provider.keyId.bind(provider),
    };
    const payload = cborEncode([1, 'tcert', cborEncode(tcertData() as unknown as CborValue)]);
    const { bytes } = await signCoseSign1(payload, keyId, keyPair, fakeProvider);
    expect(() => parseSignedObject(bytes)).toThrow(QrsUnsupportedError);
  });

  it('rejects object data that violates its static schema', async () => {
    const bad = { ...tcertData(), certificateNumber: 'not-a-number' };
    const bytes = await buildSignedObject('tcert', bad as unknown as Record<string, unknown>, keyPair, provider);
    expect(() => parseSignedObject(bytes)).toThrow(QrsParseError);
  });

  it('sdocId is deterministic and content-derived', async () => {
    const a = await buildSignedObject('sdoc', { issuedAt: 100, fields: [1] }, keyPair, provider, new Uint8Array(0), 1);
    const b = await buildSignedObject('sdoc', { issuedAt: 100, fields: [1] }, keyPair, provider, new Uint8Array(0), 1);
    const c = await buildSignedObject('sdoc', { issuedAt: 100, fields: [2] }, keyPair, provider, new Uint8Array(0), 1);
    expect(sdocIdOf(a)).toBe(sdocIdOf(b));
    expect(sdocIdOf(a)).not.toBe(sdocIdOf(c));
    expect(sdocIdOf(a)).toMatch(/^[0-9a-f]{32}$/);
    expect(tcertNumberOf(parseSignedObject(a))).toBe(1);
  });

  it('tcertId and splitTcertId round-trip', () => {
    const id = tcertIdOf('ab'.repeat(16), 3);
    expect(splitTcertId(id)).toEqual({ keyId: 'ab'.repeat(16), certificateNumber: 3 });
    expect(() => splitTcertId('malformed')).toThrow(QrsParseError);
  });
});
