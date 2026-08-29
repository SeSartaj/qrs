import { describe, expect, it } from 'vitest';
import { cborEncode } from '../src/cbor/canonical.js';
import {
  assertSupportedAlgorithm,
  decodeCoseSign1,
  signCoseSign1,
  verifyCoseSign1,
} from '../src/cose/cose.js';
import { Ed25519Provider } from '../src/crypto/ed25519.js';
import { QrsParseError, QrsUnsupportedError } from '../src/errors.js';

const provider = new Ed25519Provider();
const keyPair = await provider.generateKeyPair();
const keyId = provider.keyId(keyPair.publicJwk);

describe('COSE_Sign1', () => {
  it('signs and verifies with an empty external AAD', async () => {
    const payload = new TextEncoder().encode('payload');
    const { bytes } = await signCoseSign1(payload, keyId, keyPair, provider);
    const decoded = decodeCoseSign1(bytes);
    expect(decoded.payload).toEqual(payload);
    expect(decoded.protectedHeaders.alg).toBe(-8);
    expect(await verifyCoseSign1(decoded, provider, keyPair.publicJwk)).toBe(true);
  });

  it('requires the exact external AAD at verification time', async () => {
    const payload = new TextEncoder().encode('p');
    const aad = new TextEncoder().encode('the-secret');
    const { bytes } = await signCoseSign1(payload, keyId, keyPair, provider, aad);
    const decoded = decodeCoseSign1(bytes);
    expect(await verifyCoseSign1(decoded, provider, keyPair.publicJwk, aad)).toBe(true);
    expect(await verifyCoseSign1(decoded, provider, keyPair.publicJwk, new TextEncoder().encode('wrong'))).toBe(false);
  });

  it('fails verification when the payload is tampered with', async () => {
    const payload = new TextEncoder().encode('payload');
    const { bytes } = await signCoseSign1(payload, keyId, keyPair, provider);
    const decoded = decodeCoseSign1(bytes);
    decoded.payload[0] = (decoded.payload[0] ?? 0) ^ 0xff;
    expect(await verifyCoseSign1(decoded, provider, keyPair.publicJwk)).toBe(false);
  });

  it('fails verification with the wrong public key', async () => {
    const other = await provider.generateKeyPair();
    const payload = new TextEncoder().encode('payload');
    const { bytes } = await signCoseSign1(payload, keyId, keyPair, provider);
    const decoded = decodeCoseSign1(bytes);
    expect(await verifyCoseSign1(decoded, provider, other.publicJwk)).toBe(false);
  });

  it('rejects malformed messages', () => {
    expect(() => decodeCoseSign1(new Uint8Array([0x80]))).toThrow(QrsParseError);
    expect(() => decodeCoseSign1(new Uint8Array([0x84, 0x40, 0x40, 0x40]))).toThrow(QrsParseError); // 4 items, missing sig
    expect(() => decodeCoseSign1(new Uint8Array([0x83, 0x40, 0x40, 0x40]))).toThrow(QrsParseError); // 3 items
  });

  it('rejects protected headers that are not a map', () => {
    const protectedNotMap = cborEncode(42);
    const msg = cborEncode([protectedNotMap, cborEncode(new Map()), new Uint8Array([1]), new Uint8Array(64)]);
    expect(() => decodeCoseSign1(msg)).toThrow(QrsParseError);
  });

  it('rejects protected headers without an algorithm or key id', () => {
    const protectedEmpty = cborEncode(new Map());
    const msg = cborEncode([protectedEmpty, cborEncode(new Map()), new Uint8Array([1]), new Uint8Array(64)]);
    expect(() => decodeCoseSign1(msg)).toThrow(QrsParseError);
  });

  it('rejects unknown algorithm identifiers', () => {
    expect(() => assertSupportedAlgorithm(99)).toThrow(QrsUnsupportedError);
    expect(() => assertSupportedAlgorithm(-8)).not.toThrow();
    expect(() => assertSupportedAlgorithm(-7)).not.toThrow();
  });
});
