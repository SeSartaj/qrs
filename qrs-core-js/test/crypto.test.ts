import { describe, expect, it } from 'vitest';
import { EcdsaP256Provider } from '../src/crypto/ecdsaP256.js';
import { Ed25519Provider } from '../src/crypto/ed25519.js';
import { createDefaultCryptoRegistry } from '../src/crypto/nodeRegistry.js';
import { CryptoRegistry } from '../src/crypto/registry.js';
import { QrsUnsupportedError } from '../src/errors.js';

describe('Ed25519 provider', () => {
  const provider = new Ed25519Provider();

  it('generates a key pair and a deterministic 128-bit keyId', async () => {
    const pair = await provider.generateKeyPair();
    expect(pair.publicJwk.crv).toBe('Ed25519');
    expect(pair.publicJwk.x).toBeTruthy();
    expect(provider.keyId(pair.publicJwk)).toMatch(/^[0-9a-f]{32}$/);
    expect(provider.keyId(pair.publicJwk)).toBe(provider.keyId(pair.publicJwk));
  });

  it('produces distinct keyIds for distinct keys', async () => {
    const a = await provider.generateKeyPair();
    const b = await provider.generateKeyPair();
    expect(provider.keyId(a.publicJwk)).not.toBe(provider.keyId(b.publicJwk));
  });

  it('signs and verifies with 64-byte signatures', async () => {
    const pair = await provider.generateKeyPair();
    const data = new TextEncoder().encode('hello world');
    const signature = await provider.sign(data, pair.privateJwk);
    expect(signature.length).toBe(64);
    expect(await provider.verify(data, signature, pair.publicJwk)).toBe(true);
    expect(await provider.verify(data, new Uint8Array(64).fill(1), pair.publicJwk)).toBe(false);
    expect(await provider.verify(new TextEncoder().encode('tampered'), signature, pair.publicJwk)).toBe(false);
  });

  it('derives the public key from the private key', async () => {
    const pair = await provider.generateKeyPair();
    const derived = await provider.derivePublic(pair.privateJwk);
    expect(derived.x).toBe(pair.publicJwk.x);
    expect(provider.keyId(derived)).toBe(provider.keyId(pair.publicJwk));
  });
});

describe('ECDSA P-256 provider', () => {
  const provider = new EcdsaP256Provider();

  it('generates a key pair and a deterministic keyId', async () => {
    const pair = await provider.generateKeyPair();
    expect(pair.publicJwk.crv).toBe('P-256');
    expect(pair.publicJwk.y).toBeTruthy();
    expect(provider.keyId(pair.publicJwk)).toMatch(/^[0-9a-f]{32}$/);
    expect(provider.keyId(pair.publicJwk)).toBe(provider.keyId(pair.publicJwk));
  });

  it('signs and verifies with 64-byte (r||s) signatures', async () => {
    const pair = await provider.generateKeyPair();
    const data = new TextEncoder().encode('hello world');
    const signature = await provider.sign(data, pair.privateJwk);
    expect(signature.length).toBe(64);
    expect(await provider.verify(data, signature, pair.publicJwk)).toBe(true);
    expect(await provider.verify(data, new Uint8Array(64).fill(1), pair.publicJwk)).toBe(false);
  });

  it('derives the public key from the private key', async () => {
    const pair = await provider.generateKeyPair();
    const derived = await provider.derivePublic(pair.privateJwk);
    expect(derived.x).toBe(pair.publicJwk.x);
    expect(derived.y).toBe(pair.publicJwk.y);
  });
});

describe('CryptoRegistry', () => {
  it('returns the registered providers and rejects unknown algorithms', () => {
    const registry = createDefaultCryptoRegistry();
    expect(registry.has('Ed25519')).toBe(true);
    expect(registry.has('ECDSA-P256')).toBe(true);
    expect(registry.get('Ed25519').coseAlgorithmId).toBe(-8);
    expect(registry.get('ECDSA-P256').coseAlgorithmId).toBe(-7);
    expect(() => registry.get('RSA' as never)).toThrow(QrsUnsupportedError);
  });

  it('allows registering additional providers (open/closed)', () => {
    const registry = new CryptoRegistry();
    registry.register(new Ed25519Provider());
    expect(registry.list().map((p) => p.algorithm)).toEqual(['Ed25519']);
  });
});
