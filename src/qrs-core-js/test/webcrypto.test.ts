import { describe, expect, it } from 'vitest';
import { EcdsaP256Provider } from '../src/crypto/ecdsaP256.js';
import { Ed25519Provider } from '../src/crypto/ed25519.js';
import { createWebCryptoCryptoRegistry, WebCryptoEcdsaP256Provider, WebCryptoEd25519Provider } from '../src/crypto/webcrypto.js';

const data = new TextEncoder().encode('cross-provider test');

describe('WebCrypto Ed25519 provider', () => {
  const provider = new WebCryptoEd25519Provider();

  it('generates keys, signs and verifies with 64-byte signatures', async () => {
    const pair = await provider.generateKeyPair();
    expect(pair.publicJwk.crv).toBe('Ed25519');
    expect(pair.privateJwk.d).toBeTruthy();
    expect(provider.keyId(pair.publicJwk)).toMatch(/^[0-9a-f]{32}$/);

    const signature = await provider.sign(data, pair.privateJwk);
    expect(signature.length).toBe(64);
    expect(await provider.verify(data, signature, pair.publicJwk)).toBe(true);
    expect(await provider.verify(data, new Uint8Array(64).fill(1), pair.publicJwk)).toBe(false);
  });

  it('derives the public key from the private key', async () => {
    const pair = await provider.generateKeyPair();
    const derived = await provider.derivePublic(pair.privateJwk);
    expect(derived.x).toBe(pair.publicJwk.x);
    expect(provider.keyId(derived)).toBe(provider.keyId(pair.publicJwk));
  });

  it('is interoperable with the Node provider', async () => {
    const nodeProvider = new Ed25519Provider();
    const nodePair = await nodeProvider.generateKeyPair();

    // Node signs, WebCrypto verifies.
    const nodeSig = await nodeProvider.sign(data, nodePair.privateJwk);
    expect(await provider.verify(data, nodeSig, nodePair.publicJwk)).toBe(true);

    // WebCrypto signs, Node verifies.
    const webSig = await provider.sign(data, nodePair.privateJwk);
    expect(await nodeProvider.verify(data, webSig, nodePair.publicJwk)).toBe(true);

    // key_id derivation is identical across providers.
    expect(provider.keyId(nodePair.publicJwk)).toBe(nodeProvider.keyId(nodePair.publicJwk));
  });
});

describe('WebCrypto ECDSA P-256 provider', () => {
  const provider = new WebCryptoEcdsaP256Provider();

  it('generates keys, signs and verifies with 64-byte raw signatures', async () => {
    const pair = await provider.generateKeyPair();
    expect(pair.publicJwk.crv).toBe('P-256');
    const signature = await provider.sign(data, pair.privateJwk);
    expect(signature.length).toBe(64);
    expect(await provider.verify(data, signature, pair.publicJwk)).toBe(true);
  });

  it('is interoperable with the Node provider', async () => {
    const nodeProvider = new EcdsaP256Provider();
    const nodePair = await nodeProvider.generateKeyPair();

    const nodeSig = await nodeProvider.sign(data, nodePair.privateJwk);
    expect(await provider.verify(data, nodeSig, nodePair.publicJwk)).toBe(true);

    const webSig = await provider.sign(data, nodePair.privateJwk);
    expect(await nodeProvider.verify(data, webSig, nodePair.publicJwk)).toBe(true);

    expect(provider.keyId(nodePair.publicJwk)).toBe(nodeProvider.keyId(nodePair.publicJwk));
  });
});

describe('createWebCryptoCryptoRegistry', () => {
  it('registers both algorithms', () => {
    const registry = createWebCryptoCryptoRegistry();
    expect(registry.has('Ed25519')).toBe(true);
    expect(registry.has('ECDSA-P256')).toBe(true);
    expect(registry.get('Ed25519').coseAlgorithmId).toBe(-8);
    expect(registry.get('ECDSA-P256').coseAlgorithmId).toBe(-7);
  });
});

describe('WebCrypto availability', () => {
  it('falls back to pure-JS Ed25519 (verify + sign) when crypto.subtle lacks Ed25519', async () => {
    const provider = new WebCryptoEd25519Provider();
    // Produce a signature using the real environment first.
    const pair = await provider.generateKeyPair();
    const signature = await provider.sign(data, pair.privateJwk);

    // Simulate Firefox/Safari: crypto.getRandomValues exists but crypto.subtle
    // does not implement Ed25519. Remove only subtle, keep the random source.
    const subtleDescriptor = Object.getOwnPropertyDescriptor(crypto, 'subtle');
    try {
      Object.defineProperty(crypto, 'subtle', { value: undefined, configurable: true });
      // Verification must still work (falls back to @noble/curves Ed25519).
      expect(await provider.verify(data, signature, pair.publicJwk)).toBe(true);
      expect(await provider.verify(data, new Uint8Array(64).fill(1), pair.publicJwk)).toBe(false);
      // Signing also falls back (getRandomValues is still available for noble).
      const fallbackSig = await provider.sign(data, pair.privateJwk);
      expect(fallbackSig.length).toBe(64);
      expect(await provider.verify(data, fallbackSig, pair.publicJwk)).toBe(true);
    } finally {
      if (subtleDescriptor) Object.defineProperty(crypto, 'subtle', subtleDescriptor);
    }
  });

  it('falls back to pure-JS ECDSA P-256 (verify + sign) when crypto.subtle is missing', async () => {
    const provider = new WebCryptoEcdsaP256Provider();
    // Produce a signature using the real environment first.
    const pair = await provider.generateKeyPair();
    const signature = await provider.sign(data, pair.privateJwk);
    expect(signature.length).toBe(64);

    // Simulate an environment with NO crypto.subtle at all (e.g. a webview that
    // only provides crypto.getRandomValues). Remove subtle, keep the random source.
    const subtleDescriptor = Object.getOwnPropertyDescriptor(crypto, 'subtle');
    try {
      Object.defineProperty(crypto, 'subtle', { value: undefined, configurable: true });
      // Verification must still work (falls back to @noble/curves P-256).
      expect(await provider.verify(data, signature, pair.publicJwk)).toBe(true);
      expect(await provider.verify(data, new Uint8Array(64).fill(1), pair.publicJwk)).toBe(false);
      // Signing also falls back (raw r||s, 64 bytes).
      const fallbackSig = await provider.sign(data, pair.privateJwk);
      expect(fallbackSig.length).toBe(64);
      expect(await provider.verify(data, fallbackSig, pair.publicJwk)).toBe(true);

      // Interop with the Node provider under the fallback path: Node signs,
      // WebCrypto (fallback) verifies.
      const nodeProvider = new EcdsaP256Provider();
      const nodeSig = await nodeProvider.sign(data, pair.privateJwk);
      expect(await provider.verify(data, nodeSig, pair.publicJwk)).toBe(true);
    } finally {
      if (subtleDescriptor) Object.defineProperty(crypto, 'subtle', subtleDescriptor);
    }
  });

  it('fallback accepts high-S (non-canonical) Node ECDSA signatures', async () => {
    // Node's node:crypto (OpenSSL) emits high-S signatures ~50% of the time.
    // noble's p256.verify defaults to lowS:true and would reject them, so the
    // fallback must verify with { lowS: false } — same as WebCrypto/OpenSSL.
    const provider = new WebCryptoEcdsaP256Provider();
    const nodeProvider = new EcdsaP256Provider();
    const nodePair = await nodeProvider.generateKeyPair();
    const msg = new TextEncoder().encode('high-S interop');

    // Build a deterministic valid high-S signature: take a low-S signature and
    // replace s with n - s (the complementary, equally-valid half-order value).
    const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const sig = await nodeProvider.sign(msg, nodePair.privateJwk);
    const r = sig.slice(0, 32);
    const sInt = BigInt(`0x${Buffer.from(sig.slice(32)).toString('hex')}`);
    const flipped = (P256_N - sInt) % P256_N;
    const newS = new Uint8Array(32);
    let v = flipped;
    for (let i = 31; i >= 0; i--) {
      newS[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    const highSig = new Uint8Array(64);
    highSig.set(r, 0);
    highSig.set(newS, 32);

    // Sanity: with WebCrypto (spec-compliant) the high-S signature verifies.
    expect(await provider.verify(msg, highSig, nodePair.publicJwk)).toBe(true);

    // Under the pure-JS fallback (no crypto.subtle) it must verify too.
    const subtleDescriptor = Object.getOwnPropertyDescriptor(crypto, 'subtle');
    try {
      Object.defineProperty(crypto, 'subtle', { value: undefined, configurable: true });
      expect(await provider.verify(msg, highSig, nodePair.publicJwk)).toBe(true);
    } finally {
      if (subtleDescriptor) Object.defineProperty(crypto, 'subtle', subtleDescriptor);
    }
  });

  it('reports a clear error when no secure random source exists for key generation', async () => {
    const provider = new WebCryptoEd25519Provider();
    const original = globalThis.crypto;
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    try {
      // @ts-expect-error - temporarily remove the global for this assertion
      delete globalThis.crypto;
      // Generating a NEW key needs randomness (crypto.getRandomValues); without it
      // the fallback surfaces the underlying error instead of silently failing.
      await expect(provider.generateKeyPair()).rejects.toThrow();
    } finally {
      if (descriptor) Object.defineProperty(globalThis, 'crypto', descriptor);
      else (globalThis as Record<string, unknown>).crypto = original;
    }
  });
});
