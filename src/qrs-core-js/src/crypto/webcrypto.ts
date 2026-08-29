/**
 * WebCrypto-based crypto providers.
 *
 * These implement the same {@link ICryptoProvider} interface as the Node providers
 * but use the standard `Web Crypto API` (`globalThis.crypto.subtle`), which is
 * available in browsers and (with a polyfill for random values) React Native. This
 * module imports nothing from Node (not even type-only), so it is safe to bundle
 * for the web.
 *
 * Both providers produce standard keys/signatures that are interchangeable with the
 * Node providers: Ed25519 (64-byte signatures) and ECDSA P-256 (64-byte raw r||s
 * signatures).
 *
 * ED25519 / ECDSA FALLBACK: `crypto.subtle` only implements Ed25519 in
 * Chromium-based browsers; Firefox, Safari and some WebCrypto polyfills throw
 * `NotSupportedError` for it (and some environments lack `crypto.subtle`
 * entirely, e.g. certain webviews / partial polyfills). To keep verification
 * working there, both the Ed25519 and the ECDSA P-256 providers transparently
 * fall back to the audited pure-JS implementations from `@noble/curves`
 * whenever the platform WebCrypto rejects an operation. Signatures/keys are
 * byte-for-byte compatible with Node's `node:crypto` and with the WebCrypto
 * path, so this changes nothing for platforms that do support it.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { QrsCryptoError } from '../errors.js';
import { fromBase64Url, toBase64Url } from '../id.js';
import { canonicalPublicKeyBytes, type PrivateJwk, type PublicJwk } from './jwk.js';
import { computeKeyId, type GeneratedKeyPair, type ICryptoProvider } from './providers.js';
import { CryptoRegistry } from './registry.js';
import type { AlgorithmId } from '../types.js';

/**
 * Minimal structural types for the parts of the Web Crypto API we use. Defined
 * locally so the module has no DOM-lib or `node:crypto` dependency.
 */
interface CryptoKeyLike {}
interface CryptoKeyPairLike {
  privateKey: CryptoKeyLike;
  publicKey: CryptoKeyLike;
}
interface SubtleCryptoLike {
  generateKey(algorithm: object, extractable: boolean, keyUsages: string[]): Promise<CryptoKeyPairLike>;
  importKey(
    format: string,
    keyData: object,
    algorithm: object,
    extractable: boolean,
    keyUsages: string[]
  ): Promise<CryptoKeyLike>;
  exportKey(format: string, key: CryptoKeyLike): Promise<object>;
  sign(algorithm: object, key: CryptoKeyLike, data: Uint8Array): Promise<ArrayBuffer>;
  verify(algorithm: object, key: CryptoKeyLike, signature: Uint8Array, data: Uint8Array): Promise<boolean>;
}

function getSubtle(): SubtleCryptoLike {
  const cryptoObj = (globalThis as { crypto?: { subtle?: SubtleCryptoLike } }).crypto;
  if (!cryptoObj || typeof cryptoObj.subtle === 'undefined') {
    throw new QrsCryptoError('WebCrypto (globalThis.crypto.subtle) is not available in this environment');
  }
  return cryptoObj.subtle;
}

function stripSecret(jwk: Record<string, unknown>): PublicJwk {
  const { d: _d, ...rest } = jwk;
  return rest as unknown as PublicJwk;
}

/* -------------------------------------------------------------------------- */
/* Ed25519 JWK <-> raw byte helpers (shared by the WebCrypto + noble paths)   */
/* -------------------------------------------------------------------------- */

/** 32-byte Ed25519 public key from its JWK `x`. */
function edPublicJwkToBytes(jwk: PublicJwk): Uint8Array {
  return fromBase64Url(String(jwk.x));
}

/** 32-byte Ed25519 private seed from its JWK `d`. */
function edPrivateJwkToBytes(jwk: PrivateJwk): Uint8Array {
  return fromBase64Url(String(jwk.d));
}

/** Public JWK from a 32-byte Ed25519 public key. */
function edPublicJwkFromBytes(x: Uint8Array): PublicJwk {
  return { kty: 'OKP', crv: 'Ed25519', x: toBase64Url(x) };
}

/** Private JWK from a 32-byte seed + 32-byte public key. */
function edPrivateJwkFromBytes(seed: Uint8Array, pub: Uint8Array): PrivateJwk {
  return { kty: 'OKP', crv: 'Ed25519', x: toBase64Url(pub), d: toBase64Url(seed) };
}

/* -------------------------------------------------------------------------- */
/* ECDSA P-256 JWK <-> raw byte helpers (shared by the WebCrypto + noble paths) */
/* -------------------------------------------------------------------------- */

/** 65-byte uncompressed P-256 public key (0x04 || x || y) from its JWK. */
function ecPublicJwkToUncompressed(jwk: PublicJwk): Uint8Array {
  const x = fromBase64Url(String(jwk.x));
  const y = fromBase64Url(String(jwk.y));
  const out = new Uint8Array(65);
  out[0] = 0x04;
  out.set(x, 1);
  out.set(y, 33);
  return out;
}

/** Public JWK from a 65-byte uncompressed P-256 public key. */
function ecPublicJwkFromUncompressed(raw: Uint8Array): PublicJwk {
  return {
    kty: 'EC',
    crv: 'P-256',
    x: toBase64Url(raw.slice(1, 33)),
    y: toBase64Url(raw.slice(33, 65)),
  };
}

/** 32-byte P-256 private scalar from its JWK `d`. */
function ecPrivateJwkToScalar(jwk: PrivateJwk): Uint8Array {
  return fromBase64Url(String(jwk.d));
}

/** Private JWK from a 32-byte scalar + 65-byte uncompressed public key. */
function ecPrivateJwkFromScalar(scalar: Uint8Array, pubRaw: Uint8Array): PrivateJwk {
  return { ...ecPublicJwkFromUncompressed(pubRaw), d: toBase64Url(scalar) };
}

export class WebCryptoEd25519Provider implements ICryptoProvider {
  readonly algorithm = 'Ed25519' as const satisfies AlgorithmId;
  readonly coseAlgorithmId = -8; // EdDSA

  async generateKeyPair(): Promise<GeneratedKeyPair> {
    try {
      const subtle = getSubtle();
      const pair = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
      const privateJwk = (await subtle.exportKey('jwk', pair.privateKey)) as unknown as PrivateJwk;
      const publicJwk = (await subtle.exportKey('jwk', pair.publicKey)) as unknown as PublicJwk;
      return { algorithm: this.algorithm, publicJwk, privateJwk };
    } catch {
      // Platform WebCrypto lacks Ed25519 → generate a random seed with noble.
      const seed = ed25519.utils.randomSecretKey();
      const pub = ed25519.getPublicKey(seed);
      return {
        algorithm: this.algorithm,
        publicJwk: edPublicJwkFromBytes(pub),
        privateJwk: edPrivateJwkFromBytes(seed, pub),
      };
    }
  }

  async derivePublic(privateJwk: PrivateJwk): Promise<PublicJwk> {
    try {
      const subtle = getSubtle();
      const key = await subtle.importKey('jwk', privateJwk as object, { name: 'Ed25519' }, true, ['sign']);
      const exported = (await subtle.exportKey('jwk', key)) as unknown as Record<string, unknown>;
      return stripSecret(exported);
    } catch {
      const seed = edPrivateJwkToBytes(privateJwk);
      return edPublicJwkFromBytes(ed25519.getPublicKey(seed));
    }
  }

  async sign(data: Uint8Array, privateJwk: PrivateJwk): Promise<Uint8Array> {
    try {
      const subtle = getSubtle();
      const key = await subtle.importKey('jwk', privateJwk as object, { name: 'Ed25519' }, false, ['sign']);
      return new Uint8Array(await subtle.sign({ name: 'Ed25519' }, key, data));
    } catch {
      return ed25519.sign(data, edPrivateJwkToBytes(privateJwk));
    }
  }

  async verify(data: Uint8Array, signature: Uint8Array, publicJwk: PublicJwk): Promise<boolean> {
    try {
      const subtle = getSubtle();
      const key = await subtle.importKey('jwk', publicJwk as object, { name: 'Ed25519' }, false, ['verify']);
      return await subtle.verify({ name: 'Ed25519' }, key, signature, data);
    } catch {
      try {
        return ed25519.verify(signature, data, edPublicJwkToBytes(publicJwk));
      } catch {
        return false;
      }
    }
  }

  canonicalPublicKey(publicJwk: PublicJwk): Uint8Array {
    return canonicalPublicKeyBytes(publicJwk);
  }

  keyId(publicJwk: PublicJwk): string {
    return computeKeyId(this, publicJwk);
  }
}

export class WebCryptoEcdsaP256Provider implements ICryptoProvider {
  readonly algorithm = 'ECDSA-P256' as const satisfies AlgorithmId;
  readonly coseAlgorithmId = -7; // ES256

  async generateKeyPair(): Promise<GeneratedKeyPair> {
    try {
      const subtle = getSubtle();
      const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      const privateJwk = (await subtle.exportKey('jwk', pair.privateKey)) as unknown as PrivateJwk;
      const publicJwk = (await subtle.exportKey('jwk', pair.publicKey)) as unknown as PublicJwk;
      return { algorithm: this.algorithm, publicJwk, privateJwk };
    } catch {
      // Platform WebCrypto lacks ECDSA → generate a random P-256 scalar with noble.
      const scalar = p256.utils.randomSecretKey();
      const pubRaw = p256.getPublicKey(scalar, false); // 65-byte uncompressed 0x04 || x || y
      return {
        algorithm: this.algorithm,
        publicJwk: ecPublicJwkFromUncompressed(pubRaw),
        privateJwk: ecPrivateJwkFromScalar(scalar, pubRaw),
      };
    }
  }

  async derivePublic(privateJwk: PrivateJwk): Promise<PublicJwk> {
    try {
      const subtle = getSubtle();
      const key = await subtle.importKey(
        'jwk',
        privateJwk as object,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign']
      );
      const exported = (await subtle.exportKey('jwk', key)) as unknown as Record<string, unknown>;
      return stripSecret(exported);
    } catch {
      const pubRaw = p256.getPublicKey(ecPrivateJwkToScalar(privateJwk), false);
      return ecPublicJwkFromUncompressed(pubRaw);
    }
  }

  async sign(data: Uint8Array, privateJwk: PrivateJwk): Promise<Uint8Array> {
    try {
      const subtle = getSubtle();
      const key = await subtle.importKey(
        'jwk',
        privateJwk as object,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign']
      );
      // WebCrypto returns the raw r||s signature (64 bytes for P-256).
      return new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, data));
    } catch {
      return p256.sign(data, ecPrivateJwkToScalar(privateJwk));
    }
  }

  async verify(data: Uint8Array, signature: Uint8Array, publicJwk: PublicJwk): Promise<boolean> {
    try {
      const subtle = getSubtle();
      const key = await subtle.importKey(
        'jwk',
        publicJwk as object,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify']
      );
      return subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature, data);
    } catch {
      try {
        // Raw r||s signature (64 bytes) + 65-byte uncompressed public key.
        // `lowS: false` matches OpenSSL/WebCrypto, which accept any valid
        // signature regardless of the S half-order — Node's node:crypto ECDSA
        // emits high-S signatures ~50% of the time and noble defaults to
        // rejecting them (lowS: true).
        return p256.verify(signature, data, ecPublicJwkToUncompressed(publicJwk), { lowS: false });
      } catch {
        return false;
      }
    }
  }

  canonicalPublicKey(publicJwk: PublicJwk): Uint8Array {
    return canonicalPublicKeyBytes(publicJwk);
  }

  keyId(publicJwk: PublicJwk): string {
    return computeKeyId(this, publicJwk);
  }
}

/** Registry with the WebCrypto-backed providers (browser / React Native). */
export function createWebCryptoCryptoRegistry(): CryptoRegistry {
  return new CryptoRegistry([new WebCryptoEd25519Provider(), new WebCryptoEcdsaP256Provider()]);
}

// Re-export the registry class so a single import surface covers both provider families.
export { CryptoRegistry };
