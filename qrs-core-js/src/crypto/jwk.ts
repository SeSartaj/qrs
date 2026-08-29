/**
 * JSON Web Key (JWK) helpers.
 *
 * Keys are represented as JWK objects (the native format Node's crypto can import
 * and export), and the *canonical public key bytes* used for `key_id` derivation is
 * the canonical CBOR encoding of the public JWK with sorted keys. This keeps the
 * public key representation deterministic and language-neutral.
 */
import { cborEncode } from '../cbor/canonical.js';
import { QrsValidationError } from '../errors.js';

export interface PublicJwk {
  kty: 'OKP' | 'EC';
  crv: string;
  x: string;
  y?: string;
  /** Allows assignability to Node's JsonWebKey and JWK round-tripping. */
  [key: string]: unknown;
}

export interface PrivateJwk extends PublicJwk {
  d: string;
}

export interface KeyPairMaterial {
  publicJwk: PublicJwk;
  privateJwk: PrivateJwk;
}

/** Deterministic canonical bytes of a public key (used for `key_id` derivation). */
export function canonicalPublicKeyBytes(jwk: PublicJwk): Uint8Array {
  const sorted: { [key: string]: string } = { kty: jwk.kty, crv: jwk.crv, x: jwk.x };
  if (jwk.y !== undefined) sorted.y = jwk.y;
  return cborEncode(sorted);
}

export function assertPublicJwk(value: unknown): asserts value is PublicJwk {
  if (typeof value !== 'object' || value === null) throw new QrsValidationError('Expected a public JWK object');
  const v = value as Record<string, unknown>;
  if (v.kty !== 'OKP' && v.kty !== 'EC') throw new QrsValidationError('Unsupported JWK kty');
  if (typeof v.crv !== 'string' || typeof v.x !== 'string') {
    throw new QrsValidationError('JWK must contain crv and x');
  }
}

export function assertPrivateJwk(value: unknown): asserts value is PrivateJwk {
  assertPublicJwk(value);
  const v = value as unknown as Record<string, unknown>;
  if (typeof v.d !== 'string') throw new QrsValidationError('JWK must contain a private key (d)');
}
