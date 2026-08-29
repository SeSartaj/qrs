import { describe, expect, it } from 'vitest';
import { assertPrivateJwk, assertPublicJwk, canonicalPublicKeyBytes } from '../src/crypto/jwk.js';
import { QrsValidationError } from '../src/errors.js';

describe('JWK helpers', () => {
  it('accepts valid public keys and rejects malformed ones', () => {
    expect(() => assertPublicJwk({ kty: 'OKP', crv: 'Ed25519', x: 'x'.repeat(43) })).not.toThrow();
    expect(() => assertPublicJwk({ kty: 'EC', crv: 'P-256', x: 'x', y: 'y' })).not.toThrow();
    expect(() => assertPublicJwk({ kty: 'RSA', crv: 'x', x: 'x' })).toThrow(QrsValidationError);
    expect(() => assertPublicJwk({ kty: 'OKP' })).toThrow(QrsValidationError);
    expect(() => assertPublicJwk(null)).toThrow(QrsValidationError);
  });

  it('only accepts private keys that carry the secret (d)', () => {
    expect(() => assertPrivateJwk({ kty: 'OKP', crv: 'Ed25519', x: 'x', d: 'd' })).not.toThrow();
    expect(() => assertPrivateJwk({ kty: 'OKP', crv: 'Ed25519', x: 'x' })).toThrow(QrsValidationError);
  });

  it('produces deterministic canonical public key bytes', () => {
    const a = canonicalPublicKeyBytes({ kty: 'OKP', crv: 'Ed25519', x: 'abc' });
    const b = canonicalPublicKeyBytes({ crv: 'Ed25519', x: 'abc', kty: 'OKP' });
    expect(a).toEqual(b);
    const ecA = canonicalPublicKeyBytes({ kty: 'EC', crv: 'P-256', x: 'x', y: 'y' });
    const ecB = canonicalPublicKeyBytes({ y: 'y', x: 'x', crv: 'P-256', kty: 'EC' });
    expect(ecA).toEqual(ecB);
    expect(ecA).not.toEqual(a);
  });
});
