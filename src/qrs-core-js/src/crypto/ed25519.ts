/**
 * Ed25519 provider (RFC 8032). 32-byte public keys, 64-byte signatures.
 * Uses Node's native crypto; no external dependencies.
 */
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { canonicalPublicKeyBytes, type PrivateJwk, type PublicJwk } from './jwk.js';
import { computeKeyId, type GeneratedKeyPair, type ICryptoProvider } from './providers.js';
import type { AlgorithmId } from '../types.js';

export class Ed25519Provider implements ICryptoProvider {
  readonly algorithm = 'Ed25519' as const satisfies AlgorithmId;
  readonly coseAlgorithmId = -8; // EdDSA

  async generateKeyPair(): Promise<GeneratedKeyPair> {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const publicJwk = publicKey.export({ format: 'jwk' }) as unknown as PublicJwk;
    const privateJwk = privateKey.export({ format: 'jwk' }) as unknown as PrivateJwk;
    return { algorithm: this.algorithm, publicJwk, privateJwk };
  }

  async derivePublic(privateJwk: PrivateJwk): Promise<PublicJwk> {
    const exported = createPrivateKey({ key: privateJwk, format: 'jwk' }).export({ format: 'jwk' }) as Record<
      string,
      unknown
    >;
    const { d: _d, ...rest } = exported;
    return rest as unknown as PublicJwk;
  }

  async sign(data: Uint8Array, privateJwk: PrivateJwk): Promise<Uint8Array> {
    const key = createPrivateKey({ key: privateJwk, format: 'jwk' });
    return new Uint8Array(sign(null, data, key));
  }

  async verify(data: Uint8Array, signature: Uint8Array, publicJwk: PublicJwk): Promise<boolean> {
    try {
      const key = createPublicKey({ key: publicJwk, format: 'jwk' });
      return verify(null, data, key, signature);
    } catch {
      return false;
    }
  }

  canonicalPublicKey(publicJwk: PublicJwk): Uint8Array {
    return canonicalPublicKeyBytes(publicJwk);
  }

  keyId(publicJwk: PublicJwk): string {
    return computeKeyId(this, publicJwk);
  }
}
