/**
 * ECDSA P-256 (ES256) provider. 64-byte signatures (raw r||s via IEEE P1363),
 * 65-byte uncompressed public keys. Uses Node's native crypto.
 */
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from 'node:crypto';
import { canonicalPublicKeyBytes, type PrivateJwk, type PublicJwk } from './jwk.js';
import { computeKeyId, type GeneratedKeyPair, type ICryptoProvider } from './providers.js';
import type { AlgorithmId } from '../types.js';

export class EcdsaP256Provider implements ICryptoProvider {
  readonly algorithm = 'ECDSA-P256' as const satisfies AlgorithmId;
  readonly coseAlgorithmId = -7; // ES256

  async generateKeyPair(): Promise<GeneratedKeyPair> {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
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
    return new Uint8Array(sign('sha256', data, { key, dsaEncoding: 'ieee-p1363' }));
  }

  async verify(data: Uint8Array, signature: Uint8Array, publicJwk: PublicJwk): Promise<boolean> {
    try {
      const key = createPublicKey({ key: publicJwk, format: 'jwk' });
      return verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, signature);
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
