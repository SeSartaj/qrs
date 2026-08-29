/**
 * The crypto-provider abstraction (SOLID: one algorithm, one provider; the registry
 * makes providers interchangeable, which is what enables cryptographic agility).
 */
import { truncSha256, toHex } from '../id.js';
import type { AlgorithmId, KeyId } from '../types.js';
import type { PublicJwk, PrivateJwk } from './jwk.js';

export interface GeneratedKeyPair {
  algorithm: AlgorithmId;
  publicJwk: PublicJwk;
  privateJwk: PrivateJwk;
}

export interface ICryptoProvider {
  /** Algorithm identifier used by the protocol. */
  readonly algorithm: AlgorithmId;
  /** COSE algorithm identifier (RFC 9053 registry), used in protected headers. */
  readonly coseAlgorithmId: number;

  generateKeyPair(): Promise<GeneratedKeyPair>;
  derivePublic(privateJwk: PrivateJwk): Promise<PublicJwk>;
  sign(data: Uint8Array, privateJwk: PrivateJwk): Promise<Uint8Array>;
  verify(data: Uint8Array, signature: Uint8Array, publicJwk: PublicJwk): Promise<boolean>;
  /** Deterministic canonical bytes of a public key. */
  canonicalPublicKey(publicJwk: PublicJwk): Uint8Array;
  /** Derive the protocol `key_id` for a public key. */
  keyId(publicJwk: PublicJwk): KeyId;
}

/** Standard implementation of `key_id` derivation shared by all providers. */
export function computeKeyId(provider: ICryptoProvider, publicJwk: PublicJwk): KeyId {
  return toHex(truncSha256(provider.canonicalPublicKey(publicJwk)));
}

/** Maps COSE algorithm identifiers to protocol algorithm identifiers. */
export const COSE_ALGORITHM_TO_ID: Readonly<Record<number, AlgorithmId>> = {
  [-8]: 'Ed25519', // EdDSA
  [-7]: 'ECDSA-P256', // ES256
};

export function algorithmFromCoseAlgorithm(alg: number): AlgorithmId | undefined {
  return COSE_ALGORITHM_TO_ID[alg];
}
