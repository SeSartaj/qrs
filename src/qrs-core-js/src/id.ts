/**
 * Identifier and encoding helpers.
 *
 * All protocol identifiers are 128-bit truncated SHA-256 digests. This module is
 * deliberately platform-agnostic (no Node imports, no Buffer) and delegates every
 * cryptographic operation to audited, well-maintained libraries rather than
 * hand-rolled code:
 *   - SHA-256: `@noble/hashes` (audited, dependency-free, works in Node, browsers
 *     and React Native);
 *   - hex / base64url: `@noble/hashes/utils` and `@scure/base`;
 *   - random bytes: `globalThis.crypto.getRandomValues` (available in Node >= 20,
 *     browsers, and React Native when a polyfill such as
 *     `react-native-get-random-values` is installed).
 */
import { sha256 as nobleSha256, sha384 as nobleSha384 } from '@noble/hashes/sha2.js';
import { sha3_512 as nobleSha3_512 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { base64urlnopad } from '@scure/base';
import { QrsError, QrsParseError } from './errors.js';

/** Number of identifier bytes used for all truncated identifiers. */
export const ID_BYTES = 16;

/** Full SHA-256 digest of arbitrary bytes (synchronous, portable). */
export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

/** Hash algorithms supported for TCert-bound content hashing (attachments). */
export type HashAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA3-512';

export const HASH_ALGORITHMS: readonly HashAlgorithm[] = ['SHA-256', 'SHA-384', 'SHA3-512'];

export function isHashAlgorithm(value: unknown): value is HashAlgorithm {
  return HASH_ALGORITHMS.includes(value as HashAlgorithm);
}

/** Full SHA-384 digest of arbitrary bytes. */
export function sha384(data: Uint8Array): Uint8Array {
  return nobleSha384(data);
}

/** Full SHA3-512 digest of arbitrary bytes. */
export function sha3_512(data: Uint8Array): Uint8Array {
  return nobleSha3_512(data);
}

/** Hash arbitrary bytes with the given algorithm (defaults to SHA-256). */
export function hashFor(alg: HashAlgorithm | undefined, data: Uint8Array): Uint8Array {
  switch (alg ?? 'SHA-256') {
    case 'SHA-384':
      return sha384(data);
    case 'SHA3-512':
      return sha3_512(data);
    default:
      return sha256(data);
  }
}

/** Truncated SHA-256 digest (defaults to the 128-bit protocol identifier). */
export function truncSha256(data: Uint8Array, bytes = ID_BYTES): Uint8Array {
  const full = sha256(data);
  return full.slice(0, Math.min(bytes, full.length));
}

/** Constant-time string equality (used for bound-value comparisons). */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/* -------------------------------------------------------------------------- */
/* Encoding helpers (no Buffer dependency)                                    */
/* -------------------------------------------------------------------------- */

export function toHex(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}

export function fromHex(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    throw new QrsParseError('Invalid hex string');
  }
  return hexToBytes(hex);
}

export function toBase64Url(bytes: Uint8Array): string {
  return base64urlnopad.encode(bytes);
}

export function fromBase64Url(value: string): Uint8Array {
  // Tolerate standard base64 characters and optional padding, then delegate.
  const normalized = value.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  try {
    return base64urlnopad.decode(normalized);
  } catch {
    throw new QrsParseError('Invalid base64url string');
  }
}

/* -------------------------------------------------------------------------- */
/* Secure random                                                              */
/* -------------------------------------------------------------------------- */

/** Generate `length` cryptographically secure random bytes (portable). */
export function randomBytes(length: number): Uint8Array {
  const cryptoObj = (globalThis as { crypto?: { getRandomValues?: (a: Uint8Array) => Uint8Array } }).crypto;
  if (!cryptoObj || typeof cryptoObj.getRandomValues !== 'function') {
    throw new QrsError('No secure random source available (globalThis.crypto.getRandomValues missing)');
  }
  const out = new Uint8Array(length);
  cryptoObj.getRandomValues(out);
  return out;
}

/** Generate a random hex identifier (defaults to 16 bytes). */
export function randomId(bytes = ID_BYTES): string {
  return toHex(randomBytes(bytes));
}

/** Hex encode a big-endian uint8. */
export function uint8ToBigInt(bytes: Uint8Array): bigint {
  let out = 0n;
  for (const b of bytes) out = (out << 8n) | BigInt(b);
  return out;
}

