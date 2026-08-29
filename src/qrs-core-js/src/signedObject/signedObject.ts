/**
 * The SignedObject envelope.
 *
 * Every protocol object (TCert, SDoc, Statement) is a COSE_Sign1 message whose
 * signed payload is the canonical CBOR array:
 *
 *   [ protocolVersion, type, dataBytes ]
 *
 * where `dataBytes` is the canonical CBOR encoding of the type-specific data map.
 * The decoder reads version, then type, then dispatches to the type-specific parser.
 * It never guesses the meaning of a payload from its content.
 */
import { cborDecode, cborEncode, type CborValue } from '../cbor/canonical.js';
import { COSE_HDR_TCERT_NUMBER, decodeCoseSign1, signCoseSign1, verifyCoseSign1, type CoseSign1 } from '../cose/cose.js';
import type { KeyPairMaterial } from '../crypto/jwk.js';
import {
  algorithmFromCoseAlgorithm,
  type GeneratedKeyPair,
  type ICryptoProvider,
} from '../crypto/providers.js';
import { QrsParseError, QrsUnsupportedError } from '../errors.js';
import { fromHex, hashFor, isHashAlgorithm, toHex, truncSha256 } from '../id.js';
import type { AlgorithmId, KeyId, ProtocolVersion, SdocId, SignedObjectType, TcertId } from '../types.js';
import { assertValidObjectData, isSignedObjectType } from './schemas.js';

export interface ParsedSignedObject {
  version: ProtocolVersion;
  type: SignedObjectType;
  algorithm: AlgorithmId;
  signerKeyId: KeyId;
  /** The raw bytes signed by the COSE message ([version, type, dataBytes]). */
  payload: Uint8Array;
  /** Canonical CBOR bytes of the object data. */
  dataBytes: Uint8Array;
  /** Decoded object data (plain object for protocol data maps). */
  data: Record<string, CborValue>;
  signature: Uint8Array;
  cose: CoseSign1;
}

/** Read the authenticated TCert number from a TCert or SDoc protected header. */
export function tcertNumberOf(parsed: ParsedSignedObject): number {
  const value = parsed.cose.protectedHeaders.tcertNumber;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1 || value > 255) {
    throw new QrsParseError(`Signed ${parsed.type} has no valid protected TCert number (header ${COSE_HDR_TCERT_NUMBER})`);
  }
  return value;
}

/** Build the bytes of a signed object of the given type. */
export async function buildSignedObject(
  type: SignedObjectType,
  data: Record<string, unknown>,
  keyPair: GeneratedKeyPair,
  provider: ICryptoProvider,
  externalAad: Uint8Array = new Uint8Array(0),
  tcertNumber?: number
): Promise<Uint8Array> {
  const dataBytes = cborEncode(data as CborValue);
  const payload = cborEncode([1, type, dataBytes]);
  const { bytes } = await signCoseSign1(payload, provider.keyId(keyPair.publicJwk), keyPair, provider, externalAad, tcertNumber);
  return bytes;
}

/** Parse a signed object from its wire bytes and dispatch on its type. */
export function parseSignedObject(bytes: Uint8Array): ParsedSignedObject {
  const cose = decodeCoseSign1(bytes);

  const inner = cborDecode(cose.payload);
  if (!Array.isArray(inner) || inner.length !== 3) {
    throw new QrsParseError('SignedObject payload must be [version, type, data]');
  }
  const [version, type, dataBytes] = inner;
  if (version !== 1) {
    throw new QrsUnsupportedError(`Unsupported protocol version: ${String(version)}`);
  }
  if (typeof type !== 'string' || !isSignedObjectType(type)) {
    throw new QrsUnsupportedError(`Unknown signed object type: ${String(type)}`);
  }
  if (!(dataBytes instanceof Uint8Array)) {
    throw new QrsParseError('SignedObject data must be a byte string');
  }

  const algorithm = algorithmFromCoseAlgorithm(cose.protectedHeaders.alg ?? 0);
  if (!algorithm) {
    throw new QrsUnsupportedError(`Unsupported algorithm identifier: ${cose.protectedHeaders.alg}`);
  }

  const data = cborDecode(dataBytes);
  if (typeof data !== 'object' || data === null || Array.isArray(data) || data instanceof Map) {
    throw new QrsParseError('SignedObject data must be a map with text keys');
  }

  assertValidObjectData(type, data);

  return {
    version: version as ProtocolVersion,
    type,
    algorithm,
    signerKeyId: toHex(cose.protectedHeaders.kid ?? new Uint8Array(0)),
    payload: cose.payload,
    dataBytes,
    data: data as Record<string, CborValue>,
    signature: cose.signature,
    cose,
  };
}

/** Verify a parsed signed object using the signer's public key. */
export async function verifyParsedSignedObject(
  parsed: ParsedSignedObject,
  provider: ICryptoProvider,
  publicJwk: KeyPairMaterial['publicJwk'],
  externalAad: Uint8Array = new Uint8Array(0)
): Promise<boolean> {
  return verifyCoseSign1(parsed.cose, provider, publicJwk, externalAad);
}

/* -------------------------------------------------------------------------- */
/* Identifier helpers                                                         */
/* -------------------------------------------------------------------------- */

/** TCert id: `${keyId}:${certificateNumber}`. */
export function tcertIdOf(keyId: KeyId, certificateNumber: number): TcertId {
  return `${keyId}:${certificateNumber}`;
}

/** SDoc id: truncated SHA-256 of the signed SDoc bytes. */
export function sdocIdOf(bytes: Uint8Array): SdocId {
  return toHex(truncSha256(bytes));
}

/**
 * Content hash of a TCert (hex), used to bind attestation statements to a
 * specific TCert object. Uses the protocol hash function (`hashFor` — SHA-256
 * by default, or the TCert's declared `hashAlgorithm`).
 */
export function tcertHashOf(tcertParsed: ParsedSignedObject): string {
  const declared = tcertParsed.data.hashAlgorithm as unknown;
  const alg = typeof declared === 'string' && isHashAlgorithm(declared) ? declared : undefined;
  return toHex(hashFor(alg, tcertParsed.cose.payload));
}

/** Parse a TCert id back into its parts. */
export function splitTcertId(tcertId: TcertId): { keyId: KeyId; certificateNumber: number } {
  const idx = tcertId.indexOf(':');
  if (idx <= 0) throw new QrsParseError(`Malformed tcert id: ${tcertId}`);
  const keyId = tcertId.slice(0, idx);
  const certificateNumber = Number(tcertId.slice(idx + 1));
  if (!Number.isInteger(certificateNumber) || certificateNumber < 1 || certificateNumber > 255) {
    throw new QrsParseError(`Malformed tcert certificate number: ${tcertId}`);
  }
  return { keyId, certificateNumber };
}

/** Convenience: key bytes as hex (for TCert data fields). */
export function keyIdToBytes(keyId: KeyId): Uint8Array {
  return fromHex(keyId);
}
