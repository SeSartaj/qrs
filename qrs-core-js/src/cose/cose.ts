/**
 * COSE_Sign1 (RFC 9052) support — the signed-object cryptographic structure.
 *
 * Wire format (canonical CBOR array of four elements):
 *   [ protected, unprotected, payload, signature ]
 *
 * The signature is computed over the Sig_structure:
 *   ["Signature1", protected, external_aad, payload]
 *
 * `external_aad` is how secret-bound fields are kept OUT of the stored payload while
 * still being covered by the signature (see the secretInput field engine).
 */
import { cborDecode, cborEncode, type CborKey, type CborValue } from '../cbor/canonical.js';
import { QrsParseError, QrsUnsupportedError } from '../errors.js';
import { fromHex } from '../id.js';
import type { PrivateJwk, PublicJwk } from '../crypto/jwk.js';
import type { GeneratedKeyPair, ICryptoProvider } from '../crypto/providers.js';

/** COSE header labels (RFC 9052 §3). */
export const COSE_HDR_ALG = 1;
export const COSE_HDR_KID = 4;
/** Protocol-private protected header: the TCert certificate number (1..255). */
export const COSE_HDR_TCERT_NUMBER = -70001;

const CONTEXT = 'Signature1';

export interface CoseSign1 {
  protectedBytes: Uint8Array;
  protectedHeaders: { alg?: number; kid?: Uint8Array; tcertNumber?: number };
  unprotectedBytes: Uint8Array;
  payload: Uint8Array;
  signature: Uint8Array;
}

export interface SignedCose {
  cose: CoseSign1;
  bytes: Uint8Array;
}

/**
 * Sign a payload into a COSE_Sign1 message.
 *
 * @param payload    the bytes to sign (the SignedObject content)
 * @param keyId      the signer's `key_id` (hex)
 * @param keyPair    the signer's key material
 * @param provider   the crypto provider for `keyPair.algorithm`
 * @param externalAad additional authenticated bytes (e.g. secrets), NOT stored in the message
 */
export async function signCoseSign1(
  payload: Uint8Array,
  keyId: string,
  keyPair: GeneratedKeyPair,
  provider: ICryptoProvider,
  externalAad: Uint8Array = new Uint8Array(0),
  tcertNumber?: number
): Promise<SignedCose> {
  if (tcertNumber !== undefined && (!Number.isInteger(tcertNumber) || tcertNumber < 1 || tcertNumber > 255)) {
    throw new QrsParseError('TCert number must be an integer in the range 1..255');
  }
  const protectedHeaders = new Map<number, CborValue>([
    [COSE_HDR_ALG, provider.coseAlgorithmId],
    [COSE_HDR_KID, fromHex(keyId)],
  ]);
  if (tcertNumber !== undefined) protectedHeaders.set(COSE_HDR_TCERT_NUMBER, tcertNumber);
  const protectedBytes = cborEncode(
    protectedHeaders
  );
  const unprotectedBytes = cborEncode(new Map<number, CborValue>());

  const sigStructure = cborEncode([CONTEXT, protectedBytes, externalAad, payload]);
  const signature = await provider.sign(sigStructure, keyPair.privateJwk);

  const cose: CoseSign1 = {
    protectedBytes,
    protectedHeaders: {
      alg: provider.coseAlgorithmId,
      kid: fromHex(keyId),
      ...(tcertNumber === undefined ? {} : { tcertNumber }),
    },
    unprotectedBytes,
    payload,
    signature,
  };
  const bytes = cborEncode([protectedBytes, unprotectedBytes, payload, signature]);
  return { cose, bytes };
}

/** Parse a COSE_Sign1 message from its wire bytes. */
export function decodeCoseSign1(bytes: Uint8Array): CoseSign1 {
  const decoded = cborDecode(bytes);
  if (!Array.isArray(decoded) || decoded.length !== 4) {
    throw new QrsParseError('COSE_Sign1 must be an array of exactly 4 elements');
  }
  const [protectedBytes, unprotectedBytes, payload, signature] = decoded;
  if (
    !(protectedBytes instanceof Uint8Array) ||
    !(unprotectedBytes instanceof Uint8Array) ||
    !(payload instanceof Uint8Array) ||
    !(signature instanceof Uint8Array)
  ) {
    throw new QrsParseError('COSE_Sign1 elements must all be byte strings');
  }

  const headers = cborDecode(protectedBytes);
  if (typeof headers !== 'object' || headers === null) {
    throw new QrsParseError('COSE_Sign1 protected headers must be a map');
  }
  const headerMap: Map<CborKey, CborValue> = headers instanceof Map ? headers : new Map(Object.entries(headers));
  const alg = headerMap.get(COSE_HDR_ALG);
  const kid = headerMap.get(COSE_HDR_KID);
  const tcertNumber = headerMap.get(COSE_HDR_TCERT_NUMBER);
  if (typeof alg !== 'number') throw new QrsParseError('COSE_Sign1 protected headers must contain an algorithm');
  if (!(kid instanceof Uint8Array)) throw new QrsParseError('COSE_Sign1 protected headers must contain a key id');
  if (tcertNumber !== undefined && (typeof tcertNumber !== 'number' || !Number.isInteger(tcertNumber) || tcertNumber < 1 || tcertNumber > 255)) {
    throw new QrsParseError('COSE_Sign1 protected TCert number must be an integer in the range 1..255');
  }

  return {
    protectedBytes,
    protectedHeaders: { alg, kid, ...(tcertNumber === undefined ? {} : { tcertNumber }) },
    unprotectedBytes,
    payload,
    signature,
  };
}

/**
 * Verify a COSE_Sign1 message.
 * @param externalAad the same externally-supplied bytes used at signing time.
 */
export async function verifyCoseSign1(
  cose: CoseSign1,
  provider: ICryptoProvider,
  publicJwk: PublicJwk,
  externalAad: Uint8Array = new Uint8Array(0)
): Promise<boolean> {
  const sigStructure = cborEncode([CONTEXT, cose.protectedBytes, externalAad, cose.payload]);
  try {
    return await provider.verify(sigStructure, cose.signature, publicJwk);
  } catch {
    return false;
  }
}

export function assertSupportedAlgorithm(alg: number): void {
  // Only algorithm identifiers this profile understands may be used.
  if (alg !== -8 && alg !== -7) {
    throw new QrsUnsupportedError(`Unsupported COSE algorithm identifier: ${alg}`);
  }
}

/** Re-export for convenience. */
export type { PrivateJwk, PublicJwk };
