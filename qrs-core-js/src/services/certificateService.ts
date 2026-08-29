/**
 * CertificateService: key generation and TCert creation.
 *
 * A TCert combines an issuer identity and the schema of one document type. It is
 * always self-signed, and its `key_id` is derived from its public key. A single key
 * pair may own several TCerts (one per document type), distinguished by their
 * certificate number.
 */
import type { PublicJwk } from '../crypto/jwk.js';
import { QrsCryptoError, QrsNotFoundError, QrsValidationError } from '../errors.js';
import { toHex } from '../id.js';
import { keyIdToBytes, tcertIdOf } from '../signedObject/signedObject.js';
import {
  buildSignedObject,
  parseSignedObject,
  verifyParsedSignedObject,
  type ParsedSignedObject,
} from '../signedObject/signedObject.js';
import { assertValidObjectData, isFieldType } from '../signedObject/schemas.js';
import { isHashAlgorithm, type HashAlgorithm } from '../id.js';
import type { AlgorithmId, KeyId, TcertId } from '../types.js';
import type { FieldSchema } from '../fields/types.js';
import type { ServiceDeps } from './deps.js';

export interface CreateTcertParams {
  algorithm: AlgorithmId;
  /** Human-readable name of this TCert. A TCert represents a document/entity;
   * the *issuer* display name comes from the CA that attests it (via trust). */
  name: string;
  /** The document schema: field definitions. */
  fields: FieldSchema[];
  /** Reuse an existing key; when omitted a new key pair is generated. */
  keyId?: KeyId;
  validAfter?: number;
  validBefore?: number;
  /**
   * Default validity duration (seconds) applied to every SDoc this TCert issues:
   * a document older than this at verification time is invalid. This lets a TCert
   * that is itself valid for a long time restrict how long its documents stay
   * valid (e.g. `sdocMaxAgeSeconds: 7 * 86_400` for one week).
   */
  sdocMaxAgeSeconds?: number;
  /** Hash algorithm for attachment content hashing under this TCert (default SHA-256). */
  hashAlgorithm?: HashAlgorithm;
  onlineEndpoint?: string;
  metadata?: Record<string, unknown>;
}

export interface CreateTcertResult {
  keyId: KeyId;
  tcertId: TcertId;
  certificateNumber: number;
  bytes: Uint8Array;
  parsed: ParsedSignedObject;
}

export class CertificateService {
  constructor(private readonly deps: ServiceDeps) {}

  /** Generate a new key pair and store it (private + public). Returns the key_id. */
  async generateKeyPair(algorithm: AlgorithmId): Promise<KeyId> {
    const provider = this.deps.cryptoRegistry.get(algorithm);
    const pair = await provider.generateKeyPair();
    const keyId = provider.keyId(pair.publicJwk);
    await this.deps.privateKeyStore.save(keyId, algorithm, pair.privateJwk);
    await this.deps.publicKeyStore.save(keyId, algorithm, pair.publicJwk);
    return keyId;
  }

  /** Create a self-signed TCert for a document type and store it. */
  async createTcert(params: CreateTcertParams): Promise<CreateTcertResult> {
    for (const field of params.fields) {
      if (!isFieldType(field.type)) throw new QrsValidationError(`Unsupported field type: ${field.type}`);
      if (!field.name || !field.label) throw new QrsValidationError('Each field must have a name and a label');
      if (!this.deps.fieldRegistry.has(field.type)) {
        throw new QrsValidationError(`No field engine registered for type: ${field.type}`);
      }
    }

    let keyId = params.keyId;
    if (!keyId) keyId = await this.generateKeyPair(params.algorithm);

    const pubRec = await this.deps.publicKeyStore.load(keyId);
    if (!pubRec) throw new QrsNotFoundError(`Public key not found: ${keyId}`);
    const privRec = await this.deps.privateKeyStore.load(keyId);
    if (!privRec) throw new QrsNotFoundError(`Private key not available for signing: ${keyId}`);

    const provider = this.deps.cryptoRegistry.get(pubRec.algorithm);

    // Pick the lowest unused certificate number (1..255) for this key.
    const existing = await this.deps.certificateStore.findByKeyId(keyId);
    const used = new Set(existing.map((e) => Number(e.tcertId.split(':')[1])));
    let certificateNumber = 0;
    for (let n = 1; n <= 255; n++) {
      if (!used.has(n)) {
        certificateNumber = n;
        break;
      }
    }
    if (certificateNumber === 0) throw new QrsValidationError('No certificate numbers left for this key');

    const data: Record<string, unknown> = {
      keyId: keyIdToBytes(keyId),
      certificateNumber,
      algorithm: provider.algorithm,
      publicKey: pubRec.publicJwk,
      identity: { name: params.name },
      schema: params.fields,
    };
    const validity: { validAfter?: number; validBefore?: number; sdocMaxAgeSeconds?: number } = {};
    if (params.validAfter !== undefined) validity.validAfter = params.validAfter;
    if (params.validBefore !== undefined) validity.validBefore = params.validBefore;
    if (params.sdocMaxAgeSeconds !== undefined) validity.sdocMaxAgeSeconds = params.sdocMaxAgeSeconds;
    if (Object.keys(validity).length > 0) data.validity = validity;
    if (params.hashAlgorithm !== undefined) {
      if (!isHashAlgorithm(params.hashAlgorithm)) {
        throw new QrsValidationError(`Unsupported hash algorithm: ${String(params.hashAlgorithm)}`);
      }
      data.hashAlgorithm = params.hashAlgorithm;
    }
    if (params.onlineEndpoint) data.onlineEndpoint = params.onlineEndpoint;
    if (params.metadata && Object.keys(params.metadata).length > 0) data.metadata = params.metadata;

    const keyPair = { algorithm: provider.algorithm, publicJwk: pubRec.publicJwk, privateJwk: privRec.privateJwk };
    const bytes = await buildSignedObject('tcert', data, keyPair, provider, new Uint8Array(0), certificateNumber);
    const parsed = parseSignedObject(bytes);
    assertValidObjectData('tcert', parsed.data);

    // Self-signature must hold, and the key_id must match the embedded public key.
    if (
      !(await verifyParsedSignedObject(parsed, provider, pubRec.publicJwk)) ||
      toHex(parsed.data.keyId as Uint8Array) !== keyId
    ) {
      throw new QrsCryptoError('TCert self-signature verification failed');
    }

    const tcertId = tcertIdOf(keyId, certificateNumber);
    await this.deps.certificateStore.save(tcertId, bytes);
    return { keyId, tcertId, certificateNumber, bytes, parsed };
  }

  /** Convenience: load and parse a stored TCert. */
  async getTcert(tcertId: TcertId): Promise<{ bytes: Uint8Array; parsed: ParsedSignedObject }> {
    const bytes = await this.deps.certificateStore.get(tcertId);
    if (!bytes) throw new QrsNotFoundError(`TCert not found: ${tcertId}`);
    return { bytes, parsed: parseSignedObject(bytes) };
  }

  /** Convenience: derive the public JWK embedded in a TCert. */
  async publicKeyOf(tcertId: TcertId): Promise<{ algorithm: AlgorithmId; publicJwk: PublicJwk }> {
    const { parsed } = await this.getTcert(tcertId);
    const algorithm = parsed.data.algorithm as AlgorithmId;
    const publicJwk = parsed.data.publicKey as unknown as PublicJwk;
    return { algorithm, publicJwk };
  }
}
