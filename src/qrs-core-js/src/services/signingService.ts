/**
 * SigningService: issue an SDoc (a signed document) under a TCert.
 *
 * Secret inputs (binding `stripped`) are signed into the COSE external AAD but are
 * NOT stored in the SDoc. At verification time the same secret must be supplied to
 * reconstruct the signed bytes — the comparison is cryptographic and bit-exact.
 */
import { cborEncode } from '../cbor/canonical.js';
import type { PrivateJwk, PublicJwk } from '../crypto/jwk.js';
import { QrsCryptoError, QrsNotFoundError, QrsValidationError } from '../errors.js';
import { toHex } from '../id.js';
import { parseSignedObject, sdocIdOf, tcertNumberOf } from '../signedObject/signedObject.js';
import { isFieldType } from '../signedObject/schemas.js';
import { buildSignedObject, verifyParsedSignedObject } from '../signedObject/signedObject.js';
import type { AlgorithmId, SdocId, TcertId } from '../types.js';
import { isStrippedBinding, type FieldSchema } from '../fields/types.js';
import type { ServiceDeps } from './deps.js';

export interface IssueSdocParams {
  tcertId: TcertId;
  /** Field values keyed by field name. Secrets are prompted/supplied like any other value. */
  values: Record<string, unknown>;
  issuedAt?: number;
  /**
   * SDoc validity is NOT stored separately. If a document needs a validity window,
   * put date/datetime fields in the TCert schema with `verifyRules.expressions`
   * (e.g. `>today()`) — the SDoc then carries just those field values.
   */
}

export interface IssueSdocResult {
  sdocId: SdocId;
  bytes: Uint8Array;
  issuedAt: number;
}

export class SigningService {
  constructor(private readonly deps: ServiceDeps) {}

  async issueSdoc(params: IssueSdocParams): Promise<IssueSdocResult> {
    const tcertBytes = await this.deps.certificateStore.get(params.tcertId);
    if (!tcertBytes) throw new QrsNotFoundError(`TCert not found: ${params.tcertId}`);

    const parsed = parseSignedObject(tcertBytes);
    if (parsed.type !== 'tcert') throw new QrsValidationError('Object is not a TCert');

    const data = parsed.data;
    const keyId = parsed.signerKeyId;
    const certificateNumber = tcertNumberOf(parsed);
    const algorithm = data.algorithm as AlgorithmId;
    const publicJwk = data.publicKey as unknown as PublicJwk;

    // The stored TCert must still verify (defensive).
    const provider = this.deps.cryptoRegistry.get(algorithm);
    if (!(await verifyParsedSignedObject(parsed, provider, publicJwk))) {
      throw new QrsCryptoError('Stored TCert failed self-signature verification');
    }

    // Issue-time validity check: never sign a document that cannot be verified.
    const tcertValidity = data.validity as unknown as { validAfter?: number; validBefore?: number } | undefined;
    const now = params.issuedAt ?? this.deps.clock.now();
    if (tcertValidity) {
      if (tcertValidity.validAfter !== undefined && now < tcertValidity.validAfter) {
        throw new QrsValidationError('TCert is not yet valid');
      }
      if (tcertValidity.validBefore !== undefined && now >= tcertValidity.validBefore) {
        throw new QrsValidationError('TCert has expired');
      }
    }

    const rawSchema = data.schema;
    if (!Array.isArray(rawSchema) || rawSchema.length === 0) {
      throw new QrsValidationError('TCert has no document schema and cannot issue documents');
    }
    const fields = rawSchema as unknown as FieldSchema[];
    // Values are stored as a schema-indexed array (position i matches schema[i]).
    // Field names and labels live only in the TCert — never in the SDoc — keeping
    // the SDoc as small as possible for QR transfer.
    const storedValues: unknown[] = [];
    const secrets: Record<string, string> = {};

    for (let i = 0; i < fields.length; i++) {
      const field = fields[i];
      if (!field) continue;
      if (!isFieldType(field.type)) throw new QrsValidationError(`Unsupported field type: ${field.type}`);
      const engine = this.deps.fieldRegistry.get(field.type);
      let value = params.values[field.name];

      // Auto-fill a declared default (e.g. a hidden datetime field defaulting to now).
      if (value === undefined && field.default !== undefined) {
        value = resolveFieldDefault(field, now);
      }

      if (value === undefined) {
        const required = field.inputRules?.required === true;
        if (required) throw new QrsValidationError(`Missing required value for field '${field.name}'`);
        storedValues.push(null); // optional field omitted
        continue;
      }

      const inputError = engine.validateInput(field, value);
      if (inputError) throw new QrsValidationError(`Field '${field.name}': ${inputError.message}`);

      if (isStrippedBinding(field)) {
        secrets[field.name] = String(value);
        storedValues.push(null);
      } else {
        storedValues.push(engine.encode(field, value));
      }
    }

    const issuedAt = params.issuedAt ?? this.deps.clock.now();
    const sdocData: Record<string, unknown> = {
      issuedAt,
      fields: storedValues,
    };

    const privRec = await this.deps.privateKeyStore.load(keyId);
    if (!privRec) throw new QrsNotFoundError(`Issuer private key not available: ${keyId}`);

    // Secrets are carried in the COSE external AAD (signed but not stored).
    const externalAad = Object.keys(secrets).length > 0 ? cborEncode(secrets) : new Uint8Array(0);
    const keyPair = { algorithm, publicJwk, privateJwk: privRec.privateJwk as PrivateJwk };
    const bytes = await buildSignedObject('sdoc', sdocData, keyPair, provider, externalAad, certificateNumber);
    const sdocId = sdocIdOf(bytes);

    await this.deps.documentStore.save(sdocId, bytes);
    return { sdocId, bytes, issuedAt };
  }
}

/** Resolve a field's declared default into a concrete value at signing time. */
function resolveFieldDefault(field: FieldSchema, now: number): unknown {
  const def = field.default;
  if (def !== null && typeof def === 'object' && (def as { kind?: string }).kind === 'now') {
    const d = new Date(now * 1000);
    const pad = (n: number): string => String(n).padStart(2, '0');
    if (field.type === 'date') {
      return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
    }
    return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}Z`;
  }
  return def;
}
