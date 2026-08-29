/**
 * VerificationService: the verification pipeline.
 *
 * Pipeline (protocol §54 adapted):
 *   1. parse the SDoc
 *   2. resolve and verify the TCert (self-signature, id, validity)
 *   3. resolve trust (pinning or CA attestation)
 *   4. evaluate revocation (key, TCert, SDoc block)
 *   5. collect secret inputs, rebuild the COSE external AAD, verify the signature
 *   6. validate the payload against the schema (including contextual fields)
 *   7. produce a structured VerificationResult
 *
 * The result deliberately distinguishes `valid`, `invalid` and `cannotVerify`
 * (e.g. GPS unavailable is NOT the same as "outside the permitted area").
 */
import { cborEncode } from '../cbor/canonical.js';
import type { IContextProvider } from '../context/context.js';
import type { PublicJwk } from '../crypto/jwk.js';
import type { CryptoRegistry } from '../crypto/registry.js';
import { constantTimeEqual, toHex } from '../id.js';
import {
  effectiveBinding,
  isBoundField,
  isStrippedBinding,
  type FieldResult,
  type FieldSchema,
  type VerificationContext,
} from '../fields/types.js';
import type { FieldRegistry } from '../fields/registry.js';
import { QrsValidationError } from '../errors.js';
import { sdocIdOf, tcertIdOf, tcertNumberOf } from '../signedObject/signedObject.js';
import { parseSignedObject, verifyParsedSignedObject } from '../signedObject/signedObject.js';
import type { ICertificateStore, IEndpointConfigStore } from '../storage/stores.js';
import type { SdocId, TcertId } from '../types.js';
import type { IClock } from './clock.js';
import type { RevocationService } from './revocationService.js';
import type { ComponentState, TrustService } from './trustService.js';

export interface VerificationResult {
  overall: ComponentState;
  cryptographic: ComponentState;
  tcert: ComponentState;
  trust: ComponentState;
  revocation: ComponentState;
  schema: ComponentState;
  fields: FieldResult[];
  context: 'satisfied' | 'missing' | 'denied';
  warnings: string[];
  sdocId?: SdocId;
  tcertId?: TcertId;
  message?: string;
}

export interface VerifyOptions {
  /** Override "now" (epoch seconds) for deterministic verification. */
  currentTime?: number;
}

export interface VerificationServiceDeps {
  cryptoRegistry: CryptoRegistry;
  fieldRegistry: FieldRegistry;
  certificateStore: ICertificateStore;
  endpointConfigStore: IEndpointConfigStore;
  contextProvider: IContextProvider;
  clock: IClock;
  trustService: TrustService;
  revocationService: RevocationService;
}

export class VerificationService {
  constructor(private readonly deps: VerificationServiceDeps) {}

  async verify(bytes: Uint8Array, options: VerifyOptions = {}): Promise<VerificationResult> {
    const result = this.emptyResult();

    let parsed;
    try {
      parsed = parseSignedObject(bytes);
    } catch (error) {
      result.cryptographic = 'invalid';
      result.message = error instanceof Error ? error.message : 'malformed signed object';
      return this.finalize(result);
    }
    if (parsed.type !== 'sdoc') {
      result.cryptographic = 'invalid';
      result.message = `expected an SDoc, got ${parsed.type}`;
      return this.finalize(result);
    }
    result.sdocId = sdocIdOf(bytes);

    /* ---------- TCert ---------- */
    const keyId = parsed.signerKeyId;
    let tcertNumber: number;
    try {
      tcertNumber = tcertNumberOf(parsed);
    } catch {
      result.tcert = 'invalid';
      result.message = 'SDoc has no valid tcertNumber';
      return this.finalize(result);
    }
    const tcertId = tcertIdOf(keyId, tcertNumber);
    result.tcertId = tcertId;

    const tcertBytes = await this.deps.certificateStore.get(tcertId);
    if (!tcertBytes) {
      result.tcert = 'cannotVerify';
      result.message = 'TCert not found locally';
      return this.finalize(result);
    }
    let tcertParsed;
    try {
      tcertParsed = parseSignedObject(tcertBytes);
    } catch {
      result.tcert = 'invalid';
      result.message = 'stored TCert is malformed';
      return this.finalize(result);
    }
    const tcertProvider = this.deps.cryptoRegistry.get(tcertParsed.algorithm);
    const tcertPub = tcertParsed.data.publicKey as unknown as PublicJwk;
    const selfOk = await verifyParsedSignedObject(tcertParsed, tcertProvider, tcertPub);
    const keyIdOk = tcertProvider.keyId(tcertPub) === tcertParsed.signerKeyId;
    if (!selfOk || !keyIdOk) {
      result.tcert = 'invalid';
      result.message = 'TCert self-signature invalid';
      return this.finalize(result);
    }
    const now = options.currentTime ?? this.deps.clock.now();
    const validity = tcertParsed.data.validity as
      | { validAfter?: number; validBefore?: number; sdocMaxAgeSeconds?: number }
      | undefined;
    if (validity) {
      if (validity.validAfter !== undefined && now < validity.validAfter) {
        result.tcert = 'invalid';
        result.message = 'TCert is not yet valid';
        return this.finalize(result);
      }
      if (validity.validBefore !== undefined && now >= validity.validBefore) {
        result.tcert = 'invalid';
        result.message = 'TCert has expired';
        return this.finalize(result);
      }
      // The TCert can also restrict how long the SDocs it issues stay valid.
      if (validity.sdocMaxAgeSeconds !== undefined) {
        const sdocIssuedAt = parsed.data.issuedAt;
        if (typeof sdocIssuedAt === 'number' && Number.isInteger(sdocIssuedAt) && now - sdocIssuedAt > validity.sdocMaxAgeSeconds) {
          result.schema = 'invalid';
          result.message = 'SDoc exceeds the validity duration set by its TCert';
          return this.finalize(result);
        }
      }
    }
    result.tcert = 'valid';

    /* ---------- Trust ---------- */
    const trust = await this.deps.trustService.resolveTrust(tcertId, tcertParsed);
    result.trust = trust.state;
    if (trust.message) result.message = trust.message;
    if (trust.state === 'invalid') return this.finalize(result);

    /* ---------- Revocation ---------- */
    const issuedAt = parsed.data.issuedAt;
    if (typeof issuedAt !== 'number' || !Number.isInteger(issuedAt)) {
      result.revocation = 'invalid';
      result.message = 'SDoc has no valid issuedAt';
      return this.finalize(result);
    }
    const revocation = await this.deps.revocationService.checkRevocation(tcertId, keyId, issuedAt, result.sdocId!);
    result.revocation = revocation.state;
    if (revocation.message) result.message = revocation.message;
    if (revocation.state === 'invalid') return this.finalize(result);

    /* ---------- Secrets + signature ---------- */
    const rawSchema = tcertParsed.data.schema;
    if (!Array.isArray(rawSchema) || rawSchema.length === 0) {
      result.schema = 'invalid';
      result.message = 'signer TCert has no document schema';
      return this.finalize(result);
    }
    const fields = rawSchema as unknown as FieldSchema[];
    const secretValues: Record<string, string> = {};
    let missingSecret = false;
    for (const field of fields) {
      if (isStrippedBinding(field)) {
        const secret = await this.deps.contextProvider.requestSecret(field);
        if (secret === null) {
          missingSecret = true;
          result.warnings.push(`missing bound value '${field.name}'`);
        } else {
          secretValues[field.name] = secret;
        }
      }
    }
    if (missingSecret) {
      result.cryptographic = 'cannotVerify';
      result.context = 'missing';
      result.message = 'missing required secret input';
      return this.finalize(result);
    }
    const externalAad = Object.keys(secretValues).length > 0 ? cborEncode(secretValues) : new Uint8Array(0);
    const provider = this.deps.cryptoRegistry.get(parsed.algorithm);
    const sigOk = await verifyParsedSignedObject(parsed, provider, tcertPub, externalAad);
    if (!sigOk) {
      result.cryptographic = 'invalid';
      result.message = 'SDoc signature verification failed (tampered data or incorrect secret)';
      return this.finalize(result);
    }
    result.cryptographic = 'valid';

    /* ---------- Schema + fields ---------- */
    const storedValues = parsed.data.fields as unknown[]; // schema-indexed values
    result.schema = 'valid';
    const ctx = this.deps.contextProvider.buildContext();
    for (let i = 0; i < fields.length; i++) {
      const field = fields[i];
      if (!field) continue;
      if (isStrippedBinding(field)) {
        result.fields.push({ name: field.name, label: field.label, state: 'valid', message: 'covered by signature (not stored)' });
        continue;
      }
      const engine = this.deps.fieldRegistry.get(field.type);
      const encoded = storedValues[i];
      if (encoded === undefined || encoded === null) {
        const required = field.inputRules?.required === true;
        if (required) {
          result.schema = 'invalid';
          result.fields.push({ name: field.name, label: field.label, state: 'invalid', message: 'missing required field' });
        } else {
          result.fields.push({ name: field.name, label: field.label, state: 'valid', message: 'absent (optional)' });
        }
        continue;
      }

      // Inline-bound fields: the verifier must re-enter the exact stored value.
      // The signature already verified, so a mismatch is a rules-level failure and
      // the original (stored) value can still be shown.
      if (isBoundField(field) && effectiveBinding(field) === 'inline') {
        const bound = await this.deps.contextProvider.requestSecret(field);
        if (bound === null) {
          result.fields.push({ name: field.name, label: field.label, state: 'cannotVerify', message: 'bound value not provided' });
          result.context = 'missing';
          continue;
        }
        const presentable = String(engine.decode(field, encoded));
        if (!constantTimeEqual(bound.trim(), presentable.trim())) {
          result.schema = 'invalid';
          result.fields.push({ name: field.name, label: field.label, state: 'invalid', message: 'binding value mismatch' });
          continue;
        }
        // Value matches — fall through to the engine's normal validation below.
      }

      // Attachments are compact content-hash strings — the field engine validates
      // the shape. The actual file is NOT downloaded during verification (offline
      // first); the verifier fetches it on demand by hash and checks the hash.
      let fieldResult: FieldResult;
      try {
        fieldResult = await engine.validateField(field, encoded, ctx);
      } catch (error) {
        result.schema = 'invalid';
        result.fields.push({
          name: field.name,
          label: field.label,
          state: 'malformed',
          message: error instanceof Error ? error.message : 'malformed field value',
        });
        continue;
      }
      result.fields.push({ ...fieldResult, label: field.label });
      if (fieldResult.state === 'invalid') result.schema = 'invalid';
      if (fieldResult.state === 'cannotVerify' || fieldResult.state === 'missingContext') result.context = 'missing';
      if (fieldResult.state === 'contextDenied') result.context = 'denied';
    }

    return this.finalize(result);
  }

  private emptyResult(): VerificationResult {
    return {
      overall: 'cannotVerify',
      cryptographic: 'cannotVerify',
      tcert: 'cannotVerify',
      trust: 'cannotVerify',
      revocation: 'cannotVerify',
      schema: 'cannotVerify',
      fields: [],
      context: 'satisfied',
      warnings: [],
    };
  }

  private finalize(result: VerificationResult): VerificationResult {
    const components: ComponentState[] = [
      result.cryptographic,
      result.tcert,
      result.trust,
      result.revocation,
      result.schema,
    ];
    if (components.includes('invalid')) result.overall = 'invalid';
    else if (components.includes('cannotVerify') || result.context === 'missing' || result.context === 'denied') {
      result.overall = 'cannotVerify';
    } else {
      result.overall = 'valid';
    }
    return result;
  }
}

