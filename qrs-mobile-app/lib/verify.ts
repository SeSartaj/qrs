/**
 * Verification helper: turns an SDoc payload into a clean, easy-to-read result
 * model for the UI (verdict, issuer + verified-by-CA, decoded values, breakdown).
 */
import {
  decodeTransferPayload,
  fromBase64Url,
  parseSignedObject,
  sdocIdOf,
  tcertIdOf,
  tcertNumberOf,
  toHex,
  type FieldSchema,
} from 'qrs-core';
import { attachmentContentType, effectiveBinding, isBoundField, isStrippedBinding } from 'qrs-core';
import type { AttestationRecord, VerificationResult } from 'qrs-core';
import { getQrs } from './runtime';
import { fetchAttachmentContent } from './attachment';
import { getSettings, type TrustPolicy } from './settings';
import { dedupCaViews, issuerVerifiedByPolicy, resolveVerdict } from './trustPolicy';
import type { CaView, Verdict } from './trustPolicy';
export { dedupCaViews, issuerVerifiedByPolicy, resolveVerdict } from './trustPolicy';
export type { CaView, Verdict } from './trustPolicy';

export interface CleanValue {
  label: string;
  type: string;
  value: unknown;
  /** Signed schema MIME type for attachment fields. */
  contentType?: string;
  /** Schema options for selectv2 fields (label/value/color) — to resolve the stored index. */
  options?: unknown;
  /** Per-field verification state (only set when the field engine validates it). */
  state?: string;
  message?: string;
  /** True when this field's value is bound by the SDoc signature (shown with a protected border). */
  protected?: boolean;
}

export interface CleanVerifyResult {
  verdict: Verdict;
  overallState: string;
  documentName?: string;
  issuerName?: string;
  /** The issuing TCert is trusted (pinned or attested by a trusted CA). */
  issuerVerified: boolean;
  /** The issuing TCert is explicitly pinned on this device. */
  issuerPinned: boolean;
  /** The issuing TCert was not found on this device (→ "cannot be verified"). */
  certificateMissing: boolean;
  /** Name of the trusted CA that attests this TCert (when CA-issued). */
  caName?: string;
  caVerified: boolean;
  /** The trust policy applied when resolving multiple CA attestations. */
  trustPolicy: TrustPolicy;
  /** One view per attesting CA (for the swipeable multi-CA result). */
  caViews: CaView[];
  sdocId?: string;
  tcertId?: string;
  issuedAt?: number;
  sizeBytes?: number;
  values: CleanValue[];
  breakdown: Array<{ key: string; state: string }>;
  message?: string;
  warnings: string[];
  result: VerificationResult;
}

/** Accept a raw SDoc (base64url) or a `qrs://v1/sdoc/…` transfer envelope. */
export function normalizeSdocInput(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error('Paste an SDoc first.');
  if (trimmed.startsWith('qrs://')) {
    const decoded = decodeTransferPayload(trimmed);
    if (!decoded) throw new Error('Not a valid qrs:// transfer payload.');
    if (decoded.type !== 'sdoc') throw new Error(`Expected an SDoc, got a ${decoded.type}.`);
    return decoded.bytesB64;
  }
  return trimmed;
}

function formatValue(value: unknown): unknown {
  if (value instanceof Uint8Array) return toHex(value);
  if (Array.isArray(value)) return value.map(formatValue);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = formatValue(v);
    return out;
  }
  return value;
}

/** Resolve the display name of a CA TCert (best effort). */
async function caDisplayName(qrs: ReturnType<typeof getQrs>, caTcertId: string): Promise<string | undefined> {
  const caBytes = await qrs.deps.certificateStore.get(caTcertId);
  if (!caBytes) return undefined;
  try {
    const caParsed = parseSignedObject(caBytes);
    const caIdentity = caParsed.data.identity as { name?: string } | undefined;
    return caIdentity?.name;
  } catch {
    return undefined;
  }
}

/**
 * Evaluate one CA's independent view of the attested TCert: is the CA trusted,
 * has it revoked the target, and is its attestation cryptographically valid?
 */
async function evaluateCaView(
  qrs: ReturnType<typeof getQrs>,
  targetTcertId: string,
  att: AttestationRecord
): Promise<CaView> {
  const caTrusted = (await qrs.deps.trustStore.isPinned(att.caTcertId)) || (await qrs.deps.trustStore.isCa(att.caTcertId));
  const caDistrusted = await qrs.deps.trustStore.isDistrusted(att.caTcertId);
  const caKeyRevoked = !!(await qrs.deps.revocationStore.getRevokedKey(att.caKeyId));
  const attestationRevoked = !!(await qrs.deps.revocationStore.getRevokedAttestation(targetTcertId, att.caTcertId));
  // Per-CA revocation attribution: only a revocation signed by THIS CA counts
  // against its own attestation. A revocation signed by a different CA is that
  // CA's independent opinion and does not affect this one.
  const revocationEntries = await qrs.deps.revocationStore.getRevokedTcertEntries(targetTcertId);
  const thisCaRevoked = revocationEntries.some(
    (e) => (e.byKeyId && e.byKeyId === att.caKeyId) || (e.byTcertId && e.byTcertId === att.caTcertId)
  );
  const caName = await caDisplayName(qrs, att.caTcertId);

  let attestationValid = false;
  try {
    attestationValid = await qrs.trust.isValidAttestation(att);
  } catch {
    attestationValid = false;
  }

  const revoked = caKeyRevoked || thisCaRevoked || attestationRevoked;
  const trusted = caTrusted && !caDistrusted && !revoked;
  const state: CaView['state'] = !trusted ? 'invalid' : attestationValid ? 'valid' : 'cannotVerify';

  return {
    caTcertId: att.caTcertId,
    caName,
    caTrusted: trusted,
    revoked,
    attestationValid,
    state,
    message: revoked
      ? attestationRevoked ? 'This CA has revoked its attestation' : 'This CA has revoked the certificate'
      : !caTrusted
        ? 'This CA is not trusted on this device'
        : !attestationValid
          ? 'Attestation could not be verified'
          : undefined,
  };
}

/** Verify an SDoc and build a clean result for the UI. */
export async function verifySdoc(raw: string): Promise<CleanVerifyResult> {
  const qrs = getQrs();
  const bytesB64 = normalizeSdocInput(raw);
  const bytes = fromBase64Url(bytesB64);

  // Quick structural parse for enrichment (tcert id, values).
  const parsed = parseSignedObject(bytes);
  if (parsed.type !== 'sdoc') throw new Error(`Not an SDoc (got ${parsed.type}).`);
  const data = parsed.data as unknown as {
    issuedAt: number;
    fields: unknown[];
  };
  const sdocId = sdocIdOf(bytes);
  const keyId = parsed.signerKeyId;
  const tcertId = tcertIdOf(keyId, tcertNumberOf(parsed));

  // Required attachments are part of the document's verification dependency:
  // wait for them before returning a result. Optional attachments are checked
  // only when the user downloads/opens them from AttachmentFieldView.
  let requiredAttachmentFailure: { fieldName: string; state: 'cannotVerify' | 'invalid'; message: string } | undefined;
  const requiredTcertBytes = await qrs.deps.certificateStore.get(tcertId);
  if (requiredTcertBytes) {
    try {
      const tcert = parseSignedObject(requiredTcertBytes);
      const schema = (tcert.data.schema ?? []) as unknown as FieldSchema[];
      const stored = (data.fields ?? []) as unknown[];
      const endpoints = await qrs.endpoints.effectiveEndpoints(tcertId);
      for (let i = 0; i < schema.length; i++) {
        const field = schema[i];
        const reference = stored[i];
        if (!field || field.type !== 'attachment' || field.inputRules?.required !== true || typeof reference !== 'string') continue;
        const attachment = await fetchAttachmentContent(qrs, reference, attachmentContentType(field), endpoints);
        if (!attachment || 'error' in attachment) {
          const corrupt = attachment?.error === 'corrupt';
          requiredAttachmentFailure = {
            fieldName: field.name,
            state: corrupt ? 'invalid' : 'cannotVerify',
            message: corrupt
              ? 'Required attachment is corrupted (its hash does not match the signed SDoc)'
              : endpoints.length > 0 ? 'Required attachment could not be downloaded or verified' : 'Required attachment has no available server',
          };
          break;
        }
      }
    } catch {
      requiredAttachmentFailure = { fieldName: '', state: 'cannotVerify', message: 'Required attachment could not be verified' };
    }
  }

  const result = await qrs.verification.verify(bytes, { currentTime: Math.floor(Date.now() / 1000) });
  if (requiredAttachmentFailure) {
    result.overall = requiredAttachmentFailure.state;
    result.message = requiredAttachmentFailure.message;
    const fieldResult = result.fields.find((field) => field.name === requiredAttachmentFailure.fieldName);
    if (fieldResult) {
      fieldResult.state = requiredAttachmentFailure.state;
      fieldResult.message = requiredAttachmentFailure.message;
    }
  }

  // Enrich with TCert identity + decoded values (best effort).
  let documentName: string | undefined;
  let issuerName: string | undefined;
  const values: CleanValue[] = [];
  const tcertBytes = await qrs.deps.certificateStore.get(tcertId);
  if (tcertBytes) {
    try {
      const tcertParsed = parseSignedObject(tcertBytes);
      const tcertData = tcertParsed.data as unknown as {
        identity?: { name?: string };
        schema?: FieldSchema[];
      };
      documentName = tcertData.identity?.name; // the TCert's name = the document it represents
      const schema = tcertData.schema ?? [];
      const stored = data.fields ?? [];
      for (let i = 0; i < schema.length; i++) {
        const field = schema[i];
        if (!field) continue;
        const encoded = stored[i];
        if (encoded === undefined || encoded === null) continue;
        const engine = qrs.deps.fieldRegistry.get(field.type);
        const fieldResult = result.fields.find((f) => f.name === field.name);
        const stripped = isStrippedBinding(field);
        values.push({
          label: field.label,
          type: field.type,
          value: formatValue(engine.decode(field, encoded)),
          contentType: field.type === 'attachment' ? attachmentContentType(field) : undefined,
          options: field.type === 'selectv2' ? (field.inputRules?.options ?? field.options) : undefined,
          state: fieldResult?.state,
          message: fieldResult?.message,
          // A value that lives in the signed payload is protected by the signature.
          protected: !stripped,
        });
      }
    } catch {
      /* enrichment is best-effort */
    }
  }

  // Trust: is the issuer trusted, and by which CA(s)?
  // Gather every CA attestation so the UI can show one swipeable "version" per
  // CA, and apply the configured trust policy (any / all) to the verdict.
  const settings = await getSettings();
  const trustPolicy = settings.trustPolicy;
  let issuerVerified = false;
  let issuerPinned = false;
  let caName: string | undefined;
  let caVerified = false;
  const caViews: CaView[] = [];
  try {
    const trust = await qrs.trust.resolveTrust(tcertId);
    issuerPinned = trust.pinned;

    // Enumerate every CA that attested this TCert and evaluate each independently.
    // Build all views, then dedup by CA id so a stale duplicate attestation row
    // can never surface the same CA on multiple swipeable pages.
    const attestations = await qrs.deps.trustStore.getAttestations(tcertId);
    caViews.push(
      ...dedupCaViews(await Promise.all(attestations.map((att) => evaluateCaView(qrs, tcertId, att))))
    );

    // Apply the trust policy across all CA views.
    issuerVerified = issuerVerifiedByPolicy(caViews, trustPolicy);

    // The primary CA shown at the top is the first trusted, non-revoked one.
    const primary = caViews.find((v) => v.caTrusted && !v.revoked && v.attestationValid) ?? caViews[0];
    if (primary) {
      caName = primary.caName;
      caVerified = primary.caTrusted && !primary.revoked && primary.attestationValid;
    }

    // Pinned TCerts stay valid regardless of CA attestations.
    if (issuerPinned) issuerVerified = true;
  } catch {
    /* trust resolution best-effort */
  }
  issuerName = caName;

  // Build the verdict. The base qrs-core result encodes the *effective* (most
  // severe, an-any-CA) revocation as invalid, so for the trust/revocation
  // dimension we use the policy-based `issuerVerified` instead — that respects
  // "Any trusted CA" (valid if one CA trusts) and "All trusted CAs" (untrusted
  // if any CA revoked). The harder checks (crypto, schema, tcert presence)
  // always come from the base result.
  const isPass = (s: string | undefined): boolean => s === 'valid' || s === 'satisfied';
  const cryptographicOk = isPass(result.cryptographic);
  const schemaOk = isPass(result.schema);
  const tcertOk = result.tcert === 'valid';
  const certificateMissing = result.tcert === 'cannotVerify';

  const verdict = requiredAttachmentFailure ? requiredAttachmentFailure.state : resolveVerdict({
    issuerVerified,
    certificateMissing,
    cryptographicOk,
    schemaOk,
    tcertOk,
    revocationOk: isPass(result.revocation),
  });

  const breakdown = [
    { key: 'cryptographic', state: result.cryptographic },
    { key: 'tcert', state: result.tcert },
    { key: 'trust', state: result.trust },
    { key: 'revocation', state: result.revocation },
    { key: 'schema', state: result.schema },
    { key: 'context', state: result.context },
  ];

  return {
    verdict,
    overallState: verdict,
    documentName,
    issuerName,
    issuerVerified,
    issuerPinned,
    certificateMissing,
    caName,
    caVerified,
    trustPolicy,
    caViews,
    sdocId,
    tcertId,
    issuedAt: data.issuedAt,
    sizeBytes: bytes.byteLength,
    values,
    breakdown,
    message: result.message,
    warnings: result.warnings,
    result,
  };
}
