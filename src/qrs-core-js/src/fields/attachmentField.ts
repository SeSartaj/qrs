import { sha256, toHex } from '../id.js';
import type { ContextRequirement, FieldResult, FieldSchema, IFieldEngine, VerificationContext } from './types.js';

/** Attachment references use the same 128-bit identifier size as other QRS IDs. */
export const ATTACHMENT_HASH_HEX = 32;
const HASH_RE = /^[0-9a-f]{32}$/i;

export type AttachmentReference = string;

/** Read the one MIME type declared by an attachment field's signed schema. */
export function attachmentContentType(field: FieldSchema): string {
  const value = field.inputRules?.contentType;
  return typeof value === 'string' && value.trim() ? value.trim().toLowerCase() : 'application/octet-stream';
}

/** Build the compact, content-addressed reference stored in an SDoc/QR. */
export function attachmentReference(content: Uint8Array): AttachmentReference {
  return toHex(sha256(content)).slice(0, ATTACHMENT_HASH_HEX);
}

/** Verify downloaded bytes against the compact reference signed into the SDoc. */
export function verifyAttachmentReference(reference: AttachmentReference, content: Uint8Array): boolean {
  const actual = attachmentReference(content);
  return actual === reference.toLowerCase();
}

/**
 * Stored value of an attachment field: the content hash string.
 *
 *   - `hash` — the first 128 bits of SHA-256, used as the content-addressed
 *     handle a verifier uses to fetch the raw file from a distribution server.
 * The content type is NOT stored here — it lives in the TCert schema (the field's
 * `inputRules.contentType` / a supported-type dropdown). The server stores the raw
 * file keyed by `hash`; the verifier downloads it on demand and checks the hash.
 */
export class AttachmentField implements IFieldEngine {
  readonly type = 'attachment' as const;

  validateInput(field: FieldSchema, value: unknown): { message: string } | null {
    if (typeof value !== 'string' || !HASH_RE.test(value)) {
      return { message: `${field.label} must be a valid content hash (128-bit, 32 hex chars)` };
    }
    return null;
  }

  encode(_field: FieldSchema, value: unknown): unknown {
    return value;
  }

  decode(_field: FieldSchema, encoded: unknown): unknown {
    return encoded;
  }

  getContextRequirements(): ContextRequirement[] {
    return [];
  }

  async validateField(field: FieldSchema, encoded: unknown, _ctx: VerificationContext): Promise<FieldResult> {
    const err = this.validateInput(field, encoded);
    return err
      ? { name: field.name, label: field.label, state: 'invalid', message: err.message }
      : { name: field.name, label: field.label, state: 'valid' };
  }
}

