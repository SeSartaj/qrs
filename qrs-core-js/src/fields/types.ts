/**
 * The field model: declarative field schemas, field engines and the verification
 * context that field engines may consume. This is the shared contract between the
 * schema (defined in a TCert) and the verification pipeline.
 */
import type { FieldType } from '../types.js';

/** External information a field engine may need during verification. */
export type ContextRequirement = 'location' | 'clock' | 'secret' | 'onlineObject';

export type FieldResultState =
  | 'valid'
  | 'invalid'
  | 'cannotVerify'
  | 'missingContext'
  | 'contextDenied'
  | 'notSupported'
  | 'malformed'
  /** Fetch-able data (e.g. an attachment) could not be downloaded. Field-only, NOT a document-level failure. */
  | 'unavailable';

/** Declarative description of one document field (part of the signed TCert schema). */
export interface FieldSchema {
  type: FieldType;
  name: string;
  label: string;
  /** Options for the `select` field type. */
  options?: string[];
  /** Validation rules applied at signing time. */
  inputRules?: Record<string, unknown>;
  /** Validation rules applied against the verification context. */
  verifyRules?: Record<string, unknown>;
  /**
   * Default value auto-filled at signing time when the issuer does not provide
   * one (the field is typically hidden from the signing form). `datetime`/`date`
   * fields accept `{ kind: 'now' }` to default to the current time.
   */
  default?: unknown;
  /**
   * Value binding. When set, the verifier is prompted for the exact value at
   * verification time (similar to a password); a mismatch fails verification.
   *  - `inline` (default for non-secret types): the value is stored in the SDoc and
   *    compared against the verifier's entry (rules-level failure on mismatch, so
   *    the signature — and thus the original value — can still be shown).
   *  - `stripped` (default for `secretInput`): the value is signed into the COSE
   *    external AAD but NOT stored; a mismatch is a cryptographic failure.
   */
  binding?: 'inline' | 'stripped';
}

/** Field types that participate in value binding (verifier re-enters the value). */
export const BINDING_FIELD_TYPES: ReadonlySet<FieldType> = new Set([
  'secretInput',
  'text',
  'select',
  'number',
  'date',
]);

/** Whether a field participates in binding (a verifier prompt is required). */
export function isBoundField(field: FieldSchema): boolean {
  if (!BINDING_FIELD_TYPES.has(field.type)) return false;
  // secretInput is always a bound secret; other types only when `binding` is declared.
  return field.type === 'secretInput' || field.binding !== undefined;
}

/** Resolve the effective binding mode (defaults per type). */
export function effectiveBinding(field: FieldSchema): 'inline' | 'stripped' {
  if (field.binding !== undefined) return field.binding;
  return field.type === 'secretInput' ? 'stripped' : 'inline';
}

/** Whether the field's value is signed-but-not-stored (carried in the COSE external AAD). */
export function isStrippedBinding(field: FieldSchema): boolean {
  return isBoundField(field) && effectiveBinding(field) === 'stripped';
}

export interface FieldResult {
  name: string;
  state: FieldResultState;
  message?: string;
  /** Human-readable label from the TCert schema. */
  label?: string;
}

export interface FieldInputError {
  message: string;
}

/**
 * The external verification context. The core protocol never calls platform APIs;
 * the application supplies this context through its providers (IoC).
 */
export interface VerificationContext {
  getCurrentTime(): number;
  getLocation(): Promise<{ lat: number; lon: number } | null>;
  getSecret(fieldName: string): Promise<string | null>;
  /** Fetch a signed object by its content-addressed id (onlineEndpoints are distribution-server hints, tried in order). */
  getObject(id: string, onlineEndpoints?: string | string[]): Promise<Uint8Array | null>;
}

/**
 * A field engine implements the semantics of one field type (SOLID: one type,
 * one engine). Engines are interchangeable and pluggable via {@link FieldRegistry}.
 */
export interface IFieldEngine {
  readonly type: FieldType;

  /** Validate a raw input value against the field's input rules. */
  validateInput(field: FieldSchema, value: unknown): FieldInputError | null;

  /** Convert a validated input into its canonical stored representation. */
  encode(field: FieldSchema, value: unknown): unknown;

  /** Convert a stored representation back into a presentable value. */
  decode(field: FieldSchema, encoded: unknown): unknown;

  /** Which parts of the verification context this field needs. */
  getContextRequirements(field: FieldSchema): ContextRequirement[];

  /** Contextual validation performed after cryptographic verification. */
  validateField(field: FieldSchema, encoded: unknown, ctx: VerificationContext): Promise<FieldResult>;
}

/** Read an integer rule from a rules object, with a default. */
export function readNumberRule(rules: Record<string, unknown> | undefined, key: string, fallback: number): number {
  const v = rules?.[key];
  return typeof v === 'number' ? v : fallback;
}

export function readBoolRule(rules: Record<string, unknown> | undefined, key: string, fallback: boolean): boolean {
  const v = rules?.[key];
  return typeof v === 'boolean' ? v : fallback;
}

export function readStringArrayRule(
  rules: Record<string, unknown> | undefined,
  key: string,
  fallback: string[] = []
): string[] {
  const v = rules?.[key];
  return Array.isArray(v) && v.every((x) => typeof x === 'string') ? (v as string[]) : fallback;
}
