import {
  readBoolRule,
  type ContextRequirement,
  type FieldResult,
  type FieldSchema,
  type IFieldEngine,
  type VerificationContext,
} from './types.js';

/**
 * Secret-input field. Two bindings:
 *  - `stripped` (default): the value is signed into the COSE external AAD but is NOT
 *    stored in the SDoc. The same value must be supplied again at verification time
 *    to reconstruct the signed bytes (bit-exact, cryptographic comparison).
 *  - `inline`: the value is stored in the payload like a normal text field.
 */
export class SecretInputField implements IFieldEngine {
  readonly type = 'secretInput' as const;

  validateInput(field: FieldSchema, value: unknown): { message: string } | null {
    if (typeof value !== 'string') return { message: `${field.name} must be a string` };
    const required = readBoolRule(field.inputRules, 'required', true);
    const minLength = field.inputRules?.minLength;
    if (required && value.length === 0) return { message: `${field.label} is required` };
    if (typeof minLength === 'number' && value.length < minLength) {
      return { message: `${field.label} must be at least ${minLength} characters` };
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
    return ['secret'];
  }

  isStripped(field: FieldSchema): boolean {
    return (field.binding ?? 'stripped') === 'stripped';
  }

  async validateField(field: FieldSchema, encoded: unknown, _ctx: VerificationContext): Promise<FieldResult> {
    // Stripped secrets are validated cryptographically during signature verification,
    // before this point; here we only re-check the stored (inline) value.
    if (this.isStripped(field)) {
      return { name: field.name, state: 'valid', message: 'covered by signature (not stored)' };
    }
    const err = this.validateInput(field, encoded);
    return err ? { name: field.name, state: 'invalid', message: err.message } : { name: field.name, state: 'valid' };
  }
}
