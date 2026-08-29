import { readBoolRule, type FieldResult, type FieldSchema, type IFieldEngine, type VerificationContext } from './types.js';

/**
 * A select option with an optional color (used for presentation).
 */
export interface SelectV2Option {
  label: string;
  value: string;
  color?: string;
}

/**
 * SelectV2 field: a select whose options may carry an optional color. For QR
 * size optimization, only the *index* of the selected option is stored in the
 * SDoc — the full option details (label/value/color) live in the TCert schema
 * and are reconstructed at presentation time.
 *
 * The schema's `inputRules.options` is an array of `{ label, value, color? }`.
 */
export class SelectV2Field implements IFieldEngine {
  readonly type = 'selectv2' as const;

  private readOptions(field: FieldSchema): SelectV2Option[] {
    const raw = field.inputRules?.options;
    if (Array.isArray(raw)) {
      return raw
        .map((o) => {
          if (typeof o === 'string') return { label: o, value: o };
          if (typeof o === 'object' && o !== null) {
            const rec = o as Record<string, unknown>;
            const label = typeof rec.label === 'string' ? rec.label : String(rec.value ?? '');
            const value = typeof rec.value === 'string' ? rec.value : label;
            const color = typeof rec.color === 'string' ? rec.color : undefined;
            return { label, value, color };
          }
          return null;
        })
        .filter((o): o is SelectV2Option => o !== null);
    }
    return (field.options ?? []).map((o) => ({ label: o, value: o }));
  }

  validateInput(field: FieldSchema, value: unknown): { message: string } | null {
    // The input value is the option *index* (integer) — compact for QR.
    if (typeof value !== 'number' || !Number.isInteger(value)) {
      return { message: `${field.name} must be an option index (integer)` };
    }
    const options = this.readOptions(field);
    const required = readBoolRule(field.inputRules, 'required', false);
    if (required && options.length === 0) return { message: `${field.label} has no options` };
    if (value < 0 || value >= options.length) {
      return { message: `${field.label} must be a valid option index (0..${options.length - 1})` };
    }
    return null;
  }

  encode(_field: FieldSchema, value: unknown): unknown {
    return value;
  }

  decode(_field: FieldSchema, encoded: unknown): unknown {
    return encoded;
  }

  getContextRequirements(): [] {
    return [];
  }

  async validateField(field: FieldSchema, encoded: unknown, _ctx: VerificationContext): Promise<FieldResult> {
    const err = this.validateInput(field, encoded);
    return err ? { name: field.name, state: 'invalid', message: err.message } : { name: field.name, state: 'valid' };
  }
}