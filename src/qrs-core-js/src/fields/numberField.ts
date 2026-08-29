import { readBoolRule, readNumberRule, type FieldResult, type FieldSchema, type IFieldEngine, type VerificationContext } from './types.js';

/**
 * Canonical string form of a decimal value. Two floats with the same semantic
 * value always produce the same string (e.g. 12.50 -> "12.5"), so a decimal can
 * never have two cryptographically distinct encodings.
 */
export function canonicalDecimalString(value: number): string {
  const fixed = value.toFixed(10);
  const trimmed = fixed.replace(/0+$/, '').replace(/\.$/, '');
  return trimmed === '-0' ? '0' : trimmed;
}

export class NumberField implements IFieldEngine {
  readonly type = 'number' as const;

  validateInput(field: FieldSchema, value: unknown): { message: string } | null {
    if (typeof value !== 'number' || Number.isNaN(value)) {
      return { message: `${field.name} must be a number` };
    }
    const rules = field.inputRules ?? {};
    const min = rules.min;
    const max = rules.max;
    if (typeof min === 'number' && value < min) return { message: `${field.label} must be >= ${min}` };
    if (typeof max === 'number' && value > max) return { message: `${field.label} must be <= ${max}` };
    return null;
  }

  encode(_field: FieldSchema, value: unknown): unknown {
    const num = value as number;
    if (Number.isInteger(num) && Number.isSafeInteger(num)) return num;
    return canonicalDecimalString(num);
  }

  decode(_field: FieldSchema, encoded: unknown): unknown {
    if (typeof encoded === 'number') return encoded;
    if (typeof encoded === 'string') return Number(encoded);
    return encoded;
  }

  getContextRequirements(): [] {
    return [];
  }

  async validateField(field: FieldSchema, encoded: unknown, _ctx: VerificationContext): Promise<FieldResult> {
    const err = this.validateInput(field, this.decode(field, encoded));
    return err ? { name: field.name, state: 'invalid', message: err.message } : { name: field.name, state: 'valid' };
  }
}
