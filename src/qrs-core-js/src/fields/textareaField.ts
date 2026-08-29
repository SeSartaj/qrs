import { readBoolRule, readNumberRule, type FieldResult, type FieldSchema, type IFieldEngine, type VerificationContext } from './types.js';
import { codePointLength } from './textField.js';

/**
 * Textarea field: multi-line text. Semantically identical to `text` but intended
 * for longer, multi-line content. Stored as a plain string (NFC-normalized).
 */
export class TextareaField implements IFieldEngine {
  readonly type = 'textarea' as const;

  validateInput(field: FieldSchema, value: unknown): { message: string } | null {
    if (typeof value !== 'string') return { message: `${field.name} must be a string` };
    const rules = field.inputRules ?? {};
    const required = readBoolRule(rules, 'required', false);
    const minLength = readNumberRule(rules, 'minLength', 0);
    const maxLength = readNumberRule(rules, 'maxLength', Number.POSITIVE_INFINITY);
    const len = codePointLength(value);
    if (required && len === 0) return { message: `${field.label} is required` };
    if (len < minLength) return { message: `${field.label} must be at least ${minLength} characters` };
    if (len > maxLength) return { message: `${field.label} must be at most ${maxLength} characters` };
    return null;
  }

  encode(_field: FieldSchema, value: unknown): unknown {
    return (value as string).normalize('NFC');
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