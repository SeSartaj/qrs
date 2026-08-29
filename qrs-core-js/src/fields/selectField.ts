import { readBoolRule, readStringArrayRule, type FieldResult, type FieldSchema, type IFieldEngine, type VerificationContext } from './types.js';

export class SelectField implements IFieldEngine {
  readonly type = 'select' as const;

  validateInput(field: FieldSchema, value: unknown): { message: string } | null {
    if (typeof value !== 'string') return { message: `${field.name} must be a string` };
    const required = readBoolRule(field.inputRules, 'required', false);
    const options = readStringArrayRule(field.inputRules, 'options', field.options ?? []);
    if (required && value.length === 0) return { message: `${field.label} is required` };
    if (options.length > 0 && !options.includes(value)) {
      return { message: `${field.label} must be one of: ${options.join(', ')}` };
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
