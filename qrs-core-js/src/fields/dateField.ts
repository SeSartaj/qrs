import type { FieldResult, FieldSchema, IFieldEngine, VerificationContext } from './types.js';
import { evaluateDateExpressions, type DateRuleInput } from './dateRules.js';
import { readStringArrayRule } from './types.js';

const DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

/** Validate a calendar date and its component values. */
export function isValidCalendarDate(value: string): boolean {
  const m = DATE_RE.exec(value);
  if (!m) return false;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const dt = new Date(Date.UTC(year, month - 1, day));
  return dt.getUTCFullYear() === year && dt.getUTCMonth() === month - 1 && dt.getUTCDate() === day;
}

export class DateField implements IFieldEngine {
  readonly type = 'date' as const;

  validateInput(field: FieldSchema, value: unknown): { message: string } | null {
    if (typeof value !== 'string' || !isValidCalendarDate(value)) {
      return { message: `${field.label} must be a valid date in YYYY-MM-DD form` };
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

  async validateField(field: FieldSchema, encoded: unknown, ctx: VerificationContext): Promise<FieldResult> {
    const err = this.validateInput(field, encoded);
    if (err) return { name: field.name, label: field.label, state: 'invalid', message: err.message };
    const rules = readStringArrayRule(field.verifyRules, 'expressions');
    if (rules.length > 0) {
      const [y, mo, d] = String(encoded).split('-').map(Number);
      if (y === undefined || mo === undefined || d === undefined) {
        return { name: field.name, label: field.label, state: 'invalid', message: 'malformed date value' };
      }
      const input: DateRuleInput = {
        now: new Date(ctx.getCurrentTime() * 1000),
        fieldYear: y,
        fieldMonth: mo,
        fieldDay: d,
        fieldTime: null,
      };
      const res = evaluateDateExpressions(rules, input);
      if (!res.ok) return { name: field.name, label: field.label, state: 'invalid', message: res.message };
    }
    return { name: field.name, label: field.label, state: 'valid' };
  }
}
