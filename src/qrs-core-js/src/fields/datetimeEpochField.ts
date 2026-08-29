import type { FieldResult, FieldSchema, IFieldEngine, VerificationContext } from './types.js';
import { evaluateDateExpressions, type DateRuleInput } from './dateRules.js';
import { readStringArrayRule } from './types.js';

/**
 * Datetime-epoch field: stores a UTC epoch (integer seconds) directly. This is
 * compact (a single integer) and timezone-agnostic on the wire. It is converted
 * to a human-readable local date/time only at presentation time.
 *
 * `verifyRules.expressions` (date rules) are evaluated against the epoch, so a
 * TCert can express e.g. `age() <= 14d` or `>today()`.
 */
export class DatetimeEpochField implements IFieldEngine {
  readonly type = 'datetimeEpoch' as const;

  validateInput(field: FieldSchema, value: unknown): { message: string } | null {
    if (typeof value !== 'number' || !Number.isInteger(value)) {
      return { message: `${field.label} must be an integer epoch (seconds)` };
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
    if (typeof encoded !== 'number' || !Number.isInteger(encoded)) {
      return { name: field.name, label: field.label, state: 'invalid', message: 'must be an integer epoch (seconds)' };
    }
    const rules = readStringArrayRule(field.verifyRules, 'expressions');
    if (rules.length > 0) {
      const dt = new Date(encoded * 1000);
      const input: DateRuleInput = {
        now: new Date(ctx.getCurrentTime() * 1000),
        fieldYear: dt.getUTCFullYear(),
        fieldMonth: dt.getUTCMonth() + 1,
        fieldDay: dt.getUTCDate(),
        fieldTime: { hour: dt.getUTCHours(), minute: dt.getUTCMinutes() },
        fieldEpoch: encoded,
      };
      const res = evaluateDateExpressions(rules, input);
      if (!res.ok) return { name: field.name, label: field.label, state: 'invalid', message: res.message };
    }
    return { name: field.name, label: field.label, state: 'valid' };
  }
}