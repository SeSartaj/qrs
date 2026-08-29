import type { FieldResult, FieldSchema, IFieldEngine, VerificationContext } from './types.js';
import { evaluateDateExpressions, type DateRuleInput } from './dateRules.js';
import { readStringArrayRule } from './types.js';

const DATETIME_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;

/** Validate a canonical UTC datetime string (YYYY-MM-DDTHH:mm:ssZ). */
export function isValidUtcDatetime(value: string): boolean {
  const m = DATETIME_RE.exec(value);
  if (!m) return false;
  const nums = m.map((x) => Number(x));
  const y = nums[1];
  const mo = nums[2];
  const d = nums[3];
  const h = nums[4];
  const mi = nums[5];
  const s = nums[6];
  if (
    y === undefined ||
    mo === undefined ||
    d === undefined ||
    h === undefined ||
    mi === undefined ||
    s === undefined
  ) {
    return false;
  }
  const dt = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
  return (
    dt.getUTCFullYear() === y &&
    dt.getUTCMonth() === mo - 1 &&
    dt.getUTCDate() === d &&
    dt.getUTCHours() === h &&
    dt.getUTCMinutes() === mi &&
    dt.getUTCSeconds() === s
  );
}

export class DateTimeField implements IFieldEngine {
  readonly type = 'datetime' as const;

  validateInput(field: FieldSchema, value: unknown): { message: string } | null {
    if (typeof value !== 'string' || !isValidUtcDatetime(value)) {
      return { message: `${field.label} must be a valid UTC datetime in YYYY-MM-DDTHH:mm:ssZ form` };
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
      const m = DATETIME_RE.exec(String(encoded));
      if (!m) return { name: field.name, label: field.label, state: 'invalid', message: 'malformed datetime value' };
      const nums = m.map((x) => Number(x));
      const y = nums[1];
      const mo = nums[2];
      const d = nums[3];
      const h = nums[4];
      const mi = nums[5];
      const s = nums[6];
      if (y === undefined || mo === undefined || d === undefined || h === undefined || mi === undefined || s === undefined) {
        return { name: field.name, label: field.label, state: 'invalid', message: 'malformed datetime value' };
      }
      const dt = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
      const input: DateRuleInput = {
        now: new Date(ctx.getCurrentTime() * 1000),
        fieldYear: dt.getFullYear(),
        fieldMonth: dt.getMonth() + 1,
        fieldDay: dt.getDate(),
        fieldTime: { hour: dt.getHours(), minute: dt.getMinutes() },
        fieldEpoch: Math.floor(dt.getTime() / 1000),
      };
      const res = evaluateDateExpressions(rules, input);
      if (!res.ok) return { name: field.name, label: field.label, state: 'invalid', message: res.message };
    }
    return { name: field.name, label: field.label, state: 'valid' };
  }
}
