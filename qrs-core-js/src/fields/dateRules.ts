/**
 * Date / datetime verification rules.
 *
 * A date or datetime field in the schema may carry `verifyRules.expressions` — a
 * list of small, human-readable rules evaluated at verification time against the
 * field's value and the verifier's current local time. All rules must pass (AND).
 *
 * Supported expressions (one per array entry):
 *
 *   `<today()`   `<=today()`   `>today()`   `>=today()`   `==today()`
 *       — the field's date is before/on/after today (local calendar date).
 *   `day() == 'friday'`   `day() != 'friday'`
 *       — the field's weekday (lowercase english: monday..sunday).
 *   `daytime == 'day'`   `daytime == 'night'`
 *       — the field's local time-of-day (day = 06:00–17:59, night = 18:00–05:59).
 *         Requires a datetime field.
 *   `16:00 < x < 23:00`   `x >= 09:00`
 *       — the field's local clock time in a window. Requires a datetime field.
 *   `age() <= 14d`   `age() >= 2w`   `age() < 1m`   `age() == 0h`
 *       — how old the field's datetime is at verification time (units: m/h/d/w).
 *         Requires a datetime field (the age is measured against the UTC epoch).
 *
 * This lets a verifier express things like "the document's expiry date must still
 * be in the future" (`>today()`), "valid only on Fridays" (`day() == 'friday'`),
 * "only valid between 4 PM and 11 PM local time" (`16:00 < x < 23:00`), or "issued
 * no more than two weeks ago" (`age() <= 14d`).
 */
export interface DateRuleInput {
  /** The verifier's current local time. */
  now: Date;
  /** The field's date components (local). */
  fieldYear: number;
  fieldMonth: number; // 1..12
  fieldDay: number;
  /** Local clock time for datetime fields; `null` for date-only fields. */
  fieldTime: { hour: number; minute: number } | null;
  /** UTC epoch seconds of a datetime field (used by `age()`). */
  fieldEpoch?: number;
}

export interface DateRuleResult {
  ok: boolean;
  message?: string;
}

const WEEKDAYS = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];

const pad = (n: number): string => String(n).padStart(2, '0');
const dateKey = (y: number, m: number, d: number): string => `${y}-${pad(m)}-${pad(d)}`;
const todayKey = (d: Date): string => dateKey(d.getFullYear(), d.getMonth() + 1, d.getDate());

function cmpNums(a: number, b: number, op: string): boolean {
  switch (op) {
    case '<':
      return a < b;
    case '<=':
      return a <= b;
    case '>':
      return a > b;
    case '>=':
      return a >= b;
    case '==':
      return a === b;
    case '!=':
      return a !== b;
    default:
      return false;
  }
}

/** Flip a comparison operator (used when reversing `lo < x` into `x > lo`). */
function flipOp(op: string): string {
  switch (op) {
    case '<':
      return '>';
    case '<=':
      return '>=';
    case '>':
      return '<';
    case '>=':
      return '<=';
    default:
      return op;
  }
}

/** Evaluate a list of expressions (all must pass). */
export function evaluateDateExpressions(expressions: string[], input: DateRuleInput): DateRuleResult {
  for (const raw of expressions) {
    const expr = raw.trim();
    if (!expr) continue;
    const res = evaluateOne(expr, input);
    if (!res.ok) return res;
  }
  return { ok: true };
}

function evaluateOne(expr: string, input: DateRuleInput): DateRuleResult {
  /* today() comparisons */
  const mToday = /^(<=|>=|<|>|==|!=)\s*today\(\)$/.exec(expr);
  if (mToday) {
    const a = dateKey(input.fieldYear, input.fieldMonth, input.fieldDay);
    const b = todayKey(input.now);
    const cmp = a === b ? 0 : a < b ? -1 : 1;
    const ok = cmpNums(cmp, 0, mToday[1] ?? '');
    if (!ok) return { ok: false, message: `rule '${expr}' failed: field ${a} vs today ${b}` };
    return { ok: true };
  }

  /* day() == 'friday' */
  const mDay = /^day\(\)\s*(==|!=)\s*'([a-z]+)'$/.exec(expr);
  if (mDay) {
    const expected = mDay[2];
    const actual = WEEKDAYS[new Date(input.fieldYear, input.fieldMonth - 1, input.fieldDay).getDay()];
    const eq = actual === expected;
    if ((mDay[1] === '==' && !eq) || (mDay[1] === '!=' && eq)) {
      return { ok: false, message: `rule '${expr}' failed: field falls on ${actual}` };
    }
    return { ok: true };
  }

  /* daytime == 'day' | 'night' */
  const mDaytime = /^daytime\s*==\s*'(day|night)'$/.exec(expr);
  if (mDaytime) {
    if (!input.fieldTime) return { ok: false, message: `rule '${expr}' requires a datetime field` };
    const actual = input.fieldTime.hour >= 6 && input.fieldTime.hour < 18 ? 'day' : 'night';
    if (actual !== mDaytime[1]) {
      return { ok: false, message: `rule '${expr}' failed: it is ${actual}` };
    }
    return { ok: true };
  }

  /* two-sided time window: 16:00 < x < 23:00 */
  const mTwo = /^(\d{1,2}):(\d{2})\s*(<=|>=|<|>)\s*x\s*(<=|>=|<|>)\s*(\d{1,2}):(\d{2})$/.exec(expr);
  if (mTwo) {
    if (!input.fieldTime) return { ok: false, message: `rule '${expr}' requires a datetime field` };
    const x = input.fieldTime.hour * 60 + input.fieldTime.minute;
    const lo = Number(mTwo[1] ?? 0) * 60 + Number(mTwo[2] ?? 0);
    const hi = Number(mTwo[5] ?? 0) * 60 + Number(mTwo[6] ?? 0);
    // `16:00 < x` means x > 16:00, so the left operator is flipped for x comparisons.
    if (!cmpNums(x, lo, flipOp(mTwo[3] ?? '')) || !cmpNums(x, hi, mTwo[4] ?? '')) {
      const h = pad(input.fieldTime.hour);
      const mi = pad(input.fieldTime.minute);
      return { ok: false, message: `rule '${expr}' failed: time is ${h}:${mi}` };
    }
    return { ok: true };
  }

  /* one-sided time: x < 09:00 */
  const mOne = /^x\s*(<=|>=|<|>)\s*(\d{1,2}):(\d{2})$/.exec(expr);
  if (mOne) {
    if (!input.fieldTime) return { ok: false, message: `rule '${expr}' requires a datetime field` };
    const x = input.fieldTime.hour * 60 + input.fieldTime.minute;
    const bound = Number(mOne[2] ?? 0) * 60 + Number(mOne[3] ?? 0);
    if (!cmpNums(x, bound, mOne[1] ?? '')) {
      const h = pad(input.fieldTime.hour);
      const mi = pad(input.fieldTime.minute);
      return { ok: false, message: `rule '${expr}' failed: time is ${h}:${mi}` };
    }
    return { ok: true };
  }

  /* age(): age() <= 14d | >= 2w | < 1m | == 0h */
  const mAge = /^age\(\)\s*(<=|>=|<|>|==)\s*(\d+)\s*(m|h|d|w)$/.exec(expr);
  if (mAge) {
    if (input.fieldEpoch === undefined) {
      return { ok: false, message: `rule '${expr}' requires a datetime field` };
    }
    const unitSecs = { m: 60, h: 3_600, d: 86_400, w: 604_800 }[mAge[3] ?? 'd'] ?? 86_400;
    const nowSecs = Math.floor(input.now.getTime() / 1000);
    const ageUnits = (nowSecs - input.fieldEpoch) / unitSecs;
    const bound = Number(mAge[2] ?? 0);
    if (!cmpNums(ageUnits, bound, mAge[1] ?? '')) {
      return { ok: false, message: `rule '${expr}' failed: document is ${ageUnits.toFixed(1)} ${mAge[3]} old` };
    }
    return { ok: true };
  }

  return { ok: false, message: `unknown date rule '${expr}'` };
}
