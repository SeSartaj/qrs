import { describe, expect, it } from 'vitest';
import { evaluateDateExpressions } from '../src/fields/dateRules.js';
import type { FieldSchema } from '../src/fields/types.js';
import { makeRuntime } from './helpers.js';

const WEEKDAYS = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];

function input(year: number, month: number, day: number, time?: { hour: number; minute: number }) {
  return { now: new Date(2026, 7, 16, 10, 0, 0), fieldYear: year, fieldMonth: month, fieldDay: day, fieldTime: time ?? null };
}

describe('date rule evaluator', () => {
  it('compares the field date against today()', () => {
    expect(evaluateDateExpressions(['>today()'], input(2026, 8, 20)).ok).toBe(true);
    expect(evaluateDateExpressions(['>today()'], input(2026, 8, 10)).ok).toBe(false);
    expect(evaluateDateExpressions(['<today()'], input(2026, 8, 10)).ok).toBe(true);
    expect(evaluateDateExpressions(['==today()'], input(2026, 8, 16)).ok).toBe(true);
    expect(evaluateDateExpressions(['>=today()'], input(2026, 8, 16)).ok).toBe(true);
  });

  it('evaluates the day of week', () => {
    const d = new Date(2026, 7, 14);
    const actual = WEEKDAYS[d.getDay()];
    expect(evaluateDateExpressions([`day() == '${actual}'`], input(2026, 8, 14)).ok).toBe(true);
    const other = actual === 'friday' ? 'monday' : 'friday';
    const res = evaluateDateExpressions([`day() == '${other}'`], input(2026, 8, 14));
    expect(res.ok).toBe(false);
    expect(res.message).toBeDefined();
    expect(res.message).toContain(actual);
  });

  it('evaluates daytime (requires a datetime field)', () => {
    expect(evaluateDateExpressions(['daytime == \'night\''], input(2026, 8, 14, { hour: 21, minute: 0 })).ok).toBe(true);
    expect(evaluateDateExpressions(['daytime == \'night\''], input(2026, 8, 14, { hour: 10, minute: 0 })).ok).toBe(false);
    const res = evaluateDateExpressions(['daytime == \'night\''], input(2026, 8, 14));
    expect(res.ok).toBe(false);
    expect(res.message).toMatch(/datetime/);
  });

  it('evaluates time windows', () => {
    expect(evaluateDateExpressions(['16:00 < x < 23:00'], input(2026, 8, 14, { hour: 20, minute: 30 })).ok).toBe(true);
    expect(evaluateDateExpressions(['16:00 < x < 23:00'], input(2026, 8, 14, { hour: 12, minute: 0 })).ok).toBe(false);
    expect(evaluateDateExpressions(['x >= 09:00'], input(2026, 8, 14, { hour: 8, minute: 0 })).ok).toBe(false);
    expect(evaluateDateExpressions(['x >= 09:00'], input(2026, 8, 14, { hour: 10, minute: 0 })).ok).toBe(true);
  });

  it('rejects unknown rules', () => {
    expect(evaluateDateExpressions(['foo()'], input(2026, 8, 14)).ok).toBe(false);
  });

  it('evaluates age() against the field epoch', () => {
    const now = new Date(2026, 7, 16, 10, 0, 0);
    const nowEpoch = Math.floor(now.getTime() / 1000);
    const base = { now, fieldYear: 2026, fieldMonth: 8, fieldDay: 10, fieldTime: { hour: 10, minute: 0 } };
    expect(evaluateDateExpressions(['age() <= 14d'], { ...base, fieldEpoch: nowEpoch - 6 * 86_400 }).ok).toBe(true);
    expect(evaluateDateExpressions(['age() >= 14d'], { ...base, fieldEpoch: nowEpoch - 6 * 86_400 }).ok).toBe(false);
    expect(evaluateDateExpressions(['age() <= 14d'], { ...base, fieldEpoch: nowEpoch - 20 * 86_400 }).ok).toBe(false);
    expect(evaluateDateExpressions(['age() >= 2w'], { ...base, fieldEpoch: nowEpoch - 20 * 86_400 }).ok).toBe(true);
    const res = evaluateDateExpressions(['age() <= 14d'], base);
    expect(res.ok).toBe(false);
    expect(res.message).toMatch(/datetime/);
  });
});

describe('date rules in the verification pipeline', () => {
  it('rejects an SDoc whose expiry date is already past (>today())', async () => {
    const runtime = makeRuntime({ time: 1_700_000_000 }); // 2023-11-14
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [
        { type: 'date', name: 'expiry', label: 'Expiry', verifyRules: { expressions: ['>today()'] } },
      ],
    });
    await runtime.trust.pin(tcert.tcertId);
    const issued = await runtime.signing.issueSdoc({
      tcertId: tcert.tcertId,
      issuedAt: 1_700_000_000,
      values: { expiry: '2023-01-01' }, // already past
    });
    const result = await runtime.verification.verify(issued.bytes, { currentTime: 1_700_000_000 });
    expect(result.overall).toBe('invalid');
    const field = result.fields.find((f) => f.name === 'expiry');
    expect(field?.state).toBe('invalid');
    expect(field?.message).toMatch(/today/);
    expect(field?.label).toBe('Expiry');
  });

  it('accepts an SDoc whose expiry date is still in the future', async () => {
    const runtime = makeRuntime({ time: 1_700_000_000 });
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [{ type: 'date', name: 'expiry', label: 'Expiry', verifyRules: { expressions: ['>today()'] } }],
    });
    await runtime.trust.pin(tcert.tcertId);
    const issued = await runtime.signing.issueSdoc({
      tcertId: tcert.tcertId,
      issuedAt: 1_700_000_000,
      values: { expiry: '2027-12-29' },
    });
    const result = await runtime.verification.verify(issued.bytes, { currentTime: 1_700_000_000 });
    expect(result.overall).toBe('valid');
  });

  it('enforces a validity duration via a hidden issued_at datetime field (default now + age rule)', async () => {
    const later = 1_700_000_000 + 15 * 86_400; // 15 days after the fixed issue time
    async function issuePermit(runtime: ReturnType<typeof makeRuntime>) {
      const tcert = await runtime.certificates.createTcert({
        algorithm: 'Ed25519',
        name: 'AFDA',
        fields: [
          { type: 'text', name: 'holder', label: 'Holder' },
          {
            type: 'datetime',
            name: 'issued_at',
            label: 'Issued At',
            default: { kind: 'now' },
            verifyRules: { expressions: ['age() <= 14d'] },
          },
        ],
      });
      await runtime.trust.pin(tcert.tcertId);
      return runtime.signing.issueSdoc({
        tcertId: tcert.tcertId,
        issuedAt: 1_700_000_000,
        values: { holder: 'Ahmad' }, // issued_at is hidden and defaulted to now
      });
    }

    // Fresh (same instant): the document is within its validity duration.
    const fresh = makeRuntime({ time: 1_700_000_000 });
    const freshIssued = await issuePermit(fresh);
    let result = await fresh.verification.verify(freshIssued.bytes, { currentTime: 1_700_000_000 });
    expect(result.overall).toBe('valid');

    // Fifteen days later: the document is now too old.
    const aged = makeRuntime({ time: later });
    const agedIssued = await issuePermit(aged);
    result = await aged.verification.verify(agedIssued.bytes, { currentTime: later });
    expect(result.overall).toBe('invalid');
    const field = result.fields.find((f) => f.name === 'issued_at');
    expect(field?.state).toBe('invalid');
    expect(field?.message).toMatch(/age\(\)/);
  });

  it('keeps the SDoc minimal: stored values are a schema-indexed array without names', async () => {
    const runtime = makeRuntime({ time: 1_700_000_000 });
    const schema: FieldSchema[] = [
      { type: 'text', name: 'pharmacy_name', label: 'Pharmacy Name' },
      { type: 'date', name: 'expiry', label: 'Expiry Date' },
    ];
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: schema,
    });
    const issued = await runtime.signing.issueSdoc({
      tcertId: tcert.tcertId,
      issuedAt: 1_700_000_000,
      values: { pharmacy_name: 'Ahmad Pharmacy', expiry: '2027-12-29' },
    });
    const parsed = await import('../src/signedObject/signedObject.js').then((m) => m.parseSignedObject(issued.bytes));
    const stored = parsed.data.fields as unknown[];
    expect(stored).toEqual(['Ahmad Pharmacy', '2027-12-29']);
    // Field names and labels must NOT appear in the SDoc bytes.
    const text = JSON.stringify(issued.bytes);
    expect(text).not.toContain('pharmacy_name');
    expect(text).not.toContain('Pharmacy Name');
    expect(text).not.toContain('expiry');
    expect(text).not.toContain('Expiry Date');
  });
});
