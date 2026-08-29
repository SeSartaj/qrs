import { describe, expect, it } from 'vitest';
import { createQrs, DummyContextProvider, toBase64Url } from 'qrs-core';
import { decodeObject, toJsonSafe, verifyWithDetail } from '../src/main/objects.js';

describe('objects (dev decode + verify detail)', () => {
  it('toJsonSafe converts bytes, maps and nested structures', () => {
    expect(toJsonSafe(new Uint8Array([1, 2, 3]))).toEqual({ $bytes: '010203' });
    expect(toJsonSafe(new Map([['a', 1]]))).toEqual({ a: 1 });
    expect(toJsonSafe({ a: [new Uint8Array([0xff])], b: 'x' })).toEqual({ a: [{ $bytes: 'ff' }], b: 'x' });
    expect(toJsonSafe(42)).toBe(42);
    expect(toJsonSafe(null)).toBeNull();
  });

  it('decodes a TCert into its plaintext structure', async () => {
    const qrs = createQrs();
    const tcert = await qrs.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [{ type: 'text', name: 'name', label: 'Name' }],
    });
    const decoded = await decodeObject(toBase64Url(tcert.bytes));
    expect(decoded.type).toBe('tcert');
    expect(decoded.algorithm).toBe('Ed25519');
    expect(decoded.id).toBe(tcert.tcertId);
    const data = decoded.data as Record<string, unknown>;
    expect(Object.keys(data)).toContain('identity');
    expect((data.identity as { name: string }).name).toBe('AFDA');
    expect((data.schema as unknown[]).length).toBe(1);
  });

  it('verifyWithDetail returns result plus decoded values and issuer name', async () => {
    const qrs = createQrs({
      contextProvider: new DummyContextProvider({ secrets: { pin: '1234' } }),
    });
    const tcert = await qrs.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [
        { type: 'text', name: 'name', label: 'Name', inputRules: { required: true } },
        { type: 'secretInput', name: 'pin', label: 'PIN', binding: 'stripped' },
      ],
    });
    await qrs.trust.pin(tcert.tcertId);
    const issued = await qrs.signing.issueSdoc({
      tcertId: tcert.tcertId,
      values: { name: 'Ahmad Pharmacy', pin: '1234' },
    });

    const detail = await verifyWithDetail(qrs, toBase64Url(issued.bytes));
    expect(detail.result.overall).toBe('valid');
    expect(detail.sdocId).toBe(issued.sdocId);
    expect(detail.tcertId).toBe(tcert.tcertId);
    expect(detail.documentName).toBe('AFDA');
    expect(detail.values).toEqual([
      { name: 'name', label: 'Name', type: 'text', value: 'Ahmad Pharmacy' },
    ]);
    expect(detail.values?.some((v) => v.name === 'pin')).toBe(false);
  });

  it('verifyWithDetail reports invalid when a date rule fails', async () => {
    const qrs = createQrs({
      contextProvider: new DummyContextProvider({ time: 1_700_000_000 }), // 2023-11-14
    });
    const tcert = await qrs.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [
        { type: 'date', name: 'expiry', label: 'Expiry', verifyRules: { expressions: ['>today()'] } },
      ],
    });
    await qrs.trust.pin(tcert.tcertId);
    const issued = await qrs.signing.issueSdoc({
      tcertId: tcert.tcertId,
      values: { expiry: '2020-01-01' }, // already past
    });
    const detail = await verifyWithDetail(qrs, toBase64Url(issued.bytes), 1_700_000_000);
    expect(detail.result.overall).toBe('invalid');
    const field = detail.result.fields.find((f) => f.name === 'expiry');
    expect(field?.state).toBe('invalid');
    expect(field?.label).toBe('Expiry');
  });
});
