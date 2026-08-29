import { describe, expect, it } from 'vitest';
import {
  createQrs,
  decodeBundle,
  decodeQrsFile,
  decodeTransferPayload,
  encodeBundle,
  encodeQrsBundleFile,
  encodeQrsFile,
  encodeTransferPayload,
  fromBase64Url,
  toBase64Url,
  type IClock,
} from '../src/index.js';

class FixedClock implements IClock {
  constructor(private t: number) {}
  now(): number {
    return this.t;
  }
}

const T0 = 1_700_000_000; // 2023-11-14 UTC
const YEAR = 31_536_000;

async function makeValidTcert(qrs: ReturnType<typeof createQrs>) {
  return qrs.certificates.createTcert({
    algorithm: 'Ed25519',
    name: 'Issuer',
    fields: [{ type: 'text', name: 'name', label: 'Name', inputRules: { required: true } }],
    validAfter: T0,
    validBefore: T0 + 5 * YEAR,
  });
}

describe('SDoc validity via schema date fields (no external validity block)', () => {
  it('enforces an expiry date field with a >today() rule', async () => {
    const qrs = createQrs({ clock: new FixedClock(T0 + 100) });
    const tcert = await qrs.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'Issuer',
      fields: [{ type: 'date', name: 'valid_before', label: 'Valid Before', verifyRules: { expressions: ['>today()'] } }],
    });
    await qrs.trust.pin(tcert.tcertId);

    const future = await qrs.signing.issueSdoc({
      tcertId: tcert.tcertId,
      issuedAt: T0 + 100,
      values: { valid_before: '2027-12-29' },
    });
    expect((await qrs.verification.verify(future.bytes, { currentTime: T0 + 100 })).overall).toBe('valid');

    const past = await qrs.signing.issueSdoc({
      tcertId: tcert.tcertId,
      issuedAt: T0 + 100,
      values: { valid_before: '2023-01-01' },
    });
    const r = await qrs.verification.verify(past.bytes, { currentTime: T0 + 100 });
    expect(r.overall).toBe('invalid');
    expect(r.fields.find((f) => f.name === 'valid_before')?.state).toBe('invalid');
  });

  it('does not store a validity map on the SDoc', async () => {
    const qrs = createQrs({ clock: new FixedClock(T0 + 100) });
    const tcert = await makeValidTcert(qrs);
    const issued = await qrs.signing.issueSdoc({ tcertId: tcert.tcertId, values: { name: 'X' } });
    const parsed = await import('../src/signedObject/signedObject.js').then((m) => m.parseSignedObject(issued.bytes));
    expect((parsed.data as Record<string, unknown>).validity).toBeUndefined();
  });
});

describe('issue-time TCert validity check', () => {
  it('refuses to issue an SDoc under an expired TCert', async () => {
    const qrs = createQrs({ clock: new FixedClock(T0 + 100) });
    const tcert = await makeValidTcert(qrs); // expires at T0 + 5y
    await expect(
      qrs.signing.issueSdoc({ tcertId: tcert.tcertId, values: { name: 'X' }, issuedAt: T0 + 6 * YEAR })
    ).rejects.toThrow(/expired/i);
  });

  it('refuses to issue under a TCert that is not yet valid', async () => {
    const qrs = createQrs({ clock: new FixedClock(T0 + 100) });
    const tcert = await makeValidTcert(qrs); // validAfter T0
    await expect(
      qrs.signing.issueSdoc({ tcertId: tcert.tcertId, values: { name: 'X' }, issuedAt: T0 - 10 })
    ).rejects.toThrow(/not yet valid/i);
  });
});

describe('transfer envelope (QR payload)', () => {
  it('round-trips a TCert payload', async () => {
    const qrs = createQrs();
    const tcert = await makeValidTcert(qrs);
    const b64 = toBase64Url(tcert.bytes);
    const payload = encodeTransferPayload('tcert', b64);
    expect(payload.startsWith('qrs://v1/tcert/')).toBe(true);
    const decoded = decodeTransferPayload(payload);
    expect(decoded).not.toBeNull();
    expect(decoded!.type).toBe('tcert');
    expect(decoded!.bytesB64).toBe(b64);
    expect(fromBase64Url(decoded!.bytesB64)).toEqual(tcert.bytes);
  });

  it('supports sdoc and statement types', () => {
    expect(decodeTransferPayload(encodeTransferPayload('sdoc', 'abc'))?.type).toBe('sdoc');
    expect(decodeTransferPayload(encodeTransferPayload('statement', 'abc'))?.type).toBe('statement');
  });

  it('rejects unknown or malformed payloads', () => {
    expect(decodeTransferPayload('https://example.com/x')).toBeNull();
    expect(decodeTransferPayload('qrs://v1/unknown/abc')).toBeNull();
    expect(decodeTransferPayload('qrs://v1/tcert/')).toBeNull();
    expect(decodeTransferPayload('')).toBeNull();
  });

  it('bundles several signed objects (e.g. TCert + attestation) and round-trips', () => {
    const bundle = encodeBundle([
      { type: 'tcert', bytesB64: 'tcert-b64' },
      { type: 'statement', bytesB64: 'stmt-b64' },
      { type: 'sdoc', bytesB64: 'sdoc-b64' },
    ]);
    expect(bundle.startsWith('qrs://v1/bundle/')).toBe(true);
    const decoded = decodeBundle(bundle);
    expect(decoded?.objects).toEqual([
      { type: 'tcert', bytesB64: 'tcert-b64' },
      { type: 'statement', bytesB64: 'stmt-b64' },
      { type: 'sdoc', bytesB64: 'sdoc-b64' },
    ]);
    // A single-object envelope is not a bundle, and vice versa.
    expect(decodeBundle(encodeTransferPayload('tcert', 'x'))).toBeNull();
    expect(decodeTransferPayload(bundle)).toBeNull();
    expect(decodeBundle('garbage')).toBeNull();
  });
});

describe('.qrs file container', () => {
  it('round-trips a single signed object as UTF-8 payload text', async () => {
    const qrs = createQrs();
    const tcert = await makeValidTcert(qrs);
    const b64 = toBase64Url(tcert.bytes);

    const fileBytes = encodeQrsFile('tcert', b64);
    const text = new TextDecoder().decode(fileBytes);
    expect(text.startsWith('qrs://v1/tcert/')).toBe(true);

    const decoded = decodeQrsFile(text);
    expect(decoded).not.toBeNull();
    expect(decoded!.kind).toBe('object');
    if (decoded!.kind === 'object') {
      expect(decoded!.payload.type).toBe('tcert');
      expect(decoded!.payload.bytesB64).toBe(b64);
      expect(fromBase64Url(decoded!.payload.bytesB64)).toEqual(tcert.bytes);
    }
  });

  it('round-trips a bundle of signed objects', () => {
    const objects = [
      { type: 'tcert' as const, bytesB64: 'tcert-b64' },
      { type: 'statement' as const, bytesB64: 'stmt-b64' },
    ];
    const fileBytes = encodeQrsBundleFile(objects);
    const decoded = decodeQrsFile(new TextDecoder().decode(fileBytes));
    expect(decoded?.kind).toBe('bundle');
    if (decoded?.kind === 'bundle') expect(decoded.objects).toEqual(objects);
  });

  it('returns null for non-QRS text and rejects the wrong type', () => {
    expect(decodeQrsFile('https://example.com')).toBeNull();
    expect(decodeQrsFile('')).toBeNull();
    const bad = decodeQrsFile(encodeQrsFile('tcert', 'x').length ? new TextDecoder().decode(encodeQrsFile('tcert', 'x')) : '');
    expect(bad?.kind).toBe('object');
    if (bad?.kind === 'object') expect(bad.payload.type).toBe('tcert');
  });
});
