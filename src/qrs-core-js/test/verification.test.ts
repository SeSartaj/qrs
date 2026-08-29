import { describe, expect, it } from 'vitest';
import { sha256, toHex } from '../src/id.js';
import { KABUL, makeRuntime, pharmacySchema } from './helpers.js';

const TIME = 1_700_000_000;

async function setup(opts: { location?: { lat: number; lon: number } | null; secrets?: Record<string, string> } = {}) {
  // `undefined` means "use the default Kabul location"; `null` means "no location".
  const location = opts.location === undefined ? KABUL : opts.location;
  const secrets = opts.secrets ?? { owner_passcode: 's3cret' };
  const runtime = makeRuntime({ time: TIME, location, secrets });
  const tcert = await runtime.certificates.createTcert({
    algorithm: 'Ed25519',
    name: 'AFDA',
    fields: pharmacySchema(),
  });
  await runtime.trust.pin(tcert.tcertId);
  const issued = await runtime.signing.issueSdoc({
    tcertId: tcert.tcertId,
    issuedAt: TIME,
    values: {
      pharmacy_name: 'Ahmad Pharmacy',
      category: 'category_1',
      issue_date: '2025-01-15',
      expiry_date: '2027-12-29',
      pharmacy_location: { lat: KABUL.lat, lon: KABUL.lon },
      owner_passcode: 's3cret',
    },
  });
  return { runtime, tcert, issued };
}

describe('verification pipeline', () => {
  it('reports invalid for tampered bytes', async () => {
    const { runtime, issued } = await setup();
    const tampered = new Uint8Array(issued.bytes);
    const idx = Math.floor(tampered.length / 2);
    tampered[idx] = (tampered[idx] ?? 0) ^ 0xff;
    const result = await runtime.verification.verify(tampered, { currentTime: TIME + 100 });
    expect(result.overall).toBe('invalid');
  });

  it('reports invalid when the wrong secret is supplied', async () => {
    const { runtime, issued } = await setup({ secrets: { owner_passcode: 'wrong' } });
    const result = await runtime.verification.verify(issued.bytes, { currentTime: TIME + 100 });
    expect(result.cryptographic).toBe('invalid');
    expect(result.overall).toBe('invalid');
  });

  it('reports cannotVerify when the secret is missing', async () => {
    const { runtime, issued } = await setup({ secrets: {} });
    const result = await runtime.verification.verify(issued.bytes, { currentTime: TIME + 100 });
    expect(result.overall).toBe('cannotVerify');
    expect(result.warnings.some((w) => w.includes('owner_passcode'))).toBe(true);
  });

  it('reports invalid when the verifier is outside the permitted area', async () => {
    const { runtime, issued } = await setup({ location: { lat: 35.0, lon: 69.2 } });
    const result = await runtime.verification.verify(issued.bytes, { currentTime: TIME + 100 });
    const loc = result.fields.find((f) => f.name === 'pharmacy_location');
    expect(loc?.state).toBe('invalid');
    expect(result.overall).toBe('invalid');
  });

  it('reports cannotVerify (not invalid) when location is unavailable', async () => {
    const { runtime, issued } = await setup({ location: null });
    const result = await runtime.verification.verify(issued.bytes, { currentTime: TIME + 100 });
    const loc = result.fields.find((f) => f.name === 'pharmacy_location');
    expect(loc?.state).toBe('cannotVerify');
    expect(result.overall).toBe('cannotVerify');
  });

  it('reports invalid for an expired TCert', async () => {
    const runtime = makeRuntime({ time: TIME });
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'X',
      fields: [{ type: 'text', name: 'v', label: 'V' }],
      validBefore: TIME - 1,
    });
    await runtime.trust.pin(tcert.tcertId);
    const issued = await runtime.signing.issueSdoc({ tcertId: tcert.tcertId, issuedAt: TIME - 10, values: { v: 'x' } });
    const result = await runtime.verification.verify(issued.bytes, { currentTime: TIME });
    expect(result.tcert).toBe('invalid');
    expect(result.overall).toBe('invalid');
  });

  it('reports cannotVerify when the TCert is not known to the verifier', async () => {
    const { issued } = await setup();
    const other = makeRuntime({ time: TIME }); // empty store, never saw this TCert
    const result = await other.verification.verify(issued.bytes, { currentTime: TIME });
    expect(result.tcert).toBe('cannotVerify');
    expect(result.overall).toBe('cannotVerify');
  });

  it('rejects verifying a non-SDoc object', async () => {
    const runtime = makeRuntime();
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'X',
      fields: [],
    });
    const result = await runtime.verification.verify(tcert.bytes);
    expect(result.overall).toBe('invalid');
  });
});

describe('attachment verification (hash-only reference)', () => {
  const content = new TextEncoder().encode('photo-bytes');
  const hash = toHex(sha256(content)).slice(0, 32);

  async function setup() {
    const rt = makeRuntime({ time: TIME });
    const tcert = await rt.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [{ type: 'attachment', name: 'photo', label: 'Photo', inputRules: { contentType: 'image/png' } }],
    });
    await rt.trust.pin(tcert.tcertId);
    return { rt, tcert };
  }

  it('validates the hash-only reference and stays valid without downloading', async () => {
    const { rt, tcert } = await setup();
    const ref = hash;
    const issued = await rt.signing.issueSdoc({ tcertId: tcert.tcertId, issuedAt: TIME, values: { photo: ref } });
    const result = await rt.verification.verify(issued.bytes, { currentTime: TIME });
    const photo = result.fields.find((f) => f.name === 'photo');
    // No network fetch — offline first. The reference is structurally valid.
    expect(photo?.state).toBe('valid');
    expect(result.overall).toBe('valid');
  });

  it('rejects a malformed attachment reference at signing time', async () => {
    const { rt, tcert } = await setup();
    await expect(
      rt.signing.issueSdoc({ tcertId: tcert.tcertId, issuedAt: TIME, values: { photo: { hash: 'nope', size: 1 } } })
    ).rejects.toThrow(/valid content hash/);
  });
});

