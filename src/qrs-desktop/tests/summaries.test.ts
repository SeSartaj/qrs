import { describe, expect, it } from 'vitest';
import { createQrs } from 'qrs-core';
import { listDocuments, summarizeDocument, summarizeTcert } from '../src/main/summaries.js';

describe('summaries (main-process DTO builders)', () => {
  it('summarises a created TCert including trust state', async () => {
    const qrs = createQrs();
    const result = await qrs.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'Afghanistan FDA',
      fields: [
        { type: 'text', name: 'pharmacy_name', label: 'Pharmacy Name', inputRules: { required: true } },
        { type: 'location', name: 'pharmacy_location', label: 'Location', verifyRules: { maxRadius: 50 } },
        { type: 'secretInput', name: 'owner_passcode', label: 'Owner Passcode', binding: 'stripped' },
      ],
    });

    const summary = await summarizeTcert(qrs, result.bytes);
    expect(summary.tcertId).toBe(result.tcertId);
    expect(summary.keyId).toBe(result.keyId);
    expect(summary.name).toBe('Afghanistan FDA');
    expect(summary.algorithm).toBe('Ed25519');
    expect(summary.fields.map((f) => f.name)).toEqual([
      'pharmacy_name',
      'pharmacy_location',
      'owner_passcode',
    ]);
    expect(summary.pinned).toBe(false);
    expect(summary.revoked).toBeUndefined();
    expect(summary.bytesB64.length).toBeGreaterThan(0);
  });

  it('reflects pinning in the trust state', async () => {
    const qrs = createQrs();
    const result = await qrs.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'Issuer',
      fields: [{ type: 'text', name: 'name', label: 'Name' }],
    });
    await qrs.trust.pin(result.tcertId);

    const summary = await summarizeTcert(qrs, result.bytes);
    expect(summary.pinned).toBe(true);
  });

  it('summarises an issued SDoc and decodes its stored values', async () => {
    const qrs = createQrs();
    const tcert = await qrs.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'Afghanistan FDA',
      fields: [
        { type: 'text', name: 'pharmacy_name', label: 'Pharmacy Name' },
        { type: 'number', name: 'score', label: 'Score' },
        { type: 'location', name: 'pharmacy_location', label: 'Location', verifyRules: { maxRadius: 50 } },
        { type: 'secretInput', name: 'owner_passcode', label: 'Owner Passcode', binding: 'stripped' },
      ],
    });

    const issued = await qrs.signing.issueSdoc({
      tcertId: tcert.tcertId,
      values: {
        pharmacy_name: 'Ahmad Pharmacy',
        score: 42,
        pharmacy_location: { lat: 34.5553, lon: 69.2075 },
        owner_passcode: 's3cret',
      },
    });

    const summary = await summarizeDocument(qrs, issued.bytes);
    expect(summary.sdocId).toBe(issued.sdocId);
    expect(summary.tcertId).toBe(tcert.tcertId);
    expect(summary.sizeBytes).toBe(issued.bytes.byteLength);
    expect(summary.blocked).toBeUndefined();
    // Values are decoded back to presentable form, in schema order, with labels.
    expect(summary.values).toEqual([
      { name: 'pharmacy_name', label: 'Pharmacy Name', type: 'text', value: 'Ahmad Pharmacy' },
      { name: 'score', label: 'Score', type: 'number', value: 42 },
      { name: 'pharmacy_location', label: 'Location', type: 'location', value: { lat: 34.5553, lon: 69.2075 } },
    ]);
    // The stripped secret is NOT stored, so it must not appear in decoded values.
    expect(summary.values?.some((v) => v.name === 'owner_passcode')).toBe(false);
  });

  it('rejects non-TCert bytes', async () => {
    const qrs = createQrs();
    const tcert = await qrs.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'A',
      fields: [],
    });
    await expect(summarizeTcert(qrs, tcert.bytes)).resolves.toBeTruthy();
    await expect(summarizeDocument(qrs, tcert.bytes)).rejects.toThrow('not an SDoc');
  });

  it('listDocuments skips old-format SDocs instead of failing the whole list', async () => {
    const qrs = createQrs();
    const tcert = await qrs.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [{ type: 'text', name: 'name', label: 'Name' }],
    });
    const valid = await qrs.signing.issueSdoc({ tcertId: tcert.tcertId, values: { name: 'Ahmad' } });

    // Save a corrupt / old-format (map-fields) object alongside the valid one.
    await qrs.deps.documentStore.save('deadbeefdeadbeefdeadbeefdeadbeef', new Uint8Array([1, 2, 3, 4]));

    const docs = await listDocuments(qrs);
    expect(docs).toHaveLength(1);
    expect(docs[0]?.sdocId).toBe(valid.sdocId);
    expect(docs[0]?.documentName).toBe('AFDA');
  });
});
