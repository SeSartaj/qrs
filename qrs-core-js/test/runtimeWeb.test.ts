import { describe, expect, it } from 'vitest';
import { createQrsWeb } from '../src/runtimeWeb.js';
import { DummyContextProvider } from '../src/context/dummyContext.js';
import { FixedClock } from './helpers.js';

const TIME = 1_700_000_000;

describe('createQrsWeb (WebCrypto runtime)', () => {
  it('issues and verifies an SDoc end-to-end using WebCrypto providers', async () => {
    const qrs = createQrsWeb({
      clock: new FixedClock(TIME),
      contextProvider: new DummyContextProvider({
        time: TIME,
        location: { lat: 34.5553, lon: 69.2075 },
        secrets: { owner_passcode: 's3cret' },
      }),
    });

    const tcert = await qrs.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [
        { type: 'text', name: 'pharmacy_name', label: 'Pharmacy Name', inputRules: { required: true } },
        { type: 'location', name: 'pharmacy_location', label: 'Location', verifyRules: { maxRadius: 50 } },
        { type: 'secretInput', name: 'owner_passcode', label: 'Owner Passcode' },
      ],
    });
    await qrs.trust.pin(tcert.tcertId);

    const issued = await qrs.signing.issueSdoc({
      tcertId: tcert.tcertId,
      issuedAt: TIME,
      values: {
        pharmacy_name: 'Ahmad Pharmacy',
        pharmacy_location: { lat: 34.5553, lon: 69.2075 },
        owner_passcode: 's3cret',
      },
    });

    const result = await qrs.verification.verify(issued.bytes, { currentTime: TIME + 100 });
    expect(result.overall).toBe('valid');
    expect(result.cryptographic).toBe('valid');
    expect(result.trust).toBe('valid');
  });

  it('also supports ECDSA P-256', async () => {
    const qrs = createQrsWeb({ clock: new FixedClock(TIME) });
    const tcert = await qrs.certificates.createTcert({
      algorithm: 'ECDSA-P256',
      name: 'AFDA',
      fields: [{ type: 'text', name: 'importer', label: 'Importer' }],
    });
    await qrs.trust.pin(tcert.tcertId);
    const issued = await qrs.signing.issueSdoc({ tcertId: tcert.tcertId, issuedAt: TIME, values: { importer: 'X' } });
    const result = await qrs.verification.verify(issued.bytes, { currentTime: TIME + 100 });
    expect(result.overall).toBe('valid');
  });
});
