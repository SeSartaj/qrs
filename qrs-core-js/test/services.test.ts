import { describe, expect, it } from 'vitest';
import { toHex } from '../src/id.js';
import { parseSignedObject } from '../src/signedObject/signedObject.js';
import type { AlgorithmId } from '../src/types.js';
import { KABUL, makeRuntime, pharmacySchema } from './helpers.js';

const ALGORITHMS: AlgorithmId[] = ['Ed25519', 'ECDSA-P256'];

for (const algorithm of ALGORITHMS) {
  describe(`services with ${algorithm}`, () => {
    it('creates a self-signed TCert whose self-signature verifies', async () => {
      const runtime = makeRuntime();
      const tcert = await runtime.certificates.createTcert({
        algorithm,
        name: 'AFDA',
        fields: pharmacySchema(),
      });
      expect(tcert.tcertId).toMatch(/^[0-9a-f]{32}:\d+$/);
      expect(tcert.certificateNumber).toBe(1);
      expect(toHex(tcert.parsed.data.keyId as Uint8Array)).toBe(tcert.keyId);

      // A second TCert under the same key gets the next certificate number.
      const second = await runtime.certificates.createTcert({
        algorithm,
        name: 'AFDA',
        fields: [{ type: 'text', name: 'importer', label: 'Importer' }],
        keyId: tcert.keyId,
      });
      expect(second.certificateNumber).toBe(2);
      expect(second.keyId).toBe(tcert.keyId);
    });

    it('issues an SDoc and verifies it as valid (with secret + location)', async () => {
      const runtime = makeRuntime({
        time: 1_700_000_000,
        location: KABUL,
        secrets: { owner_passcode: 's3cret' },
      });
      const tcert = await runtime.certificates.createTcert({
        algorithm,
        name: 'AFDA',
        fields: pharmacySchema(),
      });
      await runtime.trust.pin(tcert.tcertId);

      const issued = await runtime.signing.issueSdoc({
        tcertId: tcert.tcertId,
        issuedAt: 1_700_000_000,
        values: {
          pharmacy_name: 'Ahmad Pharmacy',
          category: 'category_1',
          issue_date: '2025-01-15',
          expiry_date: '2027-12-29',
          pharmacy_location: { lat: KABUL.lat, lon: KABUL.lon },
          owner_passcode: 's3cret',
        },
      });
      expect(issued.sdocId).toMatch(/^[0-9a-f]{32}$/);

      const result = await runtime.verification.verify(issued.bytes, { currentTime: 1_700_000_100 });
      expect(result.overall).toBe('valid');
      expect(result.cryptographic).toBe('valid');
      expect(result.tcert).toBe('valid');
      expect(result.trust).toBe('valid');
      expect(result.revocation).toBe('valid');
      expect(result.schema).toBe('valid');
      const loc = result.fields.find((f) => f.name === 'pharmacy_location');
      expect(loc?.state).toBe('valid');
      const secret = result.fields.find((f) => f.name === 'owner_passcode');
      expect(secret?.state).toBe('valid');
    });

    it('does not store the stripped secret in the SDoc payload', async () => {
      const runtime = makeRuntime({ time: 1_700_000_000 });
      const tcert = await runtime.certificates.createTcert({
        algorithm,
        name: 'AFDA',
        fields: pharmacySchema(),
      });
      const issued = await runtime.signing.issueSdoc({
        tcertId: tcert.tcertId,
        issuedAt: 1_700_000_000,
        values: {
          pharmacy_name: 'Ahmad Pharmacy',
          category: 'category_1',
          issue_date: '2025-01-15',
          expiry_date: '2027-12-29',
          pharmacy_location: { lat: KABUL.lat, lon: KABUL.lon },
          owner_passcode: 'super-secret',
        },
      });
      const parsed = await import('../src/signedObject/signedObject.js').then((m) => m.parseSignedObject(issued.bytes));
      const storedFields = parsed.data.fields as unknown[];
      // owner_passcode is the last field (index 5) and is stripped → stored as null.
      expect(storedFields).toHaveLength(pharmacySchema().length);
      expect(storedFields[5]).toBeNull();
      expect(JSON.stringify(issued.bytes)).not.toContain('super-secret');
    });

    it('rejects a missing required field at issuance', async () => {
      const runtime = makeRuntime();
      const tcert = await runtime.certificates.createTcert({
        algorithm,
        name: 'AFDA',
        fields: pharmacySchema(),
      });
      await expect(
        runtime.signing.issueSdoc({
          tcertId: tcert.tcertId,
          values: { category: 'category_1' },
        })
      ).rejects.toThrow(/pharmacy_name/);
    });
  });
}
describe('certificate service helpers and error paths', () => {
  it('loads and parses a stored TCert and its embedded public key', async () => {
    const runtime = makeRuntime();
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: pharmacySchema(),
    });
    const loaded = await runtime.certificates.getTcert(tcert.tcertId);
    expect(loaded.parsed.signerKeyId).toBe(tcert.keyId);
    const pub = await runtime.certificates.publicKeyOf(tcert.tcertId);
    expect(pub.algorithm).toBe('Ed25519');
    expect(pub.publicJwk).toBeTruthy();
    await expect(runtime.certificates.getTcert('deadbeefdeadbeefdeadbeefdeadbeef:1')).rejects.toThrow(/TCert not found/);
  });

  it('fails to issue under an unknown TCert', async () => {
    const runtime = makeRuntime();
    await expect(runtime.signing.issueSdoc({ tcertId: 'ff'.repeat(16) + ':1', values: {} })).rejects.toThrow(
      /TCert not found/
    );
  });

  it('fails to issue under an object that is not a TCert', async () => {
    const runtime = makeRuntime();
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [{ type: 'text', name: 'v', label: 'V' }],
    });
    const sdoc = await runtime.signing.issueSdoc({ tcertId: tcert.tcertId, values: { v: 'x' } });
    // Store the SDoc bytes where a TCert is expected.
    await runtime.deps.certificateStore.save('aa'.repeat(16) + ':1', sdoc.bytes);
    await expect(runtime.signing.issueSdoc({ tcertId: 'aa'.repeat(16) + ':1', values: {} })).rejects.toThrow(
      /not a TCert/
    );
  });

  it('fails to create a TCert for an unsupported field type', async () => {
    const runtime = makeRuntime();
    await expect(
      runtime.certificates.createTcert({
        algorithm: 'Ed25519',
        name: 'X',
        fields: [{ type: 'bogus' as never, name: 'x', label: 'X' }],
      })
    ).rejects.toThrow(/Unsupported field type/);
  });

  it('fails to create a TCert when the private key is missing', async () => {
    const runtime = makeRuntime();
    // A key whose public half exists but whose private half was never stored.
    const provider = runtime.deps.cryptoRegistry.get('Ed25519');
    const pair = await provider.generateKeyPair();
    const orphanKeyId = provider.keyId(pair.publicJwk);
    await runtime.deps.publicKeyStore.save(orphanKeyId, 'Ed25519', pair.publicJwk);
    await expect(
      runtime.certificates.createTcert({
        algorithm: 'Ed25519',
        name: 'X',
        fields: [],
        keyId: orphanKeyId,
      })
    ).rejects.toThrow(/Private key not available/);
  });
});

describe('value binding (text/date/number)', () => {
  const boundSchema = () => [
    // Stripped text: signed into the COSE AAD, not stored.
    { type: 'text' as const, name: 'chassis_number', label: 'Chassis Number', binding: 'stripped' as const },
    // Inline text: stored, verifier must re-enter the exact value.
    { type: 'text' as const, name: 'reg_number', label: 'Registration Number', binding: 'inline' as const },
    // Inline date: stored, verifier must re-enter the exact value.
    { type: 'date' as const, name: 'first_reg', label: 'First Registration', binding: 'inline' as const },
    // Stripped number: signed into the AAD as a canonical string.
    { type: 'number' as const, name: 'owners', label: 'Number of Owners', binding: 'stripped' as const },
  ];

  const CORRECT = {
    chassis_number: 'CH-77-AA',
    reg_number: 'R-900',
    first_reg: '2025-01-15',
    owners: '2',
  };

  for (const algorithm of ALGORITHMS) {
    describe(`with ${algorithm}`, () => {
      /**
       * Issue an identical SDoc inside a runtime whose verification context returns
       * the given `secrets`. Issuance uses the raw values below; the context secrets
       * only matter at verification time.
       */
      async function issueWith(secrets: Record<string, string>) {
        const runtime = makeRuntime({ time: 1_700_000_000, secrets });
        const tcert = await runtime.certificates.createTcert({
          algorithm,
          name: 'AFDA',
          fields: boundSchema(),
        });
        await runtime.trust.pin(tcert.tcertId);
        const issued = await runtime.signing.issueSdoc({
          tcertId: tcert.tcertId,
          issuedAt: 1_700_000_000,
          values: {
            chassis_number: 'CH-77-AA',
            reg_number: 'R-900',
            first_reg: '2025-01-15',
            owners: 2,
          },
        });
        return { runtime, issued };
      }

      it('stores inline-bound values and strips stripped-bound values', async () => {
        const { issued } = await issueWith({});
        const parsed = parseSignedObject(issued.bytes);
        const stored = parsed.data.fields as unknown[];
        // [chassis(stripped)=null, reg(inline), first_reg(inline), owners(stripped)=null]
        expect(stored[0]).toBeNull();
        expect(stored[1]).toBe('R-900');
        expect(stored[2]).toBe('2025-01-15');
        expect(stored[3]).toBeNull();
        expect(JSON.stringify(issued.bytes)).not.toContain('CH-77-AA');
      });

      it('verifies valid when every bound value is entered correctly', async () => {
        const { runtime, issued } = await issueWith(CORRECT);
        const result = await runtime.verification.verify(issued.bytes, { currentTime: 1_700_000_100 });
        expect(result.overall).toBe('valid');
        expect(result.cryptographic).toBe('valid');
        expect(result.schema).toBe('valid');
        const reg = result.fields.find((f) => f.name === 'reg_number');
        expect(reg?.state).toBe('valid');
      });

      it('fails cryptographically when a stripped value is wrong', async () => {
        const { runtime, issued } = await issueWith({ ...CORRECT, chassis_number: 'WRONG' });
        const result = await runtime.verification.verify(issued.bytes, { currentTime: 1_700_000_100 });
        expect(result.overall).toBe('invalid');
        expect(result.cryptographic).toBe('invalid');
        expect(result.message).toContain('signature verification failed');
      });

      it('fails at the rules level (crypto still valid) when an inline value is wrong', async () => {
        const { runtime, issued } = await issueWith({ ...CORRECT, reg_number: 'WRONG-INLINE' });
        const result = await runtime.verification.verify(issued.bytes, { currentTime: 1_700_000_100 });
        expect(result.cryptographic).toBe('valid');
        expect(result.schema).toBe('invalid');
        const reg = result.fields.find((f) => f.name === 'reg_number');
        expect(reg?.state).toBe('invalid');
        expect(reg?.message).toContain('binding value mismatch');
        // The inline value is still stored, so the original can be shown.
        const storedFields = parseSignedObject(issued.bytes).data.fields as unknown[];
        expect(storedFields[1]).toBe('R-900');
      });

      it('cannot verify when an inline-bound value is not provided', async () => {
        const { runtime, issued } = await issueWith({
          chassis_number: CORRECT.chassis_number,
          first_reg: CORRECT.first_reg,
          owners: CORRECT.owners,
        });
        const result = await runtime.verification.verify(issued.bytes, { currentTime: 1_700_000_100 });
        expect(result.cryptographic).toBe('valid');
        expect(result.context).toBe('missing');
        const reg = result.fields.find((f) => f.name === 'reg_number');
        expect(reg?.state).toBe('cannotVerify');
      });
    });
  }
});

describe('field defaults', () => {
  it('auto-fills a hidden datetime field whose default is {kind:now}', async () => {
    const runtime = makeRuntime({ time: 1_700_000_000 }); // 2023-11-14T22:13:20Z
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [
        { type: 'text', name: 'holder', label: 'Holder' },
        { type: 'datetime', name: 'issued_at', label: 'Issued At', default: { kind: 'now' } },
      ],
    });
    const issued = await runtime.signing.issueSdoc({
      tcertId: tcert.tcertId,
      issuedAt: 1_700_000_000,
      values: { holder: 'Ahmad' }, // issued_at omitted → defaulted
    });
    const stored = parseSignedObject(issued.bytes).data.fields as unknown[];
    expect(stored[1]).toBe('2023-11-14T22:13:20Z');
  });

  it('auto-fills a static default value', async () => {
    const runtime = makeRuntime({ time: 1_700_000_000 });
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [
        { type: 'text', name: 'holder', label: 'Holder' },
        { type: 'select', name: 'region', label: 'Region', options: ['kabul', 'herat'], default: 'kabul' },
      ],
    });
    const issued = await runtime.signing.issueSdoc({
      tcertId: tcert.tcertId,
      issuedAt: 1_700_000_000,
      values: { holder: 'Ahmad' }, // region omitted → defaulted
    });
    const stored = parseSignedObject(issued.bytes).data.fields as unknown[];
    expect(stored[1]).toBe('kabul');
  });

  it('uses a supplied value over the declared default', async () => {
    const runtime = makeRuntime({ time: 1_700_000_000 });
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [
        { type: 'text', name: 'holder', label: 'Holder' },
        { type: 'datetime', name: 'issued_at', label: 'Issued At', default: { kind: 'now' } },
      ],
    });
    const issued = await runtime.signing.issueSdoc({
      tcertId: tcert.tcertId,
      issuedAt: 1_700_000_000,
      values: { holder: 'Ahmad', issued_at: '2025-01-01T00:00:00Z' },
    });
    const stored = parseSignedObject(issued.bytes).data.fields as unknown[];
    expect(stored[1]).toBe('2025-01-01T00:00:00Z');
  });
});

describe('TCert-level SDoc validity duration', () => {
  it('rejects an SDoc older than the TCert policy', async () => {
    const later = 1_700_000_000 + 8 * 86_400; // 8 days after issuance
    const aged = makeRuntime({ time: later });
    const tcert = await aged.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [{ type: 'text', name: 'holder', label: 'Holder' }],
      sdocMaxAgeSeconds: 7 * 86_400, // one week
    });
    await aged.trust.pin(tcert.tcertId);
    const issued = await aged.signing.issueSdoc({
      tcertId: tcert.tcertId,
      issuedAt: 1_700_000_000,
      values: { holder: 'Ahmad' },
    });
    const result = await aged.verification.verify(issued.bytes, { currentTime: later });
    expect(result.overall).toBe('invalid');
    expect(result.schema).toBe('invalid');
    expect(result.message).toContain('validity duration');
  });

  it('accepts an SDoc within the TCert policy', async () => {
    const runtime = makeRuntime({ time: 1_700_000_000 });
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [{ type: 'text', name: 'holder', label: 'Holder' }],
      sdocMaxAgeSeconds: 7 * 86_400,
    });
    await runtime.trust.pin(tcert.tcertId);
    const issued = await runtime.signing.issueSdoc({
      tcertId: tcert.tcertId,
      issuedAt: 1_700_000_000,
      values: { holder: 'Ahmad' },
    });
    const result = await runtime.verification.verify(issued.bytes, { currentTime: 1_700_000_000 + 3 * 86_400 });
    expect(result.overall).toBe('valid');
  });
});

describe('optional TCert schema (CA/meta certificates)', () => {
  it('rejects issuing an SDoc under a schema-less TCert', async () => {
    const runtime = makeRuntime();
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [], // a CA certificate — no document schema
    });
    await expect(runtime.signing.issueSdoc({ tcertId: tcert.tcertId, values: {} })).rejects.toThrow(/no document schema/);
  });

  it('verifies an SDoc under a schema-less signer TCert as schema-invalid', async () => {
    const runtime = makeRuntime({ time: 1_700_000_000 });
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [], // no document schema
    });
    await runtime.trust.pin(tcert.tcertId);
    // Hand-build an SDoc with the CA key (bypassing the issuing guard) to exercise
    // the verification-time guard.
    const priv = await runtime.deps.privateKeyStore.load(tcert.keyId);
    const pub = await runtime.deps.publicKeyStore.load(tcert.keyId);
    const provider = runtime.deps.cryptoRegistry.get('Ed25519');
    const { buildSignedObject } = await import('../src/signedObject/signedObject.js');
    const sdocBytes = await buildSignedObject(
      'sdoc',
      { issuedAt: 1_700_000_000, fields: [] },
      { algorithm: 'Ed25519', publicJwk: pub!.publicJwk, privateJwk: priv!.privateJwk },
      provider,
      new Uint8Array(0),
      tcert.certificateNumber
    );
    const result = await runtime.verification.verify(sdocBytes, { currentTime: 1_700_000_000 });
    expect(result.schema).toBe('invalid');
    expect(result.message).toContain('no document schema');
  });
});