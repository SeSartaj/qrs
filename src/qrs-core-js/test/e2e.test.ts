import { describe, expect, it } from 'vitest';
import { parseStatement } from '../src/services/statement.js';
import { KABUL, makeRuntime, pharmacySchema } from './helpers.js';

const TIME = 1_700_000_000;

describe('e2e: Afghanistan FDA pharmacy license', () => {
  it('issues a pharmacy license under a CA-attested TCert and verifies it offline in a separate verifier app', async () => {
    // ---- Issuer side: AFDA (CA) attests Ahmad's pharmacy TCert ----
    const issuer = makeRuntime({ time: TIME, location: KABUL, secrets: { owner_passcode: 's3cret' } });

    const afda = await issuer.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'Afghanistan FDA',
      fields: [],
    });
    const pharmacy = await issuer.certificates.createTcert({
      algorithm: 'ECDSA-P256', // cross-algorithm: CA is Ed25519, issuer is ECDSA P-256
      name: 'Ahmad',
      fields: pharmacySchema(),
    });

    await issuer.trust.addCa(afda.tcertId);
    const attestation = await issuer.trust.attest({
      caTcertId: afda.tcertId,
      targetTcertId: pharmacy.tcertId,
      claims: { name: 'Ahmad of Kabul' },
    });

    const issued = await issuer.signing.issueSdoc({
      tcertId: pharmacy.tcertId,
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

    // The signed payload must be small enough to fit a QR code comfortably.
    expect(issued.bytes.length).toBeLessThan(1024);

    // ---- Verifier side: an offline, independent app ----
    const verifier = makeRuntime({ time: TIME, location: KABUL, secrets: { owner_passcode: 's3cret' } });

    // It only ever sees the CA TCert, the target TCert and the attestation statement.
    const afdaStored = await issuer.certificates.getTcert(afda.tcertId);
    await verifier.deps.certificateStore.save(afda.tcertId, afdaStored.bytes);
    await verifier.trust.addCa(afda.tcertId);

    const pharmacyStored = await issuer.certificates.getTcert(pharmacy.tcertId);
    await verifier.deps.certificateStore.save(pharmacy.tcertId, pharmacyStored.bytes);

    const statement = parseStatement(attestation.bytes);
    const tcertHash = statement.target.kind === 'tcert' ? statement.target.tcertHash : undefined;
    await verifier.deps.trustStore.addAttestation({
      targetTcertId: pharmacy.tcertId,
      caKeyId: statement.signerKeyId,
      caTcertId: afda.tcertId,
      tcertHash: tcertHash ?? '',
      claims: statement.claims,
      issuedAt: statement.issuedAt,
      statementBytes: attestation.bytes,
    });

    // Trust resolves through the CA, even though the TCert was never pinned.
    const trust = await verifier.trust.resolveTrust(pharmacy.tcertId);
    expect(trust.state).toBe('valid');
    expect(trust.pinned).toBe(false);
    expect(trust.ca?.caTcertId).toBe(afda.tcertId);
    expect(trust.ca?.caName).toBe('Ahmad of Kabul');

    // And the document verifies end-to-end.
    const result = await verifier.verification.verify(issued.bytes, { currentTime: TIME + 100 });
    expect(result.overall).toBe('valid');
    expect(result.trust).toBe('valid');
    expect(result.cryptographic).toBe('valid');
  });

  it('a holder who does not know the owner passcode cannot get a valid result', async () => {
    const issuer = makeRuntime({ time: TIME, location: KABUL, secrets: { owner_passcode: 's3cret' } });
    const tcert = await issuer.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: pharmacySchema(),
    });
    await issuer.trust.pin(tcert.tcertId);
    const issued = await issuer.signing.issueSdoc({
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

    // Copy the QR bytes to a different holder with the wrong secret.
    const thief = makeRuntime({ time: TIME, location: KABUL, secrets: { owner_passcode: 'guess' } });
    const stored = await issuer.certificates.getTcert(tcert.tcertId);
    await thief.deps.certificateStore.save(tcert.tcertId, stored.bytes);
    await thief.trust.pin(tcert.tcertId);

    const result = await thief.verification.verify(issued.bytes, { currentTime: TIME + 100 });
    expect(result.overall).toBe('invalid');
    expect(result.cryptographic).toBe('invalid');
  });
});
