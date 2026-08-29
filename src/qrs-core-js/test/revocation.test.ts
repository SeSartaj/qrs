import { describe, expect, it } from 'vitest';
import { QrsAuthorizationError } from '../src/errors.js';
import { KABUL, makeRuntime, pharmacySchema } from './helpers.js';

const TIME = 1_700_000_000;

async function setup() {
  const runtime = makeRuntime({ time: TIME, location: KABUL, secrets: { owner_passcode: 's3cret' } });
  const tcert = await runtime.certificates.createTcert({
    algorithm: 'Ed25519',
    name: 'AFDA',
    fields: pharmacySchema(),
  });
  await runtime.trust.pin(tcert.tcertId);
  const values = {
    pharmacy_name: 'Ahmad Pharmacy',
    category: 'category_1',
    issue_date: '2025-01-15',
    expiry_date: '2027-12-29',
    pharmacy_location: { lat: KABUL.lat, lon: KABUL.lon },
    owner_passcode: 's3cret',
  };
  const early = await runtime.signing.issueSdoc({ tcertId: tcert.tcertId, issuedAt: TIME - 10_000, values });
  const late = await runtime.signing.issueSdoc({ tcertId: tcert.tcertId, issuedAt: TIME + 10_000, values });
  return { runtime, tcert, early, late };
}

describe('revocation', () => {
  it('prospective revocation only invalidates documents issued at/after the revocation', async () => {
    const { runtime, tcert, early, late } = await setup();
    await runtime.revocation.revokeTcert({ signerKeyId: tcert.keyId, targetTcertId: tcert.tcertId, type: 'prospective', issuedAt: TIME });

    const earlyResult = await runtime.verification.verify(early.bytes, { currentTime: TIME + 100 });
    expect(earlyResult.revocation).toBe('valid');
    expect(earlyResult.overall).toBe('valid');

    const lateResult = await runtime.verification.verify(late.bytes, { currentTime: TIME + 100 });
    expect(lateResult.revocation).toBe('invalid');
    expect(lateResult.overall).toBe('invalid');
  });

  it('retrospective revocation invalidates all documents', async () => {
    const { runtime, tcert, early, late } = await setup();
    await runtime.revocation.revokeTcert({ signerKeyId: tcert.keyId, targetTcertId: tcert.tcertId, type: 'retrospective', issuedAt: TIME });
    expect((await runtime.verification.verify(early.bytes, { currentTime: TIME + 100 })).overall).toBe('invalid');
    expect((await runtime.verification.verify(late.bytes, { currentTime: TIME + 100 })).overall).toBe('invalid');
  });

  it('key revocation invalidates every TCert and SDoc of that key', async () => {
    const { runtime, tcert, early, late } = await setup();
    await runtime.revocation.revokeKey({ signerKeyId: tcert.keyId, targetKeyId: tcert.keyId, issuedAt: TIME });
    expect((await runtime.verification.verify(early.bytes, { currentTime: TIME + 100 })).overall).toBe('invalid');
    expect((await runtime.verification.verify(late.bytes, { currentTime: TIME + 100 })).overall).toBe('invalid');
  });

  it('blocks and unblocks a single SDoc', async () => {
    const { runtime, tcert, early, late } = await setup();
    await runtime.revocation.blockSdoc({ signerKeyId: tcert.keyId, targetSdocId: early.sdocId, issuedAt: TIME });
    expect((await runtime.verification.verify(early.bytes, { currentTime: TIME + 100 })).overall).toBe('invalid');
    expect((await runtime.verification.verify(late.bytes, { currentTime: TIME + 100 })).overall).toBe('valid');

    await runtime.revocation.unblockSdoc({ signerKeyId: tcert.keyId, targetSdocId: early.sdocId, issuedAt: TIME + 1 });
    expect((await runtime.verification.verify(early.bytes, { currentTime: TIME + 100 })).overall).toBe('valid');
  });

  it('rejects revocation by an unauthorized signer', async () => {
    const { runtime, tcert } = await setup();
    const stranger = await runtime.certificates.generateKeyPair('Ed25519');
    await expect(
      runtime.revocation.revokeTcert({ signerKeyId: stranger, targetTcertId: tcert.tcertId, type: 'prospective' })
    ).rejects.toThrow(QrsAuthorizationError);
  });

  it('only the key owner can revoke its own key', async () => {
    const { runtime, tcert } = await setup();
    const stranger = await runtime.certificates.generateKeyPair('Ed25519');
    await expect(
      runtime.revocation.revokeKey({ signerKeyId: stranger, targetKeyId: tcert.keyId })
    ).rejects.toThrow(QrsAuthorizationError);
  });

  it('attributes each CA revocation independently so one CA revoking does not bind another', async () => {
    const runtime = makeRuntime({ time: TIME, location: KABUL, secrets: { owner_passcode: 's3cret' } });
    // Two independent CAs both attest the same target TCert.
    const caA = await runtime.certificates.createTcert({ algorithm: 'Ed25519', name: 'CA A', fields: [] });
    const caB = await runtime.certificates.createTcert({ algorithm: 'Ed25519', name: 'CA B', fields: [] });
    const target = await runtime.certificates.createTcert({ algorithm: 'Ed25519', name: 'Target', fields: pharmacySchema() });
    await runtime.trust.addCa(caA.tcertId);
    await runtime.trust.addCa(caB.tcertId);
    await runtime.trust.attest({ caTcertId: caA.tcertId, targetTcertId: target.tcertId });
    await runtime.trust.attest({ caTcertId: caB.tcertId, targetTcertId: target.tcertId });

    // CA-A revokes the target; CA-B does not.
    await runtime.revocation.revokeTcert({
      signerKeyId: caA.keyId,
      targetTcertId: target.tcertId,
      type: 'retrospective',
      issuedAt: TIME,
    });

    // The effective revocation exists, and is attributed to CA-A by key.
    const effective = await runtime.deps.revocationStore.getRevokedTcert(target.tcertId);
    expect(effective).not.toBeNull();
    expect(effective?.byKeyId).toBe(caA.keyId);

    // Per-CA entries: exactly one revocation, by CA-A.
    const entries = await runtime.deps.revocationStore.getRevokedTcertEntries(target.tcertId);
    expect(entries).toHaveLength(1);
    expect(entries[0].byKeyId).toBe(caA.keyId);

    // Trust still resolves (per-CA independence) — CA-A's revocation of the
    // target does not prevent the TCert from being trusted through the other
    // attesting CA.
    const resolution = await runtime.trust.resolveTrust(target.tcertId);
    expect(resolution.state).toBe('valid');

    // A verification of an SDoc issued under the target is invalid overall
    // because the target TCert is revoked (effective revocation), regardless of
    // which CA signed it.
    const sdoc = await runtime.signing.issueSdoc({
      tcertId: target.tcertId,
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
    const verified = await runtime.verification.verify(sdoc.bytes, { currentTime: TIME + 100 });
    expect(verified.revocation).toBe('invalid');
  });
});
