import { describe, expect, it } from 'vitest';
import { parseSignedObject, splitTcertId } from '../src/signedObject/signedObject.js';
import { tcertHashOf } from '../src/signedObject/signedObject.js';
import { buildStatement } from '../src/services/statement.js';
import { KABUL, makeRuntime, pharmacySchema } from './helpers.js';

const TIME = 1_700_000_000;

describe('trust management', () => {
  it('resolves trust for a pinned TCert', async () => {
    const runtime = makeRuntime({ time: TIME, location: KABUL, secrets: { owner_passcode: 's3cret' } });
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: pharmacySchema(),
    });
    expect((await runtime.trust.resolveTrust(tcert.tcertId)).state).toBe('cannotVerify');
    await runtime.trust.pin(tcert.tcertId);
    const resolution = await runtime.trust.resolveTrust(tcert.tcertId);
    expect(resolution.state).toBe('valid');
    expect(resolution.pinned).toBe(true);
  });

  it('resolves trust through a CA attestation', async () => {
    const runtime = makeRuntime({ time: TIME, location: KABUL, secrets: { owner_passcode: 's3cret' } });
    const ca = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'Afghanistan FDA',
      fields: [],
    });
    const pharmacy = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'Ahmad',
      fields: pharmacySchema(),
    });

    await runtime.trust.addCa(ca.tcertId);
    await runtime.trust.attest({ caTcertId: ca.tcertId, targetTcertId: pharmacy.tcertId, claims: { name: 'Ahmad of Kabul' } });

    const resolution = await runtime.trust.resolveTrust(pharmacy.tcertId);
    expect(resolution.state).toBe('valid');
    expect(resolution.pinned).toBe(false);
    expect(resolution.ca?.caTcertId).toBe(ca.tcertId);
    expect(resolution.ca?.caName).toBe('Ahmad of Kabul');
  });

it('rejects an attested TCert with a hash mismatch', async () => {
    const runtime = makeRuntime();
    const ca = await runtime.certificates.createTcert({ algorithm: 'Ed25519', name: 'CA', fields: [] });
    const target = await runtime.certificates.createTcert({ algorithm: 'Ed25519', name: 'Target', fields: [] });
    await runtime.trust.addCa(ca.tcertId);

    // Build a real attestation statement (without auto-adding a record), then
    // store it with a tampered tcertHash so it no longer matches the actual
    // target TCert content hash.
    const caKey = await runtime.deps.publicKeyStore.load(ca.keyId);
    const caPriv = await runtime.deps.privateKeyStore.load(ca.keyId);
    const provider = runtime.deps.cryptoRegistry.get(caKey!.algorithm);
    const targetParts = splitTcertId(target.tcertId);
    const built = await buildStatement(
      'attest',
      { kind: 'tcert', keyId: targetParts.keyId, certificateNumber: targetParts.certificateNumber, tcertHash: tcertHashOf(parseSignedObject(target.bytes)) },
      1,
      { claims: { name: 'x' } },
      { algorithm: caKey!.algorithm, publicJwk: caKey!.publicJwk, privateJwk: caPriv!.privateJwk },
      provider
    );
    await runtime.deps.trustStore.addAttestation({
      targetTcertId: target.tcertId,
      caTcertId: ca.tcertId,
      caKeyId: ca.keyId,
      tcertHash: 'deadbeef', // tampered — does not match the real target hash
      claims: { name: 'x' },
      issuedAt: 1,
      statementBytes: built.bytes,
    });

    // Trust must NOT resolve through the CA because the bound hash is wrong.
    const resolution = await runtime.trust.resolveTrust(target.tcertId);
    expect(resolution.state).toBe('cannotVerify');
    expect(resolution.ca).toBeUndefined();
  });

  it('respects local distrust (overrides pinning)', async () => {
    const runtime = makeRuntime();
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'X',
      fields: [],
    });
    await runtime.trust.pin(tcert.tcertId);
    await runtime.trust.distrust(tcert.tcertId);
    const resolution = await runtime.trust.resolveTrust(tcert.tcertId);
    expect(resolution.state).toBe('invalid');
    await runtime.trust.trustAgain(tcert.tcertId);
    expect((await runtime.trust.resolveTrust(tcert.tcertId)).state).toBe('valid');
  });

  it('a revoked CA invalidates CA-only trust but not pinned trust', async () => {
    const runtime = makeRuntime({ time: TIME, location: KABUL, secrets: { owner_passcode: 's3cret' } });
    const ca = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [],
    });
    const pharmacy = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'Ahmad',
      fields: pharmacySchema(),
    });
    await runtime.trust.addCa(ca.tcertId);
    await runtime.trust.attest({ caTcertId: ca.tcertId, targetTcertId: pharmacy.tcertId });

    // Revoke the CA (self-revocation by its own key).
    await runtime.revocation.revokeTcert({ signerKeyId: ca.keyId, targetTcertId: ca.tcertId, type: 'retrospective', issuedAt: TIME });

    const caOnly = await runtime.trust.resolveTrust(pharmacy.tcertId);
    expect(caOnly.state).toBe('cannotVerify');

    // Pin the same TCert: it stays valid even though the CA is gone.
    await runtime.trust.pin(pharmacy.tcertId);
    const pinned = await runtime.trust.resolveTrust(pharmacy.tcertId);
    expect(pinned.state).toBe('valid');
    expect(pinned.ca).toBeUndefined();
  });

  it('addTcert stores the TCert and creates an attestation', async () => {
    const runtime = makeRuntime();
    const ca = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [],
    });
    const pharmacy = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'Ahmad',
      fields: [],
    });
    await runtime.trust.addCa(ca.tcertId);
    await runtime.trust.addTcert({ caTcertId: ca.tcertId, targetTcertId: pharmacy.tcertId, tcertBytes: pharmacy.bytes });
    const attestations = await runtime.deps.trustStore.getAttestations(pharmacy.tcertId);
    expect(attestations.length).toBe(1);
    expect((await runtime.trust.resolveTrust(pharmacy.tcertId)).state).toBe('valid');
  });

  it('rejects attestation from a non-CA', async () => {
    const runtime = makeRuntime();
    const a = await runtime.certificates.createTcert({ algorithm: 'Ed25519', name: 'A', fields: [] });
    const b = await runtime.certificates.createTcert({ algorithm: 'Ed25519', name: 'B', fields: [] });
    await expect(runtime.trust.attest({ caTcertId: a.tcertId, targetTcertId: b.tcertId })).rejects.toThrow(
      /not configured as a CA/
    );
  });

  it('rejects a duplicate attestation (same CA attesting the same target twice)', async () => {
    const runtime = makeRuntime();
    const ca = await runtime.certificates.createTcert({ algorithm: 'Ed25519', name: 'AFDA', fields: [] });
    const target = await runtime.certificates.createTcert({ algorithm: 'Ed25519', name: 'A', fields: [] });
    await runtime.trust.addCa(ca.tcertId);
    await runtime.trust.attest({ caTcertId: ca.tcertId, targetTcertId: target.tcertId, claims: { role: 'licensee' } });
    await expect(
      runtime.trust.attest({ caTcertId: ca.tcertId, targetTcertId: target.tcertId, claims: { role: 'licensee' } })
    ).rejects.toThrow(/already attested/);
    // Still only one attestation record.
    const attestations = await runtime.deps.trustStore.getAttestations(target.tcertId);
    expect(attestations.length).toBe(1);
  });

  it('unpins and removes CA role', async () => {
    const runtime = makeRuntime();
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'X',
      fields: [],
    });
    await runtime.trust.pin(tcert.tcertId);
    expect((await runtime.trust.resolveTrust(tcert.tcertId)).state).toBe('valid');
    await runtime.trust.unpin(tcert.tcertId);
    expect((await runtime.trust.resolveTrust(tcert.tcertId)).state).toBe('cannotVerify');

    await runtime.trust.addCa(tcert.tcertId);
    expect(await runtime.deps.trustStore.isCa(tcert.tcertId)).toBe(true);
    await runtime.trust.removeCa(tcert.tcertId);
    expect(await runtime.deps.trustStore.isCa(tcert.tcertId)).toBe(false);
  });
});
