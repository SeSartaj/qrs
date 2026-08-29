import { describe, expect, it } from 'vitest';
import { makeRuntime } from './helpers.js';
import { tcertIdOf } from '../src/signedObject/signedObject.js';

describe('online importStatement', () => {
  it('retains and applies a signed attestation revocation without revoking the target TCert', async () => {
    const issuer = makeRuntime();
    const ca = await issuer.certificates.createTcert({ algorithm: 'Ed25519', name: 'CA', fields: [] });
    const target = await issuer.certificates.createTcert({ algorithm: 'Ed25519', name: 'Target', fields: [] });
    await issuer.trust.addCa(ca.tcertId);
    const attestation = await issuer.trust.attest({ caTcertId: ca.tcertId, targetTcertId: target.tcertId });
    const revocation = await issuer.revocation.revokeAttestation({ caTcertId: ca.tcertId, targetTcertId: target.tcertId });

    const verifier = makeRuntime();
    await verifier.online.importTcert(ca.bytes);
    await verifier.online.importTcert(target.bytes);
    await verifier.trust.addCa(ca.tcertId);
    expect((await verifier.online.importStatement(attestation.bytes)).applied).toBe(true);
    expect((await verifier.trust.resolveTrust(target.tcertId)).state).toBe('valid');
    expect((await verifier.online.importStatement(revocation.bytes)).action).toBe('revokeAttestation');
    expect((await verifier.trust.resolveTrust(target.tcertId)).state).toBe('cannotVerify');
    expect(await verifier.deps.revocationStore.getRevokedTcert(target.tcertId)).toBeNull();
    expect(await verifier.deps.revocationStore.getRevokedAttestation(target.tcertId, ca.tcertId)).not.toBeNull();
    expect(await verifier.deps.trustStore.getAttestations(target.tcertId)).toHaveLength(1);
  });

  it('applies a CA attestation to the trust store', async () => {
    const caRt = makeRuntime();
    const ca = await caRt.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'CA',
      fields: [],
    });
    await caRt.trust.addCa(ca.tcertId);
    const target = await caRt.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'CA',
      fields: [],
    });
    const att = await caRt.trust.attest({ caTcertId: ca.tcertId, targetTcertId: target.tcertId, claims: { role: 'x' } });

    // A separate verifier that only knows the CA's TCert bytes imports the statement.
    const verifier = makeRuntime();
    await verifier.deps.certificateStore.save(ca.tcertId, ca.bytes);
    await verifier.deps.trustStore.addCa(ca.tcertId);

    const res = await verifier.online.importStatement(att.bytes);
    expect(res.applied).toBe(true);
    expect(res.action).toBe('attest');
    const records = await verifier.deps.trustStore.getAttestations(target.tcertId);
    expect(records.length).toBe(1);
    expect(records[0]!.caTcertId).toBe(ca.tcertId);
    expect(records[0]!.claims).toEqual({ role: 'x' });
  });

  it('applies a TCert revocation to the revocation store', async () => {
    const rt = makeRuntime();
    const signer = await rt.certificates.createTcert({ algorithm: 'Ed25519', name: 'I', fields: [] });
    const target = await rt.certificates.createTcert({ algorithm: 'Ed25519', name: 'I', fields: [], keyId: signer.keyId });
    const rev = await rt.revocation.revokeTcert({
      signerKeyId: signer.keyId,
      targetTcertId: target.tcertId,
      type: 'retrospective',
      reason: 'abuse',
    });

    const verifier = makeRuntime();
    await verifier.deps.certificateStore.save(signer.tcertId, signer.bytes);
    const res = await verifier.online.importStatement(rev.bytes);
    expect(res.applied).toBe(true);
    expect(res.action).toBe('revokeTcert');
    const entry = await verifier.deps.revocationStore.getRevokedTcert(target.tcertId);
    expect(entry?.reason).toBe('abuse');
  });

  it('applies key revocation and sdoc block/unblock', async () => {
    const rt = makeRuntime();
    const signer = await rt.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'I',
      fields: [{ type: 'text', name: 'v', label: 'V' }],
    });
    const revKey = await rt.revocation.revokeKey({ signerKeyId: signer.keyId, targetKeyId: signer.keyId, reason: 'key lost' });

    const verifier = makeRuntime();
    await verifier.deps.certificateStore.save(signer.tcertId, signer.bytes);
    expect((await verifier.online.importStatement(revKey.bytes)).applied).toBe(true);
    expect(await verifier.deps.revocationStore.getRevokedKey(signer.keyId)).not.toBeNull();

    // Block an sdoc (issue one first so blockSdoc finds it locally on the issuing side).
    const issued = await rt.signing.issueSdoc({ tcertId: signer.tcertId, values: { v: 'x' } });
    const block = await rt.revocation.blockSdoc({ signerKeyId: signer.keyId, targetSdocId: issued.sdocId, reason: 'bad' });
    const verifier2 = makeRuntime();
    await verifier2.deps.certificateStore.save(signer.tcertId, signer.bytes);
    expect((await verifier2.online.importStatement(block.bytes)).applied).toBe(true);
    expect(await verifier2.deps.revocationStore.getBlockedSdoc(issued.sdocId)).not.toBeNull();

    const unblock = await rt.revocation.unblockSdoc({ signerKeyId: signer.keyId, targetSdocId: issued.sdocId });
    expect((await verifier2.online.importStatement(unblock.bytes)).applied).toBe(true);
    expect(await verifier2.deps.revocationStore.getBlockedSdoc(issued.sdocId)).toBeNull();
    const history = await verifier2.deps.revocationStore.listSdocStatements();
    expect(history.map((entry) => entry.entry.action)).toEqual(['blockSdoc', 'unblockSdoc']);
    expect(history[1]?.entry.statementBytes).toEqual(unblock.bytes);
  });

  it('refuses statements whose signer TCert is unknown', async () => {
    const rt = makeRuntime();
    const signer = await rt.certificates.createTcert({ algorithm: 'Ed25519', name: 'I', fields: [] });
    const target = await rt.certificates.createTcert({ algorithm: 'Ed25519', name: 'I', fields: [], keyId: signer.keyId });
    const rev = await rt.revocation.revokeTcert({ signerKeyId: signer.keyId, targetTcertId: target.tcertId, type: 'prospective' });

    const verifier = makeRuntime(); // never saw the signer
    const res = await verifier.online.importStatement(rev.bytes);
    expect(res.applied).toBe(false);
    expect(res.reason).toContain('no signer TCert');
  });

  it('refuses a tampered statement even when the signer is known', async () => {
    const rt = makeRuntime();
    const signer = await rt.certificates.createTcert({ algorithm: 'Ed25519', name: 'I', fields: [] });
    const target = await rt.certificates.createTcert({ algorithm: 'Ed25519', name: 'I', fields: [], keyId: signer.keyId });
    const rev = await rt.revocation.revokeTcert({ signerKeyId: signer.keyId, targetTcertId: target.tcertId, type: 'prospective' });

    const tampered = new Uint8Array(rev.bytes);
    const mid = Math.floor(tampered.length / 2);
    tampered[mid] = (tampered[mid] ?? 0) ^ 0xff;

    const verifier = makeRuntime();
    await verifier.deps.certificateStore.save(signer.tcertId, signer.bytes);
    const res = await verifier.online.importStatement(tampered);
    expect(res.applied).toBe(false);
  });

  it('refuses malformed bytes', async () => {
    const verifier = makeRuntime();
    const res = await verifier.online.importStatement(new Uint8Array([1, 2, 3]));
    expect(res.applied).toBe(false);
  });
});

describe('online importTcert', () => {
  it('verifies and stores a TCert downloaded from a server', async () => {
    const rt = makeRuntime();
    const tcert = await rt.certificates.createTcert({ algorithm: 'Ed25519', name: 'X', fields: [] });
    const verifier = makeRuntime();
    const res = await verifier.online.importTcert(tcert.bytes);
    expect(res.imported).toBe(true);
    expect(res.tcertId).toBe(tcert.tcertId);
    expect(await verifier.deps.certificateStore.get(tcert.tcertId)).not.toBeNull();
  });

  it('rejects objects that are not TCerts', async () => {
    const rt = makeRuntime();
    const tcert = await rt.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'X',
      fields: [{ type: 'text', name: 'v', label: 'V' }],
    });
    await rt.trust.pin(tcert.tcertId);
    const issued = await rt.signing.issueSdoc({ tcertId: tcert.tcertId, values: { v: 'x' } });
    const verifier = makeRuntime();
    const res = await verifier.online.importTcert(issued.bytes);
    expect(res.imported).toBe(false);
  });

  it('rejects a tampered TCert', async () => {
    const rt = makeRuntime();
    const tcert = await rt.certificates.createTcert({ algorithm: 'Ed25519', name: 'X', fields: [] });
    const tampered = new Uint8Array(tcert.bytes);
    const mid = Math.floor(tampered.length / 2);
    tampered[mid] = (tampered[mid] ?? 0) ^ 0xff;
    const verifier = makeRuntime();
    const res = await verifier.online.importTcert(tampered);
    expect(res.imported).toBe(false);
  });

  it('recomputes the tcert id rather than trusting a claimed one', async () => {
    const rt = makeRuntime();
    const tcert = await rt.certificates.createTcert({ algorithm: 'Ed25519', name: 'X', fields: [] });
    const expected = tcertIdOf(tcert.keyId, tcert.certificateNumber);
    const verifier = makeRuntime();
    await verifier.online.importTcert(tcert.bytes);
    expect(await verifier.deps.certificateStore.get(expected)).not.toBeNull();
  });
});
