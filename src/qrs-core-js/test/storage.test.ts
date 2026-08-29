import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createFileStores } from '../src/storage/fileStores.js';
import { createInMemoryStores } from '../src/storage/memoryStores.js';

type StoreBundle = ReturnType<typeof createInMemoryStores>;

/** Exercise every method of every storage interface on the given bundle. */
async function exerciseStores(stores: StoreBundle): Promise<void> {
  // --- private keys ---
  const priv = { kty: 'OKP' as const, crv: 'Ed25519', x: 'x'.repeat(43), d: 'd'.repeat(43) };
  await stores.privateKeyStore.save('k1', 'Ed25519', priv);
  expect(await stores.privateKeyStore.load('k1')).toEqual({ algorithm: 'Ed25519', privateJwk: priv });
  expect(await stores.privateKeyStore.has('k1')).toBe(true);
  expect(await stores.privateKeyStore.all()).toEqual([{ keyId: 'k1', algorithm: 'Ed25519' }]);

  // --- public keys ---
  const pub = { kty: 'OKP' as const, crv: 'Ed25519', x: 'x'.repeat(43) };
  await stores.publicKeyStore.save('k1', 'Ed25519', pub);
  expect((await stores.publicKeyStore.load('k1'))?.publicJwk).toEqual(pub);
  expect(await stores.publicKeyStore.has('k1')).toBe(true);
  expect(await stores.publicKeyStore.all()).toHaveLength(1);

  // --- certificates ---
  await stores.certificateStore.save('k1:1', new Uint8Array([1, 2, 3]));
  expect(await stores.certificateStore.get('k1:1')).toEqual(new Uint8Array([1, 2, 3]));
  expect((await stores.certificateStore.findByKeyId('k1')).map((c) => c.tcertId)).toEqual(['k1:1']);
  expect(await stores.certificateStore.all()).toHaveLength(1);
  await stores.certificateStore.remove('k1:1');
  expect(await stores.certificateStore.get('k1:1')).toBeNull();

  // --- documents ---
  await stores.documentStore.save('d1', new Uint8Array([9]));
  expect(await stores.documentStore.get('d1')).toEqual(new Uint8Array([9]));
  expect(await stores.documentStore.all()).toHaveLength(1);
  await stores.documentStore.remove('d1');
  expect(await stores.documentStore.get('d1')).toBeNull();

  // --- revocation ---
  await stores.revocationStore.addRevokedTcert('k1:1', { type: 'prospective', issuedAt: 5 });
  expect(await stores.revocationStore.getRevokedTcert('k1:1')).toEqual({ type: 'prospective', issuedAt: 5 });
  expect(await stores.revocationStore.listRevokedTcert()).toHaveLength(1);

  await stores.revocationStore.addRevokedKey('k1', {
    type: 'retrospective',
    issuedAt: 6,
    statementBytes: new Uint8Array([4, 5, 6]),
  });
  expect(await stores.revocationStore.getRevokedKey('k1')).toEqual({
    type: 'retrospective',
    issuedAt: 6,
    statementBytes: new Uint8Array([4, 5, 6]),
  });
  expect(await stores.revocationStore.listRevokedKey()).toHaveLength(1);

  await stores.revocationStore.addBlockedSdoc('d1', { issuedAt: 7 });
  expect(await stores.revocationStore.getBlockedSdoc('d1')).toEqual({ issuedAt: 7 });
  expect(await stores.revocationStore.listBlockedSdoc()).toHaveLength(1);
  await stores.revocationStore.removeBlockedSdoc('d1');
  expect(await stores.revocationStore.getBlockedSdoc('d1')).toBeNull();
  expect((await stores.revocationStore.listSdocStatements()).map((x) => x.entry.action)).toEqual(['blockSdoc']);

  // --- trust ---
  await stores.trustStore.addPinned('k1:1');
  expect(await stores.trustStore.isPinned('k1:1')).toBe(true);
  await stores.trustStore.removePinned('k1:1');
  expect(await stores.trustStore.isPinned('k1:1')).toBe(false);
  expect(await stores.trustStore.listPinned()).toEqual([]);

  await stores.trustStore.addCa('k1:1');
  expect(await stores.trustStore.isCa('k1:1')).toBe(true);
  await stores.trustStore.removeCa('k1:1');
  expect(await stores.trustStore.isCa('k1:1')).toBe(false);
  expect(await stores.trustStore.listCa()).toEqual([]);

  await stores.trustStore.addAttestation({
    targetTcertId: 'k1:1',
    caKeyId: 'k2',
    caTcertId: 'k2:1',
    tcertHash: 'abc123',
    issuedAt: 1,
    statementBytes: new Uint8Array([1]),
  });
  expect(await stores.trustStore.getAttestations('k1:1')).toHaveLength(1);

  // Re-importing the SAME CA's attestation must REPLACE, not duplicate.
  await stores.trustStore.addAttestation({
    targetTcertId: 'k1:1',
    caKeyId: 'k2',
    caTcertId: 'k2:1',
    tcertHash: 'abc123',
    issuedAt: 1,
    statementBytes: new Uint8Array([2]),
  });
  const atts = await stores.trustStore.getAttestations('k1:1');
  expect(atts).toHaveLength(1);
  expect(atts[0]?.caTcertId).toBe('k2:1');

  // A DIFFERENT CA attesting the same target is added as a separate entry.
  await stores.trustStore.addAttestation({
    targetTcertId: 'k1:1',
    caKeyId: 'k3',
    caTcertId: 'k3:1',
    tcertHash: 'def456',
    issuedAt: 2,
    statementBytes: new Uint8Array([3]),
  });
  const twoAtts = await stores.trustStore.getAttestations('k1:1');
  expect(twoAtts).toHaveLength(2);
  expect(new Set(twoAtts.map((a) => a.caTcertId))).toEqual(new Set(['k2:1', 'k3:1']));

  await stores.trustStore.addDistrust('k1:1');
  expect(await stores.trustStore.isDistrusted('k1:1')).toBe(true);
  await stores.trustStore.removeDistrust('k1:1');
  expect(await stores.trustStore.isDistrusted('k1:1')).toBe(false);
}

describe('in-memory stores', () => {
  it('exercises every interface method', async () => {
    await exerciseStores(createInMemoryStores());
  });
});

describe('file stores', () => {
  it('exercises every interface method and persists across instances', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'qrs-'));
    try {
      await exerciseStores(createFileStores(dir));

      // A brand-new set of file stores on the same directory sees the data.
      const again = createFileStores(dir);
      expect(await again.publicKeyStore.load('k1')).toBeTruthy();
      expect(await again.revocationStore.getRevokedKey('k1')).toEqual({
        type: 'retrospective',
        issuedAt: 6,
        statementBytes: new Uint8Array([4, 5, 6]),
      });
      expect((await again.revocationStore.listSdocStatements()).map((x) => x.entry.action)).toEqual(['blockSdoc']);
      expect(await again.trustStore.isPinned('k1:1')).toBe(false);
      expect(await again.certificateStore.get('k1:1')).toBeNull();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
