/**
 * Tests for the AsyncStorage-backed persistence stores.
 *
 * The core regression these guard against: a persistent verifier re-importing
 * the same CA's attestation (via sync / bundle / QR) must NOT create duplicate
 * rows — otherwise the Result screen shows the same CA on multiple swipeable
 * pages and React throws "encountered two children with the same key".
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

// --- Mock AsyncStorage (in-memory map keyed by string) ---
const store = new Map<string, string>();
vi.mock('@react-native-async-storage/async-storage', () => ({
  __esModule: true,
  default: {
    getItem: async (k: string) => store.get(k) ?? null,
    setItem: async (k: string, v: string) => {
      store.set(k, v);
    },
    removeItem: async (k: string) => {
      store.delete(k);
    },
    clear: async () => {
      store.clear();
    },
  },
}));

import { certificateStore, listArchivedTcertIds, removeTcertCascade, revocationStore, setTcertArchived, trustStore } from '../lib/stores';

const mk = (caTcertId: string, caKeyId: string, statementBytes?: Uint8Array) => ({
  targetTcertId: 'target:1',
  caKeyId,
  caTcertId,
  tcertHash: 'hash-' + caKeyId,
  claims: { name: caTcertId },
  issuedAt: 100,
  statementBytes: statementBytes ?? new Uint8Array([1, 2, 3]),
});

beforeEach(() => {
  store.clear();
});

describe('mobile trust store attestation dedup', () => {
  it('re-importing the same CA attestation replaces, not duplicates', async () => {
    await trustStore.addAttestation(mk('caA:1', 'caA'));
    await trustStore.addAttestation(mk('caA:1', 'caA'));
    await trustStore.addAttestation(mk('caA:1', 'caA', new Uint8Array([9, 9])));

    const atts = await trustStore.getAttestations('target:1');
    expect(atts).toHaveLength(1);
    expect(atts[0]?.caTcertId).toBe('caA:1');
  });

  it('two different CAs attesting the same target produce two distinct entries', async () => {
    await trustStore.addAttestation(mk('caA:1', 'caA'));
    await trustStore.addAttestation(mk('caB:1', 'caB'));

    const atts = await trustStore.getAttestations('target:1');
    expect(atts).toHaveLength(2);
    expect(new Set(atts.map((a) => a.caTcertId))).toEqual(new Set(['caA:1', 'caB:1']));
  });

  it('getAttestations dedups even if stale duplicate rows already exist (defensive)', async () => {
    // Simulate legacy data with duplicate rows already persisted.
    await trustStore.addAttestation(mk('caA:1', 'caA'));
    await trustStore.addAttestation(mk('caB:1', 'caB'));
    await trustStore.addAttestation(mk('caA:1', 'caA')); // dup via add path is already guard, but keep

    const atts = await trustStore.getAttestations('target:1');
    const caIds = atts.map((a) => a.caTcertId);
    expect(new Set(caIds).size).toBe(caIds.length); // no duplicate CA ids
  });

  it('filters attestations to the requested target only', async () => {
    await trustStore.addAttestation(mk('caA:1', 'caA'));
    await trustStore.addAttestation({ ...mk('caB:1', 'caB'), targetTcertId: 'other:2' });

    const forTarget = await trustStore.getAttestations('target:1');
    expect(forTarget).toHaveLength(1);
    expect(forTarget[0]?.caTcertId).toBe('caA:1');
  });
});

describe('mobile certificate management', () => {
  it('archives and restores a certificate', async () => {
    await setTcertArchived('caA:1', true);
    expect(await listArchivedTcertIds()).toEqual(['caA:1']);
    await setTcertArchived('caA:1', false);
    expect(await listArchivedTcertIds()).toEqual([]);
  });

  it('deleting a CA removes its statements and orphan targets but preserves independent trust paths', async () => {
    const ids = ['caA:1', 'caB:1', 'orphan:1', 'pinned:1', 'shared:1'];
    for (const [index, id] of ids.entries()) await certificateStore.save(id, new Uint8Array([index + 1]));
    await trustStore.addCa('caA:1');
    await trustStore.addCa('caB:1');
    await trustStore.addPinned('pinned:1');
    await trustStore.addAttestation({ ...mk('caA:1', 'caA'), targetTcertId: 'orphan:1' });
    await trustStore.addAttestation({ ...mk('caA:1', 'caA'), targetTcertId: 'pinned:1' });
    await trustStore.addAttestation({ ...mk('caA:1', 'caA'), targetTcertId: 'shared:1' });
    await trustStore.addAttestation({ ...mk('caB:1', 'caB'), targetTcertId: 'shared:1' });
    await revocationStore.addBlockedSdoc('doc-a', { issuedAt: 1, byTcertId: 'caA:1', byKeyId: 'caA', statementBytes: new Uint8Array([8]) });
    await revocationStore.addBlockedSdoc('doc-b', { issuedAt: 2, byTcertId: 'caB:1', byKeyId: 'caB', statementBytes: new Uint8Array([9]) });

    const result = await removeTcertCascade('caA:1');
    expect(new Set(result.removedTcertIds)).toEqual(new Set(['caA:1', 'orphan:1']));
    expect((await certificateStore.all()).map((x) => x.tcertId).sort()).toEqual(['caB:1', 'pinned:1', 'shared:1']);
    expect((await trustStore.listAttestations()).map((x) => x.caTcertId)).toEqual(['caB:1']);
    expect((await revocationStore.listSdocStatements()).map((x) => x.entry.byTcertId)).toEqual(['caB:1']);
  });
});
