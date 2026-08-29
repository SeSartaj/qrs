/**
 * Persistent stores for the qrs-core runtime, backed by AsyncStorage.
 *
 * Only the stores a *verification* app needs are persisted: certificates (TCerts),
 * trust, revocation and documents. Private/public keys keep the in-memory defaults
 * (verification does not need to sign).
 */
import AsyncStorage from '@react-native-async-storage/async-storage';
import { parseSignedObject, toBase64Url, fromBase64Url } from 'qrs-core';
import type {
  AttestationRecord,
  BlockEntry,
  ICertificateStore,
  IDocumentStore,
  IEndpointConfigStore,
  IRevocationStore,
  ITrustStore,
  RevocationEntry,
  SdocStatementEntry,
} from 'qrs-core';

const PREFIX = 'qrs.';

function key(name: string): string {
  return PREFIX + name;
}

async function readJson<T>(name: string, fallback: T): Promise<T> {
  try {
    const raw = await AsyncStorage.getItem(key(name));
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

async function writeJson(name: string, value: unknown): Promise<void> {
  await AsyncStorage.setItem(key(name), JSON.stringify(value));
}

const b64 = (bytes: Uint8Array): string => toBase64Url(bytes);
const unb64 = (s: string): Uint8Array => fromBase64Url(s);

export const certificateStore: ICertificateStore = {
  async save(tcertId, bytes) {
    const all = await readJson<Array<{ id: string; bytes: string }>>('certificates', []);
    const idx = all.findIndex((c) => c.id === tcertId);
    const entry = { id: tcertId, bytes: b64(bytes) };
    if (idx >= 0) all[idx] = entry;
    else all.push(entry);
    await writeJson('certificates', all);
  },
  async get(tcertId) {
    const all = await readJson<Array<{ id: string; bytes: string }>>('certificates', []);
    const hit = all.find((c) => c.id === tcertId);
    return hit ? unb64(hit.bytes) : null;
  },
  async findByKeyId(keyId) {
    const all = await readJson<Array<{ id: string; bytes: string }>>('certificates', []);
    const out: Array<{ tcertId: string; bytes: Uint8Array }> = [];
    for (const c of all) {
      const bytes = unb64(c.bytes);
      try {
        const parsed = parseSignedObject(bytes);
        if (parsed.type === 'tcert' && parsed.signerKeyId === keyId) out.push({ tcertId: c.id, bytes });
      } catch {
        /* skip malformed */
      }
    }
    return out;
  },
  async all() {
    const all = await readJson<Array<{ id: string; bytes: string }>>('certificates', []);
    return all.map((c) => ({ tcertId: c.id, bytes: unb64(c.bytes) }));
  },
  async remove(tcertId) {
    const all = await readJson<Array<{ id: string; bytes: string }>>('certificates', []);
    await writeJson(
      'certificates',
      all.filter((c) => c.id !== tcertId),
    );
  },
};

export const documentStore: IDocumentStore = {
  async save(sdocId, bytes) {
    const all = await readJson<Array<{ id: string; bytes: string }>>('documents', []);
    const idx = all.findIndex((d) => d.id === sdocId);
    const entry = { id: sdocId, bytes: b64(bytes) };
    if (idx >= 0) all[idx] = entry;
    else all.push(entry);
    await writeJson('documents', all);
  },
  async get(sdocId) {
    const all = await readJson<Array<{ id: string; bytes: string }>>('documents', []);
    const hit = all.find((d) => d.id === sdocId);
    return hit ? unb64(hit.bytes) : null;
  },
  async all() {
    const all = await readJson<Array<{ id: string; bytes: string }>>('documents', []);
    return all.map((d) => ({ sdocId: d.id, bytes: unb64(d.bytes) }));
  },
  async remove(sdocId) {
    const all = await readJson<Array<{ id: string; bytes: string }>>('documents', []);
    await writeJson(
      'documents',
      all.filter((d) => d.id !== sdocId),
    );
  },
};

export const revocationStore: IRevocationStore = {
  async addRevokedTcert(tcertId, entry) {
    const map = await readJson<Record<string, RevocationEntry[]>>('revoked-tcerts', {});
    const list = map[tcertId] ?? [];
    if (entry.byKeyId) {
      const idx = list.findIndex((e) => e.byKeyId === entry.byKeyId);
      if (idx >= 0) list[idx] = entry;
      else list.push(entry);
    } else {
      list.push(entry);
    }
    map[tcertId] = list;
    await writeJson('revoked-tcerts', map);
  },
  async getRevokedTcert(tcertId) {
    const map = await readJson<Record<string, RevocationEntry[]>>('revoked-tcerts', {});
    const list = map[tcertId] ?? [];
    if (list.length === 0) return null;
    const sorted = [...list].sort((a, b) => {
      const sev = (t: RevocationEntry['type']): number => (t === 'retrospective' ? 1 : 0);
      return sev(b.type) - sev(a.type) || b.issuedAt - a.issuedAt;
    });
    return sorted[0] ?? null;
  },
  async getRevokedTcertEntries(tcertId) {
    const map = await readJson<Record<string, RevocationEntry[]>>('revoked-tcerts', {});
    return [...(map[tcertId] ?? [])];
  },
  async listRevokedTcert() {
    const map = await readJson<Record<string, RevocationEntry[]>>('revoked-tcerts', {});
    return Object.entries(map).flatMap(([tcertId, list]) =>
      list.map((entry) => ({ tcertId, entry }))
    );
  },
  async addRevokedKey(keyId, entry) {
    const map = await readJson<Record<string, RevocationEntry>>('revoked-keys', {});
    map[keyId] = entry;
    await writeJson('revoked-keys', map);
  },
  async getRevokedKey(keyId) {
    const map = await readJson<Record<string, RevocationEntry>>('revoked-keys', {});
    return map[keyId] ?? null;
  },
  async listRevokedKey() {
    const map = await readJson<Record<string, RevocationEntry>>('revoked-keys', {});
    return Object.entries(map).map(([keyId, entry]) => ({ keyId, entry }));
  },
  async addRevokedAttestation(targetTcertId, caTcertId, entry) {
    const map = await readJson<Record<string, RevocationEntry>>('revoked-attestations', {});
    map[`${targetTcertId}|${caTcertId}`] = entry;
    await writeJson('revoked-attestations', map);
  },
  async getRevokedAttestation(targetTcertId, caTcertId) {
    const map = await readJson<Record<string, RevocationEntry>>('revoked-attestations', {});
    return map[`${targetTcertId}|${caTcertId}`] ?? null;
  },
  async listRevokedAttestation() {
    const map = await readJson<Record<string, RevocationEntry>>('revoked-attestations', {});
    return Object.entries(map).map(([key, entry]) => {
      const [targetTcertId, caTcertId] = key.split('|');
      return { targetTcertId: targetTcertId!, caTcertId: caTcertId!, entry };
    });
  },
  async addBlockedSdoc(sdocId, entry) {
    const map = await readJson<Record<string, BlockEntry>>('blocked-sdocs', {});
    map[sdocId] = entry;
    await writeJson('blocked-sdocs', map);
    const history = await readJson<Array<{ sdocId: string; entry: Omit<SdocStatementEntry, 'statementBytes'> & { statementBytes?: string } }>>('sdoc-statements', []);
    history.push({ sdocId, entry: { ...entry, action: 'blockSdoc', statementBytes: entry.statementBytes ? b64(entry.statementBytes) : undefined } });
    await writeJson('sdoc-statements', history);
  },
  async getBlockedSdoc(sdocId) {
    const map = await readJson<Record<string, BlockEntry>>('blocked-sdocs', {});
    return map[sdocId] ?? null;
  },
  async listBlockedSdoc() {
    const map = await readJson<Record<string, BlockEntry>>('blocked-sdocs', {});
    return Object.entries(map).map(([sdocId, entry]) => ({ sdocId, entry }));
  },
  async removeBlockedSdoc(sdocId, entry) {
    const map = await readJson<Record<string, BlockEntry>>('blocked-sdocs', {});
    delete map[sdocId];
    await writeJson('blocked-sdocs', map);
    if (entry) {
      const history = await readJson<Array<{ sdocId: string; entry: Omit<SdocStatementEntry, 'statementBytes'> & { statementBytes?: string } }>>('sdoc-statements', []);
      history.push({ sdocId, entry: { ...entry, action: 'unblockSdoc', statementBytes: entry.statementBytes ? b64(entry.statementBytes) : undefined } });
      await writeJson('sdoc-statements', history);
    }
  },
  async listSdocStatements() {
    const history = await readJson<Array<{ sdocId: string; entry: Omit<SdocStatementEntry, 'statementBytes'> & { statementBytes?: string } }>>('sdoc-statements', []);
    return history.map(({ sdocId, entry }) => ({
      sdocId,
      entry: { ...entry, statementBytes: entry.statementBytes ? unb64(entry.statementBytes) : undefined } as SdocStatementEntry,
    }));
  },
};

type StoredAttestation = Omit<AttestationRecord, 'statementBytes'> & { statementBytes: string };

export const trustStore: ITrustStore = {
  async addPinned(tcertId) {
    const list = await readJson<string[]>('pinned', []);
    if (!list.includes(tcertId)) {
      list.push(tcertId);
      await writeJson('pinned', list);
    }
  },
  async removePinned(tcertId) {
    const list = await readJson<string[]>('pinned', []);
    await writeJson(
      'pinned',
      list.filter((id) => id !== tcertId),
    );
  },
  async isPinned(tcertId) {
    const list = await readJson<string[]>('pinned', []);
    return list.includes(tcertId);
  },
  async listPinned() {
    return readJson<string[]>('pinned', []);
  },
  async addCa(tcertId) {
    const list = await readJson<string[]>('cas', []);
    if (!list.includes(tcertId)) {
      list.push(tcertId);
      await writeJson('cas', list);
    }
  },
  async removeCa(tcertId) {
    const list = await readJson<string[]>('cas', []);
    await writeJson(
      'cas',
      list.filter((id) => id !== tcertId),
    );
  },
  async isCa(tcertId) {
    const list = await readJson<string[]>('cas', []);
    return list.includes(tcertId);
  },
  async listCa() {
    return readJson<string[]>('cas', []);
  },
  async addAttestation(record) {
    const list = await readJson<StoredAttestation[]>('attestations', []);
    const entry: StoredAttestation = {
      targetTcertId: record.targetTcertId,
      caKeyId: record.caKeyId,
      caTcertId: record.caTcertId,
      tcertHash: record.tcertHash,
      claims: record.claims,
      issuedAt: record.issuedAt,
      statementBytes: b64(record.statementBytes),
    };
    // One attestation per (target, CA): re-importing the same CA's attestation
    // must replace, not duplicate. Mirrors qrs-core's FileTrustStore behavior
    // and keeps the per-CA result pages unique (no duplicate React keys).
    const idx = list.findIndex(
      (a) => a.targetTcertId === record.targetTcertId && a.caTcertId === record.caTcertId
    );
    if (idx >= 0) list[idx] = entry;
    else list.push(entry);
    await writeJson('attestations', list);
  },
  async getAttestations(targetTcertId) {
    const list = await readJson<StoredAttestation[]>('attestations', []);
    // Defensive dedup by (target, CA) so stale duplicates never surface.
    const seen = new Set<string>();
    const deduped = list.filter((a) => {
      if (a.targetTcertId !== targetTcertId) return false;
      const k = a.caTcertId;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
    return deduped.map((a) => ({ ...a, statementBytes: unb64(a.statementBytes) }));
  },
  async listAttestations() {
    const list = await readJson<StoredAttestation[]>('attestations', []);
    return list.map((record) => ({ ...record, statementBytes: fromBase64Url(record.statementBytes) }));
  },
  async addDistrust(tcertId) {
    const list = await readJson<string[]>('distrusted', []);
    if (!list.includes(tcertId)) {
      list.push(tcertId);
      await writeJson('distrusted', list);
    }
  },
  async removeDistrust(tcertId) {
    const list = await readJson<string[]>('distrusted', []);
    await writeJson(
      'distrusted',
      list.filter((id) => id !== tcertId),
    );
  },
  async isDistrusted(tcertId) {
    const list = await readJson<string[]>('distrusted', []);
    return list.includes(tcertId);
  },
};

export async function listArchivedTcertIds(): Promise<string[]> {
  return readJson<string[]>('archived-tcerts', []);
}

export async function setTcertArchived(tcertId: string, archived: boolean): Promise<void> {
  const ids = await listArchivedTcertIds();
  await writeJson('archived-tcerts', archived ? [...new Set([...ids, tcertId])] : ids.filter((id) => id !== tcertId));
}

/** Delete a certificate and the trust graph that depends exclusively on it. */
export async function removeTcertCascade(tcertId: string): Promise<{ removedTcertIds: string[] }> {
  const keyId = tcertId.slice(0, tcertId.lastIndexOf(':'));
  const attestations = await readJson<StoredAttestation[]>('attestations', []);
  const issuedByRemoved = attestations.filter((a) => a.caTcertId === tcertId);
  const remainingAttestations = attestations.filter((a) => a.caTcertId !== tcertId);
  const pinned = await readJson<string[]>('pinned', []);
  const orphanedTargets = issuedByRemoved
    .map((a) => a.targetTcertId)
    .filter((targetId, index, all) => all.indexOf(targetId) === index)
    .filter((targetId) => !pinned.includes(targetId) && !remainingAttestations.some((a) => a.targetTcertId === targetId));
  const removedTcertIds = [tcertId, ...orphanedTargets];
  const removed = new Set(removedTcertIds);

  await writeJson('attestations', remainingAttestations.filter((a) => !removed.has(a.targetTcertId)));
  await writeJson('pinned', pinned.filter((id) => !removed.has(id)));
  await writeJson('cas', (await readJson<string[]>('cas', [])).filter((id) => !removed.has(id)));
  await writeJson('distrusted', (await readJson<string[]>('distrusted', [])).filter((id) => !removed.has(id)));
  await writeJson('archived-tcerts', (await listArchivedTcertIds()).filter((id) => !removed.has(id)));

  const certificates = await readJson<Array<{ id: string; bytes: string }>>('certificates', []);
  await writeJson('certificates', certificates.filter((cert) => !removed.has(cert.id)));

  const signedByRemoved = <T extends { byKeyId?: string; byTcertId?: string }>(entry: T): boolean =>
    entry.byTcertId === tcertId || (!entry.byTcertId && entry.byKeyId === keyId);
  const revokedTcerts = await readJson<Record<string, RevocationEntry[]>>('revoked-tcerts', {});
  for (const [targetId, entries] of Object.entries(revokedTcerts)) {
    const kept = entries.filter((entry) => !signedByRemoved(entry));
    if (kept.length > 0 && !removed.has(targetId)) revokedTcerts[targetId] = kept;
    else delete revokedTcerts[targetId];
  }
  await writeJson('revoked-tcerts', revokedTcerts);
  const revokedKeys = await readJson<Record<string, RevocationEntry>>('revoked-keys', {});
  for (const [targetId, entry] of Object.entries(revokedKeys)) if (signedByRemoved(entry)) delete revokedKeys[targetId];
  await writeJson('revoked-keys', revokedKeys);
  const revokedAttestations = await readJson<Record<string, RevocationEntry>>('revoked-attestations', {});
  for (const [relation, entry] of Object.entries(revokedAttestations)) {
    const [targetId, caId] = relation.split('|');
    if (caId === tcertId || removed.has(targetId!) || signedByRemoved(entry)) delete revokedAttestations[relation];
  }
  await writeJson('revoked-attestations', revokedAttestations);
  const blocked = await readJson<Record<string, BlockEntry>>('blocked-sdocs', {});
  for (const [sdocId, entry] of Object.entries(blocked)) if (signedByRemoved(entry)) delete blocked[sdocId];
  await writeJson('blocked-sdocs', blocked);
  const sdocStatements = await readJson<Array<{ sdocId: string; entry: SdocStatementEntry }>>('sdoc-statements', []);
  await writeJson('sdoc-statements', sdocStatements.filter(({ entry }) => !signedByRemoved(entry)));

  return { removedTcertIds };
}

/** App-local distribution mirror endpoints per TCert (convenience, not protocol). */
export const endpointConfigStore: IEndpointConfigStore = {
  async getEndpoints(tcertId) {
    return readJson<string[]>(`endpoints.${tcertId}`, []);
  },
  async setEndpoints(tcertId, endpoints) {
    await writeJson(`endpoints.${tcertId}`, [...new Set(endpoints)]);
  },
  async addEndpoint(tcertId, endpoint) {
    const list = await readJson<string[]>(`endpoints.${tcertId}`, []);
    if (!list.includes(endpoint)) {
      list.push(endpoint);
      await writeJson(`endpoints.${tcertId}`, list);
    }
  },
  async removeEndpoint(tcertId, endpoint) {
    const list = await readJson<string[]>(`endpoints.${tcertId}`, []);
    await writeJson(
      `endpoints.${tcertId}`,
      list.filter((e) => e !== endpoint),
    );
  },
};

/** All persisted stores as one object for `createQrsWeb`. */
export const persistedStores = {
  certificateStore,
  documentStore,
  revocationStore,
  trustStore,
  endpointConfigStore,
};
