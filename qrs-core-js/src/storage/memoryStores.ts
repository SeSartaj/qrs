/**
 * Default in-memory implementations of every storage interface.
 * These are what `createQrs()` wires in when no store is provided.
 */
import type { AlgorithmId, KeyId, RevocationType, SdocId, TcertId } from '../types.js';
import type { PrivateJwk, PublicJwk } from '../crypto/jwk.js';
import type {
  AttestationRecord,
  BlockEntry,
  ICertificateStore,
  IDocumentStore,
  IEndpointConfigStore,
  IPrivateKeyStore,
  IPublicKeyStore,
  IRevocationStore,
  ITrustStore,
  RevocationEntry,
} from './stores.js';

export class InMemoryPrivateKeyStore implements IPrivateKeyStore {
  private readonly map = new Map<KeyId, { algorithm: AlgorithmId; privateJwk: PrivateJwk }>();
  async save(keyId: KeyId, algorithm: AlgorithmId, privateJwk: PrivateJwk): Promise<void> {
    this.map.set(keyId, { algorithm, privateJwk });
  }
  async load(keyId: KeyId) {
    return this.map.get(keyId) ?? null;
  }
  async has(keyId: KeyId) {
    return this.map.has(keyId);
  }
  async all() {
    return [...this.map.entries()].map(([keyId, v]) => ({ keyId, algorithm: v.algorithm }));
  }
}

export class InMemoryPublicKeyStore implements IPublicKeyStore {
  private readonly map = new Map<KeyId, { algorithm: AlgorithmId; publicJwk: PublicJwk }>();
  async save(keyId: KeyId, algorithm: AlgorithmId, publicJwk: PublicJwk): Promise<void> {
    this.map.set(keyId, { algorithm, publicJwk });
  }
  async load(keyId: KeyId) {
    return this.map.get(keyId) ?? null;
  }
  async has(keyId: KeyId) {
    return this.map.has(keyId);
  }
  async all() {
    return [...this.map.entries()].map(([keyId, v]) => ({ keyId, algorithm: v.algorithm, publicJwk: v.publicJwk }));
  }
}

export class InMemoryCertificateStore implements ICertificateStore {
  private readonly map = new Map<TcertId, Uint8Array>();
  async save(tcertId: TcertId, bytes: Uint8Array): Promise<void> {
    this.map.set(tcertId, new Uint8Array(bytes));
  }
  async get(tcertId: TcertId) {
    const bytes = this.map.get(tcertId);
    return bytes ? new Uint8Array(bytes) : null;
  }
  async findByKeyId(keyId: KeyId) {
    return [...this.map.entries()]
      .filter(([tcertId]) => tcertId.startsWith(`${keyId}:`))
      .map(([tcertId, bytes]) => ({ tcertId, bytes: new Uint8Array(bytes) }));
  }
  async all() {
    return [...this.map.entries()].map(([tcertId, bytes]) => ({ tcertId, bytes: new Uint8Array(bytes) }));
  }
  async remove(tcertId: TcertId): Promise<void> {
    this.map.delete(tcertId);
  }
}

export class InMemoryDocumentStore implements IDocumentStore {
  private readonly map = new Map<SdocId, Uint8Array>();
  async save(sdocId: SdocId, bytes: Uint8Array): Promise<void> {
    this.map.set(sdocId, new Uint8Array(bytes));
  }
  async get(sdocId: SdocId) {
    const bytes = this.map.get(sdocId);
    return bytes ? new Uint8Array(bytes) : null;
  }
  async all() {
    return [...this.map.entries()].map(([sdocId, bytes]) => ({ sdocId, bytes: new Uint8Array(bytes) }));
  }
  async remove(sdocId: SdocId): Promise<void> {
    this.map.delete(sdocId);
  }
}

export class InMemoryRevocationStore implements IRevocationStore {
  private readonly revokedTcert = new Map<TcertId, RevocationEntry[]>();
  private readonly revokedKey = new Map<KeyId, RevocationEntry>();
  private readonly revokedAttestation = new Map<string, RevocationEntry>();
  private readonly blockedSdoc = new Map<SdocId, BlockEntry>();
  private readonly sdocStatements: Array<{ sdocId: SdocId; entry: import('./stores.js').SdocStatementEntry }> = [];

  async addRevokedTcert(tcertId: TcertId, entry: RevocationEntry): Promise<void> {
    const list = this.revokedTcert.get(tcertId) ?? [];
    // One revocation per revoker (by key): re-importing the same revoker's
    // statement is a no-op, but a different revoker is added independently.
    if (entry.byKeyId) {
      const idx = list.findIndex((e) => e.byKeyId === entry.byKeyId);
      if (idx >= 0) list[idx] = entry;
      else list.push(entry);
    } else {
      list.push(entry);
    }
    this.revokedTcert.set(tcertId, list);
  }
  async getRevokedTcert(tcertId: TcertId): Promise<RevocationEntry | null> {
    const list = this.revokedTcert.get(tcertId) ?? [];
    if (list.length === 0) return null;
    // Most severe = the latest (retrospective overrides prospective; latest wins).
    const sorted = [...list].sort((a, b) => {
      const sev = (t: RevocationType): number => (t === 'retrospective' ? 1 : 0);
      return sev(b.type) - sev(a.type) || b.issuedAt - a.issuedAt;
    });
    return sorted[0] ?? null;
  }
  async getRevokedTcertEntries(tcertId: TcertId): Promise<RevocationEntry[]> {
    return [...(this.revokedTcert.get(tcertId) ?? [])];
  }
  async listRevokedTcert() {
    return [...this.revokedTcert.entries()].flatMap(([tcertId, list]) =>
      list.map((entry) => ({ tcertId, entry }))
    );
  }
  async addRevokedKey(keyId: KeyId, entry: RevocationEntry): Promise<void> {
    this.revokedKey.set(keyId, entry);
  }
  async getRevokedKey(keyId: KeyId) {
    return this.revokedKey.get(keyId) ?? null;
  }
  async listRevokedKey() {
    return [...this.revokedKey.entries()].map(([keyId, entry]) => ({ keyId, entry }));
  }
  async addRevokedAttestation(targetTcertId: TcertId, caTcertId: TcertId, entry: RevocationEntry) {
    this.revokedAttestation.set(`${targetTcertId}|${caTcertId}`, entry);
  }
  async getRevokedAttestation(targetTcertId: TcertId, caTcertId: TcertId) {
    return this.revokedAttestation.get(`${targetTcertId}|${caTcertId}`) ?? null;
  }
  async listRevokedAttestation() {
    return [...this.revokedAttestation.entries()].map(([key, entry]) => {
      const [targetTcertId, caTcertId] = key.split('|');
      return { targetTcertId: targetTcertId!, caTcertId: caTcertId!, entry };
    });
  }
  async addBlockedSdoc(sdocId: SdocId, entry: BlockEntry): Promise<void> {
    this.blockedSdoc.set(sdocId, entry);
    this.sdocStatements.push({ sdocId, entry: { ...entry, action: 'blockSdoc' } });
  }
  async getBlockedSdoc(sdocId: SdocId) {
    return this.blockedSdoc.get(sdocId) ?? null;
  }
  async listBlockedSdoc() {
    return [...this.blockedSdoc.entries()].map(([sdocId, entry]) => ({ sdocId, entry }));
  }
  async removeBlockedSdoc(sdocId: SdocId, entry?: BlockEntry): Promise<void> {
    this.blockedSdoc.delete(sdocId);
    if (entry) this.sdocStatements.push({ sdocId, entry: { ...entry, action: 'unblockSdoc' } });
  }
  async listSdocStatements() {
    return this.sdocStatements.map(({ sdocId, entry }) => ({ sdocId, entry: { ...entry } }));
  }
}

export class InMemoryTrustStore implements ITrustStore {
  private readonly pinned = new Set<TcertId>();
  private readonly cas = new Set<TcertId>();
  private readonly distrusted = new Set<TcertId>();
  private readonly attestations = new Map<TcertId, AttestationRecord[]>();

  async addPinned(tcertId: TcertId): Promise<void> {
    this.pinned.add(tcertId);
  }
  async removePinned(tcertId: TcertId): Promise<void> {
    this.pinned.delete(tcertId);
  }
  async isPinned(tcertId: TcertId) {
    return this.pinned.has(tcertId);
  }
  async listPinned() {
    return [...this.pinned];
  }
  async addCa(tcertId: TcertId): Promise<void> {
    this.cas.add(tcertId);
  }
  async removeCa(tcertId: TcertId): Promise<void> {
    this.cas.delete(tcertId);
  }
  async isCa(tcertId: TcertId) {
    return this.cas.has(tcertId);
  }
  async listCa() {
    return [...this.cas];
  }
  async addAttestation(record: AttestationRecord): Promise<void> {
    const list = this.attestations.get(record.targetTcertId) ?? [];
    // One attestation per (target, CA): re-importing the same CA's attestation
    // replaces the existing one instead of accumulating duplicates.
    const idx = list.findIndex((a) => a.caTcertId === record.caTcertId);
    if (idx >= 0) list[idx] = record;
    else list.push(record);
    this.attestations.set(record.targetTcertId, list);
  }
  async getAttestations(targetTcertId: TcertId) {
    return this.attestations.get(targetTcertId) ?? [];
  }
  async listAttestations() {
    return [...this.attestations.values()].flat();
  }
  async addDistrust(tcertId: TcertId): Promise<void> {
    this.distrusted.add(tcertId);
  }
  async removeDistrust(tcertId: TcertId): Promise<void> {
    this.distrusted.delete(tcertId);
  }
  async isDistrusted(tcertId: TcertId) {
    return this.distrusted.has(tcertId);
  }
}

/** All default in-memory stores as one object (convenience). */
export function createInMemoryStores(): {
  privateKeyStore: IPrivateKeyStore;
  publicKeyStore: IPublicKeyStore;
  certificateStore: ICertificateStore;
  documentStore: IDocumentStore;
  revocationStore: IRevocationStore;
  trustStore: ITrustStore;
  endpointConfigStore: IEndpointConfigStore;
} {
  return {
    privateKeyStore: new InMemoryPrivateKeyStore(),
    publicKeyStore: new InMemoryPublicKeyStore(),
    certificateStore: new InMemoryCertificateStore(),
    documentStore: new InMemoryDocumentStore(),
    revocationStore: new InMemoryRevocationStore(),
    trustStore: new InMemoryTrustStore(),
    endpointConfigStore: new InMemoryEndpointConfigStore(),
  };
}

export class InMemoryEndpointConfigStore implements IEndpointConfigStore {
  private readonly map = new Map<TcertId, string[]>();
  async getEndpoints(tcertId: TcertId) {
    return [...(this.map.get(tcertId) ?? [])];
  }
  async setEndpoints(tcertId: TcertId, endpoints: string[]) {
    this.map.set(tcertId, [...new Set(endpoints)]);
  }
  async addEndpoint(tcertId: TcertId, endpoint: string) {
    const list = this.map.get(tcertId) ?? [];
    if (!list.includes(endpoint)) {
      list.push(endpoint);
      this.map.set(tcertId, list);
    }
  }
  async removeEndpoint(tcertId: TcertId, endpoint: string) {
    const list = this.map.get(tcertId) ?? [];
    const next = list.filter((e) => e !== endpoint);
    if (next.length !== list.length) this.map.set(tcertId, next);
  }
}
