/**
 * JSON-file-backed storage implementations.
 *
 * These are provided so the CLI can persist state between invocations. A consumer
 * who wants a real database or key vault simply implements the interfaces instead.
 * Data is stored as compact JSON; byte strings are base64url.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AlgorithmId, KeyId, RevocationType, SdocId, TcertId } from '../types.js';
import type { PrivateJwk, PublicJwk } from '../crypto/jwk.js';
import { fromBase64Url, toBase64Url } from '../id.js';
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
  SdocStatementEntry,
} from './stores.js';

type JsonRecord = Record<string, unknown>;

class JsonFileStore<T> {
  private readonly map = new Map<string, T>();

  constructor(
    private readonly file: string,
    private readonly encode: (value: T) => unknown,
    private readonly decode: (raw: unknown) => T
  ) {
    this.load();
  }

  private load(): void {
    if (!existsSync(this.file)) return;
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(this.file, 'utf8'));
    } catch {
      parsed = {};
    }
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
      for (const [key, value] of Object.entries(parsed as JsonRecord)) {
        this.map.set(key, this.decode(value));
      }
    }
  }

  private persist(): void {
    const out: JsonRecord = {};
    for (const [key, value] of this.map) out[key] = this.encode(value);
    writeFileSync(this.file, JSON.stringify(out));
  }

  get(key: string): T | undefined {
    return this.map.get(key);
  }

  set(key: string, value: T): void {
    this.map.set(key, value);
    this.persist();
  }

  delete(key: string): void {
    if (this.map.delete(key)) this.persist();
  }

  entries(): Array<[string, T]> {
    return [...this.map.entries()];
  }
}

const bytesEncode = (b: Uint8Array) => toBase64Url(b);
const bytesDecode = (r: unknown) => fromBase64Url(String(r));

function encodeAttestation(value: { value: AttestationRecord }): unknown {
  return { value: { ...value.value, statementBytes: toBase64Url(value.value.statementBytes) } };
}

function decodeAttestation(raw: unknown): { value: AttestationRecord } {
  const value = (raw as { value?: Record<string, unknown> })?.value ?? {};
  const encoded = value.statementBytes;
  let statementBytes: Uint8Array;
  if (typeof encoded === 'string') statementBytes = fromBase64Url(encoded);
  else if (encoded && typeof encoded === 'object') statementBytes = new Uint8Array(Object.values(encoded as Record<string, number>));
  else statementBytes = new Uint8Array();
  return { value: { ...value, statementBytes } as unknown as AttestationRecord };
}

function encodeStatementBytes<T extends { statementBytes?: Uint8Array }>(value: T): unknown {
  return {
    ...value,
    ...(value.statementBytes ? { statementBytes: toBase64Url(value.statementBytes) } : {}),
  };
}

function decodeStatementBytes<T extends { statementBytes?: Uint8Array }>(raw: unknown): T {
  const value = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const encoded = value.statementBytes;
  let statementBytes: Uint8Array | undefined;
  if (typeof encoded === 'string') statementBytes = fromBase64Url(encoded);
  // Backward compatibility for records written before statement bytes had an
  // explicit JSON codec, when Uint8Array was serialized as a numeric object.
  else if (encoded && typeof encoded === 'object') {
    statementBytes = new Uint8Array(Object.values(encoded as Record<string, number>));
  }
  return { ...value, ...(statementBytes ? { statementBytes } : {}) } as T;
}

export class FilePrivateKeyStore implements IPrivateKeyStore {
  private readonly store: JsonFileStore<{ algorithm: AlgorithmId; privateJwk: PrivateJwk }>;
  constructor(dir: string) {
    this.store = new JsonFileStore(join(dir, 'private-keys.json'), (v) => v, (r) => r as never);
  }
  async save(keyId: KeyId, algorithm: AlgorithmId, privateJwk: PrivateJwk): Promise<void> {
    this.store.set(keyId, { algorithm, privateJwk });
  }
  async load(keyId: KeyId) {
    return this.store.get(keyId) ?? null;
  }
  async has(keyId: KeyId) {
    return this.store.get(keyId) !== undefined;
  }
  async all() {
    return this.store.entries().map(([keyId, v]) => ({ keyId, algorithm: v.algorithm }));
  }
}

export class FilePublicKeyStore implements IPublicKeyStore {
  private readonly store: JsonFileStore<{ algorithm: AlgorithmId; publicJwk: PublicJwk }>;
  constructor(dir: string) {
    this.store = new JsonFileStore(join(dir, 'public-keys.json'), (v) => v, (r) => r as never);
  }
  async save(keyId: KeyId, algorithm: AlgorithmId, publicJwk: PublicJwk): Promise<void> {
    this.store.set(keyId, { algorithm, publicJwk });
  }
  async load(keyId: KeyId) {
    return this.store.get(keyId) ?? null;
  }
  async has(keyId: KeyId) {
    return this.store.get(keyId) !== undefined;
  }
  async all() {
    return this.store.entries().map(([keyId, v]) => ({ keyId, algorithm: v.algorithm, publicJwk: v.publicJwk }));
  }
}

export class FileCertificateStore implements ICertificateStore {
  private readonly store: JsonFileStore<Uint8Array>;
  constructor(dir: string) {
    this.store = new JsonFileStore(join(dir, 'certificates.json'), bytesEncode, bytesDecode);
  }
  async save(tcertId: TcertId, bytes: Uint8Array): Promise<void> {
    this.store.set(tcertId, new Uint8Array(bytes));
  }
  async get(tcertId: TcertId) {
    const b = this.store.get(tcertId);
    return b ? new Uint8Array(b) : null;
  }
  async findByKeyId(keyId: KeyId) {
    return this.store
      .entries()
      .filter(([tcertId]) => tcertId.startsWith(`${keyId}:`))
      .map(([tcertId, bytes]) => ({ tcertId, bytes: new Uint8Array(bytes) }));
  }
  async all() {
    return this.store.entries().map(([tcertId, bytes]) => ({ tcertId, bytes: new Uint8Array(bytes) }));
  }
  async remove(tcertId: TcertId): Promise<void> {
    this.store.delete(tcertId);
  }
}

export class FileDocumentStore implements IDocumentStore {
  private readonly store: JsonFileStore<Uint8Array>;
  constructor(dir: string) {
    this.store = new JsonFileStore(join(dir, 'documents.json'), bytesEncode, bytesDecode);
  }
  async save(sdocId: SdocId, bytes: Uint8Array): Promise<void> {
    this.store.set(sdocId, new Uint8Array(bytes));
  }
  async get(sdocId: SdocId) {
    const b = this.store.get(sdocId);
    return b ? new Uint8Array(b) : null;
  }
  async all() {
    return this.store.entries().map(([sdocId, bytes]) => ({ sdocId, bytes: new Uint8Array(bytes) }));
  }
  async remove(sdocId: SdocId): Promise<void> {
    this.store.delete(sdocId);
  }
}

export class FileRevocationStore implements IRevocationStore {
  private readonly revokedTcert: JsonFileStore<RevocationEntry[]>;
  private readonly revokedKey: JsonFileStore<RevocationEntry>;
  private readonly revokedAttestation: JsonFileStore<RevocationEntry>;
  private readonly blockedSdoc: JsonFileStore<BlockEntry>;
  private readonly sdocStatements: JsonFileStore<SdocStatementEntry>;
  constructor(dir: string) {
    this.revokedTcert = new JsonFileStore(
      join(dir, 'revoked-tcerts.json'),
      (entries) => entries.map(encodeStatementBytes),
      (raw) => (Array.isArray(raw) ? raw.map((entry) => decodeStatementBytes<RevocationEntry>(entry)) : [])
    );
    this.revokedKey = new JsonFileStore(
      join(dir, 'revoked-keys.json'),
      encodeStatementBytes,
      (raw) => decodeStatementBytes<RevocationEntry>(raw)
    );
    this.revokedAttestation = new JsonFileStore(
      join(dir, 'revoked-attestations.json'), encodeStatementBytes,
      (raw) => decodeStatementBytes<RevocationEntry>(raw)
    );
    this.blockedSdoc = new JsonFileStore(
      join(dir, 'blocked-sdocs.json'),
      encodeStatementBytes,
      (raw) => decodeStatementBytes<BlockEntry>(raw)
    );
    this.sdocStatements = new JsonFileStore(
      join(dir, 'sdoc-statements.json'),
      encodeStatementBytes,
      (raw) => decodeStatementBytes<SdocStatementEntry>(raw)
    );
  }
  async addRevokedTcert(tcertId: TcertId, entry: RevocationEntry): Promise<void> {
    const list = this.revokedTcert.get(tcertId) ?? [];
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
    return this.revokedTcert
      .entries()
      .flatMap(([tcertId, list]) => list.map((entry) => ({ tcertId, entry })));
  }
  async addRevokedKey(keyId: KeyId, entry: RevocationEntry): Promise<void> {
    this.revokedKey.set(keyId, entry);
  }
  async getRevokedKey(keyId: KeyId) {
    return this.revokedKey.get(keyId) ?? null;
  }
  async listRevokedKey() {
    return this.revokedKey.entries().map(([keyId, entry]) => ({ keyId, entry }));
  }
  async addRevokedAttestation(targetTcertId: TcertId, caTcertId: TcertId, entry: RevocationEntry) {
    this.revokedAttestation.set(`${targetTcertId}|${caTcertId}`, entry);
  }
  async getRevokedAttestation(targetTcertId: TcertId, caTcertId: TcertId) {
    return this.revokedAttestation.get(`${targetTcertId}|${caTcertId}`) ?? null;
  }
  async listRevokedAttestation() {
    return this.revokedAttestation.entries().map(([key, entry]) => {
      const [targetTcertId, caTcertId] = key.split('|');
      return { targetTcertId: targetTcertId!, caTcertId: caTcertId!, entry };
    });
  }
  async addBlockedSdoc(sdocId: SdocId, entry: BlockEntry): Promise<void> {
    this.blockedSdoc.set(sdocId, entry);
    this.sdocStatements.set(`${sdocId}|${entry.issuedAt}|blockSdoc`, { ...entry, action: 'blockSdoc' });
  }
  async getBlockedSdoc(sdocId: SdocId) {
    return this.blockedSdoc.get(sdocId) ?? null;
  }
  async listBlockedSdoc() {
    return this.blockedSdoc.entries().map(([sdocId, entry]) => ({ sdocId, entry }));
  }
  async removeBlockedSdoc(sdocId: SdocId, entry?: BlockEntry): Promise<void> {
    this.blockedSdoc.delete(sdocId);
    if (entry) this.sdocStatements.set(`${sdocId}|${entry.issuedAt}|unblockSdoc`, { ...entry, action: 'unblockSdoc' });
  }
  async listSdocStatements() {
    return this.sdocStatements.entries().map(([key, entry]) => ({ sdocId: key.split('|', 1)[0]!, entry }));
  }
}

export class FileTrustStore implements ITrustStore {
  private readonly pinned: JsonFileStore<true>;
  private readonly cas: JsonFileStore<true>;
  private readonly distrusted: JsonFileStore<true>;
  private readonly attestations: JsonFileStore<{ value: AttestationRecord }>;
  constructor(dir: string) {
    this.pinned = new JsonFileStore(join(dir, 'trust-pinned.json'), (v) => v, (r) => r as never);
    this.cas = new JsonFileStore(join(dir, 'trust-cas.json'), (v) => v, (r) => r as never);
    this.distrusted = new JsonFileStore(join(dir, 'trust-distrusted.json'), (v) => v, (r) => r as never);
    this.attestations = new JsonFileStore(
      join(dir, 'trust-attestations.json'),
      encodeAttestation,
      decodeAttestation
    );
  }
  async addPinned(tcertId: TcertId): Promise<void> {
    this.pinned.set(tcertId, true);
  }
  async removePinned(tcertId: TcertId): Promise<void> {
    this.pinned.delete(tcertId);
  }
  async isPinned(tcertId: TcertId) {
    return this.pinned.get(tcertId) !== undefined;
  }
  async listPinned() {
    return this.pinned.entries().map(([k]) => k);
  }
  async addCa(tcertId: TcertId): Promise<void> {
    this.cas.set(tcertId, true);
  }
  async removeCa(tcertId: TcertId): Promise<void> {
    this.cas.delete(tcertId);
  }
  async isCa(tcertId: TcertId) {
    return this.cas.get(tcertId) !== undefined;
  }
  async listCa() {
    return this.cas.entries().map(([k]) => k);
  }
  async addAttestation(record: AttestationRecord): Promise<void> {
    // One attestation per (target, CA): re-importing the same CA's attestation
    // replaces the existing one instead of accumulating duplicates.
    const existing = this.attestations
      .entries()
      .find(([key]) => this.attestationKeyMatches(key, record.targetTcertId, record.caTcertId));
    if (existing) {
      this.attestations.set(existing[0], { value: record });
    } else {
      const key = `${record.targetTcertId}|${record.caTcertId}|${record.issuedAt}`;
      this.attestations.set(key, { value: record });
    }
  }
  async getAttestations(targetTcertId: TcertId) {
    return this.attestations
      .entries()
      .filter(([key]) => this.attestationKeyMatches(key, targetTcertId))
      .map(([, v]) => v.value);
  }
  async listAttestations() {
    return this.attestations.entries().map(([, v]) => v.value);
  }
  /**
   * Match an attestation storage key against a target (and optional CA). Keys
   * are `target|cA|issuedAt`; only the prefix (target, CA) identifies a unique
   * attestation so a single CA's re-attestation never produces a duplicate row.
   */
  private attestationKeyMatches(key: string, targetTcertId: string, caTcertId?: string): boolean {
    const parts = key.split('|');
    if (parts[0] !== targetTcertId) return false;
    if (caTcertId !== undefined && parts[1] !== caTcertId) return false;
    return true;
  }
  async addDistrust(tcertId: TcertId): Promise<void> {
    this.distrusted.set(tcertId, true);
  }
  async removeDistrust(tcertId: TcertId): Promise<void> {
    this.distrusted.delete(tcertId);
  }
  async isDistrusted(tcertId: TcertId) {
    return this.distrusted.get(tcertId) !== undefined;
  }
}

export class FileEndpointConfigStore implements IEndpointConfigStore {
  private readonly store: JsonFileStore<string[]>;
  constructor(dir: string) {
    this.store = new JsonFileStore(join(dir, 'endpoint-config.json'), (v) => v, (r) => (Array.isArray(r) ? r : []));
  }
  async getEndpoints(tcertId: TcertId) {
    return this.store.get(tcertId) ?? [];
  }
  async setEndpoints(tcertId: TcertId, endpoints: string[]) {
    this.store.set(tcertId, [...new Set(endpoints)]);
  }
  async addEndpoint(tcertId: TcertId, endpoint: string) {
    const list = this.store.get(tcertId) ?? [];
    if (!list.includes(endpoint)) {
      list.push(endpoint);
      this.store.set(tcertId, list);
    }
  }
  async removeEndpoint(tcertId: TcertId, endpoint: string) {
    const list = this.store.get(tcertId) ?? [];
    const next = list.filter((e) => e !== endpoint);
    if (next.length !== list.length) this.store.set(tcertId, next);
  }
}

/** Build all file-backed stores under `dir` (created on demand). */
export function createFileStores(dir: string): {
  privateKeyStore: IPrivateKeyStore;
  publicKeyStore: IPublicKeyStore;
  certificateStore: ICertificateStore;
  documentStore: IDocumentStore;
  revocationStore: IRevocationStore;
  trustStore: ITrustStore;
  endpointConfigStore: IEndpointConfigStore;
} {
  mkdirSync(dir, { recursive: true });
  return {
    privateKeyStore: new FilePrivateKeyStore(dir),
    publicKeyStore: new FilePublicKeyStore(dir),
    certificateStore: new FileCertificateStore(dir),
    documentStore: new FileDocumentStore(dir),
    revocationStore: new FileRevocationStore(dir),
    trustStore: new FileTrustStore(dir),
    endpointConfigStore: new FileEndpointConfigStore(dir),
  };
}
