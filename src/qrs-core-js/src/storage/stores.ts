/**
 * Storage interfaces (IoC seam).
 *
 * The package only ever talks to these interfaces. By default it uses in-memory
 * implementations; the CLI uses JSON-file-backed ones. A consumer can implement any
 * of these interfaces (e.g. a database, a secure key vault, an HSM) and inject them
 * into `createQrs` — the rest of the package is completely unaware.
 *
 * Byte strings are stored in their wire (canonical CBOR / COSE) form.
 */
import type { AlgorithmId, KeyId, RevocationType, SdocId, TcertId } from '../types.js';
import type { PrivateJwk, PublicJwk } from '../crypto/jwk.js';

export interface RevocationEntry {
  type: RevocationType;
  issuedAt: number; // epoch seconds (statement issuance time)
  reason?: string;
  /** Key id of the CA (or issuer) that signed this revocation. */
  byKeyId?: KeyId;
  /** TCert id of the CA (or issuer) that signed this revocation. */
  byTcertId?: TcertId;
  /** Original signed statement, retained for offline sharing. */
  statementBytes?: Uint8Array;
}

export interface BlockEntry {
  issuedAt: number;
  reason?: string;
  /** Original signed statement, retained for offline sharing. */
  statementBytes?: Uint8Array;
  byTcertId?: TcertId;
  byKeyId?: KeyId;
}

export interface SdocStatementEntry extends BlockEntry {
  action: 'blockSdoc' | 'unblockSdoc';
}

export interface IPrivateKeyStore {
  save(keyId: KeyId, algorithm: AlgorithmId, privateJwk: PrivateJwk): Promise<void>;
  load(keyId: KeyId): Promise<{ algorithm: AlgorithmId; privateJwk: PrivateJwk } | null>;
  has(keyId: KeyId): Promise<boolean>;
  all(): Promise<Array<{ keyId: KeyId; algorithm: AlgorithmId }>>;
}

export interface IPublicKeyStore {
  save(keyId: KeyId, algorithm: AlgorithmId, publicJwk: PublicJwk): Promise<void>;
  load(keyId: KeyId): Promise<{ algorithm: AlgorithmId; publicJwk: PublicJwk } | null>;
  has(keyId: KeyId): Promise<boolean>;
  all(): Promise<Array<{ keyId: KeyId; algorithm: AlgorithmId; publicJwk: PublicJwk }>>;
}

export interface ICertificateStore {
  save(tcertId: TcertId, bytes: Uint8Array): Promise<void>;
  get(tcertId: TcertId): Promise<Uint8Array | null>;
  findByKeyId(keyId: KeyId): Promise<Array<{ tcertId: TcertId; bytes: Uint8Array }>>;
  all(): Promise<Array<{ tcertId: TcertId; bytes: Uint8Array }>>;
  remove(tcertId: TcertId): Promise<void>;
}

export interface IDocumentStore {
  save(sdocId: SdocId, bytes: Uint8Array): Promise<void>;
  get(sdocId: SdocId): Promise<Uint8Array | null>;
  all(): Promise<Array<{ sdocId: SdocId; bytes: Uint8Array }>>;
  remove(sdocId: SdocId): Promise<void>;
}

export interface IRevocationStore {
  /** Record a revocation of a TCert by a CA/issuer. Keeps one entry per revoker. */
  addRevokedTcert(tcertId: TcertId, entry: RevocationEntry): Promise<void>;
  /** Effective (most severe) revocation for a TCert across all revokers, or null. */
  getRevokedTcert(tcertId: TcertId): Promise<RevocationEntry | null>;
  /** Every per-CA revocation recorded for a TCert (for transparency display). */
  getRevokedTcertEntries(tcertId: TcertId): Promise<RevocationEntry[]>;
  listRevokedTcert(): Promise<Array<{ tcertId: TcertId; entry: RevocationEntry }>>;

  addRevokedKey(keyId: KeyId, entry: RevocationEntry): Promise<void>;
  getRevokedKey(keyId: KeyId): Promise<RevocationEntry | null>;
  listRevokedKey(): Promise<Array<{ keyId: KeyId; entry: RevocationEntry }>>;

  addRevokedAttestation(targetTcertId: TcertId, caTcertId: TcertId, entry: RevocationEntry): Promise<void>;
  getRevokedAttestation(targetTcertId: TcertId, caTcertId: TcertId): Promise<RevocationEntry | null>;
  listRevokedAttestation(): Promise<Array<{ targetTcertId: TcertId; caTcertId: TcertId; entry: RevocationEntry }>>;

  addBlockedSdoc(sdocId: SdocId, entry: BlockEntry): Promise<void>;
  getBlockedSdoc(sdocId: SdocId): Promise<BlockEntry | null>;
  listBlockedSdoc(): Promise<Array<{ sdocId: SdocId; entry: BlockEntry }>>;
  /** Remove the effective block; when entry is supplied, retain the signed unblock in history. */
  removeBlockedSdoc(sdocId: SdocId, entry?: BlockEntry): Promise<void>;
  listSdocStatements(): Promise<Array<{ sdocId: SdocId; entry: SdocStatementEntry }>>;
}

export interface AttestationRecord {
  targetTcertId: TcertId;
  caKeyId: KeyId;
  caTcertId: TcertId;
  /** Content-address of the attested TCert — binds the attestation to a specific object. */
  tcertHash: string;
  claims?: Record<string, unknown>;
  issuedAt: number;
  statementBytes: Uint8Array;
}

export interface ITrustStore {
  addPinned(tcertId: TcertId): Promise<void>;
  removePinned(tcertId: TcertId): Promise<void>;
  isPinned(tcertId: TcertId): Promise<boolean>;
  listPinned(): Promise<TcertId[]>;

  addCa(tcertId: TcertId): Promise<void>;
  removeCa(tcertId: TcertId): Promise<void>;
  isCa(tcertId: TcertId): Promise<boolean>;
  listCa(): Promise<TcertId[]>;

  addAttestation(record: AttestationRecord): Promise<void>;
  getAttestations(targetTcertId: TcertId): Promise<AttestationRecord[]>;
  listAttestations(): Promise<AttestationRecord[]>;

  addDistrust(tcertId: TcertId): Promise<void>;
  removeDistrust(tcertId: TcertId): Promise<void>;
  isDistrusted(tcertId: TcertId): Promise<boolean>;
}

/**
 * Mutable, app-local mirror endpoints for a TCert (distribution convenience, NOT
 * part of the signed protocol data). The signed `onlineEndpoint` stays the fixed
 * default; this store holds additional mirrors the user configures later. Servers
 * are untrusted mirrors — everything downloaded is still verified cryptographically.
 */
export interface IEndpointConfigStore {
  /** All configured mirror endpoints for a TCert (excluding the signed default). */
  getEndpoints(tcertId: TcertId): Promise<string[]>;
  /** Replace the full mirror list for a TCert. */
  setEndpoints(tcertId: TcertId, endpoints: string[]): Promise<void>;
  /** Add one mirror endpoint (dedup + no-op when already present). */
  addEndpoint(tcertId: TcertId, endpoint: string): Promise<void>;
  /** Remove one mirror endpoint. */
  removeEndpoint(tcertId: TcertId, endpoint: string): Promise<void>;
}
