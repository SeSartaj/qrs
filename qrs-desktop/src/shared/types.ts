/**
 * The typed IPC contract shared by main, preload and renderer.
 *
 * Everything that crosses the process boundary is JSON-serialisable:
 * byte strings are always base64url (never raw `Uint8Array`).
 */
import type {
  AlgorithmId,
  FieldSchema,
  HashAlgorithm,
  KeyId,
  RevocationType,
  SdocId,
  TcertId,
  VerificationResult,
} from 'qrs-core';

// Re-export the protocol vocabulary so both main and renderer import from one place.
export type { AlgorithmId, KeyId, RevocationType, SdocId, TcertId } from 'qrs-core';

/* ------------------------------------------------------------------ */
/* IPC channel names                                                   */
/* ------------------------------------------------------------------ */

export const IPC = {
  app: { getInfo: 'app:getInfo' },
  keys: { list: 'keys:list', generate: 'keys:generate', passwordStatus: 'keys:passwordStatus', setPassword: 'keys:setPassword', unlock: 'keys:unlock', removePassword: 'keys:removePassword' },
  certificates: {
    list: 'certificates:list',
    create: 'certificates:create',
    get: 'certificates:get',
    import: 'certificates:import',
    export: 'certificates:export',
    remove: 'certificates:remove', setPin: 'certificates:setPin', changePin: 'certificates:changePin', removePin: 'certificates:removePin', verifyPin: 'certificates:verifyPin', isPinAuthorized: 'certificates:isPinAuthorized', beginPinSession: 'certificates:beginPinSession', endPinSession: 'certificates:endPinSession',
    exportSchema: 'certificates:exportSchema', importSchema: 'certificates:importSchema',
  },
  documents: {
    list: 'documents:list',
    issue: 'documents:issue',
    get: 'documents:get',
    import: 'documents:import',
    export: 'documents:export',
    remove: 'documents:remove',
  },
  trust: {
    state: 'trust:state',
    pin: 'trust:pin',
    unpin: 'trust:unpin',
    addCa: 'trust:addCa',
    removeCa: 'trust:removeCa',
    distrust: 'trust:distrust',
    trustAgain: 'trust:trustAgain',
    attest: 'trust:attest',
  },
  revocation: {
    state: 'revocation:state',
    revokeAttestation: 'revocation:revokeAttestation',
    revokeTcert: 'revocation:revokeTcert',
    revokeKey: 'revocation:revokeKey',
    blockSdoc: 'revocation:blockSdoc',
    unblockSdoc: 'revocation:unblockSdoc',
  },
  verification: { verify: 'verification:verify' },
  attachments: {
    submit: 'attachments:submit',
    sync: 'attachments:sync',
    syncTcert: 'attachments:syncTcert',
    queue: 'attachments:queue',
    pending: 'attachments:pending',
    pendingForTcert: 'attachments:pendingForTcert',
    get: 'attachments:get', // fetch + decode a signed attachment for display
    open: 'attachments:open', // open a downloaded attachment with the OS default app
    save: 'attachments:save', // save a downloaded attachment via a save dialog
  },
  endpoints: {
    list: 'endpoints:list', // effective endpoints (default + mirrors) for a TCert
    mirrors: 'endpoints:mirrors', // configured mirrors (excluding the signed default)
    add: 'endpoints:add', // add a mirror for a TCert
    remove: 'endpoints:remove', // remove a mirror from a TCert
  },
  objects: {
    decode: 'objects:decode', // dev-only: plaintext view of a signed object
    exportQrs: 'objects:exportQrs', // save a TCert / SDoc / Statement to a .qrs file
    exportBundle: 'objects:exportBundle',
    saveQrPng: 'objects:saveQrPng', // save the QR image as a PNG via a save dialog
  },
  config: {
    get: 'config:get', // read the whole global config
    set: 'config:set', // replace the whole global config
  },
  backup: { export: 'backup:export', chooseImport: 'backup:chooseImport', import: 'backup:import' },
  context: {
    request: 'context:request', // main -> renderer
    reply: 'context:reply', // renderer -> main
  },
} as const;

/* ------------------------------------------------------------------ */
/* DTOs                                                                */
/* ------------------------------------------------------------------ */

export interface AppInfo {
  version: string;
  electron: string;
  chrome: string;
  node: string;
  platform: string;
  dataDir: string;
  /** true when private keys are encrypted at rest (Electron safeStorage). */
  secureKeys: boolean;
  /** How private keys are protected on this host (TPM / OS-sealed / plaintext). */
  keyProtection?: {
    kind: 'hardware-tpm' | 'hardware-se' | 'os-sealed' | 'plaintext';
    osSealingAvailable: boolean;
    tpmDetected: boolean;
    note: string;
  };
}

/**
 * Global, app-level configuration persisted by the main process. Everything the
 * user configures (language, calendar, table columns, …) lives here so it is
 * shared across windows and survives restarts. It is NOT part of the protocol.
 */
export interface GlobalConfig {
  /** UI language code (en / fa / ps). */
  language?: string;
  /** Calendar preference (gregorian / jalali). */
  calendar?: string;
  /** Which SDoc field columns to show in the documents table (by field name). */
  sdocColumns?: string[];
  /** Whether private keys use the user-configured password envelope. */
  privateKeyPasswordConfigured?: boolean;
  sidebarCollapsed?: boolean;
  tcertPins?: Record<string, { salt: string; hash: string }>;
  /** TCerts hidden from the normal certificate list but retained locally. */
  archivedTcerts?: string[];
  /** Free-form extension point for future settings. */
  [key: string]: unknown;
}

export interface TcertSummary {
  tcertId: TcertId;
  keyId: KeyId;
  algorithm: AlgorithmId;
  /** Human name of this TCert (a TCert represents a document/entity). */
  name: string;
  certificateNumber: number;
  fields: FieldSchema[];
  /** true when the TCert declares document fields (a CA/meta cert has none). */
  hasSchema: boolean;
  validity?: { validAfter?: number; validBefore?: number; sdocMaxAgeSeconds?: number };
  /** Hash algorithm used for attachment content hashing (default SHA-256). */
  hashAlgorithm?: HashAlgorithm;
  onlineEndpoint?: string;
  /** Effective distribution endpoints: signed default first, then configured mirrors. */
  endpoints?: string[];
  /** true when we hold this certificate's private key (it is one of ours). */
  own?: boolean;
  hasPin?: boolean;
  metadata?: Record<string, unknown>;
  bytesB64: string;
  /** Trust state. */
  pinned: boolean;
  isCa: boolean;
  distrusted: boolean;
  /** Revocation state. */
  revoked?: { type: RevocationType; issuedAt: number; reason?: string };
}

export interface KeySummary {
  keyId: KeyId;
  algorithm: AlgorithmId;
  tcertCount: number;
  revoked?: { issuedAt: number; reason?: string };
}

export interface DocumentValue {
  /** Machine name (from the TCert schema). */
  name: string;
  /** Human label (from the TCert schema). */
  label: string;
  /** Field type (from the TCert schema) — lets the UI render values specially. */
  type: string;
  value: unknown;
  /** Signed schema MIME type for attachment fields. */
  contentType?: string;
  /** Schema options for selectv2 fields (label/value/color) — to resolve the stored index. */
  options?: unknown;
}

export interface DocumentSummary {
  sdocId: SdocId;
  tcertId: TcertId;
  issuedAt: number;
  sizeBytes: number;
  bytesB64: string;
  /** Human names resolved from the issuing TCert (for lists/dropdowns). */
  documentName?: string;
  issuerName?: string;
  /** Decoded (human-readable) stored values in schema order, with labels. */
  values?: DocumentValue[];
  blocked?: { issuedAt: number; reason?: string };
}

export interface CreateTcertInput {
  algorithm: AlgorithmId;
  name: string;
  fields: FieldSchema[];
  keyId?: KeyId;
  validAfter?: number;
  validBefore?: number;
  /** Default validity duration (seconds) applied to every SDoc this TCert issues. */
  sdocMaxAgeSeconds?: number;
  /** Hash algorithm for attachment content hashing under this TCert (default SHA-256). */
  hashAlgorithm?: HashAlgorithm;
  onlineEndpoint?: string;
  metadata?: Record<string, unknown>;
}

export interface IssueInput {
  tcertId: TcertId;
  values: Record<string, unknown>;
  issuedAt?: number;
  pin?: string;
}

export interface VerifyInput {
  bytesB64: string;
  currentTime?: number;
}

export type VerifyResultDto = VerificationResult;

/** Statement bytes (so the UI can show a QR / transfer payload). */
export interface StatementResultDto {
  statementId: string;
  bytesB64: string;
  /** true when the statement was also published to the signer's distribution servers. */
  published?: boolean;
  /** the distribution endpoints it was published to (when published). */
  endpoints?: string[];
}

/** Everything the Verify page needs: the structured result plus decoded context. */
export interface VerifyDetail {
  result: VerifyResultDto;
  sdocId?: SdocId;
  tcertId?: TcertId;
  issuedAt?: number;
  issuerName?: string;
  documentName?: string;
  caName?: string;
  /** The issuing TCert's distribution server (used to fetch attachments). */
  onlineEndpoint?: string;
  /** Effective endpoints (signed default + mirrors) used to fetch attachments. */
  onlineEndpoints?: string[];
  values?: DocumentValue[];
  bytesB64?: string;
}

/** Dev-only plaintext view of a signed object's decoded data structure. */
export interface DecodedObject {
  type: string;
  algorithm: string;
  id?: string;
  data: unknown;
  /** Complete wire-level envelope, including COSE headers and signature. */
  wire: {
    objectBytes: unknown;
    cose: unknown;
    signedPayload: unknown;
    dataBytes: unknown;
    signature: unknown;
    cborDiagnostic: unknown;
  };
}

/* ------------------------------------------------------------------ */
/* `.qrs` file export                                                   */
/* ------------------------------------------------------------------ */

/** Export a signed object to a `.qrs` file. */
export interface ExportQrsInput {
  type: 'tcert' | 'sdoc' | 'statement';
  /** Raw signed object bytes as base64url. */
  bytesB64: string;
  /** Suggested file name (without extension). */
  suggestedName?: string;
}

export interface ExportBundleInput {
  tcertBytesB64: string;
  additionalTcertBytesB64?: string[];
  /** All additional signed statements to include in the bundle. */
  statementBytesB64?: string[];
  /** Legacy single-attestation input. */
  attestationBytesB64?: string;
  suggestedName?: string;
}

export interface ExportQrsResult {
  saved: boolean;
  path?: string;
  error?: string;
}

/* ------------------------------------------------------------------ */
/* Attachments (online distribution server)                             */
/* ------------------------------------------------------------------ */

/** Upload a file to the TCert's distribution endpoints (or queue it locally). */
export interface AttachmentSubmitInput {
  keyId: KeyId;
  /** Exact issuing TCert and attachment field declaring the allowed MIME type. */
  tcertId: TcertId;
  fieldName: string;
  /** Effective endpoints (signed default + mirrors) to fan out to. When omitted, main resolves them from the key. */
  onlineEndpoints?: string[];
  /** Raw file bytes (base64url). The main process hashes it and uploads the raw file. */
  bytesB64: string;
}

export interface AttachmentSubmitResult {
  /** 128-bit content-addressed ID — the SDoc field stores only this hash. */
  hash: string;
  /** File size in bytes, returned from attachment metadata. */
  size: number;
  /** true when the file is stored locally and waiting to be synced. */
  queued: boolean;
  /** Server-side rejection returned by the upload endpoint, when available. */
  error?: string;
}

/** Fetch a raw attachment by hash for display/download. Endpoints are the issuing TCert's servers (tried in order). */
export interface AttachmentGetInput {
  /** Compact content hash stored in the SDoc. */
  id: string;
  /** Legacy size hint, ignored for new hash-only SDocs. */
  size?: number;
  /** Signed MIME rule from the TCert attachment field schema. */
  contentType: string;
  /** When true, fetch the file body; otherwise only metadata (id, size, contentType). */
  content?: boolean;
  onlineEndpoint?: string;
  onlineEndpoints?: string[];
}

/** Decoded attachment content, ready to render or hand to the OS. */
export interface AttachmentData {
  id: string;
  contentType: string;
  contentHash: string;
  /** File size in bytes. */
  size: number;
  /** Content bytes as standard base64 (present when `content` was requested). */
  contentB64?: string;
}

/** Open a file with the OS default app (bytes are the raw content). */
export interface AttachmentOpenInput {
  /** Content-addressed id (used to build a filename). */
  id: string;
  bytesB64: string;
  contentType: string;
}

/** Save a file via the native save dialog (bytes are the raw content). */
export interface AttachmentSaveInput {
  id: string;
  bytesB64: string;
  contentType: string;
  defaultName?: string;
}

export interface SyncResult {
  uploaded: number;
  pending: number;
  /** Signed objects downloaded from distribution servers. */
  downloaded: number;
  /** Statements successfully verified + applied to local stores. */
  applied: number;
  errors: string[];
}

/** A signed object currently waiting to reach its distribution server. */
export interface PendingObjectDto {
  keyId: KeyId;
  onlineEndpoint: string;
  kind: 'attachment' | 'statement';
  id: string;
}

export interface SyncQueueDto {
  queue: PendingObjectDto[];
}

/** Save the QR image (PNG data URL) via a native save dialog. */
export interface SaveQrPngInput {
  /** PNG image as a `data:image/png;base64,...` URL. */
  dataUrl: string;
  /** Suggested file name (without extension). */
  suggestedName?: string;
}

export interface SaveQrPngResult {
  saved: boolean;
  path?: string;
  error?: string;
}

export interface TrustState {
  pinned: TcertId[];
  cas: TcertId[];
  distrusted: TcertId[];
  attestations: Array<{
    targetTcertId: TcertId;
    caTcertId: TcertId;
    claims?: Record<string, unknown>;
    issuedAt: number;
    /** Signed attestation statement (base64url) — lets the UI show QR / export / verify it. */
    bytesB64?: string;
    statementId?: string;
  }>;
}

export interface RevocationState {
  revokedAttestations: Array<{ targetTcertId: TcertId; caTcertId: TcertId; issuedAt: number; reason?: string; bytesB64?: string; byKeyId?: KeyId }>;
  revokedTcerts: Array<{ tcertId: TcertId; type: RevocationType; issuedAt: number; reason?: string; bytesB64?: string; byTcertId?: TcertId; byKeyId?: KeyId }>;
  revokedKeys: Array<{ keyId: KeyId; issuedAt: number; reason?: string; bytesB64?: string; byTcertId?: TcertId; byKeyId?: KeyId }>;
  blockedSdocs: Array<{ sdocId: SdocId; issuedAt: number; reason?: string; bytesB64?: string; byTcertId?: TcertId; byKeyId?: KeyId }>;
  sdocStatements: Array<{ sdocId: SdocId; action: 'blockSdoc' | 'unblockSdoc'; issuedAt: number; reason?: string; bytesB64?: string; byTcertId?: TcertId; byKeyId?: KeyId }>;
}

/** A request the main process sends to the renderer to gather an input. */
export type ContextRequest =
  | { requestId: string; kind: 'location'; label: string }
  | { requestId: string; kind: 'secret'; label: string; name: string };

/** The renderer's reply to a {@link ContextRequest}. */
export interface ContextReply {
  requestId: string;
  /** `{ lat, lon }` for location, a string for secret, or `null` to cancel. */
  value: unknown;
}

/* ------------------------------------------------------------------ */
/* The API surface exposed on `window.qrs` by the preload script.       */
/* ------------------------------------------------------------------ */

export interface QrsApi {
  app: { getInfo(): Promise<AppInfo> };
  keys: {
    list(): Promise<KeySummary[]>;
    generate(algorithm: AlgorithmId): Promise<KeySummary>;
    passwordStatus(): Promise<{ configured: boolean; unlocked: boolean }>;
    setPassword(password: string): Promise<void>;
    unlock(password: string): Promise<void>;
    removePassword(password: string): Promise<void>;
  };
  certificates: {
    list(): Promise<TcertSummary[]>;
    create(input: CreateTcertInput): Promise<TcertSummary>;
    get(tcertId: TcertId): Promise<TcertSummary | null>;
    import(bytesB64: string): Promise<TcertSummary>;
    export(tcertId: TcertId): Promise<string>;
    remove(tcertId: TcertId): Promise<void>;
    setPin(tcertId: TcertId, pin: string): Promise<void>;
    changePin(tcertId: TcertId, previousPin: string, nextPin: string): Promise<void>;
    removePin(tcertId: TcertId, previousPin: string): Promise<void>;
    verifyPin(tcertId: TcertId, pin: string): Promise<boolean>;
    isPinAuthorized(tcertId: TcertId): Promise<boolean>;
    beginPinSession(tcertId: TcertId): Promise<void>;
    endPinSession(tcertId: TcertId): Promise<void>;
    exportSchema(tcertId: TcertId): Promise<{ saved: boolean; path?: string; error?: string }>;
    importSchema(): Promise<FieldSchema[]>;
  };
  documents: {
    list(): Promise<DocumentSummary[]>;
    issue(input: IssueInput): Promise<DocumentSummary>;
    get(sdocId: SdocId): Promise<DocumentSummary | null>;
    import(bytesB64: string): Promise<DocumentSummary>;
    export(sdocId: SdocId): Promise<string>;
    remove(sdocId: SdocId): Promise<void>;
  };
  trust: {
    state(): Promise<TrustState>;
    pin(tcertId: TcertId): Promise<void>;
    unpin(tcertId: TcertId): Promise<void>;
    addCa(tcertId: TcertId): Promise<void>;
    removeCa(tcertId: TcertId): Promise<void>;
    distrust(tcertId: TcertId): Promise<void>;
    trustAgain(tcertId: TcertId): Promise<void>;
    attest(input: {
      caTcertId: TcertId;
      targetTcertId: TcertId;
      claims?: Record<string, unknown>;
    }): Promise<StatementResultDto>;
  };
  revocation: {
    state(): Promise<RevocationState>;
    revokeAttestation(input: { caTcertId: TcertId; targetTcertId: TcertId; reason?: string }): Promise<StatementResultDto>;
    revokeTcert(input: {
      signerKeyId: KeyId;
      targetTcertId: TcertId;
      type: RevocationType;
      reason?: string;
    }): Promise<StatementResultDto>;
    revokeKey(input: { signerKeyId: KeyId; targetKeyId: KeyId; reason?: string }): Promise<StatementResultDto>;
    blockSdoc(input: { signerKeyId: KeyId; targetSdocId: SdocId; reason?: string }): Promise<StatementResultDto>;
    unblockSdoc(input: { signerKeyId: KeyId; targetSdocId: SdocId; reason?: string }): Promise<StatementResultDto>;
  };
  verification: {
    verify(input: VerifyInput): Promise<VerifyDetail>;
  };
  objects: {
    /** Dev-only: return the decoded plaintext structure of a signed object. */
    decode(bytesB64: string): Promise<DecodedObject>;
    /** Save a signed object as a `.qrs` file via a save dialog. */
    exportQrs(input: ExportQrsInput): Promise<ExportQrsResult>;
    exportBundle(input: ExportBundleInput): Promise<ExportQrsResult>;
    /** Save the QR image as a PNG file via a save dialog. */
    saveQrPng(input: SaveQrPngInput): Promise<SaveQrPngResult>;
  };
  attachments: {
    submit(input: AttachmentSubmitInput): Promise<AttachmentSubmitResult>;
    /** Full sync: upload pending + download/apply hosted objects on all endpoints. */
    sync(): Promise<SyncResult>;
    /** Sync only the distribution server of one specific TCert. */
    syncTcert(tcertId: TcertId): Promise<SyncResult>;
    /** List the objects currently waiting to be uploaded. */
    queue(): Promise<SyncQueueDto>;
    pending(): Promise<number>;
    pendingForTcert(tcertId: TcertId): Promise<number>;
    get(input: AttachmentGetInput): Promise<AttachmentData | null>;
    open(input: AttachmentOpenInput): Promise<{ opened: boolean; error?: string }>;
    save(input: AttachmentSaveInput): Promise<{ saved: boolean; path?: string; error?: string }>;
  };
  endpoints: {
    /** Effective endpoints for a TCert: signed default first, then configured mirrors. */
    list(tcertId: TcertId): Promise<string[]>;
    /** Configured mirrors only (excluding the signed default). */
    mirrors(tcertId: TcertId): Promise<string[]>;
    /** Add a mirror; returns the updated mirror list. */
    add(tcertId: TcertId, endpoint: string): Promise<string[]>;
    /** Remove a mirror; returns the updated mirror list. */
    remove(tcertId: TcertId, endpoint: string): Promise<string[]>;
  };
  config: {
    /** Read the whole global config. */
    get(): Promise<GlobalConfig>;
    /** Replace the whole global config. */
    set(config: GlobalConfig): Promise<GlobalConfig>;
  };
  backup: {
    export(password: string): Promise<{ saved: boolean; path?: string; error?: string }>;
    chooseImport(): Promise<string | null>;
    import(password: string, encryptedBackup: string): Promise<{ restored: boolean; restartRequired: boolean }>;
  };
  /** Subscribe to input requests (location/secret) from the main process. */
  onContextRequest(cb: (req: ContextRequest) => void): () => void;
  /** Reply to a pending {@link ContextRequest}. */
  replyContext(reply: ContextReply): void;
}
