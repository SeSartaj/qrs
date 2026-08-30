/**
 * Online distribution client for the desktop app.
 *
 * Handles the QRS distribution server protocol:
 *   challenge → proof-of-work → token → upload (signed object).
 *
 * Both attachments and signed statements are stored locally first (so they are
 * verifiable even offline), then uploaded to the TCert's `online_endpoint`. If the
 * server is unreachable the upload is queued, and a background timer flushes the
 * queue whenever the network becomes available. The server itself is never
 * trusted — this is just a cache sync; verification still happens cryptographically
 * on every device.
 */
import { app } from 'electron';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { toBase64Url } from 'qrs-core';
import { solvePow } from './pow.js';
import type { SyncResult } from '../shared/types.js';

const SYNC_INTERVAL_MS = 30_000;

/** Short-lived bearer tokens per (endpoint, keyId), reused within their TTL so a
 * sync of many objects does not exhaust the server's challenge throttle. */
const TOKEN_TTL_MS = 500_000;
const tokenCache = new Map<string, { token: string; expiresAt: number }>();

function tokenKey(endpoint: string, keyId: string): string {
  return `${baseUrl(endpoint)}|${keyId}`;
}

export type ObjectKind = 'attachment' | 'statement';

interface UploadAttempt {
  ok: boolean;
  /** A server response error. Network failures intentionally leave this unset. */
  error?: string;
}

/** A signed object (already built by qrs-core) ready for local storage + distribution. */
export interface SignedObjectSubmit {
  keyId: string;
  /** Exact trusted CA that signed this statement. */
  caTcertId?: string;
  /** Every distribution endpoint (signed default + configured mirrors) to fan out to. */
  onlineEndpoints?: string[];
  kind: ObjectKind;
  /** attachmentId for attachments, statementId for statements. */
  id: string;
  bytesB64: string;
}

/**
 * A signed object waiting to reach its distribution server.
 * The signed object bytes live in `<userData>/objects/<kind>/<safeId>`; the queue
 * just remembers where each one needs to go.
 */
interface PendingObject {
  keyId: string;
  onlineEndpoint: string;
  kind: ObjectKind;
  id: string;
  /** Attachment schema identity; absent for signed statements and legacy queues. */
  tcertId?: string;
  fieldName?: string;
  /** Exact CA scope for signed statements. */
  caTcertId?: string;
}

export function safeId(id: string): string {
  return id.replace(/[^a-zA-Z0-9._-]/g, '_');
}

function baseUrl(endpoint: string): string {
  return endpoint.replace(/\/+$/, '');
}

/** Obtain a short-lived upload token by solving the server's challenge. */
export async function getToken(endpoint: string, keyId: string): Promise<string | null> {
  const key = tokenKey(endpoint, keyId);
  const cached = tokenCache.get(key);
  if (cached && cached.expiresAt > Date.now()) return cached.token;
  try {
    const base = baseUrl(endpoint);
    const chRes = await fetch(`${base}/api/tcerts/${keyId}/challenge/`, { method: 'POST' });
    if (!chRes.ok) return null;
    const ch = (await chRes.json()) as { nonce: string; difficulty: number };
    const counter = solvePow(ch.nonce, ch.difficulty);
    const tokRes = await fetch(`${base}/api/tcerts/${keyId}/token/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nonce: ch.nonce, counter }),
    });
    if (!tokRes.ok) return null;
    const body = (await tokRes.json()) as { token: string };
    tokenCache.set(key, { token: body.token, expiresAt: Date.now() + TOKEN_TTL_MS });
    return body.token;
  } catch {
    return null;
  }
}

async function uploadObject(
  endpoint: string,
  keyId: string,
  token: string,
  payload: Record<string, unknown>,
  path = `/api/tcerts/${keyId}/objects/`
): Promise<boolean> {
  try {
    const res = await fetch(`${baseUrl(endpoint)}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(payload),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export class OnlineService {
  private readonly objectsDir: string;
  private readonly queueFile: string;
  private pending: PendingObject[] = [];

  constructor(userData: string) {
    this.objectsDir = join(userData, 'objects');
    this.queueFile = join(userData, 'pending-uploads.json');
    mkdirSync(this.objectsDir, { recursive: true });
    this.pending = this.loadQueue();
    setInterval(() => void this.syncNow().catch(() => undefined), SYNC_INTERVAL_MS).unref();
  }

  /** Absolute path under which a signed object's bytes are stored. */
  objectPath(kind: ObjectKind, id: string): string {
    return join(this.objectsDir, kind, safeId(id));
  }

  /**
   * Store a *signed object* locally, then try to upload it to EVERY configured
   * distribution endpoint (queuing each failed mirror independently). `bytesB64`
   * is the signed object produced by qrs-core, not the raw file.
   * Objects whose signer has no endpoints are stored but never queued.
   */
  async submitObject(input: SignedObjectSubmit): Promise<{ id: string; queued: boolean }> {
    this.storeObject(input.kind, input.id, input.bytesB64);
    const endpoints = input.onlineEndpoints ?? [];
    if (endpoints.length === 0) return { id: input.id, queued: false };
    let allOk = true;
    for (const endpoint of endpoints) {
      const entry: PendingObject = {
        keyId: input.keyId,
        caTcertId: input.caTcertId,
        onlineEndpoint: endpoint,
        kind: input.kind,
        id: input.id,
      };
      const ok = await this.uploadOne(entry);
      if (ok) continue;
      this.enqueue(entry);
      allOk = false;
    }
    return { id: input.id, queued: !allOk };
  }

  /**
   * Upload a raw attachment file to every distribution endpoint.
   * The object is stored locally and queued for each unreachable mirror.
   */
  async submitRawAttachment(input: {
    keyId: string;
    tcertId: string;
    fieldName: string;
    onlineEndpoints?: string[];
    hash: string;
    size: number;
    /** Raw file bytes, base64url encoded only inside the desktop process. */
    contentB64: string;
  }): Promise<{ id: string; queued: boolean; error?: string }> {
    this.storeObject('attachment', input.hash, input.contentB64);
    const endpoints = input.onlineEndpoints ?? [];
    if (endpoints.length === 0) return { id: input.hash, queued: true, error: 'no distribution endpoint configured' };
    let allOk = true;
    let firstError: string | undefined;
    for (const endpoint of endpoints) {
      const entry: PendingObject = {
        keyId: input.keyId,
        onlineEndpoint: endpoint,
        kind: 'attachment',
        id: input.hash,
        tcertId: input.tcertId,
        fieldName: input.fieldName,
      };
      const attempt = await this.uploadRawOne(entry, input);
      if (attempt.ok) continue;
      firstError ??= attempt.error;
      this.enqueue(entry);
      allOk = false;
    }
    return { id: input.hash, queued: !allOk, error: firstError };
  }

  /** Atomically enroll a target TCert together with an attestation from one CA. */
  async submitAttestation(input: {
    caTcertId: string;
    caKeyId: string;
    targetTcertB64: string;
    attestationB64: string;
    onlineEndpoints: string[];
  }): Promise<{ queued: boolean; error?: string }> {
    if (input.onlineEndpoints.length === 0) return { queued: true, error: 'CA has no distribution endpoint configured' };
    let allOk = true;
    let firstError: string | undefined;
    for (const endpoint of input.onlineEndpoints) {
      const token = await getToken(endpoint, input.caKeyId);
      if (!token) {
        allOk = false;
        continue;
      }
      try {
        const res = await fetch(`${baseUrl(endpoint)}/api/cas/${encodeURIComponent(input.caTcertId)}/attestations/`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify({ targetTcertB64: input.targetTcertB64, attestationB64: input.attestationB64 }),
        });
        if (res.ok) continue;
        const body = (await res.json().catch(() => null)) as { error?: unknown } | null;
        firstError ??= typeof body?.error === 'string' ? `${body.error} (HTTP ${res.status})` : `HTTP ${res.status}`;
        allOk = false;
      } catch {
        allOk = false;
      }
    }
    return { queued: !allOk, error: firstError };
  }

  /** Persist a downloaded signed object so it is verifiable offline. */
  storeObject(kind: ObjectKind, id: string, bytesB64: string): void {
    const file = this.objectPath(kind, id);
    mkdirSync(join(this.objectsDir, kind), { recursive: true });
    writeFileSync(file, Buffer.from(bytesB64, 'base64url'));
  }

  /** Read a locally stored signed object by kind + id. */
  readObject(kind: ObjectKind, id: string): Uint8Array | null {
    try {
      const file = this.objectPath(kind, id);
      if (!existsSync(file)) return null;
      return new Uint8Array(readFileSync(file));
    } catch {
      return null;
    }
  }

  /** Upload everything pending. Transport only — does not download. */
  async syncNow(): Promise<SyncResult> {
    const { uploaded, pending } = await this.uploadPending();
    return { uploaded, pending, downloaded: 0, applied: 0, errors: [] };
  }

  /** Try to upload everything pending. Returns how many succeeded + remaining.
   *  When `endpoint` is given, only entries targeting that server are flushed. */
  async uploadPending(endpoint?: string, caTcertId?: string): Promise<{ uploaded: number; pending: number }> {
    const target = endpoint ? baseUrl(endpoint) : undefined;
    let uploaded = 0;
    const remaining: PendingObject[] = [];
    for (const entry of this.pending) {
      if (target && baseUrl(entry.onlineEndpoint) !== target) {
        remaining.push(entry);
        continue;
      }
      // CA-scoped filtering applies to statements, which carry an explicit CA
      // scope. Attachments carry their issuing TCert instead; when syncing a CA
      // we select its endpoint and let the server validate that TCert's
      // enrollment, rather than dropping the attachment before retrying it.
      if (caTcertId && entry.kind === 'statement' && entry.caTcertId !== caTcertId) {
        remaining.push(entry);
        continue;
      }
      if (await this.uploadOne(entry)) uploaded++;
      else remaining.push(entry);
    }
    this.pending = remaining;
    this.saveQueue();
    return { uploaded, pending: remaining.length };
  }

  pendingCount(): number {
    return this.pending.length;
  }

  /** Number of queued attachment uploads belonging to one issuing TCert. */
  pendingAttachmentCount(tcertId: string): number {
    return this.pending.filter((entry) => entry.kind === 'attachment' && entry.tcertId === tcertId).length;
  }

  /** Snapshot of the objects currently waiting to reach their distribution server. */
  listQueue(): Array<{ keyId: string; onlineEndpoint: string; kind: ObjectKind; id: string }> {
    return this.pending.map((e) => ({ ...e }));
  }

  private async uploadOne(entry: PendingObject): Promise<boolean> {
    if (!entry.onlineEndpoint) return false;
    const token = await getToken(entry.onlineEndpoint, entry.keyId);
    if (!token) return false;
    const bytes = this.readObject(entry.kind, entry.id);
    if (!bytes) return false;
    const contentB64 = toBase64Url(bytes);
    // Attachments are independent signed objects. The server verifies the object
    // against the admitted TCert before retaining its raw content.
    if (entry.kind === 'attachment') {
      if (!entry.tcertId || !entry.fieldName) return false;
      return (await this.uploadRawOne(entry, {
        keyId: entry.keyId,
        tcertId: entry.tcertId,
        fieldName: entry.fieldName,
        hash: entry.id,
        size: bytes.byteLength,
        contentB64,
      })).ok;
    }
    // Only explicitly scoped CA statements are accepted by the server.
    if (!entry.caTcertId) {
      return uploadObject(entry.onlineEndpoint, entry.keyId, token, { bytesB64: contentB64 }, `/api/tcerts/${encodeURIComponent(entry.keyId)}/statements/`);
    }
    return uploadObject(entry.onlineEndpoint, entry.keyId, token, {
      bytesB64: contentB64,
    }, `/api/cas/${encodeURIComponent(entry.caTcertId)}/statements/`);
  }

  /** Upload a queued raw attachment file to a mirror. */
  private async uploadRawOne(
    entry: PendingObject,
    input: { keyId: string; tcertId: string; fieldName: string; hash: string; size: number; contentB64: string }
  ): Promise<UploadAttempt> {
    const token = await getToken(entry.onlineEndpoint, entry.keyId);
    if (!token) return { ok: false };
    try {
      const bytes = Buffer.from(input.contentB64, 'base64url');
      const form = new FormData();
      form.append('tcertId', input.tcertId);
      form.append('fieldName', input.fieldName);
      form.append('file', new Blob([bytes]), `${input.hash}.bin`);
      const res = await fetch(`${baseUrl(entry.onlineEndpoint)}/api/attachments/`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: form,
      });
      if (res.ok) return { ok: true };
      const body = (await res.json().catch(() => null)) as { error?: unknown } | null;
      const message = typeof body?.error === 'string' ? body.error : `HTTP ${res.status}`;
      return { ok: false, error: `${message} (HTTP ${res.status})` };
    } catch {
      return { ok: false };
    }
  }

  private enqueue(entry: PendingObject): void {
    this.pending.push(entry);
    this.saveQueue();
  }

  private loadQueue(): PendingObject[] {
    try {
      if (!existsSync(this.queueFile)) return [];
      return JSON.parse(readFileSync(this.queueFile, 'utf8')) as PendingObject[];
    } catch {
      return [];
    }
  }

  private saveQueue(): void {
    try {
      writeFileSync(this.queueFile, JSON.stringify(this.pending));
    } catch {
      /* ignore */
    }
  }
}

/** Singleton used by the IPC layer. */
let _online: OnlineService | null = null;
export function getOnlineService(): OnlineService {
  if (!_online) _online = new OnlineService(app.getPath('userData'));
  return _online;
}
