/**
 * TCert-scoped distribution sync. There is deliberately no global sync: every
 * operation is rooted in one locally configured TCert and one of its endpoints.
 */
import { fromBase64Url, parseSignedObject, toBase64Url } from 'qrs-core';
import type { SyncResult } from '../shared/types.js';
import type { DesktopRuntime } from './runtime.js';
import { getOnlineService, type OnlineService } from './online.js';

interface ServerTcert {
  tcertId: string;
  bytesB64?: string;
}

interface ServerObject {
  type: string;
  id?: string;
  statementId?: string;
  bytesB64?: string;
}

function baseUrl(endpoint: string): string {
  return endpoint.replace(/\/+$/, '');
}

/** Kept as a safe compatibility guard for older IPC callers. */
export async function syncAll(_rt: DesktopRuntime, _online: OnlineService = getOnlineService()): Promise<SyncResult> {
  return {
    uploaded: 0,
    pending: 0,
    downloaded: 0,
    applied: 0,
    errors: ['Global sync is disabled. Open and sync one TCert with a distribution endpoint instead.'],
  };
}

/**
 * Sync exactly one local TCert: flush pending uploads, then pull its hosted
 * statements. CAs use the CA endpoint because it also includes enrolled
 * targets; ordinary TCerts use the public key namespace endpoint.
 */
export async function syncTcert(
  rt: DesktopRuntime,
  tcertId: string,
  online: OnlineService = getOnlineService()
): Promise<SyncResult> {
  const tcertBytes = await rt.qrs.deps.certificateStore.get(tcertId);
  if (!tcertBytes) return { uploaded: 0, pending: online.pendingCount(), downloaded: 0, applied: 0, errors: [`TCert not found: ${tcertId}`] };
  const tcert = parseSignedObject(tcertBytes);
  if (tcert.type !== 'tcert') return { uploaded: 0, pending: online.pendingCount(), downloaded: 0, applied: 0, errors: [`not a TCert: ${tcertId}`] };
  const isCa = await rt.qrs.deps.trustStore.isCa(tcertId);
  const endpoints = await rt.qrs.endpoints.effectiveEndpoints(tcertId);
  if (endpoints.length === 0) {
    return { uploaded: 0, pending: online.pendingCount(), downloaded: 0, applied: 0, errors: ['no distribution endpoints configured on this TCert'] };
  }

  let uploaded = 0;
  let downloaded = 0;
  let applied = 0;
  const errors: string[] = [];
  for (const endpoint of endpoints) {
    const base = baseUrl(endpoint);
    if (isCa) {
      const enroll = await uploadCaEnrollments(rt, online, tcertId, tcert.signerKeyId, base);
      uploaded += enroll.uploaded;
      errors.push(...enroll.errors);
    }

    const pending = await online.uploadPending(base, tcertId);
    uploaded += pending.uploaded;

    const pulled = await (isCa ? pullCa(rt, base, tcertId) : pullTcert(rt, base, tcert.signerKeyId));
    downloaded += pulled.downloaded;
    applied += pulled.applied;
    errors.push(...pulled.errors);
  }
  return { uploaded, pending: online.pendingCount(), downloaded, applied, errors };
}

/** Pull statements hosted in a non-CA TCert's public key namespace. */
async function pullTcert(
  rt: DesktopRuntime,
  endpoint: string,
  keyId: string
): Promise<{ downloaded: number; applied: number; errors: string[] }> {
  const errors: string[] = [];
  let downloaded = 0;
  let applied = 0;
  try {
    const res = await fetch(`${endpoint}/api/tcerts/${encodeURIComponent(keyId)}/objects/`);
    if (!res.ok) {
      return {
        downloaded,
        applied,
        errors: [res.status === 404
          ? `sync ${endpoint}: TCert is not registered or admitted on this distribution server (HTTP 404)`
          : `sync ${endpoint}: HTTP ${res.status}`],
      };
    }
    const payload = (await res.json()) as { objects?: ServerObject[] };
    for (const object of payload.objects ?? []) {
      if (object.type !== 'statement' || !object.bytesB64) continue;
      try {
        const result = await rt.qrs.online.importStatement(fromBase64Url(object.bytesB64));
        downloaded++;
        if (result.applied) applied++;
        else if (result.reason) errors.push(`statement ${object.statementId ?? object.id}: ${result.reason}`);
      } catch (error) {
        errors.push(`apply statement ${object.statementId ?? object.id}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
  } catch (error) {
    errors.push(`sync ${endpoint}: ${error instanceof Error ? error.message : String(error)}`);
  }
  return { downloaded, applied, errors };
}

async function uploadCaEnrollments(
  rt: DesktopRuntime,
  online: OnlineService,
  caTcertId: string,
  caKeyId: string,
  endpoint: string
): Promise<{ uploaded: number; errors: string[] }> {
  let uploaded = 0;
  const errors: string[] = [];
  for (const target of await rt.qrs.deps.certificateStore.all()) {
    for (const attestation of await rt.qrs.deps.trustStore.getAttestations(target.tcertId)) {
      if (attestation.caTcertId !== caTcertId) continue;
      const result = await online.submitAttestation({
        caTcertId,
        caKeyId,
        targetTcertB64: toBase64Url(target.bytes),
        attestationB64: toBase64Url(attestation.statementBytes),
        onlineEndpoints: [endpoint],
      });
      if (result.queued) errors.push(`enroll ${target.tcertId}: ${result.error ?? 'server unreachable'}`);
      else uploaded++;
    }
  }
  return { uploaded, errors };
}

async function pullCa(
  rt: DesktopRuntime,
  endpoint: string,
  caTcertId: string
): Promise<{ downloaded: number; applied: number; errors: string[] }> {
  const errors: string[] = [];
  let downloaded = 0;
  let applied = 0;
  let payload: { tcerts: ServerTcert[]; objects: ServerObject[] };
  try {
    const res = await fetch(`${endpoint}/api/cas/${encodeURIComponent(caTcertId)}/sync/`, { method: 'POST' });
    if (!res.ok) return { downloaded, applied, errors: [`sync ${endpoint}: HTTP ${res.status}`] };
    payload = (await res.json()) as { tcerts: ServerTcert[]; objects: ServerObject[] };
  } catch (error) {
    return { downloaded, applied, errors: [`sync ${endpoint}: ${error instanceof Error ? error.message : String(error)}`] };
  }
  // Import targets before their attestations so qrs-core can validate the bound hash.
  for (const tcert of payload.tcerts ?? []) {
    if (!tcert.bytesB64) continue;
    try {
      const result = await rt.qrs.online.importTcert(fromBase64Url(tcert.bytesB64));
      if (result.imported) downloaded++;
    } catch (error) {
      errors.push(`import TCert ${tcert.tcertId}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  for (const object of payload.objects ?? []) {
    if (object.type !== 'statement' || !object.bytesB64) continue;
    try {
      const result = await rt.qrs.online.importStatement(fromBase64Url(object.bytesB64));
      if (result.applied) applied++;
      else if (result.reason) errors.push(`statement ${object.statementId ?? object.id}: ${result.reason}`);
    } catch (error) {
      errors.push(`apply statement ${object.statementId ?? object.id}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return { downloaded: downloaded + (payload.objects?.length ?? 0), applied, errors };
}
