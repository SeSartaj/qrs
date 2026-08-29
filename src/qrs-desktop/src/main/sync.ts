/**
 * CA-scoped distribution sync. There is deliberately no global sync: every
 * operation is rooted in one locally configured CA and one of its endpoints.
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
    errors: ['Global sync is disabled. Open and sync one trusted CA instead.'],
  };
}

/** Sync exactly one local CA: push its enrollments/statements, then pull its namespace. */
export async function syncTcert(
  rt: DesktopRuntime,
  caTcertId: string,
  online: OnlineService = getOnlineService()
): Promise<SyncResult> {
  if (!(await rt.qrs.deps.trustStore.isCa(caTcertId))) {
    return { uploaded: 0, pending: online.pendingCount(), downloaded: 0, applied: 0, errors: ['Only a locally configured CA can be synced.'] };
  }
  const caBytes = await rt.qrs.deps.certificateStore.get(caTcertId);
  if (!caBytes) return { uploaded: 0, pending: online.pendingCount(), downloaded: 0, applied: 0, errors: [`TCert not found: ${caTcertId}`] };
  const ca = parseSignedObject(caBytes);
  if (ca.type !== 'tcert') return { uploaded: 0, pending: online.pendingCount(), downloaded: 0, applied: 0, errors: [`not a TCert: ${caTcertId}`] };
  const endpoints = await rt.qrs.endpoints.effectiveEndpoints(caTcertId);
  if (endpoints.length === 0) {
    return { uploaded: 0, pending: online.pendingCount(), downloaded: 0, applied: 0, errors: ['no endpoints configured on this CA'] };
  }

  let uploaded = 0;
  let downloaded = 0;
  let applied = 0;
  const errors: string[] = [];
  for (const endpoint of endpoints) {
    const base = baseUrl(endpoint);
    const enroll = await uploadCaEnrollments(rt, online, caTcertId, ca.signerKeyId, base);
    uploaded += enroll.uploaded;
    errors.push(...enroll.errors);

    const pending = await online.uploadPending(base, caTcertId);
    uploaded += pending.uploaded;

    const pulled = await pullCa(rt, base, caTcertId);
    downloaded += pulled.downloaded;
    applied += pulled.applied;
    errors.push(...pulled.errors);
  }
  return { uploaded, pending: online.pendingCount(), downloaded, applied, errors };
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
