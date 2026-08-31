/** TCert-scoped, read-only mobile sync rooted in one TCert and its endpoints. */
import { fromBase64Url, parseSignedObject, type QrsRuntime } from 'qrs-core';

export interface MobileSyncResult {
  tcertsDownloaded: number;
  statementsApplied: number;
  errors: string[];
}

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

export function baseUrl(endpoint: string): string {
  return endpoint.trim().replace(/\/+$/, '');
}

/** Endpoints for one TCert only. */
export async function syncEndpointsFor(qrs: QrsRuntime, tcertId?: string): Promise<string[]> {
  if (!tcertId) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const endpoint of await qrs.endpoints.effectiveEndpoints(tcertId)) {
    const normalized = baseUrl(endpoint);
    if (normalized && !seen.has(normalized)) {
      seen.add(normalized);
      out.push(normalized);
    }
  }
  return out;
}

/** Pull the records hosted for one local TCert. CAs expose their enrolled
 * namespace; ordinary TCerts expose their own public-key namespace. */
export async function syncCert(
  qrs: QrsRuntime,
  tcertId: string,
  opts?: { endpoint?: string }
): Promise<MobileSyncResult> {
  const bytes = await qrs.deps.certificateStore.get(tcertId);
  if (!bytes) return { tcertsDownloaded: 0, statementsApplied: 0, errors: [`certificate not found: ${tcertId}`] };
  let parsed;
  try {
    parsed = parseSignedObject(bytes);
    if (parsed.type !== 'tcert') throw new Error('not a TCert');
  } catch (error) {
    return { tcertsDownloaded: 0, statementsApplied: 0, errors: [error instanceof Error ? error.message : 'malformed TCert'] };
  }
  const isCa = await qrs.deps.trustStore.isCa(tcertId);
  const endpoints = opts?.endpoint ? [opts.endpoint] : await syncEndpointsFor(qrs, tcertId);
  const aggregate: MobileSyncResult = { tcertsDownloaded: 0, statementsApplied: 0, errors: [] };
  for (const endpoint of endpoints) {
    const result = await (isCa
      ? syncCaEndpoint(qrs, endpoint, tcertId)
      : syncTcertEndpoint(qrs, endpoint, parsed.signerKeyId));
    aggregate.tcertsDownloaded += result.tcertsDownloaded;
    aggregate.statementsApplied += result.statementsApplied;
    aggregate.errors.push(...result.errors);
  }
  return aggregate;
}

async function syncTcertEndpoint(qrs: QrsRuntime, endpoint: string, keyId: string): Promise<MobileSyncResult> {
  const base = baseUrl(endpoint);
  try {
    const response = await fetch(`${base}/api/tcerts/${encodeURIComponent(keyId)}/objects/`);
    if (!response.ok) throw new Error(`sync failed: HTTP ${response.status}`);
    const payload = (await response.json()) as { objects?: ServerObject[] };
    let statementsApplied = 0;
    for (const object of payload.objects ?? []) {
      if (object.type !== 'statement' || !object.bytesB64) continue;
      try {
        const result = await qrs.online.importStatement(fromBase64Url(object.bytesB64));
        if (result.applied) statementsApplied++;
      } catch (error) {
        return {
          tcertsDownloaded: 0,
          statementsApplied,
          errors: [`statement ${object.statementId ?? object.id}: ${error instanceof Error ? error.message : String(error)}`],
        };
      }
    }
    return { tcertsDownloaded: 0, statementsApplied, errors: [] };
  } catch (error) {
    return { tcertsDownloaded: 0, statementsApplied: 0, errors: [`${base}: ${error instanceof Error ? error.message : String(error)}`] };
  }
}

async function syncCaEndpoint(qrs: QrsRuntime, endpoint: string, caTcertId: string): Promise<MobileSyncResult> {
  const base = baseUrl(endpoint);
  let payload: { tcerts: ServerTcert[]; objects: ServerObject[] };
  try {
    const response = await fetch(`${base}/api/cas/${encodeURIComponent(caTcertId)}/sync/`, { method: 'POST' });
    if (!response.ok) throw new Error(`sync failed: HTTP ${response.status}`);
    payload = (await response.json()) as { tcerts: ServerTcert[]; objects: ServerObject[] };
  } catch (error) {
    return { tcertsDownloaded: 0, statementsApplied: 0, errors: [`${base}: ${error instanceof Error ? error.message : String(error)}`] };
  }
  let tcertsDownloaded = 0;
  let statementsApplied = 0;
  const errors: string[] = [];
  // The target TCert must exist before qrs-core accepts its hash-bound attestation.
  for (const tcert of payload.tcerts ?? []) {
    if (!tcert.bytesB64) continue;
    try {
      if ((await qrs.online.importTcert(fromBase64Url(tcert.bytesB64))).imported) tcertsDownloaded++;
    } catch (error) {
      errors.push(`TCert ${tcert.tcertId}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  for (const object of payload.objects ?? []) {
    if (object.type !== 'statement' || !object.bytesB64) continue;
    try {
      const result = await qrs.online.importStatement(fromBase64Url(object.bytesB64));
      if (result.applied) statementsApplied++;
      else if (result.reason) errors.push(`statement ${object.statementId ?? object.id}: ${result.reason}`);
    } catch (error) {
      errors.push(`statement ${object.statementId ?? object.id}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return { tcertsDownloaded, statementsApplied, errors };
}
