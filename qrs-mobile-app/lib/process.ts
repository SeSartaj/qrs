/**
 * Intelligent payload processing.
 *
 * Given a scanned or pasted payload, decide what it is and handle it:
 *   - an SDoc        → verify it,
 *   - a TCert        → import it (so it can be trusted / used to verify),
 *   - a statement    → verify + apply it (attestation, revocation, block),
 *   - a bundle       → process every object (e.g. TCert + CA attestation),
 *   - raw base64     → try SDoc, then TCert, then statement.
 */
import { decodeBundle, decodeTransferPayload, fromBase64Url, parseSignedObject } from 'qrs-core';
import { getQrs } from './runtime';
import { verifySdoc, type CleanVerifyResult } from './verify';

/** Return an SDoc payload without performing verification, for the loading result screen. */
export function sdocPayload(raw: string): string | null {
  try {
    const transfer = decodeTransferPayload(raw.trim());
    const candidate = transfer?.type === 'sdoc' ? transfer.bytesB64 : raw.trim();
    if (!candidate) return null;
    const parsed = parseSignedObject(fromBase64Url(candidate));
    return parsed.type === 'sdoc' ? candidate : null;
  } catch {
    return null;
  }
}

export type ProcessOutcome =
  | { kind: 'verified'; result: CleanVerifyResult }
  | { kind: 'tcert-imported'; tcertId: string; documentName?: string; issuerName?: string }
  | { kind: 'statement'; statementId: string; action: string; applied: boolean; reason?: string }
  | { kind: 'bundle'; items: Array<{ type: string; ok: boolean; detail?: string }> };

async function importTcertAndDescribe(bytes: Uint8Array): Promise<{ tcertId: string; documentName?: string; issuerName?: string }> {
  const qrs = getQrs();
  const res = await qrs.online.importTcert(bytes);
  if (!res.imported || !res.tcertId) throw new Error(res.reason ?? 'Could not import certificate');
  const parsed = parseSignedObject(bytes);
  const data = parsed.data as unknown as { identity?: { name?: string; document?: string } };
  return { tcertId: res.tcertId, documentName: data.identity?.document, issuerName: data.identity?.name };
}

async function processBundle(bundle: NonNullable<ReturnType<typeof decodeBundle>>): Promise<ProcessOutcome> {
  const qrs = getQrs();
  const items: Extract<ProcessOutcome, { kind: 'bundle' }>['items'] = [];
  // Certificates are verification dependencies for statements. Process them
  // first even when a bundle from another producer puts statements first.
  const statements = bundle.objects
    .filter((obj) => obj.type === 'statement')
    .sort((a, b) => {
      const issuedAt = (obj: typeof a): number => {
        try {
          const parsed = parseSignedObject(fromBase64Url(obj.bytesB64));
          return typeof parsed.data.issuedAt === 'number' ? parsed.data.issuedAt : 0;
        } catch {
          return 0;
        }
      };
      return issuedAt(a) - issuedAt(b);
    });
  const ordered = [
    ...bundle.objects.filter((obj) => obj.type === 'tcert'),
    ...statements,
    ...bundle.objects.filter((obj) => obj.type === 'sdoc'),
  ];
  for (const obj of ordered) {
    try {
      const bytes = fromBase64Url(obj.bytesB64);
      if (obj.type === 'tcert') {
        const r = await qrs.online.importTcert(bytes);
        items.push({ type: 'tcert', ok: r.imported, detail: r.tcertId ?? r.reason });
      } else if (obj.type === 'statement') {
        const r = await qrs.online.importStatement(bytes);
        items.push({
          type: 'statement',
          ok: r.applied,
          detail: r.applied ? `${r.action}${r.target ? ' → ' + r.target : ''}` : r.reason,
        });
      } else if (obj.type === 'sdoc') {
        const r = await qrs.verification.verify(bytes, { currentTime: Math.floor(Date.now() / 1000) });
        items.push({ type: 'sdoc', ok: r.overall === 'valid', detail: r.overall });
      }
    } catch (e) {
      items.push({ type: obj.type, ok: false, detail: e instanceof Error ? e.message : 'error' });
    }
  }
  return { kind: 'bundle', items };
}

export async function processPayload(raw: string): Promise<ProcessOutcome> {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error('Empty payload.');

  // 1. Bundle (e.g. TCert + attestation from a CA).
  const bundle = decodeBundle(trimmed);
  if (bundle) return processBundle(bundle);

  // 2. Single-object transfer envelope.
  const payload = decodeTransferPayload(trimmed);
  if (payload) {
    const qrs = getQrs();
    if (payload.type === 'sdoc') {
      return { kind: 'verified', result: await verifySdoc(payload.bytesB64) };
    }
    const bytes = fromBase64Url(payload.bytesB64);
    if (payload.type === 'tcert') {
      const info = await importTcertAndDescribe(bytes);
      return { kind: 'tcert-imported', ...info };
    }
    // statement
    const r = await qrs.online.importStatement(bytes);
    return { kind: 'statement', statementId: r.statementId ?? '', action: r.action ?? 'statement', applied: r.applied, reason: r.reason };
  }

  // 3. Raw base64url: try SDoc, then TCert, then statement.
  try {
    return { kind: 'verified', result: await verifySdoc(trimmed) };
  } catch {
    /* not an SDoc */
  }
  try {
    const bytes = fromBase64Url(trimmed);
    try {
      const info = await importTcertAndDescribe(bytes);
      return { kind: 'tcert-imported', ...info };
    } catch {
      /* not a TCert */
    }
    const qrs = getQrs();
    const r = await qrs.online.importStatement(bytes);
    return { kind: 'statement', statementId: r.statementId ?? '', action: r.action ?? 'statement', applied: r.applied, reason: r.reason };
  } catch (e) {
    throw new Error(e instanceof Error ? e.message : 'Unrecognized payload.');
  }
}
