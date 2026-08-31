/**
 * IPC surface. Registers every `ipcMain.handle` used by the renderer and wires the
 * context-provider replies. All byte payloads cross the boundary as base64url.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { app, dialog, ipcMain, nativeImage } from 'electron';
import { attachmentReference, encodeBundle, encodeQrsFile, fromBase64Url, parseSignedObject, parseStatement, QRS_FILE_EXTENSION, sdocIdOf, toBase64Url, type FieldSchema } from 'qrs-core';
import {
  IPC,
  type AppInfo,
  type AttachmentData,
  type AttachmentGetInput,
  type AttachmentOpenInput,
  type AttachmentSaveInput,
  type AttachmentSubmitInput,
  type AttachmentSubmitResult,
  type ContextReply,
  type CreateTcertInput,
  type DecodedObject,
  type DocumentSummary,
  type ExportQrsInput,
  type ExportBundleInput,
  type ExportQrsResult,
  type GlobalConfig,
  type IssueInput,
  type KeySummary,
  type RevocationState,
  type SaveQrPngInput,
  type SaveQrPngResult,
  type StatementResultDto,
  type SyncQueueDto,
  type SyncResult,
  type TcertSummary,
  type TrustState,
  type VerifyDetail,
  type VerifyInput,
} from '../shared/types.js';
import type { DesktopRuntime } from './runtime.js';
import { getOnlineService } from './online.js';
import { detectKeyProtection } from './keyProtection.js';
import { fetchRawAttachment, fileNameFor, openWithDefaultApp, saveFile } from './attachments.js';
import { decodeObject, verifyWithDetail } from './objects.js';
import { listCertificates, listDocuments, summarizeDocument, summarizeTcert } from './summaries.js';
import { syncAll, syncTcert } from './sync.js';
import { TcertPinStore } from './tcertPinStore.js';

/** Union of the effective distribution endpoints across every TCert of a key. */
async function findEndpoints(rt: DesktopRuntime, keyId: string): Promise<string[]> {
  const certs = await rt.qrs.deps.certificateStore.findByKeyId(keyId);
  const out: string[] = [];
  const seen = new Set<string>();
  for (const rec of certs) {
    try {
      for (const ep of await rt.qrs.endpoints.effectiveEndpoints(rec.tcertId)) {
        if (!seen.has(ep)) {
          seen.add(ep);
          out.push(ep);
        }
      }
    } catch {
      /* skip malformed */
    }
  }
  return out;
}

/** Find the exact local CA used to authorize statements for a signing key. */
async function findCaTcertId(rt: DesktopRuntime, keyId: string): Promise<string | undefined> {
  const certs = await rt.qrs.deps.certificateStore.findByKeyId(keyId);
  for (const cert of certs) {
    if (await rt.qrs.deps.trustStore.isCa(cert.tcertId)) return cert.tcertId;
  }
  return undefined;
}

/** Publish a signed statement to every endpoint of the signer key (queue each mirror if offline). */
async function publishStatement(
  rt: DesktopRuntime,
  statement: { statementId: string; bytes: Uint8Array },
  keyId: string
): Promise<{ published: boolean; endpoints: string[] }> {
  const caTcertId = await findCaTcertId(rt, keyId);
  const signerTcert = (await rt.qrs.deps.certificateStore.findByKeyId(keyId))[0];
  const scopedTcert = caTcertId ? await rt.qrs.deps.certificateStore.get(caTcertId) : signerTcert?.bytes;
  const scopeId = caTcertId ?? (signerTcert ? `${keyId}:${(parseSignedObject(signerTcert.bytes).data as { certificateNumber?: number }).certificateNumber ?? 1}` : undefined);
  if (!scopeId || !scopedTcert) {
    console.warn(`[online] not publishing statement ${statement.statementId}: no registered signer TCert`);
    return { published: false, endpoints: [] };
  }
  const endpoints = await rt.qrs.endpoints.effectiveEndpoints(scopeId);
  if (endpoints.length === 0) {
    console.warn(`[online] not publishing statement ${statement.statementId}: CA ${caTcertId} has no endpoints`);
    return { published: false, endpoints };
  }
  const res = await getOnlineService().submitObject({
    keyId,
    caTcertId: caTcertId ?? undefined,
    onlineEndpoints: endpoints,
    kind: 'statement',
    id: statement.statementId,
    bytesB64: toBase64Url(statement.bytes),
  });
  console.log(
    `[online] statement ${statement.statementId} → ${endpoints.join(', ')}: ${res.queued ? 'PARTIALLY QUEUED' : 'PUBLISHED'}`
  );
  return { published: true, endpoints };
}

/** Enroll a target only by uploading it atomically with the CA attestation. */
async function publishAttestation(
  rt: DesktopRuntime,
  caTcertId: string,
  targetTcertId: string,
  statement: { bytes: Uint8Array }
): Promise<{ published: boolean; endpoints: string[]; error?: string }> {
  const [caBytes, targetBytes] = await Promise.all([
    rt.qrs.deps.certificateStore.get(caTcertId),
    rt.qrs.deps.certificateStore.get(targetTcertId),
  ]);
  if (!caBytes || !targetBytes) return { published: false, endpoints: [], error: 'CA or target TCert is not stored locally' };
  const ca = parseSignedObject(caBytes);
  if (ca.type !== 'tcert') return { published: false, endpoints: [], error: 'Selected CA is not a TCert' };
  const endpoints = await rt.qrs.endpoints.effectiveEndpoints(caTcertId);
  const result = await getOnlineService().submitAttestation({
    caTcertId,
    caKeyId: ca.signerKeyId,
    targetTcertB64: toBase64Url(targetBytes),
    attestationB64: toBase64Url(statement.bytes),
    onlineEndpoints: endpoints,
  });
  return { published: !result.queued, endpoints, error: result.error };
}

export function registerIpc(rt: DesktopRuntime): void {
  const pins = new TcertPinStore(() => rt.config.get(), (config) => rt.config.set(config));
  const withPin = (summary: TcertSummary): TcertSummary => ({ ...summary, hasPin: pins.has(summary.tcertId) });
  /* ---------------- app ---------------- */
  ipcMain.handle(IPC.app.getInfo, async (): Promise<AppInfo> => {
    return {
      version: app.getVersion(),
      electron: process.versions.electron ?? '',
      chrome: process.versions.chrome ?? '',
      node: process.versions.node ?? '',
      platform: process.platform,
      dataDir: rt.dataDir,
      secureKeys: rt.secureKeys,
      keyProtection: await detectKeyProtection(),
    };
  });

  /* ---------------- keys ---------------- */
  ipcMain.handle(IPC.keys.list, async (): Promise<KeySummary[]> => {
    const keys = await rt.qrs.deps.privateKeyStore.all();
    const summaries: KeySummary[] = [];
    for (const key of keys) {
      const tcerts = await rt.qrs.deps.certificateStore.findByKeyId(key.keyId);
      const revoked = await rt.qrs.deps.revocationStore.getRevokedKey(key.keyId);
      summaries.push({
        keyId: key.keyId,
        algorithm: key.algorithm,
        tcertCount: tcerts.length,
        revoked: revoked ? { issuedAt: revoked.issuedAt, reason: revoked.reason } : undefined,
      });
    }
    return summaries;
  });

  ipcMain.handle(IPC.keys.generate, async (_e, algorithm: string): Promise<KeySummary> => {
    const keyId = await rt.qrs.certificates.generateKeyPair(algorithm as never);
    const revoked = await rt.qrs.deps.revocationStore.getRevokedKey(keyId);
    return { keyId, algorithm: algorithm as never, tcertCount: 0, revoked: revoked ? { issuedAt: revoked.issuedAt, reason: revoked.reason } : undefined };
  });
  ipcMain.handle(IPC.keys.passwordStatus, async () => ({ configured: rt.privateKeyStore.isPasswordConfigured(), unlocked: rt.privateKeyStore.isPasswordUnlocked() }));
  ipcMain.handle(IPC.keys.setPassword, async (_e, password: string) => {
    await rt.privateKeyStore.setPassword(password);
    rt.config.set({ ...rt.config.get(), privateKeyPasswordConfigured: true });
  });
  ipcMain.handle(IPC.keys.unlock, async (_e, password: string) => rt.privateKeyStore.unlock(password));
  ipcMain.handle(IPC.keys.removePassword, async (_e, password: string) => {
    await rt.privateKeyStore.unlock(password);
    await rt.privateKeyStore.removePassword();
    rt.config.set({ ...rt.config.get(), privateKeyPasswordConfigured: false });
  });

  /* ---------------- certificates ---------------- */
  ipcMain.handle(IPC.certificates.list, async (): Promise<TcertSummary[]> => {
    return (await listCertificates(rt.qrs)).map(withPin);
  });

  ipcMain.handle(IPC.certificates.create, async (_e, input: CreateTcertInput): Promise<TcertSummary> => {
    const result = await rt.qrs.certificates.createTcert(input);
    return withPin(await summarizeTcert(rt.qrs, result.bytes));
  });

  ipcMain.handle(IPC.certificates.get, async (_e, tcertId: string): Promise<TcertSummary | null> => {
    const bytes = await rt.qrs.deps.certificateStore.get(tcertId);
    return bytes ? withPin(await summarizeTcert(rt.qrs, bytes)) : null;
  });

  ipcMain.handle(IPC.certificates.import, async (_e, bytesB64: string): Promise<TcertSummary> => {
    const bytes = fromBase64Url(bytesB64);
    const parsed = parseSignedObject(bytes); // throws if malformed
    if (parsed.type !== 'tcert') throw new Error('Imported object is not a TCert');
    const tcertId = `${parsed.signerKeyId}:${(parsed.data as { certificateNumber: number }).certificateNumber}`;
    await rt.qrs.deps.certificateStore.save(tcertId, bytes);
    return withPin(await summarizeTcert(rt.qrs, bytes));
  });

  ipcMain.handle(IPC.certificates.export, async (_e, tcertId: string): Promise<string> => {
    const bytes = await rt.qrs.deps.certificateStore.get(tcertId);
    if (!bytes) throw new Error(`TCert not found: ${tcertId}`);
    return toBase64Url(bytes);
  });

  ipcMain.handle(IPC.certificates.remove, async (_e, tcertId: string): Promise<void> => {
    await rt.qrs.deps.certificateStore.remove(tcertId);
    await rt.qrs.deps.trustStore.removePinned(tcertId);
    await rt.qrs.deps.trustStore.removeCa(tcertId);
    await rt.qrs.deps.trustStore.removeDistrust(tcertId);
    if (pins.has(tcertId)) {
      const config = rt.config.get();
      const tcertPins = { ...(config.tcertPins ?? {}) };
      delete tcertPins[tcertId];
      rt.config.set({ ...config, tcertPins });
    }
  });
  ipcMain.handle(IPC.certificates.setPin, async (_e, tcertId: string, pin: string) => pins.set(tcertId, pin));
  ipcMain.handle(IPC.certificates.changePin, async (_e, tcertId: string, previousPin: string, nextPin: string) => {
    if (!pins.verify(tcertId, previousPin)) throw new Error('Incorrect TCert PIN.');
    pins.set(tcertId, nextPin);
  });
  ipcMain.handle(IPC.certificates.removePin, async (_e, tcertId: string, previousPin: string) => pins.remove(tcertId, previousPin));
  ipcMain.handle(IPC.certificates.verifyPin, async (_e, tcertId: string, pin: string) => pins.verify(tcertId, pin));
  ipcMain.handle(IPC.certificates.isPinAuthorized, async (_e, tcertId: string) => pins.isAuthorized(tcertId));
  ipcMain.handle(IPC.certificates.beginPinSession, async (_e, tcertId: string) => pins.beginSession(tcertId));
  ipcMain.handle(IPC.certificates.endPinSession, async (_e, tcertId: string) => pins.endSession(tcertId));
  ipcMain.handle(IPC.certificates.exportSchema, async (_e, tcertId: string) => {
    const bytes = await rt.qrs.deps.certificateStore.get(tcertId);
    if (!bytes) throw new Error(`TCert not found: ${tcertId}`);
    const parsed = parseSignedObject(bytes);
    const name = String((parsed.data as { identity?: { name?: string } }).identity?.name ?? 'document').replace(/[^a-zA-Z0-9._-]/g, '_');
    const result = await dialog.showSaveDialog({ title: 'Export schema', defaultPath: `${name} schema.qrs`, filters: [{ name: 'QRS schema', extensions: ['qrs'] }] });
    if (result.canceled || !result.filePath) return { saved: false };
    try { writeFileSync(result.filePath, JSON.stringify({ type: 'qrs-schema', version: 1, name: (parsed.data as { identity?: { name?: string } }).identity?.name, fields: (parsed.data as { schema?: unknown[] }).schema ?? [] }, null, 2), 'utf8'); return { saved: true, path: result.filePath }; }
    catch (error) { return { saved: false, error: error instanceof Error ? error.message : 'failed to write schema' }; }
  });
  ipcMain.handle(IPC.certificates.importSchema, async () => {
    const result = await dialog.showOpenDialog({ title: 'Import schema', properties: ['openFile'], filters: [{ name: 'QRS schema', extensions: ['qrs', 'json'] }] });
    if (result.canceled || !result.filePaths[0]) throw new Error('Schema import cancelled');
    let parsed: unknown;
    try { parsed = JSON.parse(readFileSync(result.filePaths[0], 'utf8')); } catch { throw new Error('Invalid schema file.'); }
    const fields = (parsed && typeof parsed === 'object' && Array.isArray((parsed as { fields?: unknown }).fields)) ? (parsed as { fields: FieldSchema[] }).fields : undefined;
    if (!fields) throw new Error('Invalid schema file: fields are missing.');
    return fields;
  });

  /* ---------------- documents ---------------- */
  ipcMain.handle(IPC.documents.list, async (): Promise<DocumentSummary[]> => {
    return listDocuments(rt.qrs);
  });

  ipcMain.handle(IPC.documents.issue, async (_e, input: IssueInput): Promise<DocumentSummary> => {
    if (pins.has(input.tcertId) && !pins.isAuthorized(input.tcertId) && !pins.verify(input.tcertId, input.pin ?? '')) throw new Error('Incorrect TCert PIN.');
    const result = await rt.qrs.signing.issueSdoc(input);
    return summarizeDocument(rt.qrs, result.bytes);
  });

  ipcMain.handle(IPC.documents.get, async (_e, sdocId: string): Promise<DocumentSummary | null> => {
    const bytes = await rt.qrs.deps.documentStore.get(sdocId);
    return bytes ? summarizeDocument(rt.qrs, bytes) : null;
  });

  ipcMain.handle(IPC.documents.import, async (_e, bytesB64: string): Promise<DocumentSummary> => {
    const bytes = fromBase64Url(bytesB64);
    const parsed = parseSignedObject(bytes); // throws if malformed
    if (parsed.type !== 'sdoc') throw new Error('Imported object is not an SDoc');
    const sdocId = sdocIdOf(bytes);
    await rt.qrs.deps.documentStore.save(sdocId, bytes);
    return summarizeDocument(rt.qrs, bytes);
  });

  ipcMain.handle(IPC.documents.export, async (_e, sdocId: string): Promise<string> => {
    const bytes = await rt.qrs.deps.documentStore.get(sdocId);
    if (!bytes) throw new Error(`SDoc not found: ${sdocId}`);
    return toBase64Url(bytes);
  });

  ipcMain.handle(IPC.documents.remove, async (_e, sdocId: string): Promise<void> => {
    await rt.qrs.deps.documentStore.remove(sdocId);
    await rt.qrs.deps.revocationStore.removeBlockedSdoc(sdocId);
  });

  /* ---------------- trust ---------------- */
  ipcMain.handle(IPC.trust.state, async (): Promise<TrustState> => {
    const [pinned, cas, allTcerts, allAttestations] = await Promise.all([
      rt.qrs.deps.trustStore.listPinned(),
      rt.qrs.deps.trustStore.listCa(),
      rt.qrs.deps.certificateStore.all(),
      rt.qrs.deps.trustStore.listAttestations(),
    ]);
    const distrusted: string[] = [];
    for (const entry of allTcerts) {
      if (await rt.qrs.deps.trustStore.isDistrusted(entry.tcertId)) distrusted.push(entry.tcertId);
    }
    const attestations: TrustState['attestations'] = [];
    for (const record of allAttestations) {
        let statementId: string | undefined;
        try {
          statementId = parseStatement(record.statementBytes).statementId;
        } catch {
          /* best effort */
        }
        attestations.push({
          targetTcertId: record.targetTcertId,
          caTcertId: record.caTcertId,
          claims: record.claims,
          issuedAt: record.issuedAt,
          bytesB64: toBase64Url(record.statementBytes),
          statementId,
        });
      }
    return { pinned, cas, distrusted, attestations };
  });

  ipcMain.handle(IPC.trust.pin, async (_e, tcertId: string): Promise<void> => {
    await rt.qrs.trust.pin(tcertId);
  });
  ipcMain.handle(IPC.trust.unpin, async (_e, tcertId: string): Promise<void> => {
    await rt.qrs.trust.unpin(tcertId);
  });
  ipcMain.handle(IPC.trust.addCa, async (_e, tcertId: string): Promise<void> => {
    await rt.qrs.trust.addCa(tcertId);
  });
  ipcMain.handle(IPC.trust.removeCa, async (_e, tcertId: string): Promise<void> => {
    await rt.qrs.trust.removeCa(tcertId);
  });
  ipcMain.handle(IPC.trust.distrust, async (_e, tcertId: string): Promise<void> => {
    await rt.qrs.trust.distrust(tcertId);
  });
  ipcMain.handle(IPC.trust.trustAgain, async (_e, tcertId: string): Promise<void> => {
    await rt.qrs.trust.trustAgain(tcertId);
  });
  ipcMain.handle(
    IPC.trust.attest,
    async (_e, input: { caTcertId: string; targetTcertId: string; claims?: Record<string, unknown> }): Promise<StatementResultDto> => {
      const res = await rt.qrs.trust.attest(input);
      // Publish the attestation + register the attested certificate on the CA's servers.
      const pub = await publishAttestation(rt, input.caTcertId, input.targetTcertId, res);
      return {
        statementId: res.statementId,
        bytesB64: toBase64Url(res.bytes),
        published: pub.published,
        endpoints: pub.endpoints,
      };
    }
  );

  /* ---------------- revocation ---------------- */
  ipcMain.handle(IPC.revocation.state, async (): Promise<RevocationState> => {
    const [revokedTcerts, revokedKeys, blockedSdocs, sdocStatements, revokedAttestations] = await Promise.all([
      rt.qrs.deps.revocationStore.listRevokedTcert(),
      rt.qrs.deps.revocationStore.listRevokedKey(),
      rt.qrs.deps.revocationStore.listBlockedSdoc(),
      rt.qrs.deps.revocationStore.listSdocStatements(),
      rt.qrs.deps.revocationStore.listRevokedAttestation(),
    ]);
    return {
      revokedAttestations: revokedAttestations.map((e) => ({ targetTcertId: e.targetTcertId, caTcertId: e.caTcertId, issuedAt: e.entry.issuedAt, reason: e.entry.reason, bytesB64: e.entry.statementBytes ? toBase64Url(e.entry.statementBytes) : undefined, byKeyId: e.entry.byKeyId })),
      revokedTcerts: revokedTcerts.map((e) => ({
        tcertId: e.tcertId,
        type: e.entry.type,
        issuedAt: e.entry.issuedAt,
        reason: e.entry.reason,
        bytesB64: e.entry.statementBytes ? toBase64Url(e.entry.statementBytes) : undefined,
        byTcertId: e.entry.byTcertId,
        byKeyId: e.entry.byKeyId,
      })),
      revokedKeys: revokedKeys.map((e) => ({ keyId: e.keyId, issuedAt: e.entry.issuedAt, reason: e.entry.reason, bytesB64: e.entry.statementBytes ? toBase64Url(e.entry.statementBytes) : undefined, byTcertId: e.entry.byTcertId, byKeyId: e.entry.byKeyId })),
      blockedSdocs: blockedSdocs.map((e) => ({ sdocId: e.sdocId, issuedAt: e.entry.issuedAt, reason: e.entry.reason, bytesB64: e.entry.statementBytes ? toBase64Url(e.entry.statementBytes) : undefined, byTcertId: e.entry.byTcertId, byKeyId: e.entry.byKeyId })),
      sdocStatements: sdocStatements.map((e) => ({ sdocId: e.sdocId, action: e.entry.action, issuedAt: e.entry.issuedAt, reason: e.entry.reason, bytesB64: e.entry.statementBytes ? toBase64Url(e.entry.statementBytes) : undefined, byTcertId: e.entry.byTcertId, byKeyId: e.entry.byKeyId })),
    };
  });

  ipcMain.handle(IPC.revocation.revokeAttestation, async (_e, input: { caTcertId: string; targetTcertId: string; reason?: string }): Promise<StatementResultDto> => {
    const res = await rt.qrs.revocation.revokeAttestation(input);
    const signerKeyId = input.caTcertId.slice(0, input.caTcertId.lastIndexOf(':'));
    const pub = await publishStatement(rt, res, signerKeyId);
    return { statementId: res.statementId, bytesB64: toBase64Url(res.bytes), published: pub.published, endpoints: pub.endpoints };
  });

  ipcMain.handle(
    IPC.revocation.revokeTcert,
    async (_e, input: { signerKeyId: string; targetTcertId: string; type: string; reason?: string }): Promise<StatementResultDto> => {
      const res = await rt.qrs.revocation.revokeTcert(input as never);
      const pub = await publishStatement(rt, res, input.signerKeyId);
      return { statementId: res.statementId, bytesB64: toBase64Url(res.bytes), published: pub.published, endpoints: pub.endpoints };
    }
  );
  ipcMain.handle(
    IPC.revocation.revokeKey,
    async (_e, input: { signerKeyId: string; targetKeyId: string; reason?: string }): Promise<StatementResultDto> => {
      const res = await rt.qrs.revocation.revokeKey(input as never);
      const pub = await publishStatement(rt, res, input.signerKeyId);
      return { statementId: res.statementId, bytesB64: toBase64Url(res.bytes), published: pub.published, endpoints: pub.endpoints };
    }
  );
  ipcMain.handle(
    IPC.revocation.blockSdoc,
    async (_e, input: { signerKeyId: string; targetSdocId: string; reason?: string }): Promise<StatementResultDto> => {
      const res = await rt.qrs.revocation.blockSdoc(input as never);
      const pub = await publishStatement(rt, res, input.signerKeyId);
      return { statementId: res.statementId, bytesB64: toBase64Url(res.bytes), published: pub.published, endpoints: pub.endpoints };
    }
  );
  ipcMain.handle(
    IPC.revocation.unblockSdoc,
    async (_e, input: { signerKeyId: string; targetSdocId: string; reason?: string }): Promise<StatementResultDto> => {
      const res = await rt.qrs.revocation.unblockSdoc(input as never);
      const pub = await publishStatement(rt, res, input.signerKeyId);
      return { statementId: res.statementId, bytesB64: toBase64Url(res.bytes), published: pub.published, endpoints: pub.endpoints };
    }
  );

  /* ---------------- verification ---------------- */
  ipcMain.handle(IPC.verification.verify, async (_e, input: VerifyInput): Promise<VerifyDetail> => {
    return verifyWithDetail(rt.qrs, input.bytesB64, input.currentTime);
  });

  /* ---------------- objects (dev-only plaintext view) ---------------- */
  ipcMain.handle(IPC.objects.decode, async (_e, bytesB64: string): Promise<DecodedObject> => {
    return decodeObject(bytesB64);
  });

  /* ---------------- .qrs file export ---------------- */
  ipcMain.handle(IPC.objects.exportQrs, async (_e, input: ExportQrsInput): Promise<ExportQrsResult> => {
    const payloadText = new TextDecoder().decode(encodeQrsFile(input.type, input.bytesB64));
    let signedName: string | undefined;
    if (input.type === 'tcert') {
      try {
        const parsed = parseSignedObject(fromBase64Url(input.bytesB64));
        const identity = (parsed.data as { identity?: { name?: unknown } }).identity;
        if (typeof identity?.name === 'string' && identity.name.trim()) signedName = identity.name.trim();
      } catch {
        /* The export still uses the caller's fallback name for malformed legacy data. */
      }
    }
    // Preserve Unicode identity names (for example Persian/Pashto); remove only
    // characters that could create a path or are invalid in a filename.
    const safe = (signedName ?? input.suggestedName ?? 'qrs-object')
      .replace(/[<>:"/\\|?*\u0000-\u001F]+/g, '_')
      .replace(/^\.+|\.+$/g, '')
      .trim() || 'qrs-object';
    const { canceled, filePath } = await dialog.showSaveDialog({
      title: 'Export QRS signed object',
      defaultPath: `${safe}.${QRS_FILE_EXTENSION}`,
      filters: [{ name: 'QRS Signed Object', extensions: [QRS_FILE_EXTENSION] }],
    });
    if (canceled || !filePath) return { saved: false };
    try {
      writeFileSync(filePath, payloadText, 'utf8');
      return { saved: true, path: filePath };
    } catch (error) {
      return { saved: false, error: error instanceof Error ? error.message : 'failed to write file' };
    }
  });
  ipcMain.handle(IPC.objects.exportBundle, async (_e, input: ExportBundleInput): Promise<ExportQrsResult> => {
    const statements = input.statementBytesB64 ?? (input.attestationBytesB64 ? [input.attestationBytesB64] : []);
    const payload = encodeBundle([
      { type: 'tcert', bytesB64: input.tcertBytesB64 },
      ...(input.additionalTcertBytesB64 ?? []).map((bytesB64) => ({ type: 'tcert' as const, bytesB64 })),
      ...statements.map((bytesB64) => ({ type: 'statement' as const, bytesB64 })),
    ]);
    const safe = (input.suggestedName ?? 'attestation-bundle').replace(/[<>:"/\\|?*\u0000-\u001F]+/g, '_').trim() || 'attestation-bundle';
    const { canceled, filePath } = await dialog.showSaveDialog({ title: 'Export TCert attestation bundle', defaultPath: `${safe}.${QRS_FILE_EXTENSION}`, filters: [{ name: 'QRS Bundle', extensions: [QRS_FILE_EXTENSION] }] });
    if (canceled || !filePath) return { saved: false };
    try { writeFileSync(filePath, new TextEncoder().encode(payload)); return { saved: true, path: filePath }; } catch (error) { return { saved: false, error: error instanceof Error ? error.message : 'failed to write bundle' }; }
  });

  /* ---------------- QR image export (copy/download PNG) ---------------- */
  ipcMain.handle(IPC.objects.saveQrPng, async (_e, input: SaveQrPngInput): Promise<SaveQrPngResult> => {
    const safe = (input.suggestedName ?? 'qrs-qr').replace(/[^a-z0-9._-]+/gi, '_');
    const { canceled, filePath } = await dialog.showSaveDialog({
      title: 'Save QR code as PNG',
      defaultPath: `${safe}.png`,
      filters: [{ name: 'PNG image', extensions: ['png'] }],
    });
    if (canceled || !filePath) return { saved: false };
    try {
      const image = nativeImage.createFromDataURL(input.dataUrl);
      if (image.isEmpty()) return { saved: false, error: 'could not decode QR image' };
      writeFileSync(filePath, image.toPNG());
      return { saved: true, path: filePath };
    } catch (error) {
      return { saved: false, error: error instanceof Error ? error.message : 'failed to write PNG' };
    }
  });

  /* ---------------- attachments / online distribution ---------------- */
  const online = getOnlineService();
  ipcMain.handle(IPC.attachments.submit, async (_e, input: AttachmentSubmitInput): Promise<AttachmentSubmitResult> => {
    // The renderer sends raw file bytes. The SDoc stores only the truncated
    // SHA-256 content-addressed reference; the server stores the raw file.
    const bytes = fromBase64Url(input.bytesB64);
    const tcertBytes = await rt.qrs.deps.certificateStore.get(input.tcertId);
    if (!tcertBytes) throw new Error(`Issuing TCert not found: ${input.tcertId}`);
    const tcert = parseSignedObject(tcertBytes);
    if (tcert.type !== 'tcert') throw new Error(`Not a TCert: ${input.tcertId}`);
    const field = (tcert.data.schema as Array<{ type?: string; name?: string; inputRules?: { contentType?: string } }> | undefined)?.find(
      (candidate) => candidate.type === 'attachment' && candidate.name === input.fieldName
    );
    if (!field) throw new Error(`Attachment field not found in issuing TCert: ${input.fieldName}`);
    const hash = attachmentReference(bytes);
    const size = bytes.byteLength;
    const endpoints =
      (input.onlineEndpoints && input.onlineEndpoints.length > 0)
        ? input.onlineEndpoints
        : await findEndpoints(rt, input.keyId);
    const res = await online.submitRawAttachment({
      keyId: input.keyId,
      tcertId: input.tcertId,
      fieldName: input.fieldName,
      onlineEndpoints: endpoints,
      hash,
      size,
      contentB64: toBase64Url(bytes),
    });
    return { hash, size, queued: res.queued, error: res.error };
  });
  ipcMain.handle(IPC.attachments.sync, async (): Promise<SyncResult> => {
    // Full sync: upload pending signed objects + download + apply hosted objects.
    return syncAll(rt);
  });
  ipcMain.handle(IPC.attachments.syncTcert, async (_e, tcertId: string): Promise<SyncResult> => {
    // Sync only the distribution server of one specific TCert.
    return syncTcert(rt, tcertId);
  });
  ipcMain.handle(IPC.attachments.queue, async (): Promise<SyncQueueDto> => {
    return { queue: online.listQueue() };
  });
  ipcMain.handle(IPC.attachments.pending, async (): Promise<number> => {
    return online.pendingCount();
  });
  ipcMain.handle(IPC.attachments.pendingForTcert, async (_e, tcertId: string): Promise<number> => {
    return online.pendingAttachmentCount(tcertId);
  });
  ipcMain.handle(IPC.attachments.get, async (_e, input: AttachmentGetInput): Promise<AttachmentData | null> => {
    const att = await fetchRawAttachment(
      input.id,
      input.size,
      input.contentType,
      input.onlineEndpoints ?? input.onlineEndpoint,
      input.content
    );
    if (!att) return null;
    return {
      id: att.id,
      contentType: att.contentType,
      contentHash: att.contentHash,
      size: att.size,
      contentB64: att.contentB64,
    };
  });
  ipcMain.handle(IPC.attachments.open, async (_e, input: AttachmentOpenInput) => {
    return openWithDefaultApp(input.bytesB64, fileNameFor(input.id, input.contentType));
  });
  ipcMain.handle(IPC.attachments.save, async (_e, input: AttachmentSaveInput) => {
    return saveFile(input.bytesB64, input.contentType, input.defaultName ?? fileNameFor(input.id, input.contentType));
  });

  /* ---------------- endpoints (mirror management, per TCert) ---------------- */
  ipcMain.handle(IPC.endpoints.list, async (_e, tcertId: string): Promise<string[]> => {
    return rt.qrs.endpoints.effectiveEndpoints(tcertId);
  });
  ipcMain.handle(IPC.endpoints.mirrors, async (_e, tcertId: string): Promise<string[]> => {
    return rt.qrs.endpoints.listMirrors(tcertId);
  });
  ipcMain.handle(IPC.endpoints.add, async (_e, tcertId: string, endpoint: string): Promise<string[]> => {
    return rt.qrs.endpoints.addMirror(tcertId, endpoint);
  });
  ipcMain.handle(IPC.endpoints.remove, async (_e, tcertId: string, endpoint: string): Promise<string[]> => {
    return rt.qrs.endpoints.removeMirror(tcertId, endpoint);
  });

  /* ---------------- global config ---------------- */
  ipcMain.handle(IPC.config.get, async (): Promise<GlobalConfig> => {
    return rt.config.get();
  });
  ipcMain.handle(IPC.config.set, async (_e, config: GlobalConfig): Promise<GlobalConfig> => {
    return rt.config.set(config);
  });

  /* ---------------- context replies (renderer -> main) ---------------- */
  ipcMain.on(IPC.context.reply, (_e, reply: ContextReply) => {
    rt.context.reply(reply);
  });
}
