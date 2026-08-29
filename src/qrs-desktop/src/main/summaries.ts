/**
 * Summarisers that turn signed objects into JSON-safe DTOs for the renderer.
 * Pure-ish helpers over the runtime's stores and registries — kept separate from
 * IPC wiring so they are trivially unit-testable.
 */
import {
  attachmentContentType,
  parseSignedObject,
  sdocIdOf,
  tcertIdOf,
  tcertNumberOf,
  toBase64Url,
  toHex,
  type FieldSchema,
  type QrsRuntime,
} from 'qrs-core';
import type { AlgorithmId, HashAlgorithm, RevocationType } from 'qrs-core';
import type { DocumentSummary, DocumentValue, TcertSummary } from '../shared/types.js';

/** Build a {@link TcertSummary} from raw TCert bytes. */
export async function summarizeTcert(qrs: QrsRuntime, bytes: Uint8Array): Promise<TcertSummary> {
  const parsed = parseSignedObject(bytes);
  if (parsed.type !== 'tcert') throw new Error('Object is not a TCert');
  const data = parsed.data as unknown as {
    keyId: Uint8Array;
    certificateNumber: number;
    algorithm: AlgorithmId;
    identity: { name: string };
    schema?: FieldSchema[];
    hashAlgorithm?: string;
    validity?: { validAfter?: number; validBefore?: number; sdocMaxAgeSeconds?: number };
    onlineEndpoint?: string;
    metadata?: Record<string, unknown>;
  };

  const keyId = toHex(data.keyId);
  const tcertId = tcertIdOf(keyId, data.certificateNumber);

  const [pinned, isCa, distrusted, revoked, own] = await Promise.all([
    qrs.deps.trustStore.isPinned(tcertId),
    qrs.deps.trustStore.isCa(tcertId),
    qrs.deps.trustStore.isDistrusted(tcertId),
    qrs.deps.revocationStore.getRevokedTcert(tcertId),
    qrs.deps.privateKeyStore.has(keyId),
  ]);

  return {
    tcertId,
    keyId,
    algorithm: data.algorithm,
    name: data.identity.name,
    certificateNumber: data.certificateNumber,
    fields: data.schema ?? [],
    hasSchema: Array.isArray(data.schema) && data.schema.length > 0,
    hashAlgorithm: (data.hashAlgorithm as HashAlgorithm | undefined) ?? 'SHA-256',
    validity: data.validity,
    onlineEndpoint: data.onlineEndpoint,
    endpoints: await qrs.endpoints.effectiveEndpoints(tcertId),
    own,
    metadata: data.metadata,
    bytesB64: toBase64Url(bytes),
    pinned,
    isCa,
    distrusted,
    revoked: revoked
      ? { type: revoked.type as RevocationType, issuedAt: revoked.issuedAt, reason: revoked.reason }
      : undefined,
  };
}

/** Build a {@link DocumentSummary} from raw SDoc bytes (decoding stored values). */
export async function summarizeDocument(qrs: QrsRuntime, bytes: Uint8Array): Promise<DocumentSummary> {
  const parsed = parseSignedObject(bytes);
  if (parsed.type !== 'sdoc') throw new Error('Object is not an SDoc');
  const data = parsed.data as unknown as {
    issuedAt: number;
    fields: unknown[];
  };

  const sdocId = sdocIdOf(bytes);
  const keyId = parsed.signerKeyId;
  const tcertId = tcertIdOf(keyId, tcertNumberOf(parsed));

  const [tcertBytes, blocked] = await Promise.all([
    qrs.deps.certificateStore.get(tcertId),
    qrs.deps.revocationStore.getBlockedSdoc(sdocId),
  ]);

  let values: DocumentValue[] | undefined;
  let documentName: string | undefined;
  if (tcertBytes) {
    const tcertParsed = parseSignedObject(tcertBytes);
    const tcertData = tcertParsed.data as unknown as {
      schema: FieldSchema[];
      identity: { name?: string };
    };
    const schema = tcertData.schema;
    documentName = tcertData.identity?.name;
    const stored = data.fields ?? []; // schema-indexed values
    values = [];
    for (let i = 0; i < schema.length; i++) {
      const field = schema[i];
      if (!field) continue;
      const encoded = stored[i];
      if (encoded === undefined || encoded === null) continue;
      const engine = qrs.deps.fieldRegistry.get(field.type);
      const value: DocumentValue = {
        name: field.name,
        label: field.label,
        type: field.type,
        value: engine.decode(field, encoded),
      };
      if (field.type === 'attachment') value.contentType = attachmentContentType(field);
      // selectv2: carry the schema options so the renderer can resolve the
      // selected option's label + color from the stored index.
      if (field.type === 'selectv2') {
        value.options = (field.inputRules?.options as unknown) ?? field.options;
      }
      values.push(value);
    }
  }

  return {
    sdocId,
    tcertId,
    issuedAt: data.issuedAt,
    sizeBytes: bytes.byteLength,
    bytesB64: toBase64Url(bytes),
    documentName,
    values,
    blocked: blocked ? { issuedAt: blocked.issuedAt, reason: blocked.reason } : undefined,
  };
}

/**
 * List all documents, skipping any object that no longer parses (e.g. older wire
 * formats) so a single bad entry cannot blank the whole list.
 */
export async function listDocuments(qrs: QrsRuntime): Promise<DocumentSummary[]> {
  const all = await qrs.deps.documentStore.all();
  const out: DocumentSummary[] = [];
  for (const e of all) {
    try {
      out.push(await summarizeDocument(qrs, e.bytes));
    } catch {
      /* skip unparseable */
    }
  }
  return out;
}

/** List all TCerts, skipping unparseable entries (same resilience as documents). */
export async function listCertificates(qrs: QrsRuntime): Promise<TcertSummary[]> {
  const all = await qrs.deps.certificateStore.all();
  const out: TcertSummary[] = [];
  for (const e of all) {
    try {
      out.push(await summarizeTcert(qrs, e.bytes));
    } catch {
      /* skip unparseable */
    }
  }
  return out;
}
