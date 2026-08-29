/**
 * Higher-level object helpers for the IPC layer:
 *  - dev-only plaintext decode of any signed object,
 *  - verification result enriched with decoded values and issuer/CA names.
 */
import {
  fromBase64Url,
  parseSignedObject,
  sdocIdOf,
  tcertIdOf,
  toHex,
  type QrsRuntime,
} from 'qrs-core';
import type { DecodedObject, VerifyDetail } from '../shared/types.js';
import { summarizeDocument, summarizeTcert } from './summaries.js';

/** Convert decoded CBOR values into a JSON-safe tree (byte strings → hex). */
export function toJsonSafe(value: unknown): unknown {
  if (value instanceof Uint8Array) return { $bytes: toHex(value) };
  if (value instanceof Map) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of value) out[String(k)] = toJsonSafe(v);
    return out;
  }
  if (Array.isArray(value)) return value.map(toJsonSafe);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = toJsonSafe(v);
    return out;
  }
  return value;
}

/** Human-readable CBOR diagnostic dump, retaining the original wire bytes. */
function cborDiagnostic(bytes: Uint8Array): string {
  const hex = (part: Uint8Array) => Array.from(part, (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  const text = (part: Uint8Array) => JSON.stringify(new TextDecoder().decode(part));
  const read = (offset: number): { value: number; size: number } => {
    const ai = bytes[offset] & 31;
    if (ai < 24) return { value: ai, size: 1 };
    const size = ai === 24 ? 2 : ai === 25 ? 3 : ai === 26 ? 5 : ai === 27 ? 9 : 0;
    if (!size) throw new Error('indefinite CBOR is not supported in diagnostic view');
    let value = 0;
    for (let i = 1; i < size; i++) value = value * 256 + bytes[offset + i];
    return { value, size };
  };
  const lines: string[] = [];
  const visit = (offset: number, indent: string): number => {
    const start = offset;
    const initial = bytes[offset];
    const major = initial >> 5;
    const length = read(offset);
    offset += length.size;
    const label = (major === 0 ? `uint(${length.value})` : major === 1 ? `nint(${-1 - length.value})` :
      major === 2 ? `bytes(${length.value})` : major === 3 ? `text(${length.value})` :
      major === 4 ? `array(${length.value})` : major === 5 ? `map(${length.value})` : `major(${major})`);
    lines.push(`${indent}${hex(bytes.slice(start, offset))} # ${label}`);
    if (major === 2 || major === 3) {
      const end = offset + length.value;
      lines.push(`${indent}  ${hex(bytes.slice(offset, end))} # ${major === 3 ? text(bytes.slice(offset, end)) : 'bytes'}`);
      return end;
    }
    if (major === 4) for (let i = 0; i < length.value; i++) offset = visit(offset, `${indent}  `);
    if (major === 5) for (let i = 0; i < length.value * 2; i++) offset = visit(offset, `${indent}  `);
    return offset;
  };
  try { visit(0, ''); } catch (error) { lines.push(`# diagnostic error: ${error instanceof Error ? error.message : String(error)}`); }
  return lines.join('\n');
}

/** Dev-only: decode a signed object, retaining both plaintext and wire structure. */
export async function decodeObject(bytesB64: string): Promise<DecodedObject> {
  const bytes = fromBase64Url(bytesB64);
  const parsed = parseSignedObject(bytes);
  let id: string | undefined;
  if (parsed.type === 'tcert') {
    const data = parsed.data as unknown as { keyId: Uint8Array; certificateNumber: number };
    id = tcertIdOf(toHex(data.keyId), data.certificateNumber);
  } else if (parsed.type === 'sdoc') {
    id = sdocIdOf(bytes);
  }
  return {
    type: parsed.type,
    algorithm: parsed.algorithm,
    id,
    data: toJsonSafe(parsed.data),
    wire: {
      objectBytes: toJsonSafe(bytes),
      cose: toJsonSafe(parsed.cose),
      signedPayload: toJsonSafe(parsed.payload),
      dataBytes: toJsonSafe(parsed.dataBytes),
      signature: toJsonSafe(parsed.signature),
      cborDiagnostic: {
        object: cborDiagnostic(bytes),
        cose: cborDiagnostic(bytes),
        signedPayload: cborDiagnostic(parsed.payload),
        data: cborDiagnostic(parsed.dataBytes),
      },
    },
  };
}

/** Verify an SDoc and enrich the result with the decoded values + issuer/CA names. */
export async function verifyWithDetail(
  qrs: QrsRuntime,
  bytesB64: string,
  currentTime?: number
): Promise<VerifyDetail> {
  const bytes = fromBase64Url(bytesB64);
  const result = await qrs.verification.verify(bytes, currentTime !== undefined ? { currentTime } : {});
  const detail: VerifyDetail = { result };
  try {
    const sdoc = await summarizeDocument(qrs, bytes);
    detail.sdocId = sdoc.sdocId;
    detail.tcertId = sdoc.tcertId;
    detail.issuedAt = sdoc.issuedAt;
    detail.values = sdoc.values;
    detail.bytesB64 = sdoc.bytesB64;
    const tcertBytes = await qrs.deps.certificateStore.get(sdoc.tcertId);
    if (tcertBytes) {
      const tcert = await summarizeTcert(qrs, tcertBytes);
      detail.documentName = tcert.name; // the issuing TCert's name (it represents this document)
      detail.onlineEndpoint = tcert.onlineEndpoint;
      detail.onlineEndpoints = tcert.endpoints;
      const trust = await qrs.trust.resolveTrust(sdoc.tcertId);
      if (trust.ca) {
        const caBytes = await qrs.deps.certificateStore.get(trust.ca.caTcertId);
        if (caBytes) {
          const ca = await summarizeTcert(qrs, caBytes);
          detail.caName = ca.name;
          detail.issuerName = ca.name;
        }
      }
    }
  } catch {
    // Decoding is best-effort; the verification result stays authoritative.
  }
  return detail;
}
