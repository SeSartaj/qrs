/**
 * Transfer envelope.
 *
 * QR codes are the offline medium for moving signed objects (TCert, SDoc,
 * Statement) between devices — desktop to mobile, or vice-versa. The payload is a
 * small, scannable, self-describing string so the receiving app knows what it is
 * and what to do with it before parsing:
 *
 *     qrs://v1/<type>/<base64url-bytes>
 *
 * This is a *transport* format only: the receiving app still performs the full
 * protocol steps (parse, verify signature, resolve trust, check revocation).
 *
 * Multiple objects can travel together in a *bundle* (e.g. a CA shares an
 * attestation *with* the complete attested TCert so the verifier can fully
 * process it offline):
 *
 *     qrs://v1/bundle/<base64url-json>
 */
import { fromBase64Url, toBase64Url } from './id.js';

export type TransferObjectType = 'tcert' | 'sdoc' | 'statement';

export const TRANSFER_SCHEME = 'qrs';
export const TRANSFER_VERSION = 'v1';

export interface DecodedTransferPayload {
  type: TransferObjectType;
  bytesB64: string;
}

/** Build a transfer payload for a signed object's base64url bytes. */
export function encodeTransferPayload(type: TransferObjectType, bytesB64: string): string {
  return `${TRANSFER_SCHEME}://${TRANSFER_VERSION}/${type}/${bytesB64}`;
}

/** Parse a transfer payload. Returns `null` when the payload is not one of ours. */
export function decodeTransferPayload(payload: string): DecodedTransferPayload | null {
  const prefix = `${TRANSFER_SCHEME}://${TRANSFER_VERSION}/`;
  if (!payload.startsWith(prefix)) return null;
  const rest = payload.slice(prefix.length);
  const slash = rest.indexOf('/');
  if (slash === -1) return null;
  const type = rest.slice(0, slash) as TransferObjectType;
  const bytesB64 = rest.slice(slash + 1);
  if (type !== 'tcert' && type !== 'sdoc' && type !== 'statement') return null;
  if (bytesB64.length === 0) return null;
  return { type, bytesB64 };
}

/* -------------------------------------------------------------------------- */
/* Bundle (multiple signed objects in one payload)                             */
/* -------------------------------------------------------------------------- */

export interface BundleObject {
  type: TransferObjectType;
  bytesB64: string;
}

export interface DecodedBundle {
  objects: BundleObject[];
}

/** Encode several signed objects as one scannable payload (e.g. TCert + attestation). */
export function encodeBundle(objects: BundleObject[]): string {
  const json = JSON.stringify({ v: TRANSFER_VERSION, objects });
  const b64 = toBase64Url(new TextEncoder().encode(json));
  return `${TRANSFER_SCHEME}://${TRANSFER_VERSION}/bundle/${b64}`;
}

/** Parse a bundle payload. Returns `null` when the payload is not a bundle. */
export function decodeBundle(payload: string): DecodedBundle | null {
  const prefix = `${TRANSFER_SCHEME}://${TRANSFER_VERSION}/bundle/`;
  if (!payload.startsWith(prefix)) return null;
  const b64 = payload.slice(prefix.length);
  try {
    const json = JSON.parse(new TextDecoder().decode(fromBase64Url(b64))) as {
      v?: string;
      objects?: unknown;
    };
    if (!Array.isArray(json.objects)) return null;
    const objects: BundleObject[] = [];
    for (const o of json.objects as Array<Record<string, unknown>>) {
      if (!o || typeof o.type !== 'string' || typeof o.bytesB64 !== 'string') continue;
      const type = o.type as TransferObjectType;
      if (type !== 'tcert' && type !== 'sdoc' && type !== 'statement') continue;
      objects.push({ type, bytesB64: o.bytesB64 });
    }
    return { objects };
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/* `.qrs` file container                                                        */
/* -------------------------------------------------------------------------- */

/**
 * File extension used for QRS export files (a plain-text container whose content
 * is exactly a transfer payload — `qrs://v1/<type>/<base64url>` or a bundle).
 * This lets a user save a TCert / SDoc / Statement to a `.qrs` file, share it
 * out-of-band (WhatsApp, email, USB), and have the receiver import it by feeding
 * the file text straight through `processPayload`.
 */
export const QRS_FILE_EXTENSION = 'qrs';

/** Build the UTF-8 bytes of a `.qrs` file holding a single signed object. */
export function encodeQrsFile(type: TransferObjectType, bytesB64: string): Uint8Array {
  return new TextEncoder().encode(encodeTransferPayload(type, bytesB64));
}

/** Build the UTF-8 bytes of a `.qrs` file holding a bundle of signed objects. */
export function encodeQrsBundleFile(objects: BundleObject[]): Uint8Array {
  return new TextEncoder().encode(encodeBundle(objects));
}

export type DecodedQrsFile =
  | { kind: 'object'; payload: DecodedTransferPayload }
  | { kind: 'bundle'; objects: BundleObject[] };

/** Parse the text content of a `.qrs` file back into an object or a bundle. */
export function decodeQrsFile(text: string): DecodedQrsFile | null {
  const trimmed = text.trim();
  if (!trimmed) return null;
  const bundle = decodeBundle(trimmed);
  if (bundle) return { kind: 'bundle', objects: bundle.objects };
  const payload = decodeTransferPayload(trimmed);
  if (payload) return { kind: 'object', payload };
  return null;
}
