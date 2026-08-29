/**
 * Attachment fetching for the mobile verifier.
 *
 * Attachments are RAW files stored on the distribution server, referenced in the
 * SDoc by a hash string (no signed object). Verification never downloads the
 * file — this module fetches only metadata (size + contentType) for display, and
 * the file body on demand when the user taps Download/Open.
 */
import { fromBase64Url, verifyAttachmentReference, type AttachmentReference, type QrsRuntime } from 'qrs-core';
import { baseUrl } from './sync';

export interface AttachmentMeta {
  id: string;
  contentType: string;
  contentHash: string;
  size?: number;
}

export interface RawAttachment extends AttachmentMeta {
  content: Uint8Array;
}

/** Fetch the raw file body (base64url) by hash, trying each endpoint in order. */
export async function fetchAttachmentContent(
  qrs: QrsRuntime,
  reference: AttachmentReference,
  contentType: string,
  endpoints: string[]
): Promise<RawAttachment | null> {
  const id = reference;
  for (const ep of endpoints) {
    try {
      const res = await fetch(`${baseUrl(ep)}/api/attachments/${id}/?content=1`);
      if (!res.ok) continue;
      const body = (await res.json()) as {
        id?: string;
        contentType?: string;
        contentHash?: string;
        size?: number;
        contentB64?: string;
      };
      if (!body.contentB64) continue;
      const content = fromBase64Url(body.contentB64);
      if (!verifyAttachmentReference(reference, content)) continue;
      return {
        id: body.id ?? id,
        contentType,
        contentHash: body.contentHash ?? id,
        size: body.size ?? content.byteLength,
        content,
      };
    } catch {
      /* try the next mirror */
    }
  }
  return null;
}

/** A `data:<contentType>;base64,...` URI for inline rendering on web/native. */
export function attachmentDataUri(contentType: string, content: Uint8Array): string {
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < content.length; i += CHUNK) {
    bin += String.fromCharCode(...content.subarray(i, i + CHUNK));
  }
  return `data:${contentType};base64,${btoa(bin)}`;
}

/** A short file extension for a content type (for the saved file name). */
export function extFor(contentType: string): string {
  const map: Record<string, string> = {
    'application/pdf': 'pdf',
    'image/png': 'png',
    'image/jpeg': 'jpg',
    'image/webp': 'webp',
    'text/plain': 'txt',
    'application/json': 'json',
    'application/octet-stream': 'bin',
  };
  return map[contentType.toLowerCase()] ?? 'bin';
}

/** Human-readable size (e.g. "1.2 MB"). */
export function fmtSize(bytes?: number): string {
  if (bytes === undefined) return '…';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
