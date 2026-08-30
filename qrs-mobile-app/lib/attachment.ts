/**
 * Attachment fetching for the mobile verifier.
 *
 * Attachments are RAW files stored on the distribution server, referenced in the
 * SDoc by a hash string (no signed object). Verification never downloads the
 * file — this module fetches metadata for display and raw bytes when an image
 * preview or an explicit Download/Open action needs them.
 */
import { attachmentReference, verifyAttachmentReference, type AttachmentReference, type QrsRuntime } from 'qrs-core';
import { baseUrl } from './sync';

const ATTACHMENT_REQUEST_TIMEOUT_MS = 8_000;

async function fetchWithTimeout(url: string): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), ATTACHMENT_REQUEST_TIMEOUT_MS);
  try {
    return await fetch(url, { signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

export interface AttachmentMeta {
  id: string;
  contentType: string;
  contentHash: string;
  size?: number;
}

export interface RawAttachment extends AttachmentMeta {
  content: Uint8Array;
}
export interface AttachmentFetchFailure { error: 'unavailable' | 'corrupt'; }

/** One per-endpoint attempt result, for debugging "attachment unavailable". */
export interface AttachmentDiagnostic {
  endpoint: string;
  url: string;
  ok: boolean;
  status?: number;
  detail: string;
}

/** Collect per-endpoint diagnostics while fetching. */
export interface AttachmentFetchOptions {
  onDiagnostic?: (d: AttachmentDiagnostic) => void;
}

/** Fetch attachment metadata without downloading the file body. */
export async function fetchAttachmentMetadata(
  reference: AttachmentReference,
  fallbackContentType: string,
  endpoints: string[],
  opts?: AttachmentFetchOptions
): Promise<AttachmentMeta | null> {
  for (const ep of endpoints) {
    const url = `${baseUrl(ep)}/api/attachments/${reference}/`;
    try {
      const res = await fetchWithTimeout(url);
      if (!res.ok) {
        opts?.onDiagnostic?.({ endpoint: ep, url, ok: false, status: res.status, detail: `HTTP ${res.status}` });
        continue;
      }
      const body = (await res.json()) as {
        id?: string;
        contentType?: string;
        contentHash?: string;
        hash?: string;
        size?: number;
      };
      const contentHash = body.contentHash ?? body.hash;
      if (body.id && body.id.toLowerCase() !== reference.toLowerCase()) {
        opts?.onDiagnostic?.({ endpoint: ep, url, ok: true, status: res.status, detail: `id mismatch: ${body.id}` });
        continue;
      }
      if (contentHash && contentHash.slice(0, reference.length).toLowerCase() !== reference.toLowerCase()) {
        opts?.onDiagnostic?.({ endpoint: ep, url, ok: true, status: res.status, detail: `hash mismatch: ${contentHash.slice(0, 12)}…` });
        continue;
      }
      opts?.onDiagnostic?.({ endpoint: ep, url, ok: true, status: res.status, detail: `ok (${body.contentType ?? fallbackContentType}, ${body.size ?? '?'}B)` });
      return {
        id: body.id ?? reference,
        contentType: body.contentType || fallbackContentType,
        contentHash: contentHash ?? reference,
        size: typeof body.size === 'number' ? body.size : undefined,
      };
    } catch (e) {
      opts?.onDiagnostic?.({ endpoint: ep, url, ok: false, detail: `network error: ${e instanceof Error ? e.message : String(e)}` });
      /* try the next mirror */
    }
  }
  return null;
}

/** Fetch the raw file body (base64url) by hash, trying each endpoint in order. */
export async function fetchAttachmentContent(
  qrs: QrsRuntime,
  reference: AttachmentReference,
  contentType: string,
  endpoints: string[],
  opts?: AttachmentFetchOptions
): Promise<RawAttachment | AttachmentFetchFailure | null> {
  const id = reference;
  let corrupt = false;
  for (const ep of endpoints) {
    const url = `${baseUrl(ep)}/api/attachments/${id}/?content=1`;
    try {
      const res = await fetchWithTimeout(url);
      if (!res.ok) {
        opts?.onDiagnostic?.({ endpoint: ep, url, ok: false, status: res.status, detail: `HTTP ${res.status}` });
        continue;
      }
      const content = new Uint8Array(await res.arrayBuffer());
      if (!verifyAttachmentReference(reference, content)) {
        corrupt = true;
        opts?.onDiagnostic?.({ endpoint: ep, url, ok: true, status: res.status, detail: `hash mismatch (${content.byteLength}B)` });
        continue;
      }
      opts?.onDiagnostic?.({ endpoint: ep, url, ok: true, status: res.status, detail: `ok (${content.byteLength}B)` });
      return {
        id,
        contentType,
        contentHash: attachmentReference(content),
        size: content.byteLength,
        content,
      };
    } catch (e) {
      opts?.onDiagnostic?.({ endpoint: ep, url, ok: false, detail: `network error: ${e instanceof Error ? e.message : String(e)}` });
      /* try the next mirror */
    }
  }
  return corrupt ? { error: 'corrupt' } : null;
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
