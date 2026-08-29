/**
 * Attachment helpers for the main process: fetch a RAW attachment (stored by
 * content hash) from a distribution mirror and hand the content to the OS.
 */
import { dialog, shell } from 'electron';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { app } from 'electron';
import { attachmentReference, toBase64Url, verifyAttachmentReference } from 'qrs-core';
import { getOnlineService } from './online.js';

/**
 * Fetch a RAW attachment from a mirror. Returns metadata by default ({ id,
 * contentType, size, contentHash }); pass `content=true` to also fetch the file
 * body as raw bytes. The returned `contentB64` is only the local IPC payload
 * used to hand verified bytes to the Electron renderer/OS.
 */
export async function fetchRawAttachment(
  id: string,
  _expectedSize: number | undefined,
  contentType: string,
  onlineEndpoints?: string | string[],
  content = false
): Promise<{ id: string; contentType: string; size: number; contentHash: string; contentB64?: string } | null | undefined> {
  const online = getOnlineService();
  const local = online.readObject('attachment', id);
  const list = Array.isArray(onlineEndpoints) ? onlineEndpoints : onlineEndpoints ? [onlineEndpoints] : [];
  if (content && local) {
    try {
      if (!verifyAttachmentReference(id, local)) return null;
      return { id, contentType, size: local.byteLength, contentHash: attachmentReference(local), contentB64: toBase64Url(local) };
    } catch {
      return null;
    }
  }
  for (const ep of list) {
    try {
      const base = ep.replace(/\/+$/, '');
      const suffix = content ? '?content=1' : '';
      const res = await fetch(`${base}/api/attachments/${id}/${suffix}`);
      if (!res.ok) continue;
      if (content) {
        const downloaded = new Uint8Array(await res.arrayBuffer());
        if (!verifyAttachmentReference(id, downloaded)) continue;
        const encoded = toBase64Url(downloaded);
        online.storeObject('attachment', id, encoded);
        return { id, contentType, size: downloaded.byteLength, contentHash: attachmentReference(downloaded), contentB64: encoded };
      }
      const body = (await res.json()) as { id?: string; contentType?: string; size?: number; contentHash?: string };
      return {
        id: body.id ?? id,
        contentType,
        size: body.size ?? 0,
        contentHash: body.contentHash ?? id,
      };
    } catch {
      /* try the next mirror */
    }
  }
  return undefined;
}

const EXTENSIONS: Record<string, string> = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/gif': 'gif',
  'image/webp': 'webp',
  'image/svg+xml': 'svg',
  'application/pdf': 'pdf',
  'text/plain': 'txt',
  'text/csv': 'csv',
  'application/json': 'json',
  'application/zip': 'zip',
  'application/octet-stream': 'bin',
};

export function extensionFor(contentType: string): string {
  return EXTENSIONS[contentType] ?? 'bin';
}

export function fileNameFor(id: string, contentType: string): string {
  return `${id.slice(0, 16)}.${extensionFor(contentType)}`;
}

/** Write bytes to a temp file and open it with the OS default application. */
export async function openWithDefaultApp(bytesB64: string, fileName: string): Promise<{ opened: boolean; error?: string }> {
  try {
    const dir = join(app.getPath('temp'), 'qrs-attachments');
    mkdirSync(dir, { recursive: true });
    const file = join(dir, fileName.replace(/[^a-zA-Z0-9._-]/g, '_'));
    writeFileSync(file, Buffer.from(bytesB64, 'base64'));
    const error = await shell.openPath(file);
    return error ? { opened: false, error } : { opened: true };
  } catch (error) {
    return { opened: false, error: error instanceof Error ? error.message : String(error) };
  }
}

/** Show a native save dialog and write the file. */
export async function saveFile(
  bytesB64: string,
  contentType: string,
  defaultName: string
): Promise<{ saved: boolean; path?: string; error?: string }> {
  try {
    const filters = [{ name: contentType, extensions: [extensionFor(contentType)] }];
    const result = await dialog.showSaveDialog({ defaultPath: defaultName, filters });
    if (result.canceled || !result.filePath) return { saved: false };
    writeFileSync(result.filePath, Buffer.from(bytesB64, 'base64'));
    return { saved: true, path: result.filePath };
  } catch (error) {
    return { saved: false, error: error instanceof Error ? error.message : String(error) };
  }
}
