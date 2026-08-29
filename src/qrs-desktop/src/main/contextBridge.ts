/**
 * Desktop context provider.
 *
 * The qrs-core verification pipeline never touches the platform: it asks an
 * `IContextProvider` for whatever it needs (location, secrets, online objects).
 * This provider forwards location/secret requests to the renderer over IPC, where
 * a small dialog asks the user, and resolves when the renderer replies. It is
 * fully unit-testable because the window reference is injected.
 *
 * Attachment objects (signed objects referenced by a content-addressed hash) are
 * resolved here: first from the local attachments store (where the issuer keeps
 * the signed objects it created), then from the TCert's `online_endpoint` if the
 * local copy is absent. The fetched object is *not* trusted — the verification
 * pipeline verifies its signature and hash binding.
 */
import { adaptProvider, type GeoPoint, type IContextProvider } from 'qrs-core';
import { app, type BrowserWindow } from 'electron';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fromBase64Url } from 'qrs-core';
import type { FieldSchema } from 'qrs-core';
import { IPC, type ContextReply } from '../shared/types.js';

const REQUEST_TIMEOUT_MS = 5 * 60 * 1000; // give the user up to 5 minutes per prompt

/** What the provider may ask the renderer for (requestId is generated internally). */
type ContextRequestInput =
  | { kind: 'location'; label: string }
  | { kind: 'secret'; label: string; name: string };

export interface ContextWindowProvider {
  (): BrowserWindow | null;
}

export class DesktopContextProvider implements IContextProvider {
  private readonly pending = new Map<
    string,
    { resolve: (value: unknown) => void; timer: NodeJS.Timeout }
  >();
  private nextRequestId = 1;

  constructor(private readonly getWindow: ContextWindowProvider) {}

  getCurrentTime(): number {
    return Math.floor(Date.now() / 1000);
  }

  async requestLocation(field?: FieldSchema): Promise<GeoPoint | null> {
    const value = await this.ask({
      kind: 'location',
      label: field?.label ?? 'Location',
    });
    if (!value || typeof value !== 'object') return null;
    const { lat, lon } = value as { lat: number; lon: number };
    if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
    return { lat, lon };
  }

  async requestSecret(field: FieldSchema): Promise<string | null> {
    const value = await this.ask({ kind: 'secret', label: field.label, name: field.name });
    return typeof value === 'string' && value.length > 0 ? value : null;
  }

  /** Fetch a signed attachment object: local store first, then each distribution mirror in order. */
  async requestObject(id: string, _field?: FieldSchema, onlineEndpoints?: string | string[]): Promise<Uint8Array | null> {
    const local = this.localObject(id);
    if (local) return local;
    const list = Array.isArray(onlineEndpoints) ? onlineEndpoints : onlineEndpoints ? [onlineEndpoints] : [];
    for (const ep of list) {
      try {
        const base = ep.replace(/\/+$/, '');
        const res = await fetch(`${base}/api/attachments/${id}/`);
        if (!res.ok) continue;
        const body = (await res.json()) as { bytesB64?: string };
        if (body.bytesB64) return fromBase64Url(body.bytesB64);
      } catch {
        /* try the next mirror */
      }
    }
    return null;
  }

  buildContext() {
    return adaptProvider(this);
  }

  /** Handle a renderer reply (registered via ipcMain). */
  reply(reply: ContextReply): void {
    const entry = this.pending.get(reply.requestId);
    if (!entry) return;
    clearTimeout(entry.timer);
    this.pending.delete(reply.requestId);
    entry.resolve(reply.value);
  }

  /** Resolve everything as cancelled (e.g. window closed). */
  cancelAll(): void {
    for (const entry of this.pending.values()) {
      clearTimeout(entry.timer);
      entry.resolve(null);
    }
    this.pending.clear();
  }

  /** Read a signed attachment object from the local objects store, if present. */
  private localObject(id: string): Uint8Array | null {
    try {
      const safe = id.replace(/[^a-zA-Z0-9._-]/g, '_');
      const userData = app.getPath('userData');
      // New store layout (round 5+): <userData>/objects/attachment/<id>
      const candidates = [
        join(userData, 'objects', 'attachment', safe),
        // Legacy layout kept for data created before the objects store existed.
        join(userData, 'attachments', safe),
      ];
      for (const file of candidates) {
        try {
          if (!existsSync(file)) continue;
          return new Uint8Array(readFileSync(file));
        } catch {
          /* try next */
        }
      }
    } catch {
      /* no user data dir available (e.g. tests) */
    }
    return null;
  }

  private ask(req: ContextRequestInput): Promise<unknown> {
    const win = this.getWindow();
    if (!win || win.isDestroyed() || win.webContents.isDestroyed()) return Promise.resolve(null);
    const requestId = String(this.nextRequestId++);
    return new Promise<unknown>((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(requestId);
        resolve(null);
      }, REQUEST_TIMEOUT_MS);
      this.pending.set(requestId, { resolve, timer });
      win.webContents.send(IPC.context.request, { ...req, requestId });
    });
  }
}
