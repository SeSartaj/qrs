import { describe, expect, it, vi } from 'vitest';
import type { BrowserWindow } from 'electron';
import { DesktopContextProvider } from '../src/main/contextBridge.js';
import type { ContextRequest } from '../src/shared/types.js';

function makeFakeWindow() {
  const sent: ContextRequest[] = [];
  const webContents = {
    isDestroyed: () => false,
    send: (_channel: string, req: ContextRequest) => {
      sent.push(req);
    },
  };
  const win = { isDestroyed: () => false, webContents };
  return { win, sent };
}

describe('DesktopContextProvider', () => {
  it('requests a location and resolves with the renderer reply', async () => {
    const { win, sent } = makeFakeWindow();
    const ctx = new DesktopContextProvider(() => win as unknown as BrowserWindow);

    const promise = ctx.requestLocation();
    await vi.waitFor(() => expect(sent.length).toBe(1));
    const req = sent[0];
    expect(req.kind).toBe('location');

    ctx.reply({ requestId: req.requestId, value: { lat: 34.5553, lon: 69.2075 } });
    await expect(promise).resolves.toEqual({ lat: 34.5553, lon: 69.2075 });
  });

  it('requests a secret and resolves with the string reply', async () => {
    const { win, sent } = makeFakeWindow();
    const ctx = new DesktopContextProvider(() => win as unknown as BrowserWindow);

    const promise = ctx.requestSecret({ type: 'secretInput', name: 'pass', label: 'Passcode' });
    await vi.waitFor(() => expect(sent.length).toBe(1));
    const req = sent[0];
    expect(req).toMatchObject({ kind: 'secret', name: 'pass', label: 'Passcode' });

    ctx.reply({ requestId: req.requestId, value: 's3cret' });
    await expect(promise).resolves.toBe('s3cret');
  });

  it('returns null when the window is gone (no prompt possible)', async () => {
    const ctx = new DesktopContextProvider(() => null);
    await expect(ctx.requestLocation()).resolves.toBeNull();
    await expect(ctx.requestSecret({ type: 'secretInput', name: 'x', label: 'X' })).resolves.toBeNull();
  });

  it('cancelAll resolves pending prompts as null', async () => {
    const { win, sent } = makeFakeWindow();
    const ctx = new DesktopContextProvider(() => win as unknown as BrowserWindow);

    const promise = ctx.requestLocation();
    await vi.waitFor(() => expect(sent.length).toBe(1));
    ctx.cancelAll();
    await expect(promise).resolves.toBeNull();
  });

  it('ignores replies for unknown request ids', async () => {
    const { win } = makeFakeWindow();
    const ctx = new DesktopContextProvider(() => win as unknown as BrowserWindow);
    expect(() => ctx.reply({ requestId: 'nope', value: null })).not.toThrow();
  });

  it('fetches a signed attachment object from the online endpoint by id', async () => {
    const bytesB64 = Buffer.from('signed-object-bytes').toString('base64url');
    const fetchMock = vi.fn(async (url: string) => {
      expect(url).toBe('http://srv.test/api/attachments/abcd1234/');
      return { ok: true, json: async () => ({ bytesB64 }) };
    });
    vi.stubGlobal('fetch', fetchMock);
    try {
      const ctx = new DesktopContextProvider(() => null);
      const got = await ctx.requestObject('abcd1234', undefined, 'http://srv.test/');
      expect(got).toEqual(new Uint8Array(Buffer.from('signed-object-bytes')));
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('returns null when the object is not available locally or remotely', async () => {
    const fetchMock = vi.fn(async () => ({ ok: false }));
    vi.stubGlobal('fetch', fetchMock);
    try {
      const ctx = new DesktopContextProvider(() => null);
      await expect(ctx.requestObject('abcd1234', undefined, 'http://srv.test/')).resolves.toBeNull();
      await expect(ctx.requestObject('abcd1234')).resolves.toBeNull(); // no endpoint at all
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
