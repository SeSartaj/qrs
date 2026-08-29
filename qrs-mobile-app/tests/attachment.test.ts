import { afterEach, describe, expect, it, vi } from 'vitest';
import { attachmentReference } from 'qrs-core';
import { fetchAttachmentContent, fetchAttachmentMetadata } from '../lib/attachment';

afterEach(() => vi.unstubAllGlobals());

describe('mobile attachment transport', () => {
  it('fetches and validates metadata from the attachment endpoint', async () => {
    const reference = 'a'.repeat(32);
    const fetchMock = vi.fn(async (url: string) => {
      expect(url).toBe(`https://qr.afda.gov.af/api/attachments/${reference}/`);
      return {
        ok: true,
        json: async () => ({ id: reference, contentType: 'image/png', contentHash: `${reference}${'b'.repeat(32)}`, size: 9216 }),
      } as unknown as Response;
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(fetchAttachmentMetadata(reference, 'image/*', ['https://qr.afda.gov.af/'])).resolves.toEqual({
      id: reference,
      contentType: 'image/png',
      contentHash: `${reference}${'b'.repeat(32)}`,
      size: 9216,
    });
  });

  it('downloads raw content and rejects bytes with the wrong hash', async () => {
    const content = new Uint8Array([137, 80, 78, 71, 1, 2, 3]);
    const reference = attachmentReference(content);
    const fetchMock = vi.fn(async (url: string) => {
      expect(url).toBe(`https://qr.afda.gov.af/api/attachments/${reference}/?content=1`);
      return { ok: true, arrayBuffer: async () => content.buffer } as unknown as Response;
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await fetchAttachmentContent({} as never, reference, 'image/png', ['https://qr.afda.gov.af']);
    expect(result).toMatchObject({ id: reference, contentType: 'image/png', size: content.byteLength });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
