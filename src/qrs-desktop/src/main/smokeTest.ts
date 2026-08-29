/**
 * Self-test that runs the full issuer flow through the real desktop runtime
 * (file-backed stores) and prints a compact JSON result. Enabled with
 * `QRS_SMOKE_TEST=1`; useful for CI / headless verification.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { crc32, deflateSync } from 'node:zlib';
import { app } from 'electron';
import type { DesktopRuntime } from './runtime.js';
import { decodeObject } from './objects.js';
import { summarizeDocument, summarizeTcert } from './summaries.js';
import { attachmentReference, parseSignedObject, toBase64Url } from 'qrs-core';

const YEAR = 31_536_000;

function storedAttachmentShape(v: unknown): unknown {
  return v;
}

function isAttachmentHash(v: unknown, hash: string): boolean {
  return typeof v === 'object' && v !== null && (v as { hash?: unknown }).hash === hash;
}

function isAttachmentSize(v: unknown, size: number): boolean {
  return typeof v === 'object' && v !== null && (v as { size?: unknown }).size === size;
}

/** Build a solid-color PNG (width x height) so smoke screenshots show a real image. */
function solidPng(width: number, height: number, rgb: [number, number, number]): Uint8Array {
  const raw = Buffer.alloc(height * (1 + width * 3));
  for (let y = 0; y < height; y++) {
    const row = y * (1 + width * 3);
    raw[row] = 0; // filter: none
    for (let x = 0; x < width; x++) {
      const i = row + 1 + x * 3;
      raw[i] = rgb[0];
      raw[i + 1] = rgb[1];
      raw[i + 2] = rgb[2];
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // color type: truecolor
  const chunk = (type: string, data: Buffer): Buffer => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length, 0);
    const typeBuf = Buffer.from(type, 'ascii');
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
    return Buffer.concat([len, typeBuf, data, crc]);
  };
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  return new Uint8Array(
    Buffer.concat([sig, chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))])
  );
}

export async function runSmokeTest(rt: DesktopRuntime): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const tcert = await rt.qrs.certificates.createTcert({
    algorithm: 'Ed25519',
    name: 'Smoke Test Issuer',
    fields: [
      { type: 'text', name: 'name', label: 'Name', inputRules: { required: true } },
      { type: 'location', name: 'location', label: 'Location', verifyRules: { maxRadius: 5000 } },
      { type: 'secretInput', name: 'pin', label: 'PIN', binding: 'stripped' },
      { type: 'attachment', name: 'photo', label: 'Photo', inputRules: { contentType: 'image/png' } },
    ],
    validAfter: now,
    validBefore: now + 5 * YEAR,
    onlineEndpoint: 'http://127.0.0.1:8765',
  });
  await rt.qrs.trust.pin(tcert.tcertId);

  // Build a raw attachment file, store it on disk keyed by its sha256 hash, and
  // reference it in the SDoc via { hash, size } (offline-first, no signed object).
  const photoBytes = solidPng(256, 120, [52, 152, 219]); // a blue 256x120 png
  const photoHash = attachmentReference(photoBytes);
  const attDir = join(app.getPath('userData'), 'attachments');
  mkdirSync(attDir, { recursive: true });
  writeFileSync(join(attDir, photoHash), photoBytes);

  const issued = await rt.qrs.signing.issueSdoc({
    tcertId: tcert.tcertId,
    values: {
      name: 'Ahmad Pharmacy',
      location: { lat: 34.5553, lon: 69.2075 },
      pin: '1234',
      photo: { hash: photoHash, size: photoBytes.byteLength },
    },
  });

  const tcertDto = await summarizeTcert(rt.qrs, tcert.bytes);
  const sdocDto = await summarizeDocument(rt.qrs, issued.bytes);
  const decoded = await decodeObject(toBase64Url(tcert.bytes));

  const storedAttachment = (parseSignedObject(issued.bytes).data.fields as unknown[])[3];

  const result = {
    tcert: {
      tcertId: tcertDto.tcertId,
      name: tcertDto.name,
      fields: tcertDto.fields.map((f) => f.name),
      pinned: tcertDto.pinned,
      validity: tcertDto.validity,
    },
    sdoc: {
      sdocId: sdocDto.sdocId,
      sizeBytes: sdocDto.sizeBytes,
      documentName: sdocDto.documentName,
      values: sdocDto.values,
    },
    attachment: {
      storedInSdoc: storedAttachmentShape(storedAttachment),
      hashMatches: isAttachmentHash(storedAttachment, photoHash),
      sizeMatches: isAttachmentSize(storedAttachment, photoBytes.byteLength),
      rawFileBytes: photoBytes.byteLength,
    },
    decodedStructure: {
      type: decoded.type,
      id: decoded.id,
      topLevelKeys: Object.keys(decoded.data as Record<string, unknown>),
    },
  };
  console.log('QRS_SMOKE_RESULT ' + JSON.stringify(result, null, 2));
}
