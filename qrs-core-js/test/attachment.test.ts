import { describe, expect, it } from 'vitest';
import { QrsParseError } from '../src/errors.js';
import { fromHex, sha384, sha3_512, toHex } from '../src/id.js';
import {
  ATTACHMENT_ID_HEX,
  attachmentIdOf,
  buildAttachment,
  parseAttachment,
  verifyAttachment,
} from '../src/services/attachment.js';
import { makeRuntime } from './helpers.js';

describe('attachments (independent signed objects)', () => {
  it('builds an attachment whose id is the truncated content hash', async () => {
    const runtime = makeRuntime();
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [{ type: 'attachment', name: 'photo', label: 'Photo', inputRules: { contentType: 'image/png' } }],
    });

    const content = new TextEncoder().encode('png-bytes-123');
    const built = await buildAttachment(
      { keyId: tcert.keyId, contentType: 'image/png', content, issuedAt: 1_700_000_000 },
      runtime.deps
    );
    expect(built.contentHash).toMatch(/^[0-9a-f]{64}$/);
    expect(built.attachmentId).toBe(attachmentIdOf(built.contentHash));
    expect(built.attachmentId).toHaveLength(ATTACHMENT_ID_HEX);
    expect(built.parsed.type).toBe('attachment');
    expect(built.parsed.signerKeyId).toBe(tcert.keyId);
  });

  it('infers the TCert-declared hash algorithm (SHA-384)', async () => {
    const runtime = makeRuntime();
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [{ type: 'attachment', name: 'photo', label: 'Photo', inputRules: { contentType: 'image/png' } }],
      hashAlgorithm: 'SHA-384',
    });
    const content = new TextEncoder().encode('png-bytes-123');
    const built = await buildAttachment({ keyId: tcert.keyId, contentType: 'image/png', content }, runtime.deps);
    expect(built.contentHash).toMatch(/^[0-9a-f]{96}$/); // sha384 = 96 hex chars
    expect(built.contentHash).toBe(toHex(sha384(content)));
    expect(built.attachmentId).toBe(attachmentIdOf(built.contentHash));
  });

  it('supports an explicit SHA3-512 hash algorithm', async () => {
    const runtime = makeRuntime();
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [{ type: 'attachment', name: 'photo', label: 'Photo', inputRules: { contentType: 'image/png' } }],
    });
    const content = new TextEncoder().encode('png-bytes-123');
    const built = await buildAttachment(
      { keyId: tcert.keyId, contentType: 'image/png', content, hashAlgorithm: 'SHA3-512' },
      runtime.deps
    );
    expect(built.contentHash).toMatch(/^[0-9a-f]{128}$/); // sha3-512 = 128 hex chars
    expect(built.contentHash).toBe(toHex(sha3_512(content)));
  });

  it('parses the attachment and recovers its fields', async () => {
    const runtime = makeRuntime();
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'X',
      fields: [],
    });
    const content = new TextEncoder().encode('hello attachment');
    const built = await buildAttachment({ keyId: tcert.keyId, contentType: 'application/octet-stream', content }, runtime.deps);

    const parsed = parseAttachment(built.bytes);
    expect(parsed.attachmentId).toBe(built.attachmentId);
    expect(parsed.contentType).toBe('application/octet-stream');
    expect(parsed.contentHash).toBe(built.contentHash);
    expect(parsed.content).toEqual(content);
    expect(parsed.issuedAt).toBe(runtime.deps.clock.now());
    expect(parsed.signerKeyId).toBe(tcert.keyId);
  });

  it('verifies the attachment signature with the issuing public key', async () => {
    const runtime = makeRuntime();
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'X',
      fields: [],
    });
    const built = await buildAttachment({ keyId: tcert.keyId, contentType: 'text/plain', content: new TextEncoder().encode('x') }, runtime.deps);
    const parsed = parseAttachment(built.bytes);
    const provider = runtime.deps.cryptoRegistry.get(tcert.parsed.algorithm);
    const pubRec = await runtime.deps.publicKeyStore.load(tcert.keyId);
    expect(pubRec).toBeTruthy();
    expect(await verifyAttachment(parsed.parsed, pubRec!.publicJwk, provider)).toBe(true);
  });

  it('rejects non-attachment objects', async () => {
    const runtime = makeRuntime();
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'X',
      fields: [],
    });
    const built = await buildAttachment({ keyId: tcert.keyId, contentType: 'text/plain', content: new TextEncoder().encode('x') }, runtime.deps);
    expect(() => parseAttachment(fromHex('00'))).toThrow(QrsParseError);
    expect(() => parseAttachment(built.bytes)).not.toThrow();
  });
});
