import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createQrs, toBase64Url } from 'qrs-core';
import { OnlineService } from '../src/main/online.js';
import { syncTcert } from '../src/main/sync.js';
import type { DesktopRuntime } from '../src/main/runtime.js';

type Responder = (init?: RequestInit) => { status: number; body: unknown };

function mockServer(routes: Record<string, Responder>): void {
  vi.stubGlobal(
    'fetch',
    async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? 'GET').toUpperCase();
      const key = `${method} ${url}`;
      const responder = routes[key] ?? routes[url] ?? routes['*'];
      if (!responder) throw new Error(`unhandled fetch: ${key}`);
      const { status, body } = responder(init);
      return { ok: status >= 200 && status < 300, status, json: async () => body } as unknown as Response;
    }
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

function tempOnline(): OnlineService {
  return new OnlineService(mkdtempSync(join(tmpdir(), 'qrs-online-')));
}

describe('OnlineService submitObject / uploadPending', () => {
  it('uploads immediately when the signer has an online_endpoint', async () => {
    const online = tempOnline();
    mockServer({
      'POST http://srv/api/tcerts/key1/challenge/': () => ({ status: 200, body: { nonce: 'n', difficulty: 4 } }),
      'POST http://srv/api/tcerts/key1/token/': () => ({ status: 200, body: { token: 'tok' } }),
      'POST http://srv/api/cas/ca1%3A1/statements/': () => ({ status: 201, body: { ok: true } }),
    });

    const res = await online.submitObject({
      keyId: 'key1',
      caTcertId: 'ca1:1',
      onlineEndpoints: ['http://srv/'],
      kind: 'statement',
      id: 'st1',
      bytesB64: toBase64Url(new TextEncoder().encode('signed-statement')),
    });
    expect(res.queued).toBe(false);
    expect(online.pendingCount()).toBe(0);
    expect(online.readObject('statement', 'st1')).not.toBeNull();
  });

  it('returns the server rejection reason for a failed attachment upload', async () => {
    const online = tempOnline();
    mockServer({
      'POST http://srv/api/tcerts/key1/challenge/': () => ({ status: 200, body: { nonce: 'n', difficulty: 4 } }),
      'POST http://srv/api/tcerts/key1/token/': () => ({ status: 200, body: { token: 'tok' } }),
      'POST http://srv/api/attachments/': () => ({
        status: 403,
        body: { error: 'TCert is not a trusted CA nor attested by one on this server' },
      }),
    });

    const res = await online.submitRawAttachment({
      keyId: 'key1',
      tcertId: 'key1:1',
      fieldName: 'photo',
      onlineEndpoints: ['http://srv'],
      hash: 'a'.repeat(32),
      size: 3,
      contentB64: toBase64Url(new TextEncoder().encode('raw')),
    });

    expect(res.queued).toBe(true);
    expect(res.error).toContain('TCert is not a trusted CA nor attested by one on this server');
  });

  it('fans out to every endpoint and queues only the unreachable mirror', async () => {
    const online = tempOnline();
    mockServer({
      // Mirror A is down (challenge fails) → that entry is queued.
      'POST http://a/api/tcerts/key1/challenge/': () => ({ status: 500, body: {} }),
      // Mirror B is up → uploaded immediately.
      'POST http://b/api/tcerts/key1/challenge/': () => ({ status: 200, body: { nonce: 'n', difficulty: 4 } }),
      'POST http://b/api/tcerts/key1/token/': () => ({ status: 200, body: { token: 'tok' } }),
      'POST http://b/api/cas/ca1%3A1/statements/': () => ({ status: 201, body: { ok: true } }),
    });

    const res = await online.submitObject({
      keyId: 'key1',
      caTcertId: 'ca1:1',
      onlineEndpoints: ['http://a', 'http://b'],
      kind: 'statement',
      id: 'st3',
      bytesB64: toBase64Url(new TextEncoder().encode('signed')),
    });
    expect(res.queued).toBe(true);
    expect(online.pendingCount()).toBe(1);
    expect(online.listQueue()).toEqual([{ keyId: 'key1', caTcertId: 'ca1:1', onlineEndpoint: 'http://a', kind: 'statement', id: 'st3' }]);

    // Mirror A comes back: uploadPending flushes the remaining entry.
    mockServer({
      'POST http://a/api/tcerts/key1/challenge/': () => ({ status: 200, body: { nonce: 'n', difficulty: 4 } }),
      'POST http://a/api/tcerts/key1/token/': () => ({ status: 200, body: { token: 'tok' } }),
      'POST http://a/api/cas/ca1%3A1/statements/': () => ({ status: 201, body: { ok: true } }),
    });
    const { uploaded, pending } = await online.uploadPending();
    expect(uploaded).toBe(1);
    expect(pending).toBe(0);
  });

  it('stores locally without queuing when there is no endpoint', async () => {
    const online = tempOnline();
    const res = await online.submitObject({
      keyId: 'key1',
      kind: 'attachment',
      id: 'att1',
      bytesB64: toBase64Url(new TextEncoder().encode('bytes')),
    });
    expect(res.queued).toBe(false);
    expect(online.pendingCount()).toBe(0);
    expect(online.readObject('attachment', 'att1')).not.toBeNull();
  });

  it('queues when the server is unreachable, then flushes on sync', async () => {
    const online = tempOnline();
    // First submit: server is down → queued.
    mockServer({
      'POST http://srv/api/tcerts/key1/challenge/': () => ({ status: 500, body: {} }),
    });
    const res = await online.submitObject({
      keyId: 'key1',
      caTcertId: 'ca1:1',
      onlineEndpoints: ['http://srv'],
      kind: 'statement',
      id: 'st2',
      bytesB64: toBase64Url(new TextEncoder().encode('x')),
    });
    expect(res.queued).toBe(true);
    expect(online.pendingCount()).toBe(1);

    // Server comes back: uploadPending flushes it.
    mockServer({
      'POST http://srv/api/tcerts/key1/challenge/': () => ({ status: 200, body: { nonce: 'n', difficulty: 4 } }),
      'POST http://srv/api/tcerts/key1/token/': () => ({ status: 200, body: { token: 'tok' } }),
      'POST http://srv/api/cas/ca1%3A1/statements/': () => ({ status: 201, body: { ok: true } }),
    });
    const { uploaded, pending } = await online.uploadPending();
    expect(uploaded).toBe(1);
    expect(pending).toBe(0);
  });

  it('flushes queued attachments during a CA-scoped sync', async () => {
    const online = tempOnline();
    const endpoint = 'http://attachment-ca-srv';
    mockServer({
      [`POST ${endpoint}/api/tcerts/key-attachment/challenge/`]: () => ({ status: 500, body: {} }),
    });
    await online.submitRawAttachment({
      keyId: 'key-attachment',
      tcertId: 'target:1',
      fieldName: 'photo',
      onlineEndpoints: [endpoint],
      hash: 'b'.repeat(32),
      size: 3,
      contentB64: toBase64Url(new TextEncoder().encode('raw')),
    });
    expect(online.pendingCount()).toBe(1);

    mockServer({
      [`POST ${endpoint}/api/tcerts/key-attachment/challenge/`]: () => ({ status: 200, body: { nonce: 'n', difficulty: 4 } }),
      [`POST ${endpoint}/api/tcerts/key-attachment/token/`]: () => ({ status: 200, body: { token: 'tok' } }),
      [`POST ${endpoint}/api/attachments/`]: () => ({ status: 201, body: { ok: true } }),
    });
    const result = await online.uploadPending(endpoint, 'ca:1');
    expect(result.uploaded).toBe(1);
    expect(result.pending).toBe(0);
  });
});

describe('syncTcert (CA-scoped sync) download + apply', () => {
  it('downloads hosted TCerts and applies signed statements', async () => {
    // Issuer side: a CA with an online endpoint revokes a target cert.
    const issuer = createQrs();
    const ca = await issuer.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'CA',
      fields: [],
      onlineEndpoint: 'http://srv',
    });
    await issuer.trust.addCa(ca.tcertId);
    const target = await issuer.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'CA',
      fields: [],
      keyId: ca.keyId,
    });
    const rev = await issuer.revocation.revokeTcert({
      signerKeyId: ca.keyId,
      targetTcertId: target.tcertId,
      type: 'prospective',
      reason: 'compromised',
    });

    // Verifier side: trusts the CA (its online_endpoint) but not the revocation.
    const verifier = createQrs();
    await verifier.online.importTcert(ca.bytes);
    await verifier.trust.addCa(ca.tcertId);

    mockServer({
      [`POST http://srv/api/cas/${encodeURIComponent(ca.tcertId)}/sync/`]: () => ({
        status: 200,
        body: {
          tcerts: [{ keyId: ca.keyId, tcertId: ca.tcertId, bytesB64: toBase64Url(ca.bytes) }],
          objects: [{ type: 'statement', statementId: rev.statementId, bytesB64: toBase64Url(rev.bytes) }],
        },
      }),
    });

    const fakeRt = { qrs: verifier, context: null, dataDir: '' } as unknown as DesktopRuntime;
    const result = await syncTcert(fakeRt, ca.tcertId, tempOnline());

    expect(result.downloaded).toBe(2); // 1 tcert + 1 statement
    expect(result.applied).toBe(1);
    const entry = await verifier.deps.revocationStore.getRevokedTcert(target.tcertId);
    expect(entry?.reason).toBe('compromised');
  });

  it('does not apply a statement signed by an unknown signer', async () => {
    // A statement signed by an unknown key is fetched from the synced CA's
    // endpoint; the verifier holds the synced CA cert but NOT the signer's.
    const issuer = createQrs();
    const signer = await issuer.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'I',
      fields: [],
    });
    const target = await issuer.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'I',
      fields: [],
      keyId: signer.keyId,
    });
    const rev = await issuer.revocation.revokeTcert({
      signerKeyId: signer.keyId,
      targetTcertId: target.tcertId,
      type: 'prospective',
    });

    // Verifier trusts a CA that is configured for the endpoint, but the CA is NOT
    // the signer of the statement.
    const verifier = createQrs();
    const ca = await verifier.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'CA',
      fields: [],
      onlineEndpoint: 'http://srv',
    });
    await verifier.trust.addCa(ca.tcertId);

    mockServer({
      [`POST http://srv/api/cas/${encodeURIComponent(ca.tcertId)}/sync/`]: () => ({
        status: 200,
        body: {
          tcerts: [],
          objects: [{ type: 'statement', statementId: rev.statementId, bytesB64: toBase64Url(rev.bytes) }],
        },
      }),
    });

    const fakeRt = { qrs: verifier, context: null, dataDir: '' } as unknown as DesktopRuntime;
    const result = await syncTcert(fakeRt, ca.tcertId, tempOnline());
    // The statement's signer is unknown locally → not applied, reported as an error.
    expect(result.applied).toBe(0);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('uploads a queued CA attestation during CA-scoped sync', async () => {
    // Issuer creates a CA (with endpoint) and attests a target; the attestation is
    // queued (e.g. the server was briefly unreachable).
    const issuer = createQrs();
    const ca = await issuer.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'CA',
      fields: [],
      onlineEndpoint: 'http://srv',
    });
    await issuer.trust.addCa(ca.tcertId);
    const target = await issuer.certificates.createTcert({ algorithm: 'Ed25519', name: 'CA', fields: [], keyId: ca.keyId });
    const att = await issuer.trust.attest({ caTcertId: ca.tcertId, targetTcertId: target.tcertId });

    // Queue the attestation (CA enrollments use submitAttestation which needs a
    // token + the attestations endpoint).
    const online = tempOnline();
    await online.submitAttestation({
      caTcertId: ca.tcertId,
      caKeyId: ca.keyId,
      targetTcertB64: toBase64Url(target.bytes),
      attestationB64: toBase64Url(att.bytes),
      onlineEndpoints: ['http://srv'],
    });

    // Sync flushes the queued enrollment(s): token + attestations + pull.
    mockServer({
      [`POST http://srv/api/tcerts/${ca.keyId}/challenge/`]: () => ({ status: 200, body: { nonce: 'n', difficulty: 4 } }),
      [`POST http://srv/api/tcerts/${ca.keyId}/token/`]: () => ({ status: 200, body: { token: 'tok' } }),
      [`POST http://srv/api/cas/${encodeURIComponent(ca.tcertId)}/attestations/`]: () => ({ status: 201, body: { ok: true } }),
      [`POST http://srv/api/cas/${encodeURIComponent(ca.tcertId)}/sync/`]: () => ({ status: 200, body: { tcerts: [], objects: [] } }),
    });

    const fakeRt = { qrs: issuer, context: null, dataDir: '' } as unknown as DesktopRuntime;
    const result = await syncTcert(fakeRt, ca.tcertId, online);
    expect(result.uploaded).toBeGreaterThan(0);
    expect(online.pendingCount()).toBe(0);
  });
});
