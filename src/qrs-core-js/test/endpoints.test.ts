/**
 * EndpointService + IEndpointConfigStore + verification mirror fallback.
 *
 * Endpoints are app-level distribution convenience (NOT protocol): the signed
 * `onlineEndpoint` is the fixed default and additional mirrors are stored
 * app-locally. Verification tries the effective list in order.
 */
import { describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFileStores } from '../src/storage/fileStores.js';
import { InMemoryEndpointConfigStore } from '../src/storage/memoryStores.js';
import { normalizeEndpoint } from '../src/services/endpointService.js';
import { makeRuntime } from './helpers.js';

describe('normalizeEndpoint', () => {
  it('trims and strips trailing slashes', () => {
    expect(normalizeEndpoint('  http://a.example/  ')).toBe('http://a.example');
    expect(normalizeEndpoint('http://a.example///')).toBe('http://a.example');
  });
});

describe('IEndpointConfigStore implementations', () => {
  it('in-memory store adds/removes/sets with dedup', async () => {
    const s = new InMemoryEndpointConfigStore();
    expect(await s.getEndpoints('k:1')).toEqual([]);
    await s.addEndpoint('k:1', 'http://a.example');
    await s.addEndpoint('k:1', 'http://a.example'); // dedup
    await s.addEndpoint('k:1', 'http://b.example');
    expect(await s.getEndpoints('k:1')).toEqual(['http://a.example', 'http://b.example']);
    expect(await s.getEndpoints('k:2')).toEqual([]);
    await s.removeEndpoint('k:1', 'http://a.example');
    expect(await s.getEndpoints('k:1')).toEqual(['http://b.example']);
    await s.setEndpoints('k:1', ['http://x.example', 'http://x.example']);
    expect(await s.getEndpoints('k:1')).toEqual(['http://x.example']);
  });

  it('file store persists across instances', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'qrs-endpoints-'));
    try {
      const a = createFileStores(dir);
      await a.endpointConfigStore.addEndpoint('k:9', 'http://a.example');
      await a.endpointConfigStore.addEndpoint('k:9', 'http://b.example');
      // Fresh instance reads the same backing file.
      const b = createFileStores(dir);
      expect(await b.endpointConfigStore.getEndpoints('k:9')).toEqual(['http://a.example', 'http://b.example']);
      await b.endpointConfigStore.removeEndpoint('k:9', 'http://a.example');
      // A fresh instance re-reads the persisted file (instances don't share a cache).
      const c = createFileStores(dir);
      expect(await c.endpointConfigStore.getEndpoints('k:9')).toEqual(['http://b.example']);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('EndpointService.effectiveEndpoints', () => {
  it('returns [] when the TCert has no default and no mirrors', async () => {
    const rt = makeRuntime();
    const tcert = await rt.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [{ type: 'text', name: 'n', label: 'N' }],
    });
    expect(await rt.endpoints.effectiveEndpoints(tcert.tcertId)).toEqual([]);
  });

  it('falls back to the attesting CA endpoint when the TCert has none', async () => {
    const rt = makeRuntime();
    const ca = await rt.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'CA',
      fields: [],
      onlineEndpoint: 'http://ca.example/',
    });
    await rt.trust.addCa(ca.tcertId);
    // Target has NO endpoint — it is attested by the CA.
    const target = await rt.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'Target',
      fields: [{ type: 'text', name: 'n', label: 'N' }],
    });
    await rt.trust.attest({ caTcertId: ca.tcertId, targetTcertId: target.tcertId });

    expect(await rt.endpoints.effectiveEndpoints(target.tcertId)).toEqual(['http://ca.example']);
    // The CA itself keeps its own endpoint.
    expect(await rt.endpoints.effectiveEndpoints(ca.tcertId)).toEqual(['http://ca.example']);
  });

  it('prefers its own endpoints over the CA fallback', async () => {
    const rt = makeRuntime();
    const ca = await rt.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'CA',
      fields: [],
      onlineEndpoint: 'http://ca.example',
    });
    await rt.trust.addCa(ca.tcertId);
    const target = await rt.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'Target',
      fields: [{ type: 'text', name: 'n', label: 'N' }],
      onlineEndpoint: 'http://own.example',
    });
    await rt.trust.attest({ caTcertId: ca.tcertId, targetTcertId: target.tcertId });

    expect(await rt.endpoints.effectiveEndpoints(target.tcertId)).toEqual(['http://own.example']);
  });

  it('returns the signed default first, then mirrors (dedup, normalized)', async () => {
    const rt = makeRuntime();
    const tcert = await rt.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [{ type: 'text', name: 'n', label: 'N' }],
      onlineEndpoint: 'http://default.example/',
    });
    await rt.endpoints.addMirror(tcert.tcertId, 'http://mirror.example//');
    await rt.endpoints.addMirror(tcert.tcertId, 'http://default.example/'); // same as default -> dedup
    await rt.endpoints.addMirror(tcert.tcertId, 'http://other.example');
    expect(await rt.endpoints.effectiveEndpoints(tcert.tcertId)).toEqual([
      'http://default.example',
      'http://mirror.example',
      'http://other.example',
    ]);
    // listMirrors returns exactly what was configured (effectiveEndpoints dedups against the default).
    expect(await rt.endpoints.listMirrors(tcert.tcertId)).toEqual([
      'http://mirror.example',
      'http://default.example',
      'http://other.example',
    ]);
  });

  it('add/remove/set mirrors mutate the effective list', async () => {
    const rt = makeRuntime();
    const tcert = await rt.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'AFDA',
      fields: [{ type: 'text', name: 'n', label: 'N' }],
    });
    expect(await rt.endpoints.effectiveEndpoints(tcert.tcertId)).toEqual([]);
    await rt.endpoints.addMirror(tcert.tcertId, 'http://a.example');
    await rt.endpoints.addMirror(tcert.tcertId, 'http://b.example');
    expect(await rt.endpoints.effectiveEndpoints(tcert.tcertId)).toEqual(['http://a.example', 'http://b.example']);
    await rt.endpoints.removeMirror(tcert.tcertId, 'http://a.example');
    expect(await rt.endpoints.effectiveEndpoints(tcert.tcertId)).toEqual(['http://b.example']);
    await rt.endpoints.setMirrors(tcert.tcertId, ['http://c.example']);
    expect(await rt.endpoints.effectiveEndpoints(tcert.tcertId)).toEqual(['http://c.example']);
  });
});

describe('EndpointService.effectiveEndpoints (CA fallback)', () => {
  it('falls back to the attesting CA endpoint when the TCert has none', async () => {
    const rt = makeRuntime();
    const ca = await rt.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'CA',
      fields: [],
      onlineEndpoint: 'http://ca.example/',
    });
    await rt.trust.addCa(ca.tcertId);
    const target = await rt.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'Target',
      fields: [{ type: 'text', name: 'n', label: 'N' }],
    });
    await rt.trust.attest({ caTcertId: ca.tcertId, targetTcertId: target.tcertId });
    expect(await rt.endpoints.effectiveEndpoints(target.tcertId)).toEqual(['http://ca.example']);
  });
});

