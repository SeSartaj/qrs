import { describe, expect, it, vi } from 'vitest';
import type { IContextProvider } from '../src/context/context.js';
import { createQrs } from '../src/runtime.js';
import { InMemoryPrivateKeyStore } from '../src/storage/memoryStores.js';
import { FixedClock } from './helpers.js';

describe('runtime IoC', () => {
  it('defaults to in-memory storage and a dummy (non-prompting) context', async () => {
    const runtime = createQrs();
    expect(await runtime.deps.privateKeyStore.all()).toEqual([]);
    expect(await runtime.deps.certificateStore.all()).toEqual([]);
    expect(await runtime.deps.documentStore.all()).toEqual([]);
  });

  it('uses an injected private key store instead of the default', async () => {
    const privateKeyStore = new InMemoryPrivateKeyStore();
    const spy = vi.spyOn(privateKeyStore, 'save');
    const runtime = createQrs({ privateKeyStore });
    await runtime.certificates.generateKeyPair('Ed25519');
    expect(spy).toHaveBeenCalled();
  });

  it('uses an injected context provider for secrets during verification', async () => {
    let requests = 0;
    const contextProvider: IContextProvider = {
      getCurrentTime: () => 1_700_000_000,
      requestLocation: async () => null,
      requestSecret: async () => {
        requests++;
        return 'provider-secret';
      },
      requestObject: async () => null,
      buildContext() {
        return {
          getCurrentTime: () => 1_700_000_000,
          getLocation: async () => null,
          getSecret: async () => 'provider-secret',
          getObject: async () => null,
        };
      },
    };

    const runtime = createQrs({ contextProvider, clock: new FixedClock(1_700_000_000) });
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'X',
      fields: [{ type: 'secretInput', name: 'pin', label: 'PIN' }],
    });
    await runtime.trust.pin(tcert.tcertId);
    const issued = await runtime.signing.issueSdoc({
      tcertId: tcert.tcertId,
      issuedAt: 1_700_000_000,
      values: { pin: 'provider-secret' },
    });
    const result = await runtime.verification.verify(issued.bytes);
    expect(result.overall).toBe('valid');
    expect(requests).toBe(1);
  });

  it('uses an injected clock for issuance and verification timestamps', async () => {
    const clock = new FixedClock(42);
    const runtime = createQrs({ clock });
    const tcert = await runtime.certificates.createTcert({
      algorithm: 'Ed25519',
      name: 'X',
      fields: [{ type: 'text', name: 'v', label: 'V' }],
    });
    await runtime.trust.pin(tcert.tcertId);
    const issued = await runtime.signing.issueSdoc({ tcertId: tcert.tcertId, values: { v: 'x' } });
    expect(issued.issuedAt).toBe(42);
    const result = await runtime.verification.verify(issued.bytes);
    expect(result.overall).toBe('valid');
  });
});
