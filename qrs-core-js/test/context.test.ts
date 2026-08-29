import { describe, expect, it } from 'vitest';
import { DummyContextProvider } from '../src/context/dummyContext.js';

describe('DummyContextProvider', () => {
  it('exposes configured time, location, secrets and objects through the adapter', async () => {
    const obj = new Uint8Array([1, 2, 3]);
    const provider = new DummyContextProvider({
      time: 123,
      location: { lat: 34.55, lon: 69.2 },
      secrets: { pin: 's3cret' },
      objects: { 'o': obj },
    });

    expect(provider.getCurrentTime()).toBe(123);
    expect(await provider.requestLocation()).toEqual({ lat: 34.55, lon: 69.2 });
    expect(await provider.requestSecret({ type: 'secretInput', name: 'pin', label: 'PIN' })).toBe('s3cret');
    expect(await provider.requestSecret({ type: 'secretInput', name: 'nope', label: 'N' })).toBeNull();
    expect(await provider.requestObject('o')).toEqual(obj);
    expect(await provider.requestObject('missing')).toBeNull();

    const ctx = provider.buildContext();
    expect(ctx.getCurrentTime()).toBe(123);
    expect(await ctx.getSecret('pin')).toBe('s3cret');
    expect(await ctx.getLocation()).toEqual({ lat: 34.55, lon: 69.2 });
    expect(await ctx.getObject('o')).toEqual(obj);
  });

  it('defaults to the current time, null location and empty collections', async () => {
    const provider = new DummyContextProvider();
    expect(provider.getCurrentTime()).toBeGreaterThan(1_000_000_000);
    expect(await provider.requestLocation()).toBeNull();
    expect(await provider.requestObject('x')).toBeNull();
    expect(await provider.requestSecret({ type: 'secretInput', name: 'p', label: 'P' })).toBeNull();
  });
});
