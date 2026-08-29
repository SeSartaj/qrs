import { beforeEach, describe, expect, it, vi } from 'vitest';

// A mutable answer the mocked readline returns for the next prompt.
let mockAnswer = '';
vi.mock('node:readline/promises', () => ({
  createInterface: () => ({
    question: vi.fn(async () => mockAnswer),
    close: vi.fn(),
    on: vi.fn(),
    once: vi.fn(),
    off: vi.fn(),
  }),
}));

import { TerminalContextProvider } from '../src/context/terminalContext.js';
import type { FieldSchema } from '../src/fields/types.js';

describe('TerminalContextProvider', () => {
  beforeEach(() => {
    mockAnswer = '';
  });

  it('parses a location answer', async () => {
    mockAnswer = '34.5553, 69.2075';
    const provider = new TerminalContextProvider();
    expect(await provider.requestLocation()).toEqual({ lat: 34.5553, lon: 69.2075 });
  });

  it('returns null when the location answer is empty or malformed', async () => {
    const provider = new TerminalContextProvider();
    mockAnswer = '';
    expect(await provider.requestLocation()).toBeNull();
    mockAnswer = 'not a location';
    expect(await provider.requestLocation()).toBeNull();
    mockAnswer = '34.5';
    expect(await provider.requestLocation()).toBeNull();
  });

  it('returns the entered secret or null when empty', async () => {
    const field: FieldSchema = { type: 'secretInput', name: 'owner_passcode', label: 'Owner Passcode' };
    const provider = new TerminalContextProvider();
    mockAnswer = 's3cret';
    expect(await provider.requestSecret(field)).toBe('s3cret');
    mockAnswer = '';
    expect(await provider.requestSecret(field)).toBeNull();
  });

  it('has no offline object source', async () => {
    expect(await new TerminalContextProvider().requestObject('any')).toBeNull();
  });

  it('exposes the current time and builds a working verification context', async () => {
    const provider = new TerminalContextProvider();
    expect(provider.getCurrentTime()).toBeGreaterThan(1_000_000_000);
    const ctx = provider.buildContext();
    expect(typeof ctx.getCurrentTime()).toBe('number');
    mockAnswer = '';
    expect(await ctx.getLocation()).toBeNull();
  });
});
