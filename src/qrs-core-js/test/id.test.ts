import { describe, expect, it } from 'vitest';
import {
  fromBase64Url,
  fromHex,
  randomBytes,
  randomId,
  sha256,
  toBase64Url,
  toHex,
  truncSha256,
} from '../src/id.js';
import { QrsError, QrsParseError } from '../src/errors.js';

function bytesOf(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

describe('portable SHA-256', () => {
  it('matches the RFC 6234 test vectors', () => {
    // 'abc' and empty string digests are well-known.
    expect(toHex(sha256(bytesOf('')))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    );
    expect(toHex(sha256(bytesOf('abc')))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
  });

  it('is deterministic and avalanche-sensitive', () => {
    const a = sha256(bytesOf('hello'));
    const b = sha256(bytesOf('hello'));
    const c = sha256(bytesOf('hellp'));
    expect(a).toEqual(b);
    expect(a).not.toEqual(c);
    expect(a.length).toBe(32);
  });

  it('handles multi-block input', () => {
    const long = bytesOf('a'.repeat(1_000_000));
    // sha256 of 1,000,000 'a' characters (known value)
    expect(toHex(sha256(long))).toBe('cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0');
  });

  it('truncSha256 returns the requested length', () => {
    expect(truncSha256(bytesOf('x'), 16).length).toBe(16);
    expect(truncSha256(bytesOf('x'), 16)).toEqual(sha256(bytesOf('x')).slice(0, 16));
  });
});

describe('portable hex/base64url encoding', () => {
  it('round-trips hex', () => {
    const bytes = new Uint8Array([0x00, 0x0f, 0xff, 0x10]);
    expect(toHex(bytes)).toBe('000fff10');
    expect(fromHex('000FFF10')).toEqual(bytes);
    expect(() => fromHex('xyz')).toThrow(QrsParseError);
    expect(() => fromHex('0')).toThrow(QrsParseError);
  });

  it('round-trips base64url', () => {
    const bytes = bytesOf('hello world');
    const encoded = toBase64Url(bytes);
    expect(encoded).toBe('aGVsbG8gd29ybGQ');
    expect(fromBase64Url(encoded)).toEqual(bytes);
    // With padding chars that would appear in standard base64
    const raw = new Uint8Array([0xfb, 0xff, 0xff]);
    expect(fromBase64Url(toBase64Url(raw))).toEqual(raw);
  });
});

describe('portable secure random', () => {
  it('produces distinct random identifiers of the right length', () => {
    const a = randomId();
    const b = randomId();
    expect(a).toMatch(/^[0-9a-f]{32}$/);
    expect(a).not.toBe(b);
    expect(randomId(8)).toMatch(/^[0-9a-f]{16}$/);
  });

  it('produces random bytes of the requested length', () => {
    expect(randomBytes(32).length).toBe(32);
    const a = randomBytes(32);
    const b = randomBytes(32);
    expect(a).not.toEqual(b);
  });

  it('throws when there is no secure random source', () => {
    const original = globalThis.crypto;
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    try {
      // @ts-expect-error - temporarily remove the global for this assertion
      delete globalThis.crypto;
      expect(() => randomBytes(4)).toThrow(QrsError);
    } finally {
      if (descriptor) Object.defineProperty(globalThis, 'crypto', descriptor);
      else (globalThis as Record<string, unknown>).crypto = original;
    }
  });
});
