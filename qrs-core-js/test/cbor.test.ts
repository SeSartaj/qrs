import { describe, expect, it } from 'vitest';
import { cborDecode, cborEncode, compareBytes, decodeMap, type CborValue } from '../src/cbor/canonical.js';
import { QrsParseError } from '../src/errors.js';

describe('canonical CBOR', () => {
  it('encodes RFC 8949 integer/string/array/map vectors', () => {
    const vectors: Array<[unknown, string]> = [
      [0, '00'],
      [1, '01'],
      [10, '0a'],
      [23, '17'],
      [24, '1818'],
      [100, '1864'],
      [-1, '20'],
      [-10, '29'],
      [-100, '3863'],
      ['', '60'],
      ['a', '6161'],
      ['IETF', '6449455446'],
      [[], '80'],
      [[1, 2, 3], '83010203'],
      [{}, 'a0'],
      [true, 'f5'],
      [false, 'f4'],
      [null, 'f6'],
      [new Uint8Array([]), '40'],
      [new Uint8Array([1, 2]), '420102'],
    ];
    for (const [value, hex] of vectors) {
      expect(Buffer.from(cborEncode(value as never)).toString('hex')).toBe(hex);
    }
  });

  it('encodes maps with sorted keys (deterministic) regardless of insertion order', () => {
    const a = cborEncode({ b: 2, a: 1, c: 3 });
    const b = cborEncode({ c: 3, a: 1, b: 2 });
    expect(a).toEqual(b);
    // keys sorted by encoded bytes: "a" < "b" < "c"
    expect(Buffer.from(a).toString('hex')).toBe('a3616101616202616303');
  });

  it('round-trips nested structures', () => {
    const value = {
      name: 'Ahmad Pharmacy',
      category: 'category_1',
      numbers: [1, 2, 3],
      nested: { x: 1, y: 'z' },
      bytes: new Uint8Array([0, 1, 2, 255]),
      flag: true,
      nothing: null,
    };
    const decoded = cborDecode(cborEncode(value));
    expect(decoded).toEqual(value);
  });

  it('round-trips big integers', () => {
    const big = 9_000_000_000_000_000_000n;
    const decoded = cborDecode(cborEncode(big));
    expect(decoded).toBe(big);
  });

  it('rejects floating point values in the canonical profile', () => {
    expect(() => cborEncode(12.5 as never)).toThrow(QrsParseError);
  });

  it('rejects indefinite-length items on decode', () => {
    // 0x9f (indefinite array) 0x01 0xff
    expect(() => cborDecode(new Uint8Array([0x9f, 0x01, 0xff]))).toThrow(QrsParseError);
  });

  it('rejects trailing bytes', () => {
    expect(() => cborDecode(new Uint8Array([0x01, 0x02]))).toThrow(QrsParseError);
  });

  it('decodes integer maps to Map and text maps to object', () => {
    const intMap = cborDecode(cborEncode(new Map<number, CborValue>([[1, 'a'], [2, 'b']])));
    expect(intMap).toBeInstanceOf(Map);
    expect((intMap as Map<number, CborValue>).get(1)).toBe('a');

    const textMap = cborDecode(cborEncode({ hello: 'world' }));
    expect(textMap).toEqual({ hello: 'world' });
  });

  it('compareBytes orders bytewise', () => {
    expect(compareBytes(new Uint8Array([1]), new Uint8Array([2]))).toBeLessThan(0);
    expect(compareBytes(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBeLessThan(0);
    expect(compareBytes(new Uint8Array([1, 2]), new Uint8Array([1]))).toBeGreaterThan(0);
    expect(compareBytes(new Uint8Array([1]), new Uint8Array([1]))).toBe(0);
  });

  it('does not produce duplicate encodings for the same semantic value', () => {
    expect(cborEncode({ a: 1, b: 2 })).toEqual(cborEncode({ b: 2, a: 1 }));
  });

  it('decodes floats for robustness (even though the profile never encodes them)', () => {
    // 1.5 as float64 (0xfb 3ff8000000000000), float32 (0xfa 3fc00000), float16 (0xf9 3e00)
    expect(cborDecode(new Uint8Array([0xfb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0]))).toBe(1.5);
    expect(cborDecode(new Uint8Array([0xfa, 0x3f, 0xc0, 0, 0]))).toBe(1.5);
    expect(cborDecode(new Uint8Array([0xf9, 0x3e, 0x00]))).toBe(1.5);
  });

  it('decodeMap returns the decoded map or throws for non-maps', () => {
    expect(decodeMap(cborEncode({ a: 1 }))).toEqual({ a: 1 });
    expect(() => decodeMap(cborEncode(42))).toThrow(QrsParseError);
    expect(() => decodeMap(cborEncode([1, 2]))).toThrow(QrsParseError);
  });
});
