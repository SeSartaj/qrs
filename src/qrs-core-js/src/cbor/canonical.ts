/**
 * Canonical (deterministic) CBOR encoding and decoding for the protocol profile.
 *
 * Rules (RFC 8949 §4.2.1 "Core Deterministic Encoding Requirements"):
 *   - definite-length items only (never indefinite);
 *   - integers encoded in the shortest possible form;
 *   - string lengths in the shortest possible form;
 *   - map keys sorted in bytewise lexicographic order of their encoded form;
 *   - floats are NOT produced (regulated decimals use canonical strings instead);
 *   - text strings are UTF-8; map keys are compared by their encoded bytes.
 *
 * Maps that use only text keys decode back to plain objects (convenient for the
 * protocol data structures). Maps with integer keys (e.g. COSE protected headers)
 * decode to a `Map`. Encoding accepts both plain objects and `Map` instances.
 */
import { QrsParseError, QrsUnsupportedError } from '../errors.js';
import { uint8ToBigInt } from '../id.js';

export type CborKey = number | bigint | string;
export type CborMap = Map<CborKey, CborValue>;
export type CborValue =
  | null
  | boolean
  | number
  | bigint
  | string
  | Uint8Array
  | CborValue[]
  | CborMap
  | { [key: string]: CborValue };

const MT_UINT = 0;
const MT_NINT = 1;
const MT_BYTES = 2;
const MT_TEXT = 3;
const MT_ARRAY = 4;
const MT_MAP = 5;
const MT_TAG = 6;
const MT_SIMPLE = 7;

/* -------------------------------------------------------------------------- */
/* Encoding                                                                   */
/* -------------------------------------------------------------------------- */

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((acc, p) => acc + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function encodeHead(major: number, value: bigint): Uint8Array {
  const initial = major << 5;
  if (value < 0n || value > 0xffffffffffffffffn) {
    throw new QrsParseError('Integer out of CBOR range');
  }
  if (value < 24n) return Uint8Array.of(initial | Number(value));
  if (value <= 0xffn) return Uint8Array.of(initial | 24, Number(value));
  if (value <= 0xffffn) {
    const v = Number(value);
    return Uint8Array.of(initial | 25, (v >> 8) & 0xff, v & 0xff);
  }
  if (value <= 0xffffffffn) {
    const v = Number(value);
    return Uint8Array.of(initial | 26, (v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
  }
  const out = new Uint8Array(9);
  out[0] = initial | 27;
  let v = value;
  for (let i = 8; i >= 1; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function encodeInt(value: bigint): Uint8Array {
  if (value >= 0n) return encodeHead(MT_UINT, value);
  return encodeHead(MT_NINT, -value - 1n);
}

function encodeValue(value: CborValue): Uint8Array {
  if (value === null || value === undefined) return Uint8Array.of(0xf6);
  if (value === true) return Uint8Array.of(0xf5);
  if (value === false) return Uint8Array.of(0xf4);
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || !Number.isSafeInteger(value)) {
      throw new QrsParseError(
        'Floating point values are not allowed by the canonical profile; use integers or canonical decimal strings'
      );
    }
    return encodeInt(BigInt(value));
  }
  if (typeof value === 'bigint') return encodeInt(value);
  if (typeof value === 'string') {
    const bytes = new TextEncoder().encode(value);
    return concat(encodeHead(MT_TEXT, BigInt(bytes.length)), bytes);
  }
  if (value instanceof Uint8Array) {
    return concat(encodeHead(MT_BYTES, BigInt(value.length)), value);
  }
  if (Array.isArray(value)) {
    const parts: Uint8Array[] = [encodeHead(MT_ARRAY, BigInt(value.length))];
    for (const item of value) parts.push(encodeValue(item));
    return concat(...parts);
  }
  if (value instanceof Map) {
    const entries: Array<{ keyBytes: Uint8Array; valBytes: Uint8Array }> = [];
    for (const [k, v] of value) {
      entries.push({ keyBytes: encodeValue(k as CborValue), valBytes: encodeValue(v) });
    }
    return encodeMap(entries);
  }
  if (typeof value === 'object') {
    const entries: Array<{ keyBytes: Uint8Array; valBytes: Uint8Array }> = [];
    for (const [k, v] of Object.entries(value)) {
      entries.push({ keyBytes: encodeValue(k), valBytes: encodeValue(v) });
    }
    return encodeMap(entries);
  }
  throw new QrsUnsupportedError('Unsupported CBOR value type');
}

function encodeMap(entries: Array<{ keyBytes: Uint8Array; valBytes: Uint8Array }>): Uint8Array {
  entries.sort((a, b) => compareBytes(a.keyBytes, b.keyBytes));
  const parts: Uint8Array[] = [encodeHead(MT_MAP, BigInt(entries.length))];
  for (const e of entries) {
    parts.push(e.keyBytes, e.valBytes);
  }
  return concat(...parts);
}

export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return (a[i] ?? 0) - (b[i] ?? 0);
  }
  return a.length - b.length;
}

/** Deterministically encode a value to canonical CBOR bytes. */
export function cborEncode(value: CborValue): Uint8Array {
  return encodeValue(value);
}

/* -------------------------------------------------------------------------- */
/* Decoding                                                                   */
/* -------------------------------------------------------------------------- */

class Decoder {
  private pos = 0;
  constructor(private readonly bytes: Uint8Array) {}

  private readByte(): number {
    if (this.pos >= this.bytes.length) throw new QrsParseError('Unexpected end of CBOR input');
    return this.bytes[this.pos++] ?? 0;
  }

  private readBytes(n: number): Uint8Array {
    if (this.pos + n > this.bytes.length) throw new QrsParseError('Unexpected end of CBOR input');
    const out = this.bytes.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  private readHead(): { major: number; info: number; value: bigint } {
    const b = this.readByte();
    const major = b >> 5;
    const info = b & 0x1f;
    // Simple values 25/26/27 are floats: their payload bytes are consumed by
    // decodeFloat, not interpreted as an integer argument here.
    if (major === 7 && (info === 25 || info === 26 || info === 27)) {
      return { major, info, value: 0n };
    }
    if (info < 24) return { major, info, value: BigInt(info) };
    if (info === 24) return { major, info, value: BigInt(this.readByte()) };
    if (info === 25) {
      const [a, b2] = this.readBytes(2);
      return { major, info, value: BigInt(((a ?? 0) << 8) | (b2 ?? 0)) };
    }
    if (info === 26) {
      const [a, b2, c, d] = this.readBytes(4);
      return {
        major,
        info,
        value: BigInt(((a ?? 0) << 24) | ((b2 ?? 0) << 16) | ((c ?? 0) << 8) | (d ?? 0)),
      };
    }
    if (info === 27) {
      return { major, info, value: uint8ToBigInt(this.readBytes(8)) };
    }
    throw new QrsParseError('Indefinite-length items are not supported by the canonical profile');
  }

  private decodeFloat(initial: number, info: number): number {
    if (info === 25) {
      const [a, b] = this.readBytes(2);
      const bits = ((a ?? 0) << 8) | (b ?? 0);
      const sign = bits >> 15 ? -1 : 1;
      const exp = (bits >> 10) & 0x1f;
      const frac = bits & 0x3ff;
      if (exp === 0) return sign * 2 ** -14 * (frac / 1024);
      if (exp === 31) return frac ? NaN : sign * Infinity;
      return sign * 2 ** (exp - 15) * (1 + frac / 1024);
    }
    if (info === 26) {
      const buf = new DataView(this.readBytes(4).buffer);
      return buf.getFloat32(0, false);
    }
    if (info === 27) {
      const buf = new DataView(this.readBytes(8).buffer);
      return buf.getFloat64(0, false);
    }
    throw new QrsParseError('Unsupported simple value');
  }

  readValue(): CborValue {
    const { major, info, value } = this.readHead();
    switch (major) {
      case MT_UINT:
        return toJsNumber(value);
      case MT_NINT:
        return toJsNumber(-1n - value);
      case MT_BYTES:
        return this.readBytes(Number(value));
      case MT_TEXT: {
        const raw = this.readBytes(Number(value));
        return new TextDecoder().decode(raw);
      }
      case MT_ARRAY: {
        const out: CborValue[] = [];
        for (let i = 0; i < Number(value); i++) out.push(this.readValue());
        return out;
      }
      case MT_MAP: {
        const entries: Array<[CborKey, CborValue]> = [];
        for (let i = 0; i < Number(value); i++) {
          const k = this.readValue();
          const v = this.readValue();
          entries.push([toCborKey(k), v]);
        }
        return toCborMap(entries);
      }
      case MT_TAG: {
        // The protocol profile does not use tags; unwrap and return the inner value.
        return this.readValue();
      }
      case MT_SIMPLE: {
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        if (info === 23) return undefined as unknown as null;
        if (info === 25 || info === 26 || info === 27) return this.decodeFloat(0, info);
        throw new QrsParseError(`Unsupported simple value ${info}`);
      }
      default:
        throw new QrsUnsupportedError(`Unsupported CBOR major type ${major}`);
    }
  }

  atEnd(): boolean {
    return this.pos >= this.bytes.length;
  }
}

function toJsNumber(value: bigint): number | bigint {
  if (value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(value);
  }
  return value;
}

function toCborKey(value: CborValue): CborKey {
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'bigint') return value;
  throw new QrsParseError('CBOR map keys must be integers or text strings');
}

function toCborMap(entries: Array<[CborKey, CborValue]>): CborMap | { [key: string]: CborValue } {
  const allStrings = entries.every(([k]) => typeof k === 'string');
  if (allStrings) {
    const obj: { [key: string]: CborValue } = {};
    for (const [k, v] of entries) obj[k as string] = v;
    return obj;
  }
  return new Map(entries);
}

/** Decode canonical CBOR bytes back into a value. */
export function cborDecode(bytes: Uint8Array): CborValue {
  const decoder = new Decoder(bytes);
  const value = decoder.readValue();
  if (!decoder.atEnd()) throw new QrsParseError('Trailing bytes after CBOR value');
  return value;
}

/** Convenience for code that needs a decoded map (protocol data). */
export function decodeMap(bytes: Uint8Array): CborMap | { [key: string]: CborValue } {
  const value = cborDecode(bytes);
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    value instanceof Uint8Array
  ) {
    throw new QrsParseError('Expected a CBOR map');
  }
  return value;
}
