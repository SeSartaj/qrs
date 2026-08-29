import { describe, expect, it } from 'vitest';
import { adaptProvider } from '../src/context/context.js';
import {
  AttachmentField,
  attachmentContentType,
  attachmentReference,
  verifyAttachmentReference,
} from '../src/fields/attachmentField.js';
import { DateField } from '../src/fields/dateField.js';
import { DateTimeField } from '../src/fields/datetimeField.js';
import { DatetimeEpochField } from '../src/fields/datetimeEpochField.js';
import { createDefaultFieldRegistry } from '../src/fields/index.js';
import { LocationField, haversineDistance } from '../src/fields/locationField.js';
import { NumberField, canonicalDecimalString } from '../src/fields/numberField.js';
import { SecretInputField } from '../src/fields/secretInputField.js';
import { SelectField } from '../src/fields/selectField.js';
import { SelectV2Field } from '../src/fields/selectv2Field.js';
import { TextField, codePointLength } from '../src/fields/textField.js';
import { TextareaField } from '../src/fields/textareaField.js';
import type { IContextProvider } from '../src/context/context.js';
import type { FieldSchema } from '../src/fields/types.js';
import { sha256, toHex } from '../src/id.js';

function contextWith(opts: { location?: { lat: number; lon: number } | null; objects?: Record<string, Uint8Array> }): IContextProvider {
  return {
    getCurrentTime: () => 0,
    requestLocation: async () => opts.location ?? null,
    requestSecret: async () => null,
    requestObject: async (id) => opts.objects?.[id] ?? null,
    buildContext() {
      return adaptProvider(this);
    },
  };
}

describe('text field', () => {
  const engine = new TextField();
  const field: FieldSchema = { type: 'text', name: 'name', label: 'Name', inputRules: { minLength: 3, maxLength: 10, required: true } };

  it('validates length and required', () => {
    expect(engine.validateInput(field, '')?.message).toContain('required');
    expect(engine.validateInput(field, 'ab')?.message).toContain('at least 3');
    expect(engine.validateInput(field, 'abcdefghijk')?.message).toContain('at most 10');
    expect(engine.validateInput(field, 'okay')).toBeNull();
    expect(engine.validateInput(field, 5)).not.toBeNull();
  });

  it('measures length in code points', () => {
    const emoji = '👨‍👩‍👧';
    expect(codePointLength(emoji)).toBe(Array.from(emoji).length);
    expect(engine.validateInput({ type: 'text', name: 'n', label: 'N', inputRules: { maxLength: Array.from(emoji).length } }, emoji)).toBeNull();
    expect(engine.validateInput({ type: 'text', name: 'n', label: 'N', inputRules: { maxLength: Array.from(emoji).length - 1 } }, emoji)).not.toBeNull();
  });

  it('normalizes to NFC on encode', () => {
    expect(engine.encode(field, '\u0065\u0301')).toBe('\u00e9');
  });
});

describe('select field', () => {
  const engine = new SelectField();
  const field: FieldSchema = { type: 'select', name: 'category', label: 'Category', options: ['a', 'b'], inputRules: { required: true } };

  it('validates membership and required', () => {
    expect(engine.validateInput(field, 'a')).toBeNull();
    expect(engine.validateInput(field, 'zzz')).not.toBeNull();
    expect(engine.validateInput(field, '')?.message).toContain('required');
  });
});

describe('number field', () => {
  const engine = new NumberField();
  const field: FieldSchema = { type: 'number', name: 'age', label: 'Age', inputRules: { min: 0, max: 100 } };

  it('validates bounds', () => {
    expect(engine.validateInput(field, -1)?.message).toContain('>=');
    expect(engine.validateInput(field, 101)?.message).toContain('<=');
    expect(engine.validateInput(field, 50)).toBeNull();
    expect(engine.validateInput(field, 'x')).not.toBeNull();
  });

  it('encodes integers as integers and decimals as canonical strings', () => {
    expect(engine.encode(field, 42)).toBe(42);
    expect(engine.encode(field, 12.5)).toBe('12.5');
    expect(canonicalDecimalString(12.5)).toBe('12.5');
    expect(canonicalDecimalString(12.5000000001)).not.toBe('12.5');
    expect(engine.decode(field, '12.5')).toBe(12.5);
  });
});

describe('date and datetime fields', () => {
  const date = new DateField();
  const datetime = new DateTimeField();
  it('validates calendar dates', () => {
    expect(date.validateInput({ type: 'date', name: 'd', label: 'D' }, '2025-02-28')).toBeNull();
    expect(date.validateInput({ type: 'date', name: 'd', label: 'D' }, '2025-02-30')).not.toBeNull();
    expect(date.validateInput({ type: 'date', name: 'd', label: 'D' }, '02-2025')).not.toBeNull();
  });
  it('validates UTC datetimes', () => {
    expect(datetime.validateInput({ type: 'datetime', name: 't', label: 'T' }, '2026-08-13T04:30:00Z')).toBeNull();
    expect(datetime.validateInput({ type: 'datetime', name: 't', label: 'T' }, '2026-08-13T04:30:00')).not.toBeNull();
    expect(datetime.validateInput({ type: 'datetime', name: 't', label: 'T' }, '2026-13-13T04:30:00Z')).not.toBeNull();
  });
});

describe('location field', () => {
  const engine = new LocationField();
  const field: FieldSchema = { type: 'location', name: 'loc', label: 'Location', verifyRules: { maxRadius: 50 } };

  it('encodes to integer microdegrees and decodes back', () => {
    const encoded = engine.encode(field, { lat: 34.5553, lon: 69.2075 });
    expect(Number.isInteger(encoded.lat)).toBe(true);
    expect(engine.decode(field, encoded)).toEqual({ lat: 34.5553, lon: 69.2075 });
  });

  it('validates coordinates', () => {
    expect(engine.validateInput(field, { lat: 91, lon: 0 })).not.toBeNull();
    expect(engine.validateInput(field, { lat: 34, lon: 69 })).toBeNull();
  });

  it('reports valid/invalid/cannotVerify based on the verification context', async () => {
    const ctx = contextWith({ location: { lat: 34.5553, lon: 69.2075 } }).buildContext();
    const encoded = engine.encode(field, { lat: 34.5553, lon: 69.2075 });
    expect((await engine.validateField(field, encoded, ctx)).state).toBe('valid');

    const farCtx = contextWith({ location: { lat: 34.6, lon: 69.2 } }).buildContext();
    expect((await engine.validateField(field, encoded, farCtx)).state).toBe('invalid');

    const noCtx = contextWith({ location: null }).buildContext();
    expect((await engine.validateField(field, encoded, noCtx)).state).toBe('cannotVerify');
  });

  it('computes haversine distance', () => {
    expect(haversineDistance({ lat: 34.5553, lon: 69.2075 }, { lat: 34.5553, lon: 69.2075 })).toBeLessThan(1);
    // ~111km per degree of latitude
    expect(haversineDistance({ lat: 0, lon: 0 }, { lat: 1, lon: 0 })).toBeGreaterThan(100_000);
  });
});

describe('secret input field', () => {
  const engine = new SecretInputField();
  it('is stripped by default', () => {
    expect(engine.isStripped({ type: 'secretInput', name: 'p', label: 'P' })).toBe(true);
    expect(engine.isStripped({ type: 'secretInput', name: 'p', label: 'P', binding: 'inline' })).toBe(false);
  });
  it('declares the secret context requirement', () => {
    expect(engine.getContextRequirements()).toEqual(['secret']);
  });
  it('validates required', () => {
    expect(engine.validateInput({ type: 'secretInput', name: 'p', label: 'P' }, '')).not.toBeNull();
    expect(engine.validateInput({ type: 'secretInput', name: 'p', label: 'P' }, 'abc')).toBeNull();
  });
  it('reports stripped secrets as covered by the signature', async () => {
    const ctx = contextWith({}).buildContext();
    const result = await engine.validateField({ type: 'secretInput', name: 'p', label: 'P' }, undefined, ctx);
    expect(result.state).toBe('valid');
  });
  it('validates inline (stored) secrets', async () => {
    const ctx = contextWith({}).buildContext();
    const field: FieldSchema = { type: 'secretInput', name: 'p', label: 'P', binding: 'inline', inputRules: { required: true } };
    expect((await engine.validateField(field, 'abc', ctx)).state).toBe('valid');
    expect((await engine.validateField(field, '', ctx)).state).toBe('invalid');
  });
});

describe('attachment field', () => {
  const engine = new AttachmentField();
  const content = new TextEncoder().encode('photo-bytes');
  const hash = toHex(sha256(content)).slice(0, 32);

  it('validates the hash-only reference', () => {
    const field = { type: 'attachment', name: 'a', label: 'A' } as const;
    const ref = hash;
    expect(engine.validateInput(field, hash)).toBeNull();
    expect(engine.validateInput(field, toHex(sha256(content)))).not.toBeNull();
    expect(engine.validateInput(field, { id: 'obj-1' })).not.toBeNull();
    expect(engine.validateInput(field, 'not-a-hash')).not.toBeNull();
    expect(engine.validateInput(field, { hash: 'zz' + hash.slice(2) })).not.toBeNull();
    expect(ref).toBeTruthy();
  });

  it('owns schema type and compact content-reference semantics', () => {
    const field: FieldSchema = {
      type: 'attachment',
      name: 'a',
      label: 'A',
      inputRules: { contentType: 'IMAGE/PNG' },
    };
    const ref = attachmentReference(content);
    expect(attachmentContentType(field)).toBe('image/png');
    expect(ref).toBe(hash);
    expect(verifyAttachmentReference(ref, content)).toBe(true);
    expect(verifyAttachmentReference(ref, new TextEncoder().encode('tampered'))).toBe(false);
  });

  it('encodes and decodes pass-through', () => {
    const field = { type: 'attachment', name: 'a', label: 'A' } as const;
    const ref = hash;
    expect(engine.encode(field, ref)).toBe(ref);
    expect(engine.decode(field, ref)).toBe(ref);
  });

  it('treats a well-formed hash as structurally valid (no download)', async () => {
    const ctx = contextWith({}).buildContext();
    const result = await engine.validateField({ type: 'attachment', name: 'a', label: 'A' }, hash, ctx);
    expect(result.state).toBe('valid');
    const bad = await engine.validateField({ type: 'attachment', name: 'a', label: 'A' }, 'not-a-hash', ctx);
    expect(bad.state).toBe('invalid');
  });
});

describe('field registry', () => {
  it('registers all eight engines by default', () => {
    const registry = createDefaultFieldRegistry();
    for (const type of ['text', 'select', 'number', 'date', 'datetime', 'location', 'secretInput', 'attachment']) {
      expect(registry.has(type as never)).toBe(true);
    }
  });
  it('lists registered engines', () => {
    const registry = createDefaultFieldRegistry();
    expect(registry.list().map((e) => e.type).sort()).toEqual([
      'attachment',
      'date',
      'datetime',
      'datetimeEpoch',
      'location',
      'number',
      'secretInput',
      'select',
      'selectv2',
      'text',
      'textarea',
    ]);
  });
});

describe('field engine passthroughs', () => {
  const engines = {
    text: new TextField(),
    select: new SelectField(),
    number: new NumberField(),
    date: new DateField(),
    datetime: new DateTimeField(),
    location: new LocationField(),
    secret: new SecretInputField(),
    attachment: new AttachmentField(),
  };
  const base: FieldSchema = { type: 'text', name: 'f', label: 'F' };

  it('passes values through encode/decode', () => {
    expect(engines.text.decode(base, 'hello')).toBe('hello');
    expect(engines.text.encode(base, 'abc')).toBe('abc');
    expect(engines.select.decode(base, 'a')).toBe('a');
    expect(engines.number.decode(base, 5)).toBe(5);
    expect(engines.date.decode(base, '2025-01-01')).toBe('2025-01-01');
    expect(engines.datetime.encode(base, '2026-08-13T04:30:00Z')).toBe('2026-08-13T04:30:00Z');
    expect(engines.datetime.decode(base, '2026-08-13T04:30:00Z')).toBe('2026-08-13T04:30:00Z');
    expect(engines.secret.encode(base, 's')).toBe('s');
    expect(engines.secret.decode(base, 's')).toBe('s');
    expect(engines.attachment.encode(base, '0'.repeat(64))).toBe('0'.repeat(64));
    expect(engines.attachment.decode(base, '0'.repeat(32))).toBe('0'.repeat(32));
  });

  it('declares context requirements', () => {
    expect(engines.text.getContextRequirements()).toEqual([]);
    expect(engines.select.getContextRequirements()).toEqual([]);
    expect(engines.number.getContextRequirements()).toEqual([]);
    expect(engines.date.getContextRequirements()).toEqual([]);
    expect(engines.datetime.getContextRequirements()).toEqual([]);
    expect(engines.location.getContextRequirements()).toEqual(['location']);
    expect(engines.attachment.getContextRequirements()).toEqual([]);
  });

  it('validates number and datetime fields through validateField', async () => {
    const ctx = contextWith({}).buildContext();
    const bounded: FieldSchema = { type: 'number', name: 'n', label: 'N', inputRules: { min: 0, max: 10 } };
    expect((await engines.number.validateField(bounded, 5, ctx)).state).toBe('valid');
    expect((await engines.number.validateField(bounded, 99, ctx)).state).toBe('invalid');

    const dt: FieldSchema = { type: 'datetime', name: 't', label: 'T' };
    expect((await engines.datetime.validateField(dt, '2026-08-13T04:30:00Z', ctx)).state).toBe('valid');
    expect((await engines.datetime.validateField(dt, 'bogus', ctx)).state).toBe('invalid');
  });
});

describe('textarea field', () => {
  const engine = new TextareaField();
  const field: FieldSchema = { type: 'textarea', name: 'notes', label: 'Notes', inputRules: { required: true, minLength: 2 } };

  it('validates like text but allows multiline', () => {
    expect(engine.validateInput(field, '')?.message).toContain('required');
    expect(engine.validateInput(field, 'a')?.message).toContain('at least 2');
    expect(engine.validateInput(field, 'line1\nline2')).toBeNull();
    expect(engine.validateInput(field, 5)).not.toBeNull();
  });

  it('normalizes to NFC on encode', () => {
    expect(engine.encode(field, '\u0065\u0301')).toBe('\u00e9');
  });
});

describe('datetimeEpoch field', () => {
  const engine = new DatetimeEpochField();

  it('validates integer epoch seconds', () => {
    const field: FieldSchema = { type: 'datetimeEpoch', name: 't', label: 'T' };
    expect(engine.validateInput(field, 1_700_000_000)).toBeNull();
    expect(engine.validateInput(field, 1.5)).not.toBeNull();
    expect(engine.validateInput(field, 'x')).not.toBeNull();
  });

  it('validates date expressions against the epoch', async () => {
    const ctx = contextWith({}).buildContext();
    const field: FieldSchema = {
      type: 'datetimeEpoch',
      name: 't',
      label: 'T',
      verifyRules: { expressions: ['age() <= 14d'] },
    };
    // now = 0 (context), field epoch = 0 → age 0 → valid.
    expect((await engine.validateField(field, 0, ctx)).state).toBe('valid');
    // field epoch far in the past → age > 14d → invalid.
    expect((await engine.validateField(field, -2_000_000, ctx)).state).toBe('invalid');
  });
});

describe('selectv2 field', () => {
  const engine = new SelectV2Field();
  const field: FieldSchema = {
    type: 'selectv2',
    name: 'status',
    label: 'Status',
    inputRules: {
      options: [
        { label: 'Active', value: 'active', color: '#34c98f' },
        { label: 'Expired', value: 'expired', color: '#ef6a6a' },
      ],
    },
  };

  it('stores only the option index', () => {
    expect(engine.validateInput(field, 0)).toBeNull();
    expect(engine.validateInput(field, 1)).toBeNull();
    expect(engine.validateInput(field, 2)).not.toBeNull();
    expect(engine.validateInput(field, -1)).not.toBeNull();
    expect(engine.validateInput(field, 'active')).not.toBeNull();
  });

  it('accepts plain string options too', () => {
    const plain: FieldSchema = { type: 'selectv2', name: 's', label: 'S', options: ['a', 'b'] };
    expect(engine.validateInput(plain, 0)).toBeNull();
    expect(engine.validateInput(plain, 1)).toBeNull();
    expect(engine.validateInput(plain, 2)).not.toBeNull();
  });
});
