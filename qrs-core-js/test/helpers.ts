/**
 * Shared test helpers.
 */
import { DummyContextProvider } from '../src/context/dummyContext.js';
import { createQrs, type QrsRuntime } from '../src/runtime.js';
import type { IClock } from '../src/services/clock.js';
import type { FieldSchema } from '../src/fields/types.js';
import type { GeoPoint } from '../src/types.js';

export class FixedClock implements IClock {
  constructor(private readonly time: number) {}
  now(): number {
    return this.time;
  }
}

export interface RuntimeOptions {
  time?: number;
  location?: GeoPoint | null;
  secrets?: Record<string, string>;
  objects?: Record<string, Uint8Array>;
}

/** A fully in-memory runtime with a fixed clock and a configurable dummy context. */
export function makeRuntime(opts: RuntimeOptions = {}): QrsRuntime {
  const time = opts.time ?? 1_700_000_000; // 2023-11-14T22:13:20Z
  return createQrs({
    contextProvider: new DummyContextProvider({
      time,
      location: opts.location ?? null,
      secrets: opts.secrets ?? {},
      objects: opts.objects ?? {},
    }),
    clock: new FixedClock(time),
  });
}

/** A simple pharmacy-license style schema used across tests. */
export function pharmacySchema(): FieldSchema[] {
  return [
    { type: 'text', name: 'pharmacy_name', label: 'Pharmacy Name', inputRules: { minLength: 3, required: true } },
    { type: 'select', name: 'category', label: 'Category', options: ['category_1', 'category_2'], inputRules: { required: true } },
    { type: 'date', name: 'issue_date', label: 'Issue Date', inputRules: { required: true } },
    { type: 'date', name: 'expiry_date', label: 'Expiry Date', inputRules: { required: true } },
    {
      type: 'location',
      name: 'pharmacy_location',
      label: 'Location',
      verifyRules: { maxRadius: 50 },
    },
    { type: 'secretInput', name: 'owner_passcode', label: 'Owner Passcode', binding: 'stripped' },
  ];
}

export const KABUL = { lat: 34.5553, lon: 69.2075 } as const;
