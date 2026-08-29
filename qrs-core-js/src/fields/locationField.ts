import { QrsValidationError } from '../errors.js';
import type { GeoPoint } from '../types.js';
import {
  readNumberRule,
  type ContextRequirement,
  type FieldResult,
  type FieldSchema,
  type IFieldEngine,
  type VerificationContext,
} from './types.js';

/** Microdegrees per degree: coordinates are stored as fixed-point integers. */
export const MICRODEGREES = 1_000_000;

export function haversineDistance(a: GeoPoint, b: GeoPoint): number {
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const R = 6_371_000; // metres
  const dLat = toRad(b.lat - a.lat);
  const dLon = toRad(b.lon - a.lon);
  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(a.lat)) * Math.cos(toRad(b.lat)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
}

export interface EncodedLocation {
  lat: number; // microdegrees
  lon: number; // microdegrees
}

export class LocationField implements IFieldEngine {
  readonly type = 'location' as const;

  validateInput(field: FieldSchema, value: unknown): { message: string } | null {
    const point = value as Partial<GeoPoint>;
    if (typeof value !== 'object' || value === null || typeof point.lat !== 'number' || typeof point.lon !== 'number') {
      return { message: `${field.label} must be an object with lat and lon` };
    }
    if (Number.isNaN(point.lat) || point.lat < -90 || point.lat > 90) {
      return { message: `${field.label} lat must be in [-90, 90]` };
    }
    if (Number.isNaN(point.lon) || point.lon < -180 || point.lon > 180) {
      return { message: `${field.label} lon must be in [-180, 180]` };
    }
    return null;
  }

  encode(_field: FieldSchema, value: unknown): EncodedLocation {
    const point = value as GeoPoint;
    return {
      lat: Math.round(point.lat * MICRODEGREES),
      lon: Math.round(point.lon * MICRODEGREES),
    };
  }

  decode(_field: FieldSchema, encoded: unknown): GeoPoint {
    const loc = encoded as EncodedLocation;
    if (typeof loc?.lat !== 'number' || typeof loc?.lon !== 'number') {
      throw new QrsValidationError('Stored location must contain integer microdegree lat/lon');
    }
    return { lat: loc.lat / MICRODEGREES, lon: loc.lon / MICRODEGREES };
  }

  getContextRequirements(): ContextRequirement[] {
    return ['location'];
  }

  async validateField(field: FieldSchema, encoded: unknown, ctx: VerificationContext): Promise<FieldResult> {
    const current = await ctx.getLocation();
    if (current === null) {
      return { name: field.name, state: 'cannotVerify', message: 'location unavailable at verification time' };
    }
    const stored = this.decode(field, encoded);
    const maxRadius = readNumberRule(field.verifyRules, 'maxRadius', 0);
    const distance = haversineDistance(current, stored);
    if (distance <= maxRadius) {
      return { name: field.name, state: 'valid', message: `within ${maxRadius}m (${Math.round(distance)}m)` };
    }
    return {
      name: field.name,
      state: 'invalid',
      message: `outside permitted area (${Math.round(distance)}m > ${maxRadius}m)`,
    };
  }
}
