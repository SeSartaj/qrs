/**
 * Pure helpers for the location input: parse/format a "lat, lon" pair
 * (e.g. a direct paste from Google Maps like `34.51958749194178, 69.17472990319257`).
 * Kept free of UI imports so it can be unit-tested in isolation.
 */

export interface LocationPair {
  lat: number;
  lon: number;
}

const PAIR_RE = /^\s*(-?\d+(?:\.\d+)?)\s*[,;\s]+\s*(-?\d+(?:\.\d+)?)\s*$/;

/**
 * Parse a "lat, lon" string. Accepts a comma, semicolon or whitespace separator.
 * Returns `null` when the text is empty or not a valid coordinate pair.
 */
export function parseLocationPair(text: string): LocationPair | null {
  const m = PAIR_RE.exec(text.trim());
  if (!m) return null;
  const lat = parseFloat(m[1] ?? '');
  const lon = parseFloat(m[2] ?? '');
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
  if (lat < -90 || lat > 90 || lon < -180 || lon > 180) return null;
  return { lat, lon };
}

/** Format a location as a "lat, lon" string (empty when either value is missing). */
export function formatLocationPair(lat?: number, lon?: number): string {
  if (typeof lat === 'number' && typeof lon === 'number') {
    return `${lat}, ${lon}`;
  }
  return '';
}
