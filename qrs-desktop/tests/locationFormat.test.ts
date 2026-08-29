import { describe, expect, it } from 'vitest';
import { formatLocationPair, parseLocationPair } from '../src/renderer/src/lib/locationFormat.js';

describe('locationFormat (Google-Maps "lat, lon" input)', () => {
  it('parses a direct Google Maps paste', () => {
    expect(parseLocationPair('34.51958749194178, 69.17472990319257')).toEqual({
      lat: 34.51958749194178,
      lon: 69.17472990319257,
    });
  });

  it('accepts comma, semicolon and whitespace separators', () => {
    expect(parseLocationPair('34.5,69.1')).toEqual({ lat: 34.5, lon: 69.1 });
    expect(parseLocationPair('34.5;69.1')).toEqual({ lat: 34.5, lon: 69.1 });
    expect(parseLocationPair('34.5 69.1')).toEqual({ lat: 34.5, lon: 69.1 });
    expect(parseLocationPair('  -34.5 , -69.1  ')).toEqual({ lat: -34.5, lon: -69.1 });
  });

  it('rejects out-of-range or malformed values', () => {
    expect(parseLocationPair('91.0, 0.0')).toBeNull(); // lat > 90
    expect(parseLocationPair('0.0, 181.0')).toBeNull(); // lon > 180
    expect(parseLocationPair('abc, 123')).toBeNull();
    expect(parseLocationPair('34.5')).toBeNull();
    expect(parseLocationPair('')).toBeNull();
    expect(parseLocationPair('   ')).toBeNull();
  });

  it('formats a pair for display and handles missing values', () => {
    expect(formatLocationPair(34.51958749194178, 69.17472990319257)).toBe(
      '34.51958749194178, 69.17472990319257'
    );
    expect(formatLocationPair(undefined, 5)).toBe('');
    expect(formatLocationPair()).toBe('');
  });
});
