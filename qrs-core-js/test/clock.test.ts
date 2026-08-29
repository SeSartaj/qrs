import { describe, expect, it } from 'vitest';
import { SystemClock } from '../src/services/clock.js';

describe('SystemClock', () => {
  it('returns the current time as epoch seconds', () => {
    const before = Math.floor(Date.now() / 1000);
    const now = new SystemClock().now();
    const after = Math.floor(Date.now() / 1000);
    expect(now).toBeGreaterThanOrEqual(before);
    expect(now).toBeLessThanOrEqual(after);
  });
});
