import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { solvePow } from '../src/main/pow.js';

describe('online proof of work (client side)', () => {
  it('finds a counter whose sha256(nonce:counter) starts with the target zeros', () => {
    const nonce = 'abc123';
    const counter = solvePow(nonce, 4);
    const digest = createHash('sha256').update(`${nonce}:${counter}`, 'ascii').digest('hex');
    expect(digest.startsWith('0000')).toBe(true);
  });

  it('solves higher difficulty too', () => {
    const nonce = 'xyz';
    const counter = solvePow(nonce, 6);
    const digest = createHash('sha256').update(`${nonce}:${counter}`, 'ascii').digest('hex');
    expect(digest.startsWith('000000')).toBe(true);
  });
});
