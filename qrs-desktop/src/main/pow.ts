import { createHash } from 'node:crypto';

/** hashcash-style proof of work: find `counter` so sha256("nonce:counter") starts
 * with `difficulty` zero hex digits. Cheap to verify, costly to spam — this is the
 * client half of the distribution server's DDoS defense. */
export function solvePow(nonce: string, difficulty: number): number {
  const target = '0'.repeat(difficulty);
  let counter = 0;
  for (;;) {
    const digest = createHash('sha256').update(`${nonce}:${counter}`, 'ascii').digest('hex');
    if (digest.startsWith(target)) return counter;
    counter++;
  }
}
