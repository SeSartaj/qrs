/**
 * Time abstraction (IoC). The real clock is the default; tests and consumers can
 * inject a fixed clock to make behavior deterministic.
 */
export interface IClock {
  /** Current time as epoch seconds (UTC). */
  now(): number;
}

export class SystemClock implements IClock {
  now(): number {
    return Math.floor(Date.now() / 1000);
  }
}
