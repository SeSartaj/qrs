import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import type { GlobalConfig } from '../shared/types.js';

type PinRecord = { salt: string; hash: string };

export class TcertPinStore {
  private readonly authorizedUntil = new Map<string, number>();
  private readonly activeSessions = new Set<string>();
  constructor(private readonly getConfig: () => GlobalConfig, private readonly saveConfig: (c: GlobalConfig) => void) {}

  private records(): Record<string, PinRecord> {
    const value = this.getConfig().tcertPins;
    return value && typeof value === 'object' ? value as Record<string, PinRecord> : {};
  }

  has(tcertId: string): boolean { return Boolean(this.records()[tcertId]); }

  verify(tcertId: string, pin: string): boolean {
    const record = this.records()[tcertId];
    if (!record || !pin) return !record;
    const actual = scryptSync(pin, Buffer.from(record.salt, 'base64'), 32);
    const valid = timingSafeEqual(actual, Buffer.from(record.hash, 'base64'));
    if (valid) this.authorizedUntil.set(tcertId, Date.now() + 2 * 60 * 1000);
    return valid;
  }

  isAuthorized(tcertId: string): boolean {
    if (this.activeSessions.has(tcertId)) return true;
    const until = this.authorizedUntil.get(tcertId) ?? 0;
    if (until <= Date.now()) { this.authorizedUntil.delete(tcertId); return false; }
    return true;
  }

  beginSession(tcertId: string): void { if (this.isAuthorized(tcertId)) this.activeSessions.add(tcertId); }
  endSession(tcertId: string): void { this.activeSessions.delete(tcertId); }

  set(tcertId: string, pin: string): void {
    if (!/^\d{4,12}$/.test(pin)) throw new Error('PIN must contain 4 to 12 digits.');
    const records = this.records();
    const salt = randomBytes(16);
    records[tcertId] = { salt: salt.toString('base64'), hash: scryptSync(pin, salt, 32).toString('base64') };
    this.saveConfig({ ...this.getConfig(), tcertPins: records });
  }

  remove(tcertId: string, previousPin: string): void {
    if (!this.verify(tcertId, previousPin)) throw new Error('Incorrect TCert PIN.');
    const records = this.records();
    delete records[tcertId];
    this.authorizedUntil.delete(tcertId);
    this.saveConfig({ ...this.getConfig(), tcertPins: records });
  }
}
