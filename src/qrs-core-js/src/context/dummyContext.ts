/**
 * Default context provider. Never prompts: it returns the values it was configured
 * with (or `null` when absent). This is what `createQrs()` wires in by default, so
 * the core is fully usable headless; consumers override it with their own provider.
 */
import type { FieldSchema, VerificationContext } from '../fields/types.js';
import type { GeoPoint } from '../types.js';
import { adaptProvider, type IContextProvider } from './context.js';

export interface DummyContextOptions {
  time?: number;
  location?: GeoPoint | null;
  secrets?: Record<string, string>;
  objects?: Record<string, Uint8Array>;
}

export class DummyContextProvider implements IContextProvider {
  private readonly opts: Required<DummyContextOptions>;

  constructor(opts: DummyContextOptions = {}) {
    this.opts = {
      time: opts.time ?? Math.floor(Date.now() / 1000),
      location: opts.location ?? null,
      secrets: opts.secrets ?? {},
      objects: opts.objects ?? {},
    };
  }

  getCurrentTime(): number {
    return this.opts.time;
  }

  async requestLocation(_field?: FieldSchema): Promise<GeoPoint | null> {
    return this.opts.location;
  }

  async requestSecret(field: FieldSchema): Promise<string | null> {
    return this.opts.secrets[field.name] ?? null;
  }

  async requestObject(id: string, _field?: FieldSchema, _onlineEndpoints?: string | string[]): Promise<Uint8Array | null> {
    return this.opts.objects[id] ?? null;
  }

  buildContext(): VerificationContext {
    return adaptProvider(this);
  }
}
