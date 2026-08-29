/**
 * Terminal context provider: asks the user for context on the command line.
 * Used by the CLI. In a production deployment a consumer would replace this with a
 * provider that reads from a real device/backend.
 */
import type { FieldSchema, VerificationContext } from '../fields/types.js';
import type { GeoPoint } from '../types.js';
import { adaptProvider, type IContextProvider } from './context.js';
import { terminalAsk } from './terminalInput.js';

export class TerminalContextProvider implements IContextProvider {
  getCurrentTime(): number {
    return Math.floor(Date.now() / 1000);
  }

  async requestLocation(field?: FieldSchema): Promise<GeoPoint | null> {
    const label = field ? field.label : 'location';
    const answer = await terminalAsk(`Current location for "${label}" (lat,lon or empty to skip): `);
    if (!answer) return null;
    const parts = answer.split(',').map((s) => parseFloat(s.trim()));
    const lat = parts[0];
    const lon = parts[1];
    if (lat === undefined || lon === undefined || !Number.isFinite(lat) || !Number.isFinite(lon)) return null;
    return { lat, lon };
  }

  async requestSecret(field: FieldSchema): Promise<string | null> {
    const answer = await terminalAsk(`Enter secret for "${field.label}" (${field.name}): `);
    return answer.length > 0 ? answer : null;
  }

  async requestObject(_id: string, _field?: FieldSchema, _onlineEndpoints?: string | string[]): Promise<Uint8Array | null> {
    // The terminal provider has no offline object source; return null (cannot verify).
    return null;
  }

  buildContext(): VerificationContext {
    return adaptProvider(this);
  }
}
