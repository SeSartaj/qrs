/**
 * Context handlers wired into the qrs-core runtime at startup:
 *   - secrets  → the SecretPromptHost dialog,
 *   - location → expo-location (asks permission, feeds the current position so
 *                location-gated fields can be compared),
 *   - online objects → fetch a signed attachment from the issuing TCert's server.
 */
import * as Location from 'expo-location';
import { fromBase64Url } from 'qrs-core';
import type { ContextHandlers } from './runtime';
import { requestSecret } from './secretPrompt';

export async function buildContextHandlers(): Promise<ContextHandlers> {
  return {
    requestSecret: (field) => requestSecret(field),
    requestLocation: async () => {
      try {
        const { status } = await Location.requestForegroundPermissionsAsync();
        if (status !== 'granted') return null;
        const pos = await Location.getCurrentPositionAsync({ accuracy: Location.Accuracy.High });
        return { lat: pos.coords.latitude, lon: pos.coords.longitude };
      } catch {
        return null;
      }
    },
    requestObject: async (id, onlineEndpoints) => {
      const list = Array.isArray(onlineEndpoints) ? onlineEndpoints : onlineEndpoints ? [onlineEndpoints] : [];
      for (const ep of list) {
        try {
          const base = ep.replace(/\/+$/, '');
          const res = await fetch(`${base}/api/attachments/${id}/`);
          if (!res.ok) continue;
          const body = (await res.json()) as { bytesB64?: string };
          if (body.bytesB64) return fromBase64Url(body.bytesB64);
        } catch {
          /* try the next mirror */
        }
      }
      return null;
    },
  };
}
