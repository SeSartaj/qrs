/**
 * qrs-core runtime for the app.
 *
 * Uses the WebCrypto runtime (`createQrsWeb`) with AsyncStorage-backed stores.
 * The context provider delegates interactive inputs (secrets, location, online
 * objects) to whatever the UI registers — so verification can prompt for a
 * passcode, etc. without the core knowing anything about React Native.
 */
import './crypto';
import { createQrsWeb, type FieldSchema, type GeoPoint, type QrsRuntime, type VerificationContext } from 'qrs-core';
import type { IContextProvider } from 'qrs-core';
import { persistedStores } from './stores';

export interface ContextHandlers {
  /** Ask the user for a secret (e.g. a stripped passcode needed to verify). */
  requestSecret?: (field: { label: string; name: string }) => Promise<string | null>;
  /** Ask the user for their current location (or null to skip). */
  requestLocation?: () => Promise<GeoPoint | null>;
  /** Fetch a signed object (e.g. an attachment) by its content-addressed id, trying each mirror. */
  requestObject?: (id: string, onlineEndpoints?: string | string[]) => Promise<Uint8Array | null>;
}

let handlers: ContextHandlers = {};

/** Register UI-provided context handlers (called once at startup). */
export function setContextHandlers(h: ContextHandlers): void {
  handlers = h;
}

class AppContextProvider implements IContextProvider {
  getCurrentTime(): number {
    return Math.floor(Date.now() / 1000);
  }

  async requestLocation(): Promise<GeoPoint | null> {
    return (await handlers.requestLocation?.()) ?? null;
  }

  async requestSecret(field: FieldSchema): Promise<string | null> {
    return (await handlers.requestSecret?.({ label: field.label, name: field.name })) ?? null;
  }

  async requestObject(id: string, _field?: FieldSchema, onlineEndpoints?: string | string[]): Promise<Uint8Array | null> {
    return (await handlers.requestObject?.(id, onlineEndpoints)) ?? null;
  }

  buildContext(): VerificationContext {
    return {
      getCurrentTime: () => this.getCurrentTime(),
      getLocation: () => this.requestLocation(),
      getSecret: (name) =>
        this.requestSecret({ type: 'secretInput', name, label: name }),
      getObject: (id, onlineEndpoints) => this.requestObject(id, undefined, onlineEndpoints),
    };
  }
}

let runtime: QrsRuntime | null = null;

/** Lazily build the (singleton) qrs-core runtime. */
export function getQrs(): QrsRuntime {
  if (!runtime) {
    runtime = createQrsWeb({
      ...persistedStores,
      contextProvider: new AppContextProvider(),
    });
  }
  return runtime;
}

export type { QrsRuntime };
