/**
 * The context-provider abstraction (IoC for inputs).
 *
 * The verification pipeline never calls platform APIs directly. Instead it asks an
 * {@link IContextProvider} for whatever external information a field needs (time,
 * location, secrets, online objects). The package ships with two providers:
 *
 *  - {@link DummyContextProvider} — the default; returns configured values or `null`
 *    (never prompts). This is what library consumers get unless they override it.
 *  - {@link TerminalContextProvider} — used by the CLI; asks the user on the terminal.
 *
 * Consumers can implement their own provider (e.g. read from a device, a remote
 * service, or a test fixture) and inject it via `createQrs`.
 */
import type { FieldSchema, VerificationContext } from '../fields/types.js';
import type { GeoPoint } from '../types.js';


export interface IContextProvider {
  getCurrentTime(): number;
  requestLocation(field?: FieldSchema): Promise<GeoPoint | null>;
  requestSecret(field: FieldSchema): Promise<string | null>;
  /** Fetch a signed object; onlineEndpoints are distribution-server hints, tried in order. */
  requestObject(id: string, field?: FieldSchema, onlineEndpoints?: string | string[]): Promise<Uint8Array | null>;
  /** Adapt this provider into the `VerificationContext` consumed by field engines. */
  buildContext(): VerificationContext;
}

/** Adapt any provider into a {@link VerificationContext}. */
export function adaptProvider(provider: IContextProvider): VerificationContext {
  return {
    getCurrentTime: () => provider.getCurrentTime(),
    getLocation: () => provider.requestLocation(),
    getSecret: (fieldName) => provider.requestSecret({ type: 'secretInput', name: fieldName, label: fieldName }),
    getObject: (id, onlineEndpoints) => provider.requestObject(id, undefined, onlineEndpoints),
  };
}
