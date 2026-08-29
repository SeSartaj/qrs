/**
 * Node runtime factory.
 *
 * `createQrs()` wires the package with Node's built-in crypto providers by default
 * (this is the primary, best-tested entry point). For browsers / React Native use
 * `createQrsWeb` from `runtimeWeb.js` (WebCrypto providers) instead.
 *
 * Every dependency can be overridden via {@link QrsDependencies} (inversion of
 * control): storage, context, clock, crypto registry and field registry.
 */
import { DummyContextProvider } from './context/dummyContext.js';
import { createDefaultCryptoRegistry } from './crypto/nodeRegistry.js';
import { createDefaultFieldRegistry } from './fields/index.js';
import { createInMemoryStores } from './storage/memoryStores.js';
import { SystemClock } from './services/clock.js';
import type { ServiceDeps } from './services/deps.js';
import { QrsRuntime, type QrsDependencies } from './runtimeBase.js';

/** Create a runtime with Node crypto providers and in-memory defaults. */
export function createQrs(deps: QrsDependencies = {}): QrsRuntime {
  const defaults = createInMemoryStores();
  const full: ServiceDeps = {
    cryptoRegistry: deps.cryptoRegistry ?? createDefaultCryptoRegistry(),
    fieldRegistry: deps.fieldRegistry ?? createDefaultFieldRegistry(),
    privateKeyStore: deps.privateKeyStore ?? defaults.privateKeyStore,
    publicKeyStore: deps.publicKeyStore ?? defaults.publicKeyStore,
    certificateStore: deps.certificateStore ?? defaults.certificateStore,
    documentStore: deps.documentStore ?? defaults.documentStore,
    revocationStore: deps.revocationStore ?? defaults.revocationStore,
    trustStore: deps.trustStore ?? defaults.trustStore,
    endpointConfigStore: deps.endpointConfigStore ?? defaults.endpointConfigStore,
    contextProvider: deps.contextProvider ?? new DummyContextProvider(),
    clock: deps.clock ?? new SystemClock(),
  };
  return new QrsRuntime(full);
}

export { QrsRuntime, type QrsDependencies } from './runtimeBase.js';
