/**
 * Web runtime factory (browsers / React Native).
 *
 * `createQrsWeb()` is the portable twin of `createQrs()`: it wires the same services
 * but defaults to the **WebCrypto** providers (`globalThis.crypto.subtle`), which
 * require no Node APIs. It is used automatically by bundlers via the `browser` /
 * `react-native` conditions in `package.json`, or can be imported explicitly from
 * `qrs-core/browser`.
 *
 * Everything is still overridable (IoC): pass your own stores, context provider,
 * clock or registries as needed.
 */
import { DummyContextProvider } from './context/dummyContext.js';
import { createWebCryptoCryptoRegistry } from './crypto/webcrypto.js';
import { createDefaultFieldRegistry } from './fields/index.js';
import { createInMemoryStores } from './storage/memoryStores.js';
import { SystemClock } from './services/clock.js';
import type { ServiceDeps } from './services/deps.js';
import { QrsRuntime, type QrsDependencies } from './runtimeBase.js';

/** Create a runtime with WebCrypto providers and in-memory defaults. */
export function createQrsWeb(deps: QrsDependencies = {}): QrsRuntime {
  const defaults = createInMemoryStores();
  const full: ServiceDeps = {
    cryptoRegistry: deps.cryptoRegistry ?? createWebCryptoCryptoRegistry(),
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
