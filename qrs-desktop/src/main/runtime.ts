/**
 * Builds the qrs-core runtime for the desktop app.
 *
 * Persistence lives in the Electron user-data directory using the package's
 * file-backed stores. Inputs (location / secrets during verification) are gathered
 * through {@link DesktopContextProvider}, which asks the renderer over IPC.
 */
import { app, safeStorage } from 'electron';
import { join } from 'node:path';
import { mkdirSync } from 'node:fs';
import { createFileStores, createQrs, type QrsRuntime } from 'qrs-core';
import { DesktopContextProvider, type ContextWindowProvider } from './contextBridge.js';
import { createSecurePrivateKeyStore } from './securePrivateKeyStore.js';
import { GlobalConfigStore } from './configStore.js';

export interface DesktopRuntime {
  qrs: QrsRuntime;
  context: DesktopContextProvider;
  dataDir: string;
  /** true when private keys are encrypted at rest via safeStorage. */
  secureKeys: boolean;
  /** Global app-level configuration (language, table columns, …). */
  config: GlobalConfigStore;
}

/** Create the runtime. Data is stored under `<userData>/qrs-data`. */
export function createDesktopRuntime(getWindow: ContextWindowProvider): DesktopRuntime {
  const dataDir = join(app.getPath('userData'), 'qrs-data');
  mkdirSync(dataDir, { recursive: true });
  const stores = createFileStores(dataDir);
  const context = new DesktopContextProvider(getWindow);
  const secureKeys = safeStorage.isEncryptionAvailable();
  // Private keys are encrypted at rest when the platform exposes a secure store.
  const privateKeyStore = createSecurePrivateKeyStore(stores.privateKeyStore);
  const qrs = createQrs({
    ...stores,
    privateKeyStore,
    contextProvider: context,
  });
  const config = new GlobalConfigStore(dataDir);
  return { qrs, context, dataDir, secureKeys, config };
}
