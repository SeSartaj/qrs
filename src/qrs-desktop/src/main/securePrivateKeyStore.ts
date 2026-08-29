/**
 * Secure private-key storage for the desktop app.
 *
 * Wraps the plain JSON-file store and encrypts the private JWK at rest with
 * Electron's `safeStorage` (which delegates to the OS keychain-backed encryption:
 * DPAPI on Windows, Keychain on macOS, libsecret/kwallet on Linux). When the
 * platform has no secure store available (`safeStorage.isEncryptionAvailable()`
 * is false — common on headless Linux) it transparently falls back to storing the
 * plaintext, so the app keeps working.
 *
 * Existing (legacy) plaintext entries are still readable — each entry carries an
 * `encrypted` marker.
 */
import { safeStorage } from 'electron';
import type { AlgorithmId, IPrivateKeyStore, KeyId, PrivateJwk } from 'qrs-core';

interface EncryptedPrivateJwk {
  /** true when `data` is base64 of `safeStorage.encryptString(JSON)` output. */
  encrypted: boolean;
  /** Either base64(encrypted JSON) or plain JSON. */
  data: string;
}

function seal(privateJwk: PrivateJwk): EncryptedPrivateJwk {
  if (safeStorage.isEncryptionAvailable()) {
    const encrypted = safeStorage.encryptString(JSON.stringify(privateJwk));
    return { encrypted: true, data: encrypted.toString('base64') };
  }
  return { encrypted: false, data: JSON.stringify(privateJwk) };
}

function unseal(payload: EncryptedPrivateJwk): PrivateJwk {
  if (payload.encrypted) {
    const buffer = Buffer.from(payload.data, 'base64');
    return JSON.parse(safeStorage.decryptString(buffer)) as PrivateJwk;
  }
  return JSON.parse(payload.data) as PrivateJwk;
}

/** Wrap an existing {@link IPrivateKeyStore} so private JWKs are encrypted at rest. */
export function createSecurePrivateKeyStore(inner: IPrivateKeyStore): IPrivateKeyStore {
  return {
    async save(keyId: KeyId, algorithm: AlgorithmId, privateJwk: PrivateJwk): Promise<void> {
      const sealed = seal(privateJwk);
      // The marker object rides inside the stored record (FilePrivateKeyStore
      // stores whatever object it's given and is opaque to its contents).
      await inner.save(keyId, algorithm, sealed as unknown as PrivateJwk);
    },

    async load(keyId: KeyId) {
      const record = await inner.load(keyId);
      if (!record) return null;
      const sealed = record.privateJwk as unknown as EncryptedPrivateJwk;
      if (sealed && typeof sealed.data === 'string' && typeof sealed.encrypted === 'boolean') {
        return { algorithm: record.algorithm, privateJwk: unseal(sealed) };
      }
      // Legacy plaintext entry.
      return record;
    },

    has: (keyId) => inner.has(keyId),
    all: () => inner.all(),
  };
}
