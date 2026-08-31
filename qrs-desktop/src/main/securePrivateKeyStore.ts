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
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import type { AlgorithmId, IPrivateKeyStore, KeyId, PrivateJwk } from 'qrs-core';

interface EncryptedPrivateJwk {
  /** true when `data` is base64 of `safeStorage.encryptString(JSON)` output. */
  encrypted: boolean;
  /** Either base64(encrypted JSON) or plain JSON. */
  data: string;
}

interface PasswordEnvelope {
  encrypted: true;
  password: true;
  salt: string;
  iv: string;
  tag: string;
  data: string;
}

function passwordSeal(privateJwk: PrivateJwk, password: string): PasswordEnvelope {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', scryptSync(password, salt, 32), iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(privateJwk), 'utf8'), cipher.final()]);
  return { encrypted: true, password: true, salt: salt.toString('base64'), iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') };
}

function passwordUnseal(payload: PasswordEnvelope, password: string): PrivateJwk {
  const decipher = createDecipheriv('aes-256-gcm', scryptSync(password, Buffer.from(payload.salt, 'base64'), 32), Buffer.from(payload.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(payload.tag, 'base64'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(payload.data, 'base64')), decipher.final()]).toString('utf8')) as PrivateJwk;
}

function seal(privateJwk: PrivateJwk): EncryptedPrivateJwk {
  if (safeStorage.isEncryptionAvailable()) {
    const encrypted = safeStorage.encryptString(JSON.stringify(privateJwk));
    return { encrypted: true, data: encrypted.toString('base64') };
  }
  return { encrypted: false, data: JSON.stringify(privateJwk) };
}

function unseal(payload: EncryptedPrivateJwk | PasswordEnvelope, password?: string): PrivateJwk {
  if ('password' in payload && payload.password) {
    if (!password) throw new Error('Private-key password required. Unlock it in Settings.');
    try { return passwordUnseal(payload, password); } catch { throw new Error('Incorrect private-key password.'); }
  }
  if (payload.encrypted) {
    const buffer = Buffer.from(payload.data, 'base64');
    return JSON.parse(safeStorage.decryptString(buffer)) as PrivateJwk;
  }
  return JSON.parse(payload.data) as PrivateJwk;
}

/** Wrap an existing {@link IPrivateKeyStore} so private JWKs are encrypted at rest. */
export interface SecurePrivateKeyStore extends IPrivateKeyStore {
  setPassword(password: string): Promise<void>;
  unlock(password: string): Promise<void>;
  removePassword(): Promise<void>;
  isPasswordConfigured(): boolean;
  isPasswordUnlocked(): boolean;
}

export function createSecurePrivateKeyStore(inner: IPrivateKeyStore, initiallyConfigured = false): SecurePrivateKeyStore {
  let password: string | undefined;
  let passwordConfigured = initiallyConfigured;
  const store: SecurePrivateKeyStore = {
    async save(keyId: KeyId, algorithm: AlgorithmId, privateJwk: PrivateJwk): Promise<void> {
      const sealed = password ? passwordSeal(privateJwk, password) : seal(privateJwk);
      // The marker object rides inside the stored record (FilePrivateKeyStore
      // stores whatever object it's given and is opaque to its contents).
      await inner.save(keyId, algorithm, sealed as unknown as PrivateJwk);
    },

    async load(keyId: KeyId) {
      const record = await inner.load(keyId);
      if (!record) return null;
      const sealed = record.privateJwk as unknown as EncryptedPrivateJwk | PasswordEnvelope;
      if (sealed && typeof sealed.data === 'string' && typeof sealed.encrypted === 'boolean') {
        return { algorithm: record.algorithm, privateJwk: unseal(sealed, password) };
      }
      // Legacy plaintext entry.
      return record;
    },

    has: (keyId) => inner.has(keyId),
    all: () => inner.all(),
    async setPassword(nextPassword) {
      if (nextPassword.length < 8) throw new Error('Password must contain at least 8 characters.');
      const records = [] as Array<{ keyId: KeyId; algorithm: AlgorithmId; privateJwk: PrivateJwk }>;
      for (const item of await inner.all()) {
        const record = await inner.load(item.keyId);
        if (record) {
          const raw = record.privateJwk as unknown as EncryptedPrivateJwk | PasswordEnvelope | PrivateJwk;
          const privateJwk = raw && typeof raw === 'object' && 'data' in raw && typeof raw.data === 'string'
            ? unseal(raw as EncryptedPrivateJwk | PasswordEnvelope, password)
            : raw as PrivateJwk;
          records.push({ keyId: item.keyId, algorithm: record.algorithm, privateJwk });
        }
      }
      password = nextPassword;
      passwordConfigured = true;
      for (const record of records) await store.save(record.keyId, record.algorithm, record.privateJwk);
    },
    async unlock(candidate) {
      if (!passwordConfigured) return;
      const first = (await inner.all())[0];
      if (first) {
        const record = await inner.load(first.keyId);
        if (record) passwordUnseal(record.privateJwk as unknown as PasswordEnvelope, candidate);
      }
      password = candidate;
    },
    async removePassword() {
      if (!passwordConfigured) return;
      const records = [] as Array<{ keyId: KeyId; algorithm: AlgorithmId; privateJwk: PrivateJwk }>;
      for (const item of await inner.all()) {
        const record = await inner.load(item.keyId);
        if (record) records.push({ keyId: item.keyId, algorithm: record.algorithm, privateJwk: unseal(record.privateJwk as unknown as PasswordEnvelope, password) });
      }
      password = undefined;
      passwordConfigured = false;
      for (const record of records) await store.save(record.keyId, record.algorithm, record.privateJwk);
    },
    isPasswordConfigured: () => passwordConfigured,
    isPasswordUnlocked: () => !passwordConfigured || password !== undefined,
  };
  return store;
}
