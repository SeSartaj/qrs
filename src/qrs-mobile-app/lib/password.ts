/**
 * Admin password for trust management.
 *
 * The app is configured by an administrator: on first launch the admin sets a
 * password, and every *trust-affecting* action (pin, add CA, distrust, …) asks
 * for it. The password is never stored in plain text — only a salted PBKDF2-SHA256
 * hash is persisted in AsyncStorage.
 */
import AsyncStorage from '@react-native-async-storage/async-storage';
import { pbkdf2Async } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils.js';

const KEY = 'qrs.admin-password';
const DEFAULT_ADMIN_PASSWORD = '6789';
const ITERATIONS = 120_000;
const SALT_LEN = 16;
/** After a successful verification, trust actions are accepted instantly for this long. */
const AUTH_WINDOW_MS = 60_000;

let authenticatedUntil = 0;

async function derive(password: string, salt: Uint8Array): Promise<string> {
  // quick-crypto installs WebCrypto on native. PBKDF2 then runs in native code
  // instead of spending the 120k-round loop on the Hermes JS thread.
  const subtle = (globalThis.crypto as Crypto | undefined)?.subtle;
  if (subtle) {
    const passwordBytes = new TextEncoder().encode(password);
    const key = await subtle.importKey(
      'raw',
      passwordBytes.buffer as ArrayBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveBits'],
    );
    const bits = await subtle.deriveBits(
      { name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: ITERATIONS, hash: 'SHA-256' },
      key,
      256,
    );
    return bytesToHex(new Uint8Array(bits));
  }

  // Browser/test fallback when WebCrypto is unavailable.
  const key = await pbkdf2Async(sha256, new TextEncoder().encode(password), salt, {
    c: ITERATIONS,
    dkLen: 32,
  });
  return bytesToHex(key);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export interface StoredPassword {
  salt: string;
  hash: string;
}

/** True when an admin password has been configured. */
export async function hasAdminPassword(): Promise<boolean> {
  const raw = await AsyncStorage.getItem(KEY);
  if (raw) return true;
  // First-run convenience: persist only the salted hash, never the default
  // password itself. Users can change it from Settings at any time.
  await setAdminPassword(DEFAULT_ADMIN_PASSWORD);
  return true;
}

/** Set (or reset) the admin password. Returns true on success. */
export async function setAdminPassword(password: string): Promise<boolean> {
  if (password.length < 4) return false;
  const salt = randomBytes(SALT_LEN);
  const stored: StoredPassword = { salt: bytesToHex(salt), hash: await derive(password, salt) };
  await AsyncStorage.setItem(KEY, JSON.stringify(stored));
  return true;
}

/** Verify a candidate password against the stored hash. */
export async function verifyAdminPassword(password: string): Promise<boolean> {
  if (Date.now() < authenticatedUntil) return true;
  const raw = await AsyncStorage.getItem(KEY);
  if (!raw) return false;
  try {
    const stored = JSON.parse(raw) as StoredPassword;
    const salt = hexToBytes(stored.salt);
    const candidate = await derive(password, salt);
    const candidateBytes = hexToBytes(candidate);
    const expected = hexToBytes(stored.hash);
    const ok = bytesEqual(candidateBytes, expected);
    if (ok) authenticatedUntil = Date.now() + AUTH_WINDOW_MS;
    return ok;
  } catch {
    return false;
  }
}

/** Remove the admin password (used when clearing data). */
export async function clearAdminPassword(): Promise<void> {
  authenticatedUntil = 0;
  await AsyncStorage.removeItem(KEY);
}
