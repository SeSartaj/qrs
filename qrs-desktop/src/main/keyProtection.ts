/**
 * Key protection layer (hybrid, cross-platform).
 *
 * Private keys are protected in one of these ways, reported transparently:
 *
 *   - `os-sealed` — keys are encrypted at rest by the OS secure storage via
 *     Electron `safeStorage` (Windows DPAPI, macOS Keychain, Linux libsecret).
 *     On Windows/macOS the OS vault itself is TPM / Secure-Enclave aware, so on
 *     modern hardware the key material is additionally protected by the
 *     platform's secure element.
 *   - `hardware-tpm` / `hardware-se` — reserved for a dedicated hardware backend
 *     (Linux PKCS#11 over tpm2-pkcs11, Windows CNG platform crypto provider,
 *     macOS Secure Enclave) where the private key never leaves the TPM/SE.
 *   - `plaintext` — no OS vault is available; the app must warn prominently and
 *     never silently store unencrypted key material in production.
 */
import { safeStorage } from 'electron';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { existsSync } from 'node:fs';

const execFileAsync = promisify(execFile);

export type KeyProtection = 'hardware-tpm' | 'hardware-se' | 'os-sealed' | 'plaintext';

export interface KeyProtectionInfo {
  kind: KeyProtection;
  /** True when Electron safeStorage can encrypt data on this host. */
  osSealingAvailable: boolean;
  /** True when a TPM is detected on this host (Linux only today). */
  tpmDetected: boolean;
  /** Short human-readable explanation shown in the Settings UI. */
  note: string;
}

/** Best-effort TPM detection on Linux (/dev/tpm0 or tpm2_getcap). */
async function detectLinuxTpm(): Promise<boolean> {
  if (existsSync('/dev/tpm0') || existsSync('/dev/tpmrm0')) return true;
  try {
    const { stdout } = await execFileAsync('tpm2_getcap', ['properties-fixed']);
    return stdout.includes('TPM2_PT_FAMILY_INDICATOR');
  } catch {
    return false;
  }
}

/** Detect the effective key protection on the current host. */
export async function detectKeyProtection(): Promise<KeyProtectionInfo> {
  const osSealingAvailable = safeStorage.isEncryptionAvailable();
  const tpmDetected = process.platform === 'linux' ? await detectLinuxTpm() : false;

  let kind: KeyProtection;
  let note: string;

  if (process.platform === 'linux') {
    if (osSealingAvailable) {
      kind = 'os-sealed';
      note = tpmDetected
        ? 'OS-sealed via the desktop keyring (libsecret), with a TPM present on this host.'
        : 'OS-sealed via the desktop keyring (libsecret).';
    } else {
      kind = 'plaintext';
      note =
        'No OS keyring is available, so private keys are NOT encrypted at rest. ' +
        'Unlock a keyring (e.g. GNOME Keyring or KWallet) to enable encryption.';
    }
  } else if (process.platform === 'win32') {
    kind = osSealingAvailable ? 'os-sealed' : 'plaintext';
    note = osSealingAvailable
      ? 'OS-sealed via Windows DPAPI (TPM-aware on Windows 10/11 with a TPM).'
      : 'Windows DPAPI is unavailable — private keys are not encrypted at rest.';
  } else if (process.platform === 'darwin') {
    kind = osSealingAvailable ? 'os-sealed' : 'plaintext';
    note = osSealingAvailable
      ? 'OS-sealed via the macOS Keychain (Secure Enclave backed on Apple silicon).'
      : 'macOS Keychain is unavailable — private keys are not encrypted at rest.';
  } else {
    kind = osSealingAvailable ? 'os-sealed' : 'plaintext';
    note = osSealingAvailable
      ? 'OS-sealed via Electron safeStorage.'
      : 'No OS vault is available — private keys are not encrypted at rest.';
  }

  return { kind, osSealingAvailable, tpmDetected, note };
}
