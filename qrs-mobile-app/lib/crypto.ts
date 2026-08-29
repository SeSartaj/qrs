/**
 * Crypto environment setup.
 *
 * qrs-core's web runtime (`createQrsWeb`) uses the standard Web Crypto API
 * (`globalThis.crypto.subtle`), which is built into browsers (and Expo web).
 * React Native's Hermes engine does not ship `crypto.subtle`, so on native we
 * polyfill it with `react-native-quick-crypto` (audited, well-maintained native
 * crypto). `react-native-get-random-values` provides `crypto.getRandomValues`.
 */
import 'react-native-get-random-values';
import { Platform } from 'react-native';

function installQuickCrypto(): void {
  const g = globalThis as unknown as { crypto?: { subtle?: unknown } };
  // On web the native crypto already exists — never overwrite it.
  if (Platform.OS === 'web') return;
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const qcrypto = require('react-native-quick-crypto') as {
      install?: () => void;
      subtle?: unknown;
    };
    // quick-crypto v1 exposes `subtle` and an `install()` global patcher; it
    // does not expose the older `webcrypto.subtle` shape.
    if (typeof qcrypto.install === 'function') qcrypto.install();
    if (!g.crypto?.subtle && qcrypto.subtle) {
      if (!g.crypto) (g as { crypto: object }).crypto = {};
      (g.crypto as { subtle: unknown }).subtle = qcrypto.subtle;
    }
    if (!g.crypto?.subtle) throw new Error('quick-crypto loaded without crypto.subtle');
  } catch (error) {
    // Verification of Ed25519/ECDSA needs crypto.subtle; surface a clear message.
    console.warn(
      'react-native-quick-crypto is unavailable — cryptographic verification will not work on this device.',
      error,
    );
  }
}

installQuickCrypto();
