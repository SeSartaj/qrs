/**
 * Default (Node) crypto registry.
 *
 * This module is the ONLY place that assembles the Node built-in crypto providers,
 * so it is the only module that pulls in `node:crypto`. The portable/browser entry
 * (`index.browser.js`) never imports this module — it uses the WebCrypto providers
 * instead.
 */
import { EcdsaP256Provider } from './ecdsaP256.js';
import { Ed25519Provider } from './ed25519.js';
import { CryptoRegistry } from './registry.js';

/** The two reference algorithms the package supports out of the box (Node crypto). */
export function createDefaultCryptoRegistry(): CryptoRegistry {
  return new CryptoRegistry([new Ed25519Provider(), new EcdsaP256Provider()]);
}
