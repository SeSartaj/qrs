/**
 * The crypto-provider registry (portable, no Node imports).
 *
 * Providers are looked up by algorithm id, which is how the rest of the package
 * stays algorithm-agnostic (open/closed principle). The default Node providers
 * live in `nodeRegistry.js`; the WebCrypto providers live in `webcrypto.js`.
 */
import { QrsUnsupportedError } from '../errors.js';
import type { AlgorithmId } from '../types.js';
import type { ICryptoProvider } from './providers.js';

export class CryptoRegistry {
  private readonly providers = new Map<AlgorithmId, ICryptoProvider>();

  constructor(providers: ICryptoProvider[] = []) {
    for (const provider of providers) this.register(provider);
  }

  register(provider: ICryptoProvider): this {
    this.providers.set(provider.algorithm, provider);
    return this;
  }

  get(algorithm: AlgorithmId): ICryptoProvider {
    const provider = this.providers.get(algorithm);
    if (!provider) {
      throw new QrsUnsupportedError(`Unsupported algorithm: ${algorithm}`);
    }
    return provider;
  }

  has(algorithm: AlgorithmId): boolean {
    return this.providers.has(algorithm);
  }

  list(): ICryptoProvider[] {
    return [...this.providers.values()];
  }
}
