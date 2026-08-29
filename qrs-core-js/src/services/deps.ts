/**
 * The dependency bundle shared by all services. Services depend on this interface,
 * never on concrete implementations — this is what makes the whole package
 * inversion-of-control friendly: swap any store or provider and the services are
 * unchanged.
 */
import type { IContextProvider } from '../context/context.js';
import type { CryptoRegistry } from '../crypto/registry.js';
import type { FieldRegistry } from '../fields/registry.js';
import type {
  ICertificateStore,
  IDocumentStore,
  IEndpointConfigStore,
  IPrivateKeyStore,
  IPublicKeyStore,
  IRevocationStore,
  ITrustStore,
} from '../storage/stores.js';
import type { IClock } from './clock.js';

export interface ServiceDeps {
  cryptoRegistry: CryptoRegistry;
  fieldRegistry: FieldRegistry;
  privateKeyStore: IPrivateKeyStore;
  publicKeyStore: IPublicKeyStore;
  certificateStore: ICertificateStore;
  documentStore: IDocumentStore;
  revocationStore: IRevocationStore;
  trustStore: ITrustStore;
  endpointConfigStore: IEndpointConfigStore;
  contextProvider: IContextProvider;
  clock: IClock;
}
