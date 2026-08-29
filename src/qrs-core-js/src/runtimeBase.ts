/**
 * The runtime container (portable core).
 *
 * {@link QrsRuntime} wires the services together from a fully injectable dependency
 * bundle. It imports no Node-only modules, so it can be used in Node, browsers and
 * React Native. The only environment-specific choice is *which crypto registry* is
 * used — see `runtime.ts` (Node providers) and `runtimeWeb.ts` (WebCrypto providers).
 */
import type { IContextProvider } from './context/context.js';
import type { CryptoRegistry } from './crypto/registry.js';
import type { FieldRegistry } from './fields/registry.js';
import type {
  ICertificateStore,
  IDocumentStore,
  IEndpointConfigStore,
  IPrivateKeyStore,
  IPublicKeyStore,
  IRevocationStore,
  ITrustStore,
} from './storage/stores.js';
import { InMemoryEndpointConfigStore } from './storage/memoryStores.js';
import { CertificateService } from './services/certificateService.js';
import { EndpointService } from './services/endpointService.js';
import type { IClock } from './services/clock.js';
import type { ServiceDeps } from './services/deps.js';
import { AttachmentService } from './services/attachment.js';
import { OnlineService } from './services/onlineService.js';
import { RevocationService } from './services/revocationService.js';
import { SigningService } from './services/signingService.js';
import { TrustService } from './services/trustService.js';
import { VerificationService } from './services/verificationService.js';

/** Overrides accepted by `createQrs` / `createQrsWeb`. */
export interface QrsDependencies {
  cryptoRegistry?: CryptoRegistry;
  fieldRegistry?: FieldRegistry;
  privateKeyStore?: IPrivateKeyStore;
  publicKeyStore?: IPublicKeyStore;
  certificateStore?: ICertificateStore;
  documentStore?: IDocumentStore;
  revocationStore?: IRevocationStore;
  trustStore?: ITrustStore;
  endpointConfigStore?: IEndpointConfigStore;
  contextProvider?: IContextProvider;
  clock?: IClock;
}

export class QrsRuntime {
  readonly deps: ServiceDeps;
  readonly certificates: CertificateService;
  readonly signing: SigningService;
  readonly trust: TrustService;
  readonly revocation: RevocationService;
  readonly verification: VerificationService;
  readonly attachments: AttachmentService;
  readonly online: OnlineService;
  readonly endpoints: EndpointService;

  constructor(deps: ServiceDeps) {
    this.deps = deps;
    this.trust = new TrustService(deps);
    this.revocation = new RevocationService(deps);
    this.certificates = new CertificateService(deps);
    this.signing = new SigningService(deps);
    this.attachments = new AttachmentService(deps);
    this.online = new OnlineService(deps);
    this.endpoints = new EndpointService({
      certificateStore: deps.certificateStore,
      endpointConfigStore: deps.endpointConfigStore,
      trustStore: deps.trustStore,
    });
    this.verification = new VerificationService({
      cryptoRegistry: deps.cryptoRegistry,
      fieldRegistry: deps.fieldRegistry,
      certificateStore: deps.certificateStore,
      endpointConfigStore: deps.endpointConfigStore,
      contextProvider: deps.contextProvider,
      clock: deps.clock,
      trustService: this.trust,
      revocationService: this.revocation,
    });
  }
}
