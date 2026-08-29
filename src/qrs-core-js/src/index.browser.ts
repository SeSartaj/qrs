/**
 * Browser / React Native entry point.
 *
 * This entry re-exports the fully portable surface of the package and excludes every
 * Node-only module (the `node:crypto` providers, `node:fs` file stores, the
 * terminal provider and the CLI). Bundlers resolve this file automatically via the
 * `browser` / `react-native` conditions in `package.json`, or it can be imported
 * explicitly with `import { ... } from 'qrs-core/browser'`.
 *
 * Defaults used by `createQrsWeb()`:
 *   - crypto: WebCrypto providers (`globalThis.crypto.subtle`)
 *   - storage: in-memory
 *   - context: DummyContextProvider (never prompts)
 *   - clock: a wall-clock implementation based on `Date.now()`
 */

/* Core types and errors */
export * from './types.js';
export {
  QrsError,
  QrsParseError,
  QrsUnsupportedError,
  QrsValidationError,
  QrsCryptoError,
  QrsNotFoundError,
  QrsAuthorizationError,
} from './errors.js';

/* Identifiers / hashing (portable, no Node imports) */
export { sha256, sha384, sha3_512, hashFor, isHashAlgorithm, HASH_ALGORITHMS, truncSha256, toHex, fromHex, toBase64Url, fromBase64Url, randomId, randomBytes, ID_BYTES, type HashAlgorithm } from './id.js';

/* Attachment field semantics */
export { ATTACHMENT_HASH_HEX, attachmentContentType, attachmentReference, verifyAttachmentReference, type AttachmentReference } from './fields/attachmentField.js';

/* Canonical CBOR */
export { cborEncode, cborDecode, compareBytes, decodeMap, type CborKey, type CborMap, type CborValue } from './cbor/canonical.js';

/* Crypto (WebCrypto only — no node:crypto) */
export type { PublicJwk, PrivateJwk, KeyPairMaterial } from './crypto/jwk.js';
export { canonicalPublicKeyBytes, assertPublicJwk, assertPrivateJwk } from './crypto/jwk.js';
export type { ICryptoProvider, GeneratedKeyPair } from './crypto/providers.js';
export { computeKeyId, COSE_ALGORITHM_TO_ID, algorithmFromCoseAlgorithm } from './crypto/providers.js';
export { CryptoRegistry } from './crypto/registry.js';
export { WebCryptoEd25519Provider, WebCryptoEcdsaP256Provider, createWebCryptoCryptoRegistry } from './crypto/webcrypto.js';

/* COSE */
export { signCoseSign1, decodeCoseSign1, verifyCoseSign1, COSE_HDR_ALG, COSE_HDR_KID, COSE_HDR_TCERT_NUMBER, type CoseSign1 } from './cose/cose.js';

/* Signed objects */
export {
  buildSignedObject,
  parseSignedObject,
  verifyParsedSignedObject,
  tcertIdOf,
  tcertHashOf,
  sdocIdOf,
  splitTcertId,
  tcertNumberOf,
  type ParsedSignedObject,
} from './signedObject/signedObject.js';
export {
  OBJECT_DATA_SCHEMAS,
  validateObjectData,
  assertValidObjectData,
  isSignedObjectType,
  isFieldType,
  isAction,
  isRevocationType,
  FIELD_TYPES,
  ACTIONS,
  REVOCATION_TYPES,
  SIGNED_OBJECT_TYPES,
} from './signedObject/schemas.js';

/* Fields */
export type {
  FieldSchema,
  FieldResult,
  FieldResultState,
  ContextRequirement,
  FieldInputError,
  VerificationContext,
  IFieldEngine,
} from './fields/types.js';
export { readNumberRule, readBoolRule, readStringArrayRule } from './fields/types.js';
export { isBoundField, effectiveBinding, isStrippedBinding, BINDING_FIELD_TYPES } from './fields/types.js';
export { FieldRegistry } from './fields/registry.js';
export {
  createDefaultFieldRegistry,
  TextField,
  TextareaField,
  SelectField,
  SelectV2Field,
  NumberField,
  DateField,
  DateTimeField,
  DatetimeEpochField,
  LocationField,
  SecretInputField,
  AttachmentField,
} from './fields/index.js';
export { haversineDistance, MICRODEGREES } from './fields/locationField.js';
export { canonicalDecimalString } from './fields/numberField.js';
export { codePointLength } from './fields/textField.js';
export { isValidCalendarDate } from './fields/dateField.js';
export { isValidUtcDatetime } from './fields/datetimeField.js';
export { evaluateDateExpressions, type DateRuleInput, type DateRuleResult } from './fields/dateRules.js';

/* Transfer envelope (QR medium between devices) */
export {
  encodeTransferPayload,
  decodeTransferPayload,
  encodeBundle,
  decodeBundle,
  encodeQrsFile,
  encodeQrsBundleFile,
  decodeQrsFile,
  QRS_FILE_EXTENSION,
  TRANSFER_SCHEME,
  TRANSFER_VERSION,
  type TransferObjectType,
  type DecodedTransferPayload,
  type DecodedBundle,
  type BundleObject,
  type DecodedQrsFile,
} from './transfer.js';

/* Context (portable subset — terminal provider is Node-only) */
export type { IContextProvider } from './context/context.js';
export { adaptProvider } from './context/context.js';
export { DummyContextProvider, type DummyContextOptions } from './context/dummyContext.js';

/* Storage (in-memory only — file stores are Node-only) */
export type {
  IPrivateKeyStore,
  IPublicKeyStore,
  ICertificateStore,
  IDocumentStore,
  IRevocationStore,
  ITrustStore,
  IEndpointConfigStore,
  AttestationRecord,
  RevocationEntry,
  BlockEntry,
  SdocStatementEntry,
} from './storage/stores.js';
export {
  InMemoryPrivateKeyStore,
  InMemoryPublicKeyStore,
  InMemoryCertificateStore,
  InMemoryDocumentStore,
  InMemoryRevocationStore,
  InMemoryTrustStore,
  InMemoryEndpointConfigStore,
  createInMemoryStores,
} from './storage/memoryStores.js';

/* Services */
export type { IClock } from './services/clock.js';
export { SystemClock } from './services/clock.js';
export type { ServiceDeps } from './services/deps.js';
export { CertificateService, type CreateTcertParams, type CreateTcertResult } from './services/certificateService.js';
export { EndpointService, normalizeEndpoint, type EndpointServiceDeps } from './services/endpointService.js';
export { SigningService, type IssueSdocParams, type IssueSdocResult } from './services/signingService.js';
export {
  VerificationService,
  type VerificationResult,
  type VerifyOptions,
  type VerificationServiceDeps,
} from './services/verificationService.js';
export {
  TrustService,
  type TrustResolution,
  type AttestParams,
  type AddTcertParams,
  type ComponentState,
} from './services/trustService.js';
export {
  RevocationService,
  type RevokeTcertParams,
  type RevokeKeyParams,
  type BlockSdocParams,
  type RevocationCheck,
} from './services/revocationService.js';
export {
  buildStatement,
  parseStatement,
  verifyStatement,
  type StatementTarget,
  type ParsedStatement,
} from './services/statement.js';
export {
  buildAttachment,
  parseAttachment,
  verifyAttachment,
  attachmentIdOf,
  ATTACHMENT_ID_HEX,
  AttachmentService,
  type BuildAttachmentParams,
  type BuiltAttachment,
  type ParsedAttachment,
} from './services/attachment.js';
export {
  OnlineService,
  type ImportedStatement,
} from './services/onlineService.js';

/* Runtime */
export { QrsRuntime, type QrsDependencies } from './runtimeBase.js';
export { createQrsWeb } from './runtimeWeb.js';
