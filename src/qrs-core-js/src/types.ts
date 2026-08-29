/**
 * Core protocol constants and identifier/type aliases for the SDoc Verification Protocol v1.
 *
 * These are the shared vocabulary used across the whole package. Keeping them in one
 * module avoids circular imports and gives a single place where the protocol's type
 * system is defined.
 */

/** Protocol version implemented by this package. */
export const PROTOCOL_VERSION = 1 as const;
export type ProtocolVersion = typeof PROTOCOL_VERSION;

/** The four signed-object types defined by protocol version 1. */
export type SignedObjectType = 'tcert' | 'sdoc' | 'statement' | 'attachment';

/** Algorithms supported by the reference implementation (both produce small signatures). */
export type AlgorithmId = 'Ed25519' | 'ECDSA-P256';

/** Declarative field types understood by the reference field engines. */
export type FieldType =
  | 'text'
  | 'textarea'
  | 'select'
  | 'selectv2'
  | 'number'
  | 'date'
  | 'datetime'
  | 'datetimeEpoch'
  | 'location'
  | 'secretInput'
  | 'attachment';

/** Statement actions defined by protocol version 1. This set is closed. */
export type Action = 'attest' | 'addTcert' | 'revokeAttestation' | 'revokeTcert' | 'blockSdoc' | 'unblockSdoc';

/** Revocation scope for a TCert revocation statement. */
export type RevocationType = 'prospective' | 'retrospective';

/**
 * Identifier types. All identifiers are hex strings to keep them simple, stable
 * and easy to store in any backend.
 */
export type KeyId = string; // hex, 32 chars (128-bit truncated SHA-256 of canonical public key)
export type TcertId = string; // `${keyId}:${certificateNumber}`
export type SdocId = string; // hex, 32 chars (128-bit truncated SHA-256 of the signed SDoc)
export type StatementId = string; // hex, 32 chars (random)

/** A geographic point used by the location field. */
export interface GeoPoint {
  lat: number; // degrees, -90..90
  lon: number; // degrees, -180..180
}
