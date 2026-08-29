/**
 * Typed error hierarchy for the package.
 *
 * Every error thrown by the library extends {@link QrsError} so that consumers can
 * catch a single base type and still distinguish specific failure modes.
 */

export class QrsError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** Raised when bytes cannot be parsed as a valid protocol object. */
export class QrsParseError extends QrsError {}

/** Raised when an unsupported version, algorithm or object type is encountered. */
export class QrsUnsupportedError extends QrsError {}

/** Raised when a value fails validation (bad field input, bad object data, ...). */
export class QrsValidationError extends QrsError {}

/** Raised for cryptographic failures (bad key material, broken signature). */
export class QrsCryptoError extends QrsError {}

/** Raised when a requested object (key, TCert, SDoc, ...) is not found. */
export class QrsNotFoundError extends QrsError {}

/** Raised when a statement signer is not authorized for an action. */
export class QrsAuthorizationError extends QrsError {}
