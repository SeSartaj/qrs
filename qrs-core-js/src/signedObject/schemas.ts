/**
 * Static data schemas for the three signed-object types (TCert, SDoc, Statement).
 *
 * Every signed object's decoded data MUST conform to the static schema of its type
 * before the object is accepted. This is the protocol's "each signed object type has
 * a static schema" guarantee: the decoder never guesses, it validates against a known
 * shape.
 */
import { QrsParseError, QrsUnsupportedError } from '../errors.js';
import type { Action, FieldType, RevocationType, SignedObjectType } from '../types.js';

export type FieldKind = 'text' | 'int' | 'bytes' | 'map' | 'array' | 'bool';

export interface DataFieldSpec {
  kind: FieldKind;
  required?: boolean;
}

export interface ObjectDataSchema {
  fields: Record<string, DataFieldSpec>;
}

export const OBJECT_DATA_SCHEMAS: Record<SignedObjectType, ObjectDataSchema> = {
  tcert: {
    fields: {
      keyId: { kind: 'bytes', required: true },
      certificateNumber: { kind: 'int', required: true },
      algorithm: { kind: 'text', required: true },
      publicKey: { kind: 'map', required: true },
      identity: { kind: 'map', required: true },
      // Schema is optional: a TCert without one is a meta/CA certificate that
      // issues statements (attestation/revocation/blocking) rather than SDocs.
      schema: { kind: 'array' },
      hashAlgorithm: { kind: 'text' },
      validity: { kind: 'map' },
      metadata: { kind: 'map' },
      onlineEndpoint: { kind: 'text' },
    },
  },
  sdoc: {
    fields: {
      issuedAt: { kind: 'int', required: true },
      // Values are stored as a schema-indexed array (no field names/labels).
      fields: { kind: 'array', required: true },
    },
  },
  statement: {
    fields: {
      statementId: { kind: 'bytes', required: true },
      action: { kind: 'text', required: true },
      target: { kind: 'map', required: true },
      issuedAt: { kind: 'int', required: true },
      validity: { kind: 'map' },
      reason: { kind: 'text' },
      revocationType: { kind: 'text' },
      claims: { kind: 'map' },
    },
  },
  attachment: {
    fields: {
      // Content-addressed id (truncated content hash) — this is the handle a
      // verifier uses to fetch the attachment from a distribution server.
      id: { kind: 'text', required: true },
      contentType: { kind: 'text', required: true },
      contentHash: { kind: 'text', required: true },
      content: { kind: 'bytes', required: true },
      issuedAt: { kind: 'int', required: true },
    },
  },
};

/** Signed-object types governed by an app-defined static schema (not a TCert schema). */
export const STATIC_SIGNED_OBJECT_TYPES: readonly SignedObjectType[] = ['statement', 'attachment'];

export const SIGNED_OBJECT_TYPES: readonly SignedObjectType[] = ['tcert', 'sdoc', 'statement', 'attachment'];

export function isSignedObjectType(value: unknown): value is SignedObjectType {
  return SIGNED_OBJECT_TYPES.includes(value as SignedObjectType);
}

export const FIELD_TYPES: readonly FieldType[] = [
  'text',
  'textarea',
  'select',
  'selectv2',
  'number',
  'date',
  'datetime',
  'datetimeEpoch',
  'location',
  'secretInput',
  'attachment',
];

export function isFieldType(value: unknown): value is FieldType {
  return FIELD_TYPES.includes(value as FieldType);
}

export const ACTIONS: readonly Action[] = ['attest', 'addTcert', 'revokeAttestation', 'revokeTcert', 'blockSdoc', 'unblockSdoc'];

export function isAction(value: unknown): value is Action {
  return ACTIONS.includes(value as Action);
}

export const REVOCATION_TYPES: readonly RevocationType[] = ['prospective', 'retrospective'];

export function isRevocationType(value: unknown): value is RevocationType {
  return REVOCATION_TYPES.includes(value as RevocationType);
}

function checkKind(value: unknown, spec: DataFieldSpec): boolean {
  switch (spec.kind) {
    case 'text':
      return typeof value === 'string';
    case 'int':
      return typeof value === 'number' && Number.isInteger(value);
    case 'bytes':
      return value instanceof Uint8Array;
    case 'map':
      return typeof value === 'object' && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array);
    case 'array':
      return Array.isArray(value);
    case 'bool':
      return typeof value === 'boolean';
    default:
      return false;
  }
}

/**
 * Validate decoded object data against the static schema of its type.
 * Returns a list of human-readable errors (empty when valid).
 */
export function validateObjectData(type: SignedObjectType, data: unknown): string[] {
  const schema = OBJECT_DATA_SCHEMAS[type];
  if (!schema) throw new QrsUnsupportedError(`No schema for object type ${type}`);
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    return ['object data must be a map'];
  }
  const record = data as Record<string, unknown>;
  const errors: string[] = [];
  for (const [name, spec] of Object.entries(schema.fields)) {
    const present = name in record;
    if (!present) {
      if (spec.required) errors.push(`missing required field '${name}'`);
      continue;
    }
    if (!checkKind(record[name], spec)) {
      errors.push(`field '${name}' must be a ${spec.kind}`);
    }
  }
  return errors;
}

/** Assert that decoded object data conforms to its static schema or throw. */
export function assertValidObjectData(type: SignedObjectType, data: unknown): void {
  const errors = validateObjectData(type, data);
  if (errors.length > 0) {
    throw new QrsParseError(`Invalid ${type} data: ${errors.join('; ')}`);
  }
}
