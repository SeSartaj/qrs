/**
 * Statement helper: the unified signed authority action (attest, revoke, block, ...).
 *
 * A Statement is a signed object of type `statement`. Its data map is:
 *   { statementId, action, target, issuedAt, validity?, reason?, revocationType?, claims? }
 *
 * `target` is a map with a `kind` discriminator:
 *   { kind: 'tcert', keyId, certificateNumber }
 *   { kind: 'key',   keyId }
 *   { kind: 'sdoc',  sdocId }
 */
import { cborEncode } from '../cbor/canonical.js';
import type { PrivateJwk, PublicJwk } from '../crypto/jwk.js';
import type { GeneratedKeyPair, ICryptoProvider } from '../crypto/providers.js';
import { QrsParseError } from '../errors.js';
import { fromHex, randomId, toHex } from '../id.js';
import {
  buildSignedObject,
  parseSignedObject,
  verifyParsedSignedObject,
  type ParsedSignedObject,
} from '../signedObject/signedObject.js';
import { isAction, isRevocationType } from '../signedObject/schemas.js';
import type { Action, RevocationType, StatementId } from '../types.js';

export type StatementTarget =
  | { kind: 'tcert'; keyId: string; certificateNumber: number; tcertHash?: string }
  | { kind: 'key'; keyId: string }
  | { kind: 'sdoc'; sdocId: string };

export interface StatementOptions {
  reason?: string;
  revocationType?: RevocationType;
  claims?: Record<string, unknown>;
  validity?: { validAfter?: number; validBefore?: number };
}

export interface BuiltStatement {
  statementId: StatementId;
  bytes: Uint8Array;
  parsed: ParsedSignedObject;
}

export interface ParsedStatement {
  statementId: StatementId;
  action: Action;
  target: StatementTarget;
  issuedAt: number;
  validity?: { validAfter?: number; validBefore?: number };
  reason?: string;
  revocationType?: RevocationType;
  claims?: Record<string, unknown>;
  signerKeyId: string;
  parsed: ParsedSignedObject;
  bytes: Uint8Array;
}

export function encodeTarget(target: StatementTarget): Record<string, unknown> {
  switch (target.kind) {
    case 'tcert':
      return {
        kind: 'tcert',
        keyId: fromHex(target.keyId),
        certificateNumber: target.certificateNumber,
        ...(target.tcertHash ? { tcertHash: target.tcertHash } : {}),
      };
    case 'key':
      return { kind: 'key', keyId: fromHex(target.keyId) };
    case 'sdoc':
      return { kind: 'sdoc', sdocId: fromHex(target.sdocId) };
  }
}

export function decodeTarget(raw: Record<string, unknown>): StatementTarget {
  const kind = raw.kind;
  if (kind === 'tcert' && raw.keyId instanceof Uint8Array && typeof raw.certificateNumber === 'number') {
    const tcertHash = typeof raw.tcertHash === 'string' && raw.tcertHash ? raw.tcertHash : undefined;
    return { kind: 'tcert', keyId: toHex(raw.keyId), certificateNumber: raw.certificateNumber, tcertHash };
  }
  if (kind === 'key' && raw.keyId instanceof Uint8Array) {
    return { kind: 'key', keyId: toHex(raw.keyId) };
  }
  if (kind === 'sdoc' && raw.sdocId instanceof Uint8Array) {
    return { kind: 'sdoc', sdocId: toHex(raw.sdocId) };
  }
  throw new QrsParseError('Malformed statement target');
}

export async function buildStatement(
  action: Action,
  target: StatementTarget,
  issuedAt: number,
  options: StatementOptions,
  keyPair: GeneratedKeyPair,
  provider: ICryptoProvider
): Promise<BuiltStatement> {
  const statementId = randomId();
  const data: Record<string, unknown> = {
    statementId: fromHex(statementId),
    action,
    target: encodeTarget(target),
    issuedAt,
  };
  if (options.reason !== undefined) data.reason = options.reason;
  if (options.revocationType !== undefined) data.revocationType = options.revocationType;
  if (options.claims !== undefined) data.claims = options.claims;
  if (options.validity !== undefined) data.validity = options.validity;

  const bytes = await buildSignedObject('statement', data, keyPair, provider);
  const parsed = parseSignedObject(bytes);
  return { statementId, bytes, parsed };
}

export function parseStatement(bytes: Uint8Array): ParsedStatement {
  const parsed = parseSignedObject(bytes);
  if (parsed.type !== 'statement') throw new QrsParseError('Not a statement');
  const d = parsed.data;
  const action = d.action;
  if (typeof action !== 'string' || !isAction(action)) throw new QrsParseError('Unknown statement action');
  if (typeof d.target !== 'object' || d.target === null) throw new QrsParseError('Statement missing target');
  const target = decodeTarget(d.target as Record<string, unknown>);
  if (typeof d.issuedAt !== 'number') throw new QrsParseError('Statement missing issuedAt');
  const revocationType = d.revocationType;
  if (revocationType !== undefined && (typeof revocationType !== 'string' || !isRevocationType(revocationType))) {
    throw new QrsParseError('Invalid revocationType');
  }
  return {
    statementId: toHex(d.statementId as Uint8Array),
    action,
    target,
    issuedAt: d.issuedAt,
    validity: d.validity as { validAfter?: number; validBefore?: number } | undefined,
    reason: typeof d.reason === 'string' ? d.reason : undefined,
    revocationType: revocationType as RevocationType | undefined,
    claims: d.claims as Record<string, unknown> | undefined,
    signerKeyId: parsed.signerKeyId,
    parsed,
    bytes,
  };
}

/** Verify a statement with the signer's public key (cryptographic check only). */
export async function verifyStatement(
  parsed: ParsedSignedObject,
  publicJwk: PublicJwk,
  provider: ICryptoProvider
): Promise<boolean> {
  return verifyParsedSignedObject(parsed, provider, publicJwk);
}
