/**
 * RevocationService: revocation, blocking, and lifecycle checks.
 *
 * Revocation works through signed statements (offline-friendly):
 *   - `revokeTcert` targets a TCert (prospective/retrospective) or a key (target
 *     kind `key`, which invalidates all TCerts of that key).
 *   - `blockSdoc` / `unblockSdoc` target a single SDoc by its id.
 *
 * Checks distinguish prospective vs retrospective, and always evaluate key
 * revocation before TCert revocation.
 */
import type { PublicJwk } from '../crypto/jwk.js';
import { QrsAuthorizationError, QrsCryptoError, QrsNotFoundError } from '../errors.js';
import { splitTcertId, tcertIdOf } from '../signedObject/signedObject.js';
import { parseSignedObject, tcertNumberOf } from '../signedObject/signedObject.js';
import type { KeyId, RevocationType, SdocId, StatementId, TcertId } from '../types.js';
import type { ServiceDeps } from './deps.js';
import { buildStatement, verifyStatement } from './statement.js';
import type { ComponentState } from './trustService.js';

export interface RevocationCheck {
  state: ComponentState;
  message?: string;
}

export interface RevokeTcertParams {
  signerKeyId: KeyId;
  targetTcertId: TcertId;
  type: RevocationType;
  reason?: string;
  issuedAt?: number;
}

export interface RevokeKeyParams {
  signerKeyId: KeyId;
  targetKeyId: KeyId;
  reason?: string;
  issuedAt?: number;
}
export interface RevokeAttestationParams {
  caTcertId: TcertId;
  targetTcertId: TcertId;
  reason?: string;
  issuedAt?: number;
}

export interface BlockSdocParams {
  signerKeyId: KeyId;
  targetSdocId: SdocId;
  reason?: string;
  issuedAt?: number;
}

export interface StatementResult {
  statementId: StatementId;
  bytes: Uint8Array;
}

export class RevocationService {
  constructor(private readonly deps: ServiceDeps) {}

  /** Revoke this CA's attestation without revoking the target TCert itself. */
  async revokeAttestation(params: RevokeAttestationParams): Promise<StatementResult> {
    const ca = splitTcertId(params.caTcertId);
    const target = splitTcertId(params.targetTcertId);
    const attestations = await this.deps.trustStore.getAttestations(params.targetTcertId);
    if (!attestations.some((att) => att.caTcertId === params.caTcertId)) {
      throw new QrsAuthorizationError('This CA has not attested the target TCert');
    }
    const issuedAt = params.issuedAt ?? this.deps.clock.now();
    const built = await this.signStatement(
      ca.keyId,
      'revokeAttestation',
      { kind: 'tcert', keyId: target.keyId, certificateNumber: target.certificateNumber },
      issuedAt,
      { reason: params.reason, revocationType: 'prospective' }
    );
    await this.deps.revocationStore.addRevokedAttestation(params.targetTcertId, params.caTcertId, {
      type: 'prospective', issuedAt, reason: params.reason, byKeyId: ca.keyId,
      byTcertId: params.caTcertId, statementBytes: built.bytes,
    });
    return built;
  }

  /** Revoke a TCert (prospective or retrospective). */
  async revokeTcert(params: RevokeTcertParams): Promise<StatementResult> {
    const target = splitTcertId(params.targetTcertId);
    const authorized =
      params.signerKeyId === target.keyId ||
      (await this.isAuthorizedCa(params.signerKeyId, params.targetTcertId));
    if (!authorized) {
      throw new QrsAuthorizationError('Signer is not authorized to revoke this TCert');
    }
    const issuedAt = params.issuedAt ?? this.deps.clock.now();
    const built = await this.signStatement(
      params.signerKeyId,
      'revokeTcert',
      { kind: 'tcert', keyId: target.keyId, certificateNumber: target.certificateNumber },
      issuedAt,
      { reason: params.reason, revocationType: params.type }
    );
    await this.deps.revocationStore.addRevokedTcert(params.targetTcertId, {
      type: params.type,
      issuedAt,
      reason: params.reason,
      // Attribute the revocation to the signing CA/issuer so per-CA revocation
      // (one CA revokes, another still trusts) is representable and transparent.
      byKeyId: params.signerKeyId,
      statementBytes: built.bytes,
    });
    return built;
  }

  /** Revoke a key: invalidates all TCerts derived from it. */
  async revokeKey(params: RevokeKeyParams): Promise<StatementResult> {
    if (params.signerKeyId !== params.targetKeyId) {
      throw new QrsAuthorizationError('Only the key owner may revoke its own key');
    }
    const issuedAt = params.issuedAt ?? this.deps.clock.now();
    const built = await this.signStatement(
      params.signerKeyId,
      'revokeTcert',
      { kind: 'key', keyId: params.targetKeyId },
      issuedAt,
      { reason: params.reason, revocationType: 'retrospective' }
    );
    await this.deps.revocationStore.addRevokedKey(params.targetKeyId, {
      type: 'retrospective',
      issuedAt,
      reason: params.reason,
      byKeyId: params.signerKeyId,
      statementBytes: built.bytes,
    });
    return built;
  }

  /** Block one individual SDoc. */
  async blockSdoc(params: BlockSdocParams): Promise<StatementResult> {
    const sdocBytes = await this.deps.documentStore.get(params.targetSdocId);
    if (!sdocBytes) throw new QrsNotFoundError(`SDoc not found: ${params.targetSdocId}`);
    const parsed = parseSignedObject(sdocBytes);
    const tcertKeyId = parsed.signerKeyId;
    const tcertId = tcertIdOf(tcertKeyId, tcertNumberOf(parsed));
    const authorized =
      params.signerKeyId === tcertKeyId || (await this.isAuthorizedCa(params.signerKeyId, tcertId));
    if (!authorized) {
      throw new QrsAuthorizationError('Signer is not authorized to block this SDoc');
    }
    const issuedAt = params.issuedAt ?? this.deps.clock.now();
    const built = await this.signStatement(
      params.signerKeyId,
      'blockSdoc',
      { kind: 'sdoc', sdocId: params.targetSdocId },
      issuedAt,
      { reason: params.reason }
    );
    await this.deps.revocationStore.addBlockedSdoc(params.targetSdocId, { issuedAt, reason: params.reason, statementBytes: built.bytes, byKeyId: params.signerKeyId });
    return built;
  }

  /** Reverse a block of an individual SDoc. */
  async unblockSdoc(params: BlockSdocParams): Promise<StatementResult> {
    const sdocBytes = await this.deps.documentStore.get(params.targetSdocId);
    if (!sdocBytes) throw new QrsNotFoundError(`SDoc not found: ${params.targetSdocId}`);
    const parsed = parseSignedObject(sdocBytes);
    const tcertKeyId = parsed.signerKeyId;
    const tcertId = tcertIdOf(tcertKeyId, tcertNumberOf(parsed));
    const authorized =
      params.signerKeyId === tcertKeyId || (await this.isAuthorizedCa(params.signerKeyId, tcertId));
    if (!authorized) throw new QrsAuthorizationError('Signer is not authorized to unblock this SDoc');
    const issuedAt = params.issuedAt ?? this.deps.clock.now();
    const built = await this.signStatement(
      params.signerKeyId,
      'unblockSdoc',
      { kind: 'sdoc', sdocId: params.targetSdocId },
      issuedAt,
      { reason: params.reason }
    );
    await this.deps.revocationStore.removeBlockedSdoc(params.targetSdocId, {
      issuedAt,
      reason: params.reason,
      statementBytes: built.bytes,
      byKeyId: params.signerKeyId,
    });
    return built;
  }

  /** Lifecycle check used by the verification pipeline. */
  async checkRevocation(tcertId: TcertId, keyId: KeyId, issuedAt: number, sdocId: SdocId): Promise<RevocationCheck> {
    const keyEntry = await this.deps.revocationStore.getRevokedKey(keyId);
    if (keyEntry) {
      return { state: 'invalid', message: `issuer key revoked (${keyEntry.reason ?? 'key compromised'})` };
    }
    const tcertEntry = await this.deps.revocationStore.getRevokedTcert(tcertId);
    if (tcertEntry) {
      if (tcertEntry.type === 'retrospective') {
        return { state: 'invalid', message: 'TCert retrospectively revoked' };
      }
      if (issuedAt >= tcertEntry.issuedAt) {
        return { state: 'invalid', message: 'TCert prospectively revoked for documents issued at/after revocation' };
      }
      return { state: 'valid', message: 'document issued before prospective revocation' };
    }
    const block = await this.deps.revocationStore.getBlockedSdoc(sdocId);
    if (block) return { state: 'invalid', message: 'SDoc is blocked' };
    return { state: 'valid' };
  }

  /** Is the signer an authorized CA for the target TCert? */
  async isAuthorizedCa(signerKeyId: KeyId, targetTcertId: TcertId): Promise<boolean> {
    const attestations = await this.deps.trustStore.getAttestations(targetTcertId);
    for (const att of attestations) {
      if (att.caKeyId !== signerKeyId) continue;
      const caBytes = await this.deps.certificateStore.get(att.caTcertId);
      if (!caBytes) continue;
      try {
        parseSignedObject(caBytes);
      } catch {
        continue;
      }
      if (await this.deps.revocationStore.getRevokedTcert(att.caTcertId)) continue;
      if (await this.deps.revocationStore.getRevokedKey(signerKeyId)) continue;
      if (await this.deps.trustStore.isDistrusted(att.caTcertId)) continue;
      if (!(await this.deps.trustStore.isPinned(att.caTcertId)) && !(await this.deps.trustStore.isCa(att.caTcertId))) {
        continue;
      }
      return true;
    }
    return false;
  }

  private async signStatement(
    signerKeyId: KeyId,
    action: 'revokeAttestation' | 'revokeTcert' | 'blockSdoc' | 'unblockSdoc',
    target: { kind: 'tcert'; keyId: string; certificateNumber: number } | { kind: 'key'; keyId: string } | { kind: 'sdoc'; sdocId: string },
    issuedAt: number,
    options: { reason?: string; revocationType?: RevocationType }
  ): Promise<StatementResult> {
    const priv = await this.deps.privateKeyStore.load(signerKeyId);
    if (!priv) throw new QrsNotFoundError(`Signer private key not available: ${signerKeyId}`);
    const pub = await this.deps.publicKeyStore.load(signerKeyId);
    if (!pub) throw new QrsNotFoundError(`Signer public key not found: ${signerKeyId}`);
    const provider = this.deps.cryptoRegistry.get(pub.algorithm);
    const keyPair = { algorithm: pub.algorithm, publicJwk: pub.publicJwk as PublicJwk, privateJwk: priv.privateJwk };
    const built = await buildStatement(action, target, issuedAt, options, keyPair, provider);
    if (!(await verifyStatement(built.parsed, pub.publicJwk, provider))) {
      throw new QrsCryptoError('Statement failed signature verification');
    }
    return { statementId: built.statementId, bytes: built.bytes };
  }
}
