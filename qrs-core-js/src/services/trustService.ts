/**
 * TrustService: pinning, CA roles, attestations, and trust resolution.
 *
 * Trust model (v1): two levels.
 *   - Pinned TCert: the verifier explicitly trusts the TCert.
 *   - CA-issued TCert: a TCert granted CA authority has signed an `attest` statement
 *     about the target TCert.
 *
 * A TCert can be trusted through both mechanisms at once (dual endorsement). The
 * CA is not a special object type — it is an ordinary TCert the verifier has
 * configured with CA authority.
 */
import type { PublicJwk } from '../crypto/jwk.js';
import { QrsAuthorizationError, QrsCryptoError, QrsNotFoundError, QrsValidationError } from '../errors.js';
import { splitTcertId, tcertIdOf } from '../signedObject/signedObject.js';
import { parseSignedObject, verifyParsedSignedObject, type ParsedSignedObject } from '../signedObject/signedObject.js';
import { tcertHashOf } from '../signedObject/signedObject.js';
import type { AlgorithmId, KeyId, TcertId } from '../types.js';
import type { AttestationRecord } from '../storage/stores.js';
import type { ServiceDeps } from './deps.js';
import { buildStatement, parseStatement, verifyStatement } from './statement.js';

export type ComponentState = 'valid' | 'invalid' | 'cannotVerify';

export interface TrustResolution {
  state: ComponentState;
  pinned: boolean;
  ca?: { caTcertId: TcertId; caName?: string };
  message?: string;
}

export interface AttestParams {
  caTcertId: TcertId;
  targetTcertId: TcertId;
  claims?: Record<string, unknown>;
  issuedAt?: number;
}

export interface AddTcertParams extends AttestParams {
  tcertBytes?: Uint8Array;
}

export interface TcertKeyInfo {
  keyId: KeyId;
  algorithm: AlgorithmId;
  publicJwk: PublicJwk;
}

export class TrustService {
  constructor(private readonly deps: ServiceDeps) {}

  /* ---------------- trust configuration ---------------- */

  async pin(tcertId: TcertId): Promise<void> {
    await this.ensureTcert(tcertId);
    await this.deps.trustStore.addPinned(tcertId);
  }

  async unpin(tcertId: TcertId): Promise<void> {
    await this.deps.trustStore.removePinned(tcertId);
  }

  async addCa(tcertId: TcertId): Promise<void> {
    await this.ensureTcert(tcertId);
    await this.deps.trustStore.addCa(tcertId);
  }

  async removeCa(tcertId: TcertId): Promise<void> {
    await this.deps.trustStore.removeCa(tcertId);
  }

  async distrust(tcertId: TcertId): Promise<void> {
    await this.deps.trustStore.addDistrust(tcertId);
  }

  async trustAgain(tcertId: TcertId): Promise<void> {
    await this.deps.trustStore.removeDistrust(tcertId);
  }

  /* ---------------- attestation ---------------- */

  /** A CA signs an attestation about a target TCert (does not modify the target). */
  async attest(params: AttestParams): Promise<{ statementId: string; bytes: Uint8Array }> {
    if (!(await this.deps.trustStore.isCa(params.caTcertId))) {
      throw new QrsAuthorizationError(`TCert ${params.caTcertId} is not configured as a CA`);
    }
    // Prevent duplicate attestations: the same CA must not attest the same target twice.
    const existing = await this.deps.trustStore.getAttestations(params.targetTcertId);
    if (existing.some((r) => r.caTcertId === params.caTcertId)) {
      throw new QrsValidationError(`TCert ${params.targetTcertId} is already attested by ${params.caTcertId}`);
    }
    const ca = await this.keyInfoOf(params.caTcertId);
    const priv = await this.deps.privateKeyStore.load(ca.keyId);
    if (!priv) throw new QrsNotFoundError(`CA private key not available: ${ca.keyId}`);

    const target = splitTcertId(params.targetTcertId);
    // The attestation binds the content hash of the specific TCert being attested.
    const targetBytes = await this.deps.certificateStore.get(params.targetTcertId);
    if (!targetBytes) throw new QrsNotFoundError(`TCert not found: ${params.targetTcertId}`);
    const targetParsed = parseSignedObject(targetBytes);
    const tcertHash = tcertHashOf(targetParsed);
    const issuedAt = params.issuedAt ?? this.deps.clock.now();
    const keyPair = { algorithm: ca.algorithm, publicJwk: ca.publicJwk, privateJwk: priv.privateJwk };
    const built = await buildStatement(
      'attest',
      { kind: 'tcert', keyId: target.keyId, certificateNumber: target.certificateNumber, tcertHash },
      issuedAt,
      { claims: params.claims },
      keyPair,
      this.deps.cryptoRegistry.get(ca.algorithm)
    );
    if (!(await verifyStatement(built.parsed, ca.publicJwk, this.deps.cryptoRegistry.get(ca.algorithm)))) {
      throw new QrsCryptoError('Attestation statement failed verification');
    }
    const record: AttestationRecord = {
      targetTcertId: params.targetTcertId,
      caKeyId: ca.keyId,
      caTcertId: params.caTcertId,
      tcertHash,
      claims: params.claims,
      issuedAt,
      statementBytes: built.bytes,
    };
    await this.deps.trustStore.addAttestation(record);
    return { statementId: built.statementId, bytes: built.bytes };
  }

  /** A CA introduces a TCert into its namespace (optionally storing its bytes first). */
  async addTcert(params: AddTcertParams): Promise<{ statementId: string; bytes: Uint8Array }> {
    if (params.tcertBytes) {
      const parsed = parseSignedObject(params.tcertBytes);
      if (parsed.type !== 'tcert') throw new QrsValidationError('Provided object is not a TCert');
      const tcertId = tcertIdOf(parsed.signerKeyId, parsed.data.certificateNumber as number);
      if (tcertId !== params.targetTcertId) {
        throw new QrsValidationError('Provided TCert bytes do not match the target tcert id');
      }
      await this.deps.certificateStore.save(tcertId, params.tcertBytes);
    }
    return this.attest(params);
  }

  /* ---------------- trust resolution ---------------- */

  /**
   * Resolve trust for a TCert. Returns the strongest trust state available.
   * Pinned TCerts stay valid even if the attesting CA is later revoked (the CA name
   * is simply not shown); a purely CA-issued TCert depends on its CA.
   */
  async resolveTrust(tcertId: TcertId, _parsed?: ParsedSignedObject): Promise<TrustResolution> {
    if (await this.deps.trustStore.isDistrusted(tcertId)) {
      return { state: 'invalid', pinned: false, message: 'TCert is locally distrusted' };
    }
    const pinned = await this.deps.trustStore.isPinned(tcertId);
    const attestations = await this.deps.trustStore.getAttestations(tcertId);
    let ca: { caTcertId: TcertId; caName?: string } | null = null;
    for (const att of attestations) {
      if (await this.deps.revocationStore.getRevokedAttestation(att.targetTcertId, att.caTcertId)) continue;
      if (await this.isValidAttestation(att)) {
        ca = { caTcertId: att.caTcertId, caName: (att.claims?.name as string) ?? undefined };
        break;
      }
    }
    if (pinned) return { state: 'valid', pinned: true, ca: ca ?? undefined };
    if (ca) return { state: 'valid', pinned: false, ca };
    return {
      state: 'cannotVerify',
      pinned: false,
      message: 'no trust path: TCert is neither pinned nor attested by a trusted CA',
    };
  }

  /** True when `caTcertId` is a trusted CA in good standing. */
  async isTrustedCa(caTcertId: TcertId): Promise<boolean> {
    if (await this.deps.trustStore.isDistrusted(caTcertId)) return false;
    if (await this.deps.revocationStore.getRevokedTcert(caTcertId)) return false;
    const pinned = await this.deps.trustStore.isPinned(caTcertId);
    const isCa = await this.deps.trustStore.isCa(caTcertId);
    return pinned || isCa;
  }

  /** Validate an attestation record end-to-end (CA trusted, statement signature valid). */
  async isValidAttestation(att: AttestationRecord): Promise<boolean> {
    const caBytes = await this.deps.certificateStore.get(att.caTcertId);
    if (!caBytes) return false;
    let caParsed: ParsedSignedObject;
    try {
      caParsed = parseSignedObject(caBytes);
    } catch {
      return false;
    }
    if (caParsed.type !== 'tcert') return false;
    const provider = this.deps.cryptoRegistry.get(caParsed.algorithm);
    const caPub = caParsed.data.publicKey as unknown as PublicJwk;
    if (!(await verifyParsedSignedObject(caParsed, provider, caPub))) return false;
    if (!(await this.isTrustedCa(att.caTcertId))) return false;
    if (await this.deps.revocationStore.getRevokedKey(att.caKeyId)) return false;

    let stmt;
    try {
      stmt = parseStatement(att.statementBytes);
    } catch {
      return false;
    }
    if (stmt.action !== 'attest') return false;
    if (stmt.target.kind !== 'tcert') return false;
    if (tcertIdOf(stmt.target.keyId, stmt.target.certificateNumber) !== att.targetTcertId) return false;
    if (stmt.signerKeyId !== att.caKeyId) return false;

    // The attestation must bind the exact content hash of the TCert it is about.
    const targetBytes = await this.deps.certificateStore.get(att.targetTcertId);
    if (!targetBytes) return false;
    let targetParsed: ParsedSignedObject;
    try {
      targetParsed = parseSignedObject(targetBytes);
    } catch {
      return false;
    }
    if (tcertHashOf(targetParsed) !== att.tcertHash) return false;
    if (stmt.target.tcertHash !== att.tcertHash) return false;

    return verifyStatement(stmt.parsed, caPub, provider);
  }

  /* ---------------- helpers ---------------- */

  private async ensureTcert(tcertId: TcertId): Promise<void> {
    const bytes = await this.deps.certificateStore.get(tcertId);
    if (!bytes) throw new QrsNotFoundError(`TCert not found: ${tcertId}`);
  }

  private async keyInfoOf(tcertId: TcertId): Promise<TcertKeyInfo> {
    const bytes = await this.deps.certificateStore.get(tcertId);
    if (!bytes) throw new QrsNotFoundError(`TCert not found: ${tcertId}`);
    const parsed = parseSignedObject(bytes);
    const keyId = parsed.signerKeyId;
    const algorithm = parsed.data.algorithm as AlgorithmId;
    const publicJwk = parsed.data.publicKey as unknown as PublicJwk;
    return { keyId, algorithm, publicJwk };
  }
}
