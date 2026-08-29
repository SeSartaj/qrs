/**
 * OnlineService: applying signed objects fetched from distribution servers.
 *
 * The distribution server is never trusted. A verifier that downloads a signed
 * statement (an attestation, a revocation, a block) applies it to its local
 * stores only after the statement's signature verifies against the signer's TCert
 * public key. This is what makes server-hosted "revocation lists", attestations
 * and attested certificates usable offline and tamper-evident.
 *
 * Importing a statement is idempotent at the store level (records are keyed by
 * target + signer); re-importing a statement the device already holds is a no-op.
 */
import type { PublicJwk } from '../crypto/jwk.js';
import { QrsParseError } from '../errors.js';
import { tcertIdOf } from '../signedObject/signedObject.js';
import { parseSignedObject, verifyParsedSignedObject } from '../signedObject/signedObject.js';
import { tcertHashOf } from '../signedObject/signedObject.js';
import { isAction } from '../signedObject/schemas.js';
import { parseStatement, verifyStatement } from './statement.js';
import type { ServiceDeps } from './deps.js';

export interface ImportedStatement {
  applied: boolean;
  reason?: string;
  action?: string;
  target?: string;
  statementId?: string;
}

export class OnlineService {
  constructor(private readonly deps: ServiceDeps) {}

  /**
   * Parse, verify and apply a signed statement fetched from a distribution server.
   * Returns `{ applied: true }` when it was accepted, or `{ applied: false, reason }`
   * when it was malformed, unsigned by a known signer TCert, or an unsupported action.
   */
  async importStatement(bytes: Uint8Array): Promise<ImportedStatement> {
    let stmt;
    try {
      stmt = parseStatement(bytes);
    } catch (error) {
      return {
        applied: false,
        reason: error instanceof QrsParseError ? 'malformed statement' : 'unsupported statement',
      };
    }
    if (!isAction(stmt.action)) {
      return { applied: false, reason: `unsupported action: ${String(stmt.action)}`, statementId: stmt.statementId };
    }

    // The signer must be a TCert we hold locally; verify the statement against its
    // public key. Prefer a CA-configured TCert of the signer key when one exists.
    const signerTcerts = await this.deps.certificateStore.findByKeyId(stmt.signerKeyId);
    let caPreferred: { id: string } | undefined;
    let fallback: { id: string } | undefined;
    for (const rec of signerTcerts) {
      let parsed;
      try {
        parsed = parseSignedObject(rec.bytes);
      } catch {
        continue;
      }
      if (parsed.type !== 'tcert') continue;
      const pub = parsed.data.publicKey as unknown as PublicJwk;
      const provider = this.deps.cryptoRegistry.get(parsed.algorithm);
      if (await verifyStatement(stmt.parsed, pub, provider)) {
        if (await this.deps.trustStore.isCa(rec.tcertId)) caPreferred = { id: rec.tcertId };
        if (!fallback) fallback = { id: rec.tcertId };
      }
    }
    const signerTcertId = (caPreferred ?? fallback)?.id;
    if (!signerTcertId) {
      return {
        applied: false,
        reason: 'no signer TCert locally or signature invalid',
        statementId: stmt.statementId,
      };
    }

    const issuedAt = stmt.issuedAt;
    switch (stmt.action) {
      case 'attest': {
        if (stmt.target.kind !== 'tcert') break;
        const targetTcertId = tcertIdOf(stmt.target.keyId, stmt.target.certificateNumber);
        // The attestation binds the exact TCert content hash. When the target
        // TCert is available locally, verify the binding before applying; when it
        // is not yet available (offline-first, order-independent import), apply
        // with the statement's bound hash so the binding is checked later.
        const targetBytes = await this.deps.certificateStore.get(targetTcertId);
        let tcertHash = stmt.target.tcertHash ?? '';
        if (targetBytes) {
          let targetParsed;
          try {
            targetParsed = parseSignedObject(targetBytes);
          } catch {
            return { applied: false, reason: 'malformed target TCert', statementId: stmt.statementId };
          }
          const computed = tcertHashOf(targetParsed);
          if (stmt.target.tcertHash !== undefined && stmt.target.tcertHash !== computed) {
            return {
              applied: false,
              reason: 'attestation TCert hash mismatch',
              statementId: stmt.statementId,
            };
          }
          tcertHash = computed;
        }
        await this.deps.trustStore.addAttestation({
          targetTcertId,
          caKeyId: stmt.signerKeyId,
          caTcertId: signerTcertId,
          tcertHash,
          claims: stmt.claims,
          issuedAt,
          statementBytes: bytes,
        });
        return { applied: true, action: 'attest', target: targetTcertId, statementId: stmt.statementId };
      }
      case 'revokeTcert': {
        const entry = {
          type: stmt.revocationType ?? 'retrospective',
          issuedAt,
          reason: stmt.reason,
          // Attribute to the signer key so each CA's revocation is independent.
          byKeyId: stmt.signerKeyId,
          byTcertId: signerTcertId,
          statementBytes: bytes,
        };
        if (stmt.target.kind === 'tcert') {
          const targetTcertId = tcertIdOf(stmt.target.keyId, stmt.target.certificateNumber);
          await this.deps.revocationStore.addRevokedTcert(targetTcertId, entry);
          return { applied: true, action: 'revokeTcert', target: targetTcertId, statementId: stmt.statementId };
        }
        if (stmt.target.kind === 'key') {
          await this.deps.revocationStore.addRevokedKey(stmt.target.keyId, entry);
          return { applied: true, action: 'revokeTcert', target: stmt.target.keyId, statementId: stmt.statementId };
        }
        break;
      }
      case 'revokeAttestation': {
        if (stmt.target.kind !== 'tcert') break;
        const targetTcertId = tcertIdOf(stmt.target.keyId, stmt.target.certificateNumber);
        const attestations = await this.deps.trustStore.getAttestations(targetTcertId);
        if (!attestations.some((att) => att.caTcertId === signerTcertId)) {
          return { applied: false, reason: 'attestation to revoke was not found', statementId: stmt.statementId };
        }
        await this.deps.revocationStore.addRevokedAttestation(targetTcertId, signerTcertId, {
          type: 'prospective', issuedAt, reason: stmt.reason, byKeyId: stmt.signerKeyId,
          byTcertId: signerTcertId, statementBytes: bytes,
        });
        return { applied: true, action: 'revokeAttestation', target: targetTcertId, statementId: stmt.statementId };
      }
      case 'blockSdoc': {
        if (stmt.target.kind !== 'sdoc') break;
        await this.deps.revocationStore.addBlockedSdoc(stmt.target.sdocId, { issuedAt, reason: stmt.reason, statementBytes: bytes, byKeyId: stmt.signerKeyId, byTcertId: signerTcertId });
        return { applied: true, action: 'blockSdoc', target: stmt.target.sdocId, statementId: stmt.statementId };
      }
      case 'unblockSdoc': {
        if (stmt.target.kind !== 'sdoc') break;
        await this.deps.revocationStore.removeBlockedSdoc(stmt.target.sdocId, { issuedAt, reason: stmt.reason, statementBytes: bytes, byKeyId: stmt.signerKeyId, byTcertId: signerTcertId });
        return { applied: true, action: 'unblockSdoc', target: stmt.target.sdocId, statementId: stmt.statementId };
      }
      default:
        return { applied: false, reason: `unsupported action: ${stmt.action}`, statementId: stmt.statementId };
    }
    return { applied: false, reason: `unsupported target for ${stmt.action}`, statementId: stmt.statementId };
  }

  /** Verify a TCert object (downloaded from a server) and store it locally. */
  async importTcert(bytes: Uint8Array): Promise<{ imported: boolean; tcertId?: string; reason?: string }> {
    try {
      const parsed = parseSignedObject(bytes);
      if (parsed.type !== 'tcert') return { imported: false, reason: 'not a TCert' };
      const keyId = parsed.signerKeyId;
      const certificateNumber = parsed.data.certificateNumber as number;
      const tcertId = tcertIdOf(keyId, certificateNumber);
      // Self-signature + key-id binding must hold before we store it.
      const provider = this.deps.cryptoRegistry.get(parsed.algorithm);
      const pub = parsed.data.publicKey as unknown as PublicJwk;
      if (!(await verifyParsedSignedObject(parsed, provider, pub))) {
        return { imported: false, reason: 'TCert self-signature invalid' };
      }
      if (provider.keyId(pub) !== keyId) {
        return { imported: false, reason: 'TCert key id mismatch' };
      }
      await this.deps.certificateStore.save(tcertId, bytes);
      return { imported: true, tcertId };
    } catch {
      return { imported: false, reason: 'malformed TCert' };
    }
  }
}
