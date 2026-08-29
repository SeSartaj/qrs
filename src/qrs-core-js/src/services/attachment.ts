/**
 * Attachment service: attachments as independent signed objects.
 *
 * An Attachment is a signed object of type `attachment` whose data follows an
 * **app-defined static schema** (not a TCert schema):
 *
 *   { id, contentType, contentHash, content, issuedAt }
 *
 *   - `contentHash` is the sha256 of `content` (hex).
 *   - `id` is the truncated content hash (`contentHash.slice(0, 32)`) — a single
 *     content-addressed handle that uniquely identifies the attachment on a
 *     distribution server and in a signed SDoc.
 *
 * A document's `attachment` field stores **only** that `id`. The verifier fetches
 * the signed attachment object by `id`, verifies its signature against the
 * issuing TCert, and checks the `contentHash` binding.
 */
import type { PrivateJwk, PublicJwk } from '../crypto/jwk.js';
import type { ICryptoProvider } from '../crypto/providers.js';
import { QrsNotFoundError, QrsParseError } from '../errors.js';
import { hashFor, isHashAlgorithm, toHex, type HashAlgorithm } from '../id.js';
import {
  buildSignedObject,
  parseSignedObject,
  verifyParsedSignedObject,
  type ParsedSignedObject,
} from '../signedObject/signedObject.js';
import type { KeyId } from '../types.js';
import type { ServiceDeps } from './deps.js';

/** Length (hex chars) of the truncated content hash used as the attachment id. */
export const ATTACHMENT_ID_HEX = 32;

/** Content-addressed id for a content hash (first 128 bits). */
export function attachmentIdOf(contentHashHex: string): string {
  return contentHashHex.toLowerCase().slice(0, ATTACHMENT_ID_HEX);
}

export interface BuildAttachmentParams {
  keyId: KeyId;
  contentType: string;
  content: Uint8Array;
  issuedAt?: number;
  /**
   * Hash algorithm for the content hash (default: the signer TCert's declared
   * `hashAlgorithm`, falling back to SHA-256).
   */
  hashAlgorithm?: HashAlgorithm;
}

export interface BuiltAttachment {
  attachmentId: string;
  contentHash: string;
  issuedAt: number;
  bytes: Uint8Array;
  parsed: ParsedSignedObject;
}

export interface ParsedAttachment {
  attachmentId: string;
  contentType: string;
  contentHash: string;
  content: Uint8Array;
  issuedAt: number;
  signerKeyId: string;
  parsed: ParsedSignedObject;
  bytes: Uint8Array;
}

/** Build and sign an attachment object with a TCert's key. */
export async function buildAttachment(
  params: BuildAttachmentParams,
  deps: ServiceDeps
): Promise<BuiltAttachment> {
  const privRec = await deps.privateKeyStore.load(params.keyId);
  if (!privRec) throw new QrsNotFoundError(`Issuer private key not available: ${params.keyId}`);
  const pubRec = await deps.publicKeyStore.load(params.keyId);
  if (!pubRec) throw new QrsNotFoundError(`Public key not found: ${params.keyId}`);

  const provider = deps.cryptoRegistry.get(pubRec.algorithm);
  let hashAlgorithm = params.hashAlgorithm;
  if (hashAlgorithm === undefined) {
    // Infer the hash algorithm from the signer TCert when the caller did not
    // specify it explicitly.
    const certs = await deps.certificateStore.findByKeyId(params.keyId);
    for (const c of certs) {
      try {
        const p = parseSignedObject(c.bytes);
        const declared = p.data.hashAlgorithm as unknown;
        if (typeof declared === 'string' && isHashAlgorithm(declared)) {
          hashAlgorithm = declared;
          break;
        }
      } catch {
        // ignore malformed certs while inferring
      }
    }
    hashAlgorithm ??= 'SHA-256';
  }
  const contentHash = toHex(hashFor(hashAlgorithm, params.content));
  const attachmentId = attachmentIdOf(contentHash);
  const issuedAt = params.issuedAt ?? deps.clock.now();

  const data: Record<string, unknown> = {
    id: attachmentId,
    contentType: params.contentType,
    contentHash,
    content: params.content,
    issuedAt,
  };
  const keyPair = {
    algorithm: pubRec.algorithm,
    publicJwk: pubRec.publicJwk,
    privateJwk: privRec.privateJwk as PrivateJwk,
  };
  const bytes = await buildSignedObject('attachment', data, keyPair, provider);
  const parsed = parseSignedObject(bytes);
  return { attachmentId, contentHash, issuedAt, bytes, parsed };
}

/** Parse an attachment object and return its fields. */
export function parseAttachment(bytes: Uint8Array): ParsedAttachment {
  const parsed = parseSignedObject(bytes);
  if (parsed.type !== 'attachment') throw new QrsParseError('Not an attachment');
  const d = parsed.data as Record<string, unknown>;
  if (
    typeof d.id !== 'string' ||
    typeof d.contentType !== 'string' ||
    typeof d.contentHash !== 'string' ||
    !(d.content instanceof Uint8Array) ||
    typeof d.issuedAt !== 'number'
  ) {
    throw new QrsParseError('Malformed attachment');
  }
  return {
    attachmentId: d.id,
    contentType: d.contentType,
    contentHash: d.contentHash,
    content: d.content,
    issuedAt: d.issuedAt,
    signerKeyId: parsed.signerKeyId,
    parsed,
    bytes,
  };
}

/** Verify an attachment's signature with the signer's public key. */
export async function verifyAttachment(
  parsed: ParsedSignedObject,
  publicJwk: PublicJwk,
  provider: ICryptoProvider
): Promise<boolean> {
  return verifyParsedSignedObject(parsed, provider, publicJwk);
}

/**
 * Runtime-facing attachment service. Stateless: delegates to the standalone
 * functions, injecting the runtime's stores and crypto registry.
 */
export class AttachmentService {
  constructor(private readonly deps: ServiceDeps) {}

  build(params: BuildAttachmentParams): Promise<BuiltAttachment> {
    return buildAttachment(params, this.deps);
  }
}
