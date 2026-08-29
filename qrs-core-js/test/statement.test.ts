import { describe, expect, it } from 'vitest';
import { Ed25519Provider } from '../src/crypto/ed25519.js';
import { QrsParseError } from '../src/errors.js';
import { buildSignedObject } from '../src/signedObject/signedObject.js';
import { buildStatement, parseStatement, verifyStatement } from '../src/services/statement.js';

const provider = new Ed25519Provider();
const keyPair = await provider.generateKeyPair();
const keyId = provider.keyId(keyPair.publicJwk);

describe('statements', () => {
  it('builds, parses and verifies a tcert-target statement', async () => {
    const built = await buildStatement(
      'revokeTcert',
      { kind: 'tcert', keyId: 'ab'.repeat(16), certificateNumber: 1 },
      100,
      { reason: 'key compromised', revocationType: 'prospective' },
      keyPair,
      provider
    );
    const parsed = parseStatement(built.bytes);
    expect(parsed.action).toBe('revokeTcert');
    expect(parsed.target).toEqual({ kind: 'tcert', keyId: 'ab'.repeat(16), certificateNumber: 1 });
    expect(parsed.reason).toBe('key compromised');
    expect(parsed.revocationType).toBe('prospective');
    expect(parsed.issuedAt).toBe(100);
    expect(parsed.signerKeyId).toBe(keyId);
    expect(await verifyStatement(parsed.parsed, keyPair.publicJwk, provider)).toBe(true);

    const other = await provider.generateKeyPair();
    expect(await verifyStatement(parsed.parsed, other.publicJwk, provider)).toBe(false);
  });

  it('supports key and sdoc targets', async () => {
    const key = await buildStatement('revokeTcert', { kind: 'key', keyId: 'ff'.repeat(16) }, 1, {}, keyPair, provider);
    expect(parseStatement(key.bytes).target).toEqual({ kind: 'key', keyId: 'ff'.repeat(16) });

    const sdoc = await buildStatement('blockSdoc', { kind: 'sdoc', sdocId: 'ee'.repeat(16) }, 1, {}, keyPair, provider);
    const parsed = parseStatement(sdoc.bytes);
    expect(parsed.target).toEqual({ kind: 'sdoc', sdocId: 'ee'.repeat(16) });
    expect(parsed.claims).toBeUndefined();
  });

  it('carries claims and validity', async () => {
    const built = await buildStatement(
      'attest',
      { kind: 'tcert', keyId: 'ab'.repeat(16), certificateNumber: 1 },
      5,
      { claims: { name: 'Ahmad of Kabul' }, validity: { validAfter: 1, validBefore: 100 } },
      keyPair,
      provider
    );
    const parsed = parseStatement(built.bytes);
    expect(parsed.claims).toEqual({ name: 'Ahmad of Kabul' });
    expect(parsed.validity).toEqual({ validAfter: 1, validBefore: 100 });
  });

  it('rejects non-statement objects', async () => {
    const tcertBytes = await buildSignedObject(
      'tcert',
      {
        keyId: new Uint8Array([1]),
        certificateNumber: 1,
        algorithm: 'Ed25519',
        publicKey: keyPair.publicJwk,
        identity: { name: 'x' },
        schema: [],
      },
      keyPair,
      provider
    );
    expect(() => parseStatement(tcertBytes)).toThrow(QrsParseError);
  });

  it('rejects malformed targets and unknown actions', async () => {
    const badTarget = await buildSignedObject(
      'statement',
      { statementId: new Uint8Array(16), action: 'attest', target: { kind: 'wat' }, issuedAt: 1 },
      keyPair,
      provider
    );
    expect(() => parseStatement(badTarget)).toThrow(QrsParseError);

    const badAction = await buildSignedObject(
      'statement',
      { statementId: new Uint8Array(16), action: 'bogus', target: { kind: 'sdoc', sdocId: new Uint8Array(16) }, issuedAt: 1 },
      keyPair,
      provider
    );
    expect(() => parseStatement(badAction)).toThrow(QrsParseError);
  });
});
