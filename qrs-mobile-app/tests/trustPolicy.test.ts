/**
 * Tests for the pure trust-policy logic (dedup + any/all + verdict).
 *
 * These catch the edge cases that previously produced "same CA displayed three
 * times" on the Result screen (duplicate attestations → duplicate React keys).
 */
import { describe, expect, it } from 'vitest';
import {
  caView,
  dedupCaViews,
  issuerVerifiedByPolicy,
  resolveVerdict,
} from '../lib/trustPolicy';

const trustedCa = (id: string) =>
  caView({ caTcertId: id, caTrusted: true, attestationValid: true, state: 'valid' });
const revokedCa = (id: string) =>
  caView({ caTcertId: id, caTrusted: true, attestationValid: true, revoked: true, state: 'invalid' });

describe('dedupCaViews', () => {
  it('removes duplicate CA entries by caTcertId', () => {
    const views = [trustedCa('caA:1'), trustedCa('caB:1'), trustedCa('caA:1')];
    const deduped = dedupCaViews(views);
    expect(deduped).toHaveLength(2);
    expect(deduped.map((v) => v.caTcertId)).toEqual(['caA:1', 'caB:1']);
  });

  it('keeps distinct CAs', () => {
    const views = [trustedCa('caA:1'), trustedCa('caB:1')];
    expect(dedupCaViews(views)).toHaveLength(2);
  });
});

describe('issuerVerifiedByPolicy', () => {
  it('any policy: valid when at least one CA trusts', () => {
    const views = [revokedCa('caA:1'), trustedCa('caB:1')];
    expect(issuerVerifiedByPolicy(views, 'any')).toBe(true);
  });

  it('any policy: valid when all trust', () => {
    const views = [trustedCa('caA:1'), trustedCa('caB:1')];
    expect(issuerVerifiedByPolicy(views, 'any')).toBe(true);
  });

  it('any policy: invalid when no CA trusts (all revoked)', () => {
    const views = [revokedCa('caA:1'), revokedCa('caB:1')];
    expect(issuerVerifiedByPolicy(views, 'any')).toBe(false);
  });

  it('any policy: invalid when there are no attestations', () => {
    expect(issuerVerifiedByPolicy([], 'any')).toBe(false);
  });

  it('all policy: invalid when one CA revoked even if another trusts', () => {
    const views = [revokedCa('caA:1'), trustedCa('caB:1')];
    expect(issuerVerifiedByPolicy(views, 'all')).toBe(false);
  });

  it('all policy: valid only when every CA trusts', () => {
    const views = [trustedCa('caA:1'), trustedCa('caB:1')];
    expect(issuerVerifiedByPolicy(views, 'all')).toBe(true);
  });

  it('all policy: invalid when one CA is untrusted', () => {
    const views = [trustedCa('caA:1'), caView({ caTcertId: 'caB:1', caTrusted: false, state: 'invalid' })];
    expect(issuerVerifiedByPolicy(views, 'all')).toBe(false);
  });

  it('all policy: invalid when no attestations', () => {
    expect(issuerVerifiedByPolicy([], 'all')).toBe(false);
  });
});

describe('resolveVerdict', () => {
  const base = { cryptographicOk: true, schemaOk: true, tcertOk: true };

  it('valid when issuer verified and all checks pass', () => {
    expect(resolveVerdict({ ...base, issuerVerified: true, certificateMissing: false })).toBe('valid');
  });

  it('invalid when issuer not verified under any policy', () => {
    expect(resolveVerdict({ ...base, issuerVerified: false, certificateMissing: false })).toBe('invalid');
  });

  it('cannotVerify when the certificate is missing', () => {
    expect(resolveVerdict({ ...base, issuerVerified: true, certificateMissing: true })).toBe('cannotVerify');
  });

  it('invalid when a hard check fails even if issuer verified', () => {
    expect(
      resolveVerdict({ ...base, cryptographicOk: false, issuerVerified: true, certificateMissing: false })
    ).toBe('invalid');
  });

  it('invalid when the SDoc or its TCert is revoked', () => {
    expect(resolveVerdict({ ...base, revocationOk: false, issuerVerified: true, certificateMissing: false })).toBe('invalid');
  });
});
