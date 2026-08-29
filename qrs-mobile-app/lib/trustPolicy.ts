import type { TrustPolicy } from './settings';

export type Verdict = 'valid' | 'invalid' | 'cannotVerify';

export interface CaView {
  caTcertId: string;
  caName?: string;
  caTrusted: boolean;
  revoked?: boolean;
  attestationValid: boolean;
  state: 'valid' | 'invalid' | 'cannotVerify';
  message?: string;
}

/** Build a normalized CA view for verification and tests. */
export function caView(input: Partial<CaView> & Pick<CaView, 'caTcertId' | 'caTrusted' | 'state'>): CaView {
  return { attestationValid: false, revoked: false, ...input };
}

/** Keep one view per CA, preserving the first occurrence. */
export function dedupCaViews(views: CaView[]): CaView[] {
  const seen = new Set<string>();
  return views.filter((view) => !seen.has(view.caTcertId) && (seen.add(view.caTcertId), true));
}

export function issuerVerifiedByPolicy(views: CaView[], policy: TrustPolicy): boolean {
  if (views.length === 0) return false;
  const valid = views.map((view) => view.caTrusted && !view.revoked && view.attestationValid);
  return policy === 'all' ? valid.every(Boolean) : valid.some(Boolean);
}

export function resolveVerdict(input: { cryptographicOk: boolean; schemaOk: boolean; tcertOk: boolean; revocationOk?: boolean; issuerVerified: boolean; certificateMissing: boolean }): Verdict {
  if (input.certificateMissing) return 'cannotVerify';
  return input.cryptographicOk && input.schemaOk && input.tcertOk && input.revocationOk !== false && input.issuerVerified ? 'valid' : 'invalid';
}
