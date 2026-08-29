/**
 * EndpointService: distribution mirrors for a TCert (app-level convenience, NOT
 * protocol core).
 *
 * A TCert's signed `onlineEndpoint` is the fixed default. Additional mirrors are
 * configured by the user at any time and stored app-locally via
 * {@link IEndpointConfigStore}. The effective endpoint list is the default first,
 * then the configured mirrors (deduplicated). Servers are untrusted mirrors —
 * every downloaded object is still verified cryptographically, so a mirror is
 * just a routing hint.
 */
import type { ICertificateStore, IEndpointConfigStore, ITrustStore } from '../storage/stores.js';
import { parseSignedObject } from '../signedObject/signedObject.js';
import type { TcertId } from '../types.js';

/** Normalize a base URL: trim and strip trailing slashes. */
export function normalizeEndpoint(endpoint: string): string {
  return endpoint.trim().replace(/\/+$/, '');
}

export interface EndpointServiceDeps {
  certificateStore: ICertificateStore;
  endpointConfigStore: IEndpointConfigStore;
  trustStore: ITrustStore;
}

export class EndpointService {
  constructor(private readonly deps: EndpointServiceDeps) {}

  /** The signed default endpoint of a TCert (if any). */
  async defaultEndpoint(tcertId: TcertId): Promise<string | undefined> {
    const bytes = await this.deps.certificateStore.get(tcertId);
    if (!bytes) return undefined;
    try {
      const parsed = parseSignedObject(bytes);
      const ep = parsed.type === 'tcert' ? (parsed.data.onlineEndpoint as string | undefined) : undefined;
      return typeof ep === 'string' && ep ? normalizeEndpoint(ep) : undefined;
    } catch {
      return undefined;
    }
  }

  /** Configured mirrors (excluding the signed default). */
  async listMirrors(tcertId: TcertId): Promise<string[]> {
    const list = await this.deps.endpointConfigStore.getEndpoints(tcertId);
    return list.map(normalizeEndpoint).filter(Boolean);
  }

  /**
   * All endpoints for a TCert, best-effort: the signed default first, then the
   * user-configured mirrors. When the TCert has NO endpoints of its own but is
   * attested (issued) by a CA, fall back to the CA's endpoints — a TCert without
   * an endpoint hosts its attachments through the CA that attested it.
   */
  async effectiveEndpoints(tcertId: TcertId): Promise<string[]> {
    const seen = new Set<string>();
    const out: string[] = [];
    const push = (ep?: string) => {
      if (!ep) return;
      const n = normalizeEndpoint(ep);
      if (!seen.has(n)) {
        seen.add(n);
        out.push(n);
      }
    };

    push(await this.defaultEndpoint(tcertId));
    for (const ep of await this.listMirrors(tcertId)) push(ep);

    // Fallback: use the endpoints of the CAs that attest this TCert.
    if (out.length === 0) {
      const atts = await this.deps.trustStore.getAttestations(tcertId);
      for (const att of atts) {
        const bytes = await this.deps.certificateStore.get(att.caTcertId);
        if (!bytes) continue;
        try {
          const parsed = parseSignedObject(bytes);
          if (parsed.type !== 'tcert') continue;
          push(parsed.data.onlineEndpoint as string | undefined);
          for (const ep of await this.deps.endpointConfigStore.getEndpoints(att.caTcertId)) push(ep);
        } catch {
          /* skip malformed CA */
        }
      }
    }

    return out;
  }

  /** Add a mirror endpoint (dedup + normalized). Returns the updated mirror list. */
  async addMirror(tcertId: TcertId, endpoint: string): Promise<string[]> {
    const n = normalizeEndpoint(endpoint);
    if (n) await this.deps.endpointConfigStore.addEndpoint(tcertId, n);
    return this.listMirrors(tcertId);
  }

  /** Remove a mirror endpoint. Returns the updated mirror list. */
  async removeMirror(tcertId: TcertId, endpoint: string): Promise<string[]> {
    await this.deps.endpointConfigStore.removeEndpoint(tcertId, normalizeEndpoint(endpoint));
    return this.listMirrors(tcertId);
  }

  /** Replace the whole mirror list. Returns the updated mirror list. */
  async setMirrors(tcertId: TcertId, endpoints: string[]): Promise<string[]> {
    await this.deps.endpointConfigStore.setEndpoints(
      tcertId,
      endpoints.map(normalizeEndpoint).filter(Boolean)
    );
    return this.listMirrors(tcertId);
  }
}
