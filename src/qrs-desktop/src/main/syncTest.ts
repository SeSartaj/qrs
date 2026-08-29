/**
 * Headless sync self-test: reproduces the CA → attest → sync workflow against a
 * live distribution server and prints the full sync result (including every error
 * message) to the terminal. Enabled with `QRS_SYNC_TEST=1`; the server URL is taken
 * from `QRS_SYNC_ENDPOINT` (default http://127.0.0.1:8000).
 *
 * This mirrors what happens when a user marks a certificate as CA, attests issued
 * certificates, and clicks Sync — so sync problems can be reproduced and shared.
 */
import type { DesktopRuntime } from './runtime.js';
import { getOnlineService } from './online.js';
import { syncAll } from './sync.js';
import { toBase64Url } from 'qrs-core';

export async function runSyncTest(rt: DesktopRuntime): Promise<void> {
  const endpoint = process.env['QRS_SYNC_ENDPOINT'] ?? 'http://127.0.0.1:8000';
  const online = getOnlineService();

  // 1. Create a CA cert with the server as its online_endpoint.
  const ca = await rt.qrs.certificates.createTcert({
    algorithm: 'Ed25519',
    name: 'Sync Test CA',
    fields: [],
    onlineEndpoint: endpoint,
  });
  await rt.qrs.trust.addCa(ca.tcertId);
  console.log(`[synctest] CA created + declared: ${ca.tcertId} endpoint=${endpoint}`);

  // 2. Issue + attest a couple of certificates with this CA. Mirror the UI/ipc
  //    flow: each attestation is also published (queued if the server is not ready).
  const issued: string[] = [];
  for (const name of ['Sync License A', 'Sync License B']) {
    const t = await rt.qrs.certificates.createTcert({
      algorithm: 'Ed25519',
      name,
      fields: [{ type: 'text', name: 'owner', label: 'Owner' }],
    });
    const att = await rt.qrs.trust.attest({ caTcertId: ca.tcertId, targetTcertId: t.tcertId, claims: { role: 'licensee' } });
    const pub = await online.submitObject({
      keyId: ca.keyId,
      onlineEndpoints: [endpoint],
      kind: 'statement',
      id: att.statementId,
      bytesB64: toBase64Url(att.bytes),
    });
    console.log(`[synctest] attested + published ${t.tcertId} (${name}) queued=${pub.queued}`);
    issued.push(t.tcertId);
  }

  // 3. Full sync (register local certs → upload pending → download + apply).
  console.log(`[synctest] running syncAll against ${endpoint} …`);
  const result = await syncAll(rt);

  console.log('QRS_SYNC_RESULT ' + JSON.stringify(result, null, 2));
  console.log(
    `[synctest] uploaded=${result.uploaded} pending=${result.pending} downloaded=${result.downloaded} applied=${result.applied} errors=${result.errors.length}`
  );

  const ok =
    result.errors.length === 0 &&
    (result.applied >= 2 || (result.uploaded > 0 && result.downloaded >= 1));
  console.log(ok ? 'QRS_SYNC_OK' : 'QRS_SYNC_FAIL');
}
