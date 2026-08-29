#!/usr/bin/env node
/**
 * Client-side smoke test for the QRS distribution server.
 * Mirrors the desktop app's OnlineService flow:
 *   register TCert → challenge → proof-of-work → token → upload statement +
 *   attachment → list → fetch attachment.
 *
 * Usage: node verify/client_smoke.mjs <base-url>
 * Example: node verify/client_smoke.mjs http://127.0.0.1:8765
 */
import { createHash } from 'node:crypto';
import { attachmentReference, createQrs, fromBase64Url, toBase64Url } from 'qrs-core';

const base = (process.argv[2] ?? 'http://127.0.0.1:8765').replace(/\/+$/, '');

function solvePow(nonce, difficulty) {
  const target = '0'.repeat(difficulty);
  let counter = 0;
  for (;;) {
    const digest = createHash('sha256').update(`${nonce}:${counter}`, 'ascii').digest('hex');
    if (digest.startsWith(target)) return counter;
    counter++;
  }
}

async function getToken(endpoint, keyId) {
  const chRes = await fetch(`${endpoint}/api/tcerts/${keyId}/challenge/`, { method: 'POST' });
  const ch = await chRes.json();
  const counter = solvePow(ch.nonce, ch.difficulty);
  const tokRes = await fetch(`${endpoint}/api/tcerts/${keyId}/token/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ nonce: ch.nonce, counter }),
  });
  return (await tokRes.json()).token;
}

async function upload(endpoint, keyId, token, payload) {
  const res = await fetch(`${endpoint}/api/tcerts/${keyId}/objects/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(payload),
  });
  return { status: res.status, body: await res.json() };
}

async function uploadAttachment(endpoint, token, payload) {
  const form = new FormData();
  form.append('tcertId', payload.tcertId);
  form.append('fieldName', payload.fieldName);
  form.append('file', new Blob([payload.file]), 'attachment.bin');
  const res = await fetch(`${endpoint}/api/attachments/`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: form,
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

// ---- build a TCert (with online_endpoint) + a signed statement ----
const qrs = createQrs();
const tcert = await qrs.certificates.createTcert({
  algorithm: 'Ed25519',
  name: 'Client License',
  fields: [
    { type: 'text', name: 'name', label: 'Name' },
    { type: 'attachment', name: 'evidence', label: 'Evidence', inputRules: { contentType: 'text/plain' } },
  ],
  onlineEndpoint: base,
});
const target = await qrs.certificates.createTcert({
  algorithm: 'Ed25519',
  name: 'Target',
  fields: [],
  keyId: tcert.keyId,
});
await qrs.trust.addCa(tcert.tcertId);
const attest = await qrs.trust.attest({ caTcertId: tcert.tcertId, targetTcertId: target.tcertId });
const key = tcert.keyId;

// ---- 1. register ----
const reg = await fetch(`${base}/api/tcerts/`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ bytesB64: toBase64Url(tcert.bytes) }),
});
console.log('register:', reg.status, reg.status === 201 ? 'OK' : 'FAIL');

// ---- 2. token ----
const token = await getToken(base, key);
console.log('token:', token ? 'OK' : 'FAIL');

// ---- 3. upload a signed statement ----
const stmt = await upload(base, key, token, { type: 'statement', bytesB64: toBase64Url(attest.bytes) });
console.log('upload statement:', stmt.status, stmt.status === 201 ? 'OK' : JSON.stringify(stmt.body));

// ---- 4. upload a raw attachment through its signed TCert field schema ----
const attContent = new TextEncoder().encode('hello from the desktop client');
const reference = attachmentReference(attContent);
const attId = reference;
const att = await uploadAttachment(base, token, {
  tcertId: tcert.tcertId,
  fieldName: 'evidence',
  file: attContent,
});
console.log('upload attachment:', att.status, att.status === 201 ? 'OK' : JSON.stringify(att.body));

// ---- 5. list ----
const list = await (await fetch(`${base}/api/tcerts/${key}/objects/`)).json();
const hasStmt = list.objects.some((o) => o.type === 'statement' && o.action === 'attest');
const hasAtt = list.objects.some((o) => o.type === 'attachment' && o.id === attId);
console.log('list objects: statement=', hasStmt, 'attachment=', hasAtt);

// ---- 6. discovery returns full TCert bytes (attested certs are shareable) ----
const disc = await (await fetch(`${base}/api/tcerts/`)).json();
const discCert = disc.tcerts.find((t) => t.keyId === key);
const discHasBytes = !!discCert?.bytesB64 && discCert.bytesB64 === toBase64Url(tcert.bytes);
console.log('discovery bytesB64:', discHasBytes ? 'OK' : 'FAIL');

// ---- 7. fetch raw attachment content and verify its compact reference locally ----
const fetchedContent = new Uint8Array(await (await fetch(`${base}/api/attachments/${attId}/?content=1`)).arrayBuffer());
const contentMatch = attachmentReference(fetchedContent) === attId;
console.log('fetch attachment + verify:', contentMatch ? 'OK' : 'FAIL');

// ---- 8. a fresh verifier downloads the hosted statement and applies it ----
const verifier = createQrs();
await verifier.online.importTcert(fromBase64Url(discCert.bytesB64)); // CA root
const stmtB64 = list.objects.find((o) => o.type === 'statement').bytesB64;
const imported = await verifier.online.importStatement(fromBase64Url(stmtB64));
const applied = imported.applied && (await verifier.deps.trustStore.getAttestations(target.tcertId)).length === 1;
console.log('download + apply attestation:', applied ? 'OK' : 'FAIL');

const allOk =
  reg.status === 201 && token && stmt.status === 201 && att.status === 201 && hasStmt && hasAtt && discHasBytes && applied;
console.log(allOk ? 'CLIENT_SMOKE_OK' : 'CLIENT_SMOKE_FAIL');
