#!/usr/bin/env node
// Creates a TCert + a signed statement and prints their base64url forms,
// so the Python side / verify bridge can be exercised.
import { createQrs, encodeQrsBundleFile, encodeQrsFile, toBase64Url } from 'qrs-core';

const qrs = createQrs();
const tcert = await qrs.certificates.createTcert({
  algorithm: 'Ed25519',
  name: 'License',
  fields: [
    { type: 'text', name: 'name', label: 'Name' },
    { type: 'attachment', name: 'photo', label: 'Photo', inputRules: { contentType: 'image/png' } },
  ],
});
const keyId = tcert.keyId;

// A CA-style setup: create a second (target) tcert under the same key.
const target = await qrs.certificates.createTcert({
  algorithm: 'Ed25519',
  name: 'Target License',
  fields: [],
  keyId,
});
await qrs.trust.addCa(tcert.tcertId);

// Attestation statement signed by the CA key.
const attest = await qrs.trust.attest({
  caTcertId: tcert.tcertId,
  targetTcertId: target.tcertId,
  claims: { role: 'inspector' },
});

// Revocation statement signed by the CA key.
const revoke = await qrs.revocation.revokeTcert({
  signerKeyId: keyId,
  targetTcertId: target.tcertId,
  type: 'retrospective',
  reason: 'license revoked',
});

// --- Second, fully independent CA for the independent-CA regression test ---
// CA-B owns its own key pair, so its attestation is cryptographically
// independent of the first CA (CA-A). Both may attest the *same* target TCert,
// and CA-As revocation must not prevent CA-B from doing so.
const caB = await qrs.certificates.createTcert({
  algorithm: 'Ed25519',
  name: 'CA B',
  fields: [],
});
await qrs.trust.addCa(caB.tcertId);
const attestB = await qrs.trust.attest({
  caTcertId: caB.tcertId,
  targetTcertId: target.tcertId,
  claims: { role: 'independent-inspector' },
});

// Attachment signed object (independent signed object with a static schema).
const attachment = await qrs.attachments.build({
  keyId,
  contentType: 'image/png',
  content: new TextEncoder().encode('fake-png-bytes'),
});

const tcertB64 = toBase64Url(tcert.bytes);
const targetB64 = toBase64Url(target.bytes);
const decode = (bytes) => new TextDecoder().decode(bytes);

console.log(
  JSON.stringify(
    {
      tcertB64,
      tcertId: tcert.tcertId,
      targetB64,
      targetTcertId: target.tcertId,
      attestB64: toBase64Url(attest.bytes),
      revokeB64: toBase64Url(revoke.bytes),
      caBB64: toBase64Url(caB.bytes),
      caBTcertId: caB.tcertId,
      attestBB64: toBase64Url(attestB.bytes),
      attachmentB64: toBase64Url(attachment.bytes),
      attachmentId: attachment.attachmentId,
      // `.qrs` file text: a single TCert, and a bundle with both TCerts.
      qrsFileText: decode(encodeQrsFile('tcert', tcertB64)),
      qrsStatementText: decode(encodeQrsFile('statement', toBase64Url(attest.bytes))),
      qrsBundleText: decode(
        encodeQrsBundleFile([
          { type: 'tcert', bytesB64: tcertB64 },
          { type: 'tcert', bytesB64: targetB64 },
        ])
      ),
    },
    null,
    2
  )
);
