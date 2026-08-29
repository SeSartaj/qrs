// Reproduction: desktop-generated QR (qrs://v1/...) scanned/processed the way the
// mobile app does it (processPayload / verify.ts paths).
import {
  createQrs,
  encodeTransferPayload,
  decodeTransferPayload,
  fromBase64Url,
  toBase64Url,
  parseSignedObject,
  verifyParsedSignedObject,
} from './dist/index.js';

const log = (label, val) => console.log(label, typeof val === 'string' ? val : JSON.stringify(val, (k, v) => (v instanceof Uint8Array ? `0x${Buffer.from(v).toString('hex').slice(0, 12)}…` : v), 2));

const rt = createQrs();

// 1. Create a TCert (issuer side)
const tcert = await rt.certificates.createTcert({
  algorithm: 'Ed25519',
  name: 'Pharmacy License',
  fields: [
    { name: 'name', label: 'Name', type: 'text', inputRules: { required: true } },
    { name: 'licenseNo', label: 'License No', type: 'text', inputRules: { required: true } },
  ],
});
log('created tcertId:', tcert.tcertId);

// 2. Issue an SDoc (issuer side)
const sdoc = await rt.signing.issueSdoc({
  tcertId: tcert.tcertId,
  values: { name: 'Ahmad', licenseNo: 'ABC-123' },
});
log('issued sdocId:', sdoc.sdocId);

// 3. What the desktop app puts in the QR code:
const tcertPayload = encodeTransferPayload('tcert', toBase64Url(tcert.bytes));
const sdocPayload = encodeTransferPayload('sdoc', toBase64Url(sdoc.bytes));
log('tcert QR payload:', tcertPayload.slice(0, 40) + '…');
log('sdoc QR payload: ', sdocPayload.slice(0, 40) + '…');

// 4. Mobile app: processPayload on the scanned string.
//    - Bundle? no. -> decodeTransferPayload.
const dt = decodeTransferPayload(tcertPayload);
log('decoded tcert:', dt);

//    a) import TCert exactly like lib/process.ts importTcertAndDescribe
const bytes = fromBase64Url(dt.bytesB64);
const importRes = await rt.online.importTcert(bytes);
log('importTcert:', importRes);

//    b) parse the imported TCert to confirm the self-signature verifies via the
//       verification pipeline the way a verifier would.
const parsedTcert = parseSignedObject(bytes);
const pub = parsedTcert.data.publicKey;
const provider = rt.deps.cryptoRegistry.get(parsedTcert.algorithm);
const keyIdOk = provider.keyId(pub) === Buffer.from(parsedTcert.data.keyId).toString('hex');
const sigOk = await verifyParsedSignedObject(parsedTcert, provider, pub);
log('tcert sigOk:', sigOk, 'keyIdOk:', keyIdOk);

//    c) verify the SDoc like lib/verify.ts verifySdoc does.
const ds = decodeTransferPayload(sdocPayload);
const sdocBytes = fromBase64Url(ds.bytesB64);
const verifyRes = await rt.verification.verify(sdocBytes);
log('verify overall:', verifyRes.overall, '| message:', verifyRes.message ?? '(none)');

// 5. Now the WRONG path the user suspects: passing the raw qrs:// string as if it
//    were base64url SDoc bytes.
try {
  const bad = fromBase64Url(sdocPayload);
  await rt.verification.verify(bad);
  log('bad-path verify: no error');
} catch (e) {
  log('bad-path verify throws:', e.message);
}
