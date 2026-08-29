// Generate a real TCert + SDoc pair with transfer payloads, exactly like the
// desktop app produces them, to drive the mobile web app.
import { createQrs, encodeTransferPayload, toBase64Url } from './dist/index.js';

const rt = createQrs();

const tcert = await rt.certificates.createTcert({
  algorithm: 'Ed25519',
  name: 'AFDA',
  fields: [
    { name: 'name', label: 'Name', type: 'text', inputRules: { required: true } },
    { name: 'licenseNo', label: 'License No', type: 'text', inputRules: { required: true } },
  ],
});

const sdoc = await rt.signing.issueSdoc({
  tcertId: tcert.tcertId,
  values: { name: 'Ahmad', licenseNo: 'ABC-123' },
});

const tcertPayload = encodeTransferPayload('tcert', toBase64Url(tcert.bytes));
const sdocPayload = encodeTransferPayload('sdoc', toBase64Url(sdoc.bytes));
const sdocRawB64 = toBase64Url(sdoc.bytes);

console.log('TCERT_PAYLOAD=' + tcertPayload);
console.log('SDOC_PAYLOAD=' + sdocPayload);
console.log('SDOC_RAW_B64=' + sdocRawB64);
console.log('TCERT_ID=' + tcert.tcertId);
console.log('SDOC_ID=' + sdoc.sdocId);
