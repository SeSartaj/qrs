// Check the desktop app's stored TCerts: verify each self-signature with the
// Node provider (what the desktop uses) AND the WebCrypto provider (what the
// mobile app uses). Any that pass with Node but fail with WebCrypto = the bug.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import {
  parseSignedObject,
  verifyParsedSignedObject,
  Ed25519Provider,
  EcdsaP256Provider,
  WebCryptoEd25519Provider,
  WebCryptoEcdsaP256Provider,
  CryptoRegistry,
  toBase64Url,
} from './dist/index.js';

const dir = join(homedir(), '.config', 'qrs-desktop', 'qrs-data');
const certs = JSON.parse(readFileSync(join(dir, 'certificates.json'), 'utf8'));

const nodeReg = new CryptoRegistry([new Ed25519Provider(), new EcdsaP256Provider()]);
const webReg = new CryptoRegistry([new WebCryptoEd25519Provider(), new WebCryptoEcdsaP256Provider()]);

console.log('Total stored TCerts:', Object.keys(certs).length);
let failures = 0;
for (const [tcertId, b64] of Object.entries(certs)) {
  const parsed = parseSignedObject(Uint8Array.from(Buffer.from(b64, 'base64url')));
  const pub = parsed.data.publicKey;
  const nodeProv = nodeReg.get(parsed.algorithm);
  const webProv = webReg.get(parsed.algorithm);
  const nodeSig = await verifyParsedSignedObject(parsed, nodeProv, pub);
  let webSig = false;
  let webErr = '';
  try {
    webSig = await verifyParsedSignedObject(parsed, webProv, pub);
  } catch (e) {
    webErr = e.message;
  }
  // Also check keyId binding (the second condition in the verification pipeline).
  const keyIdOk = nodeProv.keyId(pub) === Buffer.from(parsed.data.keyId).toString('hex');
  const flag = nodeSig && !webSig ? '  <-- NODE OK, WEB FAIL' : '';
  if (nodeSig && !webSig) failures++;
  if (!nodeSig) console.log(`${tcertId}  alg=${parsed.algorithm}  nodeSig=${nodeSig} keyIdOk=${keyIdOk} webErr=${webErr || ''}`);
  else if (flag) console.log(`${tcertId}  alg=${parsed.algorithm}  nodeSig=true keyIdOk=${keyIdOk} webSig=${webSig}${flag} ${webErr ? 'err=' + webErr : ''}`);
}
console.log('count where Node OK but Web failed:', failures);

// Also try to actually import each into a WebCrypto runtime and re-verify one of
// the docs, to mirror the mobile app exactly.
