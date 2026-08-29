try {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const quickCrypto = require('react-native-quick-crypto');
  console.log('quick-crypto loaded OK; webcrypto present:', !!quickCrypto.webcrypto, 'subtle:', !!quickCrypto.webcrypto?.subtle);
  const subtle = quickCrypto.webcrypto.subtle;
  // Try Ed25519 keygen + sign + verify round trip
  subtle
    .generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
    .then(async (pair) => {
      console.log('Ed25519 keygen OK');
      const pubJwk = await subtle.exportKey('jwk', pair.publicKey);
      console.log('pub jwk:', JSON.stringify(pubJwk));
      const data = new Uint8Array([1, 2, 3, 4]);
      const sig = new Uint8Array(await subtle.sign({ name: 'Ed25519' }, pair.privateKey, data));
      console.log('sig len:', sig.length);
      const ok = await subtle.verify({ name: 'Ed25519' }, pair.publicKey, sig, data);
      console.log('verify roundtrip:', ok);
    })
    .catch((e) => console.log('Ed25519 ERROR:', e && e.name, e && e.message));
} catch (e) {
  console.log('FAILED to load quick-crypto in Node:', e && e.message);
}
