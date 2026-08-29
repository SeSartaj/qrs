# qrs-core

The **SDoc Verification Protocol** core — an offline-first, cross-organization protocol for issuing and verifying digitally signed documents (TCert / SDoc / Statement) that are small enough to fit inside a QR code.

This package is the reference implementation of the protocol. It is written in strict TypeScript, follows SOLID principles, and uses **inversion of control** everywhere: the package ships with default in-memory storage and a dummy (non-prompting) context provider, and consumers implement small interfaces to plug in their own storage, key management, and input/context sources.

It runs in **Node**, in the **browser**, and in **React Native** (see [Environments](#environments--entry-points)).

```
issuer key ──► TCert (identity + document schema) ──► SDoc (signed document) ──► QR code
                          │                                    │
                          └── Statement (attest / revoke / block) ┘
```

---

## Cryptography & trust

We never hand-roll cryptographic primitives:

- **SHA-256** and **base64url / hex** come from the audited, dependency-free libraries [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) and [`@scure/base`](https://github.com/paulmillr/scure-base).
- **Ed25519 / ECDSA P-256 signatures** use platform primitives: Node's `node:crypto` in Node, and the standard **Web Crypto API** (`globalThis.crypto.subtle`) in browsers / React Native.
- **Random bytes** come from `globalThis.crypto.getRandomValues`.

The only serialization code that is not a crypto primitive is the deterministic (canonical) CBOR encoder, which is fully tested against RFC 8949 vectors.

---

## Features

- **TCert (template certificate)** — a self-signed certificate that combines an issuer identity *and* the schema of exactly one document type. One key pair can own many TCerts (one per document type).
- **SDoc (signed document)** — the actual signed data issued under a TCert, compact enough for a QR code.
- **Statement** — a unified signed authority action: `attest`, `addTcert`, `revokeTcert`, `blockSdoc`, `unblockSdoc`.
- **Offline-first** — cryptographic verification needs no network. The network is only an optional enhancement.
- **Declarative field model** with eight pluggable field engines: `text`, `select`, `number`, `date`, `datetime`, `location`, `secretInput`, `attachment`.
- **Configurable verification inputs (holder/context binding)** — three input classes:
  - *payload* (stored),
  - *secret* (signed via COSE external AAD but **not stored**; the same value must be re-entered to verify — bit-exact),
  - *verification-context* (e.g. location compared against the stored value).
- **Trust management** — pinning, a two-level CA model, attestations, local distrust.
- **Revocation & lifecycle** — prospective/retrospective TCert revocation, key revocation, per-document blocking/unblocking, statement ordering by signed issuance time.
- **Validity windows** — TCerts carry optional `validAfter` / `validBefore` (epoch seconds). An SDoc cannot be issued under an expired (or not-yet-valid) TCert, and an expired TCert is rejected at verification. SDocs themselves carry **no validity block** — per-document validity is expressed with schema `date`/`datetime` fields plus the date rules below.
- **Transfer envelope (QR)** — `encodeTransferPayload` / `decodeTransferPayload` build and parse the `qrs://v1/<tcert|sdoc|statement>/<base64url>` payload used to move signed objects between devices over QR (see [Transfer envelope](#transfer-envelope-qr)).
- **Cryptographic agility** — two small-signature algorithms: **Ed25519** (64-byte signatures) and **ECDSA P-256** (64-byte `r||s` signatures), both identified explicitly in the COSE protected headers.
- **Canonical CBOR + COSE_Sign1** wire format — deterministic serialization so signatures are reproducible and interoperable.
- **IoC everywhere** — storage, context, clock, crypto providers and field engines are all interfaces.

---

## Requirements

- Node.js >= 20 (for Node usage)
- npm

---

## Install / build / test

```bash
cd qrs-core-package
npm install
npm run build     # compile to dist/
npm test          # run Vitest
npm run coverage  # run Vitest with coverage thresholds
npm run typecheck
```

`prepublishOnly` runs `clean && build && test`.

The package ships a CLI binary named `qrs` (see [CLI](#cli)).

---

## Transfer envelope (QR)

QR codes are the offline medium for moving signed objects between devices (desktop → mobile, or mobile → desktop). The payload is a small, self-describing string:

```
qrs://v1/<tcert|sdoc|statement>/<base64url-bytes>
```

```ts
import { encodeTransferPayload, decodeTransferPayload, fromBase64Url } from 'qrs-core';

const payload = encodeTransferPayload('tcert', tcertB64); // "qrs://v1/tcert/…"
const decoded = decodeTransferPayload(payload);           // { type: 'tcert', bytesB64: '…' }
const bytes = fromBase64Url(decoded!.bytesB64);           // the signed object bytes
```

The envelope is only the *transport*: the receiving app still performs the full protocol steps (parse → verify signature → resolve trust → check revocation) before acting on the object.

## `.qrs` file container

Signed objects can be saved to a **`.qrs` file** — a plain-text container whose content is exactly a transfer payload (or a bundle). This lets you export a TCert / SDoc / Statement from a desktop app, share it out-of-band (WhatsApp, email, USB), and import it on another device by feeding the file text through the normal processing pipeline.

```ts
import { encodeQrsFile, encodeQrsBundleFile, decodeQrsFile, QRS_FILE_EXTENSION } from 'qrs-core';

// Save a single object as a .qrs file (UTF-8 text)
const fileBytes = encodeQrsFile('tcert', tcertB64); // "qrs://v1/tcert/…"
writeFileSync(`afda-tcert.${QRS_FILE_EXTENSION}`, fileBytes);

// A bundle of several objects (e.g. TCert + CA attestation) also fits in one file
const bundleBytes = encodeQrsBundleFile([{ type: 'tcert', bytesB64: tcertB64 }, …]);

// Parse a .qrs file back into an object or a bundle
const decoded = decodeQrsFile(fileText); // { kind: 'object', payload } | { kind: 'bundle', objects } | null
```

Because a `.qrs` file is just the transfer-payload text, a receiving app that already handles `qrs://…` payloads (scan / paste / import) accepts the file unchanged.

## Date / datetime verification rules

A `date` or `datetime` field may carry `verifyRules.expressions` — a list of small rules evaluated at verification time against the field's value and the verifier's current **local** time (all must pass):

| Expression | Meaning |
| --- | --- |
| `<today()` `<=today()` `>today()` `>=today()` `==today()` | the field's date compared to today (local calendar date) |
| `day() == 'friday'` / `day() != 'friday'` | the field's weekday (monday…sunday) |
| `daytime == 'day'` / `daytime == 'night'` | local time-of-day (night = 18:00–05:59); needs a datetime field |
| `16:00 < x < 23:00` / `x >= 09:00` | local clock time in a window; needs a datetime field |

```ts
// TCert schema: the document is valid only while its expiry date is in the future
fields: [{ type: 'date', name: 'expiry', label: 'Expiry Date', verifyRules: { expressions: ['>today()'] } }]
```

Evaluated by `evaluateDateExpressions` (see `src/fields/dateRules.ts`); a failed rule makes the field `invalid`.

## Minimal SDoc (small enough for QR)

SDoc field values are stored as a **schema-indexed array** in canonical CBOR: position `i` matches schema `i`. Field **names and labels are never stored in the SDoc** — they live only in the TCert schema — and the SDoc carries no separate validity block. This keeps the SDoc compact. The verifier (and any consumer) reconstructs named values by mapping the array back onto the schema.

## Attachments (independent signed objects)

An **attachment** is an independent signed object of type `attachment` governed by an
app-defined static schema (not a TCert schema):

```ts
{ id, contentType, contentHash, content, issuedAt }
```

- `contentHash` is the sha256 of `content` (hex).
- `id` is the **truncated content hash** (`contentHash.slice(0, 32)`) — a single
  content-addressed handle that uniquely identifies the attachment on a
  distribution server and inside a signed SDoc.
- The document's `attachment` field stores **only that `id`**. No application
  state, content type or other metadata lives in the SDoc — the content type is
  declared in the TCert schema (`inputRules.contentType`).

```ts
const built = await qrs.attachments.build({ keyId, contentType: 'image/png', content });
// built.attachmentId, built.contentHash, built.bytes (the signed object)

const parsed = parseAttachment(built.bytes); // -> { attachmentId, contentType, contentHash, content, issuedAt, signerKeyId }
const ok = await verifyAttachment(parsed.parsed, tcertPublicJwk, provider);
```

When verifying an SDoc with an attachment field, the verifier fetches the signed
object by `id` (via the context provider's `requestObject(id, field, onlineEndpoint)`),
verifies its signature against the issuing TCert's public key, and checks that
`contentHash` starts with the stored `id` (plus the schema-declared content type).

## Environments & entry points

| Environment   | Import                       | Crypto used                        | Notes |
| ------------- | ---------------------------- | ---------------------------------- | ----- |
| Node          | `import { … } from 'qrs-core'` | `node:crypto` (Ed25519, ECDSA)     | default, best-tested |
| Browser       | `import { … } from 'qrs-core'` | WebCrypto via `createQrsWeb()`     | bundlers pick the `browser` condition automatically |
| React Native  | `import { … } from 'qrs-core'` | WebCrypto via `createQrsWeb()`     | needs random-values + subtle polyfills (see below) |
| Explicit web  | `import { … } from 'qrs-core/browser'` | WebCrypto                  | the portable entry, no Node modules |

- `createQrs()` → Node providers by default.
- `createQrsWeb()` → WebCrypto providers by default (also the default under the `browser`/`react-native` package conditions).
- `qrs-core/cli` → the CLI (Node only).

The browser entry (`qrs-core/browser`) re-exports the fully portable surface and **excludes** every Node-only module (the `node:crypto` providers, file stores, terminal provider and CLI). It is verified to bundle with **zero `node:` references**.

---

## Library usage (Node)

### Quick start

```ts
import { createQrs } from 'qrs-core';

// Defaults: in-memory storage, dummy context (never prompts), real clock.
const qrs = createQrs();

// 1. Generate a key and create a self-signed TCert for a document type.
const tcert = await qrs.certificates.createTcert({
  algorithm: 'Ed25519',
  issuerName: 'Afghanistan FDA',
  documentName: 'Pharmacy License',
  fields: [
    { type: 'text', name: 'pharmacy_name', label: 'Pharmacy Name', inputRules: { required: true, minLength: 3 } },
    { type: 'select', name: 'category', label: 'Category', options: ['category_1', 'category_2'] },
    { type: 'date', name: 'expiry_date', label: 'Expiry Date', inputRules: { required: true } },
    { type: 'location', name: 'pharmacy_location', label: 'Location', verifyRules: { maxRadius: 50 } },
    { type: 'secretInput', name: 'owner_passcode', label: 'Owner Passcode', binding: 'stripped' },
  ],
});

// 2. A verifier app trusts the TCert directly (pinning) …
await qrs.trust.pin(tcert.tcertId);

// 3. … or through a CA attestation:
//    await qrs.trust.addCa(caTcertId);
//    await qrs.trust.attest({ caTcertId, targetTcertId: tcert.tcertId, claims: { name: 'Ahmad of Kabul' } });

// 4. Issue an SDoc. The secret is signed but NOT stored in the payload.
const issued = await qrs.signing.issueSdoc({
  tcertId: tcert.tcertId,
  values: {
    pharmacy_name: 'Ahmad Pharmacy',
    category: 'category_1',
    expiry_date: '2027-12-29',
    pharmacy_location: { lat: 34.5553, lon: 69.2075 },
    owner_passcode: 's3cret',
  },
});
// issued.bytes is the SDoc; encode it into a QR code and print it on the document.

// 5. Verify offline. The result is structured — it distinguishes VALID / INVALID / CANNOT VERIFY.
const result = await qrs.verification.verify(issued.bytes, { currentTime: 1_700_000_100 });
console.log(result.overall); // 'valid' | 'invalid' | 'cannotVerify'
```

The crypto layer is **async** (it wraps Node crypto and WebCrypto), so every method that signs/verifies returns a `Promise`.

### Providing context (the IoC point for inputs)

The verification pipeline never calls platform APIs. It asks an `IContextProvider` for anything it needs. The default `DummyContextProvider` returns configured values or `null` (never prompts). Implement your own to read from a device, a backend, or a test fixture:

```ts
import { adaptProvider, createQrs, type IContextProvider } from 'qrs-core';

const myContext: IContextProvider = {
  getCurrentTime: () => Math.floor(Date.now() / 1000),
  async requestLocation(field) { return await readGps(field?.name); },
  async requestSecret(field) { return await keychain.get(field.name); },
  async requestObject(id) { return await fetchSignedObject(id); },
  buildContext() { return adaptProvider(this); },
};

const qrs = createQrs({ contextProvider: myContext });
```

There is also a `TerminalContextProvider` (used by the CLI) that prompts on the command line.

### Custom storage (the IoC point for persistence)

Storage is behind six interfaces — implement any of them and inject:

```ts
import { createQrs } from 'qrs-core';
import type { IPrivateKeyStore, ICertificateStore, IDocumentStore, IPublicKeyStore, IRevocationStore, ITrustStore } from 'qrs-core';

const qrs = createQrs({
  privateKeyStore: myKmsStore,   // e.g. a hardware key vault / HSM adapter
  publicKeyStore: myDbStore,
  certificateStore: myDbStore,
  documentStore: myDbStore,
  revocationStore: myDbStore,
  trustStore: myDbStore,
});
```

The package provides in-memory defaults (`createInMemoryStores()`) and JSON-file-backed stores (`createFileStores(dir)`, used by the CLI).

### Custom crypto providers and field engines

- **Crypto**: implement `ICryptoProvider` and register it via `CryptoRegistry` (or pass `cryptoRegistry` to `createQrs`). Algorithm identifiers are explicit in every signed object. Built-ins: `Ed25519Provider`, `EcdsaP256Provider` (Node), `WebCryptoEd25519Provider`, `WebCryptoEcdsaP256Provider` (browser/RN), plus `createDefaultCryptoRegistry()` and `createWebCryptoCryptoRegistry()`.
- **Fields**: implement `IFieldEngine` and register it via `FieldRegistry` (or pass `fieldRegistry` to `createQrs`). A TCert schema only references field *types* — it never contains executable code.

### Inversion of control summary

| Dependency        | Default                          | Override via               |
| ----------------- | -------------------------------- | -------------------------- |
| Storage           | in-memory                        | `IPrivateKeyStore`, `IPublicKeyStore`, `ICertificateStore`, `IDocumentStore`, `IRevocationStore`, `ITrustStore` |
| Context / inputs  | `DummyContextProvider` (no prompts) | `IContextProvider`      |
| Clock             | `SystemClock`                    | `IClock`                   |
| Crypto (Node)     | Ed25519 + ECDSA-P256 (`node:crypto`) | `ICryptoProvider` + `CryptoRegistry` |
| Crypto (web/RN)   | Ed25519 + ECDSA-P256 (WebCrypto) | `ICryptoProvider` + `CryptoRegistry` |
| Field engines     | the 8 built-in types             | `IFieldEngine` + `FieldRegistry` |

---

## Using this package for testing

The design is very test-friendly: everything is injected, time can be frozen, and the context provider is a plain object you fully control. There are no mocks of `node:crypto` or network calls to stub.

### Deterministic verification

Freeze the clock and drive the context with a `DummyContextProvider`:

```ts
import { describe, expect, it } from 'vitest';
import { createQrs, DummyContextProvider, type IClock } from 'qrs-core';

class FixedClock implements IClock {
  constructor(private t: number) {}
  now(): number { return this.t; }
}

const TIME = 1_700_000_000;

function makeRuntime() {
  return createQrs({
    clock: new FixedClock(TIME),
    contextProvider: new DummyContextProvider({
      time: TIME,
      location: { lat: 34.5553, lon: 69.2075 },
      secrets: { owner_passcode: 's3cret' },
    }),
  });
}

it('verifies a valid document', async () => {
  const qrs = makeRuntime();
  const tcert = await qrs.certificates.createTcert({ /* … */ });
  await qrs.trust.pin(tcert.tcertId);
  const issued = await qrs.signing.issueSdoc({ tcertId: tcert.tcertId, values: { /* … */ } });

  const result = await qrs.verification.verify(issued.bytes, { currentTime: TIME + 100 });
  expect(result.overall).toBe('valid');
});
```

The three outcomes map directly to assertions:

| Scenario                                 | `result.overall`   |
| ---------------------------------------- | ------------------ |
| Correct issuer, secret, location         | `valid`            |
| Tampered bytes / wrong secret / revoked  | `invalid`          |
| TCert unknown / secret missing / GPS off | `cannotVerify`     |

### Generating fixtures

In-memory stores mean tests are isolated (nothing is written to disk). To build reusable fixtures (e.g. a fixed issuer key + TCert + SDoc), create them once and serialize with `toBase64Url(bytes)`:

```ts
import { createQrs, toBase64Url, fromBase64Url } from 'qrs-core';

const qrs = createQrs();
const tcert = await qrs.certificates.createTcert({ algorithm: 'Ed25519', issuerName: 'AFDA', documentName: 'License', fields: [/* … */] });
const issued = await qrs.signing.issueSdoc({ tcertId: tcert.tcertId, values: {/* … */} });

// Store these strings in your fixture file / snapshot.
const tcertB64 = toBase64Url(tcert.bytes);
const sdocB64 = toBase64Url(issued.bytes);
```

### Tamper / replay / revocation tests

```ts
const tampered = new Uint8Array(issued.bytes);
tampered[Math.floor(tampered.length / 2)] ^= 0xff;
expect((await qrs.verification.verify(tampered)).overall).toBe('invalid');

await qrs.revocation.revokeTcert({ signerKeyId: tcert.keyId, targetTcertId: tcert.tcertId, type: 'retrospective' });
expect((await qrs.verification.verify(issued.bytes)).overall).toBe('invalid');
```

### Cross-organization offline scenario

Simulate two independent apps — an issuer and a verifier — that only exchange TCert/attestation bytes:

```ts
const issuer = makeRuntime();
const verifier = makeRuntime(); // separate stores, never shared

// issuer creates + attests …
const ca = await issuer.certificates.createTcert({ /* CA tcert */ });
const pharmacy = await issuer.certificates.createTcert({ /* pharmacy tcert */ });
await issuer.trust.addCa(ca.tcertId);
await issuer.trust.attest({ caTcertId: ca.tcertId, targetTcertId: pharmacy.tcertId });

// the verifier only receives public bytes (no private keys) …
await verifier.deps.certificateStore.save(ca.tcertId, (await issuer.certificates.getTcert(ca.tcertId)).bytes);
await verifier.trust.addCa(ca.tcertId);
await verifier.deps.certificateStore.save(pharmacy.tcertId, (await issuer.certificates.getTcert(pharmacy.tcertId)).bytes);

// … and verifies the document offline.
const result = await verifier.verification.verify(issued.bytes, { currentTime: TIME + 100 });
expect(result.overall).toBe('valid');
expect(result.trust).toBe('valid');
```

You can also implement a fake `IContextProvider` (returning canned values) instead of `DummyContextProvider`, and a spy `IPrivateKeyStore` to assert that keys are stored. See the package's own test suite (`test/`) for a full worked example, including the Afghanistan-FDA pharmacy-license e2e scenario.

---

## Using this package in a web application

In a browser, use the WebCrypto-backed runtime. Bundlers (Vite, webpack, Rollup, esbuild) pick the `browser` condition of `qrs-core` automatically; you can also import `qrs-core/browser` explicitly.

```ts
// main.ts — a browser verifier
import { createQrsWeb, fromBase64Url, type IContextProvider } from 'qrs-core';

const contextProvider: IContextProvider = {
  getCurrentTime: () => Math.floor(Date.now() / 1000),
  async requestLocation() {
    const pos = await new Promise<GeolocationPosition | null>((resolve) =>
      navigator.geolocation?.getCurrentPosition(resolve, () => resolve(null), { timeout: 3000 })
    );
    return pos ? { lat: pos.coords.latitude, lon: pos.coords.longitude } : null;
  },
  async requestSecret(field) {
    return window.prompt(`Enter ${field.label}:`); // or a nicer UI
  },
  async requestObject() { return null; }, // online objects are out of scope here
  buildContext() { return adaptProvider(this); },
};

const qrs = createQrsWeb({ contextProvider });

async function verifySdoc(encodedOrBytes: string | Uint8Array) {
  const bytes = typeof encodedOrBytes === 'string' ? fromBase64Url(encodedOrBytes) : encodedOrBytes;
  const result = await qrs.verification.verify(bytes);
  renderResult(result); // overall: valid | invalid | cannotVerify
}
```

Notes for the browser:

- **Only the verifier flow needs to run in the browser for most products.** The issuer can keep its private key server-side; the browser verifies SDocs against public TCerts it has pinned or received via attestations.
- If you do issue in the browser, the private key lives in JS memory — treat that as a conscious trust decision for demos; keep real issuance server-side.
- The browser entry has **no Node imports** — verified by bundling it with esbuild (zero `node:` references).

---

## Using this package in React Native

React Native does not ship `node:crypto` or `node:fs`, so use the WebCrypto runtime and implement the storage/context interfaces with native primitives.

1. **Random values.** Install `react-native-get-random-values` and import it once (`import 'react-native-get-random-values'`) so `globalThis.crypto.getRandomValues` exists.
2. **WebCrypto (`crypto.subtle`).** Provide a `crypto.subtle` implementation if your Hermes/React Native version lacks it — for example via `react-native-quick-crypto` (Expo/RN) or `expo-crypto`. Alternatively, implement your own `ICryptoProvider` using a native crypto library.
3. **Storage.** Implement the store interfaces on top of `AsyncStorage` or `expo-sqlite` (keys may also go to `expo-secure-store`).
4. **Context.** Implement `IContextProvider` (location via `expo-location`, secrets via `expo-secure-store`, online objects via `fetch`).

```ts
import 'react-native-get-random-values';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { createQrsWeb, type ICertificateStore, type IDocumentStore, type ITrustStore } from 'qrs-core';

const certificateStore: ICertificateStore = {
  async save(tcertId, bytes) { await AsyncStorage.setItem(`cert:${tcertId}`, base64FromBytes(bytes)); },
  async get(tcertId) { const s = await AsyncStorage.getItem(`cert:${tcertId}`); return s ? bytesFromBase64(s) : null; },
  // … findByName / all / remove
};

const qrs = createQrsWeb({
  certificateStore,
  // documentStore, revocationStore, trustStore, privateKeyStore, publicKeyStore: implement the same way
});
```

---

## CLI

```bash
npm run build
node dist/cli/cli.js --help
# or, after `npm link`:
qrs --help
```

State is stored in `./.qrs-data` (override with `--data-dir <dir>` or `$QRS_DATA_DIR`).

### Non-interactive (scripted) example

```bash
QRS="node dist/cli/cli.js"
D=/tmp/qrs-demo

# 1. Create a TCert (schema supplied as JSON — no prompts)
"$QRS" create-tcert --data-dir "$D" \
  --name "Afghanistan FDA" --document "Pharmacy License" \
  --fields-json '[{"type":"text","name":"pharmacy_name","label":"Pharmacy Name","inputRules":{"required":true}},{"type":"secretInput","name":"owner_passcode","label":"Owner Passcode"}]'
# prints: tcertId: <id>

# 2. Issue an SDoc (values supplied as JSON)
"$QRS" issue --data-dir "$D" --tcert "<tcertId>" \
  --values-json '{"pharmacy_name":"Ahmad Pharmacy","owner_passcode":"s3cret"}'
# prints: sdocId: <id>  and saves <id>.sdoc.bin in the data dir

# 3. The verifier pins the TCert, then verifies offline
"$QRS" pin --data-dir "$D" --tcert "<tcertId>"
"$QRS" verify --data-dir "$D" "<id>.sdoc.bin" --secret owner_passcode=s3cret
# overall: valid

# Wrong secret → invalid; missing secret → cannotVerify
"$QRS" verify --data-dir "$D" "<id>.sdoc.bin" --secret owner_passcode=wrong
```

Scripting flags:

| Flag | Used by | Meaning |
| --- | --- | --- |
| `--fields-json '<json>'` | `create-tcert` | Array of field schemas (skips prompts) |
| `--values-json '<json>'` | `issue` | Object of field values (skips prompts) |
| `--secret k=v[,k2=v2]` | `verify` | Provide secrets instead of prompting |
| `--location <lat,lon>` | `verify` | Provide the current location |
| `--time <epoch>` | `verify`, `create-tcert`, `issue` | Override "now" (epoch seconds) |
| `--data-dir <dir>` | all | Storage directory |

When these flags are omitted the CLI prompts interactively (a real terminal).

### Commands

- Keys: `generate-key`
- Certificates: `create-tcert`, `import-tcert <b64|file> [--pin]`, `export-tcert --tcert <id>`
- Documents: `issue --tcert <id>`, `verify <b64|file>`, `export-sdoc --sdoc <id>`
- Trust: `pin`, `unpin`, `add-ca`, `remove-ca`, `distrust`, `trust`, `attest --ca <id> --target <id>`, `add-tcert --ca <id> --target <id>`
- Revocation: `revoke-tcert --target <id> [--type prospective|retrospective]`, `revoke-key --target <keyId>`, `block-sdoc --target <sdocId>`, `unblock-sdoc --target <sdocId>`
- Other: `list [--kind tcert|sdoc|key]`, `version`, `help`

---

## Architecture

The package is split into small, single-responsibility modules:

| Module | Responsibility |
| --- | --- |
| `cbor/canonical.ts` | Deterministic (canonical) CBOR encoding/decoding — the signature input |
| `crypto/*` | `ICryptoProvider` (Ed25519, ECDSA-P256; Node + WebCrypto), JWK helpers, registries |
| `cose/cose.ts` | COSE_Sign1 signing/verification, including external AAD |
| `signedObject/*` | The SignedObject envelope, static per-type data schemas, id derivation |
| `fields/*` | The field model and the eight field engines |
| `context/*` | The context-provider abstraction, dummy + terminal implementations |
| `storage/*` | Storage interfaces, in-memory + file-backed implementations |
| `services/*` | CertificateService, SigningService, VerificationService, TrustService, RevocationService |
| `runtimeBase.ts` / `runtime.ts` / `runtimeWeb.ts` | The portable runtime container + Node / Web factories (`createQrs`, `createQrsWeb`) |
| `index.ts` / `index.browser.ts` | Node entry / portable browser entry |
| `cli/*` | The `qrs` command-line tool (a thin layer over the core) |

### Signed-object wire format

Every signed object is a COSE_Sign1 message whose payload is:

```
[ protocolVersion, type, data ]
```

- `protocolVersion` = 1
- `type` ∈ `tcert | sdoc | statement`
- `data` = canonical CBOR of the type-specific data map

The COSE protected headers carry the algorithm id and the signer's `key_id`. Secret inputs are signed via the COSE **external AAD**, so they are covered by the signature but never stored in the payload.

### Static schemas

Each signed-object type has a **static schema** (see `signedObject/schemas.ts`) that the decoder validates against before accepting an object. The decoder never guesses the meaning of a payload.

---

## Security notes

- **Assumptions:** the verifier's device/application is trusted; the issuer keeps its private key secret; physical paper security and internal approval workflows are out of scope.
- **Cryptography:** SHA-256, base64url and hex come from audited libraries (`@noble/hashes`, `@scure/base`); signatures use platform crypto (Node `node:crypto` or WebCrypto). No cryptographic primitive is hand-implemented.
- **Trust model:** two levels. A TCert is either pinned directly or trusted through a CA attestation. A revoked CA invalidates CA-only trust; a pinned TCert remains valid but loses the CA's display metadata.
- **Revocation:** statements are ordered by their signed `issuedAt`. `retrospective` invalidates all documents; `prospective` invalidates only documents issued at/after the revocation. Key revocation invalidates every TCert and SDoc of that key.
- **The network is untrusted:** everything retrieved from an endpoint is verified cryptographically before use; transport is never a trust anchor.
- **Unknowns are never treated as valid:** `cannotVerify` is distinct from `invalid` (e.g. GPS unavailable ≠ outside permitted area).

---

## Development

```bash
npm test          # vitest run
npm run coverage  # vitest run --coverage (thresholds enforced)
npm run typecheck
npm run build
```

Coverage thresholds are enforced in `vitest.config.ts` (lines/functions/statements ≥ 80%, branches ≥ 70%). The suite includes unit tests for canonical CBOR, the crypto providers (Node **and** WebCrypto, including cross-provider interoperability), COSE, signed objects, every field engine, the storage interfaces (in-memory + file), the services, trust, revocation, verification states, IoC overrides, the WebCrypto runtime, and an end-to-end Afghanistan-FDA pharmacy-license scenario (including a cross-organizational offline verification and a stolen-secret case).

## License

MIT

