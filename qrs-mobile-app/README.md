# QRS Verifier (React Native)

A mobile verification app for the **SDoc Verification Protocol**, built on the
shared [`qrs-core`](../qrs-core-package) library (React Native / WebCrypto runtime).
It is an **admin-configurable verifier**: scan or paste any signed object and get a
clean, easy-to-understand verdict — plus password-protected trust management.

## Features (v1)

- **Process (paste)** — paste any payload (`base64url` or a `qrs://v1/…` transfer
  payload) and the app **automatically figures out what it is**:
  - **SDoc** → verify it and show the result screen.
  - **TCert** → import the certificate (with a summary of what was added).
  - **Statement** (attestation / revocation / block) → verify and apply it
    automatically, showing the action and outcome.
  - **Bundle** (`qrs://v1/bundle/…`) → process every object in it (e.g. a CA
    attestation bundled with its full TCert and the attested certificate).
  - **`.qrs` file** → import a signed object shared out-of-band (WhatsApp / email /
    USB) from the desktop app. Tap **Import .qrs file** on the Process screen and
    pick the file — its text is fed through the same processing.
- **Scan** — the default screen (a raised, primary-colored circular button in the
  center of the bottom bar). A **square scan frame** with corner brackets keeps the
  camera focused on the code; a **flashlight toggle** in the header helps in dim
  rooms (native only). Point it at any QR: document (SDoc), certificate, statement
  or bundle; the same intelligent processing runs on whatever was scanned. On
  desktop/web the camera is unavailable, so it shows a permission prompt instead.
  The scan state resets automatically when you come back to the tab, so you can
  scan several documents in a row without reopening the app. (Importing `.qrs`
  files lives on the Process tab, keeping the scanner focused.)
- **Bottom navigation** — `Verify | [Scan] | Trust | Settings` with the Scan
  button centered and floating slightly above the bar like a primary action.
- **Clean result screen** (top → bottom):
  1. **CA name** with a **blue verified tick** (Twitter/X style) when the chain
     resolves to a trusted CA.
  2. **Issuer name** — with the verified tick if the issuer is pinned, or a
     “verified” label when CA-attested but not pinned.
  3. **Document name**.
  4. Each decoded field as `label: value`.
  5. **Validity** — a per-check breakdown (cryptographic / tcert / trust /
     revocation / schema / context).
  6. A big final verdict: green **VALID** / red **INVALID** / amber
     **CANNOT BE VERIFIED** (shown when the issuing certificate isn't found).
- **Context support** — `qrs-core` context fields are satisfied on-device: a
  **secret/passcode** field asks for the value in a dialog, and a **location** field
  requests device location permission and compares it to the claimed value.
- **Trust management** — import certificates (TCert) and **pin**, mark as **CA**,
  or **distrust** them. The issuing TCert must be trusted (pinned or CA-attested)
  for the verified tick to appear.
- **Admin password** — trust actions are protected. On first launch, Settings asks
  the administrator to set a password; every pin / CA / distrust action then
  requires it (only a salted PBKDF2-SHA256 hash is stored).
- **Settings as a list of pages** — Settings shows clean list rows: **Security →
  Change/set admin password** and **Data → Clear all data**, each opening its own
  screen (ChangePassword / Data with confirmation).
- **Offline-first** — verification happens entirely on-device via `qrs-core`
  (Ed25519 / ECDSA-P256, canonical CBOR + COSE). No network is needed to verify.

## Tech

- **Expo SDK 57** (React Native 0.86, TypeScript) + **react-native-paper** for UI
  (bottom-tabs / native-stack navigation).
- **`qrs-core`** via **yalc** (same as the desktop/server): WebCrypto runtime
  (`createQrsWeb`) with AsyncStorage-backed stores.
- **Crypto on device**: `react-native-get-random-values` + `react-native-quick-crypto`
  (native `crypto.subtle`). On web the browser's native WebCrypto is used.
- **Camera** via `expo-camera`; **location** via `expo-location`.

## Run

```bash
cd src/qrs-mobile-app
npm install
# link the shared core (must be published first: cd ../qrs-core-package && npx yalc publish)
npx yalc add qrs-core

npx expo start          # then press a / i / w for Android / iOS / web
```

- **Android/iOS** need a device/emulator (or Expo Go with a development build for
  `react-native-quick-crypto`).
- **Web** (`npx expo start --web` or `npx expo export --platform web`) is the
  quickest way to try it — no native build required.

## Project layout

```
lib/
  crypto.ts       # crypto polyfills (getRandomValues + quick-crypto subtle)
  stores.ts       # AsyncStorage-backed qrs-core stores (cert/trust/revocation/doc)
  runtime.ts      # createQrsWeb singleton + injectable context provider
  password.ts     # admin password (PBKDF2-SHA256), set/verify
  secretPrompt.ts # promise-based prompt for verification passcodes
  process.ts      # processPayload(): SDoc/TCert/Statement/Bundle dispatch
  contextHandlers.ts # secret / location / attachment-object handlers
  verify.ts       # verifySdoc() -> clean result model
  theme.ts        # paper theme + verdict colors
screens/
  VerifyScreen.tsx      # paste payload / history (process anything)
  ScanScreen.tsx        # full-screen camera, intelligent scan (default tab)
  ResultScreen.tsx      # clean verdict + CA/issuer ticks (centered names)
  ProcessedScreen.tsx   # TCert / statement / bundle outcome
  TrustScreen.tsx       # password-gated pin / CA / distrust + import
  SettingsScreen.tsx    # list of admin pages (change password / data)
  ChangePasswordScreen.tsx # set / change admin password
  DataScreen.tsx        # storage summary + clear all data (confirm dialog)
components/
  VerifiedBadge.tsx  # the blue verified tick
  AdminPasswordBottomSheet.tsx # keyboard-aware admin password gate
  SecretPromptHost.tsx
navigation/AppNavigator.tsx  # custom tab bar (centered raised Scan) + stack
```

## How it interoperates

The app verifies the exact same TCert / SDoc / Statement format as the desktop app
(`src/qrs-desktop`) and the Django server (`src/qrs-server`). A document signed on
the desktop (or generated by `qrs-core`) verifies here as long as the issuing TCert
is imported and trusted. Statements (attestation / revocation / block) and bundles
produced by the desktop or server can be pasted or scanned and are applied
automatically. Cross-provider interoperability (Node crypto ↔ WebCrypto) is covered
by the `qrs-core` test suite.
