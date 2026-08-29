# QRS Desktop

A production-oriented **Electron** desktop app for the **SDoc Verification Protocol**. It is an offline-first **issuer and verifier**: create certificates (TCert), sign documents (SDoc), verify them offline, and manage trust & revocation — all on-device, no network required.

It is built on the [`qrs-core`](../qrs-core-package) package, which is the *single shared protocol layer* used by every platform. The mobile (React Native) verifier you build later will reuse the exact same `qrs-core` APIs — the desktop app does **not** duplicate protocol logic.

> Note on a shared `common/` folder: it was deliberately **not** used. The genuinely shared layer is `qrs-core` itself (it ships Node, browser and React Native entry points). The only app-local shared code is the typed IPC contract in [`src/shared/`](src/shared), which is required for type-safe Electron main ↔ renderer communication.

---

## Stack

| Area | Choice |
| --- | --- |
| Shell | Electron 43 |
| Build tooling | electron-vite 5 (Vite 7) + electron-builder |
| UI | React 19 + MUI 7 (dark theme) |
| Protocol | `qrs-core` 0.1.0 (linked via **yalc**) |
| Language | TypeScript 5.9 (strict) |
| Tests | Vitest 4 (Node environment) |

## Layout

```
qrs-desktop/
├─ electron.vite.config.ts     # main / preload / renderer build config
├─ electron-builder config     # in package.json ("build" key)
├─ vitest.config.ts
├─ src/
│  ├─ shared/types.ts          # typed IPC contract + DTOs (main ⇄ renderer)
│  ├─ main/
│  │  ├─ index.ts              # app lifecycle + smoke-test / screenshot hooks
│  │  ├─ window.ts             # secure BrowserWindow (contextIsolation, no nodeIntegration)
│  │  ├─ runtime.ts            # creates the qrs-core runtime with file stores in userData
│  │  ├─ contextBridge.ts      # IContextProvider that asks the renderer for inputs
│  │  ├─ ipc.ts                # all ipcMain.handle handlers
│  │  ├─ summaries.ts          # signed objects → JSON DTOs (decodes field values)
│  │  └─ smokeTest.ts          # headless end-to-end self test (QRS_SMOKE_TEST=1)
│  ├─ preload/index.ts         # exposes window.qrs (typed, minimal, secure)
│  └─ renderer/
│     ├─ index.html
│     └─ src/
│        ├─ App.tsx            # nav + snackbar + context dialog host + page routing
│        ├─ api.ts             # window.qrs helpers + safe() error handling
│        ├─ i18n.ts            # i18next (en / ps / fa) + RTL detection
│        ├─ theme.ts           # MUI dark theme factory (ltr/rtl)
│        ├─ locales/           # en.ts · ps.ts · fa.ts translations
│        ├─ components/        # Layout, FieldValueInput, ContextDialogHost,
│        │                     # FlexDateInput (tri-calendar), QRCodeDialog,
│        │                     # LocationFieldInput (paste "lat, lon" from Maps),
│        │                     # ObjectActions (QR + .qrs export + dev inspect),
│        │                     # StructureDialog
│        └─ pages/             # Dashboard, Issuer, Documents, Verify, Trust, Revocation, Settings
└─ tests/                      # unit tests for main-process logic + location parsing
```

## Prerequisites

- Node.js ≥ 20.19
- npm

## Install & run

The app depends on `qrs-core`, which is linked with **yalc** so you can develop both packages together:

```bash
# 1. Publish the core package to the local yalc store (from the core package)
cd ../qrs-core-package
npm run build
npx yalc publish

# 2. Install the desktop app and link the core package
cd ../qrs-desktop
npm install
npx yalc add qrs-core

# 3. Development (hot reload)
npm run dev

# 4. Typecheck + build
npm run build          # runs typecheck (node + web) then electron-vite build

# 5. Tests
npm test               # Vitest (main-process logic, no Electron needed)

# 6. Package a production build
npm run pack           # build + electron-builder --dir (unpacked app in release/)
npm run dist           # build + electron-builder (installers: dmg/nsis/AppImage/deb)
```

When `qrs-core` changes, re-publish it and refresh the link:

```bash
cd ../qrs-core-package && npm run build && npx yalc publish
cd ../qrs-desktop && npx yalc update
```

> Publishing to npm is the right long-term move; the `file:.yalc/…` dependency is just for local development.

## What the app does

The UI is organised around **how often a task happens**: daily work is one click from the sidebar; one-off setup lives under **Settings**.

- **Sign documents** *(main page)* — the daily driver, and the default landing page. It is **certificate-centric**: you see every TCert as a card; click one to drill into it. Inside you get the certificate's details, a **“Sign new document”** button that reveals the field form, and the list of **documents issued by that certificate** (each shareable as base64url / QR / `.qrs` file, and verifiable in one click).
- **Verify** — paste/scan an SDoc and verify **offline**. The result is structured (`valid` / `invalid` / `cannotVerify`), with a **centered header** showing CA → issuer → document, the **actual decoded field values**, and a per-component breakdown (cryptographic, TCert, trust, revocation, schema). During verification the app asks for location and/or secrets through dialogs — the renderer is the *input provider* for the core.
- **Trust** — pin TCerts, promote CAs, distrust, issue attestations, import TCerts. Every TCert shows a **QR code** and (in dev mode) a plaintext structure inspector.
- **Revocation** — revoke TCerts (prospective/retrospective), revoke keys, block/unblock SDocs. Every **statement** gets a **QR code** so the mobile app can act on it.
- **Settings** — the **one-off** tasks and preferences: **Certificates & Keys** (create a TCert, choosing to **reuse an existing key pair** or generate a fresh one), the calendar preference, and **About** — including whether private keys are **encrypted at rest** (Electron `safeStorage`).
- **Location input** — location fields (and the confirm-location dialog) accept a direct paste from Google Maps (e.g. `34.51958749194178, 69.17472990319257`) in a single field, alongside separate Latitude/Longitude inputs (see `LocationFieldInput`).

### Private keys & secure storage

Private key pairs are stored under `…/qrs-data/private-keys.json`. On platforms where the OS exposes a secure store, they are **encrypted at rest** with Electron `safeStorage` (DPAPI / Keychain / libsecret) — the JSON file then holds only the encrypted blob (`encrypted: true`), and existing plaintext entries remain readable. When no secure store is available (e.g. headless Linux), it falls back to plaintext and **Settings** shows a warning.

## Sharing signed objects (QR / `.qrs` file)

Every signed object (TCert / SDoc / Statement) has a **download icon** in its row: export it as a **`.qrs` file** via a save dialog (the file is plain text holding the `qrs://…` transfer payload), plus a **QR code** button. Share either through WhatsApp / email / USB — the mobile app imports `.qrs` files and scans QR codes through the same pipeline.

All data is stored under the OS user-data directory (`…/qrs-desktop/qrs-data`), using the file-backed stores from `qrs-core`.

## Validity & date verification rules

- A **TCert** can carry `validAfter` / `validBefore` (epoch seconds). The UI asks for both, suggests a maximum of **5–10 years**, and offers one-click 5/10-year presets.
- An **SDoc has no separate validity block** — keeping it minimal. If a document needs a validity window, add `date`/`datetime` fields to the schema with verification rules. A certificate may be valid for 5 years while its SDoc is valid for one day, one week, or a year — or rely on the TCert window alone.
- The protocol enforces TCert validity: an SDoc **cannot be issued under an expired (or not-yet-valid) TCert**, and verification rejects it if the TCert has expired.
- **Date/datetime fields** can carry verification rules (one per line) checked against the verifier's current local time:

  | Rule | Meaning |
  | --- | --- |
  | `<today()` · `>today()` · `==today()` | the field's date is before / after / equal to today |
  | `day() == 'friday'` · `day() != 'friday'` | the field's weekday |
  | `daytime == 'night'` · `daytime == 'day'` | local time-of-day (night = 18:00–05:59) |
  | `16:00 < x < 23:00` · `x >= 09:00` | local clock time in a window (requires datetime) |

  Example: an SDoc schema with an expiry date field using `>today()` means "valid only while the expiry date is in the future".

## QR transfer (desktop → mobile)

Every signed object (TCert / SDoc / Statement) can be shown as a QR code. The payload is a small, self-describing **transfer envelope** so the receiving app knows what it is and what to do with it:

```
qrs://v1/<tcert|sdoc|statement>/<base64url-bytes>
```

- Defined in `qrs-core` (`encodeTransferPayload` / `decodeTransferPayload` in `src/transfer.ts`) so the **mobile app reuses the exact same format**.
- Scan a TCert/attestation/revocation QR with the mobile app → it imports the object and runs the full protocol steps (parse → verify signature → trust → revocation). The QR is the transport; the protocol does the security.
- Available via the QR button on Trust rows, Documents rows, the verify result, and after issuing an attestation/revocation/block statement.

## Localization (English / Pashto / فارسی) + calendar & dates

- The UI is fully localized via `i18next` with **English (en)**, **Pashto (پښتو)**, and **Persian (فارسی)**; Pashto and Persian render **RTL** (MUI direction + emotion cache switch). Switch languages from the sidebar.
- **One global calendar setting** (like the language setting) picks Gregorian / Jalali / Islamic — set it in the sidebar or Settings. Every date input uses it; there is **no per-field calendar selector**.
- **Dates are always stored as Gregorian** on the protocol; the user enters them in their chosen calendar. Input is only parsed when it is a complete date (never auto-converted mid-typing) — the `FlexDateInput` (built on the `tri-calendar` package) converts reliably and shows the Gregorian/Jalali equivalent as you go.

## Minimal SDoc size

- SDoc field values are stored as a **schema-indexed array** in canonical CBOR — field **names and labels are never stored in the SDoc** (they live only in the TCert schema), and the SDoc carries **no separate validity block**. This keeps the SDoc small so it fits comfortably in a QR code; the verifier maps positions back to the schema.
- The Verify screen shows the **labels** (not machine names) for the decoded values, and document **lists/dropdowns show the human names** (document name, issuer, certificate id).

## Developer mode (plaintext view)

When running in dev mode (`npm run dev`), every signed object gets an **Inspect** button that decodes and shows its **plaintext data structure** (the decoded CBOR/COSE payload: `identity`, `schema`, `validity`, `fields`, `publicKey`, …) via `window.qrs.objects.decode`. This is gated behind `import.meta.env.DEV` — it is **not** available in packaged builds.

## Online distribution server & attachments

A TCert can carry an **`online_endpoint`** — the URL of a public distribution
server (Django, see `../qrs-server`). It is set when creating the TCert and is
**signed into the TCert**, so verifiers can discover the server, but the server is
**never trusted**: it is a cache, and every verifier still checks signatures
cryptographically.

- **Attachment fields** now use a **file input**. When you choose a file, the app:
  1. sends the raw file bytes to the main process, which builds and **signs an
     independent attachment object** (`qrs-core` → `qrs.attachments.build`),
  2. stores the signed object **locally** (`<userData>/objects/attachment/<id>`),
  3. uploads it to the TCert's `online_endpoint` (challenge → proof-of-work →
     token → upload),
  4. if the network is unavailable, it stays **queued** and **syncs automatically**
     in the background (or via **Sync** on the Documents page).
- The signed SDoc stores only the **single content-addressed hash** (the
  attachment's `id` = truncated sha256). No app state, content type or metadata
  lives in the SDoc — the content type is declared in the TCert schema. A verifier
  fetches the signed object by `id` (local store first, then the `online_endpoint`),
  verifies its signature against the issuing TCert, and checks the hash binding.

### Displaying attachments

When a verified document has an attachment field, the **Verify** page fetches the
signed attachment object and renders it inline:

- **Images** (`image/*`) show a **thumbnail**; clicking it opens the image **full
  size** in a lightbox.
- **Everything else** (PDF, text, …) shows the content type plus **Open** (opens
  with the OS default application) and **Download** (native save dialog) buttons.

The content is fetched through `window.qrs.attachments.get` (local store first,
then the issuing TCert's `online_endpoint`), decoded from the signed object, and
opened/saved via `attachments.open` / `attachments.save`.

### Distributing other signed objects (revocations, attestations, attested certs)

The **Sync** button (always visible on the Documents page) is a full bidirectional
sync:

- **Upload** — pending attachments and signed statements are pushed to the
  signer's `online_endpoint`.
- **Download** — from every configured endpoint the app:
  1. fetches the hosted **TCerts** (discovery) and stores any it doesn't have
     (this is how a CA shares its **attested certificates** and root TCerts),
  2. fetches the hosted **signed statements** and, after verifying each one
     against the signer's TCert public key, **applies** them locally — this is
     how **revocation lists** and **attestations** propagate,
  3. caches hosted **attachment** objects so they verify offline.

Statements are **auto-published**: when you create an attestation (Trust page) or
a revocation / block (Revocation page), the signed statement is uploaded to the
signer certificate's `online_endpoint` (queued if offline). An attestation also
registers the attested certificate on the CA's server so it can be discovered. The
UI reports whether each statement was published and where.

Before uploading, **Sync first registers every local certificate that belongs on
the server** (its own `online_endpoint` matches, or it is issued by a CA whose
endpoint matches). This is what makes the CA → attest → share workflow work: the
CA cert and its issued certs become discoverable, and the server accepts the
statements signed under their keyIds.

### Debugging sync

Sync runs in the **main process**, so its HTTP requests do **not** appear in the
renderer DevTools network tab — watch the **terminal where the app was launched**
(or the Django server console). Every step and every error is logged with a
`[sync]` / `[online]` prefix. The UI also shows the actual error messages in a red
alert on the Documents page (not just a count).

There is a headless reproduction harness for the whole CA → attest → sync flow:

```bash
# run the Django server first, then:
QRS_SYNC_TEST=1 QRS_SYNC_ENDPOINT=http://127.0.0.1:8000 npx electron . --no-sandbox --disable-gpu
# prints [sync]/[synctest] logs + QRS_SYNC_RESULT {uploaded,pending,downloaded,applied,errors}
```
- The uploaded signed objects (statements and attachments) are verified by the
  server against the TCert's public key before being hosted.

## Security model

- Renderer runs with `contextIsolation: true`, `nodeIntegration: false`, `webSecurity: true`, and a strict CSP. It never touches Node/Electron APIs — it only sees the typed `window.qrs` bridge.
- External links open in the system browser (window-open handler denies new windows).
- Private keys are generated by `qrs-core` (Node `crypto` for Ed25519/ECDSA) and stored in the file stores — the same trust model as the CLI. For hardware-backed keys, implement `IPrivateKeyStore` and inject it in `src/main/runtime.ts`.

## Headless self-test / CI

```bash
QRS_SMOKE_TEST=1 npx electron . --no-sandbox --disable-gpu
# prints QRS_SMOKE_RESULT {…} (includes TCert/SDoc validity + decoded structure) then QRS_SMOKE_OK (exit 0).

QRS_SCREENSHOT=/tmp/ui.png npx electron . --no-sandbox --disable-gpu
# saves a PNG of the rendered UI and exits. Optional: QRS_SCREENSHOT_PAGE=issue|verify|…,
# QRS_SCREENSHOT_LANG=en|ps|fa to capture a specific page / language.
```

## Tests

`tests/contextBridge.test.ts` — the renderer-bridge context provider (location/secret requests, cancellation, missing window).

`tests/summaries.test.ts` — TCert/SDoc → DTO summarisation, including decoding stored field values (with labels), confirming that `stripped` secrets are **not** stored, and that unparseable/old-format documents are skipped from the list.

`tests/objects.test.ts` — plaintext decode (`toJsonSafe`, `decodeObject`) and `verifyWithDetail` (result + decoded values + issuer/CA names, date-rule failure).

`tests/online.test.ts` — the client-side proof-of-work solver used to talk to the distribution server.

```bash
npm test
```

## Roadmap / notes

- The **React Native** verifier (see `../qrs_app/qrs`) will consume `qrs-core/browser` (WebCrypto) and implement storage + context with native primitives — the same patterns used here, plus the **same QR transfer-envelope format** and the same screen designs (the MUI screens are the design reference).
- QR **generation** is provided by the desktop app (via `qrcode.react`); QR **scanning** will live in the mobile app.
