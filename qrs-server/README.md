# QRS Distribution Server (Django)

A **public distribution cache** for the SDoc Verification Protocol. It helps
signed objects (statements, online attachments) reach verifiers, but it is **never
trusted** — every verifier still performs the full protocol steps
(parse → verify signature → resolve trust → check revocation) itself.

The server lives in `src/qrs-server/` and is implemented in **Django + DRF**.
Cryptographic verification is delegated to `qrs-core` through a tiny Node bridge.

```
 issuer host ──(register TCert)──► server
 issuer host ──(challenge → PoW → token)──► server
 issuer host ──(upload signed statement / raw attachment file)──► server
 verifier    ──(GET via TCert.online_endpoint)──► server          [verifier verifies]
```

---

## Trust model (the key decision)

> **The server is a public cache, not a CA and not a trusted party.**

- It stores only **public** data: the TCert's public key, identity and
  `online_endpoint`. It never sees a private key.
- A verifier that downloads data from this server still verifies every signed
  object cryptographically against the TCert's public key. A malicious/compromised
  server can at most *withhold* data or *fail to serve* it — it cannot forge a
  valid attestation, revocation or blocked-SDoc statement, because it cannot sign.
- The server's value is **availability and discoverability**, not authority.

## How the flow works

1. **Register a TCert as supported.** The issuer host posts the TCert bytes
   (`POST /api/tcerts/`). The server parses it through the Node bridge, checks the
   TCert's **self-signature**, extracts `key_id`, public key, identity and
   `online_endpoint`, and stores it. A TCert is now "supported" (the server will
   host its distribution).
2. **Challenge → proof-of-work → token.** To upload, the host first asks for a
   challenge (`POST /api/tcerts/<keyId>/challenge/`). The server returns a random
   `nonce` and a `difficulty`. The host must find a `counter` such that
   `sha256(nonce:counter)` starts with `difficulty` zero hex digits (hashcash-style
   — cheap to verify, costly to spam). It redeems the solved challenge at
   `POST /api/tcerts/<keyId>/token/` for a **short-lived bearer token** (10 min).
   This is the DDoS defense: a host must burn CPU per upload session.
3. **Upload signed objects.** With the token, the host posts to
   `POST /api/tcerts/<keyId>/objects/`:
   - `type: "statement"` — the bytes of a signed statement (attest, revokeTcert,
     blockSdoc, unblockSdoc). The server **cryptographically verifies the signature**
     against the TCert's public key before storing it, and only accepts known
     statement actions.
   - `type: "attachment"` — a normal multipart file upload. The server hashes
     the file with SHA-256 and stores it as a Django `FileField` keyed by the
     truncated hash. The SDoc carries that truncated hash; no signed attachment
     object or base64 file payload is used.
4. **Verifiers fetch.** Anyone can `GET /api/tcerts/` (discovery — returns the
   full TCert bytes via `bytesB64`, so attested certificates and CA roots can be
   downloaded), `GET /api/tcerts/<keyId>/objects/` (list statements + attachment
   metadata) and `GET /api/attachments/<id>/` (attachment metadata or raw file).
   The verifier finds the server through the TCert's
   `online_endpoint` property, downloads, and verifies everything client-side —
   **it never trusts the server.** Because hosted statements are signed, a verifier
   can download and *apply* them locally: attestations extend the trust graph and
   revocations/blocks update the revocation list, without the server being able to
   forge any of it.

## Why a Node verification bridge?

The protocol's wire format is canonical CBOR + COSE_Sign1 with Ed25519 / ECDSA.
Re-implementing canonical CBOR + COSE in Python risks subtle, non-interoperable
bugs (and hand-rolling crypto is forbidden in this project). Instead, the Python
server shells out to small Node scripts (`verify/describe.mjs`,
`verify/verify_object.mjs`) that import **`qrs-core`** — the same audited,
byte-identical implementation the desktop/mobile apps use — and return a JSON
verdict. Verification is therefore guaranteed to match the reference
implementation.

## Attachment integrity

An attachment field in a signed SDoc stores a single content-addressed id: the
first 128 bits of the file's SHA-256 digest. The server calculates the full
digest itself, stores the raw file through Django's `FileField`, and exposes
metadata publicly plus the raw file on `?content=1`. A verifier downloads the
raw file when policy requires it, calculates SHA-256 locally, truncates it, and
compares it with the signed SDoc value. Required attachments are part of the
document verification decision; optional attachments are checked only when the
verifier downloads or opens them.

The server separates each physical content-addressed file (`AttachmentBlob`)
from the per-TCert logical reference (`AttachmentReference`). Identical files
uploaded under multiple TCerts are stored once and linked to each TCert
independently. The blob uses Django's `FileField` storage interface, so the
storage backend can later be switched to an S3-compatible service such as
RustFS without changing the attachment API.

## Proof-of-work details

- `difficulty` default 4 (≈16 bits of work); range 1–8. Tokens expire after 10
  minutes (`QRS_TOKEN_TTL_SECONDS`). Challenges expire after 5 minutes.
- Endpoints are additionally throttled (DRF): `challenge`/`token` 60/min, register
  60/min.

## Importing a `.qrs` file

A TCert (or a bundle of TCerts) exported as a `.qrs` file by the desktop app can be
registered directly — the server decodes the transfer payload through the Node
bridge and self-verifies every TCert before storing it.

```bash
# multipart file upload
curl -F "file=@tcert.qrs;type=text/plain" http://localhost:8000/api/tcerts/import/

# or send the file text as JSON
curl -H "Content-Type: application/json" \
     -d "{\"qrs\": \"qrs://v1/tcert/<base64url>\"}" \
     http://localhost:8000/api/tcerts/import/
```

Non-TCert objects inside the file are skipped; the endpoint returns
`{ imported: [...], skipped: [...] }` (HTTP 201 when at least one TCert was
registered, 400 otherwise).

## API reference

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| GET | `/api/tcerts/` | — | List supported TCerts |
| POST | `/api/tcerts/` | — | Register a TCert (self-verified) |
| POST | `/api/tcerts/import/` | — | Upload a `.qrs` file (single TCert or bundle) to register its TCerts |
| POST | `/api/tcerts/<keyId>/challenge/` | — | Get a PoW challenge |
| POST | `/api/tcerts/<keyId>/token/` | — | Redeem a solved challenge for a token |
| POST | `/api/tcerts/<keyId>/objects/` | Bearer | Legacy object endpoint (statements use dedicated endpoints) |
| POST | `/api/attachments/` | Bearer | Upload a raw multipart file for an admitted TCert field |
| GET | `/api/tcerts/<keyId>/objects/` | — | List hosted statements + attachments |
| GET | `/api/attachments/<id>/` | — | Fetch attachment content |

## Run

```bash
cd src/qrs-server

# Python side
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver 0.0.0.0:8000

# Node bridge deps (qrs-core)
npm install            # installs qrs-core + its deps (linked via yalc)
# after changing qrs-core: (cd ../qrs-core-js && npx yalc publish) && npx yalc update qrs-core

# Tests
python manage.py test api
```

`requirements.txt`:

```
Django>=6.0
djangorestframework>=3.15
django-cors-headers>=4.4
```

## Decision log

| # | Decision | Rationale |
| --- | --- | --- |
| D1 | Server stores public data only, never private keys | It cannot be a forgery risk; the protocol keeps trust in the issuer key |
| D2 | Signature verification delegated to qrs-core via Node bridge | Byte-identical verification; no hand-rolled crypto in Python |
| D3 | Proof-of-work before upload + short-lived tokens | DDoS defense; uploads stay cheap but spam is expensive |
| D4 | Statements verified server-side before storage | The server refuses to host content that isn't genuinely from the TCert's key |
| D5 | Attachments are independent signed objects referenced by a single content-addressed hash | No app state in SDocs; the download is self-authenticating (signature + hash binding); contentType lives in the TCert schema, not the SDoc |
| D6 | Read endpoints are public and unauthenticated | Distribution is the whole point; verifiers independently verify |
| D7 | SQLite by default, JSON API, CORS open | Simple, deployable; nothing on the server is a secret |
| D8 | `online_endpoint` lives in the signed TCert | Discovery is signed and tamper-evident, so the server URL itself is authentic |
