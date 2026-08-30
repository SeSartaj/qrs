# qrs — SDoc Verification Protocol v1 (Python core)

A portable, **stateless, extendible** core for the SDoc Verification Protocol:
offline-first, cross-organization verification of digitally signed documents
(TCert / SDoc / Statement) that are small enough to fit inside a QR code.

This is the Python port of the reference implementation
(`qrs-core`, a TypeScript package). The wire format is **byte-for-byte
compatible**: canonical CBOR, COSE_Sign1, the same key-id derivation, the same
static schemas and the same signed-object envelope. Objects signed by the Node
core verify here and vice-versa.

The core is a *framework*, not an application. It never calls platform APIs:
every external input and every persistence concern is injected through
interfaces. That is what lets one core serve Django, FastAPI, Electron,
React Native, or a plain script.

## Design goals

- **Stateless core** — all state lives in the injected stores; services are
  pure. Build a runtime per request (or reuse one) and swap stores freely.
- **Extendible without protocol changes** — new *field types* (implement
  `IFieldEngine` and register it) and new *algorithms* (implement
  `ICryptoProvider` and register it) are additive. Protocol-version bumps are
  reserved for changes to the core wire format itself.
- **Minimal core, maximal plug-ins** — the core ships only the envelope, the
  canonical CBOR/COSE layer, the service orchestration and the interfaces.
  Everything else (specific field semantics, crypto backends, storage, context)
  is pluggable.
- **Portable by construction** — the wire format is deterministic and
  language-neutral (canonical CBOR, JWK public keys, hex identifiers), so other
  language implementations are straightforward.

## Layout

```
src/qrs/
├── cbor.py                # canonical (deterministic) CBOR encode/decode
├── cose.py                # COSE_Sign1 (RFC 9052) envelope
├── envelope.py            # SignedObject: [version, type, dataBytes]
├── signed_object.py       # static data schemas + validation
├── id.py                  # sha256/384/sha3, hex, base64url, random ids
├── crypto/                # providers (Ed25519, ECDSA-P256) + registry
├── fields.py              # FieldSchema, field-engine interface
├── field_engines.py       # the 8 reference engines (text…attachment)
├── field_registry.py      # engine registry
├── date_rules.py          # date/datetime verification rules
├── context.py             # IContextProvider + DummyContextProvider
├── storage/               # interfaces + in-memory + JSON-file stores
├── services/              # certificates, signing, trust, revocation,
│                          #   verification, attachments, online, endpoints
├── deps.py                # ServiceDeps (dependency bundle)
├── runtime.py             # create_qrs() — the IoC container
└── __init__.py            # public API
```

## Install

```bash
cd src/qrs-package
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
# tests
pip install pytest pytest-asyncio
pytest
```

Requires Python ≥ 3.11 and the `cryptography` package (an audited, maintained
crypto library — we never hand-roll crypto).

## Quick start

```python
import asyncio
from qrs import create_qrs
from qrs.fields import FieldSchema
from qrs.runtime import QrsDependencies
from qrs.context import DummyContextProvider
from qrs.services.certificateService import CreateTcertParams
from qrs.services.signingService import IssueSdocParams

async def main():
    qrs = create_qrs(QrsDependencies(
        context_provider=DummyContextProvider(secrets={"pin": "s3cret"}),
    ))

    # 1. Create a TCert (a document type schema).
    tcert = await qrs.certificates.create_tcert(CreateTcertParams(
        algorithm="Ed25519",
        name="AFDA Pharmacy License",
        fields=[
            FieldSchema(type="text", name="license_no", label="License number"),
            FieldSchema(type="date", name="expiry", label="Expiry date"),
            FieldSchema(type="secretInput", name="pin", label="PIN"),
        ],
    ))

    # 2. The verifier explicitly trusts the TCert (pin), or a CA attests it.
    await qrs.trust.pin(tcert.tcert_id)

    # 3. Issue an SDoc. The 'pin' secret is signed into the COSE external AAD
    #    but NOT stored in the SDoc.
    issued = await qrs.signing.issue_sdoc(IssueSdocParams(
        tcert_id=tcert.tcert_id,
        values={"license_no": "AFDA-123", "expiry": "2027-01-01", "pin": "s3cret"},
    ))

    # 4. Verify offline. The result distinguishes VALID / INVALID / CANNOT VERIFY.
    result = await qrs.verification.verify(issued.bytes)
    assert result.overall == "valid"
    print("SDoc", issued.sdoc_id, "→", result.overall)

asyncio.run(main())
```

## Trust model

Two levels (v1):

- **Pinned TCert** — the verifier explicitly trusts a TCert (`qrs.trust.pin`).
- **CA-issued TCert** — a TCert granted CA authority (`qrs.trust.add_ca`)
  signs an `attest` statement about a target TCert (`qrs.trust.attest`).

A TCert can be trusted through both mechanisms at once. The CA is not a special
object type — it is an ordinary TCert the verifier has configured with CA
authority. Servers are never trusted: everything downloaded is still verified
cryptographically before it is applied (`qrs.online.import_tcert`,
`qrs.online.import_statement`).

## Storage & context (IoC)

The core depends only on the interfaces in `qrs.storage.interfaces`:

| Store | Purpose |
| --- | --- |
| `IPrivateKeyStore` / `IPublicKeyStore` | key material (JWK) |
| `ICertificateStore` | signed TCert bytes |
| `IDocumentStore` | signed SDoc bytes |
| `IRevocationStore` | revoked TCerts / keys / blocked SDocs |
| `ITrustStore` | pinned / CA / distrusted / attestations |
| `IEndpointConfigStore` | mutable mirror endpoints (app-level, not protocol) |

In-memory stores are the default; JSON-file-backed stores are provided for the
CLI (`qrs.storage.memory_stores.create_file_stores`). A Django or FastAPI
consumer implements these interfaces over its ORM and injects them.

The `IContextProvider` abstraction supplies whatever external information a
field needs during verification: time, location, secrets, online objects. The
default `DummyContextProvider` never prompts (returns configured values or
`None`). Applications implement their own (e.g. a dialog, a GPS API, a token
vault).

## Extending the core

### New field type

```python
from qrs.fields import IFieldEngine, FieldSchema, FieldResult, VerificationContext, FieldInputError

class SsnField(IFieldEngine):
    type = "ssn"
    def validate_input(self, field, value):
        return None if isinstance(value, str) and len(value) == 10 \
               else FieldInputError(message=f"{field.label} must be a 10-char SSN")
    def encode(self, field, value): return value
    def decode(self, field, encoded): return encoded
    def get_context_requirements(self, field): return []
    async def validate_field(self, field, encoded, ctx):
        return FieldResult(name=field.name, label=field.label,
                           state="valid" if isinstance(encoded, str) else "invalid")

from qrs.field_registry import FieldRegistry, create_default_field_registry
registry = create_default_field_registry()
registry.register(SsnField())
qrs = create_qrs(QrsDependencies(field_registry=registry))
```

### New algorithm

```python
from qrs.crypto.registry import CryptoRegistry, create_default_crypto_registry
from qrs.crypto.providers import ICryptoProvider

class MyK256Provider(ICryptoProvider):
    algorithm = "K256"
    cose_algorithm_id = -46  # ECDSA-SHA256 over secp256k1 (example)
    ...  # implement generate/derive/sign/verify/canonical_public_key/key_id

registry = create_default_crypto_registry()
registry.register(MyK256Provider())
qrs = create_qrs(QrsDependencies(crypto_registry=registry))
```

## Wire format (compatibility with qrs-core)

- Identifiers: hex strings — `key_id` = `trunc_sha256(canonical CBOR of public
  JWK, 16 bytes)`, `tcert_id` = `keyId:certificateNumber`, `sdoc_id` =
  `trunc_sha256(signed bytes)`.
- Signed objects: `[protocolVersion, type, dataBytes]` inside a COSE_Sign1
  message (`["Signature1", protected, externalAad, payload]`).
- Canonical CBOR per RFC 8949 §4.2.1 (deterministic, no floats — regulated
  decimals use canonical strings).
- Secret-bound fields are signed into the COSE external AAD; they are never
  stored in the payload.
- Values in an SDoc are a **schema-indexed array** — field names/labels live
  only in the TCert schema, keeping the SDoc small enough for QR transfer.

## Tests

```bash
cd src/qrs-package
. .venv/bin/activate
PYTHONPATH=src pytest
```

Coverage: canonical CBOR, both crypto providers, COSE, signed objects, every
field engine, the storage interfaces (in-memory + file), the services, trust,
revocation, verification states, and end-to-end flows (full VALID path, wrong
secret, missing secret, untrusted TCert, revocation, CA attestation).

### Cross-implementation conformance

This package is a port of the reference TypeScript `qrs-core` (in
`src/qrs-core-js`). The conformance suite (`tests/test_conformance.py`) proves
the two cores are **wire-compatible**:

- **Golden vectors** — a shared `src/qrs-conformance/fixtures/golden.json`
  (generated by the reference) is consumed by both suites; each asserts it
  produces byte-identical canonical CBOR, hashes, key ids, identifiers and
  transfer envelopes.
- **Bidirectional cross-verification** — objects signed by the Python core
  verify in the reference JS core, and objects signed by the JS core verify in
  the Python core, for both Ed25519 and ECDSA-P256.

Regenerate the fixture after any wire-format change:

```bash
node src/qrs-conformance/generate-fixtures.mjs
```

The conformance tests require Node.js (for the JS verifier bridge) and the
`qrs-core-js` build (`npm run build` in `src/qrs-core-js`).