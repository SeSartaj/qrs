# QRS

QRS is a signed credential and document-verification system. It lets issuers
publish verifiable credentials (TCerts), signed statements, and attachments;
verifiers fetch that data and validate it locally.

## Repository layout

- `qrs-core-js/` — canonical protocol implementation for CBOR, COSE, TCerts,
  SDocs, signing, and verification.
- `qrs-core-python/` — Python bindings and protocol support.
- `qrs-server/` — Django distribution server for public discovery and storage.
- `qrs-desktop/` — desktop client.
- `qrs-mobile-app/` — mobile client.
- `qrs-conformance/` — cross-implementation conformance tests.

## How QRS works

1. An issuer creates and signs a TCert using its private key.
2. A verifier receives the TCert and checks its signature and trust chain.
3. The issuer publishes signed statements and optional attachments through the
   QRS server.
4. A verifier fetches the published data and verifies signatures, attestations,
   revocations, blocks, and attachment hashes locally.

The server is only a distribution layer. It never receives private keys and is
not trusted to make verification decisions.

## Using the server

The server is in [`qrs-server/`](qrs-server/). Run it locally with:

```bash
cd qrs-server
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
npm install
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
```

See [`qrs-server/README.md`](qrs-server/README.md) for the API, CA enrollment,
upload-token flow, attachments, administration, and Docker deployment.

## Development

Keep protocol logic in small, tested functions. Client and server code should
reuse `qrs-core` for serialization, signing, and verification rather than
implementing cryptography or wire-format handling independently.
