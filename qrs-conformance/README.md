# qrs-core conformance suite

Proves the two `qrs-core` implementations — the reference TypeScript core
(`../qrs-core-js`) and the Python port (`../qrs-core-python`) — are
**wire-compatible**: data produced by one is consumable by the other.

## Layout

- `generate-fixtures.mjs` — generates `fixtures/golden.json` from the reference
  JS core (canonical CBOR, hashes, key ids, identifiers, transfer envelopes).
- `fixtures/golden.json` — the shared, language-neutral golden vectors.
- `verify_js.mjs` — Node bridge: verifies a signed object (base64url on stdin)
  and prints a JSON verdict. Used by the Python tests.
- `verify_python.py` — Python bridge: verifies a signed object and prints a JSON
  verdict. Used by the JS tests.

## How the tests use it

- **JS** (`../qrs-core-js/test/conformance.test.ts`): self-checks against
  `golden.json`, and shells out to `verify_python.py` to verify JS-signed
  objects in the Python core.
- **Python** (`../qrs-core-python/tests/test_conformance.py`): self-checks
  against `golden.json`, and shells out to `verify_js.mjs` to verify
  Python-signed objects in the JS core.

## Regenerating the fixture

After any wire-format change:

```bash
node generate-fixtures.mjs
```

## Running everything

```bash
# 1. Build the JS core (the conformance tests import dist/)
cd ../qrs-core-js && npm run build && npm test

# 2. Python core (needs its venv + Node for the JS bridge)
cd ../qrs-core-python && . .venv/bin/activate && python -m pytest
```

## Prerequisites

- Node.js ≥ 20 (for the JS core, the fixture generator, and `verify_js.mjs`).
- Python ≥ 3.11 with `cryptography`, `pytest`, `pytest-asyncio` (see
  `../qrs-core-python/README.md`).
- The Python venv at `../qrs-core-python/.venv` (the JS conformance test invokes
  its interpreter directly).