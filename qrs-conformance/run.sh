#!/usr/bin/env bash
# Run the full qrs-core conformance suite (both implementations).
# Usage: bash run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Building JS core (dist/)"
(cd "$ROOT/../qrs-core-js" && npm run build)

echo "==> JS core tests (incl. conformance)"
(cd "$ROOT/../qrs-core-js" && npm test)

echo "==> Python core tests (incl. conformance)"
(cd "$ROOT/../qrs-core-python" && . .venv/bin/activate && python -m pytest)

echo "==> Conformance OK"