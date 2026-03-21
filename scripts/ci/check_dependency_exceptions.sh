#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

EXCEPTIONS_PATH="${RUSTYNET_DEPENDENCY_EXCEPTIONS_PATH:-documents/operations/dependency_exceptions.json}"

cargo run --quiet -p rustynet-cli -- ops check-dependency-exceptions \
  --path "$EXCEPTIONS_PATH"
