#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

exec cargo run --quiet -p rustynet-cli --bin test_validate_cross_network_remote_exit_reports -- "$@"
