#!/usr/bin/env bash
set -euo pipefail

exec cargo run --quiet -p rustynet-cli --bin check_phase6_platform_parity -- "$@"
