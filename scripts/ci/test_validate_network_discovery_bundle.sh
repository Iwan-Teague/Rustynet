#!/usr/bin/env bash
set -euo pipefail

exec cargo run --quiet -p rustynet-cli --bin test_validate_network_discovery_bundle -- "$@"
