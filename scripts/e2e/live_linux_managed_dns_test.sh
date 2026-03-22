#!/usr/bin/env bash
set -euo pipefail

exec cargo run --quiet -p rustynet-cli --bin live_linux_managed_dns_test -- "$@"
