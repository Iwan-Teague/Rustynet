#!/usr/bin/env bash
set -euo pipefail
exec cargo run --quiet -p rustynet-cli --bin test_check_fresh_install_os_matrix_readiness -- "$@"
