#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin check_fresh_install_os_matrix_readiness -- "$@"
