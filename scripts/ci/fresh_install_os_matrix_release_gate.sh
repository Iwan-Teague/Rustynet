#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin fresh_install_os_matrix_release_gate -- "$@"
