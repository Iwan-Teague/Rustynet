#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin live_linux_role_switch_matrix_test -- "$@"
