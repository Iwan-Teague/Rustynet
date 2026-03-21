#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin role_auth_matrix_gates -- "$@"
