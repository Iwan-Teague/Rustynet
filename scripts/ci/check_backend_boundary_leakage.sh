#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin check_backend_boundary_leakage -- "$@"
