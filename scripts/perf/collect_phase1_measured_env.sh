#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin collect_phase1_measured_env -- "$@"
