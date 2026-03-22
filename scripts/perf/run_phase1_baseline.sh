#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin run_phase1_baseline -- "$@"
