#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin phase1_gates -- "$@"
