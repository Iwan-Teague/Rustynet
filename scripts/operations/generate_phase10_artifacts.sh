#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin generate_phase10_artifacts -- "$@"
