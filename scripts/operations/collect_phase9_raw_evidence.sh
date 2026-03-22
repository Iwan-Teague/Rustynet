#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin collect_phase9_raw_evidence -- "$@"
