#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin fuzz_smoke -- "$@"
