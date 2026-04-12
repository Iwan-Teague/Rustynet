#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin release_readiness_gates -- "$@"
