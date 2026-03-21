#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin check_phase9_readiness -- "$@"
