#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin perf_regression_gate -- "$@"
