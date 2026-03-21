#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin security_regression_gates -- "$@"
