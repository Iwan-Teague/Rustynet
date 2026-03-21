#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin bootstrap_ci_tools -- "$@"
