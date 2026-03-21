#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin prepare_advisory_db -- "$@"
