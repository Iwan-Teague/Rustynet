#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin supply_chain_integrity_gates -- "$@"
