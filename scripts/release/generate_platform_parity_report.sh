#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin generate_platform_parity_report -- "$@"
