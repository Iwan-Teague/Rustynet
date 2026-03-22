#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin collect_platform_parity_bundle -- "$@"
