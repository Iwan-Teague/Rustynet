#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin test_validate_network_discovery_bundle -- "$@"
