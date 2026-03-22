#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin collect_network_discovery_info -- "$@"
