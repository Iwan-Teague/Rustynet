#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin live_linux_network_flap_test -- "$@"
