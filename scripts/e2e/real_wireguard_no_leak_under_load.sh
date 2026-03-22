#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin real_wireguard_no_leak_under_load -- "$@"
