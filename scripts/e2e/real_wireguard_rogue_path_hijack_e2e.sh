#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin real_wireguard_rogue_path_hijack_e2e -- "$@"
