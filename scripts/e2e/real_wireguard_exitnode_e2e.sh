#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin real_wireguard_exitnode_e2e -- "$@"
