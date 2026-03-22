#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin real_wireguard_signed_state_tamper_e2e -- "$@"
