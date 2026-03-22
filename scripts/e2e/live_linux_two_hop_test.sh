#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin live_linux_two_hop_test -- "$@"
