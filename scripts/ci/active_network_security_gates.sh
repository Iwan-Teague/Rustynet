#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin active_network_security_gates -- "$@"
