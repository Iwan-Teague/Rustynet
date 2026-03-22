#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin live_linux_server_ip_bypass_test -- "$@"
