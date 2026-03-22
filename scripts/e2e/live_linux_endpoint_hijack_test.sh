#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin live_linux_endpoint_hijack_test -- "$@"
