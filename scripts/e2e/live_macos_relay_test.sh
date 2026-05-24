#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin live_linux_relay_test -- --platform macos "$@"
