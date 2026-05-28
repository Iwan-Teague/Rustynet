#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin live_linux_secrets_not_in_logs_test -- "$@"
