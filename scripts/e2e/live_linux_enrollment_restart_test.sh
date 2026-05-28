#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin live_linux_enrollment_restart_test -- "$@"
