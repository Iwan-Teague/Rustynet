#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin live_linux_managed_dns_test -- --platform windows "$@"
