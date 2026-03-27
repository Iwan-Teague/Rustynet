#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin collect_linux_reconnect_bundle -- "$@"
