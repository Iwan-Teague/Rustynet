#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin no_leak_dataplane_gate -- "$@"
