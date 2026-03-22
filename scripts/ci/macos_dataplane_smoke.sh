#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin macos_dataplane_smoke -- "$@"
