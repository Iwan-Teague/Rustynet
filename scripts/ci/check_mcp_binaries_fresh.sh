#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin check_mcp_binaries_fresh -- "$@"
