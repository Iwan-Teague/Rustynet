#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin install_rustynetd_service -- "$@"
