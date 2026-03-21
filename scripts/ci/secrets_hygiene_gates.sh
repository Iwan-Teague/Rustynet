#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin secrets_hygiene_gates -- "$@"
