#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin verify_release_attestation -- "$@"
