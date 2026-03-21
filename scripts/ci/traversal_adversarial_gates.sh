#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin traversal_adversarial_gates -- "$@"
