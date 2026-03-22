#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin test_validate_cross_network_nat_matrix -- "$@"
