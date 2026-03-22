#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin apply_cross_network_impairment_profile -- "$@"
