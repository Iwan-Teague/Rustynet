#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin test_cross_network_remote_exit_skeleton_validators -- "$@"
