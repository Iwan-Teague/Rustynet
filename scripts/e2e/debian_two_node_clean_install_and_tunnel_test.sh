#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin debian_two_node_clean_install_and_tunnel_test -- "$@"
