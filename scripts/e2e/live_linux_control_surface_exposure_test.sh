#!/usr/bin/env bash
exec cargo run --quiet -p rustynet-cli --bin live_linux_control_surface_exposure_test -- "$@"
