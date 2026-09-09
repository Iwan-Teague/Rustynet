#!/usr/bin/env bash
# QH-82 platform-infer tripwire: fails when `infer(` is composed with an
# `unwrap_or`/`unwrap_or_else` fallback yielding VmGuestPlatform::Linux, or
# when a bare `unwrap_or(VmGuestPlatform::Linux)` appears in the scanned
# tree. See the binary for the exact rule set.
exec cargo run --quiet -p rustynet-cli --bin check_platform_infer_tripwire -- "$@"
