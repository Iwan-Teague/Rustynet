#!/usr/bin/env bash
# Thin CI-faithful cargo wrapper (for developers without `just`).
#
# Bare `cargo` on this Mac resolves rustc and cargo-clippy to the
# Homebrew-installed toolchain that shadows them on PATH, while CI builds with
# the toolchain pinned in rust-toolchain.toml. This wrapper forces the pinned
# rustup toolchain's bin directory onto PATH and points CARGO_TARGET_DIR at the
# dedicated target-pinned/ build dir, then execs cargo with the given
# arguments. See the justfile and the README "Build and Validate" section.
#
# Usage: scripts/dev/cargo-pinned.sh <cargo args...>
#   scripts/dev/cargo-pinned.sh clippy --workspace --all-targets --all-features -- -D warnings
set -euo pipefail

pin="1.88.0-aarch64-apple-darwin"
pinned_bin="$HOME/.rustup/toolchains/$pin/bin"

if [ ! -x "$pinned_bin/cargo" ]; then
    echo "ERROR: pinned toolchain not found: $pinned_bin" >&2
    echo "Install it with: rustup toolchain install 1.88.0 --profile minimal --component rustfmt clippy" >&2
    exit 1
fi

export PATH="$pinned_bin:$PATH"

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target-pinned}"

echo "== pinned $(rustc --version), $(cargo --version), CARGO_TARGET_DIR=$CARGO_TARGET_DIR" >&2
exec cargo "$@"
