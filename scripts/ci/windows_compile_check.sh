#!/usr/bin/env bash
# windows_compile_check.sh — local Windows compile gate (readiness plan E1).
#
# Cross-`cargo check`s the cfg(windows) code against x86_64-pc-windows-msvc (the
# lab guest's ABI) so Windows-only code gets compile feedback on the macOS host
# WITHOUT a full guest build. `cargo check` does not link, so the MSVC linker /
# Visual Studio toolchain is NOT required — only the rustup target std.
#
# WHY THE EXPLICIT TOOLCHAIN: on this host `cargo`/`rustc` on PATH resolve to
# Homebrew Rust, which ships only the macOS std (no Windows target) and is not
# rustup-managed. We therefore invoke the rustup toolchain's cargo + rustc
# directly (and pin RUSTC, because plain `rustup run` still let cargo pick up the
# Homebrew rustc via PATH). The toolchain channel is read from rust-toolchain.toml.
#
# USAGE
#   scripts/ci/windows_compile_check.sh                 # checks rustynetd + rustynet-cli
#   WINDOWS_CHECK_CRATES="-p rustynet-windows-native" scripts/ci/windows_compile_check.sh
#   WINDOWS_CHECK_TARGET=x86_64-pc-windows-gnu scripts/ci/windows_compile_check.sh
#
# SETUP (one-time): rustup target add x86_64-pc-windows-msvc  (for the pinned toolchain)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

TARGET="${WINDOWS_CHECK_TARGET:-x86_64-pc-windows-msvc}"
CRATES="${WINDOWS_CHECK_CRATES:--p rustynetd -p rustynet-cli}"

if ! command -v rustup >/dev/null 2>&1; then
  printf 'rustup is required (cargo/rustc on PATH may be Homebrew Rust without Windows target std)\n' >&2
  exit 2
fi

# Resolve the pinned toolchain channel from rust-toolchain.toml (fallback: stable).
CHANNEL="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' rust-toolchain.toml 2>/dev/null | head -1)"
CHANNEL="${CHANNEL:-stable}"

# Locate the rustup toolchain's cargo + rustc directly.
CARGO_BIN="$(rustup which --toolchain "$CHANNEL" cargo 2>/dev/null || true)"
if [[ -z "$CARGO_BIN" || ! -x "$CARGO_BIN" ]]; then
  printf 'cargo not found for rustup toolchain %s; install it: rustup toolchain install %s\n' "$CHANNEL" "$CHANNEL" >&2
  exit 2
fi
TC_BIN="$(dirname "$CARGO_BIN")"

# Verify the target std is present (cargo check needs core/std for the target).
if [[ ! -d "$(dirname "$TC_BIN")/lib/rustlib/$TARGET/lib" ]]; then
  printf 'Windows target std for %s missing in toolchain %s.\n' "$TARGET" "$CHANNEL" >&2
  printf 'Install it with:  rustup target add %s --toolchain %s\n' "$TARGET" "$CHANNEL" >&2
  exit 2
fi

printf '== Windows compile gate: cargo check --target %s (%s) %s ==\n' "$TARGET" "$CHANNEL" "$CRATES"
# shellcheck disable=SC2086
RUSTC="$TC_BIN/rustc" "$TC_BIN/cargo" check --target "$TARGET" $CRATES --all-features
printf '\nWindows compile gate passed for %s.\n' "$TARGET"
