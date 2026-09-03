#!/usr/bin/env bash
set -euo pipefail

# Compile gate for the `fuzz/` crate.
#
# WHY THIS EXISTS: fuzz/ declares its own [workspace] (like
# crates/rustynet-lab-monitor), so every `cargo ... --workspace` gate in
# AGENTS.md §7 skips it entirely. Nothing else in CI references it, which
# meant a fuzz target that stopped compiling was invisible until someone
# ran cargo-fuzz by hand. This script is that crate's gate.
#
# WHAT IT DOES: `cargo build --bins` from inside fuzz/ compiles every
# [[bin]] in fuzz/Cargo.toml (ipc_parse_command, membership_decode_state,
# membership_decode_signed_update) as regular binaries under the repo's
# pinned stable toolchain (rust-toolchain.toml). libfuzzer-sys' default
# `link_libfuzzer` feature builds the bundled libFuzzer C++ runtime via
# the `cc` crate, so a C++ compiler must exist (bootstrap_ci_tools.sh
# installs build-essential on Debian; macOS runners ship clang) — but no
# nightly toolchain, cargo-fuzz, or -Zsanitizer is required, because
# instrumentation is what cargo-fuzz adds at link time, not something the
# harness source needs to typecheck. We are asserting "the targets still
# compile", not running the fuzzer.
#
# WHY IT CANNOT PASS ON A BROKEN TARGET: cargo build returns non-zero when
# any [[bin]] fails to compile, and `set -euo pipefail` turns that into the
# script's exit status (verified: a deliberately-broken target made this
# gate exit 101 with `error[E0425]`). There is no codegen-free shortcut:
# cargo build compiles each bin through to linking. No --locked here: the
# fuzz workspace's Cargo.lock is deliberately gitignored (cargo-fuzz
# regenerates it), so cargo resolves the graph from the manifests each
# run; a dependency removed upstream is still caught because the targets
# must then name-resolve against whatever crate actually builds.
#
# Scope note: macOS/Linux only. The Windows CI leg omits this gate the same
# way it omits lab_monitor_gates.sh; MSVC has no libFuzzer runtime to link.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
crate_dir="${repo_root}/fuzz"

echo "Running fuzz-target compile gate (workspace-excluded crate)..."
cd "${crate_dir}"

echo "[1/2] cargo build --bins"
cargo build --bins

echo "[2/2] fuzz target inventory"
for target in ipc_parse_command membership_decode_state membership_decode_signed_update; do
  test -f "fuzz_targets/${target}.rs" || {
    echo "fuzz target source missing: fuzz_targets/${target}.rs" >&2
    exit 1
  }
done
echo "fuzz-target compile gate: PASS"
