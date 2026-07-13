#!/usr/bin/env bash
set -euo pipefail

# Standalone gate wrapper for the `rustynet-lab-monitor` crate.
#
# WHY THIS EXISTS: rustynet-lab-monitor is intentionally EXCLUDED from the main
# Cargo workspace (see the root Cargo.toml `exclude` list and the crate's
# README). The workspace CI gates (`cargo ... --workspace`) therefore never
# touch it -- a fmt/clippy/check/test regression in the monitor is completely
# invisible to them. This script is that crate's first-class gate: it runs the
# same four gates the §7 workspace list runs, but scoped to the standalone
# crate from inside its own directory (which has its own Cargo.lock). Wire it
# into CI alongside the workspace gates so the excluded crate stays green.
#
# The crate is macOS/Linux only (it runs on the lab host machine and has no
# Windows port -- see LabMonitorTUIDesign_2026-06-29.md §10 Non-Goals), so this
# gate belongs on the macOS and Linux CI legs, not the Windows leg.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
crate_dir="${repo_root}/crates/rustynet-lab-monitor"

echo "Running rustynet-lab-monitor standalone gates (workspace-excluded crate)..."
cd "${crate_dir}"

echo "[1/4] cargo fmt --check"
cargo fmt --check

echo "[2/4] cargo clippy --all-targets --locked -- -D warnings"
cargo clippy --all-targets --locked -- -D warnings

echo "[3/4] cargo check --all-targets --locked"
cargo check --all-targets --locked

echo "[4/4] cargo test --locked"
cargo test --locked

echo "rustynet-lab-monitor standalone gates: PASS"
