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
#
# SUPPLY-CHAIN COVERAGE: the root `cargo audit --deny warnings` reads only the
# ROOT Cargo.lock, so this crate's own Cargo.lock was never audited. Step 5 runs
# cargo-audit against it. If cargo-audit is not installed the step SKIPS LOUDLY
# (stderr banner + a GitHub ::warning annotation, and the PASS line says so),
# unless RUSTYNET_REQUIRE_CARGO_AUDIT=1, which turns a missing cargo-audit into a
# failure (the CI legs set it: bootstrap_ci_tools installs cargo-audit first).
# Other lockfiles still unaudited by any gate: gui/node-map-tool/Cargo.lock and
# third_party/boringtun/Cargo.lock (see CiGateWiringAudit_2026-11-01.md).

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
crate_dir="${repo_root}/crates/rustynet-lab-monitor"

# Zero-match guard (run_required_test). Sourced by absolute path BEFORE the cd
# below, because BASH_SOURCE[0] may be relative to the caller's cwd.
# shellcheck source=lib/required_test.sh
source "${repo_root}/scripts/ci/lib/required_test.sh"

echo "Running rustynet-lab-monitor standalone gates (workspace-excluded crate)..."
cd "${crate_dir}"

echo "[1/5] cargo fmt --check"
cargo fmt --check

echo "[2/5] cargo clippy --all-targets --locked -- -D warnings"
cargo clippy --all-targets --locked -- -D warnings

echo "[3/5] cargo check --all-targets --locked"
cargo check --all-targets --locked

echo "[4/5] cargo test --locked (fails if the suite ran zero tests)"
run_required_test --locked

echo "[5/5] cargo audit --deny warnings (this crate's own Cargo.lock)"
audit_note=""
if cargo audit --version >/dev/null 2>&1; then
  cargo audit --deny warnings --file Cargo.lock
elif [ "${RUSTYNET_REQUIRE_CARGO_AUDIT:-0}" = "1" ]; then
  echo "FAIL: cargo-audit is required (RUSTYNET_REQUIRE_CARGO_AUDIT=1) but is not installed" >&2
  exit 1
else
  echo "SKIP: cargo-audit is not installed; crates/rustynet-lab-monitor/Cargo.lock was NOT audited" >&2
  echo "::warning::lab-monitor cargo audit skipped: cargo-audit not installed" >&2
  audit_note=" (cargo audit SKIPPED: cargo-audit not installed)"
fi

echo "rustynet-lab-monitor standalone gates: PASS${audit_note}"
