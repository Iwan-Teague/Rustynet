#!/usr/bin/env bash
set -euo pipefail

# LLM ↔ exit-node coexistence gates (D13.d — LlmNodeRoleDesign §6):
# when a client selects an exit node, internet egresses the exit
# while overlay (LLM/NAS) traffic stays intra-mesh. WireGuard's
# longest-prefix cryptokey routing provides the precedence; the
# daemon guard refuses any route set where the exit default would
# swallow the overlay because mesh routes were dropped.

echo "Running LLM exit-coexistence gates..."

required_files=(
  crates/rustynetd/src/daemon.rs
)

for path in "${required_files[@]}"; do
  test -f "$path"
done

# The guard exists and is wired into BOTH dataplane apply paths
# (bootstrap + reconcile), each with its own fail-closed reason tag.
rg -q 'fn enforce_overlay_exception_for_exit_routes' crates/rustynetd/src/daemon.rs
rg -q 'bootstrap_exit_overlay_exception_violated' crates/rustynetd/src/daemon.rs
rg -q 'reconcile_exit_overlay_exception_violated' crates/rustynetd/src/daemon.rs

run_required_test() {
  local out
  out="$(cargo test "$@" 2>&1)" || { printf '%s\n' "$out"; return 1; }
  printf '%s\n' "$out"
  if ! printf '%s\n' "$out" | grep -Eq 'test result: ok\. [1-9][0-9]* passed'; then
    echo "GATE DEFECT: test filter matched zero tests: cargo test $*" >&2
    return 1
  fi
}

run_required_test -p rustynetd --lib enforce_overlay_exception_accepts_exit_default_with_mesh_route
run_required_test -p rustynetd --lib enforce_overlay_exception_refuses_exit_default_without_mesh_route
run_required_test -p rustynetd --lib enforce_overlay_exception_accepts_route_sets_without_exit_default

echo "LLM exit-coexistence gates: PASS"
