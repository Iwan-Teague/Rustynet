#!/usr/bin/env bash
set -euo pipefail

# Role-transition audit gates, extended to the eight-preset surface
# (D12 audit machinery + D13 service-hosting presets). The audit
# event types are generic over RolePreset/Capability, so nas/llm
# transitions and serves_nas/serves_llm capability mutations flow
# through the same hash-chained append-only log; these gates pin
# that the chain integrity properties and the eight-preset
# vocabulary hold together.

echo "Running role-transition audit gates (eight presets)..."

required_files=(
  crates/rustynet-control/src/role_audit.rs
  crates/rustynet-cli/src/role_cli.rs
  scripts/ci/role_taxonomy_gates.sh
)

for path in "${required_files[@]}"; do
  test -f "$path"
done

# The audit event vocabulary is generic over the canonical enums —
# the eight-preset extension must not have forked it.
rg -q 'RoleTransitionEvent' crates/rustynet-control/src/role_audit.rs
rg -q 'CapabilityMutation' crates/rustynet-control/src/role_audit.rs
rg -q 'emit_role_audit' crates/rustynet-cli/src/main.rs

run_required_test() {
  local out
  out="$(cargo test "$@" 2>&1)" || { printf '%s\n' "$out"; return 1; }
  printf '%s\n' "$out"
  if ! printf '%s\n' "$out" | grep -Eq 'test result: ok\. [1-9][0-9]* passed'; then
    echo "GATE DEFECT: test filter matched zero tests: cargo test $*" >&2
    return 1
  fi
}

# Hash-chain integrity (append-only, tamper-evident).
run_required_test -p rustynet-control role_audit::tests::append_chains_subsequent_entries
run_required_test -p rustynet-control role_audit::tests::tampering_with_payload_breaks_chain
run_required_test -p rustynet-control role_audit::tests::reordering_entries_breaks_chain
run_required_test -p rustynet-control role_audit::tests::capability_mutation_payload_contains_capability

# Eight-preset vocabulary feeding the audit events.
run_required_test -p rustynet-control role_presets::tests::preset_table_has_exactly_eight_entries
run_required_test -p rustynet-control role_presets::tests::capability_str_round_trip

echo "Role-transition audit gates: PASS"
