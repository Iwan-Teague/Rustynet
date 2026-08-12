#!/usr/bin/env bash
# Linux exit-role orchestration parity gates. Hermetic: validates
# producer modules, orchestrator evaluator wiring, and unit tests only.
set -euo pipefail

echo "Running Linux exit-role CI gates..."

# --features vm-lab is REQUIRED, not decoration: the vm_lab:: modules filtered
# below sit behind that default-off feature (RNQ-17), so without it every
# filter matches zero tests -- and `cargo test` exits 0 on an empty match, so
# the gate would report success having checked nothing. run_cli_test asserts a
# non-zero pass count so an empty match can never read as a pass.
run_cli_test() {
  local out
  out="$(cargo test -p rustynet-cli --features vm-lab --bin rustynet-cli "$@" 2>&1)" || {
    printf '%s\n' "$out"
    return 1
  }
  if ! printf '%s\n' "$out" | grep -Eq 'test result: ok\. [1-9][0-9]* passed'; then
    echo "GATE DEFECT: test filter matched zero tests: $*" >&2
    return 1
  fi
}

required_files=(
  crates/rustynetd/src/linux_exit_nat_lifecycle.rs
  crates/rustynetd/src/linux_exit_dns_failclosed.rs
  scripts/e2e/capture_linux_exit_nat_lifecycle.sh
)

for path in "${required_files[@]}"; do
  test -f "$path"
done

rg -q 'linux-exit-nat-lifecycle-snapshot' crates/rustynetd/src/main.rs
rg -q 'linux-exit-dns-failclosed-capture' crates/rustynetd/src/main.rs
rg -q 'pub mod linux_exit_nat_lifecycle' crates/rustynetd/src/lib.rs
rg -q 'pub mod linux_exit_dns_failclosed' crates/rustynetd/src/lib.rs
rg -q 'validate_linux_exit_nat_lifecycle' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'validate_linux_exit_dns_failclosed' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'validate_linux_relay_service_lifecycle' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'validate_linux_anchor_bundle_pull' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'validate_linux_membership_genesis' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'evaluate_linux_exit_nat_lifecycle_artifact' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'merge_linux_exit_nat_lifecycle_artifact' crates/rustynetd/src/linux_exit_nat_lifecycle.rs

cargo test -p rustynetd --lib linux_exit_nat_lifecycle:: -- --nocapture
cargo test -p rustynetd --lib linux_exit_dns_failclosed:: -- --nocapture
run_cli_test \
  vm_lab::tests::evaluate_linux_exit_nat_lifecycle_artifact_accepts_reviewed_payload -- --nocapture
run_cli_test \
  vm_lab::tests::evaluate_linux_exit_dns_failclosed_artifact_dir_accepts_reviewed_payloads -- --nocapture
run_cli_test \
  vm_lab::tests::linux_exit_nat_lifecycle_producer_to_validator_round_trip -- --nocapture
run_cli_test \
  vm_lab::tests::linux_exit_nat_lifecycle_producer_round_trip_rejects_forwarding_not_restored -- --nocapture
run_cli_test \
  vm_lab::tests::linux_relay_lifecycle_output_validators_accept_reviewed_dry_run_text -- --nocapture
run_cli_test \
  vm_lab::tests::linux_membership_genesis_validator_accepts_reviewed_output -- --nocapture

echo "Linux exit-role CI gates: PASS"
