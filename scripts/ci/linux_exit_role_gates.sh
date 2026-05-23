#!/usr/bin/env bash
# Linux exit-role orchestration parity gates. Hermetic: validates
# producer modules, orchestrator evaluator wiring, and unit tests only.
set -euo pipefail

echo "Running Linux exit-role CI gates..."

required_files=(
  crates/rustynetd/src/linux_exit_nat_lifecycle.rs
  scripts/e2e/capture_linux_exit_nat_lifecycle.sh
)

for path in "${required_files[@]}"; do
  test -f "$path"
done

rg -q 'linux-exit-nat-lifecycle-snapshot' crates/rustynetd/src/main.rs
rg -q 'pub mod linux_exit_nat_lifecycle' crates/rustynetd/src/lib.rs
rg -q 'validate_linux_exit_nat_lifecycle' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'validate_linux_relay_service_lifecycle' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'validate_linux_anchor_bundle_pull' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'validate_linux_membership_genesis' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'evaluate_linux_exit_nat_lifecycle_artifact' crates/rustynet-cli/src/vm_lab/mod.rs
rg -q 'merge_linux_exit_nat_lifecycle_artifact' crates/rustynetd/src/linux_exit_nat_lifecycle.rs

cargo test -p rustynetd --lib linux_exit_nat_lifecycle:: -- --nocapture
cargo test -p rustynet-cli --bin rustynet-cli \
  vm_lab::tests::evaluate_linux_exit_nat_lifecycle_artifact_accepts_reviewed_payload -- --nocapture
cargo test -p rustynet-cli --bin rustynet-cli \
  vm_lab::tests::linux_exit_nat_lifecycle_producer_to_validator_round_trip -- --nocapture
cargo test -p rustynet-cli --bin rustynet-cli \
  vm_lab::tests::linux_exit_nat_lifecycle_producer_round_trip_rejects_forwarding_not_restored -- --nocapture
cargo test -p rustynet-cli --bin rustynet-cli \
  vm_lab::tests::linux_relay_lifecycle_output_validators_accept_reviewed_dry_run_text -- --nocapture
cargo test -p rustynet-cli --bin rustynet-cli \
  vm_lab::tests::linux_membership_genesis_validator_accepts_reviewed_output -- --nocapture

echo "Linux exit-role CI gates: PASS"
