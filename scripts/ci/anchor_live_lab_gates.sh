#!/usr/bin/env bash
set -euo pipefail

echo "Running anchor live-lab CI gates..."

test -f crates/rustynet-cli/src/bin/live_linux_anchor_test.rs
test -x scripts/e2e/live_linux_anchor_test.sh
test -x scripts/e2e/live_macos_anchor_test.sh
test -x scripts/e2e/live_windows_anchor_test.sh
rg -q 'stage_run_live_anchor' scripts/e2e/live_linux_lab_orchestrator.sh
rg -q 'live_anchor' documents/operations/active/AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md

cargo test -p rustynet-cli --bin live_linux_anchor_test -- --nocapture
cargo test -p rustynet-cli --bin rustynet-cli \
  vm_lab::tests::validate_anchor_init_bundle_pull_plan -- --nocapture
cargo test -p rustynet-cli --bin rustynet-cli \
  vm_lab::tests::validate_windows_anchor_bundle_pull_plan_contract -- --nocapture
cargo test -p rustynet-cli --bin rustynet-cli \
  vm_lab::tests::validate_windows_relay_service_lifecycle_contract -- --nocapture

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
cargo run --quiet -p rustynet-cli --bin live_linux_anchor_test -- \
  --dry-run \
  --report-path "$tmp_dir/live_linux_anchor_report.json" \
  --log-path "$tmp_dir/live_linux_anchor.log"
cargo run --quiet -p rustynet-cli --bin live_linux_anchor_test -- \
  --platform macos \
  --dry-run \
  --report-path "$tmp_dir/live_macos_anchor_report.json" \
  --log-path "$tmp_dir/live_macos_anchor.log"
cargo run --quiet -p rustynet-cli --bin live_linux_anchor_test -- \
  --platform windows \
  --dry-run \
  --anchor-token-path 'C:\ProgramData\RustyNet\anchor\bundle-pull.token' \
  --membership-snapshot-path 'C:\ProgramData\RustyNet\state\membership.snapshot' \
  --report-path "$tmp_dir/live_windows_anchor_report.json" \
  --log-path "$tmp_dir/live_windows_anchor.log"

test -s "$tmp_dir/live_linux_anchor_report.json"
test -s "$tmp_dir/live_macos_anchor_report.json"
test -s "$tmp_dir/live_windows_anchor_report.json"
rg -q '"stage": "live_anchor"' "$tmp_dir/live_linux_anchor_report.json"
rg -q '"dry_run": true' "$tmp_dir/live_linux_anchor_report.json"
rg -q '"name": "validate_anchor_membership_advertise"' "$tmp_dir/live_linux_anchor_report.json"
rg -q '"name": "validate_anchor_bundle_pull"' "$tmp_dir/live_linux_anchor_report.json"
rg -q '"name": "validate_anchor_gossip_priority"' "$tmp_dir/live_linux_anchor_report.json"
rg -q '"name": "validate_anchor_enrollment_endpoint"' "$tmp_dir/live_linux_anchor_report.json"
rg -q '"name": "validate_anchor_downgrade_revocation"' "$tmp_dir/live_linux_anchor_report.json"
rg -q '"platform": "macos"' "$tmp_dir/live_macos_anchor_report.json"
rg -q '"platform": "windows"' "$tmp_dir/live_windows_anchor_report.json"

echo "Anchor live-lab CI gates: PASS"
