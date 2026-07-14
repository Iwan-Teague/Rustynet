#!/usr/bin/env bash
set -euo pipefail

echo "Running anchor live-lab CI gates..."

test -f crates/rustynet-cli/src/bin/live_linux_anchor_test.rs
test -f crates/rustynet-cli/src/bin/live_macos_anchor_test.rs
test -x scripts/e2e/live_linux_anchor_test.sh
test -x scripts/e2e/live_macos_anchor_test.sh
test -x scripts/e2e/live_macos_anchor_bundle_pull_test.sh
test -x scripts/e2e/live_windows_anchor_test.sh
test -f scripts/launchd/com.rustynet.anchor.plist
rg -q 'stage_run_live_anchor' scripts/e2e/live_linux_lab_orchestrator.sh
rg -q 'live_anchor' documents/operations/active/AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md

cargo test -p rustynet-cli --bin live_linux_anchor_test -- --nocapture
cargo test -p rustynet-cli --bin live_macos_anchor_test -- --nocapture
cargo test -p rustynetd --lib macos_service_hardening -- --nocapture
cargo test -p rustynet-cli --features vm-lab --bin rustynet-cli \
  ops_install_macos_anchor:: -- --nocapture
cargo test -p rustynet-cli --features vm-lab --bin rustynet-cli \
  vm_lab::tests::validate_macos_anchor_bundle_pull_report -- --nocapture
cargo test -p rustynet-cli --features vm-lab --bin rustynet-cli \
  vm_lab::tests::validate_anchor_init_bundle_pull_plan -- --nocapture
cargo test -p rustynet-cli --features vm-lab --bin rustynet-cli \
  vm_lab::tests::validate_windows_anchor_bundle_pull_plan_contract -- --nocapture
cargo test -p rustynet-cli --features vm-lab --bin rustynet-cli \
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
  --membership-log-path 'C:\ProgramData\RustyNet\state\membership.log' \
  --enrollment-secret-path 'C:\ProgramData\RustyNet\keys\enrollment.secret' \
  --enrollment-ledger-path 'C:\ProgramData\RustyNet\state\enrollment.ledger' \
  --owner-signing-key-path 'C:\ProgramData\RustyNet\keys\membership.owner.key' \
  --signing-key-passphrase-cred-path 'C:\ProgramData\RustyNet\keys\signing_key_passphrase.cred' \
  --report-path "$tmp_dir/live_windows_anchor_report.json" \
  --log-path "$tmp_dir/live_windows_anchor.log"

cargo run --quiet -p rustynet-cli --bin live_macos_anchor_test -- \
  --dry-run \
  --report-path "$tmp_dir/live_macos_anchor_bundle_pull_report.json" \
  --log-path "$tmp_dir/live_macos_anchor_bundle_pull.log"

test -s "$tmp_dir/live_linux_anchor_report.json"
test -s "$tmp_dir/live_macos_anchor_report.json"
test -s "$tmp_dir/live_windows_anchor_report.json"
test -s "$tmp_dir/live_macos_anchor_bundle_pull_report.json"
rg -q '"stage": "live_macos_anchor_bundle_pull"' "$tmp_dir/live_macos_anchor_bundle_pull_report.json"
rg -q '"name": "validate_macos_anchor_bundle_pull_lan_refused"' "$tmp_dir/live_macos_anchor_bundle_pull_report.json"
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
