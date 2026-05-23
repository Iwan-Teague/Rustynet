#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

WORK_DIR="${TMPDIR:-/tmp}/rustynet-chaos-gates.$$"
mkdir -p "$WORK_DIR"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "[chaos-gates] checking impairment harness parser"
bash scripts/e2e/chaos_impair_link.sh \
  --mode plan \
  --platform linux \
  --interface rustynet0 \
  --allow-interface rustynet0 \
  --profile loss \
  --direction both \
  --output-path "$WORK_DIR/impair_loss.json" >/dev/null
grep -q '"status": "planned"' "$WORK_DIR/impair_loss.json"
if bash scripts/e2e/chaos_impair_link.sh \
  --mode plan \
  --platform linux \
  --interface en0 \
  --profile loss \
  --direction both \
  --output-path "$WORK_DIR/impair_reject.json" >/dev/null 2>&1
then
  echo "impairment harness accepted a non-allow-listed interface" >&2
  exit 1
fi

echo "[chaos-gates] checking signed bundle forger"
cargo run --quiet -p rustynet-cli --features chaos-forger --bin live_signed_bundle_forger -- \
  --output-dir "$WORK_DIR/forger" \
  --scenario all >/dev/null
grep -q '"production_accepted": false' "$WORK_DIR/forger/manifest.json"
grep -q 'forged_signature_attempt' "$WORK_DIR/forger/manifest.json"

echo "[chaos-gates] checking category dry-run reports"
for bin in \
  live_chaos_daemon_fault_test \
  live_chaos_clock_attack_test \
  live_chaos_signed_state_adversarial_test \
  live_chaos_crash_recovery_test \
  live_chaos_resource_exhaustion_test \
  live_chaos_network_impairment_test \
  live_chaos_membership_adversarial_test \
  live_chaos_privileged_boundary_test
do
  cargo run --quiet -p rustynet-cli --bin "$bin" -- \
    --dry-run \
    --report-path "$WORK_DIR/${bin}.json" \
    --log-path "$WORK_DIR/${bin}.log" >/dev/null
  grep -q '"suite": "rustynet-live-lab-chaos"' "$WORK_DIR/${bin}.json"
  grep -q '"requires_explicit_enable_chaos_suite": true' "$WORK_DIR/${bin}.json"
done
grep -q '"category": "chaos_signed_state_adversarial"' "$WORK_DIR/live_chaos_signed_state_adversarial_test.json"
grep -q '"overall_status": "pass"' "$WORK_DIR/live_chaos_signed_state_adversarial_test.json"
grep -q '"expected_result": "reject_fail_closed"' "$WORK_DIR/live_chaos_signed_state_adversarial_test.json"
grep -q '"production_accepted": false' "$WORK_DIR/live_chaos_signed_state_adversarial_test.json"

echo "[chaos-gates] pass"
