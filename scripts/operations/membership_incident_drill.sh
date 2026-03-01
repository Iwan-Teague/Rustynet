#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
OUTPUT_DIR="${1:-artifacts/membership}"
MEMBERSHIP_SNAPSHOT_PATH="${RUSTYNET_MEMBERSHIP_SNAPSHOT_PATH:-/var/lib/rustynet/membership.snapshot}"
MEMBERSHIP_LOG_PATH="${RUSTYNET_MEMBERSHIP_LOG_PATH:-/var/lib/rustynet/membership.log}"
MEMBERSHIP_EVIDENCE_ENVIRONMENT="${RUSTYNET_MEMBERSHIP_EVIDENCE_ENVIRONMENT:-incident-drill}"

mkdir -p "$OUTPUT_DIR"
cargo run -p rustynet-cli -- membership generate-evidence \
  --snapshot "$MEMBERSHIP_SNAPSHOT_PATH" \
  --log "$MEMBERSHIP_LOG_PATH" \
  --output-dir "$OUTPUT_DIR" \
  --environment "$MEMBERSHIP_EVIDENCE_ENVIRONMENT"

for artifact in \
  "$OUTPUT_DIR/membership_conformance_report.json" \
  "$OUTPUT_DIR/membership_negative_tests_report.json" \
  "$OUTPUT_DIR/membership_recovery_report.json" \
  "$OUTPUT_DIR/membership_audit_integrity.log"; do
  if [[ ! -f "$artifact" ]]; then
    echo "missing membership drill artifact: $artifact"
    exit 1
  fi
done

require_measured_evidence_metadata() {
  local artifact="$1"
  if ! rg -q '"evidence_mode"\s*:\s*"measured"' "$artifact"; then
    echo "artifact is not measured evidence: $artifact"
    exit 1
  fi
  if ! rg -q '"captured_at_unix"\s*:\s*[0-9]+' "$artifact"; then
    echo "artifact missing captured_at_unix metadata: $artifact"
    exit 1
  fi
  if ! rg -q '"environment"\s*:\s*"[^"]+"' "$artifact"; then
    echo "artifact missing environment metadata: $artifact"
    exit 1
  fi
}

require_measured_evidence_metadata "$OUTPUT_DIR/membership_conformance_report.json"
require_measured_evidence_metadata "$OUTPUT_DIR/membership_negative_tests_report.json"
require_measured_evidence_metadata "$OUTPUT_DIR/membership_recovery_report.json"

if ! rg -q '"status"\s*:\s*"pass"' "$OUTPUT_DIR/membership_conformance_report.json"; then
  echo "membership conformance drill failed"
  exit 1
fi
if ! rg -q '"status"\s*:\s*"pass"' "$OUTPUT_DIR/membership_negative_tests_report.json"; then
  echo "membership negative-tests drill failed"
  exit 1
fi
if ! rg -q '"status"\s*:\s*"pass"' "$OUTPUT_DIR/membership_recovery_report.json"; then
  echo "membership recovery drill failed"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
cat > "$OUTPUT_DIR/drill_summary.log" <<EOF
timestamp_utc=$TIMESTAMP
scenario=approver_compromise_recovery
conformance=pass
negative=pass
recovery=pass
audit_log=$OUTPUT_DIR/membership_audit_integrity.log
EOF

echo "membership incident drill complete: $OUTPUT_DIR"
