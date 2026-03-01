#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
OUTPUT_DIR="${1:-artifacts/membership/drills/$TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

cargo run -p rustynet-control -- --emit-membership-evidence "$OUTPUT_DIR"

if ! rg -q '"status":"pass"' "$OUTPUT_DIR/membership_conformance_report.json"; then
  echo "membership conformance drill failed"
  exit 1
fi
if ! rg -q '"status":"pass"' "$OUTPUT_DIR/membership_negative_tests_report.json"; then
  echo "membership negative-tests drill failed"
  exit 1
fi
if ! rg -q '"status":"pass"' "$OUTPUT_DIR/membership_recovery_report.json"; then
  echo "membership recovery drill failed"
  exit 1
fi

cat > "$OUTPUT_DIR/drill_summary.log" <<EOF
timestamp_utc=$TIMESTAMP
scenario=approver_compromise_recovery
conformance=pass
negative=pass
recovery=pass
audit_log=$OUTPUT_DIR/membership_audit_integrity.log
EOF

echo "membership incident drill complete: $OUTPUT_DIR"
