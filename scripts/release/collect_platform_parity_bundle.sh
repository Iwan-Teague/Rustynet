#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

RAW_DIR="${RUSTYNET_PHASE6_PARITY_RAW_DIR:-artifacts/release/raw}"
INBOX_DIR="${RUSTYNET_PHASE6_PARITY_INBOX_DIR:-artifacts/release/inbox}"
STRICT_MODE="${RUSTYNET_PHASE6_PARITY_STRICT:-1}"

mkdir -p "$RAW_DIR"
mkdir -p "$INBOX_DIR"

./scripts/release/collect_platform_probe.sh

for platform in linux macos windows; do
  raw_path="$RAW_DIR/platform_parity_${platform}.json"
  inbox_path="$INBOX_DIR/platform_parity_${platform}.json"

  if [[ ! -f "$raw_path" && -f "$inbox_path" ]]; then
    cp "$inbox_path" "$raw_path"
  fi

  if [[ ! -f "$raw_path" ]]; then
    echo "missing platform parity probe for ${platform}: expected $raw_path or $inbox_path" >&2
    exit 1
  fi
done

RUSTYNET_PHASE6_PARITY_RAW_DIR="$RAW_DIR" ./scripts/release/generate_platform_parity_report.sh

if [[ "$STRICT_MODE" == "1" ]]; then
  ./scripts/ci/check_phase6_platform_parity.sh
fi

echo "phase6 platform parity bundle generated from probes"
