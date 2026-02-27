#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

SBOM_JSON="artifacts/release/sbom.cargo-metadata.json"
SBOM_DIGEST_FILE="artifacts/release/sbom.sha256"
PROVENANCE_JSON="artifacts/release/rustynetd.provenance.json"

for file in "$SBOM_JSON" "$SBOM_DIGEST_FILE" "$PROVENANCE_JSON"; do
  if [[ ! -f "$file" ]]; then
    echo "missing release integrity artifact: $file"
    exit 1
  fi
done

expected_sbom_digest="$(cat "$SBOM_DIGEST_FILE" | tr -d '[:space:]')"
actual_sbom_digest="$(shasum -a 256 "$SBOM_JSON" | awk '{print $1}')"
if [[ "$expected_sbom_digest" != "$actual_sbom_digest" ]]; then
  echo "sbom digest mismatch"
  exit 1
fi

artifact_path="$(rg -o '"artifact_path": "[^"]+"' "$PROVENANCE_JSON" | sed -E 's/"artifact_path": "([^"]+)"/\1/')"
recorded_artifact_digest="$(rg -o '"sha256": "[^"]+"' "$PROVENANCE_JSON" | sed -E 's/"sha256": "([^"]+)"/\1/')"
if [[ ! -f "$artifact_path" ]]; then
  echo "provenance artifact not found: $artifact_path"
  exit 1
fi

actual_artifact_digest="$(shasum -a 256 "$artifact_path" | awk '{print $1}')"
if [[ "$recorded_artifact_digest" != "$actual_artifact_digest" ]]; then
  echo "artifact digest mismatch in provenance"
  exit 1
fi

echo "Release attestation verification: PASS"
