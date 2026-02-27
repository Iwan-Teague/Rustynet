#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="artifacts/release"
SBOM_JSON="$OUT_DIR/sbom.cargo-metadata.json"
SBOM_DIGEST="$OUT_DIR/sbom.sha256"

mkdir -p "$OUT_DIR"
cargo metadata --format-version 1 > "$SBOM_JSON"
shasum -a 256 "$SBOM_JSON" | awk '{print $1}' > "$SBOM_DIGEST"

echo "SBOM generated:"
echo "  - $SBOM_JSON"
echo "  - $SBOM_DIGEST"
