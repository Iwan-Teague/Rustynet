#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <artifact-path> <track> <output-json>"
  exit 1
fi

ARTIFACT_PATH="$1"
TRACK="$2"
OUTPUT_JSON="$3"
OUTPUT_DIR="$(dirname "$OUTPUT_JSON")"
SBOM_JSON="${RUSTYNET_RELEASE_SBOM_PATH:-$OUTPUT_DIR/sbom.cargo-metadata.json}"
SBOM_DIGEST="${RUSTYNET_RELEASE_SBOM_SHA256_PATH:-$OUTPUT_DIR/sbom.sha256}"

case "$TRACK" in
  unstable|canary|stable|internal|beta) ;;
  *)
    echo "invalid release track: $TRACK"
    exit 1
    ;;
esac

if [[ ! -f "$ARTIFACT_PATH" ]]; then
  echo "artifact not found: $ARTIFACT_PATH"
  exit 1
fi
if [[ ! -f "$SBOM_JSON" ]]; then
  echo "sbom not found: $SBOM_JSON"
  exit 1
fi
if [[ ! -f "$SBOM_DIGEST" ]]; then
  echo "sbom digest not found: $SBOM_DIGEST"
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT_JSON")"
RUSTYNET_RELEASE_ARTIFACT_PATH="$ARTIFACT_PATH" \
RUSTYNET_RELEASE_TRACK="$TRACK" \
RUSTYNET_RELEASE_PROVENANCE_PATH="$OUTPUT_JSON" \
RUSTYNET_RELEASE_SBOM_PATH="$SBOM_JSON" \
RUSTYNET_RELEASE_SBOM_SHA256_PATH="$SBOM_DIGEST" \
cargo run --quiet -p rustynet-cli -- ops sign-release-artifact
