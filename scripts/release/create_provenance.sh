#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <artifact-path> <track> <output-json>"
  exit 1
fi

ARTIFACT_PATH="$1"
TRACK="$2"
OUTPUT_JSON="$3"

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

ARTIFACT_HASH="$(shasum -a 256 "$ARTIFACT_PATH" | awk '{print $1}')"
GENERATED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

mkdir -p "$(dirname "$OUTPUT_JSON")"
cat > "$OUTPUT_JSON" <<EOF
{
  "artifact_path": "$ARTIFACT_PATH",
  "sha256": "$ARTIFACT_HASH",
  "release_track": "$TRACK",
  "generated_at_utc": "$GENERATED_AT"
}
EOF

echo "Provenance generated: $OUTPUT_JSON"
