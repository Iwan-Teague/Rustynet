#!/usr/bin/env bash
set -euo pipefail

if ! command -v rustynet >/dev/null 2>&1; then
  echo "rustynet CLI is required in PATH" >&2
  exit 1
fi

exec rustynet ops run-debian-two-node-e2e "$@"
