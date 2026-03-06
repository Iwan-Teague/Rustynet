#!/usr/bin/env bash
set -euo pipefail

RUSTYNET_BIN="${RUSTYNET_BIN:-/usr/local/bin/rustynet}"
if [[ ! -x "${RUSTYNET_BIN}" ]]; then
  RUSTYNET_BIN="$(command -v rustynet || true)"
fi
if [[ -z "${RUSTYNET_BIN}" ]]; then
  echo "[assignment-refresh] required command not found: rustynet" >&2
  exit 1
fi

exec "${RUSTYNET_BIN}" ops refresh-assignment
