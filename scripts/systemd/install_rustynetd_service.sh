#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUSTYNET_BIN="${RUSTYNET_BIN:-/usr/local/bin/rustynet}"
if [[ ! -x "${RUSTYNET_BIN}" ]]; then
  RUSTYNET_BIN="$(command -v rustynet || true)"
fi
if [[ -z "${RUSTYNET_BIN}" ]]; then
  echo "[install-systemd] required command not found: rustynet" >&2
  exit 1
fi

export RUSTYNET_INSTALL_SOURCE_ROOT="${ROOT_DIR}"
exec "${RUSTYNET_BIN}" ops install-systemd
