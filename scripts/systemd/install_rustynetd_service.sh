#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUSTYNET_BIN="${RUSTYNET_BIN:-/usr/local/bin/rustynet}"
if [[ "${RUSTYNET_BIN}" != "/usr/local/bin/rustynet" ]]; then
  echo "[install-systemd] one hardened path is enforced; expected /usr/local/bin/rustynet, got: ${RUSTYNET_BIN}" >&2
  exit 1
fi

export RUSTYNET_INSTALL_SOURCE_ROOT="${ROOT_DIR}"
"${RUSTYNET_BIN}" ops verify-runtime-binary-custody >/dev/null
exec "${RUSTYNET_BIN}" ops install-systemd
