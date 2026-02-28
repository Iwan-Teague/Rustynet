#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVICE_SRC="${ROOT_DIR}/scripts/systemd/rustynetd.service"
SERVICE_DST="/etc/systemd/system/rustynetd.service"

if [[ ! -f "${SERVICE_SRC}" ]]; then
  echo "missing service file: ${SERVICE_SRC}" >&2
  exit 1
fi

install -d -m 0700 /etc/rustynet /run/rustynet /var/lib/rustynet
install -m 0644 "${SERVICE_SRC}" "${SERVICE_DST}"

systemctl daemon-reload
systemctl enable rustynetd.service
systemctl restart rustynetd.service
systemctl --no-pager --full status rustynetd.service
