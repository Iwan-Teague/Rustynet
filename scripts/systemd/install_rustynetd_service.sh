#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVICE_SRC="${ROOT_DIR}/scripts/systemd/rustynetd.service"
SERVICE_DST="/etc/systemd/system/rustynetd.service"
ENV_DST="/etc/default/rustynetd"

if [[ ! -f "${SERVICE_SRC}" ]]; then
  echo "missing service file: ${SERVICE_SRC}" >&2
  exit 1
fi

install -d -m 0700 /etc/rustynet /run/rustynet /var/lib/rustynet
install -m 0644 "${SERVICE_SRC}" "${SERVICE_DST}"

EGRESS_IFACE="${RUSTYNET_EGRESS_INTERFACE:-}"
if [[ -z "${EGRESS_IFACE}" ]]; then
  EGRESS_IFACE="$(ip -o -4 route show to default | awk 'NR==1 { print $5 }')"
fi
if [[ -z "${EGRESS_IFACE}" ]]; then
  echo "unable to detect default egress interface; set RUSTYNET_EGRESS_INTERFACE" >&2
  exit 1
fi
if ! ip link show "${EGRESS_IFACE}" >/dev/null 2>&1; then
  echo "egress interface does not exist: ${EGRESS_IFACE}" >&2
  exit 1
fi
cat >"${ENV_DST}" <<EOF
RUSTYNET_EGRESS_INTERFACE=${EGRESS_IFACE}
EOF
chmod 0644 "${ENV_DST}"

systemctl daemon-reload
systemctl enable rustynetd.service
systemctl restart rustynetd.service
systemctl --no-pager --full status rustynetd.service
