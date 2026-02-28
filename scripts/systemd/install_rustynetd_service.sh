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

SOCKET_PATH="${RUSTYNET_SOCKET:-/run/rustynet/rustynetd.sock}"
STATE_PATH="${RUSTYNET_STATE:-/var/lib/rustynet/rustynetd.state}"
TRUST_EVIDENCE_PATH="${RUSTYNET_TRUST_EVIDENCE:-/var/lib/rustynet/rustynetd.trust}"
TRUST_VERIFIER_KEY_PATH="${RUSTYNET_TRUST_VERIFIER_KEY:-/etc/rustynet/trust-evidence.pub}"
TRUST_WATERMARK_PATH="${RUSTYNET_TRUST_WATERMARK:-/var/lib/rustynet/rustynetd.trust.watermark}"
BACKEND_MODE="${RUSTYNET_BACKEND:-linux-wireguard}"
WG_INTERFACE="${RUSTYNET_WG_INTERFACE:-rustynet0}"
WG_PRIVATE_KEY_PATH="${RUSTYNET_WG_PRIVATE_KEY:-/etc/rustynet/wireguard.key}"
DATAPLANE_MODE="${RUSTYNET_DATAPLANE_MODE:-hybrid-native}"
RECONCILE_INTERVAL_MS="${RUSTYNET_RECONCILE_INTERVAL_MS:-1000}"
MAX_RECONCILE_FAILURES="${RUSTYNET_MAX_RECONCILE_FAILURES:-5}"
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
RUSTYNET_SOCKET=${SOCKET_PATH}
RUSTYNET_STATE=${STATE_PATH}
RUSTYNET_TRUST_EVIDENCE=${TRUST_EVIDENCE_PATH}
RUSTYNET_TRUST_VERIFIER_KEY=${TRUST_VERIFIER_KEY_PATH}
RUSTYNET_TRUST_WATERMARK=${TRUST_WATERMARK_PATH}
RUSTYNET_BACKEND=${BACKEND_MODE}
RUSTYNET_WG_INTERFACE=${WG_INTERFACE}
RUSTYNET_WG_PRIVATE_KEY=${WG_PRIVATE_KEY_PATH}
RUSTYNET_EGRESS_INTERFACE=${EGRESS_IFACE}
RUSTYNET_DATAPLANE_MODE=${DATAPLANE_MODE}
RUSTYNET_RECONCILE_INTERVAL_MS=${RECONCILE_INTERVAL_MS}
RUSTYNET_MAX_RECONCILE_FAILURES=${MAX_RECONCILE_FAILURES}
EOF
chmod 0644 "${ENV_DST}"

systemctl daemon-reload
systemctl enable rustynetd.service
systemctl restart rustynetd.service
systemctl --no-pager --full status rustynetd.service
