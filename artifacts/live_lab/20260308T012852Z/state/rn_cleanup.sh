#!/usr/bin/env bash
set -euo pipefail

run_root() {
  sudo -S -p '' "$@" < /tmp/rn_sudo.pass
}

run_root systemctl disable --now \
  rustynetd.service \
  rustynetd-privileged-helper.service \
  rustynetd-trust-refresh.service \
  rustynetd-trust-refresh.timer \
  rustynetd-assignment-refresh.service \
  rustynetd-assignment-refresh.timer >/dev/null 2>&1 || true
run_root pkill -f 'rustynetd daemon' >/dev/null 2>&1 || true
run_root pkill -f 'rustynetd privileged-helper' >/dev/null 2>&1 || true
run_root ip link set rustynet0 down >/dev/null 2>&1 || true
run_root ip link delete rustynet0 >/dev/null 2>&1 || true
run_root ip route flush table 51820 >/dev/null 2>&1 || true
run_root ip -6 route flush table 51820 >/dev/null 2>&1 || true
if command -v nft >/dev/null 2>&1; then
  while read -r family table_name; do
    [[ -n "${family}" && -n "${table_name}" ]] || continue
    run_root nft flush table "${family}" "${table_name}" >/dev/null 2>&1 || true
    run_root nft delete table "${family}" "${table_name}" >/dev/null 2>&1 || true
  done < <(run_root nft list tables 2>/dev/null | awk '/^table / && $3 ~ /^rustynet/ { print $2 " " $3 }' | tr -d '\r')
  if run_root nft list tables 2>/dev/null | awk '/^table / && $3 ~ /^rustynet/ { exit 0 } END { exit 1 }'; then
    echo "residual rustynet nftables state remained after cleanup" >&2
    exit 1
  fi
fi
run_root rm -f \
  /etc/systemd/system/rustynetd.service \
  /etc/systemd/system/rustynetd-privileged-helper.service \
  /etc/systemd/system/rustynetd-trust-refresh.service \
  /etc/systemd/system/rustynetd-trust-refresh.timer \
  /etc/systemd/system/rustynetd-assignment-refresh.service \
  /etc/systemd/system/rustynetd-assignment-refresh.timer
run_root systemctl daemon-reload >/dev/null 2>&1 || true
run_root rm -rf /etc/rustynet /var/lib/rustynet /run/rustynet
run_root rm -f /usr/local/bin/rustynet /usr/local/bin/rustynetd
rm -f /tmp/rn_sudo.pass /tmp/rn_bootstrap.env /tmp/rn_bootstrap.sh /tmp/rn_source.tar.gz
rm -rf "${HOME}/Rustynet"
