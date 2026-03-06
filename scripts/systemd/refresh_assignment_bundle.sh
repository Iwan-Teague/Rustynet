#!/usr/bin/env bash
set -euo pipefail

RUSTYNET_BIN="${RUSTYNET_BIN:-/usr/local/bin/rustynet}"
if [[ "${RUSTYNET_BIN}" != /* ]]; then
  echo "[assignment-refresh] RUSTYNET_BIN must be an absolute path: ${RUSTYNET_BIN}" >&2
  exit 1
fi
if [[ ! -x "${RUSTYNET_BIN}" ]]; then
  echo "[assignment-refresh] required executable not found: ${RUSTYNET_BIN}" >&2
  exit 1
fi

bin_uid=""
if stat -c '%u' "${RUSTYNET_BIN}" >/dev/null 2>&1; then
  bin_uid="$(stat -c '%u' "${RUSTYNET_BIN}")"
elif stat -f '%u' "${RUSTYNET_BIN}" >/dev/null 2>&1; then
  bin_uid="$(stat -f '%u' "${RUSTYNET_BIN}")"
fi
if [[ "${bin_uid}" != "0" ]]; then
  echo "[assignment-refresh] rustynet binary must be root-owned: ${RUSTYNET_BIN}" >&2
  exit 1
fi

bin_mode=""
if stat -c '%a' "${RUSTYNET_BIN}" >/dev/null 2>&1; then
  bin_mode="$(stat -c '%a' "${RUSTYNET_BIN}")"
elif stat -f '%OLp' "${RUSTYNET_BIN}" >/dev/null 2>&1; then
  bin_mode="$(stat -f '%OLp' "${RUSTYNET_BIN}")"
  bin_mode="${bin_mode#0}"
fi
if [[ "${bin_mode}" =~ ^[0-9]{3,4}$ ]]; then
  mode3="${bin_mode: -3}"
  group_digit="${mode3:1:1}"
  other_digit="${mode3:2:1}"
  if (( (10#${group_digit} & 2) != 0 || (10#${other_digit} & 2) != 0 )); then
    echo "[assignment-refresh] rustynet binary must not be group/world writable: ${RUSTYNET_BIN} (${mode3})" >&2
    exit 1
  fi
else
  echo "[assignment-refresh] unable to validate binary mode: ${RUSTYNET_BIN}" >&2
  exit 1
fi

exec "${RUSTYNET_BIN}" ops refresh-assignment
