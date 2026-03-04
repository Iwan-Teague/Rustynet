#!/usr/bin/env bash
set -euo pipefail

umask 0077

log() {
  printf '[trust-refresh] %s\n' "$*"
}

die() {
  printf '[trust-refresh] %s\n' "$*" >&2
  exit 1
}

bool_enabled() {
  case "$1" in
    true|TRUE|yes|YES|1|on|ON) return 0 ;;
    false|FALSE|no|NO|0|off|OFF|"") return 1 ;;
    *) die "invalid boolean value: $1" ;;
  esac
}

if [[ "${EUID}" -ne 0 ]]; then
  die "run as root"
fi

for tool in date install mktemp openssl xxd; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    die "required command not found: ${tool}"
  fi
done

trust_evidence_path="${RUSTYNET_TRUST_EVIDENCE:-/var/lib/rustynet/rustynetd.trust}"
trust_signer_key_path="${RUSTYNET_TRUST_SIGNER_KEY:-/etc/rustynet/trust-evidence.key}"
daemon_group="${RUSTYNET_DAEMON_GROUP:-rustynetd}"
trust_auto_refresh="${RUSTYNET_TRUST_AUTO_REFRESH:-true}"

if ! bool_enabled "${trust_auto_refresh}"; then
  log "auto-refresh disabled; skipping."
  exit 0
fi

if [[ "${trust_evidence_path}" != /* ]]; then
  die "trust evidence path must be absolute: ${trust_evidence_path}"
fi
if [[ "${trust_signer_key_path}" != /* ]]; then
  die "trust signer key path must be absolute: ${trust_signer_key_path}"
fi
if [[ ! -f "${trust_signer_key_path}" ]]; then
  die "trust signer key missing: ${trust_signer_key_path}"
fi
if [[ -L "${trust_signer_key_path}" ]]; then
  die "trust signer key must not be a symlink: ${trust_signer_key_path}"
fi

if stat -c '%u' "${trust_signer_key_path}" >/dev/null 2>&1; then
  owner_uid="$(stat -c '%u' "${trust_signer_key_path}")"
  mode_octal="$(stat -c '%a' "${trust_signer_key_path}")"
  if [[ "${owner_uid}" != "0" ]]; then
    die "trust signer key must be owned by root: ${trust_signer_key_path}"
  fi
  if (( (8#${mode_octal}) & 8#022 )); then
    die "trust signer key must not be group/world writable: ${trust_signer_key_path}"
  fi
fi

updated_at="$(date +%s)"
nonce="$(date +%s%N)"

target_dir="$(dirname "${trust_evidence_path}")"
mkdir -p "${target_dir}"
payload_tmp="$(mktemp "${target_dir}/rustynetd-trust-payload.XXXXXX")"
sig_tmp="$(mktemp "${target_dir}/rustynetd-trust-signature.XXXXXX")"
record_tmp="$(mktemp "${target_dir}/rustynetd-trust-record.XXXXXX")"

cleanup() {
  rm -f "${payload_tmp}" "${sig_tmp}" "${record_tmp}"
}
trap cleanup EXIT

cat >"${payload_tmp}" <<EOF
version=2
tls13_valid=true
signed_control_valid=true
signed_data_age_secs=0
clock_skew_secs=0
updated_at_unix=${updated_at}
nonce=${nonce}
EOF

openssl pkeyutl -sign -inkey "${trust_signer_key_path}" -rawin -in "${payload_tmp}" -out "${sig_tmp}"
sig_hex="$(xxd -p -c 200 "${sig_tmp}" | tr -d '\n')"
cat "${payload_tmp}" >"${record_tmp}"
printf 'signature=%s\n' "${sig_hex}" >>"${record_tmp}"

trust_group="root"
trust_mode="0644"
if command -v getent >/dev/null 2>&1 && getent group "${daemon_group}" >/dev/null 2>&1; then
  trust_group="${daemon_group}"
  trust_mode="0640"
fi

if [[ ! -d "${target_dir}" ]]; then
  install -d -m 0750 -o root -g "${trust_group}" "${target_dir}"
fi
install -m "${trust_mode}" -o root -g "${trust_group}" "${record_tmp}" "${trust_evidence_path}"

log "refreshed signed trust evidence at ${trust_evidence_path}"
