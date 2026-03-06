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

for tool in date getent install mktemp rustynet stat; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    die "required command not found: ${tool}"
  fi
done

trust_evidence_path="${RUSTYNET_TRUST_EVIDENCE:-/var/lib/rustynet/rustynetd.trust}"
trust_signer_key_path="${RUSTYNET_TRUST_SIGNER_KEY:-/etc/rustynet/trust-evidence.key}"
trust_signer_key_passphrase_path="${RUSTYNET_TRUST_SIGNING_KEY_PASSPHRASE_FILE:-}"
daemon_group="${RUSTYNET_DAEMON_GROUP:-rustynetd}"
trust_auto_refresh="${RUSTYNET_TRUST_AUTO_REFRESH:-true}"

if ! bool_enabled "${trust_auto_refresh}"; then
  log "auto-refresh disabled; skipping."
  exit 0
fi

if [[ -z "${trust_signer_key_passphrase_path}" ]]; then
  die "trust signing key passphrase path is required (RUSTYNET_TRUST_SIGNING_KEY_PASSPHRASE_FILE)"
fi
if [[ "${trust_evidence_path}" != /* ]]; then
  die "trust evidence path must be absolute: ${trust_evidence_path}"
fi
if [[ "${trust_signer_key_path}" != /* ]]; then
  die "trust signer key path must be absolute: ${trust_signer_key_path}"
fi
if [[ "${trust_signer_key_passphrase_path}" != /* ]]; then
  die "trust signer key passphrase path must be absolute: ${trust_signer_key_passphrase_path}"
fi
if [[ ! -f "${trust_signer_key_path}" ]]; then
  die "trust signer key missing: ${trust_signer_key_path}"
fi
if [[ -L "${trust_signer_key_path}" ]]; then
  die "trust signer key must not be a symlink: ${trust_signer_key_path}"
fi
if [[ ! -f "${trust_signer_key_passphrase_path}" ]]; then
  die "trust signer key passphrase file missing: ${trust_signer_key_passphrase_path}"
fi
if [[ -L "${trust_signer_key_passphrase_path}" ]]; then
  die "trust signer key passphrase file must not be a symlink: ${trust_signer_key_passphrase_path}"
fi

owner_uid="$(stat -c '%u' "${trust_signer_key_path}")"
mode_octal="$(stat -c '%a' "${trust_signer_key_path}")"
if [[ "${owner_uid}" != "0" ]]; then
  die "trust signer key must be owned by root: ${trust_signer_key_path}"
fi
if (( (8#${mode_octal}) & 8#077 )); then
  die "trust signer key must be owner-only (0600): ${trust_signer_key_path}"
fi

passphrase_owner_uid="$(stat -c '%u' "${trust_signer_key_passphrase_path}")"
passphrase_mode_octal="$(stat -c '%a' "${trust_signer_key_passphrase_path}")"
if [[ "${passphrase_owner_uid}" != "0" ]]; then
  die "trust signer key passphrase file must be owned by root: ${trust_signer_key_passphrase_path}"
fi
passphrase_disallowed_mask="077"
passphrase_expected="owner-only (0600)"
if [[ "${trust_signer_key_passphrase_path}" == /run/credentials/* ]]; then
  passphrase_disallowed_mask="037"
  passphrase_expected="owner-only or systemd credential mode"
fi
if (( (8#${passphrase_mode_octal}) & (8#${passphrase_disallowed_mask}) )); then
  die "trust signer key passphrase file permissions too broad (${passphrase_mode_octal}); expected ${passphrase_expected}: ${trust_signer_key_passphrase_path}"
fi

updated_at="$(date +%s)"
nonce="$(date +%s%N)"

target_dir="$(dirname "${trust_evidence_path}")"
mkdir -p "${target_dir}"
record_tmp="$(mktemp "${target_dir}/rustynetd-trust-record.XXXXXX")"

cleanup() {
  rm -f "${record_tmp}"
}
trap cleanup EXIT

rustynet trust issue \
  --signing-key "${trust_signer_key_path}" \
  --signing-key-passphrase-file "${trust_signer_key_passphrase_path}" \
  --output "${record_tmp}" \
  --updated-at-unix "${updated_at}" \
  --nonce "${nonce}" >/dev/null

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
