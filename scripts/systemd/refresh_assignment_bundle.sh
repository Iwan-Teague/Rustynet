#!/usr/bin/env bash
set -euo pipefail

umask 0077

log() {
  printf '[assignment-refresh] %s\n' "$*"
}

die() {
  printf '[assignment-refresh] %s\n' "$*" >&2
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

for tool in awk date getent install mktemp rustynet stat; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    die "required command not found: ${tool}"
  fi
done

assignment_auto_refresh="${RUSTYNET_ASSIGNMENT_AUTO_REFRESH:-false}"
if ! bool_enabled "${assignment_auto_refresh}"; then
  log "auto-refresh disabled; skipping."
  exit 0
fi

target_node_id="${RUSTYNET_ASSIGNMENT_TARGET_NODE_ID:-${RUSTYNET_NODE_ID:-}}"
nodes_spec="${RUSTYNET_ASSIGNMENT_NODES:-}"
allow_spec="${RUSTYNET_ASSIGNMENT_ALLOW:-}"
exit_node_id="${RUSTYNET_ASSIGNMENT_EXIT_NODE_ID:-}"
signing_secret_path="${RUSTYNET_ASSIGNMENT_SIGNING_SECRET:-/etc/rustynet/assignment.signing.secret}"
signing_secret_passphrase_path="${RUSTYNET_ASSIGNMENT_SIGNING_SECRET_PASSPHRASE_FILE:-}"
bundle_path="${RUSTYNET_ASSIGNMENT_OUTPUT:-/var/lib/rustynet/rustynetd.assignment}"
verifier_key_path="${RUSTYNET_ASSIGNMENT_VERIFIER_KEY_OUTPUT:-/etc/rustynet/assignment.pub}"
ttl_secs="${RUSTYNET_ASSIGNMENT_TTL_SECS:-300}"
min_remaining_secs="${RUSTYNET_ASSIGNMENT_MIN_REMAINING_SECS:-180}"
daemon_group="${RUSTYNET_DAEMON_GROUP:-rustynetd}"

if [[ -z "${target_node_id}" ]]; then
  die "assignment target node id is required (RUSTYNET_ASSIGNMENT_TARGET_NODE_ID or RUSTYNET_NODE_ID)"
fi
if [[ -z "${nodes_spec}" ]]; then
  die "assignment node map is required (RUSTYNET_ASSIGNMENT_NODES)"
fi
if [[ -z "${allow_spec}" ]]; then
  die "assignment allow rules are required (RUSTYNET_ASSIGNMENT_ALLOW)"
fi
if [[ -z "${signing_secret_passphrase_path}" ]]; then
  die "assignment signing secret passphrase path is required (RUSTYNET_ASSIGNMENT_SIGNING_SECRET_PASSPHRASE_FILE)"
fi

if [[ ! "${target_node_id}" =~ ^[A-Za-z0-9._:-]+$ ]]; then
  die "target node id contains unsupported characters: ${target_node_id}"
fi
if [[ -n "${exit_node_id}" && ! "${exit_node_id}" =~ ^[A-Za-z0-9._:-]+$ ]]; then
  die "exit node id contains unsupported characters: ${exit_node_id}"
fi

for path_value in "${signing_secret_path}" "${signing_secret_passphrase_path}" "${bundle_path}" "${verifier_key_path}"; do
  if [[ "${path_value}" != /* ]]; then
    die "path must be absolute: ${path_value}"
  fi
done

if ! [[ "${ttl_secs}" =~ ^[0-9]+$ ]] || (( ttl_secs < 60 || ttl_secs > 86400 )); then
  die "assignment ttl must be an integer in range 60-86400 seconds: ${ttl_secs}"
fi
if ! [[ "${min_remaining_secs}" =~ ^[0-9]+$ ]]; then
  die "assignment min remaining threshold must be an integer: ${min_remaining_secs}"
fi
if (( min_remaining_secs >= ttl_secs )); then
  log "min remaining threshold >= ttl; refresh will run every timer interval."
fi

if [[ ! -f "${signing_secret_path}" ]]; then
  die "assignment signing secret missing: ${signing_secret_path}"
fi
if [[ -L "${signing_secret_path}" ]]; then
  die "assignment signing secret must not be a symlink: ${signing_secret_path}"
fi
if [[ ! -f "${signing_secret_passphrase_path}" ]]; then
  die "assignment signing secret passphrase file missing: ${signing_secret_passphrase_path}"
fi
if [[ -L "${signing_secret_passphrase_path}" ]]; then
  die "assignment signing secret passphrase file must not be a symlink: ${signing_secret_passphrase_path}"
fi

owner_uid="$(stat -c '%u' "${signing_secret_path}")"
mode_octal="$(stat -c '%a' "${signing_secret_path}")"
if [[ "${owner_uid}" != "0" ]]; then
  die "assignment signing secret must be owned by root: ${signing_secret_path}"
fi
if (( (8#${mode_octal}) & 8#077 )); then
  die "assignment signing secret must be owner-only (0600): ${signing_secret_path}"
fi

passphrase_owner_uid="$(stat -c '%u' "${signing_secret_passphrase_path}")"
passphrase_mode_octal="$(stat -c '%a' "${signing_secret_passphrase_path}")"
if [[ "${passphrase_owner_uid}" != "0" ]]; then
  die "assignment signing secret passphrase file must be owned by root: ${signing_secret_passphrase_path}"
fi
passphrase_disallowed_mask="077"
passphrase_expected="owner-only (0600)"
if [[ "${signing_secret_passphrase_path}" == /run/credentials/* ]]; then
  passphrase_disallowed_mask="037"
  passphrase_expected="owner-only or systemd credential mode"
fi
if (( (8#${passphrase_mode_octal}) & (8#${passphrase_disallowed_mask}) )); then
  die "assignment signing secret passphrase file permissions too broad (${passphrase_mode_octal}); expected ${passphrase_expected}: ${signing_secret_passphrase_path}"
fi

now_unix="$(date +%s)"
if [[ -f "${bundle_path}" ]]; then
  current_expires_at="$(
    awk -F= '/^expires_at_unix=/ { print $2; exit }' "${bundle_path}" | tr -d '[:space:]'
  )"
  if [[ "${current_expires_at}" =~ ^[0-9]+$ ]]; then
    if (( current_expires_at > now_unix + min_remaining_secs )); then
      remaining_secs=$((current_expires_at - now_unix))
      log "current assignment expires in ${remaining_secs}s; skip refresh."
      exit 0
    fi
  fi
fi

bundle_dir="$(dirname "${bundle_path}")"
verifier_dir="$(dirname "${verifier_key_path}")"
bundle_tmp="$(mktemp "${bundle_dir}/rustynetd.assignment.tmp.XXXXXX")"
verifier_tmp="$(mktemp "${verifier_dir}/assignment.pub.tmp.XXXXXX")"

cleanup() {
  rm -f "${bundle_tmp}" "${verifier_tmp}"
}
trap cleanup EXIT

issue_cmd=(
  rustynet assignment issue
  --target-node-id "${target_node_id}"
  --nodes "${nodes_spec}"
  --allow "${allow_spec}"
  --signing-secret "${signing_secret_path}"
  --signing-secret-passphrase-file "${signing_secret_passphrase_path}"
  --output "${bundle_tmp}"
  --verifier-key-output "${verifier_tmp}"
  --ttl-secs "${ttl_secs}"
)
if [[ -n "${exit_node_id}" ]]; then
  issue_cmd+=(--exit-node-id "${exit_node_id}")
fi
"${issue_cmd[@]}" >/dev/null

generated_at_unix="$(awk -F= '/^generated_at_unix=/ { print $2; exit }' "${bundle_tmp}" | tr -d '[:space:]')"
expires_at_unix="$(awk -F= '/^expires_at_unix=/ { print $2; exit }' "${bundle_tmp}" | tr -d '[:space:]')"
if [[ ! "${generated_at_unix}" =~ ^[0-9]+$ || ! "${expires_at_unix}" =~ ^[0-9]+$ ]]; then
  die "issued assignment bundle missing generated_at_unix/expires_at_unix fields"
fi
if (( generated_at_unix >= expires_at_unix )); then
  die "issued assignment bundle has invalid expiry window"
fi

bundle_group="root"
if getent group "${daemon_group}" >/dev/null 2>&1; then
  bundle_group="${daemon_group}"
fi

if [[ ! -d "${bundle_dir}" ]]; then
  install -d -m 0750 -o root -g "${bundle_group}" "${bundle_dir}"
fi
if [[ ! -d "${verifier_dir}" ]]; then
  install -d -m 0750 -o root -g "${bundle_group}" "${verifier_dir}"
fi

install -m 0640 -o root -g "${bundle_group}" "${bundle_tmp}" "${bundle_path}"
install -m 0644 -o root -g root "${verifier_tmp}" "${verifier_key_path}"

log "refreshed signed assignment bundle at ${bundle_path} (generated_at_unix=${generated_at_unix} expires_at_unix=${expires_at_unix})"
