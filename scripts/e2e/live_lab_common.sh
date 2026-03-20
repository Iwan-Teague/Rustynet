#!/usr/bin/env bash

live_lab_require_command() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd" >&2
    exit 1
  fi
}

live_lab_require_file() {
  local path="$1"
  local label="$2"
  if [[ ! -f "$path" ]]; then
    echo "missing ${label}: ${path}" >&2
    exit 1
  fi
}

live_lab_init() {
  if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "usage: live_lab_init <prefix> <ssh-identity-file> [deprecated-auth-file]" >&2
    exit 2
  fi

  local prefix="$1"
  LIVE_LAB_SSH_IDENTITY_FILE="$2"
  export LIVE_LAB_SSH_IDENTITY_FILE

  live_lab_require_file "$LIVE_LAB_SSH_IDENTITY_FILE" "ssh identity file"
  if [[ -L "$LIVE_LAB_SSH_IDENTITY_FILE" ]]; then
    echo "ssh identity file must not be a symlink: $LIVE_LAB_SSH_IDENTITY_FILE" >&2
    exit 1
  fi
  if ! python3 - "$LIVE_LAB_SSH_IDENTITY_FILE" <<'PY'
import os
import stat
import sys

path = sys.argv[1]
st = os.stat(path, follow_symlinks=False)
mode = stat.S_IMODE(st.st_mode)
if mode & 0o077:
    raise SystemExit(
        f"ssh identity file must be owner-only (0400/0600): {path} ({mode:03o})"
    )
PY
  then
    exit 1
  fi

  for cmd in ssh scp ssh-keygen awk sed openssl xxd mktemp chmod tr python3; do
    live_lab_require_command "$cmd"
  done

  LIVE_LAB_PINNED_KNOWN_HOSTS_FILE="${LIVE_LAB_PINNED_KNOWN_HOSTS_FILE:-${HOME}/.ssh/known_hosts}"
  export LIVE_LAB_PINNED_KNOWN_HOSTS_FILE
  live_lab_require_known_hosts_file "$LIVE_LAB_PINNED_KNOWN_HOSTS_FILE"

  LIVE_LAB_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/${prefix}.XXXXXX")"
  LIVE_LAB_KNOWN_HOSTS="$LIVE_LAB_WORK_DIR/known_hosts"
  LIVE_LAB_REMOTE_CLEANUP_TARGETS=()
  export LIVE_LAB_WORK_DIR LIVE_LAB_KNOWN_HOSTS

  live_lab_seed_known_hosts_file "$LIVE_LAB_KNOWN_HOSTS"
}

live_lab_cleanup() {
  if [[ -n "${LIVE_LAB_WORK_DIR:-}" && -d "${LIVE_LAB_WORK_DIR}" ]]; then
    rm -rf "$LIVE_LAB_WORK_DIR"
  fi
}

live_lab_require_known_hosts_file() {
  local path="$1"
  if [[ -z "$path" ]]; then
    echo "pinned known_hosts file path is required" >&2
    exit 1
  fi
  if [[ ! -f "$path" ]]; then
    echo "missing pinned known_hosts file: $path" >&2
    exit 1
  fi
  if [[ -L "$path" ]]; then
    echo "pinned known_hosts file must not be a symlink: $path" >&2
    exit 1
  fi
  if ! python3 - "$path" <<'PY'
import os
import stat
import sys

path = sys.argv[1]
st = os.stat(path, follow_symlinks=False)
mode = stat.S_IMODE(st.st_mode)
if mode & 0o022:
    raise SystemExit(f"pinned known_hosts file must not be group/world writable: {path} ({mode:03o})")
PY
  then
    exit 1
  fi
}

live_lab_seed_known_hosts_file() {
  local destination="$1"
  cat "$LIVE_LAB_PINNED_KNOWN_HOSTS_FILE" > "$destination"
  chmod 600 "$destination"
}

live_lab_require_pinned_host_entry() {
  local target="$1"
  local host
  host="$(live_lab_target_address "$target")"
  if ! ssh-keygen -F "$host" -f "$LIVE_LAB_PINNED_KNOWN_HOSTS_FILE" >/dev/null 2>&1; then
    echo "pinned known_hosts file lacks host key for ${host}: $LIVE_LAB_PINNED_KNOWN_HOSTS_FILE" >&2
    exit 1
  fi
}

live_lab_prepare_worker_known_hosts() {
  local worker_name="$1"
  local worker_known_hosts="$LIVE_LAB_WORK_DIR/known_hosts.${worker_name}"
  live_lab_seed_known_hosts_file "$worker_known_hosts"
  export LIVE_LAB_KNOWN_HOSTS="$worker_known_hosts"
}

live_lab_log() {
  printf '[%s] %s\n' "${LIVE_LAB_LOG_PREFIX:-live-lab}" "$*"
}

live_lab_target_user() {
  local target="$1"
  printf '%s' "${target%%@*}"
}

live_lab_target_address() {
  local target="$1"
  printf '%s' "${target#*@}"
}

live_lab_remote_src_dir() {
  local target="$1"
  local user
  user="$(live_lab_target_user "$target")"
  if [[ "$user" == "root" ]]; then
    printf '/root/Rustynet'
    return 0
  fi
  printf '/home/%s/Rustynet' "$user"
}

live_lab_ssh() {
  local target="$1"
  local command="$2"
  local timeout="${3:-10800}"
  local ssh_args=(
    ssh
    -n
    -o LogLevel=ERROR
    -o BatchMode=yes
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="$LIVE_LAB_KNOWN_HOSTS"
    -o ConnectTimeout=15
    -o ServerAliveInterval=20
    -o ServerAliveCountMax=3
    -o IdentitiesOnly=yes
    -i "$LIVE_LAB_SSH_IDENTITY_FILE"
    -- "$target" "$command"
  )
  live_lab_require_pinned_host_entry "$target"
  if command -v timeout >/dev/null 2>&1; then
    timeout "$timeout" "${ssh_args[@]}"
    return
  fi
  "${ssh_args[@]}"
}

live_lab_scp_to() {
  local src="$1"
  local target="$2"
  local dst="$3"
  local timeout="${4:-10800}"
  local scp_args=(
    scp
    -q
    -o LogLevel=ERROR
    -o BatchMode=yes
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="$LIVE_LAB_KNOWN_HOSTS"
    -o ConnectTimeout=15
    -o IdentitiesOnly=yes
    -i "$LIVE_LAB_SSH_IDENTITY_FILE"
    -- "$src" "${target}:${dst}"
  )
  live_lab_require_pinned_host_entry "$target"
  if command -v timeout >/dev/null 2>&1; then
    timeout "$timeout" "${scp_args[@]}"
    return
  fi
  "${scp_args[@]}"
}

live_lab_scp_from() {
  local target="$1"
  local src="$2"
  local dst="$3"
  local timeout="${4:-10800}"
  local scp_args=(
    scp
    -q
    -o LogLevel=ERROR
    -o BatchMode=yes
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="$LIVE_LAB_KNOWN_HOSTS"
    -o ConnectTimeout=15
    -o IdentitiesOnly=yes
    -i "$LIVE_LAB_SSH_IDENTITY_FILE"
    -- "${target}:${src}" "$dst"
  )
  live_lab_require_pinned_host_entry "$target"
  if command -v timeout >/dev/null 2>&1; then
    timeout "$timeout" "${scp_args[@]}"
    return
  fi
  "${scp_args[@]}"
}

live_lab_capture() {
  local target="$1"
  local body="$2"
  local timeout="${3:-10800}"
  local raw
  raw="$(live_lab_ssh "$target" "printf '__CAP_BEGIN__\\n'; { ${body}; }; printf '\\n__CAP_END__\\n'" "$timeout")"
  printf '%s\n' "$raw" | awk '
    /__CAP_BEGIN__/ {
      capture=1
      prev_set=0
      next
    }
    /__CAP_END__/ {
      if (prev_set && prev != "") {
        print prev
      }
      capture=0
      prev_set=0
      next
    }
    capture && tolower($0) !~ /password:/ {
      gsub(/\r/, "", $0)
      if (prev_set) {
        print prev
      }
      prev=$0
      prev_set=1
    }
  '
}

live_lab_rootify() {
  local body="$1"
  printf 'root(){ sudo -n "$@"; }; set -euo pipefail; %s' "$body"
}

live_lab_verify_sudo() {
  local target="$1"
  local hostname_precheck_cmd
  local verify_cmd
  hostname_precheck_cmd="current_hostname=\$(hostname); if ! grep -Eq \"(^|[[:space:]])\${current_hostname}([[:space:]]|$)\" /etc/hosts; then printf 'local hostname %s is missing from /etc/hosts\\n' \"\$current_hostname\"; exit 1; fi"
  live_lab_ssh "$target" "$hostname_precheck_cmd" || return 1
  verify_cmd="if timeout 15 sudo -n -k true >/dev/null 2>&1; then :; else printf 'passwordless sudo (sudo -n) is required for live lab automation\\n'; printf 'user: %s\\n' \"\$(id -un)\"; printf 'groups: %s\\n' \"\$(id -Gn)\"; exit 1; fi"
  live_lab_ssh "$target" "$verify_cmd"
}

live_lab_push_sudo_password() {
  local target="$1"
  local existing
  for existing in "${LIVE_LAB_REMOTE_CLEANUP_TARGETS[@]:-}"; do
    if [[ "$existing" == "$target" ]]; then
      live_lab_verify_sudo "$target" || return 1
      return 0
    fi
  done
  LIVE_LAB_REMOTE_CLEANUP_TARGETS+=("$target")
  live_lab_verify_sudo "$target" || return 1
}

live_lab_run_root() {
  local target="$1"
  local body="$2"
  live_lab_push_sudo_password "$target" || return 1
  live_lab_ssh "$target" "$(live_lab_rootify "$body")"
}

live_lab_retry_root() {
  local target="$1"
  local body="$2"
  local attempts="${3:-20}"
  local sleep_secs="${4:-2}"
  local attempt
  for ((attempt=1; attempt<=attempts; attempt++)); do
    if live_lab_run_root "$target" "$body" >/dev/null 2>&1; then
      return 0
    fi
    if (( attempt < attempts )); then
      sleep "$sleep_secs"
    fi
  done
  live_lab_run_root "$target" "$body"
}

live_lab_capture_root() {
  local target="$1"
  local body="$2"
  live_lab_push_sudo_password "$target" || return 1
  live_lab_capture "$target" "$(live_lab_rootify "$body")"
}

live_lab_base64_to_hex() {
  local value="$1"
  printf '%s' "$value" | openssl base64 -d -A 2>/dev/null | xxd -p -c 256 | tr -d '\n'
}

live_lab_collect_pubkey_hex() {
  local target="$1"
  local pub_b64
  pub_b64="$(live_lab_capture_root "$target" "root cat /var/lib/rustynet/keys/wireguard.pub | tr -d '[:space:]'")"
  local pub_hex
  pub_hex="$(live_lab_base64_to_hex "$pub_b64")"
  if [[ ! "$pub_hex" =~ ^[0-9a-f]{64}$ ]]; then
    echo "failed to decode wireguard pubkey for ${target}" >&2
    exit 1
  fi
  printf '%s' "$pub_hex"
}

live_lab_quote_env_value() {
  local value="$1"
  if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
    echo "env value contains newline characters" >&2
    exit 1
  fi
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//\$/\\\$}"
  value="${value//\`/\\\`}"
  printf '"%s"' "$value"
}

live_lab_append_env_assignment() {
  local env_path="$1"
  local key="$2"
  local value="$3"
  printf '%s=%s\n' "$key" "$(live_lab_quote_env_value "$value")" >> "$env_path"
}

live_lab_write_assignment_refresh_env() {
  local env_path="$1"
  local target_node_id="$2"
  local nodes_spec="$3"
  local allow_spec="$4"
  local exit_node_id="${5:-}"
  : > "$env_path"
  live_lab_append_env_assignment "$env_path" "RUSTYNET_ASSIGNMENT_TARGET_NODE_ID" "$target_node_id"
  live_lab_append_env_assignment "$env_path" "RUSTYNET_ASSIGNMENT_NODES" "$nodes_spec"
  live_lab_append_env_assignment "$env_path" "RUSTYNET_ASSIGNMENT_ALLOW" "$allow_spec"
  live_lab_append_env_assignment "$env_path" "RUSTYNET_ASSIGNMENT_SIGNING_SECRET" "/etc/rustynet/assignment.signing.secret"
  live_lab_append_env_assignment "$env_path" "RUSTYNET_ASSIGNMENT_SIGNING_SECRET_PASSPHRASE_FILE" "/run/credentials/rustynetd-assignment-refresh.service/signing_key_passphrase"
  live_lab_append_env_assignment "$env_path" "RUSTYNET_ASSIGNMENT_TTL_SECS" "300"
  live_lab_append_env_assignment "$env_path" "RUSTYNET_ASSIGNMENT_MIN_REMAINING_SECS" "180"
  if [[ -n "$exit_node_id" ]]; then
    live_lab_append_env_assignment "$env_path" "RUSTYNET_ASSIGNMENT_EXIT_NODE_ID" "$exit_node_id"
  fi
}

live_lab_install_assignment_bundle() {
  local target="$1"
  local assignment_pub_local="$2"
  local assignment_bundle_local="$3"
  live_lab_scp_to "$assignment_pub_local" "$target" "/tmp/rn-assignment.pub" || return 1
  live_lab_scp_to "$assignment_bundle_local" "$target" "/tmp/rn-assignment.bundle" || return 1
  live_lab_run_root "$target" "root install -m 0644 -o root -g root /tmp/rn-assignment.pub /etc/rustynet/assignment.pub && root install -m 0640 -o root -g rustynetd /tmp/rn-assignment.bundle /var/lib/rustynet/rustynetd.assignment && root rm -f /var/lib/rustynet/rustynetd.assignment.watermark /tmp/rn-assignment.pub /tmp/rn-assignment.bundle" || return 1
}

live_lab_install_assignment_refresh_env() {
  local target="$1"
  local env_local="$2"
  live_lab_scp_to "$env_local" "$target" "/tmp/rn-assignment-refresh.env" || return 1
  live_lab_run_root "$target" "root install -m 0600 -o root -g root /tmp/rn-assignment-refresh.env /etc/rustynet/assignment-refresh.env && root rm -f /tmp/rn-assignment-refresh.env" || return 1
}

live_lab_enforce_host() {
  local target="$1"
  local role="$2"
  local node_id="$3"
  local ssh_allow_cidrs="$4"
  local src_dir="$5"
  live_lab_run_root "$target" "root rustynet ops e2e-enforce-host --role '${role}' --node-id '${node_id}' --src-dir '${src_dir}' --ssh-allow-cidrs '${ssh_allow_cidrs}'" || return 1
}

live_lab_apply_role_coupling() {
  local target="$1"
  local target_role="$2"
  local preferred_exit_node_id="${3:-}"
  local enable_exit_advertise="${4:-false}"
  local env_path="${5:-/etc/rustynet/assignment-refresh.env}"
  local command
  live_lab_push_sudo_password "$target" || return 1
  command="root env RUSTYNET_SOCKET=/run/rustynet/rustynetd.sock RUSTYNET_AUTO_TUNNEL_BUNDLE=/var/lib/rustynet/rustynetd.assignment RUSTYNET_AUTO_TUNNEL_WATERMARK=/var/lib/rustynet/rustynetd.assignment.watermark rustynet ops apply-role-coupling --target-role '${target_role}' --enable-exit-advertise '${enable_exit_advertise}' --env-path '${env_path}'"
  if [[ -n "$preferred_exit_node_id" ]]; then
    command+=" --preferred-exit-node-id '${preferred_exit_node_id}'"
  fi
  live_lab_run_root "$target" "$command" || return 1
}

live_lab_apply_lan_access_coupling() {
  local target="$1"
  local enable="$2"
  local lan_routes="${3:-}"
  local env_path="${4:-/etc/rustynet/assignment-refresh.env}"
  local command
  live_lab_push_sudo_password "$target" || return 1
  command="root env RUSTYNET_SOCKET=/run/rustynet/rustynetd.sock RUSTYNET_AUTO_TUNNEL_BUNDLE=/var/lib/rustynet/rustynetd.assignment RUSTYNET_AUTO_TUNNEL_WATERMARK=/var/lib/rustynet/rustynetd.assignment.watermark rustynet ops apply-lan-access-coupling --enable '${enable}' --env-path '${env_path}'"
  if [[ -n "$lan_routes" ]]; then
    command+=" --lan-routes '${lan_routes}'"
  fi
  live_lab_run_root "$target" "$command" || return 1
}

live_lab_wait_for_daemon_socket() {
  local target="$1"
  local socket_path="${2:-/run/rustynet/rustynetd.sock}"
  local attempts="${3:-20}"
  local sleep_secs="${4:-2}"
  live_lab_retry_root "$target" "root test -S '${socket_path}'" "$attempts" "$sleep_secs" || return 1
}

live_lab_status() {
  local target="$1"
  live_lab_capture_root "$target" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet status"
}

live_lab_no_plaintext_passphrase_check() {
  local target="$1"
  live_lab_capture_root "$target" "root test ! -e /var/lib/rustynet/keys/wireguard.passphrase && root test ! -e /etc/rustynet/wireguard.passphrase && root test ! -e /etc/rustynet/signing_key_passphrase && echo no-plaintext-passphrase-files"
}
