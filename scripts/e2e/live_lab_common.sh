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
  if [[ $# -ne 3 ]]; then
    echo "usage: live_lab_init <prefix> <ssh-password-file> <sudo-password-file>" >&2
    exit 2
  fi

  local prefix="$1"
  LIVE_LAB_SSH_PASSWORD_FILE="$2"
  LIVE_LAB_SUDO_PASSWORD_FILE="$3"
  export LIVE_LAB_SSH_PASSWORD_FILE LIVE_LAB_SUDO_PASSWORD_FILE

  live_lab_require_file "$LIVE_LAB_SSH_PASSWORD_FILE" "ssh password file"
  live_lab_require_file "$LIVE_LAB_SUDO_PASSWORD_FILE" "sudo password file"

  for cmd in expect ssh scp ssh-keygen awk sed openssl xxd mktemp chmod tr python3; do
    live_lab_require_command "$cmd"
  done

  LIVE_LAB_PINNED_KNOWN_HOSTS_FILE="${LIVE_LAB_PINNED_KNOWN_HOSTS_FILE:-${HOME}/.ssh/known_hosts}"
  export LIVE_LAB_PINNED_KNOWN_HOSTS_FILE
  live_lab_require_known_hosts_file "$LIVE_LAB_PINNED_KNOWN_HOSTS_FILE"

  LIVE_LAB_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/${prefix}.XXXXXX")"
  LIVE_LAB_KNOWN_HOSTS="$LIVE_LAB_WORK_DIR/known_hosts"
  LIVE_LAB_SSH_EXPECT="$LIVE_LAB_WORK_DIR/ssh_pass.expect"
  LIVE_LAB_SCP_EXPECT="$LIVE_LAB_WORK_DIR/scp_pass.expect"
  LIVE_LAB_REMOTE_CLEANUP_TARGETS=()
  export LIVE_LAB_WORK_DIR LIVE_LAB_KNOWN_HOSTS LIVE_LAB_SSH_EXPECT LIVE_LAB_SCP_EXPECT

  live_lab_seed_known_hosts_file "$LIVE_LAB_KNOWN_HOSTS"

  cat > "$LIVE_LAB_SSH_EXPECT" <<EXPECTSSH
#!/usr/bin/expect -f
if {\$argc < 3 || \$argc > 4} {
  puts stderr "usage: ssh_pass.expect <password-file> <target> <command> ?timeout?"
  exit 2
}
if {![info exists env(LIVE_LAB_KNOWN_HOSTS)] || \$env(LIVE_LAB_KNOWN_HOSTS) eq ""} {
  puts stderr "LIVE_LAB_KNOWN_HOSTS is required"
  exit 2
}
set password_file [lindex \$argv 0]
set target [lindex \$argv 1]
set command [lindex \$argv 2]
set timeout 10800
if {\$argc == 4} {
  set timeout [lindex \$argv 3]
}
set fh [open \$password_file r]
gets \$fh password
close \$fh
set output ""
match_max 2000000
log_user 0
spawn ssh -o LogLevel=ERROR -o StrictHostKeyChecking=yes -o UserKnownHostsFile=\$env(LIVE_LAB_KNOWN_HOSTS) -o ConnectTimeout=15 -- \$target \$command
while {1} {
  expect {
    -re {(?i)password:} { send -- "\$password\r"; exp_continue }
    -re {.+} {
      append output \$expect_out(buffer)
      exp_continue
    }
    eof {
      regsub -all "\r" \$output "" normalized
      set cleaned ""
      foreach line [split \$normalized "\n"] {
        if {[string trim \$line] eq ""} {
          continue
        }
        append cleaned \$line "\n"
      }
      puts -nonewline [string trimright \$cleaned "\n"]
      catch wait result
      exit [lindex \$result 3]
    }
  }
}
EXPECTSSH

  cat > "$LIVE_LAB_SCP_EXPECT" <<EXPECTSCP
#!/usr/bin/expect -f
if {\$argc < 3 || \$argc > 4} {
  puts stderr "usage: scp_pass.expect <password-file> <source> <target> ?timeout?"
  exit 2
}
if {![info exists env(LIVE_LAB_KNOWN_HOSTS)] || \$env(LIVE_LAB_KNOWN_HOSTS) eq ""} {
  puts stderr "LIVE_LAB_KNOWN_HOSTS is required"
  exit 2
}
set password_file [lindex \$argv 0]
set source [lindex \$argv 1]
set target [lindex \$argv 2]
set timeout 10800
if {\$argc == 4} {
  set timeout [lindex \$argv 3]
}
set fh [open \$password_file r]
gets \$fh password
close \$fh
set output ""
match_max 2000000
log_user 0
spawn scp -q -o LogLevel=ERROR -o StrictHostKeyChecking=yes -o UserKnownHostsFile=\$env(LIVE_LAB_KNOWN_HOSTS) -o ConnectTimeout=15 -- \$source \$target
while {1} {
  expect {
    -re {(?i)password:} { send -- "\$password\r"; exp_continue }
    -re {.+} {
      append output \$expect_out(buffer)
      exp_continue
    }
    eof {
      regsub -all "\r" \$output "" normalized
      set cleaned ""
      foreach line [split \$normalized "\n"] {
        if {[string trim \$line] eq ""} {
          continue
        }
        append cleaned \$line "\n"
      }
      puts -nonewline [string trimright \$cleaned "\n"]
      catch wait result
      exit [lindex \$result 3]
    }
  }
}
EXPECTSCP

  chmod 700 "$LIVE_LAB_SSH_EXPECT" "$LIVE_LAB_SCP_EXPECT"
}

live_lab_cleanup() {
  local target
  for target in "${LIVE_LAB_REMOTE_CLEANUP_TARGETS[@]:-}"; do
    live_lab_run_root "$target" "root rustynet ops secure-remove --path /tmp/rn_sudo.pass >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
  done
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
  live_lab_require_pinned_host_entry "$target"
  "$LIVE_LAB_SSH_EXPECT" "$LIVE_LAB_SSH_PASSWORD_FILE" "$target" "$command" "$timeout"
}

live_lab_scp_to() {
  local src="$1"
  local target="$2"
  local dst="$3"
  local timeout="${4:-10800}"
  live_lab_require_pinned_host_entry "$target"
  "$LIVE_LAB_SCP_EXPECT" "$LIVE_LAB_SSH_PASSWORD_FILE" "$src" "${target}:${dst}" "$timeout"
}

live_lab_scp_from() {
  local target="$1"
  local src="$2"
  local dst="$3"
  local timeout="${4:-10800}"
  live_lab_require_pinned_host_entry "$target"
  "$LIVE_LAB_SCP_EXPECT" "$LIVE_LAB_SSH_PASSWORD_FILE" "${target}:${src}" "$dst" "$timeout"
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
  printf 'root(){ sudo -S -p "" "$@" < /tmp/rn_sudo.pass; }; set -euo pipefail; %s' "$body"
}

live_lab_push_sudo_password() {
  local target="$1"
  local existing
  for existing in "${LIVE_LAB_REMOTE_CLEANUP_TARGETS[@]:-}"; do
    if [[ "$existing" == "$target" ]]; then
      live_lab_scp_to "$LIVE_LAB_SUDO_PASSWORD_FILE" "$target" "/tmp/rn_sudo.pass" || return 1
      live_lab_ssh "$target" "chmod 600 /tmp/rn_sudo.pass" || return 1
      return 0
    fi
  done
  LIVE_LAB_REMOTE_CLEANUP_TARGETS+=("$target")
  live_lab_scp_to "$LIVE_LAB_SUDO_PASSWORD_FILE" "$target" "/tmp/rn_sudo.pass" || return 1
  live_lab_ssh "$target" "chmod 600 /tmp/rn_sudo.pass" || return 1
}

live_lab_run_root() {
  local target="$1"
  local body="$2"
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
