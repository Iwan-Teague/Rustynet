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
  if ! cargo run --quiet -p rustynet-cli -- ops check-local-file-mode \
    --path "$LIVE_LAB_SSH_IDENTITY_FILE" \
    --policy owner-only \
    --label 'ssh identity file' >/dev/null
  then
    exit 1
  fi

  for cmd in ssh scp ssh-keygen awk sed openssl xxd mktemp chmod tr; do
    live_lab_require_command "$cmd"
  done

  LIVE_LAB_UTMCTL_PATH="${LIVE_LAB_UTMCTL_PATH:-/Applications/UTM.app/Contents/MacOS/utmctl}"
  export LIVE_LAB_UTMCTL_PATH
  if live_lab_has_utm_transport; then
    live_lab_require_utmctl
  fi

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
  if ! cargo run --quiet -p rustynet-cli -- ops check-local-file-mode \
    --path "$path" \
    --policy no-group-world-write \
    --label 'pinned known_hosts file' >/dev/null
  then
    exit 1
  fi
}

live_lab_seed_known_hosts_file() {
  local destination="$1"
  cat "$LIVE_LAB_PINNED_KNOWN_HOSTS_FILE" > "$destination"
  chmod 600 "$destination"
}

live_lab_known_hosts_lookup_host() {
  local host="$1"
  local port="$2"
  if [[ -z "$host" ]]; then
    return 1
  fi
  if [[ -z "$port" || "$port" == "22" ]]; then
    printf '%s' "$host"
    return 0
  fi
  printf '[%s]:%s' "$host" "$port"
}

live_lab_require_pinned_host_entry() {
  local target="$1"
  local resolved raw_host port hostkeyalias hostname lookup_host
  local -a lookup_candidates=()
  raw_host="$(live_lab_target_address "$target")"
  resolved="$(ssh -G "$target" 2>/dev/null)" || {
    echo "failed resolving SSH target for host-key verification: ${target}" >&2
    exit 1
  }
  port="$(awk '$1=="port"{print $2; exit}' <<<"$resolved")"
  hostkeyalias="$(awk '$1=="hostkeyalias"{print $2; exit}' <<<"$resolved")"
  hostname="$(awk '$1=="hostname"{print $2; exit}' <<<"$resolved")"

  if [[ -n "$hostkeyalias" && "$hostkeyalias" != "none" ]]; then
    lookup_host="$(live_lab_known_hosts_lookup_host "$hostkeyalias" "$port")" || {
      echo "failed rendering hostkeyalias known_hosts lookup for ${target}" >&2
      exit 1
    }
    lookup_candidates+=("$lookup_host")
  fi

  lookup_host="$(live_lab_known_hosts_lookup_host "$raw_host" "$port")" || {
    echo "failed rendering raw host known_hosts lookup for ${target}" >&2
    exit 1
  }
  lookup_candidates+=("$lookup_host")

  if [[ -n "$hostname" ]]; then
    lookup_host="$(live_lab_known_hosts_lookup_host "$hostname" "$port")" || {
      echo "failed rendering resolved host known_hosts lookup for ${target}" >&2
      exit 1
    }
    if [[ " ${lookup_candidates[*]} " != *" ${lookup_host} "* ]]; then
      lookup_candidates+=("$lookup_host")
    fi
  fi

  for lookup_host in "${lookup_candidates[@]}"; do
    if ssh-keygen -F "$lookup_host" -f "$LIVE_LAB_PINNED_KNOWN_HOSTS_FILE" >/dev/null 2>&1; then
      return 0
    fi
  done

  if [[ "${#lookup_candidates[@]}" -eq 0 ]]; then
    echo "pinned known_hosts verification resolved no lookup candidates for ${target}" >&2
  else
    echo "pinned known_hosts file lacks host key for ${target}; checked ${lookup_candidates[*]} in ${LIVE_LAB_PINNED_KNOWN_HOSTS_FILE}" >&2
  fi
  exit 1
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

live_lab_target_home() {
  local user
  user="$(live_lab_target_user "$1")"
  if [[ "$user" == "root" ]]; then
    printf '/root'
    return 0
  fi
  printf '/home/%s' "$user"
}

live_lab_target_utm_name() {
  local target="$1"
  if [[ -n "${EXIT_TARGET:-}" && "$target" == "$EXIT_TARGET" ]]; then
    printf '%s' "${EXIT_UTM_NAME:-}"
    return 0
  fi
  if [[ -n "${CLIENT_TARGET:-}" && "$target" == "$CLIENT_TARGET" ]]; then
    printf '%s' "${CLIENT_UTM_NAME:-}"
    return 0
  fi
  if [[ -n "${ENTRY_TARGET:-}" && "$target" == "$ENTRY_TARGET" ]]; then
    printf '%s' "${ENTRY_UTM_NAME:-}"
    return 0
  fi
  if [[ -n "${AUX_TARGET:-}" && "$target" == "$AUX_TARGET" ]]; then
    printf '%s' "${AUX_UTM_NAME:-}"
    return 0
  fi
  if [[ -n "${EXTRA_TARGET:-}" && "$target" == "$EXTRA_TARGET" ]]; then
    printf '%s' "${EXTRA_UTM_NAME:-}"
    return 0
  fi
  if [[ -n "${FIFTH_CLIENT_TARGET:-}" && "$target" == "$FIFTH_CLIENT_TARGET" ]]; then
    printf '%s' "${FIFTH_CLIENT_UTM_NAME:-}"
    return 0
  fi
  return 1
}

live_lab_target_uses_utm_transport() {
  if [[ "${LIVE_LAB_FORCE_SSH_TRANSPORT:-0}" == "1" ]]; then
    return 1
  fi
  local utm_name
  utm_name="$(live_lab_target_utm_name "$1" 2>/dev/null || true)"
  [[ -n "$utm_name" ]]
}

live_lab_has_utm_transport() {
  [[ -n "${EXIT_UTM_NAME:-}${CLIENT_UTM_NAME:-}${ENTRY_UTM_NAME:-}${AUX_UTM_NAME:-}${EXTRA_UTM_NAME:-}${FIFTH_CLIENT_UTM_NAME:-}" ]]
}

live_lab_can_use_ssh_transport() {
  [[ -n "${LIVE_LAB_SSH_IDENTITY_FILE:-}" && -f "${LIVE_LAB_SSH_IDENTITY_FILE}" ]] || return 1
  [[ -n "${LIVE_LAB_KNOWN_HOSTS:-}" && -f "${LIVE_LAB_KNOWN_HOSTS}" ]] || return 1
  return 0
}

live_lab_require_utmctl() {
  if [[ ! -x "$LIVE_LAB_UTMCTL_PATH" ]]; then
    echo "missing executable UTM control tool: $LIVE_LAB_UTMCTL_PATH" >&2
    exit 1
  fi
}

# UTM guest-agent operations abort under concurrent host-side calls on this Mac,
# so serialize every utmctl file/exec invocation across live-lab workers.
live_lab_utm_lock_dir() {
  printf '%s/utmctl.lock' "$LIVE_LAB_WORK_DIR"
}

live_lab_utm_lock_acquire() {
  local wait_secs="${1:-10800}"
  local lock_dir pid_file owner_pid waited_secs=0
  lock_dir="$(live_lab_utm_lock_dir)"
  pid_file="${lock_dir}/pid"
  while ! mkdir "$lock_dir" 2>/dev/null; do
    owner_pid=""
    if [[ -f "$pid_file" ]]; then
      owner_pid="$(cat "$pid_file" 2>/dev/null | tr -d '[:space:]' || true)"
    fi
    if [[ "$owner_pid" =~ ^[0-9]+$ ]] && ! kill -0 "$owner_pid" 2>/dev/null; then
      rm -rf "$lock_dir" 2>/dev/null || true
      continue
    fi
    if (( waited_secs >= wait_secs )); then
      echo "timed out waiting for serialized utmctl access" >&2
      return 1
    fi
    sleep 1
    waited_secs=$((waited_secs + 1))
  done
  printf '%s\n' "$$" > "$pid_file"
}

live_lab_utm_lock_release() {
  local lock_dir
  lock_dir="$(live_lab_utm_lock_dir)"
  rm -rf "$lock_dir" 2>/dev/null || true
}

live_lab_utm_run_locked() {
  local lock_wait_secs="${1:-10800}"
  shift
  local rc
  live_lab_utm_lock_acquire "$lock_wait_secs" || return 1
  if "$@"; then
    rc=0
  else
    rc=$?
  fi
  live_lab_utm_lock_release
  return "$rc"
}

live_lab_utm_run_locked_stdin() {
  local stdin_file="$1"
  local lock_wait_secs="${2:-10800}"
  shift 2
  local rc
  live_lab_utm_lock_acquire "$lock_wait_secs" || return 1
  if "$@" < "$stdin_file"; then
    rc=0
  else
    rc=$?
  fi
  live_lab_utm_lock_release
  return "$rc"
}

live_lab_wait_for_background_command() {
  local pid="$1"
  local timeout_secs="${2:-60}"
  local waited_secs=0
  local rc
  if [[ ! "$timeout_secs" =~ ^[0-9]+$ ]] || (( timeout_secs < 1 )); then
    timeout_secs=1
  fi
  while kill -0 "$pid" 2>/dev/null; do
    if (( waited_secs >= timeout_secs )); then
      kill "$pid" 2>/dev/null || true
      sleep 1
      kill -9 "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      return 124
    fi
    sleep 1
    waited_secs=$((waited_secs + 1))
  done
  if wait "$pid"; then
    rc=0
  else
    rc=$?
  fi
  return "$rc"
}

live_lab_utm_run_locked_timeout() {
  local lock_wait_secs="${1:-10800}"
  local command_timeout_secs="${2:-60}"
  shift 2
  local rc pid
  live_lab_utm_lock_acquire "$lock_wait_secs" || return 1
  "$@" &
  pid=$!
  if live_lab_wait_for_background_command "$pid" "$command_timeout_secs"; then
    rc=0
  else
    rc=$?
  fi
  live_lab_utm_lock_release
  return "$rc"
}

live_lab_utm_run_locked_stdin_timeout() {
  local stdin_file="$1"
  local lock_wait_secs="${2:-10800}"
  local command_timeout_secs="${3:-60}"
  shift 3
  local rc pid
  live_lab_utm_lock_acquire "$lock_wait_secs" || return 1
  "$@" < "$stdin_file" &
  pid=$!
  if live_lab_wait_for_background_command "$pid" "$command_timeout_secs"; then
    rc=0
  else
    rc=$?
  fi
  live_lab_utm_lock_release
  return "$rc"
}

live_lab_utm_cleanup_exec_files() {
  local utm_name="$1"
  local remote_script="$2"
  local remote_wrapper="$3"
  local remote_output="$4"
  local remote_rc="$5"
  live_lab_utm_run_locked_timeout 10800 20 \
    "$LIVE_LAB_UTMCTL_PATH" exec "$utm_name" --cmd /bin/bash -lc "rm -f $(printf '%q' "$remote_script") $(printf '%q' "$remote_wrapper") $(printf '%q' "$remote_output") $(printf '%q' "$remote_rc")" \
    >/dev/null 2>&1 || true
}

live_lab_utm_cleanup_run_files() {
  local utm_name="$1"
  local remote_script="$2"
  local remote_wrapper="$3"
  live_lab_utm_run_locked_timeout 10800 20 \
    "$LIVE_LAB_UTMCTL_PATH" exec "$utm_name" --cmd /bin/bash -lc "rm -f $(printf '%q' "$remote_script") $(printf '%q' "$remote_wrapper")" \
    >/dev/null 2>&1 || true
}

live_lab_utm_push_raw() {
  local src="$1"
  local target="$2"
  local dst="$3"
  local timeout_secs="${4:-60}"
  local utm_name attempt rc
  utm_name="$(live_lab_target_utm_name "$target")" || {
    echo "missing UTM mapping for target: $target" >&2
    return 1
  }
  local push_args=(
    "$LIVE_LAB_UTMCTL_PATH"
    file
    push
    "$utm_name"
    "$dst"
  )
  for attempt in 1 2 3; do
    if live_lab_utm_run_locked_stdin_timeout "$src" 10800 "$timeout_secs" "${push_args[@]}"; then
      return 0
    else
      rc=$?
    fi
    if [[ "$attempt" -lt 3 ]]; then
      sleep 2
    fi
  done
  live_lab_utm_run_locked_stdin_timeout "$src" 10800 "$timeout_secs" "${push_args[@]}"
}

live_lab_resolved_target_address() {
  local target="$1"
  local resolved hostname
  resolved="$(ssh -G "$target" 2>/dev/null)" || {
    live_lab_target_address "$target"
    return 0
  }
  hostname="$(awk '$1=="hostname"{print $2; exit}' <<<"$resolved")"
  if [[ -n "$hostname" ]]; then
    printf '%s' "$hostname"
    return 0
  fi
  live_lab_target_address "$target"
}

live_lab_utm_exec_as_user() {
  local target="$1"
  local user="$2"
  local home="$3"
  local command="$4"
  local timeout_secs="${5:-10800}"
  local utm_name attempt rc local_script local_wrapper
  local remote_base remote_script remote_wrapper remote_output remote_rc
  local local_output_capture local_rc_capture wrapper_rc
  local pull_attempt rc_contents output_attempt max_rc_attempts
  utm_name="$(live_lab_target_utm_name "$target")" || {
    echo "missing UTM mapping for target: $target" >&2
    return 1
  }
  local_script="$(mktemp "${LIVE_LAB_WORK_DIR}/utm-exec.XXXXXX")" || return 1
  local_wrapper="$(mktemp "${LIVE_LAB_WORK_DIR}/utm-wrapper.XXXXXX")" || {
    rm -f "$local_script"
    return 1
  }
  local_output_capture="$(mktemp "${LIVE_LAB_WORK_DIR}/utm-output.XXXXXX")" || {
    rm -f "$local_script" "$local_wrapper"
    return 1
  }
  local_rc_capture="$(mktemp "${LIVE_LAB_WORK_DIR}/utm-rc.XXXXXX")" || {
    rm -f "$local_script" "$local_wrapper" "$local_output_capture"
    return 1
  }
  {
    printf '%s\n' '#!/usr/bin/env bash'
    printf '%s\n' 'set -euo pipefail'
    printf '%s\n' "$command"
  } > "$local_script"
  chmod 700 "$local_script"
cat > "$local_wrapper" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: rn-utm-wrapper.sh <user> <home> <command-script> <output-path> <rc-path>" >&2
  exit 2
fi

user="$1"
home="$2"
command_script="$3"
output_path="$4"
rc_path="$5"
rc=0

if [[ "$user" == "root" ]]; then
  chmod 700 "$command_script"
  if /usr/bin/env HOME="$home" USER=root LOGNAME=root PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin \
    /bin/bash "$command_script" >"$output_path" 2>&1
  then
    rc=0
  else
    rc=$?
  fi
else
  chmod 755 "$command_script"
  if runuser -u "$user" -- env HOME="$home" USER="$user" LOGNAME="$user" PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin \
    /bin/bash "$command_script" >"$output_path" 2>&1
  then
    rc=0
  else
    rc=$?
  fi
fi

printf '%s\n' "$rc" > "$rc_path"
sync "$output_path" "$rc_path" >/dev/null 2>&1 || sync >/dev/null 2>&1 || true
exit 0
EOF
  chmod 700 "$local_wrapper"
  remote_base="/var/tmp/rn-utm-exec.$$.${RANDOM}"
  remote_script="${remote_base}.sh"
  remote_wrapper="${remote_base}.wrapper.sh"
  remote_output="${remote_base}.out"
  remote_rc="${remote_base}.rc"
  if ! live_lab_utm_push_raw "$local_script" "$target" "$remote_script" 60; then
    rm -f "$local_script" "$local_wrapper" "$local_output_capture" "$local_rc_capture"
    return 1
  fi
  if ! live_lab_utm_push_raw "$local_wrapper" "$target" "$remote_wrapper" 60; then
    rm -f "$local_script" "$local_wrapper" "$local_output_capture" "$local_rc_capture"
    live_lab_utm_cleanup_exec_files "$utm_name" "$remote_script" "$remote_wrapper" "$remote_output" "$remote_rc"
    return 1
  fi
  local -a exec_args
  exec_args=(
    "$LIVE_LAB_UTMCTL_PATH"
    exec
    "$utm_name"
    --cmd
    /bin/bash
    "$remote_wrapper"
    "$user"
    "$home"
    "$remote_script"
    "$remote_output"
    "$remote_rc"
  )
  wrapper_rc=1
  for attempt in 1 2 3; do
    if live_lab_utm_run_locked_timeout 10800 "$((timeout_secs + 30))" "${exec_args[@]}"; then
      wrapper_rc=0
      break
    else
      rc=$?
    fi
    if [[ "$attempt" -lt 3 ]]; then
      live_lab_utm_cleanup_exec_files "$utm_name" "$remote_script" "$remote_wrapper" "$remote_output" "$remote_rc"
      sleep 2
      if ! live_lab_utm_push_raw "$local_script" "$target" "$remote_script" 60; then
        rm -f "$local_script" "$local_wrapper" "$local_output_capture" "$local_rc_capture"
        return "$rc"
      fi
      if ! live_lab_utm_push_raw "$local_wrapper" "$target" "$remote_wrapper" 60; then
        rm -f "$local_script" "$local_wrapper" "$local_output_capture" "$local_rc_capture"
        return "$rc"
      fi
    fi
  done
  if [[ "$wrapper_rc" -ne 0 ]]; then
    live_lab_utm_cleanup_exec_files "$utm_name" "$remote_script" "$remote_wrapper" "$remote_output" "$remote_rc"
    rm -f "$local_script" "$local_wrapper" "$local_output_capture" "$local_rc_capture"
    return "$rc"
  fi
  max_rc_attempts="$timeout_secs"
  if [[ ! "$max_rc_attempts" =~ ^[0-9]+$ ]] || (( max_rc_attempts < 10 )); then
    max_rc_attempts=10
  fi
  rc_contents=""
  for ((pull_attempt=1; pull_attempt<=max_rc_attempts; pull_attempt++)); do
    : > "$local_rc_capture"
    live_lab_utm_pull "$target" "$remote_rc" "$local_rc_capture" >/dev/null 2>&1 || true
    rc_contents="$(tr -d '\r\n' < "$local_rc_capture" 2>/dev/null || true)"
    if [[ "$rc_contents" =~ ^[0-9]+$ ]]; then
      break
    fi
    if (( pull_attempt < max_rc_attempts )); then
      sleep 1
    fi
  done
  if [[ ! "$rc_contents" =~ ^[0-9]+$ ]]; then
    echo "invalid UTM command exit status for ${target}" >&2
    if [[ -n "$rc_contents" ]]; then
      printf '%s\n' "$rc_contents" >&2
    fi
    live_lab_utm_cleanup_exec_files "$utm_name" "$remote_script" "$remote_wrapper" "$remote_output" "$remote_rc"
    rm -f "$local_script" "$local_wrapper" "$local_output_capture" "$local_rc_capture"
    return 1
  fi
  for output_attempt in 1 2 3 4 5; do
    : > "$local_output_capture"
    live_lab_utm_pull "$target" "$remote_output" "$local_output_capture" >/dev/null 2>&1 || true
    if ! grep -q '^Error from event:' "$local_output_capture" 2>/dev/null; then
      break
    fi
    if [[ "$output_attempt" -lt 5 ]]; then
      sleep 1
    fi
  done
  cat "$local_output_capture"
  rc="$rc_contents"
  live_lab_utm_cleanup_exec_files "$utm_name" "$remote_script" "$remote_wrapper" "$remote_output" "$remote_rc"
  rm -f "$local_script" "$local_wrapper" "$local_output_capture" "$local_rc_capture"
  return "$rc"
}

live_lab_utm_run_as_user() {
  local target="$1"
  local user="$2"
  local home="$3"
  local command="$4"
  local utm_name attempt rc local_script local_wrapper
  local remote_base remote_script remote_wrapper
  utm_name="$(live_lab_target_utm_name "$target")" || {
    echo "missing UTM mapping for target: $target" >&2
    return 1
  }
  local_script="$(mktemp "${LIVE_LAB_WORK_DIR}/utm-run.XXXXXX")" || return 1
  local_wrapper="$(mktemp "${LIVE_LAB_WORK_DIR}/utm-run-wrapper.XXXXXX")" || {
    rm -f "$local_script"
    return 1
  }
  {
    printf '%s\n' '#!/usr/bin/env bash'
    printf '%s\n' 'set -euo pipefail'
    printf '%s\n' "$command"
  } > "$local_script"
  chmod 700 "$local_script"
  cat > "$local_wrapper" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: rn-utm-run-wrapper.sh <user> <home> <command-script>" >&2
  exit 2
fi

user="$1"
home="$2"
command_script="$3"

if [[ "$user" == "root" ]]; then
  chmod 700 "$command_script"
exec /usr/bin/env HOME="$home" USER=root LOGNAME=root PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin \
  /bin/bash "$command_script"
fi

chmod 755 "$command_script"
exec runuser -u "$user" -- env HOME="$home" USER="$user" LOGNAME="$user" PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin \
  /bin/bash "$command_script"
EOF
  chmod 700 "$local_wrapper"
  remote_base="/var/tmp/rn-utm-run.$$.${RANDOM}"
  remote_script="${remote_base}.sh"
  remote_wrapper="${remote_base}.wrapper.sh"
  if ! live_lab_utm_push_raw "$local_script" "$target" "$remote_script" 60; then
    rm -f "$local_script" "$local_wrapper"
    return 1
  fi
  if ! live_lab_utm_push_raw "$local_wrapper" "$target" "$remote_wrapper" 60; then
    rm -f "$local_script" "$local_wrapper"
    live_lab_utm_cleanup_run_files "$utm_name" "$remote_script" "$remote_wrapper"
    return 1
  fi
  local -a exec_args
  exec_args=(
    "$LIVE_LAB_UTMCTL_PATH"
    exec
    "$utm_name"
    --cmd
    /bin/bash
    "$remote_wrapper"
    "$user"
    "$home"
    "$remote_script"
  )
  rc=1
  for attempt in 1 2 3; do
    if live_lab_utm_run_locked_timeout 10800 90 "${exec_args[@]}"; then
      rc=0
      break
    else
      rc=$?
    fi
    if [[ "$attempt" -lt 3 ]]; then
      live_lab_utm_cleanup_run_files "$utm_name" "$remote_script" "$remote_wrapper"
      sleep 1
      if ! live_lab_utm_push_raw "$local_script" "$target" "$remote_script" 60; then
        rm -f "$local_script" "$local_wrapper"
        return "$rc"
      fi
      if ! live_lab_utm_push_raw "$local_wrapper" "$target" "$remote_wrapper" 60; then
        rm -f "$local_script" "$local_wrapper"
        return "$rc"
      fi
    fi
  done
  live_lab_utm_cleanup_run_files "$utm_name" "$remote_script" "$remote_wrapper"
  rm -f "$local_script" "$local_wrapper"
  return "$rc"
}

live_lab_utm_exec() {
  local target="$1"
  local command="$2"
  local timeout_secs="${3:-10800}"
  local user home
  user="$(live_lab_target_user "$target")"
  home="$(live_lab_target_home "$target")"
  live_lab_utm_exec_as_user "$target" "$user" "$home" "$command" "$timeout_secs"
}

live_lab_utm_exec_root() {
  local target="$1"
  local command="$2"
  local timeout_secs="${3:-10800}"
  live_lab_utm_exec_as_user "$target" "root" "/root" "$command" "$timeout_secs"
}

live_lab_utm_run() {
  local target="$1"
  local command="$2"
  local user home
  user="$(live_lab_target_user "$target")"
  home="$(live_lab_target_home "$target")"
  live_lab_utm_run_as_user "$target" "$user" "$home" "$command"
}

live_lab_utm_run_root() {
  local target="$1"
  local command="$2"
  live_lab_utm_run_as_user "$target" "root" "/root" "$command"
}

live_lab_utm_push() {
  local src="$1"
  local target="$2"
  local dst="$3"
  local utm_name attempt rc user quoted_user quoted_dst
  utm_name="$(live_lab_target_utm_name "$target")" || {
    echo "missing UTM mapping for target: $target" >&2
    return 1
  }
  user="$(live_lab_target_user "$target")"
  quoted_user="$(printf '%q' "$user")"
  quoted_dst="$(printf '%q' "$dst")"
  local push_args=(
    "$LIVE_LAB_UTMCTL_PATH"
    file
    push
    "$utm_name"
    "$dst"
  )
  for attempt in 1 2 3; do
    if live_lab_utm_run_locked_stdin "$src" 10800 "${push_args[@]}"; then
      if [[ "$user" != "root" ]]; then
        live_lab_utm_run_locked_timeout 10800 20 \
          "$LIVE_LAB_UTMCTL_PATH" exec "$utm_name" --cmd /bin/bash -lc "chown ${quoted_user}:${quoted_user} ${quoted_dst}" \
          >/dev/null || return 1
      fi
      return 0
    else
      rc=$?
    fi
    if [[ "$attempt" -lt 3 ]]; then
      sleep 2
    fi
  done
  if ! live_lab_utm_run_locked_stdin "$src" 10800 "${push_args[@]}"; then
    return $?
  fi
  if [[ "$user" != "root" ]]; then
    live_lab_utm_run_locked_timeout 10800 20 \
      "$LIVE_LAB_UTMCTL_PATH" exec "$utm_name" --cmd /bin/bash -lc "chown ${quoted_user}:${quoted_user} ${quoted_dst}" \
      >/dev/null || return 1
  fi
}

live_lab_utm_pull() {
  local target="$1"
  local src="$2"
  local dst="$3"
  local utm_name attempt rc
  utm_name="$(live_lab_target_utm_name "$target")" || {
    echo "missing UTM mapping for target: $target" >&2
    return 1
  }
  local pull_args=(
    "$LIVE_LAB_UTMCTL_PATH"
    file
    pull
    "$utm_name"
    "$src"
  )
  for attempt in 1 2 3; do
    if live_lab_utm_run_locked 10800 "${pull_args[@]}" > "$dst"; then
      return 0
    else
      rc=$?
    fi
    if [[ "$attempt" -lt 3 ]]; then
      sleep 2
    fi
  done
  live_lab_utm_run_locked 10800 "${pull_args[@]}" > "$dst"
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

live_lab_ssh_via_ssh() {
  local target="$1"
  local command="$2"
  local _timeout="${3:-10800}"
  local ssh_args=(
    ssh
    -n
    -o LogLevel=ERROR
    -o BatchMode=yes
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="$LIVE_LAB_KNOWN_HOSTS"
    -o ConnectTimeout=30
    -o ServerAliveInterval=60
    -o ServerAliveCountMax=20
    -o IdentitiesOnly=yes
    -i "$LIVE_LAB_SSH_IDENTITY_FILE"
    -- "$target" "$command"
  )
  local attempt rc
  live_lab_require_pinned_host_entry "$target"
  for attempt in 1 2 3; do
    if "${ssh_args[@]}"; then
      return 0
    else
      rc=$?
    fi
    if [[ "$rc" -ne 255 ]]; then
      return "$rc"
    fi
    if [[ "$attempt" -lt 3 ]]; then
      sleep 2
    fi
  done
  "${ssh_args[@]}"
}

live_lab_scp_to_via_ssh() {
  local src="$1"
  local target="$2"
  local dst="$3"
  local _timeout="${4:-10800}"
  local scp_args=(
    scp
    -q
    -o LogLevel=ERROR
    -o BatchMode=yes
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="$LIVE_LAB_KNOWN_HOSTS"
    -o ConnectTimeout=30
    -o ServerAliveInterval=60
    -o ServerAliveCountMax=20
    -o IdentitiesOnly=yes
    -i "$LIVE_LAB_SSH_IDENTITY_FILE"
    -- "$src" "${target}:${dst}"
  )
  local attempt rc
  live_lab_require_pinned_host_entry "$target"
  for attempt in 1 2 3; do
    if "${scp_args[@]}"; then
      return 0
    else
      rc=$?
    fi
    if [[ "$rc" -ne 255 ]]; then
      return "$rc"
    fi
    if [[ "$attempt" -lt 3 ]]; then
      sleep 2
    fi
  done
  "${scp_args[@]}"
}

live_lab_scp_from_via_ssh() {
  local target="$1"
  local src="$2"
  local dst="$3"
  local _timeout="${4:-10800}"
  local scp_args=(
    scp
    -q
    -o LogLevel=ERROR
    -o BatchMode=yes
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="$LIVE_LAB_KNOWN_HOSTS"
    -o ConnectTimeout=30
    -o ServerAliveInterval=60
    -o ServerAliveCountMax=20
    -o IdentitiesOnly=yes
    -i "$LIVE_LAB_SSH_IDENTITY_FILE"
    -- "${target}:${src}" "$dst"
  )
  local attempt rc
  live_lab_require_pinned_host_entry "$target"
  for attempt in 1 2 3; do
    if "${scp_args[@]}"; then
      return 0
    else
      rc=$?
    fi
    if [[ "$rc" -ne 255 ]]; then
      return "$rc"
    fi
    if [[ "$attempt" -lt 3 ]]; then
      sleep 2
    fi
  done
  "${scp_args[@]}"
}

live_lab_capture_via_ssh() {
  local target="$1"
  local body="$2"
  local timeout="${3:-10800}"
  local raw
  raw="$(live_lab_ssh_via_ssh "$target" "printf '__CAP_BEGIN__\\n'; { ${body}; }; printf '\\n__CAP_END__\\n'" "$timeout")" || return $?
  live_lab_extract_capture_output "$raw"
}

live_lab_ssh() {
  local target="$1"
  local command="$2"
  local timeout="${3:-10800}"
  if live_lab_target_uses_utm_transport "$target"; then
    if live_lab_utm_exec "$target" "$command" "$timeout"; then
      return 0
    fi
    printf 'UTM exec failed for %s; falling back to SSH\n' "$target" >&2
  fi
  live_lab_ssh_via_ssh "$target" "$command" "$timeout"
}

live_lab_scp_to() {
  local src="$1"
  local target="$2"
  local dst="$3"
  local timeout="${4:-10800}"
  if live_lab_target_uses_utm_transport "$target"; then
    if live_lab_utm_push "$src" "$target" "$dst"; then
      return 0
    fi
    printf 'UTM file push failed for %s; falling back to SCP\n' "$target" >&2
  fi
  live_lab_scp_to_via_ssh "$src" "$target" "$dst" "$timeout"
}

live_lab_scp_from() {
  local target="$1"
  local src="$2"
  local dst="$3"
  local timeout="${4:-10800}"
  if live_lab_target_uses_utm_transport "$target"; then
    if live_lab_utm_pull "$target" "$src" "$dst"; then
      return 0
    fi
    printf 'UTM file pull failed for %s; falling back to SCP\n' "$target" >&2
  fi
  live_lab_scp_from_via_ssh "$target" "$src" "$dst" "$timeout"
}

live_lab_capture() {
  local target="$1"
  local body="$2"
  local timeout="${3:-10800}"
  if live_lab_target_uses_utm_transport "$target"; then
    if live_lab_utm_exec "$target" "$body" "$timeout"; then
      return 0
    fi
    printf 'UTM capture failed for %s; falling back to SSH\n' "$target" >&2
  fi
  live_lab_capture_via_ssh "$target" "$body" "$timeout"
}

live_lab_extract_capture_output() {
  local raw="$1"
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
  # Preserve the installed RustyNet binaries under sudo while keeping the
  # command path fixed to a small, predictable set of system directories.
  printf 'root(){ sudo -n env PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin "$@"; }; set -euo pipefail; %s' "$body"
}

live_lab_rootify_direct() {
  local body="$1"
  printf 'root(){ env PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin "$@"; }; set -euo pipefail; %s' "$body"
}

live_lab_verify_sudo() {
  local target="$1"
  if live_lab_target_uses_utm_transport "$target"; then
    return 0
  fi
  local hostname_precheck_cmd
  local verify_cmd
  hostname_precheck_cmd="current_hostname=\$(hostname); if ! grep -Eq \"(^|[[:space:]])\${current_hostname}([[:space:]]|$)\" /etc/hosts; then printf 'local hostname %s is missing from /etc/hosts\\n' \"\$current_hostname\"; exit 1; fi"
  live_lab_ssh "$target" "$hostname_precheck_cmd" || return 1
  verify_cmd="if timeout 15 sudo -n -k true >/dev/null 2>&1; then :; else printf 'passwordless sudo (sudo -n) is required for live lab automation\\n'; printf 'user: %s\\n' \"\$(id -un)\"; printf 'groups: %s\\n' \"\$(id -Gn)\"; exit 1; fi"
  live_lab_ssh "$target" "$verify_cmd"
}

live_lab_retry_verify_sudo() {
  local target="$1"
  local attempts="${2:-3}"
  local sleep_secs="${3:-2}"
  local attempt

  for ((attempt=1; attempt<=attempts; attempt++)); do
    if live_lab_verify_sudo "$target"; then
      return 0
    fi
    if (( attempt < attempts )); then
      sleep "$sleep_secs"
    fi
  done

  live_lab_verify_sudo "$target"
}

live_lab_push_sudo_password() {
  local target="$1"
  if live_lab_target_uses_utm_transport "$target"; then
    local existing
    for existing in "${LIVE_LAB_REMOTE_CLEANUP_TARGETS[@]:-}"; do
      if [[ "$existing" == "$target" ]]; then
        return 0
      fi
    done
    LIVE_LAB_REMOTE_CLEANUP_TARGETS+=("$target")
    return 0
  fi
  local existing
  for existing in "${LIVE_LAB_REMOTE_CLEANUP_TARGETS[@]:-}"; do
    if [[ "$existing" == "$target" ]]; then
      live_lab_retry_verify_sudo "$target" || return 1
      return 0
    fi
  done
  LIVE_LAB_REMOTE_CLEANUP_TARGETS+=("$target")
  live_lab_retry_verify_sudo "$target" || return 1
}

live_lab_run_root() {
  local target="$1"
  local body="$2"
  if live_lab_target_uses_utm_transport "$target"; then
    if live_lab_utm_exec_root "$target" "$(live_lab_rootify_direct "$body")"; then
      return 0
    fi
    printf 'UTM root exec failed for %s; falling back to SSH\n' "$target" >&2
  fi
  live_lab_push_sudo_password "$target" || return 1
  live_lab_ssh_via_ssh "$target" "$(live_lab_rootify "$body")"
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
  if live_lab_target_uses_utm_transport "$target"; then
    if live_lab_utm_exec_root "$target" "$(live_lab_rootify_direct "$body")"; then
      return 0
    fi
    printf 'UTM root capture failed for %s; falling back to SSH\n' "$target" >&2
  fi
  live_lab_push_sudo_password "$target" || return 1
  live_lab_capture_via_ssh "$target" "$(live_lab_rootify "$body")"
}

live_lab_base64_to_hex() {
  local value="$1"
  printf '%s' "$value" | openssl base64 -d -A 2>/dev/null | xxd -p -c 256 | tr -d '\n'
}

live_lab_collect_pubkey_hex() {
  local target="$1"
  local pub_b64
  if live_lab_target_uses_utm_transport "$target"; then
    pub_b64="$(live_lab_utm_exec_root "$target" "cat /var/lib/rustynet/keys/wireguard.pub | tr -d '[:space:]'; printf '\n'")" || return 1
    pub_b64="${pub_b64//$'\r'/}"
    pub_b64="${pub_b64//$'\n'/}"
  else
    pub_b64="$(live_lab_capture_root "$target" "root cat /var/lib/rustynet/keys/wireguard.pub | tr -d '[:space:]'")"
  fi
  local pub_hex
  pub_hex="$(live_lab_base64_to_hex "$pub_b64")"
  if [[ ! "$pub_hex" =~ ^[0-9a-f]{64}$ ]]; then
    echo "failed to decode wireguard pubkey for ${target}" >&2
    return 1
  fi
  printf '%s' "$pub_hex"
}

live_lab_fetch_root_file_to_local() {
  local target="$1"
  local remote_path="$2"
  local local_path="$3"
  local quoted_remote_path
  if live_lab_target_uses_utm_transport "$target"; then
    live_lab_scp_from "$target" "$remote_path" "$local_path"
    return $?
  fi
  quoted_remote_path="$(printf '%q' "$remote_path")"
  live_lab_capture_root "$target" "root cat ${quoted_remote_path}" > "$local_path"
}

live_lab_quote_env_value() {
  local value="$1"
  if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
    echo "env value contains newline characters" >&2
    return 1
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
  live_lab_ensure_rustynetd_group "$target" || return 1
  live_lab_scp_to "$assignment_pub_local" "$target" "/tmp/rn-assignment.pub" || return 1
  live_lab_scp_to "$assignment_bundle_local" "$target" "/tmp/rn-assignment.bundle" || return 1
  live_lab_run_root "$target" "root install -d -m 0750 -o root -g rustynetd /etc/rustynet && root install -d -m 0700 -o rustynetd -g rustynetd /var/lib/rustynet && root install -m 0644 -o root -g root /tmp/rn-assignment.pub /etc/rustynet/assignment.pub && root install -m 0640 -o root -g rustynetd /tmp/rn-assignment.bundle /var/lib/rustynet/rustynetd.assignment && root rm -f /var/lib/rustynet/rustynetd.assignment.watermark /tmp/rn-assignment.pub /tmp/rn-assignment.bundle" || return 1
}

live_lab_install_assignment_refresh_env() {
  local target="$1"
  local env_local="$2"
  live_lab_scp_to "$env_local" "$target" "/tmp/rn-assignment-refresh.env" || return 1
  live_lab_run_root "$target" "root install -d -m 0750 -o root -g rustynetd /etc/rustynet && root install -m 0600 -o root -g root /tmp/rn-assignment-refresh.env /etc/rustynet/assignment-refresh.env && root rm -f /tmp/rn-assignment-refresh.env" || return 1
}

live_lab_install_dns_zone_bundle() {
  local target="$1"
  local dns_zone_pub_local="$2"
  local dns_zone_bundle_local="$3"
  live_lab_ensure_rustynetd_group "$target" || return 1
  live_lab_scp_to "$dns_zone_pub_local" "$target" "/tmp/rn-dns-zone.pub" || return 1
  live_lab_scp_to "$dns_zone_bundle_local" "$target" "/tmp/rn-dns-zone.bundle" || return 1
  live_lab_run_root "$target" "root install -d -m 0750 -o root -g rustynetd /etc/rustynet && root install -d -m 0700 -o rustynetd -g rustynetd /var/lib/rustynet && root install -m 0644 -o root -g root /tmp/rn-dns-zone.pub /etc/rustynet/dns-zone.pub && root install -m 0640 -o root -g rustynetd /tmp/rn-dns-zone.bundle /var/lib/rustynet/rustynetd.dns-zone && root rm -f /var/lib/rustynet/rustynetd.dns-zone.watermark /tmp/rn-dns-zone.pub /tmp/rn-dns-zone.bundle" || return 1
}

live_lab_ensure_rustynetd_group() {
  local target="$1"
  live_lab_run_root "$target" "if ! root getent group rustynetd >/dev/null 2>&1; then root groupadd --system rustynetd; fi" || return 1
}

live_lab_issue_assignment_bundles_from_env() {
  local target="$1"
  local env_local="$2"
  local remote_env_path="${3:-/tmp/rn-e2e-assignments.env}"
  live_lab_scp_to "$env_local" "$target" "$remote_env_path" || return 1
  if ! live_lab_run_root "$target" "root rustynet ops e2e-issue-assignment-bundles-from-env --env-file '${remote_env_path}'"; then
    live_lab_run_root "$target" "root rm -f '${remote_env_path}'" >/dev/null 2>&1 || true
    return 1
  fi
  live_lab_run_root "$target" "root rm -f '${remote_env_path}'" || return 1
}

live_lab_issue_traversal_bundles_from_env() {
  local target="$1"
  local env_local="$2"
  local remote_env_path="${3:-/tmp/rn-e2e-traversal.env}"
  live_lab_scp_to "$env_local" "$target" "$remote_env_path" || return 1
  if ! live_lab_run_root "$target" "root rustynet ops e2e-issue-traversal-bundles-from-env --env-file '${remote_env_path}'"; then
    live_lab_run_root "$target" "root rm -f '${remote_env_path}'" >/dev/null 2>&1 || true
    return 1
  fi
  live_lab_run_root "$target" "root rm -f '${remote_env_path}'" || return 1
}

live_lab_issue_dns_zone_bundles_from_env() {
  local target="$1"
  local env_local="$2"
  local remote_env_path="${3:-/tmp/rn-e2e-dns-zone.env}"
  live_lab_scp_to "$env_local" "$target" "$remote_env_path" || return 1
  if ! live_lab_run_root "$target" "root rustynet ops e2e-issue-dns-zone-bundles-from-env --env-file '${remote_env_path}'"; then
    live_lab_run_root "$target" "root rm -f '${remote_env_path}'" >/dev/null 2>&1 || true
    return 1
  fi
  live_lab_run_root "$target" "root rm -f '${remote_env_path}'" || return 1
}

live_lab_enforce_host() {
  local target="$1"
  local role="$2"
  local node_id="$3"
  local ssh_allow_cidrs="$4"
  local src_dir="$5"
  local backend_env=""
  if [[ -n "${RUSTYNET_BACKEND:-}" ]]; then
    backend_env="env RUSTYNET_BACKEND='${RUSTYNET_BACKEND}' "
  fi
  live_lab_run_root "$target" "root ${backend_env}rustynet ops e2e-enforce-host --role '${role}' --node-id '${node_id}' --src-dir '${src_dir}' --ssh-allow-cidrs '${ssh_allow_cidrs}'" || return 1
}

live_lab_apply_role_coupling() {
  local target="$1"
  local target_role="$2"
  local preferred_exit_node_id="${3:-}"
  local enable_exit_advertise="${4:-false}"
  local env_path="${5:-/etc/rustynet/assignment-refresh.env}"
  local skip_client_exit_route_wait="${6:-false}"
  local command
  live_lab_push_sudo_password "$target" || return 1
  command="root env RUSTYNET_SOCKET=/run/rustynet/rustynetd.sock RUSTYNET_AUTO_TUNNEL_BUNDLE=/var/lib/rustynet/rustynetd.assignment RUSTYNET_AUTO_TUNNEL_WATERMARK=/var/lib/rustynet/rustynetd.assignment.watermark rustynet ops apply-role-coupling --target-role '${target_role}' --enable-exit-advertise '${enable_exit_advertise}' --env-path '${env_path}'"
  if [[ -n "$preferred_exit_node_id" ]]; then
    command+=" --preferred-exit-node-id '${preferred_exit_node_id}'"
  fi
  if [[ "$skip_client_exit_route_wait" == "true" ]]; then
    command+=" --skip-client-exit-route-convergence-wait"
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

live_lab_shell_quote() {
  printf '%q' "$1"
}

live_lab_status_snapshot_body() {
  cat <<'EOF'
printf '__RNLAB_STATUS_BEGIN__\n'
root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet status || true
printf '__RNLAB_STATUS_END__\n'
EOF
}

live_lab_service_snapshot_body() {
  live_lab_status_snapshot_body
  cat <<'EOF'
printf '__RNLAB_SYSTEMD_BEGIN__\n'
root systemctl status rustynetd.service rustynetd-privileged-helper.service rustynetd-managed-dns.service --no-pager -l || true
printf '__RNLAB_SYSTEMD_END__\n'
printf '__RNLAB_SOCKET_BEGIN__\n'
root ls -l /run/rustynet || true
root test -S /run/rustynet/rustynetd.sock && echo daemon_socket_present || echo daemon_socket_missing
printf '__RNLAB_SOCKET_END__\n'
printf '__RNLAB_SS_BEGIN__\n'
root ss -tulpn || true
printf '__RNLAB_SS_END__\n'
printf '__RNLAB_JOURNAL_BEGIN__\n'
root journalctl -u rustynetd.service -u rustynetd-privileged-helper.service -u rustynetd-managed-dns.service -n 120 --no-pager --output=short-iso || true
printf '__RNLAB_JOURNAL_END__\n'
EOF
}

live_lab_signed_state_body() {
  local node_id="$1"
  local zone_name="${2:-${RUSTYNET_DNS_ZONE_NAME:-rustynet}}"
  local max_age_secs="${3:-${CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS:-900}}"
  local max_clock_skew_secs="${4:-${CROSS_NETWORK_MAX_TIME_SKEW_SECS:-2}}"
  local quoted_node_id quoted_zone_name quoted_max_age quoted_max_clock_skew
  quoted_node_id="$(live_lab_shell_quote "$node_id")"
  quoted_zone_name="$(live_lab_shell_quote "$zone_name")"
  quoted_max_age="$(live_lab_shell_quote "$max_age_secs")"
  quoted_max_clock_skew="$(live_lab_shell_quote "$max_clock_skew_secs")"
  cat <<EOF
node_id=${quoted_node_id}
zone_name=${quoted_zone_name}
max_age_secs=${quoted_max_age}
max_clock_skew_secs=${quoted_max_clock_skew}
artifact_chain_result=fail
netcheck_rc=0
assignment_verify_rc=0
traversal_verify_rc=0
trust_verify_rc=0
dns_zone_verify_rc=0
netcheck_output="\$(root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet netcheck 2>&1)" || netcheck_rc=\$?
assignment_verify_output="\$(root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet assignment verify --bundle /var/lib/rustynet/rustynetd.assignment --verifier-key /etc/rustynet/assignment.pub --watermark /var/lib/rustynet/rustynetd.assignment.watermark --expected-node-id "\$node_id" --max-age-secs "\$max_age_secs" --max-clock-skew-secs "\$max_clock_skew_secs" 2>&1)" || assignment_verify_rc=\$?
traversal_verify_output="\$(root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet traversal verify --bundle /var/lib/rustynet/rustynetd.traversal --verifier-key /etc/rustynet/traversal.pub --watermark /var/lib/rustynet/rustynetd.traversal.watermark --expected-source-node-id "\$node_id" --max-age-secs "\$max_age_secs" --max-clock-skew-secs "\$max_clock_skew_secs" 2>&1)" || traversal_verify_rc=\$?
trust_verify_output="\$(root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet trust verify --evidence /var/lib/rustynet/rustynetd.trust --verifier-key /etc/rustynet/trust-evidence.pub --watermark /var/lib/rustynet/rustynetd.trust.watermark --max-age-secs "\$max_age_secs" --max-clock-skew-secs "\$max_clock_skew_secs" 2>&1)" || trust_verify_rc=\$?
dns_zone_verify_output="\$(root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet dns zone verify --bundle /var/lib/rustynet/rustynetd.dns-zone --verifier-key /etc/rustynet/dns-zone.pub --expected-zone-name "\$zone_name" 2>&1)" || dns_zone_verify_rc=\$?
if [[ "\$assignment_verify_rc" -eq 0 && "\$traversal_verify_rc" -eq 0 && "\$trust_verify_rc" -eq 0 && "\$dns_zone_verify_rc" -eq 0 ]]; then
  artifact_chain_result=pass
fi
printf 'signed_state_snapshot_version=1\n'
printf 'signed_state_node_id=%s\n' "\$node_id"
printf 'signed_state_zone_name=%s\n' "\$zone_name"
printf 'signed_state_max_age_secs=%s\n' "\$max_age_secs"
printf 'signed_state_max_clock_skew_secs=%s\n' "\$max_clock_skew_secs"
printf 'artifact_chain_result=%s\n' "\$artifact_chain_result"
printf 'signed_state_health=%s\n' "\$artifact_chain_result"
printf 'signed_artifact_chain_status=%s\n' "\$artifact_chain_result"
if [[ "\$artifact_chain_result" == "pass" ]]; then
  printf 'signed_artifact_chain_ok\n'
fi
printf 'netcheck_rc=%s\n' "\$netcheck_rc"
printf 'assignment_verify_rc=%s\n' "\$assignment_verify_rc"
printf 'traversal_verify_rc=%s\n' "\$traversal_verify_rc"
printf 'trust_verify_rc=%s\n' "\$trust_verify_rc"
printf 'dns_zone_verify_rc=%s\n' "\$dns_zone_verify_rc"
printf 'netcheck_begin\n'
printf '%s\n' "\$netcheck_output"
printf 'netcheck_end\n'
printf 'assignment_verify_begin\n'
printf '%s\n' "\$assignment_verify_output"
printf 'assignment_verify_end\n'
printf 'traversal_verify_begin\n'
printf '%s\n' "\$traversal_verify_output"
printf 'traversal_verify_end\n'
printf 'trust_verify_begin\n'
printf '%s\n' "\$trust_verify_output"
printf 'trust_verify_end\n'
printf 'dns_zone_verify_begin\n'
printf '%s\n' "\$dns_zone_verify_output"
printf 'dns_zone_verify_end\n'
EOF
}

live_lab_signed_state_snapshot_body() {
  local node_id="$1"
  local zone_name="${2:-${RUSTYNET_DNS_ZONE_NAME:-rustynet}}"
  local max_age_secs="${3:-${CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS:-900}}"
  local max_clock_skew_secs="${4:-${CROSS_NETWORK_MAX_TIME_SKEW_SECS:-2}}"
  cat <<EOF
printf '__RNLAB_SIGNED_STATE_BEGIN__\n'
$(live_lab_signed_state_body "$node_id" "$zone_name" "$max_age_secs" "$max_clock_skew_secs")
printf '__RNLAB_SIGNED_STATE_END__\n'
EOF
}

live_lab_route_policy_body() {
  local destination="${1:-1.1.1.1}"
  local expected_next_hop="${2:-}"
  local quoted_destination quoted_expected
  quoted_destination="$(live_lab_shell_quote "$destination")"
  quoted_expected="$(live_lab_shell_quote "$expected_next_hop")"
  cat <<EOF
destination=${quoted_destination}
expected_next_hop=${quoted_expected}
route_get_output=""
route_get_rc=0
if route_get_output="\$(ip -4 route get "\$destination" 2>&1)"; then
  :
else
  route_get_rc=\$?
fi
actual_route_table="main"
if [[ "\$route_get_output" =~ (^|[[:space:]])table[[:space:]]+([^[:space:]]+) ]]; then
  actual_route_table="\${BASH_REMATCH[2]}"
fi
actual_route_device=""
if [[ "\$route_get_output" =~ (^|[[:space:]])dev[[:space:]]+([^[:space:]]+) ]]; then
  actual_route_device="\${BASH_REMATCH[2]}"
fi
actual_via=""
if [[ "\$route_get_output" =~ (^|[[:space:]])via[[:space:]]+([^[:space:]]+) ]]; then
  actual_via="\${BASH_REMATCH[2]}"
fi
actual_next_hop="unresolved"
if [[ -n "\$actual_via" ]]; then
  actual_next_hop="\$actual_via"
elif [[ -n "\$actual_route_device" && "\$route_get_rc" -eq 0 ]]; then
  actual_next_hop="direct:\$actual_route_device"
fi
expected_next_hop_match="skipped"
if [[ -n "\$expected_next_hop" ]]; then
  if [[ "\$actual_next_hop" == "\$expected_next_hop" ]]; then
    expected_next_hop_match="pass"
  else
    expected_next_hop_match="fail"
  fi
fi
printf 'route_policy_version=1\n'
printf 'route_destination=%s\n' "\$destination"
printf 'route_get_rc=%s\n' "\$route_get_rc"
printf 'actual_route_table=%s\n' "\$actual_route_table"
printf 'actual_route_device=%s\n' "\$actual_route_device"
printf 'actual_next_hop=%s\n' "\$actual_next_hop"
printf 'expected_next_hop_match=%s\n' "\$expected_next_hop_match"
printf 'ip_rule_begin\n'
ip rule show || true
printf 'ip_rule_end\n'
printf 'route_main_begin\n'
ip -4 route show table main || true
printf 'route_main_end\n'
printf 'route_51820_begin\n'
ip -4 route show table 51820 || true
printf 'route_51820_end\n'
printf 'route_get_begin\n'
printf '%s\n' "\$route_get_output"
printf 'route_get_end\n'
EOF
}

live_lab_route_policy_snapshot_body() {
  local destination="${1:-1.1.1.1}"
  local expected_next_hop="${2:-}"
  cat <<EOF
printf '__RNLAB_ROUTE_POLICY_BEGIN__\n'
$(live_lab_route_policy_body "$destination" "$expected_next_hop")
printf '__RNLAB_ROUTE_POLICY_END__\n'
EOF
}

live_lab_dns_state_body() {
  local probe
  local quoted_probes=""
  for probe in "$@"; do
    quoted_probes+=" $(live_lab_shell_quote "$probe")"
  done
  cat <<EOF
probe_names=(${quoted_probes})
if [[ "\${#probe_names[@]}" -eq 0 ]]; then
  probe_names=(localhost)
  current_hostname="\$(hostname 2>/dev/null || true)"
  if [[ -n "\$current_hostname" && "\$current_hostname" != "localhost" ]]; then
    probe_names+=("\$current_hostname")
  fi
fi
resolv_conf_target="\$(readlink -f /etc/resolv.conf 2>/dev/null || printf '/etc/resolv.conf')"
systemd_resolved_service="missing"
managed_dns_service="missing"
if command -v systemctl >/dev/null 2>&1; then
  systemd_resolved_service="\$(systemctl is-active systemd-resolved.service 2>/dev/null || true)"
  [[ -n "\$systemd_resolved_service" ]] || systemd_resolved_service="unknown"
  managed_dns_service="\$(systemctl is-active rustynetd-managed-dns.service 2>/dev/null || true)"
  [[ -n "\$managed_dns_service" ]] || managed_dns_service="unknown"
fi
resolvectl_available=0
if command -v resolvectl >/dev/null 2>&1; then
  resolvectl_available=1
fi
run_dns_probe() {
  local probe="\$1"
  if [[ "\$resolvectl_available" -eq 1 ]]; then
    if command -v timeout >/dev/null 2>&1; then
      root timeout 15 resolvectl query --legend=no "\$probe" 2>/dev/null || timeout 15 resolvectl query --legend=no "\$probe" 2>/dev/null || true
    else
      root resolvectl query --legend=no "\$probe" 2>/dev/null || resolvectl query --legend=no "\$probe" 2>/dev/null || true
    fi
    return 0
  fi
  getent ahostsv4 "\$probe" 2>/dev/null || getent hosts "\$probe" 2>/dev/null || true
}
printf 'dns_state_version=1\n'
printf 'resolv_conf_target=%s\n' "\$resolv_conf_target"
printf 'systemd_resolved_service=%s\n' "\$systemd_resolved_service"
printf 'managed_dns_service=%s\n' "\$managed_dns_service"
printf 'resolvectl_available=%s\n' "\$resolvectl_available"
printf 'probe_count=%s\n' "\${#probe_names[@]}"
for index in "\${!probe_names[@]}"; do
  printf 'probe_%s=%s\n' "\$index" "\${probe_names[\$index]}"
done
printf 'resolv_conf_begin\n'
if root test -f /etc/resolv.conf; then
  root cat /etc/resolv.conf 2>/dev/null || cat /etc/resolv.conf 2>/dev/null || true
else
  printf 'resolv.conf missing\n'
fi
printf 'resolv_conf_end\n'
printf 'service_status_begin\n'
printf 'systemd_resolved_service=%s\n' "\$systemd_resolved_service"
printf 'managed_dns_service=%s\n' "\$managed_dns_service"
printf 'service_status_end\n'
printf 'resolvectl_status_begin\n'
if [[ "\$resolvectl_available" -eq 1 ]]; then
  if command -v timeout >/dev/null 2>&1; then
    root timeout 15 resolvectl status 2>/dev/null || timeout 15 resolvectl status 2>/dev/null || true
  else
    root resolvectl status 2>/dev/null || resolvectl status 2>/dev/null || true
  fi
else
  printf 'resolvectl_missing\n'
fi
printf 'resolvectl_status_end\n'
for probe in "\${probe_names[@]}"; do
  printf 'probe_begin=%s\n' "\$probe"
  run_dns_probe "\$probe"
  printf 'probe_end=%s\n' "\$probe"
done
EOF
}

live_lab_dns_state_snapshot_body() {
  cat <<EOF
printf '__RNLAB_DNS_STATE_BEGIN__\n'
$(live_lab_dns_state_body "$@")
printf '__RNLAB_DNS_STATE_END__\n'
EOF
}

live_lab_dns_zone_body() {
  local node_id="$1"
  local zone_name="${2:-${RUSTYNET_DNS_ZONE_NAME:-rustynet}}"
  local quoted_node_id quoted_zone_name
  quoted_node_id="$(live_lab_shell_quote "$node_id")"
  quoted_zone_name="$(live_lab_shell_quote "$zone_name")"
  cat <<EOF
node_id=${quoted_node_id}
zone_name=${quoted_zone_name}
status_rc=0
dns_inspect_rc=0
dns_zone_verify_rc=0
status_output="\$(root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet status 2>&1)" || status_rc=\$?
dns_inspect_output="\$(root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet dns inspect 2>&1)" || dns_inspect_rc=\$?
dns_zone_verify_output="\$(root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet dns zone verify --bundle /var/lib/rustynet/rustynetd.dns-zone --verifier-key /etc/rustynet/dns-zone.pub --expected-zone-name "\$zone_name" 2>&1)" || dns_zone_verify_rc=\$?
dns_zone_bundle_present=0
dns_zone_verifier_present=0
dns_zone_watermark_present=0
if root test -f /var/lib/rustynet/rustynetd.dns-zone; then
  dns_zone_bundle_present=1
fi
if root test -f /etc/rustynet/dns-zone.pub; then
  dns_zone_verifier_present=1
fi
if root test -e /var/lib/rustynet/rustynetd.dns-zone.watermark; then
  dns_zone_watermark_present=1
fi
printf 'dns_zone_snapshot_version=1\n'
printf 'dns_zone_node_id=%s\n' "\$node_id"
printf 'dns_zone_name=%s\n' "\$zone_name"
printf 'status_rc=%s\n' "\$status_rc"
printf 'dns_inspect_rc=%s\n' "\$dns_inspect_rc"
printf 'dns_zone_verify_rc=%s\n' "\$dns_zone_verify_rc"
printf 'dns_zone_bundle_present=%s\n' "\$dns_zone_bundle_present"
printf 'dns_zone_verifier_present=%s\n' "\$dns_zone_verifier_present"
printf 'dns_zone_watermark_present=%s\n' "\$dns_zone_watermark_present"
printf 'status_begin\n'
printf '%s\n' "\$status_output"
printf 'status_end\n'
printf 'dns_inspect_begin\n'
printf '%s\n' "\$dns_inspect_output"
printf 'dns_inspect_end\n'
printf 'dns_zone_verify_begin\n'
printf '%s\n' "\$dns_zone_verify_output"
printf 'dns_zone_verify_end\n'
EOF
}

live_lab_dns_zone_snapshot_body() {
  local node_id="$1"
  local zone_name="${2:-${RUSTYNET_DNS_ZONE_NAME:-rustynet}}"
  cat <<EOF
printf '__RNLAB_DNS_ZONE_BEGIN__\n'
$(live_lab_dns_zone_body "$node_id" "$zone_name")
printf '__RNLAB_DNS_ZONE_END__\n'
EOF
}

live_lab_collect_dns_snapshot() {
  local target="$1"
  shift || true
  local snapshot
  snapshot="$(live_lab_capture_root "$target" "$(live_lab_dns_state_snapshot_body "$@")")" || return 1
  {
    printf 'dns_state_target=%s\n' "$target"
    printf 'dns_state_collected_at_utc=%s\n' "$(date -u +%FT%TZ)"
    printf '%s\n' "$snapshot"
  }
}

live_lab_network_snapshot_body() {
  cat <<'EOF'
printf '__RNLAB_NETWORK_BEGIN__\n'
printf 'interfaces_begin\n'
ip -br addr || true
printf 'interfaces_end\n'
printf 'links_begin\n'
ip -br link || true
printf 'links_end\n'
printf 'rules_begin\n'
ip rule show || true
printf 'rules_end\n'
printf 'route_main_begin\n'
ip -4 route show table main || true
printf 'route_main_end\n'
printf 'route_51820_begin\n'
ip -4 route show table 51820 || true
printf 'route_51820_end\n'
printf 'route_get_begin\n'
ip -4 route get 1.1.1.1 || true
printf 'route_get_end\n'
printf 'wg_endpoints_begin\n'
root wg show rustynet0 endpoints || true
printf 'wg_endpoints_end\n'
printf 'nft_ruleset_begin\n'
root nft list ruleset || true
printf 'nft_ruleset_end\n'
printf '__RNLAB_NETWORK_END__\n'
EOF
}

live_lab_secret_hygiene_snapshot_body() {
  cat <<'EOF'
printf '__RNLAB_SECRET_HYGIENE_BEGIN__\n'
EOF
  live_lab_secret_hygiene_body
  cat <<'EOF'
printf '__RNLAB_SECRET_HYGIENE_END__\n'
EOF
}

live_lab_secret_hygiene_body() {
  cat <<'EOF'
plaintext_present=0
for path in /var/lib/rustynet/keys/wireguard.passphrase /etc/rustynet/wireguard.passphrase /etc/rustynet/signing_key_passphrase; do
  if root test -e "$path"; then
    printf 'plaintext_passphrase_present=%s\n' "$path"
    plaintext_present=1
  else
    printf 'plaintext_passphrase_absent=%s\n' "$path"
  fi
done
for path in /etc/rustynet/credentials/wg_key_passphrase.cred /etc/rustynet/credentials/signing_key_passphrase.cred; do
  if root test -e "$path"; then
    printf 'credential_present=%s\n' "$path"
  else
    printf 'credential_missing=%s\n' "$path"
  fi
done
if root test -S /run/rustynet/rustynetd.sock; then
  printf 'daemon_socket=present\n'
else
  printf 'daemon_socket=missing\n'
fi
if [[ "$plaintext_present" -eq 0 ]]; then
  printf 'result=no-plaintext-passphrase-files\n'
else
  printf 'result=plaintext-passphrase-files-present\n'
fi
EOF
}

live_lab_collect_secret_hygiene() {
  local target="$1"
  local snapshot
  snapshot="$(live_lab_capture_root "$target" "$(live_lab_secret_hygiene_snapshot_body)")" || return 1
  {
    printf 'secret_hygiene_version=1\n'
    printf 'target=%s\n' "$target"
    printf 'collected_at_utc=%s\n' "$(date -u +%FT%TZ)"
    printf '%s\n' "$snapshot"
  }
}

live_lab_collect_service_snapshot() {
  local target="$1"
  local snapshot
  snapshot="$(live_lab_capture_root "$target" "$(live_lab_service_snapshot_body)")" || return 1
  {
    printf 'service_snapshot_version=1\n'
    printf 'target=%s\n' "$target"
    printf 'collected_at_utc=%s\n' "$(date -u +%FT%TZ)"
    printf '%s\n' "$snapshot"
  }
}

live_lab_collect_signed_state_snapshot() {
  local target="$1"
  local node_id="$2"
  local role="${3:-}"
  local zone_name="${4:-${RUSTYNET_DNS_ZONE_NAME:-rustynet}}"
  local max_age_secs="${5:-${CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS:-900}}"
  local max_clock_skew_secs="${6:-${CROSS_NETWORK_MAX_TIME_SKEW_SECS:-2}}"
  local snapshot
  snapshot="$(live_lab_capture_root "$target" "$(live_lab_signed_state_snapshot_body "$node_id" "$zone_name" "$max_age_secs" "$max_clock_skew_secs")")" || return 1
  {
    printf 'signed_state_target=%s\n' "$target"
    printf 'signed_state_node_id=%s\n' "$node_id"
    printf 'signed_state_role=%s\n' "$role"
    printf 'signed_state_zone_name=%s\n' "$zone_name"
    printf 'signed_state_max_age_secs=%s\n' "$max_age_secs"
    printf 'signed_state_max_clock_skew_secs=%s\n' "$max_clock_skew_secs"
    printf 'signed_state_collected_at_utc=%s\n' "$(date -u +%FT%TZ)"
    printf '%s\n' "$snapshot"
  }
}

live_lab_collect_dns_zone_snapshot() {
  local target="$1"
  local node_id="$2"
  local zone_name="${3:-${RUSTYNET_DNS_ZONE_NAME:-rustynet}}"
  local snapshot
  snapshot="$(live_lab_capture_root "$target" "$(live_lab_dns_zone_snapshot_body "$node_id" "$zone_name")")" || return 1
  {
    printf 'dns_zone_target=%s\n' "$target"
    printf 'dns_zone_node_id=%s\n' "$node_id"
    printf 'dns_zone_name=%s\n' "$zone_name"
    printf 'dns_zone_collected_at_utc=%s\n' "$(date -u +%FT%TZ)"
    printf '%s\n' "$snapshot"
  }
}

live_lab_collect_network_snapshot() {
  local target="$1"
  local snapshot
  snapshot="$(live_lab_capture_root "$target" "$(live_lab_network_snapshot_body)")" || return 1
  {
    printf 'network_snapshot_version=1\n'
    printf 'target=%s\n' "$target"
    printf 'collected_at_utc=%s\n' "$(date -u +%FT%TZ)"
    printf '%s\n' "$snapshot"
  }
}

live_lab_time_snapshot_body() {
  local reference_unix="${1:-}"
  local max_clock_skew_secs="${2:-${CROSS_NETWORK_MAX_TIME_SKEW_SECS:-2}}"
  local quoted_reference_unix quoted_max_clock_skew_secs
  quoted_reference_unix="$(live_lab_shell_quote "$reference_unix")"
  quoted_max_clock_skew_secs="$(live_lab_shell_quote "$max_clock_skew_secs")"
  cat <<EOF
reference_unix=${quoted_reference_unix}
max_clock_skew_secs=${quoted_max_clock_skew_secs}
time_snapshot_status=pass
timedatectl_available=0
chronyc_available=0
ntpq_available=0
sync_evidence_present=0
sync_source_kind=none
sync_source_detail=none
system_clock_synchronized=unknown
clock_skew_secs=unknown
remote_unix_now="\$(date -u +%s)"
timedatectl_status_output=""
timedatectl_show_output=""
timedatectl_timesync_output=""
chronyc_tracking_output=""
chronyc_sources_output=""
ntpq_output=""
timesync_service_output=""
normalize_single_line() {
  tr '\n' ' ' | tr -s ' '
}
if command -v timedatectl >/dev/null 2>&1; then
  timedatectl_available=1
fi
if command -v chronyc >/dev/null 2>&1; then
  chronyc_available=1
fi
if command -v ntpq >/dev/null 2>&1; then
  ntpq_available=1
fi
if command -v systemctl >/dev/null 2>&1; then
  timesync_service_output="\$(root systemctl status systemd-timesyncd.service chronyd.service chrony.service --no-pager -l 2>/dev/null || systemctl status systemd-timesyncd.service chronyd.service chrony.service --no-pager -l 2>/dev/null || true)"
fi
if [[ "\$timedatectl_available" -eq 1 ]]; then
  timedatectl_status_output="\$(root timedatectl status 2>/dev/null || timedatectl status 2>/dev/null || true)"
  timedatectl_show_output="\$(root timedatectl show --all 2>/dev/null || timedatectl show --all 2>/dev/null || true)"
  timedatectl_timesync_output="\$(root timedatectl show-timesync --all 2>/dev/null || timedatectl show-timesync --all 2>/dev/null || true)"
  if grep -Eq 'System clock synchronized:[[:space:]]+yes' <<<"\$timedatectl_status_output" \
    || grep -Eq '^SystemClockSynchronized=yes$' <<<"\$timedatectl_show_output" \
    || grep -Eq '^NTPSynchronized=yes$' <<<"\$timedatectl_show_output"; then
    system_clock_synchronized=yes
  elif grep -Eq 'System clock synchronized:[[:space:]]+no' <<<"\$timedatectl_status_output" \
    || grep -Eq '^SystemClockSynchronized=no$' <<<"\$timedatectl_show_output" \
    || grep -Eq '^NTPSynchronized=no$' <<<"\$timedatectl_show_output"; then
    system_clock_synchronized=no
  fi
  sync_source_detail="\$(awk -F= '/^(ServerName|ServerAddress)=/ && \$2 != "" { print \$2; exit }' <<<"\$timedatectl_timesync_output" | normalize_single_line)"
  if [[ "\$system_clock_synchronized" == "yes" && -n "\$sync_source_detail" ]]; then
    sync_evidence_present=1
    sync_source_kind=timedatectl
  fi
fi
if [[ "\$sync_evidence_present" -eq 0 && "\$chronyc_available" -eq 1 ]]; then
  chronyc_tracking_output="\$(root chronyc tracking 2>/dev/null || chronyc tracking 2>/dev/null || true)"
  chronyc_sources_output="\$(root chronyc sources -v 2>/dev/null || chronyc sources -v 2>/dev/null || true)"
  if grep -Eq 'Leap status[[:space:]]*:[[:space:]]*Normal' <<<"\$chronyc_tracking_output"; then
    sync_source_detail="\$(awk -F':[[:space:]]*' '/^Reference ID/ { print \$2; exit }' <<<"\$chronyc_tracking_output" | normalize_single_line)"
    if [[ -z "\$sync_source_detail" ]]; then
      sync_source_detail="\$(awk '/^[[:space:]]*[\^\=\#\?\+\-xo~]\*/ { print \$2; exit }' <<<"\$chronyc_sources_output" | normalize_single_line)"
    fi
    if [[ -n "\$sync_source_detail" && "\$sync_source_detail" != *"LOCAL"* && "\$sync_source_detail" != "00000000" ]]; then
      sync_evidence_present=1
      sync_source_kind=chronyc
      system_clock_synchronized=yes
    fi
  fi
fi
if [[ "\$sync_evidence_present" -eq 0 && "\$ntpq_available" -eq 1 ]]; then
  ntpq_output="\$(root ntpq -p 2>/dev/null || ntpq -p 2>/dev/null || true)"
  sync_source_detail="\$(awk '/^\*/ { print \$1 " " \$2; exit }' <<<"\$ntpq_output" | normalize_single_line)"
  if [[ -n "\$sync_source_detail" ]]; then
    sync_evidence_present=1
    sync_source_kind=ntpq
    system_clock_synchronized=yes
  fi
fi
if [[ "\$sync_evidence_present" -eq 0 ]]; then
  time_snapshot_status=fail
fi
if [[ "\$reference_unix" =~ ^[0-9]+$ ]]; then
  if (( remote_unix_now >= reference_unix )); then
    clock_skew_secs=\$((remote_unix_now - reference_unix))
  else
    clock_skew_secs=\$((reference_unix - remote_unix_now))
  fi
else
  time_snapshot_status=fail
fi
if [[ "\$clock_skew_secs" =~ ^[0-9]+$ && "\$max_clock_skew_secs" =~ ^[0-9]+$ ]] \
  && (( clock_skew_secs > max_clock_skew_secs )); then
  time_snapshot_status=fail
fi
printf '__RNLAB_TIME_BEGIN__\n'
printf 'time_snapshot_version=2\n'
printf 'utc_now=%s\n' "\$(date -u +%FT%TZ)"
printf 'reference_unix=%s\n' "\$reference_unix"
printf 'max_clock_skew_secs=%s\n' "\$max_clock_skew_secs"
printf 'remote_unix_now=%s\n' "\$remote_unix_now"
printf 'clock_skew_secs=%s\n' "\$clock_skew_secs"
printf 'timedatectl_available=%s\n' "\$timedatectl_available"
printf 'chronyc_available=%s\n' "\$chronyc_available"
printf 'ntpq_available=%s\n' "\$ntpq_available"
printf 'system_clock_synchronized=%s\n' "\$system_clock_synchronized"
printf 'sync_evidence_present=%s\n' "\$sync_evidence_present"
printf 'sync_source_kind=%s\n' "\$sync_source_kind"
printf 'sync_source_detail=%s\n' "\$sync_source_detail"
printf 'time_snapshot_status=%s\n' "\$time_snapshot_status"
if [[ "\$timedatectl_available" -eq 1 || "\$chronyc_available" -eq 1 || "\$ntpq_available" -eq 1 ]]; then
  printf 'time_sync_observability=full\n'
else
  printf 'time_sync_observability=partial\n'
fi
printf 'date_begin\n'
date -u +%FT%TZ
date -u +%s
printf 'date_end\n'
printf 'timedatectl_begin\n'
if [[ "\$timedatectl_available" -eq 1 ]]; then
  printf '%s\n' "\$timedatectl_status_output"
  printf 'timedatectl_show_begin\n'
  printf '%s\n' "\$timedatectl_show_output"
  printf 'timedatectl_show_end\n'
  printf 'timedatectl_timesync_begin\n'
  printf '%s\n' "\$timedatectl_timesync_output"
  printf 'timedatectl_timesync_end\n'
else
  printf 'timedatectl_missing\n'
fi
printf 'timedatectl_end\n'
printf 'chronyc_begin\n'
if [[ "\$chronyc_available" -eq 1 ]]; then
  printf 'chronyc_tracking_begin\n'
  printf '%s\n' "\$chronyc_tracking_output"
  printf 'chronyc_tracking_end\n'
  printf 'chronyc_sources_begin\n'
  printf '%s\n' "\$chronyc_sources_output"
  printf 'chronyc_sources_end\n'
else
  printf 'chronyc_missing\n'
fi
printf 'chronyc_end\n'
printf 'ntpq_begin\n'
if [[ "\$ntpq_available" -eq 1 ]]; then
  printf '%s\n' "\$ntpq_output"
else
  printf 'ntpq_missing\n'
fi
printf 'ntpq_end\n'
printf 'timesync_service_begin\n'
printf '%s\n' "\$timesync_service_output"
printf 'timesync_service_end\n'
printf '__RNLAB_TIME_END__\n'
EOF
}

live_lab_collect_time_snapshot() {
  local target="$1"
  local node_id="${2:-}"
  local role="${3:-}"
  local reference_unix="${4:-$(date -u +%s)}"
  local max_clock_skew_secs="${5:-${CROSS_NETWORK_MAX_TIME_SKEW_SECS:-2}}"
  local snapshot
  snapshot="$(live_lab_capture_root "$target" "$(live_lab_time_snapshot_body "$reference_unix" "$max_clock_skew_secs")")" || return 1
  {
    printf 'time_target=%s\n' "$target"
    printf 'time_node_id=%s\n' "$node_id"
    printf 'time_role=%s\n' "$role"
    printf 'time_reference_unix=%s\n' "$reference_unix"
    printf 'time_max_clock_skew_secs=%s\n' "$max_clock_skew_secs"
    printf 'time_collected_at_utc=%s\n' "$(date -u +%FT%TZ)"
    printf '%s\n' "$snapshot"
  }
}

live_lab_process_snapshot_body() {
  cat <<'EOF'
process_snapshot_status=pass
ps_output="$(root ps -eo pid=,ppid=,user=,comm=,args= --sort=pid 2>/dev/null || ps -eo pid=,ppid=,user=,comm=,args= --sort=pid 2>/dev/null || true)"
count_matches() {
  awk 'NF { count++ } END { print count + 0 }'
}
unit_property() {
  local unit="$1"
  local property="$2"
  root systemctl show "$unit" --property="$property" --value 2>/dev/null || systemctl show "$unit" --property="$property" --value 2>/dev/null || true
}
daemon_matches="$(grep -E '(^|[[:space:]])rustynetd([[:space:]]|/).* daemon([[:space:]]|$)' <<<"$ps_output" || true)"
helper_matches="$(grep -E '(^|[[:space:]])rustynetd([[:space:]]|/).* privileged-helper([[:space:]]|$)' <<<"$ps_output" || true)"
managed_dns_matches="$(grep -E 'rustynetd-managed-dns' <<<"$ps_output" || true)"
resolved_matches="$(grep -E '(^|[[:space:]])systemd-resolve(d)?([[:space:]]|$)' <<<"$ps_output" || true)"
all_rustynetd_matches="$(grep -E '(^|[[:space:]])rustynetd([[:space:]]|$)' <<<"$ps_output" || true)"
daemon_process_count="$(printf '%s\n' "$daemon_matches" | count_matches)"
helper_process_count="$(printf '%s\n' "$helper_matches" | count_matches)"
managed_dns_process_count="$(printf '%s\n' "$managed_dns_matches" | count_matches)"
systemd_resolved_process_count="$(printf '%s\n' "$resolved_matches" | count_matches)"
unexpected_rustynetd_process_count=0
unexpected_rustynetd_matches=""
while IFS= read -r line; do
  [[ -n "$line" ]] || continue
  if [[ "$line" == *"rustynetd daemon"* || "$line" == *"rustynetd privileged-helper"* ]]; then
    continue
  fi
  unexpected_rustynetd_process_count=$((unexpected_rustynetd_process_count + 1))
  unexpected_rustynetd_matches+="${line}"$'\n'
done <<<"$all_rustynetd_matches"
rustynetd_active_state="$(unit_property rustynetd.service ActiveState)"
rustynetd_sub_state="$(unit_property rustynetd.service SubState)"
rustynetd_main_pid="$(unit_property rustynetd.service MainPID)"
helper_active_state="$(unit_property rustynetd-privileged-helper.service ActiveState)"
helper_sub_state="$(unit_property rustynetd-privileged-helper.service SubState)"
helper_main_pid="$(unit_property rustynetd-privileged-helper.service MainPID)"
managed_dns_active_state="$(unit_property rustynetd-managed-dns.service ActiveState)"
managed_dns_sub_state="$(unit_property rustynetd-managed-dns.service SubState)"
managed_dns_main_pid="$(unit_property rustynetd-managed-dns.service MainPID)"
systemd_resolved_active_state="$(unit_property systemd-resolved.service ActiveState)"
systemd_resolved_sub_state="$(unit_property systemd-resolved.service SubState)"
systemd_resolved_main_pid="$(unit_property systemd-resolved.service MainPID)"
if [[ "$daemon_process_count" != "1" || "$helper_process_count" != "1" || "$unexpected_rustynetd_process_count" != "0" ]]; then
  process_snapshot_status=fail
fi
if [[ "$rustynetd_active_state" != "active" || "$rustynetd_sub_state" != "running" ]]; then
  process_snapshot_status=fail
fi
if [[ "$helper_active_state" != "active" || "$helper_sub_state" != "running" ]]; then
  process_snapshot_status=fail
fi
if [[ "$managed_dns_active_state" != "active" || ( "$managed_dns_sub_state" != "exited" && "$managed_dns_sub_state" != "running" ) ]]; then
  process_snapshot_status=fail
fi
if [[ ! "$managed_dns_process_count" =~ ^[0-9]+$ || "$managed_dns_process_count" -ne 0 ]]; then
  process_snapshot_status=fail
fi
if [[ "$systemd_resolved_active_state" != "active" || ! "$systemd_resolved_process_count" =~ ^[0-9]+$ || "$systemd_resolved_process_count" -lt 1 ]]; then
  process_snapshot_status=fail
fi
printf '__RNLAB_PROCESS_BEGIN__\n'
printf 'process_snapshot_version=2\n'
printf 'daemon_process_count=%s\n' "$daemon_process_count"
printf 'helper_process_count=%s\n' "$helper_process_count"
printf 'managed_dns_process_count=%s\n' "$managed_dns_process_count"
printf 'systemd_resolved_process_count=%s\n' "$systemd_resolved_process_count"
printf 'unexpected_rustynetd_process_count=%s\n' "$unexpected_rustynetd_process_count"
printf 'rustynetd_active_state=%s\n' "$rustynetd_active_state"
printf 'rustynetd_sub_state=%s\n' "$rustynetd_sub_state"
printf 'rustynetd_main_pid=%s\n' "$rustynetd_main_pid"
printf 'helper_active_state=%s\n' "$helper_active_state"
printf 'helper_sub_state=%s\n' "$helper_sub_state"
printf 'helper_main_pid=%s\n' "$helper_main_pid"
printf 'managed_dns_active_state=%s\n' "$managed_dns_active_state"
printf 'managed_dns_sub_state=%s\n' "$managed_dns_sub_state"
printf 'managed_dns_main_pid=%s\n' "$managed_dns_main_pid"
printf 'systemd_resolved_active_state=%s\n' "$systemd_resolved_active_state"
printf 'systemd_resolved_sub_state=%s\n' "$systemd_resolved_sub_state"
printf 'systemd_resolved_main_pid=%s\n' "$systemd_resolved_main_pid"
printf 'process_snapshot_status=%s\n' "$process_snapshot_status"
printf 'daemon_matches_begin\n'
printf '%s\n' "$daemon_matches"
printf 'daemon_matches_end\n'
printf 'helper_matches_begin\n'
printf '%s\n' "$helper_matches"
printf 'helper_matches_end\n'
printf 'managed_dns_matches_begin\n'
printf '%s\n' "$managed_dns_matches"
printf 'managed_dns_matches_end\n'
printf 'systemd_resolved_matches_begin\n'
printf '%s\n' "$resolved_matches"
printf 'systemd_resolved_matches_end\n'
printf 'unexpected_rustynetd_matches_begin\n'
printf '%s\n' "$unexpected_rustynetd_matches"
printf 'unexpected_rustynetd_matches_end\n'
printf 'ps_begin\n'
printf '%s\n' "$ps_output"
printf 'ps_end\n'
printf 'pgrep_begin\n'
for pattern in \
  rustynetd \
  rustynetd-privileged-helper \
  rustynetd-managed-dns \
  systemd-timesyncd \
  chronyd \
  chrony \
  systemd-resolved \
  wg
do
  printf 'pattern=%s\n' "$pattern"
  root pgrep -af "$pattern" 2>/dev/null || pgrep -af "$pattern" 2>/dev/null || true
done
printf 'pgrep_end\n'
printf 'systemd_show_begin\n'
for unit in \
  rustynetd.service \
  rustynetd-privileged-helper.service \
  rustynetd-managed-dns.service \
  systemd-timesyncd.service \
  chronyd.service \
  chrony.service \
  systemd-resolved.service
do
  printf 'unit=%s\n' "$unit"
  root systemctl show "$unit" \
    --property=Id,LoadState,ActiveState,SubState,MainPID,ExecMainPID,FragmentPath,UnitFileState \
    2>/dev/null || systemctl show "$unit" \
    --property=Id,LoadState,ActiveState,SubState,MainPID,ExecMainPID,FragmentPath,UnitFileState \
    2>/dev/null || true
done
printf 'systemd_show_end\n'
printf 'cmdline_begin\n'
for pattern in \
  rustynetd \
  rustynetd-privileged-helper \
  rustynetd-managed-dns \
  systemd-timesyncd \
  chronyd \
  chrony \
  systemd-resolved \
  wg
do
  process_pids="$(root pgrep -f "$pattern" 2>/dev/null || pgrep -f "$pattern" 2>/dev/null || true)"
  for pid in $process_pids; do
    printf 'pattern=%s pid=%s\n' "$pattern" "$pid"
    root cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' || cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' || true
    printf '\n'
  done
done
printf 'cmdline_end\n'
printf '__RNLAB_PROCESS_END__\n'
EOF
}

live_lab_collect_process_snapshot() {
  local target="$1"
  local node_id="${2:-}"
  local role="${3:-}"
  local snapshot
  snapshot="$(live_lab_capture_root "$target" "$(live_lab_process_snapshot_body)")" || return 1
  {
    printf 'process_target=%s\n' "$target"
    printf 'process_node_id=%s\n' "$node_id"
    printf 'process_role=%s\n' "$role"
    printf 'process_collected_at_utc=%s\n' "$(date -u +%FT%TZ)"
    printf '%s\n' "$snapshot"
  }
}

live_lab_socket_snapshot_body() {
  cat <<'EOF'
socket_snapshot_status=pass
expected_daemon_socket=/run/rustynet/rustynetd.sock
expected_helper_socket=/run/rustynet/rustynetd-privileged.sock
expected_runtime_dir=/run/rustynet
expected_dns_bind_addr="${RUSTYNET_DNS_RESOLVER_BIND_ADDR:-127.0.0.1:53535}"
expected_wg_listen_port="${RUSTYNET_WG_LISTEN_PORT:-51820}"
expected_dns_host="${expected_dns_bind_addr%:*}"
expected_dns_port="${expected_dns_bind_addr##*:}"
tcp_listener_output="$(root ss -H -ltnp 2>/dev/null || ss -H -ltnp 2>/dev/null || true)"
udp_listener_output="$(root ss -H -lunp 2>/dev/null || ss -H -lunp 2>/dev/null || true)"
unix_listener_output="$(root ss -H -xlpn 2>/dev/null || ss -H -xlpn 2>/dev/null || true)"
runtime_socket_listing="$(root find /run/rustynet -maxdepth 1 -type s -name '*.sock' 2>/dev/null | sort || find /run/rustynet -maxdepth 1 -type s -name '*.sock' 2>/dev/null | sort || true)"
socket_fact() {
  local fact_name="$1"
  local path="$2"
  local stat_output mode owner group kind
  printf 'socket_fact_begin\n'
  printf 'name=%s\n' "$fact_name"
  printf 'path=%s\n' "$path"
  if root test -e "$path"; then
    stat_output="$(root stat -Lc '%a|%U|%G|%F' "$path" 2>/dev/null || stat -Lc '%a|%U|%G|%F' "$path" 2>/dev/null || true)"
    IFS='|' read -r mode owner group kind <<<"$stat_output"
    printf 'present=1\n'
    printf 'mode=%s\n' "$mode"
    printf 'owner=%s\n' "$owner"
    printf 'group=%s\n' "$group"
    printf 'type=%s\n' "$kind"
  else
    printf 'present=0\n'
  fi
  printf 'socket_fact_end\n'
}
daemon_socket_present=0
helper_socket_present=0
if root test -S "$expected_daemon_socket"; then
  daemon_socket_present=1
fi
if root test -S "$expected_helper_socket"; then
  helper_socket_present=1
fi
daemon_unix_listener_count="$(awk -v path="$expected_daemon_socket" 'index($0, path) { count++ } END { print count + 0 }' <<<"$unix_listener_output")"
helper_unix_listener_count="$(awk -v path="$expected_helper_socket" 'index($0, path) { count++ } END { print count + 0 }' <<<"$unix_listener_output")"
wireguard_udp_listener_count="$(awk -v suffix=":"expected_wg_listen_port '$4 ~ suffix"$" { count++ } END { print count + 0 }' <<<"$udp_listener_output")"
dns_udp_loopback_listener_count="$(awk -v port=":"expected_dns_port '($4 ~ port"$") && ($4 ~ /^127\.0\.0\.1:/ || $4 ~ /^\[::1\]:/) { count++ } END { print count + 0 }' <<<"$udp_listener_output")"
dns_udp_nonloopback_listener_count="$(awk -v port=":"expected_dns_port '($4 ~ port"$") && $4 !~ /^127\.0\.0\.1:/ && $4 !~ /^\[::1\]:/ { count++ } END { print count + 0 }' <<<"$udp_listener_output")"
dns_tcp_listener_count="$(awk -v port=":"expected_dns_port '$4 ~ port"$" { count++ } END { print count + 0 }' <<<"$tcp_listener_output")"
unexpected_runtime_socket_count=0
unexpected_runtime_sockets=""
while IFS= read -r socket_path; do
  [[ -n "$socket_path" ]] || continue
  case "$socket_path" in
    "$expected_daemon_socket"|"$expected_helper_socket")
      ;;
    *)
      unexpected_runtime_socket_count=$((unexpected_runtime_socket_count + 1))
      unexpected_runtime_sockets+="${socket_path}"$'\n'
      ;;
  esac
done <<<"$runtime_socket_listing"
if [[ "$daemon_socket_present" != "1" || "$helper_socket_present" != "1" ]]; then
  socket_snapshot_status=fail
fi
if [[ "$daemon_unix_listener_count" != "1" || "$helper_unix_listener_count" != "1" ]]; then
  socket_snapshot_status=fail
fi
if [[ "$wireguard_udp_listener_count" != "1" || "$dns_udp_loopback_listener_count" != "1" ]]; then
  socket_snapshot_status=fail
fi
if [[ "$dns_udp_nonloopback_listener_count" != "0" || "$dns_tcp_listener_count" != "0" || "$unexpected_runtime_socket_count" != "0" ]]; then
  socket_snapshot_status=fail
fi
printf '__RNLAB_SOCKET_BEGIN__\n'
printf 'socket_snapshot_version=2\n'
printf 'expected_daemon_socket=%s\n' "$expected_daemon_socket"
printf 'expected_helper_socket=%s\n' "$expected_helper_socket"
printf 'expected_runtime_dir=%s\n' "$expected_runtime_dir"
printf 'expected_dns_bind_addr=%s\n' "$expected_dns_bind_addr"
printf 'expected_wg_listen_port=%s\n' "$expected_wg_listen_port"
printf 'daemon_socket_present=%s\n' "$daemon_socket_present"
printf 'helper_socket_present=%s\n' "$helper_socket_present"
printf 'daemon_unix_listener_count=%s\n' "$daemon_unix_listener_count"
printf 'helper_unix_listener_count=%s\n' "$helper_unix_listener_count"
printf 'wireguard_udp_listener_count=%s\n' "$wireguard_udp_listener_count"
printf 'dns_udp_loopback_listener_count=%s\n' "$dns_udp_loopback_listener_count"
printf 'dns_udp_nonloopback_listener_count=%s\n' "$dns_udp_nonloopback_listener_count"
printf 'dns_tcp_listener_count=%s\n' "$dns_tcp_listener_count"
printf 'unexpected_runtime_socket_count=%s\n' "$unexpected_runtime_socket_count"
printf 'socket_snapshot_status=%s\n' "$socket_snapshot_status"
socket_fact daemon_socket "$expected_daemon_socket"
socket_fact helper_socket "$expected_helper_socket"
socket_fact runtime_dir "$expected_runtime_dir"
printf 'runtime_socket_listing_begin\n'
printf '%s\n' "$runtime_socket_listing"
printf 'runtime_socket_listing_end\n'
printf 'unexpected_runtime_sockets_begin\n'
printf '%s\n' "$unexpected_runtime_sockets"
printf 'unexpected_runtime_sockets_end\n'
printf 'listen_tcp_begin\n'
printf '%s\n' "$tcp_listener_output"
printf 'listen_tcp_end\n'
printf 'listen_udp_begin\n'
printf '%s\n' "$udp_listener_output"
printf 'listen_udp_end\n'
printf 'listen_unix_begin\n'
printf '%s\n' "$unix_listener_output"
printf 'listen_unix_end\n'
printf '__RNLAB_SOCKET_END__\n'
EOF
}

live_lab_collect_socket_snapshot() {
  local target="$1"
  local node_id="${2:-}"
  local role="${3:-}"
  local snapshot
  snapshot="$(live_lab_capture_root "$target" "$(live_lab_socket_snapshot_body)")" || return 1
  {
    printf 'socket_target=%s\n' "$target"
    printf 'socket_node_id=%s\n' "$node_id"
    printf 'socket_role=%s\n' "$role"
    printf 'socket_collected_at_utc=%s\n' "$(date -u +%FT%TZ)"
    printf '%s\n' "$snapshot"
  }
}

live_lab_permissions_snapshot_body() {
  cat <<'EOF'
permissions_snapshot_status=pass
emit_permissions_fact() {
  local fact_kind="$1"
  local path="$2"
  local stat_output mode owner group kind
  printf 'permissions_fact_begin\n'
  printf 'fact_kind=%s\n' "$fact_kind"
  printf 'path=%s\n' "$path"
  if root test -e "$path"; then
    stat_output="$(root stat -Lc '%a|%U|%G|%F' "$path" 2>/dev/null || stat -Lc '%a|%U|%G|%F' "$path" 2>/dev/null || true)"
    IFS='|' read -r mode owner group kind <<<"$stat_output"
    printf 'present=1\n'
    printf 'mode=%s\n' "$mode"
    printf 'owner=%s\n' "$owner"
    printf 'group=%s\n' "$group"
    printf 'type=%s\n' "$kind"
  else
    printf 'present=0\n'
    if [[ "$fact_kind" == "required" ]]; then
      permissions_snapshot_status=fail
    fi
  fi
  printf 'permissions_fact_end\n'
}
printf '__RNLAB_PERMISSIONS_BEGIN__\n'
printf 'permissions_snapshot_version=2\n'
required_paths=(
  /etc/rustynet
  /etc/rustynet/credentials
  /var/lib/rustynet
  /run/rustynet
  /var/lib/rustynet/keys
  /etc/rustynet/credentials/wg_key_passphrase.cred
  /etc/rustynet/credentials/signing_key_passphrase.cred
  /var/lib/rustynet/keys/wireguard.key.enc
  /run/rustynet/wireguard.key
  /var/lib/rustynet/keys/wireguard.pub
  /var/lib/rustynet/membership.snapshot
  /var/lib/rustynet/membership.log
  /var/lib/rustynet/membership.watermark
  /etc/rustynet/assignment.pub
  /etc/rustynet/traversal.pub
  /etc/rustynet/trust-evidence.pub
  /etc/rustynet/dns-zone.pub
  /etc/rustynet/assignment-refresh.env
  /var/lib/rustynet/rustynetd.assignment
  /var/lib/rustynet/rustynetd.assignment.watermark
  /var/lib/rustynet/rustynetd.traversal
  /var/lib/rustynet/rustynetd.traversal.watermark
  /var/lib/rustynet/rustynetd.trust
  /var/lib/rustynet/rustynetd.trust.watermark
  /var/lib/rustynet/rustynetd.dns-zone
  /var/lib/rustynet/rustynetd.dns-zone.watermark
)
conditional_secret_paths=(
  /etc/rustynet/assignment.signing.secret
  /etc/rustynet/trust-evidence.key
)
forbidden_plaintext_paths=(
  /var/lib/rustynet/keys/wireguard.passphrase
  /etc/rustynet/wireguard.passphrase
  /etc/rustynet/signing_key_passphrase
)
printf 'required_path_count=%s\n' "${#required_paths[@]}"
for path in "${required_paths[@]}"; do
  emit_permissions_fact required "$path"
done
printf 'conditional_secret_path_count=%s\n' "${#conditional_secret_paths[@]}"
for path in "${conditional_secret_paths[@]}"; do
  emit_permissions_fact conditional_secret "$path"
done
printf 'forbidden_plaintext_path_count=%s\n' "${#forbidden_plaintext_paths[@]}"
for path in "${forbidden_plaintext_paths[@]}"; do
  emit_permissions_fact forbidden_plaintext "$path"
  if root test -e "$path"; then
    permissions_snapshot_status=fail
  fi
done
printf 'permissions_snapshot_status=%s\n' "$permissions_snapshot_status"
printf '__RNLAB_PERMISSIONS_END__\n'
EOF
}

live_lab_collect_permissions_snapshot() {
  local target="$1"
  local node_id="${2:-}"
  local role="${3:-}"
  local snapshot
  snapshot="$(live_lab_capture_root "$target" "$(live_lab_permissions_snapshot_body)")" || return 1
  {
    printf 'permissions_target=%s\n' "$target"
    printf 'permissions_node_id=%s\n' "$node_id"
    printf 'permissions_role=%s\n' "$role"
    printf 'permissions_collected_at_utc=%s\n' "$(date -u +%FT%TZ)"
    printf '%s\n' "$snapshot"
  }
}

live_lab_peer_inventory_snapshot_body() {
  local discovery_script_path="$1"
  local quoted_discovery_script_path
  quoted_discovery_script_path="$(live_lab_shell_quote "$discovery_script_path")"
  cat <<EOF
overall_status=pass
last_step_rc=0
run_step() {
  local step_name="\$1"
  shift
  local rc=0
  printf '%s_begin\n' "\$step_name"
  if "\$@"; then
    rc=0
  else
    rc=\$?
    overall_status=fail
  fi
  last_step_rc="\$rc"
  printf '%s_rc=%s\n' "\$step_name" "\$rc"
  printf '%s_end\n' "\$step_name"
}
printf '__RNLAB_PEER_INVENTORY_BEGIN__\n'
printf 'peer_inventory_version=1\n'
printf 'peer_inventory_source=collect_network_discovery_info.sh\n'
run_step discovery_bundle root bash $quoted_discovery_script_path --quiet
printf 'peer_inventory_health=%s\n' "\$overall_status"
printf 'peer_inventory_status=%s\n' "\$overall_status"
printf '__RNLAB_PEER_INVENTORY_END__\n'
EOF
}

live_lab_collect_peer_inventory_snapshot() {
  local target="$1"
  local node_id="$2"
  local role="${3:-}"
  local remote_src discovery_script_path snapshot
  remote_src="$(live_lab_remote_src_dir "$target")"
  discovery_script_path="${remote_src}/scripts/operations/collect_network_discovery_info.sh"
  snapshot="$(live_lab_capture_root "$target" "$(live_lab_peer_inventory_snapshot_body "$discovery_script_path")")" || return 1
  {
    printf 'peer_inventory_target=%s\n' "$target"
    printf 'peer_inventory_node_id=%s\n' "$node_id"
    printf 'peer_inventory_role=%s\n' "$role"
    printf 'peer_inventory_collected_at_utc=%s\n' "$(date -u +%FT%TZ)"
    printf '%s\n' "$snapshot"
  }
}

live_lab_firewall_snapshot_body() {
  cat <<'EOF'
overall_status=pass
last_step_rc=0
run_step() {
  local step_name="$1"
  shift
  local rc=0
  printf '%s_begin\n' "$step_name"
  if "$@"; then
    rc=0
  else
    rc=$?
    overall_status=fail
  fi
  last_step_rc="$rc"
  printf '%s_rc=%s\n' "$step_name" "$rc"
  printf '%s_end\n' "$step_name"
}
printf '__RNLAB_FIREWALL_BEGIN__\n'
printf 'firewall_snapshot_version=1\n'
run_step nft_tables root nft list tables
run_step nft_ruleset root nft list ruleset
printf 'firewall_health=%s\n' "$overall_status"
printf 'firewall_status=%s\n' "$overall_status"
printf '__RNLAB_FIREWALL_END__\n'
EOF
}

live_lab_collect_firewall_snapshot() {
  local target="$1"
  local node_id="$2"
  local role="${3:-}"
  local snapshot
  snapshot="$(live_lab_capture_root "$target" "$(live_lab_firewall_snapshot_body)")" || return 1
  {
    printf 'firewall_target=%s\n' "$target"
    printf 'firewall_node_id=%s\n' "$node_id"
    printf 'firewall_role=%s\n' "$role"
    printf 'firewall_collected_at_utc=%s\n' "$(date -u +%FT%TZ)"
    printf '%s\n' "$snapshot"
  }
}

live_lab_collect_route_policy() {
  local target="$1"
  local destination="${2:-1.1.1.1}"
  local expected_next_hop="${3:-}"
  local snapshot
  snapshot="$(live_lab_capture_root "$target" "$(live_lab_route_policy_snapshot_body "$destination" "$expected_next_hop")")" || return 1
  {
    printf 'route_policy_target=%s\n' "$target"
    printf 'route_policy_collected_at_utc=%s\n' "$(date -u +%FT%TZ)"
    printf '%s\n' "$snapshot"
  }
}

live_lab_collect_dns_state() {
  live_lab_collect_dns_snapshot "$@"
}

live_lab_collect_node_snapshot() {
  local target="$1"
  local node_id="$2"
  local role="$3"
  local body snapshot
  local expected_next_hop=""
  local reference_unix
  local max_clock_skew_secs="${CROSS_NETWORK_MAX_TIME_SKEW_SECS:-2}"
  if [[ "$role" == "client" ]]; then
    expected_next_hop="direct:rustynet0"
  fi
  reference_unix="$(date -u +%s)"
  body="$(printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s' \
    "$(live_lab_service_snapshot_body)" \
    "$(live_lab_network_snapshot_body)" \
    "$(live_lab_time_snapshot_body "$reference_unix" "$max_clock_skew_secs")" \
    "$(live_lab_process_snapshot_body)" \
    "$(live_lab_socket_snapshot_body)" \
    "$(live_lab_permissions_snapshot_body)" \
    "$(live_lab_route_policy_snapshot_body "1.1.1.1" "$expected_next_hop")" \
    "$(live_lab_dns_state_snapshot_body)" \
    "$(live_lab_firewall_snapshot_body)" \
    "$(live_lab_dns_zone_snapshot_body "$node_id")" \
    "$(live_lab_signed_state_snapshot_body "$node_id")" \
    "$(live_lab_secret_hygiene_snapshot_body)")"
  snapshot="$(live_lab_capture_root "$target" "$body")" || return 1
  {
    printf 'node_snapshot_version=1\n'
    printf 'target=%s\n' "$target"
    printf 'node_id=%s\n' "$node_id"
    printf 'role=%s\n' "$role"
    printf 'collected_at_utc=%s\n' "$(date -u +%FT%TZ)"
    printf '%s\n' "$snapshot"
  }
}

live_lab_collect_runtime_validation_snapshot() {
  local target="$1"
  local node_id="$2"
  local role="$3"
  local body snapshot
  local expected_next_hop=""
  if [[ "$role" == "client" ]]; then
    expected_next_hop="direct:rustynet0"
  fi
  # Keep the runtime convergence snapshot small on the UTM path.
  # Signed-state and DNS-zone convergence are validated separately by
  # dedicated collectors before baseline runtime sampling begins.
  body="$(printf '%s\n%s\n%s\n' \
    "$(live_lab_status_snapshot_body)" \
    "$(live_lab_route_policy_snapshot_body "1.1.1.1" "$expected_next_hop")" \
    "$(live_lab_secret_hygiene_snapshot_body)")"
  snapshot="$(live_lab_capture_root "$target" "$body")" || return 1
  {
    printf 'node_snapshot_version=1\n'
    printf 'target=%s\n' "$target"
    printf 'node_id=%s\n' "$node_id"
    printf 'role=%s\n' "$role"
    printf 'collected_at_utc=%s\n' "$(date -u +%FT%TZ)"
    printf '%s\n' "$snapshot"
  }
}

live_lab_no_plaintext_passphrase_check() {
  local target="$1"
  local hygiene
  hygiene="$(live_lab_collect_secret_hygiene "$target")" || return 1
  if [[ "$hygiene" == *"result=no-plaintext-passphrase-files"* ]]; then
    printf 'no-plaintext-passphrase-files\n'
    return 0
  fi
  printf '%s\n' "$hygiene"
  return 1
}
