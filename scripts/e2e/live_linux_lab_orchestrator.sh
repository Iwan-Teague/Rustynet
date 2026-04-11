#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

source "$ROOT_DIR/scripts/e2e/live_lab_common.sh"

SCRIPT_NAME="$(basename "$0")"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_STARTED_AT_UNIX="$(date +%s)"
RUN_STARTED_AT_LOCAL="$(date '+%Y-%m-%d %H:%M:%S %Z')"
RUN_STARTED_AT_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
NETWORK_ID="rn-live-lab-${RUN_ID}"
SSH_ALLOW_CIDRS="192.168.18.0/24"
REPO_REF="HEAD"
SOURCE_MODE="local-head"
RUSTYNET_BACKEND="${RUSTYNET_BACKEND:-}"
REPORT_DIR="${ROOT_DIR}/artifacts/live_lab/${RUN_ID}"
LOG_DIR="${REPORT_DIR}/logs"
VERIFICATION_DIR="${REPORT_DIR}/verification"
STATE_DIR="${REPORT_DIR}/state"
SUMMARY_JSON="${REPORT_DIR}/run_summary.json"
SUMMARY_MD="${REPORT_DIR}/run_summary.md"
FAILURE_DIGEST_JSON="${REPORT_DIR}/failure_digest.json"
FAILURE_DIGEST_MD="${REPORT_DIR}/failure_digest.md"
STAGE_TSV="${STATE_DIR}/stages.tsv"
NODES_TSV="${STATE_DIR}/nodes.tsv"
SOURCE_ARCHIVE="${STATE_DIR}/rustynet-source.tar.gz"
PUBKEYS_TSV="${STATE_DIR}/pubkeys.tsv"
ONEHOP_STATE_ENV="${STATE_DIR}/onehop_state.env"
SOAK_HARD_FAIL=0
RUN_LOCAL_GATES=1
RUN_SOAK=1
DRY_RUN=0
SETUP_ONLY=0
SKIP_SETUP=0
PRESERVE_REPORT_STATE=0
RESUME_FROM_STAGE=""
RERUN_STAGE=""
MAX_PARALLEL_NODE_WORKERS="${MAX_PARALLEL_NODE_WORKERS:-2}"
CROSS_NETWORK_MODE="auto"
CROSS_NETWORK_SKIP_REASON=""
OVERALL_STATUS="pass"
FAILURE_COUNT=0
SOFT_FAILURE_COUNT=0
SSH_IDENTITY_FILE=""
SSH_KNOWN_HOSTS_FILE=""
EXIT_TARGET=""
CLIENT_TARGET=""
ENTRY_TARGET=""
AUX_TARGET=""
EXTRA_TARGET=""
FIFTH_CLIENT_TARGET=""
EXIT_UTM_NAME=""
CLIENT_UTM_NAME=""
ENTRY_UTM_NAME=""
AUX_UTM_NAME=""
EXTRA_UTM_NAME=""
FIFTH_CLIENT_UTM_NAME=""
ENTRY_TARGET_DECLARED=0
AUX_TARGET_DECLARED=0
EXTRA_TARGET_DECLARED=0
FIFTH_CLIENT_TARGET_DECLARED=0
PROFILE_PATH=""
DEFAULT_PROFILE_PATH="${ROOT_DIR}/profiles/live_lab/default_four_node.env"
SOURCE_MODE_EXPLICIT=0
TRAVERSAL_TTL_SECS=120
MANAGED_DNS_FATAL_PATTERN_1='rustynetd-managed-dns\.service failed to reach active state'
MANAGED_DNS_FATAL_PATTERN_2='command failed \(systemctl restart rustynetd-managed-dns\.service\)'
MANAGED_DNS_FATAL_PATTERN_3='Job for rustynetd-managed-dns\.service canceled'
CROSS_NETWORK_NAT_PROFILES="${RUSTYNET_CROSS_NETWORK_NAT_PROFILES:-baseline_lan}"
CROSS_NETWORK_REQUIRED_NAT_PROFILES="${RUSTYNET_CROSS_NETWORK_REQUIRED_NAT_PROFILES:-}"
CROSS_NETWORK_IMPAIRMENT_PROFILE="${RUSTYNET_CROSS_NETWORK_IMPAIRMENT_PROFILE:-none}"
CROSS_NETWORK_MAX_TIME_SKEW_SECS="${RUSTYNET_CROSS_NETWORK_MAX_TIME_SKEW_SECS:-2}"
CROSS_NETWORK_DISCOVERY_MAX_AGE_SECS="${RUSTYNET_CROSS_NETWORK_DISCOVERY_MAX_AGE_SECS:-900}"
CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS="${RUSTYNET_CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS:-900}"
CROSS_NETWORK_CLIENT_UNDERLAY_IP="${RUSTYNET_CROSS_NETWORK_CLIENT_UNDERLAY_IP:-}"
CROSS_NETWORK_EXIT_UNDERLAY_IP="${RUSTYNET_CROSS_NETWORK_EXIT_UNDERLAY_IP:-}"
CROSS_NETWORK_RELAY_UNDERLAY_IP="${RUSTYNET_CROSS_NETWORK_RELAY_UNDERLAY_IP:-}"
CROSS_NETWORK_PROBE_UNDERLAY_IP="${RUSTYNET_CROSS_NETWORK_PROBE_UNDERLAY_IP:-}"
CROSS_NETWORK_NAT_PROFILE_LIST=()
CROSS_NETWORK_REQUIRED_NAT_PROFILE_LIST=()

sanitize_text() {
  printf '%s' "$1" | tr '\t\r\n' '   '
}

format_elapsed_duration() {
  local total_secs="${1:-0}"
  local days hours minutes seconds
  if (( total_secs < 0 )); then
    total_secs=0
  fi
  days=$((total_secs / 86400))
  hours=$(((total_secs % 86400) / 3600))
  minutes=$(((total_secs % 3600) / 60))
  seconds=$((total_secs % 60))
  if (( days > 0 )); then
    printf '%dd %02dh %02dm %02ds' "$days" "$hours" "$minutes" "$seconds"
  elif (( hours > 0 )); then
    printf '%02dh %02dm %02ds' "$hours" "$minutes" "$seconds"
  else
    printf '%02dm %02ds' "$minutes" "$seconds"
  fi
}

usage() {
  cat <<USAGE
usage: ${SCRIPT_NAME} [options]

Interactive by default. If any required target/input is missing, the script prompts.
Interactive source selection now also supports:
  - use local committed HEAD (default), or
  - update from latest git and pick a branch from a numbered list

options:
  --profile <path>               Load saved lab profile (.env-style)
  --source-mode <mode>           Source mode: working-tree | local-head | origin-main
  --use-origin-main              Fetch and archive latest committed origin/main
  --use-local-head               Archive local committed HEAD (default)
  --exit-target <user@host|host>     Primary exit node target
  --client-target <user@host|host>   Primary client node target
  --entry-target <user@host|host>    Entry relay / alternate exit target
  --aux-target <user@host|host>      Auxiliary client / blind-exit target
  --extra-target <user@host|host>    Optional extra client target
  --fifth-client-target <user@host|host>
                                Optional fifth client target for six-node live labs
  --ssh-identity-file <path>     SSH private key for key-based authentication
  --ssh-password-file <path>     REMOVED. Use --ssh-identity-file for key auth.
  --sudo-password-file <path>    REMOVED. Password files are not accepted here.
  --ssh-known-hosts-file <path>  Pinned SSH known_hosts file (defaults to ~/.ssh/known_hosts)
  --network-id <id>              Override generated network ID
  --ssh-allow-cidrs <cidrs>      SSH management CIDRs (default: ${SSH_ALLOW_CIDRS})
  --repo-ref <ref>               Explicit git ref to archive (implies source-mode=ref)
  --report-dir <path>            Override report output directory
  --setup-only                   Run only the preflight + baseline setup stages
  --skip-setup                   Skip preflight + baseline setup stages and run follow-on tests only
  --preserve-report-state        Reuse an existing report dir instead of truncating stage state
  --resume-from <stage>          Resume the setup stage sequence from a specific setup stage
  --rerun-stage <stage>          Rerun one setup stage in an existing report dir
  --max-parallel-node-workers <n>
                                Cap concurrent parallel worker fan-out (default: ${MAX_PARALLEL_NODE_WORKERS})
  --traversal-ttl-secs <secs>    Signed traversal bundle TTL for issued lab bundles (1-120, default: ${TRAVERSAL_TTL_SECS})
  --skip-gates                   Skip local full gate suite
  --skip-soak                    Skip extended soak/reboot stages
  --skip-cross-network           Skip cross-network validator stages
  --force-cross-network          Force cross-network validator stages even on same-prefix underlay targets
  --cross-network-nat-profiles <csv>
                                 Cross-network NAT profile matrix to execute (default: ${CROSS_NETWORK_NAT_PROFILES})
  --cross-network-required-nat-profiles <csv>
                                 NAT profiles that must be present for matrix pass (default: same as --cross-network-nat-profiles)
  --cross-network-impairment-profile <profile>
                                 Deterministic stage-scoped impairment profile: none | latency_50ms_loss_1pct | latency_120ms_loss_3pct | loss_5pct (default: ${CROSS_NETWORK_IMPAIRMENT_PROFILE})
  --cross-network-max-time-skew-secs <secs>
                                 Maximum allowed host clock skew before cross-network validators run (default: ${CROSS_NETWORK_MAX_TIME_SKEW_SECS})
  --cross-network-discovery-max-age-secs <secs>
                                 Maximum allowed age for discovery bundles generated during preflight (default: ${CROSS_NETWORK_DISCOVERY_MAX_AGE_SECS})
  --cross-network-signed-artifact-max-age-secs <secs>
                                 Maximum allowed age for signed runtime artifacts in preflight (default: ${CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS})
  --cross-network-client-underlay-ip <ipv4>
                                 Override client underlay endpoint/topology IP for cross-network validators
  --cross-network-exit-underlay-ip <ipv4>
                                 Override exit underlay endpoint/topology IP for cross-network validators
  --cross-network-relay-underlay-ip <ipv4>
                                 Override relay underlay endpoint/topology IP for cross-network validators
  --cross-network-probe-underlay-ip <ipv4>
                                 Override probe underlay endpoint/topology IP for cross-network validators
  --reboot-hard-fail             Deprecated: extended soak is hard-fail by default
  --dry-run                      Validate config and planned stages without touching hosts
  -h, --help                     Show this help
USAGE
}

prompt_value() {
  local prompt="$1"
  local default_value="${2:-}"
  local reply
  if [[ -n "$default_value" ]]; then
    printf '%s [%s]: ' "$prompt" "$default_value" >&2
  else
    printf '%s: ' "$prompt" >&2
  fi
  read -r reply
  if [[ -z "$reply" ]]; then
    reply="$default_value"
  fi
  printf '%s' "$reply"
}

prompt_secret() {
  local prompt="$1"
  local reply
  printf '%s: ' "$prompt" >&2
  read -r -s reply
  printf '\n' >&2
  printf '%s' "$reply"
}

prompt_yes_no() {
  local prompt="$1"
  local default_answer="${2:-y}"
  local suffix='[y/N]'
  local reply=""
  if [[ "$default_answer" == "y" || "$default_answer" == "Y" ]]; then
    suffix='[Y/n]'
  fi
  while true; do
    printf '%s %s: ' "$prompt" "$suffix" >&2
    read -r reply
    reply="$(trim_ascii "$reply")"
    if [[ -z "$reply" ]]; then
      reply="$default_answer"
    fi
    case "$reply" in
      y|Y|yes|YES|Yes) return 0 ;;
      n|N|no|NO|No) return 1 ;;
      *) printf 'please answer yes or no\n' >&2 ;;
    esac
  done
}

prompt_with_default() {
  local prompt="$1"
  local default_value="${2:-}"
  local reply=""
  if [[ -n "$default_value" ]]; then
    printf '%s [%s]: ' "$prompt" "$default_value" >&2
  else
    printf '%s: ' "$prompt" >&2
  fi
  read -r reply
  reply="$(trim_ascii "$reply")"
  if [[ -z "$reply" ]]; then
    reply="$default_value"
  fi
  printf '%s' "$reply"
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    printf 'missing required command: %s\n' "$cmd" >&2
    return 1
  fi
}

trim_ascii() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

validate_positive_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value <= 0 )); then
    printf '%s must be a positive integer (got: %s)\n' "$name" "$value" >&2
    return 1
  fi
}

is_valid_profile_label() {
  local value="$1"
  [[ "$value" =~ ^[A-Za-z0-9._-]+$ ]]
}

is_supported_impairment_profile() {
  local value="$1"
  case "$value" in
    none|latency_50ms_loss_1pct|latency_120ms_loss_3pct|loss_5pct) return 0 ;;
    *) return 1 ;;
  esac
}

parse_profile_csv_to_array() {
  local raw="$1"
  local target_array_name="$2"
  local item trimmed existing duplicate
  local -a items=()
  local -a parsed=()
  IFS=',' read -r -a items <<< "$raw"
  for item in "${items[@]-}"; do
    trimmed="$(trim_ascii "$item")"
    [[ -n "$trimmed" ]] || continue
    if ! is_valid_profile_label "$trimmed"; then
      printf 'invalid profile label: %s\n' "$trimmed" >&2
      return 1
    fi
    duplicate=0
    for existing in "${parsed[@]-}"; do
      if [[ "$existing" == "$trimmed" ]]; then
        duplicate=1
        break
      fi
    done
    [[ "$duplicate" -eq 1 ]] && continue
    parsed+=("$trimmed")
  done
  if [[ "${#parsed[@]}" -eq 0 ]]; then
    printf 'profile list must include at least one non-empty label\n' >&2
    return 1
  fi
  case "$target_array_name" in
    CROSS_NETWORK_NAT_PROFILE_LIST)
      CROSS_NETWORK_NAT_PROFILE_LIST=("${parsed[@]}")
      ;;
    CROSS_NETWORK_REQUIRED_NAT_PROFILE_LIST)
      CROSS_NETWORK_REQUIRED_NAT_PROFILE_LIST=("${parsed[@]}")
      ;;
    *)
      printf 'unsupported profile array target: %s\n' "$target_array_name" >&2
      return 1
      ;;
  esac
}

join_csv() {
  local IFS=','
  printf '%s' "$*"
}

derive_ipv4_cidr_24() {
  local address="$1"
  if [[ "$address" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.[0-9]{1,3}$ ]]; then
    printf '%s.%s.%s.0/24' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
    return 0
  fi
  return 1
}

auto_adjust_default_ssh_allow_cidrs_for_targets() {
  local legacy_default="192.168.18.0/24"
  local target address cidr existing duplicate
  local -a derived=()
  if [[ "$SSH_ALLOW_CIDRS" != "$legacy_default" ]]; then
    return 0
  fi
  for target in "$EXIT_TARGET" "$CLIENT_TARGET" "$ENTRY_TARGET" "$AUX_TARGET" "$EXTRA_TARGET" "$FIFTH_CLIENT_TARGET"; do
    [[ -n "$target" ]] || continue
    address="$(live_lab_resolved_target_address "$target")"
    if ! cidr="$(derive_ipv4_cidr_24 "$address")"; then
      # Keep explicit/default value unchanged for non-IPv4 targets.
      return 0
    fi
    duplicate=0
    for existing in "${derived[@]-}"; do
      if [[ "$existing" == "$cidr" ]]; then
        duplicate=1
        break
      fi
    done
    if [[ "$duplicate" -eq 0 ]]; then
      derived+=("$cidr")
    fi
  done
  if [[ "${#derived[@]}" -gt 0 ]]; then
    SSH_ALLOW_CIDRS="$(join_csv "${derived[@]}")"
    if [[ "$SSH_ALLOW_CIDRS" != "$legacy_default" ]]; then
      printf 'auto-adjusted SSH allow CIDRs from %s to %s based on target underlay addresses\n' \
        "$legacy_default" "$SSH_ALLOW_CIDRS"
    fi
  fi
}

prepare_cross_network_profile_config() {
  parse_profile_csv_to_array "$CROSS_NETWORK_NAT_PROFILES" CROSS_NETWORK_NAT_PROFILE_LIST || return 1
  if [[ -z "$CROSS_NETWORK_REQUIRED_NAT_PROFILES" ]]; then
    CROSS_NETWORK_REQUIRED_NAT_PROFILES="$(join_csv "${CROSS_NETWORK_NAT_PROFILE_LIST[@]}")"
  fi
  parse_profile_csv_to_array "$CROSS_NETWORK_REQUIRED_NAT_PROFILES" CROSS_NETWORK_REQUIRED_NAT_PROFILE_LIST || return 1
  if [[ -z "$CROSS_NETWORK_IMPAIRMENT_PROFILE" ]]; then
    printf 'cross-network impairment profile must be non-empty\n' >&2
    return 1
  fi
  if ! is_valid_profile_label "$CROSS_NETWORK_IMPAIRMENT_PROFILE"; then
    printf 'invalid cross-network impairment profile: %s\n' "$CROSS_NETWORK_IMPAIRMENT_PROFILE" >&2
    return 1
  fi
  if ! is_supported_impairment_profile "$CROSS_NETWORK_IMPAIRMENT_PROFILE"; then
    printf 'unsupported cross-network impairment profile: %s (supported: none, latency_50ms_loss_1pct, latency_120ms_loss_3pct, loss_5pct)\n' "$CROSS_NETWORK_IMPAIRMENT_PROFILE" >&2
    return 1
  fi
  local required profile found
  for required in "${CROSS_NETWORK_REQUIRED_NAT_PROFILE_LIST[@]}"; do
    found=0
    for profile in "${CROSS_NETWORK_NAT_PROFILE_LIST[@]}"; do
      if [[ "$profile" == "$required" ]]; then
        found=1
        break
      fi
    done
    if [[ "$found" -eq 0 ]]; then
      printf 'required NAT profile %s is not present in configured cross-network NAT profiles (%s)\n' \
        "$required" "$CROSS_NETWORK_NAT_PROFILES" >&2
      return 1
    fi
  done
}

cross_network_stage_suffix_for_profile_index() {
  local index="$1"
  local profile="$2"
  if [[ "$index" -eq 0 ]]; then
    printf ''
  else
    printf '_%s' "$profile"
  fi
}

cross_network_report_path_for_profile() {
  local base_name="$1"
  local index="$2"
  local profile="$3"
  if [[ "$index" -eq 0 ]]; then
    printf '%s/%s' "$REPORT_DIR" "$base_name"
  else
    local stem="${base_name%.json}"
    printf '%s/%s_%s.json' "$REPORT_DIR" "$stem" "$profile"
  fi
}

cross_network_log_path_for_profile() {
  local base_name="$1"
  local index="$2"
  local profile="$3"
  if [[ "$index" -eq 0 ]]; then
    printf '%s/%s' "$REPORT_DIR" "$base_name"
  else
    local stem="${base_name%.log}"
    printf '%s/%s_%s.log' "$REPORT_DIR" "$stem" "$profile"
  fi
}

is_valid_ipv4() {
  local ip="$1"
  local octet
  local IFS='.'
  read -r -a octets <<< "$ip"
  [[ ${#octets[@]} -eq 4 ]] || return 1
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^[0-9]{1,3}$ ]] || return 1
    ((octet >= 0 && octet <= 255)) || return 1
  done
}

host_part_from_target() {
  local target="$1"
  if [[ "$target" == *"@"* ]]; then
    printf '%s' "${target#*@}"
  else
    printf '%s' "$target"
  fi
}

validate_target_host() {
  local label="$1"
  local target="$2"
  local host
  host="$(host_part_from_target "$target")"
  if [[ -z "$host" ]]; then
    printf 'missing host for %s target\n' "$label" >&2
    return 1
  fi
  if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    if ! is_valid_ipv4 "$host"; then
      printf 'invalid IPv4 address for %s target: %s\n' "$label" "$host" >&2
      return 1
    fi
    return 0
  fi
  if [[ "$host" == *:* ]]; then
    if [[ "$host" =~ ^[0-9A-Fa-f:]+$ ]]; then
      return 0
    fi
    printf 'invalid IPv6 address for %s target: %s\n' "$label" "$host" >&2
    return 1
  fi
  if [[ ! "$host" =~ ^[A-Za-z0-9._-]+$ ]]; then
    printf 'invalid host syntax for %s target: %s\n' "$label" "$host" >&2
    return 1
  fi
}

load_profile_file() {
  local profile_path="$1"
  local line key value
  if [[ ! -f "$profile_path" ]]; then
    printf 'missing profile file: %s\n' "$profile_path" >&2
    return 1
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="$(trim_ascii "$line")"
    [[ -n "$line" ]] || continue
    [[ "${line:0:1}" == "#" ]] && continue
    if [[ "$line" != *=* ]]; then
      printf 'invalid profile line (expected KEY=VALUE): %s\n' "$line" >&2
      return 1
    fi
    key="$(trim_ascii "${line%%=*}")"
    value="${line#*=}"
    value="$(trim_ascii "$value")"
    if [[ "$value" == \"*\" && "$value" == *\" ]]; then
      value="${value:1:${#value}-2}"
    elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
      value="${value:1:${#value}-2}"
    fi
    case "$key" in
      EXIT_TARGET) [[ -z "$EXIT_TARGET" ]] && EXIT_TARGET="$value" ;;
      CLIENT_TARGET) [[ -z "$CLIENT_TARGET" ]] && CLIENT_TARGET="$value" ;;
      EXIT_UTM_NAME) [[ -z "$EXIT_UTM_NAME" ]] && EXIT_UTM_NAME="$value" ;;
      CLIENT_UTM_NAME) [[ -z "$CLIENT_UTM_NAME" ]] && CLIENT_UTM_NAME="$value" ;;
      ENTRY_TARGET)
        ENTRY_TARGET_DECLARED=1
        [[ -z "$ENTRY_TARGET" ]] && ENTRY_TARGET="$value"
        ;;
      ENTRY_UTM_NAME) [[ -z "$ENTRY_UTM_NAME" ]] && ENTRY_UTM_NAME="$value" ;;
      AUX_TARGET)
        AUX_TARGET_DECLARED=1
        [[ -z "$AUX_TARGET" ]] && AUX_TARGET="$value"
        ;;
      AUX_UTM_NAME) [[ -z "$AUX_UTM_NAME" ]] && AUX_UTM_NAME="$value" ;;
      EXTRA_TARGET)
        EXTRA_TARGET_DECLARED=1
        [[ -z "$EXTRA_TARGET" ]] && EXTRA_TARGET="$value"
        ;;
      EXTRA_UTM_NAME) [[ -z "$EXTRA_UTM_NAME" ]] && EXTRA_UTM_NAME="$value" ;;
      FIFTH_CLIENT_TARGET)
        FIFTH_CLIENT_TARGET_DECLARED=1
        [[ -z "$FIFTH_CLIENT_TARGET" ]] && FIFTH_CLIENT_TARGET="$value"
        ;;
      FIFTH_CLIENT_UTM_NAME) [[ -z "$FIFTH_CLIENT_UTM_NAME" ]] && FIFTH_CLIENT_UTM_NAME="$value" ;;
      SSH_IDENTITY_FILE) [[ -z "$SSH_IDENTITY_FILE" ]] && SSH_IDENTITY_FILE="$value" ;;
      SSH_PASSWORD_FILE) [[ -z "$SSH_IDENTITY_FILE" ]] && SSH_IDENTITY_FILE="$value" ;;
      SUDO_PASSWORD_FILE) [[ -z "$SSH_IDENTITY_FILE" ]] && SSH_IDENTITY_FILE="$value" ;;
      SSH_KNOWN_HOSTS_FILE) [[ -z "$SSH_KNOWN_HOSTS_FILE" ]] && SSH_KNOWN_HOSTS_FILE="$value" ;;
      NETWORK_ID) [[ "$NETWORK_ID" == rn-live-lab-* ]] && NETWORK_ID="$value" ;;
      SSH_ALLOW_CIDRS) [[ "$SSH_ALLOW_CIDRS" == "192.168.18.0/24" ]] && SSH_ALLOW_CIDRS="$value" ;;
      TRAVERSAL_TTL_SECS) [[ "$TRAVERSAL_TTL_SECS" == "120" ]] && TRAVERSAL_TTL_SECS="$value" ;;
      CROSS_NETWORK_NAT_PROFILES) [[ "$CROSS_NETWORK_NAT_PROFILES" == "${RUSTYNET_CROSS_NETWORK_NAT_PROFILES:-baseline_lan}" ]] && CROSS_NETWORK_NAT_PROFILES="$value" ;;
      CROSS_NETWORK_REQUIRED_NAT_PROFILES) [[ -z "$CROSS_NETWORK_REQUIRED_NAT_PROFILES" ]] && CROSS_NETWORK_REQUIRED_NAT_PROFILES="$value" ;;
      CROSS_NETWORK_IMPAIRMENT_PROFILE) [[ "$CROSS_NETWORK_IMPAIRMENT_PROFILE" == "${RUSTYNET_CROSS_NETWORK_IMPAIRMENT_PROFILE:-none}" ]] && CROSS_NETWORK_IMPAIRMENT_PROFILE="$value" ;;
      CROSS_NETWORK_MAX_TIME_SKEW_SECS) [[ "$CROSS_NETWORK_MAX_TIME_SKEW_SECS" == "${RUSTYNET_CROSS_NETWORK_MAX_TIME_SKEW_SECS:-2}" ]] && CROSS_NETWORK_MAX_TIME_SKEW_SECS="$value" ;;
      CROSS_NETWORK_DISCOVERY_MAX_AGE_SECS) [[ "$CROSS_NETWORK_DISCOVERY_MAX_AGE_SECS" == "${RUSTYNET_CROSS_NETWORK_DISCOVERY_MAX_AGE_SECS:-900}" ]] && CROSS_NETWORK_DISCOVERY_MAX_AGE_SECS="$value" ;;
      CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS) [[ "$CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS" == "${RUSTYNET_CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS:-900}" ]] && CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS="$value" ;;
      CROSS_NETWORK_CLIENT_UNDERLAY_IP) [[ -z "$CROSS_NETWORK_CLIENT_UNDERLAY_IP" ]] && CROSS_NETWORK_CLIENT_UNDERLAY_IP="$value" ;;
      CROSS_NETWORK_EXIT_UNDERLAY_IP) [[ -z "$CROSS_NETWORK_EXIT_UNDERLAY_IP" ]] && CROSS_NETWORK_EXIT_UNDERLAY_IP="$value" ;;
      CROSS_NETWORK_RELAY_UNDERLAY_IP) [[ -z "$CROSS_NETWORK_RELAY_UNDERLAY_IP" ]] && CROSS_NETWORK_RELAY_UNDERLAY_IP="$value" ;;
      CROSS_NETWORK_PROBE_UNDERLAY_IP) [[ -z "$CROSS_NETWORK_PROBE_UNDERLAY_IP" ]] && CROSS_NETWORK_PROBE_UNDERLAY_IP="$value" ;;
      RUSTYNET_BACKEND) [[ -z "$RUSTYNET_BACKEND" ]] && RUSTYNET_BACKEND="$value" ;;
      SOURCE_MODE)
        if [[ "$SOURCE_MODE_EXPLICIT" -eq 0 ]]; then
          SOURCE_MODE="$value"
          SOURCE_MODE_EXPLICIT=1
        fi
        ;;
      REPO_REF)
        if [[ "$SOURCE_MODE_EXPLICIT" -eq 0 || "$SOURCE_MODE" == "ref" ]]; then
          REPO_REF="$value"
          if [[ "$SOURCE_MODE_EXPLICIT" -eq 0 ]]; then
            SOURCE_MODE="ref"
            SOURCE_MODE_EXPLICIT=1
          fi
        fi
        ;;
      REPORT_DIR)
        if [[ "$REPORT_DIR" == "${ROOT_DIR}/artifacts/live_lab/${RUN_ID}" ]]; then
          REPORT_DIR="$value"
          LOG_DIR="$REPORT_DIR/logs"
          VERIFICATION_DIR="$REPORT_DIR/verification"
          STATE_DIR="$REPORT_DIR/state"
          SUMMARY_JSON="$REPORT_DIR/run_summary.json"
          SUMMARY_MD="$REPORT_DIR/run_summary.md"
          FAILURE_DIGEST_JSON="$REPORT_DIR/failure_digest.json"
          FAILURE_DIGEST_MD="$REPORT_DIR/failure_digest.md"
          STAGE_TSV="$STATE_DIR/stages.tsv"
          NODES_TSV="$STATE_DIR/nodes.tsv"
          SOURCE_ARCHIVE="$STATE_DIR/rustynet-source.tar.gz"
          PUBKEYS_TSV="$STATE_DIR/pubkeys.tsv"
          ONEHOP_STATE_ENV="$STATE_DIR/onehop_state.env"
        fi
        ;;
      '')
        ;;
      *)
        printf 'unsupported profile key: %s\n' "$key" >&2
        return 1
        ;;
    esac
    :
  done < "$profile_path"
  return 0
}

validate_source_mode() {
  case "$SOURCE_MODE" in
    working-tree|local-head|origin-main|ref)
      ;;
    *)
      printf 'unsupported source mode: %s\n' "$SOURCE_MODE" >&2
      return 1
      ;;
  esac
  if [[ "$SOURCE_MODE" == "ref" ]]; then
    if [[ -z "$REPO_REF" ]]; then
      printf 'source-mode=ref requires --repo-ref <ref>\n' >&2
      return 1
    fi
  fi
}

resolve_source_ref() {
  case "$SOURCE_MODE" in
    local-head)
      printf 'HEAD'
      ;;
    origin-main)
      printf 'origin/main'
      ;;
    ref)
      printf '%s' "$REPO_REF"
      ;;
    *)
      printf ''
      ;;
  esac
}

describe_source_mode() {
  case "$SOURCE_MODE" in
    working-tree)
      printf 'local working tree'
      ;;
    local-head)
      printf 'local committed HEAD'
      ;;
    origin-main)
      printf 'latest committed origin/main'
      ;;
    ref)
      printf 'git ref %s' "$REPO_REF"
      ;;
  esac
}

fetch_git_ref_if_needed() {
  local ref="$1"
  if is_origin_branch_ref "$ref"; then
    git -C "$ROOT_DIR" fetch origin --prune --quiet
  fi
}

git_ref_exists() {
  local ref="$1"
  git -C "$ROOT_DIR" rev-parse --verify --quiet "$ref" >/dev/null 2>&1
}

is_origin_branch_ref() {
  local ref="$1"
  [[ "$ref" == origin/* ]]
}

collect_interactive_git_branches() {
  local branch
  local seen=""
  local branches=()
  local remote_count=0

  while IFS= read -r branch; do
    branch="$(trim_ascii "$branch")"
    [[ -n "$branch" ]] || continue
    [[ "$branch" == "origin" ]] && continue
    [[ "$branch" == "HEAD" ]] && continue
    [[ "$branch" == "origin/HEAD" ]] && continue
    branch="${branch#origin/}"
    if [[ ",$seen," != *",$branch,"* ]]; then
      branches+=("$branch")
      seen="${seen},${branch}"
      remote_count=$((remote_count + 1))
    fi
  done < <(git -C "$ROOT_DIR" for-each-ref refs/remotes/origin --format='%(refname:short)' 2>/dev/null || true)

  if (( remote_count > 0 )); then
    printf '%s\n' "${branches[@]}"
    return 0
  fi

  while IFS= read -r branch; do
    branch="$(trim_ascii "$branch")"
    [[ -n "$branch" ]] || continue
    if [[ ",$seen," != *",$branch,"* ]]; then
      branches+=("$branch")
      seen="${seen},${branch}"
    fi
  done < <(git -C "$ROOT_DIR" for-each-ref refs/heads --format='%(refname:short)' 2>/dev/null || true)

  printf '%s\n' "${branches[@]}"
}

default_interactive_git_branch() {
  if git_ref_exists "refs/remotes/origin/main"; then
    printf 'main'
    return 0
  fi
  if git_ref_exists "refs/heads/main"; then
    printf 'main'
    return 0
  fi
  git -C "$ROOT_DIR" symbolic-ref --quiet --short HEAD 2>/dev/null || true
}

resolve_interactive_git_branch_ref() {
  local branch_name="$1"
  if git_ref_exists "refs/remotes/origin/${branch_name}"; then
    printf 'origin/%s' "$branch_name"
    return 0
  fi
  if git_ref_exists "refs/heads/${branch_name}"; then
    printf '%s' "$branch_name"
    return 0
  fi
  if git_ref_exists "$branch_name"; then
    printf '%s' "$branch_name"
    return 0
  fi
  return 1
}

prompt_for_git_branch_source() {
  local fetch_failed=0
  local branch_lines branch_count=0
  local branch_choices=()
  local branch default_branch selection selected_ref index

  if ! git -C "$ROOT_DIR" fetch origin --prune --quiet; then
    fetch_failed=1
    printf 'warning: git fetch origin failed; listing currently available local refs\n' >&2
  fi

  branch_lines="$(collect_interactive_git_branches)"
  while IFS= read -r branch; do
    branch="$(trim_ascii "$branch")"
    [[ -n "$branch" ]] || continue
    branch_choices+=("$branch")
    branch_count=$((branch_count + 1))
  done <<< "$branch_lines"

  if [[ "$branch_count" -eq 0 ]]; then
    printf 'no git branches available for interactive selection\n' >&2
    return 1
  fi

  printf 'Available branches:\n' >&2
  for index in "${!branch_choices[@]}"; do
    printf '  %d) %s\n' "$((index + 1))" "${branch_choices[$index]}" >&2
  done

  default_branch="$(default_interactive_git_branch)"
  if [[ -z "$default_branch" ]]; then
    default_branch="${branch_choices[0]}"
  fi

  while true; do
    selection="$(prompt_with_default 'Branch to deploy (number or name)' "$default_branch")"
    if [[ "$selection" =~ ^[0-9]+$ ]]; then
      index=$((selection - 1))
      if (( index >= 0 && index < ${#branch_choices[@]} )); then
        selection="${branch_choices[$index]}"
      else
        printf 'invalid branch selection: %s\n' "$selection" >&2
        continue
      fi
    fi
    selected_ref="$(resolve_interactive_git_branch_ref "$selection")" || {
      printf 'unknown branch: %s\n' "$selection" >&2
      continue
    }
    SOURCE_MODE="ref"
    REPO_REF="$selected_ref"
    if [[ "$fetch_failed" -eq 0 && "$selected_ref" == "origin/main" ]]; then
      SOURCE_MODE="origin-main"
    fi
    return 0
  done
}

node_target_for_label() {
  local label="$1"
  awk -F '\t' -v label="$label" '$1 == label { print $2; exit }' "$NODES_TSV"
}

node_id_for_label() {
  local label="$1"
  awk -F '\t' -v label="$label" '$1 == label { print $3; exit }' "$NODES_TSV"
}

node_role_for_label() {
  local label="$1"
  awk -F '\t' -v label="$label" '$1 == label { print $4; exit }' "$NODES_TSV"
}

has_label() {
  local label="$1"
  awk -F '\t' -v label="$label" '$1 == label { found=1; exit } END { exit(found ? 0 : 1) }' "$NODES_TSV"
}

node_count() {
  awk 'END { print NR + 0 }' "$NODES_TSV"
}

has_four_node_live_topology() {
  has_label entry && has_label aux
}

has_five_node_release_gate_topology() {
  has_four_node_live_topology && has_label extra
}

managed_peer_labels() {
  awk -F '\t' '$1 != "exit" && $1 != "client" { print $1 }' "$NODES_TSV"
}

cross_network_network_id_for_label() {
  local label="$1"
  printf '%s-%s' "$NETWORK_ID" "$label"
}

cross_network_override_underlay_ip_for_label() {
  local label="$1"
  case "$label" in
    client) printf '%s' "$CROSS_NETWORK_CLIENT_UNDERLAY_IP" ;;
    exit) printf '%s' "$CROSS_NETWORK_EXIT_UNDERLAY_IP" ;;
    relay) printf '%s' "$CROSS_NETWORK_RELAY_UNDERLAY_IP" ;;
    probe) printf '%s' "$CROSS_NETWORK_PROBE_UNDERLAY_IP" ;;
    *) printf '' ;;
  esac
}

cross_network_underlay_ip_for_label() {
  local label="$1"
  local override target
  override="$(cross_network_override_underlay_ip_for_label "$label")"
  if [[ -n "$override" ]]; then
    printf '%s' "$override"
    return 0
  fi
  target="$(node_target_for_label "$label")"
  if [[ -z "$target" ]]; then
    return 1
  fi
  live_lab_resolved_target_address "$target"
}

cross_network_relay_label() {
  if has_label entry; then
    printf 'entry'
    return 0
  fi
  if has_label aux; then
    printf 'aux'
    return 0
  fi
  return 1
}

cross_network_probe_label() {
  if has_label aux; then
    printf 'aux'
    return 0
  fi
  if has_label entry; then
    printf 'entry'
    return 0
  fi
  return 1
}

cross_network_impairment_remote_script() {
  local target="$1"
  local remote_src
  remote_src="$(live_lab_remote_src_dir "$target")"
  printf '%s/scripts/e2e/apply_cross_network_impairment_profile.sh' "$remote_src"
}

cross_network_apply_impairment_profile_target() {
  local target="$1"
  local script_path
  script_path="$(cross_network_impairment_remote_script "$target")"
  live_lab_run_root "$target" \
    "root test -f '$script_path' && root bash '$script_path' --mode apply --profile '$CROSS_NETWORK_IMPAIRMENT_PROFILE' --interface rustynet0"
}

cross_network_clear_impairment_profile_target() {
  local target="$1"
  local script_path
  script_path="$(cross_network_impairment_remote_script "$target")"
  live_lab_run_root "$target" \
    "root test -f '$script_path' && root bash '$script_path' --mode clear --profile '$CROSS_NETWORK_IMPAIRMENT_PROFILE' --interface rustynet0"
}

cross_network_stage_labels_for_impairment() {
  local stage_kind="$1"
  local relay_label probe_label
  case "$stage_kind" in
    direct|dns|soak|node_switch)
      printf '%s\n' client exit
      ;;
    relay|failback|controller_switch)
      relay_label="$(cross_network_relay_label)" || return 1
      printf '%s\n' client exit "$relay_label"
      ;;
    adversarial)
      probe_label="$(cross_network_probe_label)" || return 1
      printf '%s\n' client exit "$probe_label"
      ;;
    *)
      printf 'unsupported cross-network stage kind for impairment: %s\n' "$stage_kind" >&2
      return 1
      ;;
  esac
}

run_cross_network_stage_with_impairment() {
  local stage_kind="$1"
  shift
  local -a cmd=("$@")
  local -a labels=()
  local -a targets=()
  local -a applied_targets=()
  local label target
  local rc=0
  local cleanup_failed=0

  if [[ "$CROSS_NETWORK_IMPAIRMENT_PROFILE" == "none" ]]; then
    "${cmd[@]}"
    return $?
  fi

  while IFS= read -r label; do
    [[ -n "$label" ]] || continue
    target="$(node_target_for_label "$label")"
    if [[ -z "$target" ]]; then
      printf 'missing target for impairment label: %s\n' "$label" >&2
      return 1
    fi
    labels+=("$label")
    targets+=("$target")
  done < <(cross_network_stage_labels_for_impairment "$stage_kind")

  set +e
  for target in "${targets[@]}"; do
    if ! cross_network_apply_impairment_profile_target "$target"; then
      rc=1
      break
    fi
    applied_targets+=("$target")
  done
  if [[ "$rc" -eq 0 ]]; then
    "${cmd[@]}"
    rc=$?
  fi
  for target in "${applied_targets[@]}"; do
    if ! cross_network_clear_impairment_profile_target "$target"; then
      cleanup_failed=1
    fi
  done
  set -e

  if [[ "$cleanup_failed" -ne 0 ]]; then
    printf 'failed to clear impairment profile (%s) on one or more targets\n' "$CROSS_NETWORK_IMPAIRMENT_PROFILE" >&2
    return 1
  fi
  return "$rc"
}

cross_network_stages_applicable() {
  local client_target exit_target client_addr exit_addr same_prefix_rc
  CROSS_NETWORK_SKIP_REASON=""
  if [[ "$CROSS_NETWORK_MODE" == "skip" ]]; then
    CROSS_NETWORK_SKIP_REASON="skipped by --skip-cross-network"
    return 1
  fi
  if [[ "$CROSS_NETWORK_MODE" == "force" ]]; then
    return 0
  fi
  client_target="$(node_target_for_label client)"
  exit_target="$(node_target_for_label exit)"
  if [[ -z "$client_target" || -z "$exit_target" ]]; then
    CROSS_NETWORK_SKIP_REASON="requires client and exit targets"
    return 1
  fi
  client_addr="$(cross_network_underlay_ip_for_label client)" || {
    CROSS_NETWORK_SKIP_REASON="unable to resolve client underlay address"
    return 1
  }
  exit_addr="$(cross_network_underlay_ip_for_label exit)" || {
    CROSS_NETWORK_SKIP_REASON="unable to resolve exit underlay address"
    return 1
  }
  set +e
  local topology_result
  topology_result="$(cargo run --quiet -p rustynet-cli -- ops classify-cross-network-topology --ip-a "$client_addr" --ip-b "$exit_addr" --ipv4-prefix 24 --ipv6-prefix 64 2>/dev/null)"
  same_prefix_rc=$?
  set -e
  if [[ "$same_prefix_rc" -eq 0 ]]; then
    topology_result="$(printf '%s' "$topology_result" | tr -d '[:space:]')"
    if [[ "$topology_result" == "fail" ]]; then
      same_prefix_rc=0
    else
      same_prefix_rc=1
    fi
  else
    same_prefix_rc=2
  fi
  if [[ "$same_prefix_rc" -eq 0 ]]; then
    CROSS_NETWORK_SKIP_REASON="requires distinct client/exit underlay prefixes (client=${client_addr}, exit=${exit_addr}); use --force-cross-network to override"
    return 1
  fi
  if [[ "$same_prefix_rc" -eq 2 ]]; then
    return 0
  fi
  return 0
}

normalize_target() {
  local label="$1"
  local value="$2"
  local normalized="$value"
  local user_part=""
  local host_part=""
  if [[ "$value" == *"@"* ]]; then
    printf '%s' "$value"
    return 0
  fi
  host_part="$value"
  user_part="$(prompt_value "SSH user for ${label} (${host_part})")"
  if [[ -z "$user_part" ]]; then
    printf 'missing SSH user for %s\n' "$label" >&2
    return 1
  fi
  normalized="${user_part}@${host_part}"
  printf '%s' "$normalized"
}

ensure_password_file() {
  local provided_path="$1"
  local prompt="$2"
  local __resultvar="$3"
  local selected_path="$provided_path"
  if [[ -z "$selected_path" && -t 0 && -t 1 ]]; then
    selected_path="$(prompt_value "$prompt")"
  fi
  if [[ -z "$selected_path" ]]; then
    printf 'missing required file path for %s\n' "$prompt" >&2
    return 1
  fi
  if [[ ! -f "$selected_path" ]]; then
    printf 'missing file: %s\n' "$selected_path" >&2
    return 1
  fi
  if [[ -L "$selected_path" ]]; then
    printf 'path must not be a symlink: %s\n' "$selected_path" >&2
    return 1
  fi
  if ! cargo run --quiet -p rustynet-cli -- ops check-local-file-mode \
    --path "$selected_path" \
    --policy owner-only \
    --label file >/dev/null
  then
    return 1
  fi
  printf -v "$__resultvar" '%s' "$selected_path"
}

record_node() {
  local label="$1"
  local target="$2"
  local node_id="$3"
  local role="$4"
  printf '%s\t%s\t%s\t%s\n' "$label" "$target" "$node_id" "$role" >> "$NODES_TSV"
}

record_stage() {
  local stage_name="$1"
  local severity="$2"
  local status="$3"
  local rc="$4"
  local log_path="$5"
  local message="$6"
  local started_at="$7"
  local finished_at="$8"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$stage_name" \
    "$severity" \
    "$status" \
    "$rc" \
    "$log_path" \
    "$(sanitize_text "$message")" \
    "$started_at" \
    "$finished_at" >> "$STAGE_TSV"
}

record_stage_skip() {
  local stage_name="$1"
  local severity="$2"
  local message="$3"
  local log_path="$LOG_DIR/${stage_name}.log"
  : > "$log_path"
  record_stage "$stage_name" "$severity" "skipped" "0" "$log_path" "$message" "$(date -u +%FT%TZ)" "$(date -u +%FT%TZ)"
  refresh_failure_digest
}

is_setup_stage_name() {
  case "$1" in
    preflight|prepare_source_archive|verify_ssh_reachability|prime_remote_access|cleanup_hosts|bootstrap_hosts|collect_pubkeys|membership_setup|distribute_membership_state|issue_and_distribute_assignments|issue_and_distribute_traversal|issue_and_distribute_dns_zone|enforce_baseline_runtime|validate_baseline_runtime)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

setup_stage_index() {
  local stage_name="$1"
  local idx=0
  local stages=(
    preflight
    prepare_source_archive
    verify_ssh_reachability
    prime_remote_access
    cleanup_hosts
    bootstrap_hosts
    collect_pubkeys
    membership_setup
    distribute_membership_state
    issue_and_distribute_assignments
    issue_and_distribute_traversal
    issue_and_distribute_dns_zone
    enforce_baseline_runtime
    validate_baseline_runtime
  )
  for idx in "${!stages[@]}"; do
    if [[ "${stages[$idx]}" == "$stage_name" ]]; then
      printf '%s' "$idx"
      return 0
    fi
  done
  return 1
}

reset_setup_stage_state() {
  local reset_from="$1"
  local reset_mode="$2"
  local tmp_stage_tsv="${STAGE_TSV}.tmp"
  local line stage_name stage_idx reset_idx
  if [[ ! -f "$STAGE_TSV" ]]; then
    return 0
  fi
  if ! reset_idx="$(setup_stage_index "$reset_from")"; then
    printf 'unsupported setup stage for reset: %s\n' "$reset_from" >&2
    return 1
  fi
  : > "$tmp_stage_tsv"
  while IFS= read -r line; do
    stage_name="${line%%$'\t'*}"
    if is_setup_stage_name "$stage_name"; then
      if [[ "$reset_mode" == "rerun" ]]; then
        [[ "$stage_name" == "$reset_from" ]] && continue
      else
        stage_idx="$(setup_stage_index "$stage_name" || true)"
        if [[ -n "$stage_idx" && "$stage_idx" -ge "$reset_idx" ]]; then
          continue
        fi
      fi
    fi
    printf '%s\n' "$line" >> "$tmp_stage_tsv"
  done < "$STAGE_TSV"
  mv "$tmp_stage_tsv" "$STAGE_TSV"
  rm -f "$LOG_DIR/${reset_from}.log"
  rm -rf "$STATE_DIR/parallel-${reset_from}"
}

run_setup_stage() {
  local severity="$1"
  local stage_name="$2"
  local description="$3"
  shift 3

  if [[ -n "$RERUN_STAGE" ]]; then
    if [[ "$stage_name" != "$RERUN_STAGE" ]]; then
      return 0
    fi
  elif [[ -n "$RESUME_FROM_STAGE" ]]; then
    local current_idx resume_idx
    current_idx="$(setup_stage_index "$stage_name" || true)"
    resume_idx="$(setup_stage_index "$RESUME_FROM_STAGE" || true)"
    if [[ -z "$current_idx" || -z "$resume_idx" ]]; then
      printf 'unsupported resume stage: %s\n' "$RESUME_FROM_STAGE" >&2
      return 1
    fi
    if [[ "$current_idx" -lt "$resume_idx" ]]; then
      return 0
    fi
  fi

  run_stage "$severity" "$stage_name" "$description" "$@"
}

wait_for_parallel_slot() {
  local max_jobs="$1"
  local running
  while true; do
    running="$(jobs -rp | wc -l | tr -d ' ')"
    if [[ "$running" -lt "$max_jobs" ]]; then
      return 0
    fi
    sleep 0.2
  done
}

update_overall_status() {
  local severity="$1"
  local status="$2"
  if [[ "$status" != "fail" ]]; then
    return 0
  fi
  FAILURE_COUNT=$((FAILURE_COUNT + 1))
  if [[ "$severity" == "soft" ]]; then
    SOFT_FAILURE_COUNT=$((SOFT_FAILURE_COUNT + 1))
    if [[ "$OVERALL_STATUS" == "pass" ]]; then
      OVERALL_STATUS="pass_with_warnings"
    fi
    return 0
  fi
  OVERALL_STATUS="fail"
}

stage_requires_forensics_bundle() {
  local stage_name="$1"
  [[ "$stage_name" == cross_network_* ]]
}

redact_forensics_text() {
  cargo run --quiet -p rustynet-cli -- ops redact-forensics-text
}

capture_forensics_user() {
  local target="$1"
  local command="$2"
  local output_path="$3"
  local raw rc
  set +e
  raw="$(live_lab_capture "$target" "$command" 120 2>&1)"
  rc=$?
  set -e
  {
    printf 'target=%s\n' "$target"
    printf 'capture_mode=user\n'
    printf 'capture_rc=%s\n' "$rc"
    printf 'command=%s\n' "$command"
    printf -- '---\n'
    printf '%s\n' "$raw" | redact_forensics_text
  } > "$output_path"
}

capture_forensics_root() {
  local target="$1"
  local command="$2"
  local output_path="$3"
  local raw rc
  set +e
  raw="$(live_lab_capture_root "$target" "$command" 120 2>&1)"
  rc=$?
  set -e
  {
    printf 'target=%s\n' "$target"
    printf 'capture_mode=root\n'
    printf 'capture_rc=%s\n' "$rc"
    printf 'command=%s\n' "$command"
    printf -- '---\n'
    printf '%s\n' "$raw" | redact_forensics_text
  } > "$output_path"
}

live_lab_collect_forensics_bundle() {
  local stage_name="$1"
  local collected_at stage_dir node_dir label target node_id role manifest_path
  collected_at="$(date -u +%Y%m%dT%H%M%SZ)"
  stage_dir="$REPORT_DIR/forensics/${stage_name}/${collected_at}"
  mkdir -p "$stage_dir"

  while IFS=$'\t' read -r label target node_id role; do
    [[ -n "$target" ]] || continue
    node_dir="$stage_dir/${label}"
    mkdir -p "$node_dir"

    local service_snapshot service_rc network_snapshot network_rc route_policy route_policy_rc
    local dns_state dns_state_rc time_snapshot time_rc process_snapshot process_rc
    local socket_snapshot socket_rc permissions_snapshot permissions_rc
    local firewall_snapshot firewall_rc dns_zone_snapshot dns_zone_rc signed_state_snapshot signed_state_rc
    local secret_hygiene secret_rc node_snapshot node_rc
    set +e
    service_snapshot="$(live_lab_collect_service_snapshot "$target" 2>&1)"
    service_rc=$?
    set -e
    {
      printf 'capture_rc=%s\n' "$service_rc"
      printf '%s\n' "$service_snapshot"
    } > "$node_dir/service_snapshot.txt"

    set +e
    network_snapshot="$(live_lab_collect_network_snapshot "$target" 2>&1)"
    network_rc=$?
    set -e
    {
      printf 'capture_rc=%s\n' "$network_rc"
      printf '%s\n' "$network_snapshot"
    } > "$node_dir/network_snapshot.txt"

    set +e
    route_policy="$(live_lab_collect_route_policy "$target" 2>&1)"
    route_policy_rc=$?
    set -e
    {
      printf 'capture_rc=%s\n' "$route_policy_rc"
      printf '%s\n' "$route_policy"
    } > "$node_dir/route_policy.txt"

    set +e
    dns_state="$(live_lab_collect_dns_snapshot "$target" 2>&1)"
    dns_state_rc=$?
    set -e
    {
      printf 'capture_rc=%s\n' "$dns_state_rc"
      printf '%s\n' "$dns_state"
    } > "$node_dir/dns_state.txt"

    set +e
    time_snapshot="$(live_lab_collect_time_snapshot "$target" "$node_id" "$role" 2>&1)"
    time_rc=$?
    set -e
    {
      printf 'capture_rc=%s\n' "$time_rc"
      printf '%s\n' "$time_snapshot"
    } > "$node_dir/time_snapshot.txt"

    set +e
    process_snapshot="$(live_lab_collect_process_snapshot "$target" "$node_id" "$role" 2>&1)"
    process_rc=$?
    set -e
    {
      printf 'capture_rc=%s\n' "$process_rc"
      printf '%s\n' "$process_snapshot"
    } > "$node_dir/process_snapshot.txt"

    set +e
    socket_snapshot="$(live_lab_collect_socket_snapshot "$target" "$node_id" "$role" 2>&1)"
    socket_rc=$?
    set -e
    {
      printf 'capture_rc=%s\n' "$socket_rc"
      printf '%s\n' "$socket_snapshot"
    } > "$node_dir/socket_snapshot.txt"

    set +e
    permissions_snapshot="$(live_lab_collect_permissions_snapshot "$target" "$node_id" "$role" 2>&1)"
    permissions_rc=$?
    set -e
    {
      printf 'capture_rc=%s\n' "$permissions_rc"
      printf '%s\n' "$permissions_snapshot"
    } > "$node_dir/permissions_snapshot.txt"

    set +e
    firewall_snapshot="$(live_lab_collect_firewall_snapshot "$target" "$node_id" "$role" 2>&1)"
    firewall_rc=$?
    set -e
    {
      printf 'capture_rc=%s\n' "$firewall_rc"
      printf '%s\n' "$firewall_snapshot"
    } > "$node_dir/firewall.txt"

    set +e
    dns_zone_snapshot="$(live_lab_collect_dns_zone_snapshot "$target" "$node_id" 2>&1)"
    dns_zone_rc=$?
    set -e
    {
      printf 'capture_rc=%s\n' "$dns_zone_rc"
      printf '%s\n' "$dns_zone_snapshot"
    } > "$node_dir/dns_zone.txt"

    set +e
    signed_state_snapshot="$(live_lab_collect_signed_state_snapshot "$target" "$node_id" "$role" 2>&1)"
    signed_state_rc=$?
    set -e
    {
      printf 'capture_rc=%s\n' "$signed_state_rc"
      printf '%s\n' "$signed_state_snapshot"
    } > "$node_dir/signed_state.txt"

    set +e
    secret_hygiene="$(live_lab_collect_secret_hygiene "$target" 2>&1)"
    secret_rc=$?
    set -e
    {
      printf 'capture_rc=%s\n' "$secret_rc"
      printf '%s\n' "$secret_hygiene"
    } > "$node_dir/secret_hygiene.txt"

    set +e
    node_snapshot="$(live_lab_collect_node_snapshot "$target" "$node_id" "$role" 2>&1)"
    node_rc=$?
    set -e
    {
      printf 'capture_rc=%s\n' "$node_rc"
      printf '%s\n' "$node_snapshot"
    } > "$node_dir/node_snapshot.txt"

    {
      printf 'label=%s\n' "$label"
      printf 'target=%s\n' "$target"
      printf 'node_id=%s\n' "$node_id"
      printf 'role=%s\n' "$role"
    } > "$node_dir/node_identity.txt"
  done < "$NODES_TSV"

  local route_matrix_snapshot route_matrix_rc
  set +e
  route_matrix_snapshot="$(live_lab_collect_route_matrix_snapshot "$stage_name" 2>&1)"
  route_matrix_rc=$?
  set -e
  {
    printf 'capture_rc=%s\n' "$route_matrix_rc"
    printf '%s\n' "$route_matrix_snapshot"
  } > "$stage_dir/route_matrix.txt"

  local cluster_snapshot cluster_rc
  set +e
  cluster_snapshot="$(live_lab_collect_cluster_snapshot "$stage_name" 2>&1)"
  cluster_rc=$?
  set -e
  {
    printf 'capture_rc=%s\n' "$cluster_rc"
    printf '%s\n' "$cluster_snapshot"
  } > "$stage_dir/cluster_snapshot.txt"

  manifest_path="$stage_dir/manifest.json"
  cargo run --quiet -p rustynet-cli -- ops write-cross-network-forensics-manifest \
    --stage "$stage_name" \
    --collected-at-utc "$collected_at" \
    --stage-dir "$stage_dir" \
    --output "$manifest_path" >/dev/null

  local artifact_index_path bundle_validation_path helper_output helper_rc
  bundle_validation_path="$stage_dir/bundle_validation.json"
  set +e
  helper_output="$(live_lab_assert_forensics_bundle_complete "$stage_name" "$stage_dir" "$bundle_validation_path" 2>&1)"
  helper_rc=$?
  set -e
  if [[ "$helper_rc" -ne 0 ]]; then
    printf '[forensics:%s] warning: failed to validate bundle completeness: %s\n' "$stage_name" "$helper_output" >&2
  fi

  artifact_index_path="$stage_dir/artifact_index.json"
  set +e
  helper_output="$(live_lab_collect_stage_artifact_index "$stage_name" "$stage_dir" "$artifact_index_path" 2>&1)"
  helper_rc=$?
  set -e
  if [[ "$helper_rc" -ne 0 ]]; then
    printf '[forensics:%s] warning: failed to write artifact index: %s\n' "$stage_name" "$helper_output" >&2
  fi

  printf '%s' "$stage_dir"
}

collect_cross_network_failure_forensics() {
  local stage_name="$1"
  live_lab_collect_forensics_bundle "$stage_name"
}

live_lab_collect_stage_artifact_index() {
  local stage_name="$1"
  local stage_dir="$2"
  local output_path="${3:-$stage_dir/artifact_index.json}"
  cargo run --quiet -p rustynet-cli -- ops write-live-lab-stage-artifact-index \
    --stage-name "$stage_name" \
    --stage-dir "$stage_dir" \
    --output "$output_path"
}

live_lab_assert_forensics_bundle_complete() {
  local stage_name="$1"
  local stage_dir="$2"
  local output_path="${3:-$stage_dir/bundle_validation.json}"
  cargo run --quiet -p rustynet-cli -- ops validate-cross-network-forensics-bundle \
    --stage-name "$stage_name" \
    --nodes-tsv "$NODES_TSV" \
    --stage-dir "$stage_dir" \
    --output "$output_path"
}

live_lab_collect_cluster_snapshot() {
  local stage_name="${1:-cluster_snapshot}"
  local collected_at label target node_id role
  local peer_inventory peer_rc signed_state signed_rc firewall firewall_rc cluster_status="pass"

  collected_at="$(date -u +%FT%TZ)"
  {
    printf '__RNLAB_CLUSTER_BEGIN__\n'
    printf 'cluster_snapshot_version=1\n'
    printf 'cluster_stage_name=%s\n' "$stage_name"
    printf 'cluster_collected_at_utc=%s\n' "$collected_at"
    printf 'cluster_node_count=%s\n' "$(node_count)"
    while IFS=$'\t' read -r label target node_id role; do
      [[ -n "$target" ]] || continue
      printf 'cluster_node_begin\n'
      printf 'label=%s\n' "$label"
      printf 'target=%s\n' "$target"
      printf 'node_id=%s\n' "$node_id"
      printf 'role=%s\n' "$role"

      set +e
      peer_inventory="$(live_lab_collect_peer_inventory_snapshot "$target" "$node_id" "$role" 2>&1)"
      peer_rc=$?
      signed_state="$(live_lab_collect_signed_state_snapshot "$target" "$node_id" "$role" 2>&1)"
      signed_rc=$?
      firewall="$(live_lab_collect_firewall_snapshot "$target" "$node_id" "$role" 2>&1)"
      firewall_rc=$?
      set -e

      if [[ "$peer_rc" -ne 0 || "$signed_rc" -ne 0 || "$firewall_rc" -ne 0 ]]; then
        cluster_status="fail"
      fi

      printf 'peer_inventory_capture_rc=%s\n' "$peer_rc"
      printf '%s\n' "$peer_inventory"
      printf 'signed_state_capture_rc=%s\n' "$signed_rc"
      printf '%s\n' "$signed_state"
      printf 'firewall_capture_rc=%s\n' "$firewall_rc"
      printf '%s\n' "$firewall"
      printf 'cluster_node_end\n'
    done < "$NODES_TSV"
    printf 'cluster_snapshot_status=%s\n' "$cluster_status"
    printf '__RNLAB_CLUSTER_END__\n'
  }
}

live_lab_collect_route_matrix_snapshot() {
  local stage_name="${1:-route_matrix}"
  local collected_at source_label source_target source_node_id source_role
  local dest_label dest_target dest_node_id dest_role
  local route_policy_snapshot route_policy_rc
  local source_status_snapshot source_status_rc
  local source_default_route_snapshot source_default_route_rc
  local matrix_status="pass"

  collected_at="$(date -u +%FT%TZ)"
  {
    printf '__RNLAB_ROUTE_MATRIX_BEGIN__\n'
    printf 'route_matrix_version=2\n'
    printf 'route_matrix_stage_name=%s\n' "$stage_name"
    printf 'route_matrix_collected_at_utc=%s\n' "$collected_at"
    printf 'route_matrix_node_count=%s\n' "$(node_count)"
    while IFS=$'\t' read -r source_label source_target source_node_id source_role; do
      [[ -n "$source_target" ]] || continue
      printf 'source_node_begin\n'
      printf 'source_label=%s\n' "$source_label"
      printf 'source_target=%s\n' "$source_target"
      printf 'source_node_id=%s\n' "$source_node_id"
      printf 'source_role=%s\n' "$source_role"
      set +e
      source_status_snapshot="$(live_lab_collect_service_snapshot "$source_target" 2>&1)"
      source_status_rc=$?
      source_default_route_snapshot="$(live_lab_collect_route_policy "$source_target" "1.1.1.1" 2>&1)"
      source_default_route_rc=$?
      set -e
      if [[ "$source_status_rc" -ne 0 || "$source_default_route_rc" -ne 0 ]]; then
        matrix_status="fail"
      fi
      printf 'source_status_capture_rc=%s\n' "$source_status_rc"
      printf '%s\n' "$source_status_snapshot"
      printf 'source_default_route_capture_rc=%s\n' "$source_default_route_rc"
      printf '%s\n' "$source_default_route_snapshot"
      while IFS=$'\t' read -r dest_label dest_target dest_node_id dest_role; do
        [[ -n "$dest_target" ]] || continue
        printf 'pair_begin\n'
        printf 'destination_label=%s\n' "$dest_label"
        printf 'destination_target=%s\n' "$dest_target"
        printf 'destination_node_id=%s\n' "$dest_node_id"
        printf 'destination_role=%s\n' "$dest_role"
        set +e
        route_policy_snapshot="$(live_lab_collect_route_policy "$source_target" "$(live_lab_resolved_target_address "$dest_target")" 2>&1)"
        route_policy_rc=$?
        set -e
        if [[ "$route_policy_rc" -ne 0 ]]; then
          matrix_status="fail"
        fi
        printf 'route_policy_capture_rc=%s\n' "$route_policy_rc"
        printf '%s\n' "$route_policy_snapshot"
        printf 'pair_end\n'
      done < "$NODES_TSV"
      printf 'source_node_end\n'
    done < "$NODES_TSV"
    printf 'route_matrix_status=%s\n' "$matrix_status"
    printf '__RNLAB_ROUTE_MATRIX_END__\n'
    if [[ "$matrix_status" != "pass" ]]; then
      exit 1
    fi
  }
}

run_stage() {
  local severity="$1"
  local stage_name="$2"
  local description="$3"
  shift 3
  local log_path="$LOG_DIR/${stage_name}.log"
  local started_at="$(date -u +%FT%TZ)"
  local finished_at
  local rc
  local status="pass"
  local forensics_dir=""
  printf '[stage:%s] START %s\n' "$stage_name" "$description" | tee "$log_path"
  if (
    set -euo pipefail
    "$@"
  ) 2>&1 | tee -a "$log_path"; then
    rc=0
  else
    rc=$?
  fi
  finished_at="$(date -u +%FT%TZ)"
  if [[ "$rc" -ne 0 ]]; then
    status="fail"
    printf '[stage:%s] FAIL rc=%s\n' "$stage_name" "$rc" | tee -a "$log_path"
    if stage_requires_forensics_bundle "$stage_name"; then
      if forensics_dir="$(collect_cross_network_failure_forensics "$stage_name")"; then
        printf '[stage:%s] forensics bundle: %s\n' "$stage_name" "$forensics_dir" | tee -a "$log_path"
      else
        printf '[stage:%s] warning: failed to collect forensics bundle\n' "$stage_name" | tee -a "$log_path"
      fi
    fi
    printf '[stage:%s] failure digest: %s\n' "$stage_name" "$FAILURE_DIGEST_MD" | tee -a "$log_path"
  else
    printf '[stage:%s] PASS\n' "$stage_name" | tee -a "$log_path"
  fi
  record_stage "$stage_name" "$severity" "$status" "$rc" "$log_path" "$description" "$started_at" "$finished_at"
  update_overall_status "$severity" "$status"
  refresh_failure_digest
  if [[ "$status" == "fail" && "$severity" == "hard" ]]; then
    write_run_summary
    return "$rc"
  fi
  return 0
}

parallel_stage_dir() {
  local stage_name="$1"
  printf '%s/parallel-%s' "$STATE_DIR" "$stage_name"
}

stage_worker_artifact_dir() {
  local label="$1"
  if [[ -z "${LIVE_LAB_STAGE_DIR:-}" ]]; then
    printf 'LIVE_LAB_STAGE_DIR is not set for stage worker artifact capture\n' >&2
    return 1
  fi
  printf '%s/evidence/%s' "$LIVE_LAB_STAGE_DIR" "$label"
}

stage_worker_artifact_path() {
  local label="$1"
  local artifact_name="$2"
  local artifact_dir
  artifact_dir="$(stage_worker_artifact_dir "$label")" || return 1
  mkdir -p "$artifact_dir"
  printf '%s/%s' "$artifact_dir" "$artifact_name"
}

stage_worker_write_artifact() {
  local label="$1"
  local artifact_name="$2"
  local content="$3"
  local artifact_path
  artifact_path="$(stage_worker_artifact_path "$label" "$artifact_name")" || return 1
  printf '%s\n' "$content" > "$artifact_path"
  printf '%s' "$artifact_path"
}

live_lab_extract_primary_failure_reason() {
  local log_path="$1"
  if [[ ! -f "$log_path" ]]; then
    printf 'log file missing'
    return 0
  fi
  awk '
    function trim(value) {
      sub(/^[[:space:]]+/, "", value)
      sub(/[[:space:]]+$/, "", value)
      return value
    }
    /^\[stage:/ && ($0 ~ /] START/ || $0 ~ /] PASS/ || $0 ~ /] FAIL/) { next }
    /^\[parallel:/ { next }
    /^----- / { next }
    {
      line = trim($0)
      gsub(/\r/, "", line)
      if (line == "") {
        next
      }
      lines[++count] = line
    }
    END {
      if (count == 0) {
        print "see full log"
        exit
      }
      for (i = count; i >= 1; i--) {
        lower = tolower(lines[i])
        if (lower ~ /error:|fail|timed out|timeout|permission denied|missing|invalid|mismatch|does not exist|no such|unreachable/) {
          print lines[i]
          exit
        }
      }
      print lines[count]
    }
  ' "$log_path" | head -n 1 | tr '\t\r\n' '   '
}

live_lab_emit_stage_result() {
  local output_tsv="$1"
  local stage_name="$2"
  local label="$3"
  local target="$4"
  local node_id="$5"
  local role="$6"
  local rc="$7"
  local started_at="$8"
  local finished_at="$9"
  local log_path="${10}"
  local snapshot_path="${11:-}"
  local route_policy_path="${12:-}"
  local dns_state_path="${13:-}"
  local primary_failure_reason="${14:-}"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$stage_name" \
    "$label" \
    "$target" \
    "$node_id" \
    "$role" \
    "$rc" \
    "$started_at" \
    "$finished_at" \
    "$log_path" \
    "$snapshot_path" \
    "$route_policy_path" \
    "$dns_state_path" \
    "$(sanitize_text "$primary_failure_reason")" >> "$output_tsv"
}

parallel_stage_scope_matches() {
  local scope="$1"
  local label="$2"
  case "$scope" in
    all) return 0 ;;
    non_exit)
      [[ "$label" != "exit" ]]
      return
      ;;
    exit_only)
      [[ "$label" == "exit" ]]
      return
      ;;
    *)
      printf 'unsupported parallel scope: %s\n' "$scope" >&2
      return 1
      ;;
  esac
}

run_parallel_node_stage() {
  local stage_name="$1"
  local worker_fn="$2"
  local scope="${3:-all}"
  local stage_dir workers_tsv results_tsv worker_count=0 failed=0
  local label target node_id role pid log_path rc started_at finished_at
  local snapshot_path route_policy_path dns_state_path primary_failure_reason
  local -x LIVE_LAB_STAGE_NAME="$stage_name"
  local append_stage_dir="${LIVE_LAB_STAGE_APPEND:-0}"

  case "$scope" in
    all|non_exit|exit_only)
      ;;
    *)
      printf 'unsupported parallel scope: %s\n' "$scope" >&2
      return 1
      ;;
  esac

  stage_dir="$(parallel_stage_dir "$stage_name")"
  local -x LIVE_LAB_STAGE_DIR="$stage_dir"
  workers_tsv="${stage_dir}/workers.tsv"
  results_tsv="${stage_dir}/results.tsv"
  if [[ "$append_stage_dir" != "1" ]]; then
    rm -rf "$stage_dir"
    mkdir -p "$stage_dir"
  else
    mkdir -p "$stage_dir"
    [[ -f "$results_tsv" ]] || : > "$results_tsv"
  fi
  : > "$workers_tsv"
  [[ "$append_stage_dir" == "1" ]] || : > "$results_tsv"

  while IFS=$'\t' read -r label target node_id role; do
    if ! parallel_stage_scope_matches "$scope" "$label"; then
      continue
    fi
    wait_for_parallel_slot "$MAX_PARALLEL_NODE_WORKERS"
    log_path="${stage_dir}/${label}.log"
    started_at="$(date -u +%FT%TZ)"
    (
      set -euo pipefail
      live_lab_prepare_worker_known_hosts "${stage_name}.${label}"
      "$worker_fn" "$label" "$target" "$node_id" "$role"
    ) >"$log_path" 2>&1 &
    pid=$!
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$label" "$target" "$node_id" "$role" "$pid" "$log_path" "$started_at" >> "$workers_tsv"
    worker_count=$((worker_count + 1))
  done < "$NODES_TSV"

  if [[ "$worker_count" -eq 0 ]]; then
    printf '[parallel:%s] no workers matched scope=%s\n' "$stage_name" "$scope"
    return 0
  fi

  while IFS=$'\t' read -r label target node_id role pid log_path started_at; do
    if wait "$pid"; then
      rc=0
    else
      rc=$?
      failed=1
    fi
    finished_at="$(date -u +%FT%TZ)"
    snapshot_path="${stage_dir}/evidence/${label}/snapshot.txt"
    route_policy_path="${stage_dir}/evidence/${label}/route_policy.txt"
    dns_state_path="${stage_dir}/evidence/${label}/dns_state.txt"
    [[ -f "$snapshot_path" ]] || snapshot_path=""
    [[ -f "$route_policy_path" ]] || route_policy_path=""
    [[ -f "$dns_state_path" ]] || dns_state_path=""
    primary_failure_reason=""
    if [[ "$rc" -ne 0 ]]; then
      primary_failure_reason="$(live_lab_extract_primary_failure_reason "$log_path")"
    fi
    live_lab_emit_stage_result \
      "$results_tsv" \
      "$stage_name" \
      "$label" \
      "$target" \
      "$node_id" \
      "$role" \
      "$rc" \
      "$started_at" \
      "$finished_at" \
      "$log_path" \
      "$snapshot_path" \
      "$route_policy_path" \
      "$dns_state_path" \
      "$primary_failure_reason"
    printf '[parallel:%s] %s %s rc=%s\n' "$stage_name" "$label" "$target" "$rc"
    printf -- '----- %s/%s (%s %s) BEGIN -----\n' "$stage_name" "$label" "$node_id" "$role"
    cat "$log_path"
    printf -- '\n----- %s/%s END -----\n' "$stage_name" "$label"
  done < "$workers_tsv"

  [[ "$failed" -eq 0 ]]
}

run_serial_node_stage() {
  local stage_name="$1"
  local worker_fn="$2"
  local scope="${3:-all}"
  local stage_dir workers_tsv results_tsv failed=0
  local label target node_id role log_path rc started_at finished_at
  local snapshot_path route_policy_path dns_state_path primary_failure_reason
  local -x LIVE_LAB_STAGE_NAME="$stage_name"
  local append_stage_dir="${LIVE_LAB_STAGE_APPEND:-0}"

  case "$scope" in
    all|non_exit|exit_only)
      ;;
    *)
      printf 'unsupported serial scope: %s\n' "$scope" >&2
      return 1
      ;;
  esac

  stage_dir="$(parallel_stage_dir "$stage_name")"
  local -x LIVE_LAB_STAGE_DIR="$stage_dir"
  workers_tsv="${stage_dir}/workers.tsv"
  results_tsv="${stage_dir}/results.tsv"
  if [[ "$append_stage_dir" != "1" ]]; then
    rm -rf "$stage_dir"
    mkdir -p "$stage_dir"
  else
    mkdir -p "$stage_dir"
    [[ -f "$results_tsv" ]] || : > "$results_tsv"
  fi
  : > "$workers_tsv"
  [[ "$append_stage_dir" == "1" ]] || : > "$results_tsv"

  while IFS=$'\t' read -r label target node_id role; do
    if ! parallel_stage_scope_matches "$scope" "$label"; then
      continue
    fi
    log_path="${stage_dir}/${label}.log"
    started_at="$(date -u +%FT%TZ)"
    (
      set -euo pipefail
      live_lab_prepare_worker_known_hosts "${stage_name}.${label}"
      "$worker_fn" "$label" "$target" "$node_id" "$role"
    ) >"$log_path" 2>&1
    rc=$?
    finished_at="$(date -u +%FT%TZ)"
    snapshot_path="${stage_dir}/evidence/${label}/snapshot.txt"
    route_policy_path="${stage_dir}/evidence/${label}/route_policy.txt"
    dns_state_path="${stage_dir}/evidence/${label}/dns_state.txt"
    [[ -f "$snapshot_path" ]] || snapshot_path=""
    [[ -f "$route_policy_path" ]] || route_policy_path=""
    [[ -f "$dns_state_path" ]] || dns_state_path=""
    primary_failure_reason=""
    if [[ "$rc" -ne 0 ]]; then
      primary_failure_reason="$(live_lab_extract_primary_failure_reason "$log_path")"
    fi
    live_lab_emit_stage_result \
      "$results_tsv" \
      "$stage_name" \
      "$label" \
      "$target" \
      "$node_id" \
      "$role" \
      "$rc" \
      "$started_at" \
      "$finished_at" \
      "$log_path" \
      "$snapshot_path" \
      "$route_policy_path" \
      "$dns_state_path" \
      "$primary_failure_reason"
    printf '[serial:%s] %s %s rc=%s\n' "$stage_name" "$label" "$target" "$rc"
    printf -- '----- %s/%s (%s %s) BEGIN -----\n' "$stage_name" "$label" "$node_id" "$role"
    cat "$log_path"
    printf -- '\n----- %s/%s END -----\n' "$stage_name" "$label"
    if [[ "$rc" -ne 0 ]]; then
      failed=1
    fi
  done < "$NODES_TSV"

  [[ "$failed" -eq 0 ]]
}

append_env_assignment() {
  local env_path="$1"
  local key="$2"
  local value="$3"
  live_lab_append_env_assignment "$env_path" "$key" "$value"
}

build_nodes_file() {
  : > "$NODES_TSV"
  record_node "exit" "$EXIT_TARGET" "exit-1" "admin"
  record_node "client" "$CLIENT_TARGET" "client-1" "client"
  if [[ -n "$ENTRY_TARGET" ]]; then
    record_node "entry" "$ENTRY_TARGET" "client-2" "client"
  fi
  if [[ -n "$AUX_TARGET" ]]; then
    record_node "aux" "$AUX_TARGET" "client-3" "client"
  fi
  if [[ -n "$EXTRA_TARGET" ]]; then
    record_node "extra" "$EXTRA_TARGET" "client-4" "client"
  fi
  if [[ -n "$FIFTH_CLIENT_TARGET" ]]; then
    record_node "fifth_client" "$FIFTH_CLIENT_TARGET" "client-5" "client"
  fi
}

validate_topology_inputs() {
  local label target host
  local seen_hosts_file="${STATE_DIR}/seen-hosts.tsv"
  : > "$seen_hosts_file"
  while IFS=$'\t' read -r label target _node_id _role; do
    [[ -n "$target" ]] || continue
    validate_target_host "$label" "$target" || return 1
    host="$(host_part_from_target "$target")"
    if awk -F '\t' -v host="$host" '($1 == host) { found=1; exit } END { exit(found ? 0 : 1) }' "$seen_hosts_file"; then
      local prior_label
      prior_label="$(awk -F '\t' -v host="$host" '($1 == host) { print $2; exit }' "$seen_hosts_file")"
      printf 'duplicate host configured for %s and %s: %s\n' "$prior_label" "$label" "$host" >&2
      return 1
    fi
    printf '%s\t%s\n' "$host" "$label" >> "$seen_hosts_file"
  done < "$NODES_TSV"
}

register_cleanup_targets() {
  local target
  while IFS=$'\t' read -r _label target _node_id _role; do
    [[ -n "$target" ]] || continue
    LIVE_LAB_REMOTE_CLEANUP_TARGETS+=("$target")
  done < "$NODES_TSV"
}

write_remote_scripts() {
  cat > "$STATE_DIR/rn_cleanup.sh" <<'EOF_CLEANUP'
#!/usr/bin/env bash
set -euo pipefail

run_root() {
  sudo -n "$@"
}

run_root_timed() {
  local timeout_secs="$1"
  shift
  timeout "$timeout_secs" sudo -n "$@"
}

run_root pkill -f '/tmp/rn_bootstrap.sh' >/dev/null 2>&1 || true
run_root pkill -f '/tmp/rn_bootstrap.env' >/dev/null 2>&1 || true
run_root pkill -f 'rn-sudo-verify' >/dev/null 2>&1 || true
run_root pkill -f 'sudo -A -p .* -k true' >/dev/null 2>&1 || true
run_root pkill -f 'sudo -S -p .* -k true' >/dev/null 2>&1 || true
run_root pkill -f 'apt-get install' >/dev/null 2>&1 || true
run_root pkill -f 'apt-get update' >/dev/null 2>&1 || true
run_root pkill -f '/usr/lib/apt/methods/' >/dev/null 2>&1 || true
run_root pkill -f 'dpkg' >/dev/null 2>&1 || true
run_root pkill -f 'dnf install -y' >/dev/null 2>&1 || true
run_root pkill -f 'cargo build --release -p rustynetd -p rustynet-cli' >/dev/null 2>&1 || true

run_root_timed 30 systemctl stop \
  rustynetd.service \
  rustynetd-privileged-helper.service \
  rustynetd-trust-refresh.service \
  rustynetd-trust-refresh.timer \
  rustynetd-assignment-refresh.service \
  rustynetd-assignment-refresh.timer >/dev/null 2>&1 || true
run_root_timed 30 systemctl disable \
  rustynetd.service \
  rustynetd-privileged-helper.service \
  rustynetd-trust-refresh.service \
  rustynetd-trust-refresh.timer \
  rustynetd-assignment-refresh.service \
  rustynetd-assignment-refresh.timer >/dev/null 2>&1 || true
run_root_timed 30 systemctl disable rustynetd-managed-dns.service >/dev/null 2>&1 || true
if command -v resolvectl >/dev/null 2>&1 && run_root_timed 15 resolvectl status >/dev/null 2>&1; then
  run_root_timed 30 systemctl stop rustynetd-managed-dns.service >/dev/null 2>&1 || true
else
  run_root_timed 30 systemctl kill rustynetd-managed-dns.service >/dev/null 2>&1 || true
fi
run_root_timed 30 systemctl reset-failed rustynetd-managed-dns.service >/dev/null 2>&1 || true
run_root pkill -f 'rustynetd daemon' >/dev/null 2>&1 || true
run_root pkill -f 'rustynetd privileged-helper' >/dev/null 2>&1 || true
run_root_timed 30 ip link set rustynet0 down >/dev/null 2>&1 || true
run_root_timed 30 ip link delete rustynet0 >/dev/null 2>&1 || true
run_root_timed 30 ip route flush table 51820 >/dev/null 2>&1 || true
run_root_timed 30 ip -6 route flush table 51820 >/dev/null 2>&1 || true
if command -v nft >/dev/null 2>&1; then
  for _attempt in 1 2 3; do
    while read -r family table_name; do
      [[ -n "${family}" && -n "${table_name}" ]] || continue
      run_root_timed 30 nft flush table "${family}" "${table_name}" >/dev/null 2>&1 || true
      run_root_timed 30 nft delete table "${family}" "${table_name}" >/dev/null 2>&1 || true
    done < <(run_root_timed 30 nft list tables 2>/dev/null | awk '/^table / && $3 ~ /^rustynet/ { print $2 " " $3 }' | tr -d '\r')
    if ! run_root_timed 30 nft list tables 2>/dev/null | grep -qE '^table [^[:space:]]+ rustynet'; then
      break
    fi
    sleep 1
  done
  if run_root_timed 30 nft list tables 2>/dev/null | grep -qE '^table [^[:space:]]+ rustynet'; then
    echo "residual rustynet nftables state remained after cleanup" >&2
    exit 1
  fi
fi
run_root rm -f \
  /etc/systemd/system/rustynetd.service \
  /etc/systemd/system/rustynetd-privileged-helper.service \
  /etc/systemd/system/rustynetd-managed-dns.service \
  /etc/systemd/system/rustynetd-trust-refresh.service \
  /etc/systemd/system/rustynetd-trust-refresh.timer \
  /etc/systemd/system/rustynetd-assignment-refresh.service \
  /etc/systemd/system/rustynetd-assignment-refresh.timer
run_root_timed 30 systemctl daemon-reload >/dev/null 2>&1 || true
run_root rm -rf /etc/rustynet /var/lib/rustynet /run/rustynet
run_root rm -f /usr/local/bin/rustynet /usr/local/bin/rustynetd
rm -f /tmp/rn_bootstrap.env /tmp/rn_bootstrap.sh /tmp/rn_source.tar.gz
run_root rm -rf "${HOME}/Rustynet"
EOF_CLEANUP
  chmod 700 "$STATE_DIR/rn_cleanup.sh"

  cat > "$STATE_DIR/rn_bootstrap.sh" <<'EOF_BOOTSTRAP'
#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: rn_bootstrap.sh <env-file>" >&2
  exit 2
fi

source "$1"

run_root() {
  sudo -n "$@"
}

run_root_timed() {
  local timeout_secs="$1"
  shift
  timeout "$timeout_secs" sudo -n "$@"
}

run_local_timed() {
  local timeout_secs="$1"
  shift
  timeout "$timeout_secs" "$@"
}

clear_residual_rustynet_state() {
  run_root_timed 30 ip link set rustynet0 down >/dev/null 2>&1 || true
  run_root_timed 30 ip link delete rustynet0 >/dev/null 2>&1 || true
  run_root_timed 30 ip route flush table 51820 >/dev/null 2>&1 || true
  run_root_timed 30 ip -6 route flush table 51820 >/dev/null 2>&1 || true
  if command -v nft >/dev/null 2>&1; then
    for _attempt in $(seq 1 3); do
      while read -r family table_name; do
        [[ -n "${family}" && -n "${table_name}" ]] || continue
        run_root_timed 30 nft flush table "${family}" "${table_name}" >/dev/null 2>&1 || true
        run_root_timed 30 nft delete table "${family}" "${table_name}" >/dev/null 2>&1 || true
      done < <(run_root_timed 30 nft list tables 2>/dev/null | awk '/^table / && $3 ~ /^rustynet/ { print $2 " " $3 }' | tr -d '\r')
      if ! run_root_timed 30 nft list tables 2>/dev/null | grep -qE '^table [^[:space:]]+ rustynet'; then
        break
      fi
      sleep 1
    done
    if run_root_timed 30 nft list tables 2>/dev/null | grep -qE '^table [^[:space:]]+ rustynet'; then
      echo "residual rustynet nftables state remained before bootstrap" >&2
      exit 1
    fi
  fi
}

wait_for_package_manager_idle() {
  local pattern="$1"
  local label="$2"
  local attempt
  for attempt in $(seq 1 60); do
    if ! pgrep -f "$pattern" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "${label} remained busy after waiting for prior lab processes to exit" >&2
  pgrep -af "$pattern" >&2 || true
  exit 1
}

build_bootstrap_prereqs_present() {
  local PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"
  local missing=0
  local cmd
  local llvm_found=0
  for cmd in curl git make pkg-config clang nft wg rustup; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
      echo "[bootstrap] missing prerequisite command: ${cmd}" >&2
      missing=1
    fi
  done
  if ! command -v gcc >/dev/null 2>&1 && ! command -v cc >/dev/null 2>&1; then
    echo "[bootstrap] missing C compiler command (gcc/cc)" >&2
    missing=1
  fi
  if ! command -v g++ >/dev/null 2>&1 && ! command -v c++ >/dev/null 2>&1; then
    echo "[bootstrap] missing C++ compiler command (g++/c++)" >&2
    missing=1
  fi
  if command -v llvm-config >/dev/null 2>&1; then
    llvm_found=1
  else
    for cmd in /usr/bin/llvm-config-* /usr/local/bin/llvm-config-*; do
      [[ -x "${cmd}" ]] || continue
      llvm_found=1
      break
    done
  fi
  if [[ "${llvm_found}" -eq 0 ]]; then
    echo "[bootstrap] missing llvm-config command" >&2
    missing=1
  fi
  if command -v pkg-config >/dev/null 2>&1; then
    if ! pkg-config --exists openssl >/dev/null 2>&1; then
      echo "[bootstrap] missing pkg-config openssl development metadata" >&2
      missing=1
    fi
    if ! pkg-config --exists sqlite3 >/dev/null 2>&1; then
      echo "[bootstrap] missing pkg-config sqlite3 development metadata" >&2
      missing=1
    fi
  fi
  if [[ ! -r /etc/ssl/certs/ca-certificates.crt ]]; then
    echo "[bootstrap] missing readable CA certificate bundle at /etc/ssl/certs/ca-certificates.crt" >&2
    missing=1
  fi
  [[ "${missing}" -eq 0 ]]
}

install_prereqs() {
  local os_id=""
  local os_like=""
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    os_id="${ID:-}"
    os_like="${ID_LIKE:-}"
  fi
  if build_bootstrap_prereqs_present; then
    echo "[bootstrap] prerequisite toolchain already present; skipping package manager mutation" >&2
    return 0
  fi
  if [[ "${os_id}" == "fedora" || "${os_like}" == *"fedora"* || "${os_like}" == *"rhel"* ]]; then
    wait_for_package_manager_idle 'dnf|rpm' 'dnf/rpm'
    run_root_timed 1800 dnf install -y \
      ca-certificates curl git gcc gcc-c++ make pkgconf-pkg-config openssl-devel \
      sqlite-devel clang llvm nftables wireguard-tools rustup
  elif [[ "${os_id}" == "debian" || "${os_id}" == "ubuntu" || "${os_id}" == "linuxmint" || "${os_like}" == *"debian"* ]] || command -v apt-get >/dev/null 2>&1; then
    run_apt_update_hardened
    run_apt_install_hardened \
      ca-certificates curl git build-essential pkg-config libssl-dev libsqlite3-dev \
      clang llvm nftables wireguard-tools openssl systemd-resolved libnss-resolve rustup
  else
    echo "unsupported package manager; expected apt-get or dnf" >&2
    exit 1
  fi
  if ! build_bootstrap_prereqs_present; then
    echo "[bootstrap] prerequisite verification failed after package installation" >&2
    exit 1
  fi
}

ensure_llvm_config_alias() {
  if command -v llvm-config >/dev/null 2>&1; then
    return 0
  fi
  local candidate=""
  for candidate in /usr/bin/llvm-config-* /usr/local/bin/llvm-config-*; do
    [[ -x "${candidate}" ]] || continue
    run_root ln -sf "${candidate}" /usr/local/bin/llvm-config
    return 0
  done
  echo "[bootstrap] unable to locate versioned llvm-config binary" >&2
  return 1
}

run_apt_update_hardened() {
  local attempt
  local apt_log
  local -a apt_network_opts
  apt_network_opts=(
    -o Acquire::Retries=3
    -o Acquire::ForceIPv4=true
    -o Acquire::http::Timeout=60
    -o Acquire::https::Timeout=60
    -o Dpkg::Use-Pty=0
  )
  for attempt in $(seq 1 3); do
    wait_for_package_manager_idle 'apt-get|/usr/lib/apt/methods/|dpkg' 'apt/dpkg'
    apt_log="$(mktemp /tmp/rn-apt-update.XXXXXX.log)"
    if run_root_timed 240 env DEBIAN_FRONTEND=noninteractive apt-get \
      "${apt_network_opts[@]}" \
      update 2>&1 | tee "${apt_log}"; then
      if ! grep -Eiq '(^W: Failed to fetch|Temporary failure resolving|Some index files failed to download)' "${apt_log}"; then
        rm -f "${apt_log}"
        return 0
      fi
      echo "[bootstrap] apt-get update reported fetch warnings; treating as failure" >&2
    fi
    rm -f "${apt_log}"
    if [[ "${attempt}" -lt 3 ]]; then
      echo "[bootstrap] apt-get update attempt ${attempt} failed; retrying after DNS repair" >&2
      run_root_timed 120 env DEBIAN_FRONTEND=noninteractive apt-get clean >/dev/null 2>&1 || true
      repair_bootstrap_dns_state
      sleep 2
    fi
  done
  echo "[bootstrap] apt-get update failed after retries" >&2
  emit_bootstrap_network_diagnostics "deb.debian.org"
  return 1
}

run_apt_install_hardened() {
  local attempt
  local -a apt_network_opts
  apt_network_opts=(
    -o Acquire::Retries=3
    -o Acquire::ForceIPv4=true
    -o Acquire::http::Timeout=60
    -o Acquire::https::Timeout=60
    -o Dpkg::Use-Pty=0
  )
  if [[ "$#" -eq 0 ]]; then
    echo "run_apt_install_hardened requires package names" >&2
    return 2
  fi
  for attempt in $(seq 1 3); do
    if run_root_timed 5400 env DEBIAN_FRONTEND=noninteractive apt-get \
      "${apt_network_opts[@]}" \
      install -y --no-install-recommends "$@"; then
      return 0
    fi
    if [[ "${attempt}" -lt 3 ]]; then
      echo "[bootstrap] apt-get install attempt ${attempt} failed; retrying after DNS repair" >&2
      run_root_timed 120 env DEBIAN_FRONTEND=noninteractive apt-get clean >/dev/null 2>&1 || true
      repair_bootstrap_dns_state
      sleep 2
    fi
  done
  echo "[bootstrap] apt-get install failed after retries" >&2
  emit_bootstrap_network_diagnostics "deb.debian.org"
  return 1
}

repair_managed_dns_prereqs() {
  local os_id=""
  local os_like=""
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    os_id="${ID:-}"
    os_like="${ID_LIKE:-}"
  fi
  if [[ "${os_id}" != "debian" && "${os_id}" != "ubuntu" && "${os_id}" != "linuxmint" && "${os_like}" != *"debian"* ]]; then
    return 0
  fi
  if ! command -v resolvectl >/dev/null 2>&1; then
    echo "managed DNS routing requires resolvectl on Debian-like hosts" >&2
    exit 1
  fi
  run_root systemctl enable --now systemd-resolved.service
  if ! run_root resolvectl status >/dev/null 2>&1; then
    run_root systemctl reload dbus
    run_root systemctl restart systemd-resolved.service
    run_root resolvectl status >/dev/null 2>&1 || {
      echo "managed DNS control plane remained unhealthy after dbus reload and systemd-resolved restart" >&2
      exit 1
    }
  fi
}

repair_local_hostname_resolution() {
  local current_hostname=""
  current_hostname="$(hostname)"
  [[ -n "${current_hostname}" ]] || return 0
  if grep -Eq "(^|[[:space:]])${current_hostname}([[:space:]]|$)" /etc/hosts; then
    return 0
  fi
  run_root sh -c 'printf "\n127.0.1.1\t%s\n" "$1" >> /etc/hosts' sh "${current_hostname}"
}

repair_rustup_toolchain_state() {
  local channel="$1"
  rustup toolchain uninstall "$channel" >/dev/null 2>&1 || true
  rm -rf "$HOME/.rustup/tmp"
  mkdir -p "$HOME/.rustup/downloads" "$HOME/.rustup/toolchains"
  find "$HOME/.rustup/downloads" -maxdepth 1 -type f -delete 2>/dev/null || true
  rm -rf "$HOME/.rustup/toolchains/${channel}" "$HOME/.rustup/toolchains/${channel}.tmp"*
}

repair_bootstrap_dns_state() {
  local default_iface=""
  local default_gateway=""
  default_iface="$(ip -4 route show default 2>/dev/null | awk '/default/ { for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
  default_gateway="$(ip -4 route show default 2>/dev/null | awk '/default/ { print $3; exit }')"

  if command -v systemctl >/dev/null 2>&1; then
    run_root_timed 30 systemctl reload dbus >/dev/null 2>&1 || true
    run_root_timed 30 systemctl enable --now systemd-resolved.service >/dev/null 2>&1 || true
    run_root_timed 30 systemctl restart systemd-resolved.service >/dev/null 2>&1 || true
  fi
  if [[ -e /run/systemd/resolve/stub-resolv.conf ]]; then
    run_root_timed 30 ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf >/dev/null 2>&1 || true
  fi
  if command -v resolvectl >/dev/null 2>&1; then
    if [[ -n "${default_iface}" ]]; then
      run_root_timed 30 resolvectl revert "${default_iface}" >/dev/null 2>&1 || true
      if [[ -n "${default_gateway}" ]]; then
        run_root_timed 30 resolvectl dns "${default_iface}" "${default_gateway}" >/dev/null 2>&1 || true
      fi
      run_root_timed 30 resolvectl domain "${default_iface}" "~." >/dev/null 2>&1 || true
      run_root_timed 30 resolvectl default-route "${default_iface}" yes >/dev/null 2>&1 || true
    fi
    run_root_timed 30 resolvectl flush-caches >/dev/null 2>&1 || true
  elif [[ -n "${default_gateway}" ]]; then
    run_root sh -c 'printf "nameserver %s\noptions timeout:2 attempts:2\n" "$1" > /etc/resolv.conf' sh "${default_gateway}"
  fi
}

emit_bootstrap_network_diagnostics() {
  local host="$1"
  echo "[bootstrap] network diagnostics for host=${host}" >&2
  echo "--- /etc/resolv.conf ---" >&2
  cat /etc/resolv.conf >&2 || true
  echo "--- ip -4 route ---" >&2
  ip -4 route >&2 || true
  echo "--- ip -4 addr ---" >&2
  ip -4 addr >&2 || true
  if command -v resolvectl >/dev/null 2>&1; then
    echo "--- resolvectl status ---" >&2
    run_root_timed 30 resolvectl status >&2 || true
    echo "--- resolvectl query ${host} ---" >&2
    run_root_timed 30 resolvectl query "${host}" >&2 || true
  fi
  echo "--- getent ahosts ${host} ---" >&2
  getent ahosts "${host}" >&2 || true
}

wait_for_bootstrap_rustup_endpoint() {
  local channel="$1"
  local endpoint="https://static.rust-lang.org/dist/channel-rust-${channel}.toml.sha256"
  local attempt
  for attempt in $(seq 1 8); do
    if run_local_timed 60 curl --ipv4 --fail --silent --show-error --head "${endpoint}" >/dev/null 2>&1; then
      return 0
    fi
    repair_bootstrap_dns_state
    sleep 2
  done
  echo "[bootstrap] failed to reach Rust toolchain endpoint: ${endpoint}" >&2
  emit_bootstrap_network_diagnostics "static.rust-lang.org"
  return 1
}

install_rust_toolchain_hardened() {
  local channel="$1"
  local attempt
  wait_for_bootstrap_rustup_endpoint "${channel}" || return 1
  for attempt in $(seq 1 3); do
    if run_local_timed 3600 env \
      RUSTUP_DOWNLOAD_TIMEOUT=600 \
      RUSTUP_CONCURRENT_DOWNLOADS=1 \
      rustup toolchain install "${channel}" --profile minimal; then
      return 0
    fi
    if [[ "${attempt}" -lt 3 ]]; then
      echo "[bootstrap] rustup install attempt ${attempt} failed; retrying after DNS repair" >&2
      repair_bootstrap_dns_state
      wait_for_bootstrap_rustup_endpoint "${channel}" || true
      sleep 2
    fi
  done
  echo "[bootstrap] rustup toolchain install failed after retries for channel ${channel}" >&2
  emit_bootstrap_network_diagnostics "static.rust-lang.org"
  return 1
}

clear_residual_rustynet_state
repair_local_hostname_resolution
install_prereqs
ensure_llvm_config_alias
repair_managed_dns_prereqs
if ! command -v rustup >/dev/null 2>&1; then
  echo "rustup is required on test hosts; missing after prerequisite install" >&2
  exit 1
fi

rm -rf "${HOME}/Rustynet"
mkdir -p "${HOME}/Rustynet"
tar -xzf "${SOURCE_ARCHIVE}" -C "${HOME}/Rustynet"
cd "${HOME}/Rustynet"

RUST_TOOLCHAIN_CHANNEL="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' rust-toolchain.toml 2>/dev/null | head -n 1)"
if [[ -z "${RUST_TOOLCHAIN_CHANNEL}" ]]; then
  echo "failed to determine required Rust toolchain from rust-toolchain.toml" >&2
  exit 1
fi

export PATH="${HOME}/.cargo/bin:${PATH}"
rustup set profile minimal
if ! rustup run "${RUST_TOOLCHAIN_CHANNEL}" rustc --version >/dev/null 2>&1 || ! rustup run "${RUST_TOOLCHAIN_CHANNEL}" cargo --version >/dev/null 2>&1; then
  repair_rustup_toolchain_state "${RUST_TOOLCHAIN_CHANNEL}"
  install_rust_toolchain_hardened "${RUST_TOOLCHAIN_CHANNEL}"
fi
rustup default "${RUST_TOOLCHAIN_CHANNEL}"

run_local_timed 7200 rustup run "${RUST_TOOLCHAIN_CHANNEL}" cargo build --release -p rustynetd -p rustynet-cli
run_root install -m 0755 target/release/rustynetd /usr/local/bin/rustynetd
run_root install -m 0755 target/release/rustynet-cli /usr/local/bin/rustynet
backend_env=()
if [[ -n "${RUSTYNET_BACKEND:-}" ]]; then
  backend_env+=(RUSTYNET_BACKEND="${RUSTYNET_BACKEND}")
fi
run_root env RUSTYNET_INSTALL_SOURCE_ROOT="${HOME}/Rustynet" "${backend_env[@]}" \
  rustynet ops e2e-bootstrap-host \
  --role "${ROLE}" \
  --node-id "${NODE_ID}" \
  --network-id "${NETWORK_ID}" \
  --src-dir "${HOME}/Rustynet" \
  --ssh-allow-cidrs "${SSH_ALLOW_CIDRS}" \
  --skip-apt
EOF_BOOTSTRAP
  chmod 700 "$STATE_DIR/rn_bootstrap.sh"
}

prime_remote_access() {
  run_serial_node_stage prime_remote_access prime_remote_access_worker
}

stage_verify_ssh_reachability() {
  local force_ssh_for_reachability=0
  if live_lab_has_utm_transport && live_lab_can_use_ssh_transport; then
    export LIVE_LAB_FORCE_SSH_TRANSPORT=1
    force_ssh_for_reachability=1
  fi
  run_parallel_node_stage verify_ssh_reachability ssh_reachability_worker
  local rc=$?
  if (( force_ssh_for_reachability )); then
    unset LIVE_LAB_FORCE_SSH_TRANSPORT
  fi
  return "$rc"
}

ssh_reachability_worker() {
  local label="$1"
  local target="$2"
  printf '[ssh-reachable] %s %s\n' "$label" "$target"
  ssh_wait_for_host "$target" 120 5 || return 1
}

prime_remote_access_worker() {
  local label="$1"
  local target="$2"
  printf '[prime-remote] %s %s\n' "$label" "$target"
  # Keep this stage safe if it is invoked directly, even though the composed
  # setup wrapper now performs an explicit SSH reachability gate first.
  ssh_reachability_worker "$label" "$target" || return 1
  live_lab_push_sudo_password "$target"
}

stage_preflight() {
  require_cmd bash
  require_cmd git
  require_cmd tar
  require_cmd expect
  require_cmd rg
  require_cmd awk
  require_cmd openssl
  require_cmd xxd
  require_cmd scp
  require_cmd ssh
  if [[ "$RUN_LOCAL_GATES" -eq 1 ]]; then
    require_cmd cargo
    require_cmd rustup
  fi
}

stage_prepare_source_archive() {
  local archive_ref=""
  local tar_version
  local -a tar_flags=()
  write_remote_scripts
  printf 'source mode: %s\n' "$(describe_source_mode)"
  if [[ "$SOURCE_MODE" == "working-tree" ]]; then
    tar_version="$(tar --version 2>/dev/null || true)"
    tar_version="${tar_version%%$'\n'*}"
    if [[ "$tar_version" == *"bsdtar"* ]]; then
      # Prevent host-local metadata leakage into deployment archives on macOS.
      tar_flags+=(--no-mac-metadata --no-xattrs --no-acls --no-fflags)
    fi
    COPYFILE_DISABLE=1 tar "${tar_flags[@]}" -C "$ROOT_DIR" \
      --exclude='.git' \
      --exclude='target' \
      --exclude='.cargo-home' \
      --exclude='.ci-home' \
      --exclude='artifacts/live_lab' \
      -czf "$SOURCE_ARCHIVE" .
  else
    archive_ref="$(resolve_source_ref)"
    fetch_git_ref_if_needed "$archive_ref"
    git -C "$ROOT_DIR" archive --format=tar.gz --output "$SOURCE_ARCHIVE" "$archive_ref"
  fi
  if [[ "$SOURCE_MODE" == "working-tree" ]]; then
    git rev-parse HEAD > "$STATE_DIR/git_head.txt"
  else
    git -C "$ROOT_DIR" rev-parse "$(resolve_source_ref)" > "$STATE_DIR/git_head.txt"
  fi
  git status --short > "$STATE_DIR/git_status.txt"
  printf '%s\n' "$(describe_source_mode)" > "$STATE_DIR/source_mode.txt"
}

stage_run_fresh_bootstrap_and_network_setup() {
  run_setup_stage hard prepare_source_archive 'package local source tree for remote install' stage_prepare_source_archive || return 1
  run_setup_stage hard verify_ssh_reachability 'verify all selected nodes are reachable via ssh' stage_verify_ssh_reachability || return 1
  run_setup_stage hard prime_remote_access 'push sudo credentials to all targets' prime_remote_access || return 1
  run_setup_stage hard cleanup_hosts 'remove prior RustyNet state from targets' stage_cleanup_hosts || return 1
  run_setup_stage hard bootstrap_hosts 'fresh install and bootstrap RustyNet on all targets' stage_bootstrap_hosts || return 1
  run_setup_stage hard collect_pubkeys 'collect WireGuard public keys from all targets' stage_collect_pubkeys || return 1
  run_setup_stage hard membership_setup 'apply signed membership updates on primary exit' stage_membership_setup || return 1
  run_setup_stage hard distribute_membership_state 'export and install membership state to peers' stage_distribute_membership_state || return 1
  run_setup_stage hard issue_and_distribute_assignments 'issue signed one-hop assignments and install refresh env files' stage_issue_and_distribute_assignments || return 1
  run_setup_stage hard issue_and_distribute_traversal 'issue and distribute signed traversal bundles for all managed peers' stage_issue_and_distribute_traversal || return 1
  run_setup_stage hard issue_and_distribute_dns_zone 'issue and distribute signed DNS zone bundles for all managed peers' stage_issue_and_distribute_dns_zone || return 1
  run_setup_stage hard enforce_baseline_runtime 'enforce baseline runtime roles and advertise exit route' stage_enforce_baseline_runtime || return 1
  run_setup_stage hard validate_baseline_runtime 'validate one-hop routing and no-plaintext-passphrase state' stage_validate_baseline_runtime || return 1
}

stage_cleanup_hosts() {
  run_serial_node_stage cleanup_hosts cleanup_host_worker
}

cleanup_host_worker() {
  local label="$1"
  local target="$2"
  printf '[cleanup] %s %s\n' "$label" "$target"
  ssh_wait_for_host "$target" 120 5 || return 1
  live_lab_scp_to "$STATE_DIR/rn_cleanup.sh" "$target" "/tmp/rn_cleanup.sh"
  live_lab_ssh "$target" "chmod 700 /tmp/rn_cleanup.sh && bash /tmp/rn_cleanup.sh"
}

stage_bootstrap_hosts() {
  run_parallel_node_stage bootstrap_hosts bootstrap_host_worker
}

bootstrap_host_worker() {
  local label="$1"
  local target="$2"
  local node_id="$3"
  local role="$4"
  local env_path
  local attempt max_attempts=12 sleep_secs=10
  ssh_wait_for_host "$target" || return 1
  live_lab_push_sudo_password "$target"
  env_path="$STATE_DIR/bootstrap-${label}.env"
  cat > "$env_path" <<EOF_ENV
ROLE=${role}
NODE_ID=${node_id}
NETWORK_ID=${NETWORK_ID}
SSH_ALLOW_CIDRS=${SSH_ALLOW_CIDRS}
SOURCE_ARCHIVE=/tmp/rn_source.tar.gz
EOF_ENV
  if [[ -n "${RUSTYNET_BACKEND:-}" ]]; then
    printf 'RUSTYNET_BACKEND=%s\n' "${RUSTYNET_BACKEND}" >> "$env_path"
  fi
  printf '[bootstrap] %s %s (%s %s)\n' "$label" "$target" "$node_id" "$role"
  for attempt in $(seq 1 "$max_attempts"); do
    if live_lab_scp_to "$STATE_DIR/rn_bootstrap.sh" "$target" "/tmp/rn_bootstrap.sh" &&
      live_lab_scp_to "$env_path" "$target" "/tmp/rn_bootstrap.env" &&
      live_lab_scp_to "$SOURCE_ARCHIVE" "$target" "/tmp/rn_source.tar.gz" &&
      live_lab_ssh "$target" "chmod 700 /tmp/rn_bootstrap.sh && bash /tmp/rn_bootstrap.sh /tmp/rn_bootstrap.env" &&
      live_lab_wait_for_daemon_socket "$target" &&
      live_lab_run_root "$target" "root test -x /usr/local/bin/rustynet && root test -x /usr/local/bin/rustynetd && root test -f /var/lib/rustynet/keys/wireguard.pub && root getent group rustynetd >/dev/null 2>&1"
    then
      return 0
    fi
    if [[ "$attempt" -lt "$max_attempts" ]]; then
      sleep "$sleep_secs"
    fi
  done
  return 1
}

stage_collect_pubkeys() {
  local label
  local stage_dir
  : > "$PUBKEYS_TSV"
  stage_dir="$(parallel_stage_dir collect_pubkeys)"
  run_parallel_node_stage collect_pubkeys collect_pubkey_worker
  while IFS=$'\t' read -r label _target _node_id _role; do
    if [[ ! -f "${stage_dir}/pubkey-${label}.tsv" ]]; then
      printf 'missing pubkey result for %s\n' "$label" >&2
      return 1
    fi
    cat "${stage_dir}/pubkey-${label}.tsv" >> "$PUBKEYS_TSV"
  done < "$NODES_TSV"
}

collect_pubkey_worker() {
  local label="$1"
  local target="$2"
  local node_id="$3"
  local pub_hex
  local stage_dir result_path
  stage_dir="$(parallel_stage_dir collect_pubkeys)"
  result_path="${stage_dir}/pubkey-${label}.tsv"
  if ! pub_hex="$(live_lab_collect_pubkey_hex "$target")"; then
    return 1
  fi
  if [[ -z "$pub_hex" ]]; then
    echo "failed to collect wireguard pubkey for ${target}" >&2
    return 1
  fi
  printf '%s\t%s\t%s\t%s\n' "$label" "$target" "$node_id" "$pub_hex" > "$result_path"
  printf '[pubkey] %s %s %s\n' "$label" "$target" "$pub_hex"
}

build_onehop_specs() {
  local nodes_spec=""
  local allow_spec=""
  local assignments_spec=""
  local exit_target exit_node_id target node_id pub_hex first="1"
  exit_target="$(node_target_for_label exit)"
  exit_node_id="$(node_id_for_label exit)"
  while IFS=$'\t' read -r _label target node_id pub_hex; do
    if [[ "$first" == "1" ]]; then
      nodes_spec="${node_id}|$(live_lab_resolved_target_address "$target"):51820|${pub_hex}"
      first="0"
    else
      nodes_spec="${nodes_spec};${node_id}|$(live_lab_resolved_target_address "$target"):51820|${pub_hex}"
    fi
    if [[ "$node_id" == "$exit_node_id" ]]; then
      assignments_spec="${assignments_spec:+${assignments_spec};}${node_id}|-"
    else
      allow_spec="${allow_spec:+${allow_spec};}${node_id}|${exit_node_id};${exit_node_id}|${node_id}"
      assignments_spec="${assignments_spec:+${assignments_spec};}${node_id}|${exit_node_id}"
    fi
  done < "$PUBKEYS_TSV"

  cat > "$ONEHOP_STATE_ENV" <<EOF_ENV
NODES_SPEC=$(quote_env "$nodes_spec")
ALLOW_SPEC=$(quote_env "$allow_spec")
ASSIGNMENTS_SPEC=$(quote_env "$assignments_spec")
EXIT_TARGET=$(quote_env "$exit_target")
EXIT_NODE_ID=$(quote_env "$exit_node_id")
EOF_ENV
}

quote_env() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//\$/\\\$}"
  value="${value//\`/\\\`}"
  printf '"%s"' "$value"
}

stage_membership_setup() {
  local exit_target exit_node_id target node_id pub_hex owner_approver_id
  exit_target="$(node_target_for_label exit)"
  exit_node_id="$(node_id_for_label exit)"
  owner_approver_id="${exit_node_id}-owner"
  live_lab_run_root "$exit_target" "root test -f /var/lib/rustynet/membership.snapshot && root test -f /var/lib/rustynet/membership.log && root test -f /var/lib/rustynet/membership.watermark && root chown rustynetd:rustynetd /var/lib/rustynet/membership.snapshot /var/lib/rustynet/membership.log /var/lib/rustynet/membership.watermark && root chmod 0600 /var/lib/rustynet/membership.snapshot /var/lib/rustynet/membership.log /var/lib/rustynet/membership.watermark" || return 1
  while IFS=$'\t' read -r _label target node_id pub_hex; do
    [[ "$node_id" == "$exit_node_id" ]] && continue
    live_lab_run_root "$exit_target" "root rustynet ops e2e-membership-add --client-node-id '${node_id}' --client-pubkey-hex '${pub_hex}' --owner-approver-id '${owner_approver_id}'" || return 1
  done < "$PUBKEYS_TSV"
}

stage_distribute_membership_state() {
  local exit_target target snapshot_local log_local
  exit_target="$(node_target_for_label exit)"
  snapshot_local="$STATE_DIR/membership.snapshot"
  log_local="$STATE_DIR/membership.log"
  live_lab_capture_root "$exit_target" "root cat /var/lib/rustynet/membership.snapshot" > "$snapshot_local" || return 1
  live_lab_capture_root "$exit_target" "root cat /var/lib/rustynet/membership.log" > "$log_local" || return 1
  run_parallel_node_stage distribute_membership_state distribute_membership_worker non_exit
}

distribute_membership_worker() {
  local label="$1"
  local target="$2"
  printf '[membership-distribute] %s %s\n' "$label" "$target"
  live_lab_scp_to "$STATE_DIR/membership.snapshot" "$target" "/tmp/rn-membership.snapshot"
  live_lab_scp_to "$STATE_DIR/membership.log" "$target" "/tmp/rn-membership.log"
  live_lab_run_root "$target" "root mkdir -p /var/lib/rustynet && root install -m 0600 -o rustynetd -g rustynetd /tmp/rn-membership.snapshot /var/lib/rustynet/membership.snapshot && root install -m 0600 -o rustynetd -g rustynetd /tmp/rn-membership.log /var/lib/rustynet/membership.log && root rm -f /var/lib/rustynet/membership.watermark /tmp/rn-membership.snapshot /tmp/rn-membership.log"
}

stage_issue_and_distribute_assignments() {
  local exit_target env_path verifier_local
  build_onehop_specs
  # shellcheck disable=SC1090
  source "$ONEHOP_STATE_ENV"
  exit_target="$EXIT_TARGET"
  env_path="$STATE_DIR/issue_assignments.env"
  : > "$env_path"
  append_env_assignment "$env_path" "NODES_SPEC" "$NODES_SPEC"
  append_env_assignment "$env_path" "ALLOW_SPEC" "$ALLOW_SPEC"
  append_env_assignment "$env_path" "ASSIGNMENTS_SPEC" "$ASSIGNMENTS_SPEC"
  live_lab_issue_assignment_bundles_from_env "$exit_target" "$env_path" "/tmp/rn_issue_assignments.env" || return 1

  verifier_local="$STATE_DIR/assignment.pub"
  live_lab_fetch_root_file_to_local "$exit_target" "/run/rustynet/assignment-issue/rn-assignment.pub" "$verifier_local" || return 1
  run_parallel_node_stage issue_and_distribute_assignments distribute_assignment_worker
}

distribute_assignment_worker() {
  local _label="$1"
  local target="$2"
  local node_id="$3"
  local bundle_local refresh_env exit_target exit_node_id
  # shellcheck disable=SC1090
  source "$ONEHOP_STATE_ENV"
  exit_target="$EXIT_TARGET"
  exit_node_id="$(node_id_for_label exit)"
  bundle_local="$STATE_DIR/assignment-${node_id}.bundle"
  refresh_env="$STATE_DIR/assignment-refresh-${node_id}.env"
  printf '[assignment-distribute] %s %s\n' "$node_id" "$target"
  live_lab_fetch_root_file_to_local "$exit_target" "/run/rustynet/assignment-issue/rn-assignment-${node_id}.assignment" "$bundle_local" || return 1
  live_lab_install_assignment_bundle "$target" "$STATE_DIR/assignment.pub" "$bundle_local"
  if [[ "$node_id" == "$exit_node_id" ]]; then
    live_lab_write_assignment_refresh_env "$refresh_env" "$node_id" "$NODES_SPEC" "$ALLOW_SPEC"
  else
    live_lab_write_assignment_refresh_env "$refresh_env" "$node_id" "$NODES_SPEC" "$ALLOW_SPEC" "$exit_node_id"
  fi
  live_lab_install_assignment_refresh_env "$target" "$refresh_env"
}

issue_and_distribute_traversal_snapshot() {
  local stage_name="$1"
  local exit_target env_path verifier_local
  build_onehop_specs
  # shellcheck disable=SC1090
  source "$ONEHOP_STATE_ENV"
  exit_target="$EXIT_TARGET"
  env_path="$STATE_DIR/issue_traversal.env"
  : > "$env_path"
  append_env_assignment "$env_path" "NODES_SPEC" "$NODES_SPEC"
  append_env_assignment "$env_path" "ALLOW_SPEC" "$ALLOW_SPEC"
  append_env_assignment "$env_path" "TRAVERSAL_TTL_SECS" "$TRAVERSAL_TTL_SECS"
  live_lab_issue_traversal_bundles_from_env "$exit_target" "$env_path" "/tmp/rn_issue_traversal.env" || return 1

  verifier_local="$STATE_DIR/traversal.pub"
  live_lab_fetch_root_file_to_local "$exit_target" "/run/rustynet/traversal-issue/rn-traversal.pub" "$verifier_local" || return 1
  run_parallel_node_stage "$stage_name" distribute_traversal_worker
}

stage_issue_and_distribute_traversal() {
  issue_and_distribute_traversal_snapshot issue_and_distribute_traversal
}

issue_and_distribute_dns_zone_snapshot() {
  local stage_name="$1"
  local exit_target env_path verifier_local
  build_onehop_specs
  # shellcheck disable=SC1090
  source "$ONEHOP_STATE_ENV"
  exit_target="$EXIT_TARGET"
  env_path="$STATE_DIR/issue_dns_zone.env"
  : > "$env_path"
  append_env_assignment "$env_path" "NODES_SPEC" "$NODES_SPEC"
  append_env_assignment "$env_path" "ALLOW_SPEC" "$ALLOW_SPEC"
  append_env_assignment "$env_path" "DNS_ZONE_NAME" "${RUSTYNET_DNS_ZONE_NAME:-rustynet}"
  live_lab_issue_dns_zone_bundles_from_env "$exit_target" "$env_path" "/tmp/rn_issue_dns_zone.env" || return 1

  verifier_local="$STATE_DIR/dns-zone.pub"
  live_lab_fetch_root_file_to_local "$exit_target" "/run/rustynet/dns-zone-issue/rn-dns-zone.pub" "$verifier_local" || return 1
  run_parallel_node_stage "$stage_name" distribute_dns_zone_worker
}

stage_issue_and_distribute_dns_zone() {
  issue_and_distribute_dns_zone_snapshot issue_and_distribute_dns_zone
}

distribute_traversal_worker() {
  local _label="$1"
  local target="$2"
  local node_id="$3"
  local bundle_local exit_target
  # shellcheck disable=SC1090
  source "$ONEHOP_STATE_ENV"
  exit_target="$EXIT_TARGET"
  bundle_local="$STATE_DIR/traversal-${node_id}.bundle"
  printf '[traversal-distribute] %s %s\n' "$node_id" "$target"
  live_lab_ensure_rustynetd_group "$target" || return 1
  live_lab_fetch_root_file_to_local "$exit_target" "/run/rustynet/traversal-issue/rn-traversal-${node_id}.traversal" "$bundle_local" || return 1
  live_lab_scp_to "$STATE_DIR/traversal.pub" "$target" "/tmp/rn-traversal.pub"
  live_lab_scp_to "$bundle_local" "$target" "/tmp/rn-traversal.bundle"
  live_lab_run_root "$target" "root install -d -m 0750 -o root -g rustynetd /etc/rustynet && root install -d -m 0700 -o rustynetd -g rustynetd /var/lib/rustynet && root install -m 0644 -o root -g root /tmp/rn-traversal.pub /etc/rustynet/traversal.pub && root install -m 0640 -o root -g rustynetd /tmp/rn-traversal.bundle /var/lib/rustynet/rustynetd.traversal && root rm -f /var/lib/rustynet/rustynetd.traversal.watermark /tmp/rn-traversal.pub /tmp/rn-traversal.bundle"
}

distribute_dns_zone_worker() {
  local _label="$1"
  local target="$2"
  local node_id="$3"
  local bundle_local exit_target
  # shellcheck disable=SC1090
  source "$ONEHOP_STATE_ENV"
  exit_target="$EXIT_TARGET"
  bundle_local="$STATE_DIR/dns-zone-${node_id}.bundle"
  printf '[dns-zone-distribute] %s %s\n' "$node_id" "$target"
  live_lab_fetch_root_file_to_local "$exit_target" "/run/rustynet/dns-zone-issue/rn-dns-zone-${node_id}.dns-zone" "$bundle_local" || return 1
  live_lab_install_dns_zone_bundle "$target" "$STATE_DIR/dns-zone.pub" "$bundle_local"
}

stage_enforce_baseline_runtime() {
  run_parallel_node_stage enforce_baseline_runtime enforce_runtime_worker
  run_parallel_node_stage refresh_runtime_after_enforce refresh_runtime_state_worker
  live_lab_retry_root "$(node_target_for_label exit)" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 0.0.0.0/0" 10 2 || return 1
  sleep 5
  # Refresh traversal coordination immediately before baseline validation so the
  # 30-second signed-coordination window is not spent on earlier enforcement work.
  issue_and_distribute_traversal_snapshot refresh_traversal_after_enforce || return 1
  run_parallel_node_stage refresh_runtime_after_traversal refresh_signed_state_worker
}

enforce_runtime_worker() {
  local label="$1"
  local target="$2"
  local node_id="$3"
  local role="$4"
  printf '[runtime-enforce] %s %s (%s %s)\n' "$label" "$target" "$node_id" "$role"
  live_lab_enforce_host "$target" "$role" "$node_id" "$SSH_ALLOW_CIDRS" "$(live_lab_remote_src_dir "$target")"
  live_lab_wait_for_daemon_socket "$target"
}

refresh_runtime_state_worker() {
  local label="$1"
  local target="$2"
  local node_id="$3"
  local _role="$4"
  printf '[runtime-refresh] %s %s (%s)\n' "$label" "$target" "$node_id"
  live_lab_run_root "$target" "root rustynet ops force-local-assignment-refresh-now"
  live_lab_wait_for_daemon_socket "$target"
}

refresh_runtime_state_all_nodes() {
  local refresh_label refresh_target refresh_node_id refresh_role
  while IFS=$'\t' read -r refresh_label refresh_target refresh_node_id refresh_role; do
    [[ -n "$refresh_target" ]] || continue
    refresh_runtime_state_worker "$refresh_label" "$refresh_target" "$refresh_node_id" "$refresh_role" || return 1
  done < "$NODES_TSV"
}

refresh_runtime_state_for_label() {
  local refresh_label="$1"
  local refresh_target refresh_node_id refresh_role
  refresh_target="$(node_target_for_label "$refresh_label")"
  refresh_node_id="$(node_id_for_label "$refresh_label")"
  refresh_role="$(node_role_for_label "$refresh_label")"
  [[ -n "$refresh_target" && -n "$refresh_node_id" && -n "$refresh_role" ]] || {
    printf 'missing runtime refresh metadata for label: %s\n' "$refresh_label" >&2
    return 1
  }
  refresh_runtime_state_worker "$refresh_label" "$refresh_target" "$refresh_node_id" "$refresh_role"
}

refresh_signed_state_for_label() {
  local refresh_label="$1"
  local refresh_target refresh_node_id refresh_role
  refresh_target="$(node_target_for_label "$refresh_label")"
  refresh_node_id="$(node_id_for_label "$refresh_label")"
  refresh_role="$(node_role_for_label "$refresh_label")"
  [[ -n "$refresh_target" && -n "$refresh_node_id" && -n "$refresh_role" ]] || {
    printf 'missing signed-state refresh metadata for label: %s\n' "$refresh_label" >&2
    return 1
  }
  refresh_signed_state_worker "$refresh_label" "$refresh_target" "$refresh_node_id" "$refresh_role"
}

validation_runtime_refresh_order() {
  local target_label="$1"
  if [[ "$target_label" != "exit" ]]; then
    printf 'exit\n'
  fi
  printf '%s\n' "$target_label"
}

refresh_runtime_state_for_validation() {
  local target_label="$1"
  local refresh_label
  while IFS= read -r refresh_label; do
    [[ -n "$refresh_label" ]] || continue
    refresh_runtime_state_for_label "$refresh_label" || return 1
  done < <(validation_runtime_refresh_order "$target_label")
}

refresh_runtime_state_for_validation_cluster() {
  # Peer coordination is directional. Refresh client roles first so the exit
  # can consume their latest coordination, then refresh the exit, then refresh
  # client roles again so they can consume the exit coordination that was just
  # published. This avoids the parallel race where exit and clients refresh
  # against stale peer coordination in the same moment.
  run_parallel_node_stage refresh_runtime_before_validate_non_exit refresh_runtime_state_worker non_exit || return 1
  refresh_runtime_state_for_label exit || return 1
  run_parallel_node_stage refresh_runtime_after_exit_before_validate refresh_runtime_state_worker non_exit || return 1
}

issue_baseline_validation_artifacts() {
  local traversal_stage_name="$1"
  local dns_stage_name="$2"
  issue_and_distribute_traversal_snapshot "$traversal_stage_name" || return 1
  issue_and_distribute_dns_zone_snapshot "$dns_stage_name" || return 1
}

prime_baseline_runtime_validation_state() {
  issue_baseline_validation_artifacts refresh_traversal_before_validate refresh_dns_zone_before_validate || return 1
  refresh_runtime_state_for_validation_cluster || return 1
}

live_lab_collect_baseline_runtime_cluster_snapshot() {
  local expected_membership_nodes exit_node_id
  local label target node_id role snapshot capture_rc ready
  local overall_status="pass"

  expected_membership_nodes="$(node_count)"
  exit_node_id="$(node_id_for_label exit)"

  {
    printf '__RNLAB_BASELINE_CLUSTER_BEGIN__\n'
    printf 'baseline_cluster_version=1\n'
    printf 'baseline_cluster_collected_at_utc=%s\n' "$(date -u +%FT%TZ)"
    while IFS=$'\t' read -r label target node_id role; do
      [[ -n "$target" ]] || continue
      set +e
      snapshot="$(live_lab_collect_runtime_validation_snapshot "$target" "$node_id" "$role" 2>&1)"
      capture_rc=$?
      set -e
      ready=0
      if [[ "$capture_rc" -eq 0 ]] && live_lab_runtime_snapshot_ready \
        "$snapshot" \
        "$node_id" \
        "$target" \
        "$role" \
        "$expected_membership_nodes" \
        "$exit_node_id" >/dev/null 2>&1; then
        ready=1
      else
        overall_status="fail"
      fi
      printf 'node_begin\n'
      printf 'label=%s\n' "$label"
      printf 'target=%s\n' "$target"
      printf 'node_id=%s\n' "$node_id"
      printf 'role=%s\n' "$role"
      printf 'capture_rc=%s\n' "$capture_rc"
      printf 'runtime_ready=%s\n' "$ready"
      printf '%s\n' "$snapshot"
      printf 'node_end\n'
    done < "$NODES_TSV"
    printf 'baseline_cluster_status=%s\n' "$overall_status"
    printf '__RNLAB_BASELINE_CLUSTER_END__\n'
  }
}

baseline_cluster_not_ready_labels() {
  local snapshot="$1"
  awk '
    /^node_begin$/ {
      in_node = 1
      label = ""
      ready = ""
      next
    }
    /^node_end$/ {
      if (in_node && ready == "0" && label != "") {
        print label
      }
      in_node = 0
      next
    }
    in_node && /^label=/ {
      label = substr($0, length("label=") + 1)
      next
    }
    in_node && /^runtime_ready=/ {
      ready = substr($0, length("runtime_ready=") + 1)
      next
    }
  ' <<<"$snapshot"
}

wait_for_baseline_runtime_cluster_convergence() {
  local cluster_snapshot
  local attempts=120
  local sleep_secs=2
  local refresh_every_attempts=60
  local targeted_refresh_after_attempt=30
  local attempt
  local not_ready_labels=()
  local label
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    cluster_snapshot="$(live_lab_collect_baseline_runtime_cluster_snapshot 2>&1)" || cluster_snapshot="${cluster_snapshot:-}"
    if [[ "$cluster_snapshot" == *"baseline_cluster_status=pass"* ]]; then
      printf '[baseline-cluster]\n%s\n' "$cluster_snapshot"
      return 0
    fi
    if (( attempt >= targeted_refresh_after_attempt )); then
      not_ready_labels=()
      while IFS= read -r label; do
        [[ -n "$label" ]] || continue
        not_ready_labels+=("$label")
      done < <(baseline_cluster_not_ready_labels "$cluster_snapshot")
      if (( ${#not_ready_labels[@]} > 0 && ${#not_ready_labels[@]} < $(node_count) )); then
        printf '[baseline-cluster-targeted-refresh] attempt=%s labels=%s\n' "$attempt" "${not_ready_labels[*]}"
        for label in "${not_ready_labels[@]}"; do
          refresh_runtime_state_for_label "$label" || return 1
        done
      fi
    fi
    if (( attempt % refresh_every_attempts == 0 )); then
      printf '[baseline-cluster-refresh] attempt=%s\n' "$attempt"
      prime_baseline_runtime_validation_state || return 1
    fi
    if (( attempt < attempts )); then
      sleep "$sleep_secs"
    fi
  done
  printf '[baseline-cluster]\n%s\n' "$cluster_snapshot"
  return 1
}

refresh_signed_state_for_validation() {
  local target_label="$1"
  local refresh_label
  while IFS= read -r refresh_label; do
    [[ -n "$refresh_label" ]] || continue
    refresh_signed_state_for_label "$refresh_label" || return 1
  done < <(validation_runtime_refresh_order "$target_label")
}

refresh_validation_state_for_label() {
  local target_label="$1"

  # Validation depends on fresh traversal coordination and DNS-zone state.
  # Reissue both immediately before the target sample, then refresh only the
  # nodes that are on the critical path for that sample so the 30-second
  # traversal coordination window is not consumed by unrelated nodes.
  issue_and_distribute_traversal_snapshot "refresh_traversal_before_validate_${target_label}" || return 1
  issue_and_distribute_dns_zone_snapshot "refresh_dns_zone_before_validate_${target_label}" || return 1
  refresh_runtime_state_for_validation "$target_label" || return 1
  refresh_signed_state_for_validation "$target_label" || return 1
  refresh_runtime_state_for_validation "$target_label" || return 1
}

refresh_signed_state_worker() {
  local label="$1"
  local target="$2"
  local node_id="$3"
  local _role="$4"
  printf '[signed-state-refresh] %s %s (%s)\n' "$label" "$target" "$node_id"
  live_lab_wait_for_daemon_socket "$target"
  live_lab_retry_root "$target" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet state refresh" 5 2
}

refresh_signed_state_all_nodes() {
  local refresh_label refresh_target refresh_node_id refresh_role
  while IFS=$'\t' read -r refresh_label refresh_target refresh_node_id refresh_role; do
    [[ -n "$refresh_target" ]] || continue
    refresh_signed_state_worker "$refresh_label" "$refresh_target" "$refresh_node_id" "$refresh_role" || return 1
  done < "$NODES_TSV"
}

stage_validate_baseline_runtime() {
  local nft_rules
  local force_ssh_for_validation=0
  local original_max_parallel_workers="$MAX_PARALLEL_NODE_WORKERS"
  local append_stage_dir_set=0

  if live_lab_has_utm_transport && live_lab_can_use_ssh_transport; then
    # UTM guest-agent transport is serialized on this host, which consumes the
    # short traversal coordination window during baseline validation. Once SSH
    # reachability is established, force SSH transport for validation so we can
    # refresh nodes and capture immediately while coordination records are
    # still fresh.
    export LIVE_LAB_FORCE_SSH_TRANSPORT=1
    force_ssh_for_validation=1
    MAX_PARALLEL_NODE_WORKERS="$(node_count)"
  fi

  issue_baseline_validation_artifacts refresh_traversal_before_validate refresh_dns_zone_before_validate || {
    if (( force_ssh_for_validation )); then
      unset LIVE_LAB_FORCE_SSH_TRANSPORT
      MAX_PARALLEL_NODE_WORKERS="$original_max_parallel_workers"
    fi
    return 1
  }
  run_parallel_node_stage refresh_runtime_before_validate_non_exit refresh_runtime_state_worker non_exit || {
    if (( force_ssh_for_validation )); then
      unset LIVE_LAB_FORCE_SSH_TRANSPORT
      MAX_PARALLEL_NODE_WORKERS="$original_max_parallel_workers"
    fi
    return 1
  }
  refresh_runtime_state_for_label exit || {
    if (( force_ssh_for_validation )); then
      unset LIVE_LAB_FORCE_SSH_TRANSPORT
      MAX_PARALLEL_NODE_WORKERS="$original_max_parallel_workers"
    fi
    return 1
  }

  issue_baseline_validation_artifacts refresh_traversal_before_validate_clients refresh_dns_zone_before_validate_clients || {
    if (( force_ssh_for_validation )); then
      unset LIVE_LAB_FORCE_SSH_TRANSPORT
      MAX_PARALLEL_NODE_WORKERS="$original_max_parallel_workers"
    fi
    return 1
  }

  if [[ "${LIVE_LAB_FORCE_SSH_TRANSPORT:-0}" == "1" ]]; then
    run_parallel_node_stage validate_baseline_runtime validate_runtime_worker_after_refresh non_exit || {
      if (( force_ssh_for_validation )); then
        unset LIVE_LAB_FORCE_SSH_TRANSPORT
        MAX_PARALLEL_NODE_WORKERS="$original_max_parallel_workers"
      fi
      return 1
    }
    issue_baseline_validation_artifacts refresh_traversal_before_validate_exit refresh_dns_zone_before_validate_exit || {
      if (( force_ssh_for_validation )); then
        unset LIVE_LAB_FORCE_SSH_TRANSPORT
        MAX_PARALLEL_NODE_WORKERS="$original_max_parallel_workers"
      fi
      return 1
    }
    export LIVE_LAB_STAGE_APPEND=1
    append_stage_dir_set=1
    run_parallel_node_stage validate_baseline_runtime validate_runtime_worker_after_refresh exit_only || {
      unset LIVE_LAB_STAGE_APPEND
      if (( force_ssh_for_validation )); then
        unset LIVE_LAB_FORCE_SSH_TRANSPORT
        MAX_PARALLEL_NODE_WORKERS="$original_max_parallel_workers"
      fi
      return 1
    }
    unset LIVE_LAB_STAGE_APPEND
    append_stage_dir_set=0
    run_parallel_node_stage refresh_runtime_after_validate refresh_runtime_state_worker || {
      if (( force_ssh_for_validation )); then
        unset LIVE_LAB_FORCE_SSH_TRANSPORT
        MAX_PARALLEL_NODE_WORKERS="$original_max_parallel_workers"
      fi
      return 1
    }
  elif live_lab_has_utm_transport; then
    # Keep the serialized UTM fallback only when SSH is unavailable.
    run_serial_node_stage validate_baseline_runtime validate_runtime_worker_after_refresh non_exit || return 1
    issue_baseline_validation_artifacts refresh_traversal_before_validate_exit refresh_dns_zone_before_validate_exit || {
      return 1
    }
    export LIVE_LAB_STAGE_APPEND=1
    append_stage_dir_set=1
    run_serial_node_stage validate_baseline_runtime validate_runtime_worker_after_refresh exit_only || {
      unset LIVE_LAB_STAGE_APPEND
      return 1
    }
    unset LIVE_LAB_STAGE_APPEND
    append_stage_dir_set=0
    run_parallel_node_stage refresh_runtime_after_validate refresh_runtime_state_worker || return 1
  else
    run_parallel_node_stage validate_baseline_runtime validate_runtime_worker_after_refresh non_exit || return 1
    issue_baseline_validation_artifacts refresh_traversal_before_validate_exit refresh_dns_zone_before_validate_exit || {
      return 1
    }
    export LIVE_LAB_STAGE_APPEND=1
    append_stage_dir_set=1
    run_parallel_node_stage validate_baseline_runtime validate_runtime_worker_after_refresh exit_only || {
      unset LIVE_LAB_STAGE_APPEND
      return 1
    }
    unset LIVE_LAB_STAGE_APPEND
    append_stage_dir_set=0
    run_parallel_node_stage refresh_runtime_after_validate refresh_runtime_state_worker || return 1
  fi

  nft_rules="$(live_lab_capture_root "$(node_target_for_label exit)" "root nft list ruleset || true")" || return 1
  if (( append_stage_dir_set )); then
    unset LIVE_LAB_STAGE_APPEND
  fi
  if (( force_ssh_for_validation )); then
    unset LIVE_LAB_FORCE_SSH_TRANSPORT
    MAX_PARALLEL_NODE_WORKERS="$original_max_parallel_workers"
  fi
  printf '[exit-nft]\n%s\n' "$nft_rules"
  grep -Eq 'masquerade|rustynet' <<<"$nft_rules" || return 1
}

validate_runtime_worker_with_fresh_traversal() {
  local label="$1"
  local target="$2"
  local node_id="$3"
  local role="$4"
  refresh_validation_state_for_label "$label" || return 1
  validate_runtime_worker "$label" "$target" "$node_id" "$role"
}

live_lab_runtime_snapshot_ready() {
  local snapshot="$1"
  local node_id="$2"
  local target="$3"
  local role="$4"
  local expected_membership_nodes="$5"
  local exit_node_id="$6"
  local status state restricted_safe_mode bootstrap_error last_reconcile_error

  status="$(snapshot_section_text "$snapshot" "RNLAB_STATUS")"
  [[ -n "$status" ]] || return 1

  state="$(snapshot_field_value "$status" "state")"
  restricted_safe_mode="$(snapshot_field_value "$status" "restricted_safe_mode")"
  bootstrap_error="$(snapshot_field_value "$status" "bootstrap_error")"
  last_reconcile_error="$(snapshot_field_value "$status" "last_reconcile_error")"

  [[ -n "$state" && "$state" != "FailClosed" ]] || return 1
  [[ "$restricted_safe_mode" == "false" ]] || return 1
  [[ "$bootstrap_error" == "none" ]] || return 1
  [[ "$last_reconcile_error" == "none" ]] || return 1

  live_lab_assert_runtime_spec \
    "$snapshot" \
    "$node_id" \
    "$target" \
    "$role" \
    "$expected_membership_nodes" \
    "$exit_node_id"
}

live_lab_wait_for_node_convergence() {
  local target="$1"
  local node_id="$2"
  local role="$3"
  local expected_membership_nodes="$4"
  local exit_node_id="$5"
  local attempts="${6:-60}"
  local sleep_secs="${7:-10}"
  local attempt snapshot

  for ((attempt = 1; attempt <= attempts; attempt++)); do
    snapshot="$(live_lab_collect_runtime_validation_snapshot "$target" "$node_id" "$role")" || snapshot=""
    if [[ -n "$snapshot" ]] && live_lab_runtime_snapshot_ready \
      "$snapshot" \
      "$node_id" \
      "$target" \
      "$role" \
      "$expected_membership_nodes" \
      "$exit_node_id" >/dev/null 2>&1; then
      printf '%s' "$snapshot"
      return 0
    fi
    if [[ "$attempt" -lt "$attempts" ]]; then
      sleep "$sleep_secs"
    fi
  done

  snapshot="$(live_lab_collect_runtime_validation_snapshot "$target" "$node_id" "$role")" || snapshot=""
  if [[ -n "$snapshot" ]] && live_lab_runtime_snapshot_ready \
    "$snapshot" \
    "$node_id" \
    "$target" \
    "$role" \
    "$expected_membership_nodes" \
    "$exit_node_id" >/dev/null 2>&1; then
    printf '%s' "$snapshot"
    return 0
  fi
  printf '%s' "$snapshot"
  return 1
}

live_lab_route_matrix_matches_expected_topology() {
  local snapshot="$1"
  local expected_exit_node_id="$2"
  awk -v expected_exit="$expected_exit_node_id" '
    function after(prefix) {
      return substr($0, length(prefix) + 1)
    }
    function reset_source() {
      source_id = ""
      source_status_rc = ""
      source_default_route_rc = ""
      source_default_route_get_rc = ""
      status_state = ""
      status_exit_node = ""
      status_serving_exit_node = ""
      status_restricted_safe_mode = ""
      status_bootstrap_error = ""
      status_last_reconcile_error = ""
      default_route_device = ""
      default_route_table = ""
      pair_count = 0
    }
    function finalize_pair() {
      if (!in_pair) {
        return
      }
      pair_count++
      if (pair_destination_node_id == "" || pair_capture_rc != "0" || pair_route_get_rc != "0") {
        fail = 1
      }
      in_pair = 0
      pair_destination_node_id = ""
      pair_capture_rc = ""
      pair_route_get_rc = ""
      next_route_context = ""
    }
    function finalize_source() {
      if (!in_source) {
        return
      }
      finalize_pair()
      source_count++
      if (source_id == "" || source_status_rc != "0" || source_default_route_rc != "0" || source_default_route_get_rc != "0") {
        fail = 1
      }
      if (status_restricted_safe_mode != "false" || status_bootstrap_error != "none" || status_last_reconcile_error != "none") {
        fail = 1
      }
      if (status_state == "" || status_state == "FailClosed") {
        fail = 1
      }
      if (pair_count != expected_node_count + 0) {
        fail = 1
      }
      if (source_id == expected_exit) {
        exit_seen = 1
        if (status_serving_exit_node != "true") {
          fail = 1
        }
      } else {
        if (status_exit_node != expected_exit) {
          fail = 1
        }
        if (default_route_device != "rustynet0" || default_route_table != "51820") {
          fail = 1
        }
      }
      in_source = 0
      in_status = 0
      in_route_policy = 0
      route_context = ""
      next_route_context = ""
    }
    /^route_matrix_node_count=/ {
      expected_node_count = after("route_matrix_node_count=")
      next
    }
    /^route_matrix_status=/ {
      overall_status = after("route_matrix_status=")
      next
    }
    /^source_node_begin$/ {
      finalize_source()
      in_source = 1
      reset_source()
      next
    }
    /^source_node_end$/ {
      finalize_source()
      next
    }
    /^pair_begin$/ {
      finalize_pair()
      in_pair = 1
      next
    }
    /^pair_end$/ {
      finalize_pair()
      next
    }
    /^source_node_id=/ && in_source && !in_pair {
      source_id = after("source_node_id=")
      next
    }
    /^source_status_capture_rc=/ && in_source {
      source_status_rc = after("source_status_capture_rc=")
      next
    }
    /^source_default_route_capture_rc=/ && in_source {
      source_default_route_rc = after("source_default_route_capture_rc=")
      next_route_context = "source_default"
      next
    }
    /^route_policy_capture_rc=/ && in_pair {
      pair_capture_rc = after("route_policy_capture_rc=")
      next_route_context = "pair"
      next
    }
    /^destination_node_id=/ && in_pair {
      pair_destination_node_id = after("destination_node_id=")
      next
    }
    /^__RNLAB_STATUS_BEGIN__$/ && in_source {
      in_status = 1
      next
    }
    /^__RNLAB_STATUS_END__$/ && in_source {
      in_status = 0
      next
    }
    /^__RNLAB_ROUTE_POLICY_BEGIN__$/ && in_source {
      in_route_policy = 1
      route_context = next_route_context
      next_route_context = ""
      next
    }
    /^__RNLAB_ROUTE_POLICY_END__$/ && in_source {
      in_route_policy = 0
      route_context = ""
      next
    }
    in_status && /^state=/ {
      status_state = after("state=")
      next
    }
    in_status && /^exit_node=/ {
      status_exit_node = after("exit_node=")
      next
    }
    in_status && /^serving_exit_node=/ {
      status_serving_exit_node = after("serving_exit_node=")
      next
    }
    in_status && /^restricted_safe_mode=/ {
      status_restricted_safe_mode = after("restricted_safe_mode=")
      next
    }
    in_status && /^bootstrap_error=/ {
      status_bootstrap_error = after("bootstrap_error=")
      next
    }
    in_status && /^last_reconcile_error=/ {
      status_last_reconcile_error = after("last_reconcile_error=")
      next
    }
    in_route_policy && route_context == "source_default" && /^route_get_rc=/ {
      source_default_route_get_rc = after("route_get_rc=")
      next
    }
    in_route_policy && route_context == "source_default" && /^actual_route_device=/ {
      default_route_device = after("actual_route_device=")
      next
    }
    in_route_policy && route_context == "source_default" && /^actual_route_table=/ {
      default_route_table = after("actual_route_table=")
      next
    }
    in_route_policy && route_context == "pair" && /^route_get_rc=/ {
      pair_route_get_rc = after("route_get_rc=")
      next
    }
    END {
      finalize_source()
      if (expected_node_count == "" || source_count != expected_node_count + 0 || !exit_seen || overall_status != "pass" || fail) {
        exit 1
      }
    }
  ' <<<"$snapshot"
}

live_lab_wait_for_route_matrix_convergence() {
  local expected_exit_node_id="$1"
  local consecutive_polls="${2:-2}"
  local attempts="${3:-20}"
  local sleep_secs="${4:-3}"
  local stage_name="${5:-route_matrix_convergence}"
  local attempt snapshot
  local matched_polls=0

  for ((attempt = 1; attempt <= attempts; attempt++)); do
    snapshot="$(live_lab_collect_route_matrix_snapshot "$stage_name" 2>&1)" || snapshot="${snapshot:-}"
    if [[ -n "$snapshot" ]] && live_lab_route_matrix_matches_expected_topology "$snapshot" "$expected_exit_node_id" >/dev/null 2>&1; then
      matched_polls=$((matched_polls + 1))
      if (( matched_polls >= consecutive_polls )); then
        printf '%s' "$snapshot"
        return 0
      fi
    else
      matched_polls=0
    fi
    if [[ "$attempt" -lt "$attempts" ]]; then
      sleep "$sleep_secs"
    fi
  done

  snapshot="$(live_lab_collect_route_matrix_snapshot "$stage_name" 2>&1)" || snapshot="${snapshot:-}"
  printf '%s' "$snapshot"
  return 1
}

validate_runtime_worker() {
  local _label="$1"
  local target="$2"
  local node_id="$3"
  local role="$4"
  local expected_membership_nodes exit_node_id snapshot wait_rc
  local route_policy route_policy_rc dns_snapshot dns_snapshot_rc expected_next_hop
  local signed_state_snapshot signed_state_rc dns_zone_snapshot dns_zone_rc
  local zone_name
  local runtime_attempts=8
  local runtime_sleep_secs=1
  local signed_state_attempts=5
  local signed_state_sleep_secs=1
  local dns_zone_attempts=5
  local dns_zone_sleep_secs=1

  expected_membership_nodes="$(node_count)"
  exit_node_id="$(node_id_for_label exit)"
  zone_name="${RUSTYNET_DNS_ZONE_NAME:-rustynet}"
  expected_next_hop=""
  if [[ "$role" == "client" ]]; then
    expected_next_hop="direct:rustynet0"
  fi
  set +e
  # Stage-level route-matrix convergence already waited for the cluster to
  # settle before this worker runs. Keep the per-node wait short so we capture
  # the fresh runtime and signed-state window immediately after the final
  # refresh cycle instead of burning it here.
  snapshot="$(live_lab_wait_for_node_convergence "$target" "$node_id" "$role" "$expected_membership_nodes" "$exit_node_id" "$runtime_attempts" "$runtime_sleep_secs")"
  wait_rc=$?
  signed_state_snapshot="$(live_lab_wait_for_signed_state_convergence "$target" "$node_id" "$role" "$zone_name" "${CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS:-900}" "${CROSS_NETWORK_MAX_TIME_SKEW_SECS:-2}" "$signed_state_attempts" "$signed_state_sleep_secs")"
  signed_state_rc=$?
  dns_zone_snapshot="$(live_lab_wait_for_dns_zone_convergence "$target" "$node_id" "$zone_name" "$dns_zone_attempts" "$dns_zone_sleep_secs")"
  dns_zone_rc=$?
  route_policy="$(live_lab_collect_route_policy "$target" "1.1.1.1" "$expected_next_hop" 2>&1)"
  route_policy_rc=$?
  dns_snapshot="$(live_lab_collect_dns_snapshot "$target" 2>&1)"
  dns_snapshot_rc=$?
  set -e
  if [[ -n "${LIVE_LAB_STAGE_DIR:-}" ]]; then
    stage_worker_write_artifact "$_label" "signed_state.txt" "$(printf 'capture_rc=%s\n%s\n' "$signed_state_rc" "$signed_state_snapshot")" >/dev/null || return 1
    stage_worker_write_artifact "$_label" "dns_zone.txt" "$(printf 'capture_rc=%s\n%s\n' "$dns_zone_rc" "$dns_zone_snapshot")" >/dev/null || return 1
    stage_worker_write_artifact "$_label" "snapshot.txt" "$(printf 'capture_rc=%s\n%s\n' "$wait_rc" "$snapshot")" >/dev/null || return 1
    stage_worker_write_artifact "$_label" "route_policy.txt" "$(printf 'capture_rc=%s\n%s\n' "$route_policy_rc" "$route_policy")" >/dev/null || return 1
    stage_worker_write_artifact "$_label" "dns_state.txt" "$(printf 'capture_rc=%s\n%s\n' "$dns_snapshot_rc" "$dns_snapshot")" >/dev/null || return 1
  fi
  printf '[signed-state] %s %s\n%s\n' "$node_id" "$target" "$signed_state_snapshot"
  printf '[dns-zone] %s %s\n%s\n' "$node_id" "$target" "$dns_zone_snapshot"
  printf '[snapshot] %s %s\n%s\n' "$node_id" "$target" "$snapshot"
  printf '[route-policy] %s %s\n%s\n' "$node_id" "$target" "$route_policy"
  printf '[dns-state] %s %s\n%s\n' "$node_id" "$target" "$dns_snapshot"
  [[ "$signed_state_rc" -eq 0 ]] || return "$signed_state_rc"
  [[ "$dns_zone_rc" -eq 0 ]] || return "$dns_zone_rc"
  [[ "$route_policy_rc" -eq 0 ]] || return "$route_policy_rc"
  [[ "$dns_snapshot_rc" -eq 0 ]] || return "$dns_snapshot_rc"
  live_lab_assert_runtime_spec \
    "$snapshot" \
    "$node_id" \
    "$target" \
    "$role" \
    "$expected_membership_nodes" \
    "$exit_node_id"
  # Keep the convergence helper return code in the worker artifacts for
  # forensics, but fail only on the explicit runtime, signed-state, DNS-zone,
  # route-policy, and secret-hygiene assertions above. The helper can time out
  # even when the final captured snapshot already satisfies the validator.
  return 0
}

refresh_runtime_state_for_validation_worker() {
  local label="$1"
  local target="$2"
  local _node_id="$3"
  local role="$4"
  local exit_node_id

  if [[ "$role" == "client" ]]; then
    exit_node_id="$(node_id_for_label exit)"
    [[ -n "$exit_node_id" ]] || {
      printf 'missing exit node id for client validation refresh\n' >&2
      return 1
    }
    printf '[runtime-refresh-role-coupling] %s %s (exit=%s)\n' "$label" "$target" "$exit_node_id"
    # Baseline validation performs the authoritative route assertion itself.
    # Skip the helper's internal route wait here so we do not spend the short
    # signed-state window on a second convergence loop before collecting the
    # final validation snapshots.
    live_lab_apply_role_coupling "$target" "client" "$exit_node_id" "false" "/etc/rustynet/assignment-refresh.env" "true" || return 1
    live_lab_wait_for_daemon_socket "$target"
    return 0
  fi

  refresh_runtime_state_worker "$label" "$target" "$_node_id" "$role"
}

validate_runtime_worker_after_refresh() {
  local label="$1"
  local target="$2"
  local node_id="$3"
  local role="$4"
  refresh_runtime_state_for_validation_worker "$label" "$target" "$node_id" "$role" || return 1
  validate_runtime_worker "$label" "$target" "$node_id" "$role"
}

current_run_git_commit() {
  tr -d '[:space:]' < "$STATE_DIR/git_head.txt" | tr '[:upper:]' '[:lower:]'
}

current_run_git_commit_short() {
  local commit
  commit="$(current_run_git_commit)"
  printf '%.7s' "$commit"
}

current_local_head_commit() {
  git -C "$ROOT_DIR" rev-parse HEAD | tr '[:upper:]' '[:lower:]'
}

current_run_git_status_is_dirty() {
  [[ -s "$STATE_DIR/git_status.txt" ]]
}

current_local_source_tree_is_dirty() {
  git -C "$ROOT_DIR" status --short --untracked-files=all -- \
    . \
    ':(exclude)artifacts' \
    ':(exclude).cargo-audit-db' \
    ':(exclude)profiles/live_lab' | grep -q .
}

assert_local_gate_suite_provenance() {
  local deployed_commit local_head
  deployed_commit="$(current_run_git_commit)"
  local_head="$(current_local_head_commit)"
  if [[ "$deployed_commit" != "$local_head" ]]; then
    printf 'local full gate suite refuses mixed-source attestation: deployed commit %s differs from local HEAD %s\n' \
      "$deployed_commit" "$local_head" >&2
    return 1
  fi
  if [[ "$SOURCE_MODE" == "working-tree" ]] && current_run_git_status_is_dirty; then
    printf 'local full gate suite refuses dirty-working-tree attestation: commit-bound evidence requires a clean working tree or an explicit committed ref\n' >&2
    return 1
  fi
  if current_local_source_tree_is_dirty; then
    printf 'local full security gate suite refuses dirty source tree: tracked/untracked changes outside generated evidence paths make provenance non-commit-bound\n' >&2
    return 1
  fi
}

stage_run_live_role_switch_matrix() {
  local commit_short role_report role_source role_log
  if ! has_five_node_release_gate_topology; then
    printf 'role switch matrix requires the full five-node topology (client, entry, aux, and extra targets)\n' >&2
    return 1
  fi
  commit_short="$(current_run_git_commit_short)"
  mkdir -p "$REPORT_DIR/source"
  role_report="$REPORT_DIR/role_switch_matrix_report_${commit_short}.json"
  role_source="$REPORT_DIR/source/role_switch_matrix_${commit_short}.md"
  role_log="$REPORT_DIR/live_linux_role_switch_matrix.log"
  RUSTYNET_EXPECTED_GIT_COMMIT="$(current_run_git_commit)" \
  bash "$ROOT_DIR/scripts/e2e/live_linux_role_switch_matrix_test.sh" \
    --ssh-identity-file "$SSH_IDENTITY_FILE" \
    --known-hosts "$SSH_KNOWN_HOSTS_FILE" \
    --traversal-env-file "$STATE_DIR/issue_traversal.env" \
    --exit-host "$(node_target_for_label exit)" \
    --exit-node-id "$(node_id_for_label exit)" \
    --debian-host "$(node_target_for_label client)" \
    --debian-node-id "$(node_id_for_label client)" \
    --ubuntu-host "$(node_target_for_label entry)" \
    --ubuntu-node-id "$(node_id_for_label entry)" \
    --fedora-host "$(node_target_for_label aux)" \
    --fedora-node-id "$(node_id_for_label aux)" \
    --mint-host "$(node_target_for_label extra)" \
    --mint-node-id "$(node_id_for_label extra)" \
    --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
    --report-path "$role_report" \
    --source-path "$role_source" \
    --log-path "$role_log"
}

stage_run_local_full_gate_suite() {
  local gate_log="$VERIFICATION_DIR/full_gate_suite_${RUN_ID}.log"
  if ! has_five_node_release_gate_topology; then
    printf 'local full gate suite requires the full five-node topology so release-gate evidence remains commit-bound and complete\n' >&2
    return 1
  fi
  assert_local_gate_suite_provenance || return 1
  mkdir -p "$VERIFICATION_DIR"
  : > "$gate_log"
  export RUSTYNET_FRESH_INSTALL_OS_MATRIX_PROFILE=linux
  export RUSTYNET_FRESH_INSTALL_OS_MATRIX_EXPECTED_GIT_COMMIT
  RUSTYNET_FRESH_INSTALL_OS_MATRIX_EXPECTED_GIT_COMMIT="$(current_run_git_commit)"
  run_gate() {
    local script="$1"
    local rc=0
    printf '\n[%s] RUN %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$script" | tee -a "$gate_log"
    set +e
    "$script" 2>&1 | tee -a "$gate_log"
    rc=${PIPESTATUS[0]}
    set -e
    if [[ "$rc" -ne 0 ]]; then
      printf '[%s] FAIL %s rc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$script" "$rc" | tee -a "$gate_log"
      return "$rc"
    fi
    printf '[%s] PASS %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$script" | tee -a "$gate_log"
  }
  run_gate ./scripts/ci/phase1_gates.sh
  run_gate ./scripts/ci/phase3_gates.sh
  run_gate ./scripts/ci/phase4_gates.sh
  run_gate ./scripts/ci/phase5_gates.sh
  run_gate ./scripts/ci/phase6_gates.sh
  run_gate ./scripts/ci/phase7_gates.sh
  run_gate ./scripts/ci/phase8_gates.sh
  run_gate ./scripts/ci/phase9_gates.sh
  run_gate ./scripts/ci/fresh_install_os_matrix_release_gate.sh
  run_gate ./scripts/ci/phase10_gates.sh
  run_gate ./scripts/ci/membership_gates.sh
  run_gate ./scripts/ci/secrets_hygiene_gates.sh
  run_gate ./scripts/ci/role_auth_matrix_gates.sh
  run_gate ./scripts/ci/traversal_adversarial_gates.sh
  run_gate ./scripts/ci/security_regression_gates.sh
  run_gate ./scripts/ci/supply_chain_integrity_gates.sh
  run_gate ./scripts/ci/perf_regression_gate.sh
  printf '\n[%s] FULL GATE SUITE PASS\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$gate_log"
}

stage_run_live_exit_handoff() {
  local alternate_label alternate_target alternate_node_id
  if has_label entry; then
    alternate_label="entry"
  elif has_label aux; then
    alternate_label="aux"
  else
    printf 'exit handoff requires entry or aux target\n' >&2
    return 1
  fi
  alternate_target="$(node_target_for_label "$alternate_label")"
  alternate_node_id="$(node_id_for_label "$alternate_label")"
  RUSTYNET_EXPECTED_GIT_COMMIT="$(current_run_git_commit)" \
  bash "$ROOT_DIR/scripts/e2e/live_linux_exit_handoff_test.sh" \
    --ssh-identity-file "$SSH_IDENTITY_FILE" \
    --known-hosts "$SSH_KNOWN_HOSTS_FILE" \
    --exit-a-host "$(node_target_for_label exit)" \
    --exit-a-node-id "$(node_id_for_label exit)" \
    --client-host "$(node_target_for_label client)" \
    --client-node-id "$(node_id_for_label client)" \
    --exit-b-host "$alternate_target" \
    --exit-b-node-id "$alternate_node_id" \
    --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
    --report-path "$REPORT_DIR/live_linux_exit_handoff_report.json" \
    --log-path "$REPORT_DIR/live_linux_exit_handoff.log" \
    --monitor-log "$REPORT_DIR/live_linux_exit_handoff_monitor.log"
}

stage_run_live_two_hop() {
  local second_client_label second_client_target second_client_node_id
  if ! has_label entry || ! has_label aux; then
    printf 'two-hop requires entry and aux targets\n' >&2
    return 1
  fi
  if has_label extra; then
    second_client_label="extra"
  else
    second_client_label="aux"
  fi
  second_client_target="$(node_target_for_label "$second_client_label")"
  second_client_node_id="$(node_id_for_label "$second_client_label")"
  RUSTYNET_EXPECTED_GIT_COMMIT="$(current_run_git_commit)" \
  bash "$ROOT_DIR/scripts/e2e/live_linux_two_hop_test.sh" \
    --ssh-identity-file "$SSH_IDENTITY_FILE" \
    --known-hosts "$SSH_KNOWN_HOSTS_FILE" \
    --final-exit-host "$(node_target_for_label exit)" \
    --final-exit-node-id "$(node_id_for_label exit)" \
    --client-host "$(node_target_for_label client)" \
    --client-node-id "$(node_id_for_label client)" \
    --entry-host "$(node_target_for_label entry)" \
    --entry-node-id "$(node_id_for_label entry)" \
    --second-client-host "$second_client_target" \
    --second-client-node-id "$second_client_node_id" \
    --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
    --report-path "$REPORT_DIR/live_linux_two_hop_report.json" \
    --log-path "$REPORT_DIR/live_linux_two_hop.log"
}

stage_run_live_lan_toggle() {
  if ! has_label aux; then
    printf 'LAN toggle requires aux target\n' >&2
    return 1
  fi
  RUSTYNET_EXPECTED_GIT_COMMIT="$(current_run_git_commit)" \
  bash "$ROOT_DIR/scripts/e2e/live_linux_lan_toggle_test.sh" \
    --ssh-identity-file "$SSH_IDENTITY_FILE" \
    --exit-host "$(node_target_for_label exit)" \
    --exit-node-id "$(node_id_for_label exit)" \
    --client-host "$(node_target_for_label client)" \
    --client-node-id "$(node_id_for_label client)" \
    --blind-exit-host "$(node_target_for_label aux)" \
    --blind-exit-node-id "$(node_id_for_label aux)" \
    --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
    --report-path "$REPORT_DIR/live_linux_lan_toggle_report.json" \
    --log-path "$REPORT_DIR/live_linux_lan_toggle.log"
}

assert_json_report_status_pass() {
  local report_path="$1"
  local label="$2"
  local status
  if [[ ! -f "$report_path" ]]; then
    printf '%s report missing: %s\n' "$label" "$report_path" >&2
    return 1
  fi
  status="$(cargo run --quiet -p rustynet-cli -- ops read-cross-network-report-fields \
    --report-path "$report_path" \
    --include-status \
    --default-value fail)"
  status="$(printf '%s' "$status" | tr -d '[:space:]')"
  if [[ "$status" != "pass" ]]; then
    printf '%s report status is not pass: %s\n' "$label" "$status" >&2
    return 1
  fi
}

assert_log_absent_patterns() {
  local log_path="$1"
  local label="$2"
  shift 2
  local pattern
  if [[ ! -f "$log_path" ]]; then
    printf '%s log missing: %s\n' "$label" "$log_path" >&2
    return 1
  fi
  for pattern in "$@"; do
    if rg -n -- "$pattern" "$log_path" >/dev/null 2>&1; then
      printf '%s log contains forbidden pattern (%s): %s\n' "$label" "$pattern" "$log_path" >&2
      rg -n -- "$pattern" "$log_path" >&2 || true
      return 1
    fi
  done
}

assert_log_contains_pattern() {
  local log_path="$1"
  local label="$2"
  local pattern="$3"
  if [[ ! -f "$log_path" ]]; then
    printf '%s log missing: %s\n' "$label" "$log_path" >&2
    return 1
  fi
  if ! rg -n -- "$pattern" "$log_path" >/dev/null 2>&1; then
    printf '%s log missing required pattern (%s): %s\n' "$label" "$pattern" "$log_path" >&2
    return 1
  fi
}

assert_text_contains() {
  local text="$1"
  local label="$2"
  local pattern="$3"
  if [[ "$text" != *"$pattern"* ]]; then
    printf '%s missing required text (%s)\n' "$label" "$pattern" >&2
    return 1
  fi
}

assert_text_absent() {
  local text="$1"
  local label="$2"
  local pattern="$3"
  if [[ "$text" == *"$pattern"* ]]; then
    printf '%s contains forbidden text (%s)\n' "$label" "$pattern" >&2
    return 1
  fi
}

snapshot_section_text() {
  local snapshot="$1"
  local section_name="$2"
  local begin_marker end_marker
  if [[ "$section_name" == RNLAB_* ]]; then
    begin_marker="__${section_name}_BEGIN__"
    end_marker="__${section_name}_END__"
  else
    begin_marker="__RNLAB_${section_name}_BEGIN__"
    end_marker="__RNLAB_${section_name}_END__"
  fi
  awk -v begin="$begin_marker" -v end="$end_marker" '
    $0 == begin {
      capture = 1
      next
    }
    $0 == end {
      capture = 0
      next
    }
    capture {
      print
    }
  ' <<<"$snapshot"
}

snapshot_section_or_self_text() {
  local snapshot="$1"
  local section_name="$2"
  local section
  section="$(snapshot_section_text "$snapshot" "$section_name")"
  if [[ -n "$section" ]]; then
    printf '%s' "$section"
    return 0
  fi
  printf '%s' "$snapshot"
}

snapshot_named_block_text() {
  local snapshot="$1"
  local block_name="$2"
  awk -v begin="${block_name}_begin" -v end="${block_name}_end" '
    $0 == begin {
      capture = 1
      next
    }
    $0 == end {
      capture = 0
      next
    }
    capture {
      print
    }
  ' <<<"$snapshot"
}

snapshot_field_value() {
  local snapshot="$1"
  local key="$2"
  awk -v key="$key" '
    index($0, key "=") == 1 {
      print substr($0, length(key) + 2)
      exit
    }
  ' <<<"$snapshot"
}

snapshot_keyed_block_text() {
  local snapshot="$1"
  local begin_marker="$2"
  local end_marker="$3"
  local selector_key="$4"
  local selector_value="$5"
  awk \
    -v begin="$begin_marker" \
    -v end="$end_marker" \
    -v selector_key="$selector_key" \
    -v selector_value="$selector_value" '
      $0 == begin {
        capture = 1
        matches = 0
        block = ""
        next
      }
      $0 == end {
        if (capture && matches) {
          printf "%s", block
          exit
        }
        capture = 0
        matches = 0
        block = ""
        next
      }
      capture {
        block = block $0 ORS
        if (index($0, selector_key "=") == 1 && substr($0, length(selector_key) + 2) == selector_value) {
          matches = 1
        }
      }
    ' <<<"$snapshot"
}

permissions_fact_text() {
  local snapshot="$1"
  local path="$2"
  snapshot_keyed_block_text "$snapshot" "permissions_fact_begin" "permissions_fact_end" "path" "$path"
}

socket_fact_text() {
  local snapshot="$1"
  local fact_name="$2"
  snapshot_keyed_block_text "$snapshot" "socket_fact_begin" "socket_fact_end" "name" "$fact_name"
}

mode_world_digit() {
  local mode="$1"
  if [[ ! "$mode" =~ ^[0-7]{3,4}$ ]]; then
    return 1
  fi
  printf '%s' "$((10#$mode % 10))"
}

assert_mode_not_world_accessible() {
  local mode="$1"
  local label="$2"
  local path="$3"
  local world_digit
  world_digit="$(mode_world_digit "$mode")" || {
    printf '%s has invalid mode for %s: %s\n' "$label" "$path" "${mode:-missing}" >&2
    return 1
  }
  if [[ "$world_digit" != "0" ]]; then
    printf '%s has world-accessible mode for %s: %s\n' "$label" "$path" "$mode" >&2
    return 1
  fi
}

permissions_fact_require() {
  local permissions_snapshot="$1"
  local path="$2"
  local label="$3"
  local mode_pattern="$4"
  local owner_pattern="$5"
  local group_pattern="$6"
  local type_pattern="$7"
  local fact present mode owner group kind

  fact="$(permissions_fact_text "$permissions_snapshot" "$path")"
  if [[ -z "$fact" ]]; then
    printf '%s missing permissions fact for %s\n' "$label" "$path" >&2
    return 1
  fi
  present="$(snapshot_field_value "$fact" "present")"
  mode="$(snapshot_field_value "$fact" "mode")"
  owner="$(snapshot_field_value "$fact" "owner")"
  group="$(snapshot_field_value "$fact" "group")"
  kind="$(snapshot_field_value "$fact" "type")"
  if [[ "$present" != "1" ]]; then
    printf '%s missing required path %s\n' "$label" "$path" >&2
    return 1
  fi
  if ! [[ "$mode" =~ $mode_pattern ]]; then
    printf '%s unexpected mode for %s: %s\n' "$label" "$path" "${mode:-missing}" >&2
    return 1
  fi
  if ! [[ "$owner" =~ $owner_pattern ]]; then
    printf '%s unexpected owner for %s: %s\n' "$label" "$path" "${owner:-missing}" >&2
    return 1
  fi
  if ! [[ "$group" =~ $group_pattern ]]; then
    printf '%s unexpected group for %s: %s\n' "$label" "$path" "${group:-missing}" >&2
    return 1
  fi
  if ! [[ "$kind" =~ $type_pattern ]]; then
    printf '%s unexpected type for %s: %s\n' "$label" "$path" "${kind:-missing}" >&2
    return 1
  fi
}

permissions_fact_require_if_present() {
  local permissions_snapshot="$1"
  local path="$2"
  local label="$3"
  local mode_pattern="$4"
  local owner_pattern="$5"
  local group_pattern="$6"
  local type_pattern="$7"
  local fact present

  fact="$(permissions_fact_text "$permissions_snapshot" "$path")"
  if [[ -z "$fact" ]]; then
    printf '%s missing permissions fact for %s\n' "$label" "$path" >&2
    return 1
  fi
  present="$(snapshot_field_value "$fact" "present")"
  if [[ "$present" == "0" ]]; then
    return 0
  fi
  permissions_fact_require "$permissions_snapshot" "$path" "$label" "$mode_pattern" "$owner_pattern" "$group_pattern" "$type_pattern"
}

permissions_fact_require_absent() {
  local permissions_snapshot="$1"
  local path="$2"
  local label="$3"
  local fact present

  fact="$(permissions_fact_text "$permissions_snapshot" "$path")"
  if [[ -z "$fact" ]]; then
    printf '%s missing permissions fact for %s\n' "$label" "$path" >&2
    return 1
  fi
  present="$(snapshot_field_value "$fact" "present")"
  if [[ "$present" != "0" ]]; then
    printf '%s expected plaintext path to be absent: %s\n' "$label" "$path" >&2
    return 1
  fi
}

live_lab_assert_time_sync() {
  local snapshot="$1"
  local node_id="$2"
  local target="$3"
  local time_snapshot time_label
  local reference_unix max_clock_skew_secs remote_unix_now clock_skew_secs
  local sync_evidence_present sync_source_kind time_sync_observability system_clock_synchronized timedatectl_available

  time_label="time sync (${node_id})"
  if [[ "$snapshot" == *"time_target="* ]]; then
    assert_text_contains "$snapshot" "time snapshot (${node_id})" "time_target=${target}"
  fi
  if [[ "$snapshot" == *"time_node_id="* ]]; then
    assert_text_contains "$snapshot" "time snapshot (${node_id})" "time_node_id=${node_id}"
  fi
  time_snapshot="$(snapshot_section_or_self_text "$snapshot" "RNLAB_TIME")"
  assert_text_contains "$time_snapshot" "$time_label" "time_snapshot_version=2"

  reference_unix="$(snapshot_field_value "$time_snapshot" "reference_unix")"
  max_clock_skew_secs="$(snapshot_field_value "$time_snapshot" "max_clock_skew_secs")"
  remote_unix_now="$(snapshot_field_value "$time_snapshot" "remote_unix_now")"
  clock_skew_secs="$(snapshot_field_value "$time_snapshot" "clock_skew_secs")"
  sync_evidence_present="$(snapshot_field_value "$time_snapshot" "sync_evidence_present")"
  sync_source_kind="$(snapshot_field_value "$time_snapshot" "sync_source_kind")"
  time_sync_observability="$(snapshot_field_value "$time_snapshot" "time_sync_observability")"
  system_clock_synchronized="$(snapshot_field_value "$time_snapshot" "system_clock_synchronized")"
  timedatectl_available="$(snapshot_field_value "$time_snapshot" "timedatectl_available")"

  if [[ ! "$reference_unix" =~ ^[0-9]+$ || ! "$max_clock_skew_secs" =~ ^[0-9]+$ || ! "$remote_unix_now" =~ ^[0-9]+$ || ! "$clock_skew_secs" =~ ^[0-9]+$ ]]; then
    printf '%s missing numeric skew evidence\n' "$time_label" >&2
    return 1
  fi
  if (( clock_skew_secs > max_clock_skew_secs )); then
    printf '%s exceeds skew bound: skew=%s max=%s\n' "$time_label" "$clock_skew_secs" "$max_clock_skew_secs" >&2
    return 1
  fi
  if [[ "$sync_evidence_present" != "1" ]]; then
    printf '%s missing credible synchronization source evidence\n' "$time_label" >&2
    return 1
  fi
  if [[ -z "$sync_source_kind" || "$sync_source_kind" == "none" ]]; then
    printf '%s missing synchronization source classification\n' "$time_label" >&2
    return 1
  fi
  if [[ "$time_sync_observability" != "full" ]]; then
    printf '%s missing full time-sync observability\n' "$time_label" >&2
    return 1
  fi
  if [[ "$timedatectl_available" == "1" && "$system_clock_synchronized" != "yes" ]]; then
    printf '%s expected timedatectl synchronized=yes, got %s\n' "$time_label" "${system_clock_synchronized:-missing}" >&2
    return 1
  fi
}

live_lab_assert_process_health() {
  local snapshot="$1"
  local node_id="$2"
  local target="$3"
  local process_snapshot process_label
  local daemon_process_count helper_process_count managed_dns_process_count systemd_resolved_process_count
  local unexpected_rustynetd_process_count rustynetd_active_state rustynetd_sub_state rustynetd_main_pid
  local helper_active_state helper_sub_state helper_main_pid managed_dns_active_state managed_dns_sub_state
  local systemd_resolved_active_state

  process_label="process health (${node_id})"
  if [[ "$snapshot" == *"process_target="* ]]; then
    assert_text_contains "$snapshot" "process snapshot (${node_id})" "process_target=${target}"
  fi
  if [[ "$snapshot" == *"process_node_id="* ]]; then
    assert_text_contains "$snapshot" "process snapshot (${node_id})" "process_node_id=${node_id}"
  fi
  process_snapshot="$(snapshot_section_or_self_text "$snapshot" "RNLAB_PROCESS")"
  assert_text_contains "$process_snapshot" "$process_label" "process_snapshot_version=2"

  daemon_process_count="$(snapshot_field_value "$process_snapshot" "daemon_process_count")"
  helper_process_count="$(snapshot_field_value "$process_snapshot" "helper_process_count")"
  managed_dns_process_count="$(snapshot_field_value "$process_snapshot" "managed_dns_process_count")"
  systemd_resolved_process_count="$(snapshot_field_value "$process_snapshot" "systemd_resolved_process_count")"
  unexpected_rustynetd_process_count="$(snapshot_field_value "$process_snapshot" "unexpected_rustynetd_process_count")"
  rustynetd_active_state="$(snapshot_field_value "$process_snapshot" "rustynetd_active_state")"
  rustynetd_sub_state="$(snapshot_field_value "$process_snapshot" "rustynetd_sub_state")"
  rustynetd_main_pid="$(snapshot_field_value "$process_snapshot" "rustynetd_main_pid")"
  helper_active_state="$(snapshot_field_value "$process_snapshot" "helper_active_state")"
  helper_sub_state="$(snapshot_field_value "$process_snapshot" "helper_sub_state")"
  helper_main_pid="$(snapshot_field_value "$process_snapshot" "helper_main_pid")"
  managed_dns_active_state="$(snapshot_field_value "$process_snapshot" "managed_dns_active_state")"
  managed_dns_sub_state="$(snapshot_field_value "$process_snapshot" "managed_dns_sub_state")"
  systemd_resolved_active_state="$(snapshot_field_value "$process_snapshot" "systemd_resolved_active_state")"

  if [[ "$daemon_process_count" != "1" || "$helper_process_count" != "1" || "$unexpected_rustynetd_process_count" != "0" ]]; then
    printf '%s unexpected daemon/helper process counts\n' "$process_label" >&2
    return 1
  fi
  if [[ ! "$rustynetd_main_pid" =~ ^[1-9][0-9]*$ || ! "$helper_main_pid" =~ ^[1-9][0-9]*$ ]]; then
    printf '%s missing active main PID evidence\n' "$process_label" >&2
    return 1
  fi
  if [[ "$rustynetd_active_state" != "active" || "$rustynetd_sub_state" != "running" ]]; then
    printf '%s rustynetd.service not active/running\n' "$process_label" >&2
    return 1
  fi
  if [[ "$helper_active_state" != "active" || "$helper_sub_state" != "running" ]]; then
    printf '%s rustynetd-privileged-helper.service not active/running\n' "$process_label" >&2
    return 1
  fi
  if [[ "$managed_dns_active_state" != "active" || ( "$managed_dns_sub_state" != "exited" && "$managed_dns_sub_state" != "running" ) ]]; then
    printf '%s rustynetd-managed-dns.service not active/exited\n' "$process_label" >&2
    return 1
  fi
  if [[ "$managed_dns_process_count" != "0" ]]; then
    printf '%s unexpected persistent managed-DNS process count: %s\n' "$process_label" "${managed_dns_process_count:-missing}" >&2
    return 1
  fi
  if [[ "$systemd_resolved_active_state" != "active" || ! "$systemd_resolved_process_count" =~ ^[1-9][0-9]*$ ]]; then
    printf '%s systemd-resolved is not active with a live process\n' "$process_label" >&2
    return 1
  fi
}

live_lab_assert_socket_health() {
  local snapshot="$1"
  local node_id="$2"
  local target="$3"
  local _role="$4"
  local socket_snapshot socket_label
  local daemon_socket_present helper_socket_present daemon_unix_listener_count helper_unix_listener_count
  local wireguard_udp_listener_count dns_udp_loopback_listener_count dns_udp_nonloopback_listener_count
  local dns_tcp_listener_count unexpected_runtime_socket_count
  local daemon_fact helper_fact runtime_dir_fact
  local daemon_mode daemon_owner helper_mode helper_owner runtime_dir_mode runtime_dir_owner

  socket_label="socket health (${node_id})"
  if [[ "$snapshot" == *"socket_target="* ]]; then
    assert_text_contains "$snapshot" "socket snapshot (${node_id})" "socket_target=${target}"
  fi
  if [[ "$snapshot" == *"socket_node_id="* ]]; then
    assert_text_contains "$snapshot" "socket snapshot (${node_id})" "socket_node_id=${node_id}"
  fi
  socket_snapshot="$(snapshot_section_or_self_text "$snapshot" "RNLAB_SOCKET")"
  assert_text_contains "$socket_snapshot" "$socket_label" "socket_snapshot_version=2"

  daemon_socket_present="$(snapshot_field_value "$socket_snapshot" "daemon_socket_present")"
  helper_socket_present="$(snapshot_field_value "$socket_snapshot" "helper_socket_present")"
  daemon_unix_listener_count="$(snapshot_field_value "$socket_snapshot" "daemon_unix_listener_count")"
  helper_unix_listener_count="$(snapshot_field_value "$socket_snapshot" "helper_unix_listener_count")"
  wireguard_udp_listener_count="$(snapshot_field_value "$socket_snapshot" "wireguard_udp_listener_count")"
  dns_udp_loopback_listener_count="$(snapshot_field_value "$socket_snapshot" "dns_udp_loopback_listener_count")"
  dns_udp_nonloopback_listener_count="$(snapshot_field_value "$socket_snapshot" "dns_udp_nonloopback_listener_count")"
  dns_tcp_listener_count="$(snapshot_field_value "$socket_snapshot" "dns_tcp_listener_count")"
  unexpected_runtime_socket_count="$(snapshot_field_value "$socket_snapshot" "unexpected_runtime_socket_count")"

  if [[ "$daemon_socket_present" != "1" || "$helper_socket_present" != "1" ]]; then
    printf '%s missing daemon/helper socket paths\n' "$socket_label" >&2
    return 1
  fi
  if [[ "$daemon_unix_listener_count" != "1" || "$helper_unix_listener_count" != "1" ]]; then
    printf '%s missing bound daemon/helper UNIX listeners\n' "$socket_label" >&2
    return 1
  fi
  if [[ "$wireguard_udp_listener_count" != "1" || "$dns_udp_loopback_listener_count" != "1" ]]; then
    printf '%s missing required WireGuard or loopback DNS listeners\n' "$socket_label" >&2
    return 1
  fi
  if [[ "$dns_udp_nonloopback_listener_count" != "0" || "$dns_tcp_listener_count" != "0" || "$unexpected_runtime_socket_count" != "0" ]]; then
    printf '%s found unexpected listener exposure\n' "$socket_label" >&2
    return 1
  fi

  daemon_fact="$(socket_fact_text "$socket_snapshot" "daemon_socket")"
  helper_fact="$(socket_fact_text "$socket_snapshot" "helper_socket")"
  runtime_dir_fact="$(socket_fact_text "$socket_snapshot" "runtime_dir")"
  daemon_mode="$(snapshot_field_value "$daemon_fact" "mode")"
  daemon_owner="$(snapshot_field_value "$daemon_fact" "owner")"
  helper_mode="$(snapshot_field_value "$helper_fact" "mode")"
  helper_owner="$(snapshot_field_value "$helper_fact" "owner")"
  runtime_dir_mode="$(snapshot_field_value "$runtime_dir_fact" "mode")"
  runtime_dir_owner="$(snapshot_field_value "$runtime_dir_fact" "owner")"

  if [[ "$(snapshot_field_value "$daemon_fact" "present")" != "1" || "$(snapshot_field_value "$daemon_fact" "type")" != "socket" ]]; then
    printf '%s daemon socket stat evidence is missing\n' "$socket_label" >&2
    return 1
  fi
  if [[ "$(snapshot_field_value "$helper_fact" "present")" != "1" || "$(snapshot_field_value "$helper_fact" "type")" != "socket" ]]; then
    printf '%s helper socket stat evidence is missing\n' "$socket_label" >&2
    return 1
  fi
  if [[ "$(snapshot_field_value "$runtime_dir_fact" "present")" != "1" || "$(snapshot_field_value "$runtime_dir_fact" "type")" != "directory" ]]; then
    printf '%s runtime directory stat evidence is missing\n' "$socket_label" >&2
    return 1
  fi
  assert_mode_not_world_accessible "$daemon_mode" "$socket_label" "/run/rustynet/rustynetd.sock" || return 1
  assert_mode_not_world_accessible "$helper_mode" "$socket_label" "/run/rustynet/rustynetd-privileged.sock" || return 1
  assert_mode_not_world_accessible "$runtime_dir_mode" "$socket_label" "/run/rustynet" || return 1
  if ! [[ "$daemon_owner" =~ ^(root|rustynetd)$ ]]; then
    printf '%s unexpected daemon socket owner: %s\n' "$socket_label" "${daemon_owner:-missing}" >&2
    return 1
  fi
  if [[ "$helper_owner" != "root" ]]; then
    printf '%s unexpected helper socket owner: %s\n' "$socket_label" "${helper_owner:-missing}" >&2
    return 1
  fi
  if ! [[ "$runtime_dir_owner" =~ ^(root|rustynetd)$ ]]; then
    printf '%s unexpected runtime directory owner: %s\n' "$socket_label" "${runtime_dir_owner:-missing}" >&2
    return 1
  fi
}

live_lab_assert_permissions_hardening() {
  local snapshot="$1"
  local node_id="$2"
  local target="$3"
  local _role="$4"
  local permissions_snapshot permissions_label
  local etc_fact state_fact run_fact

  permissions_label="permissions hardening (${node_id})"
  if [[ "$snapshot" == *"permissions_target="* ]]; then
    assert_text_contains "$snapshot" "permissions snapshot (${node_id})" "permissions_target=${target}"
  fi
  if [[ "$snapshot" == *"permissions_node_id="* ]]; then
    assert_text_contains "$snapshot" "permissions snapshot (${node_id})" "permissions_node_id=${node_id}"
  fi
  permissions_snapshot="$(snapshot_section_or_self_text "$snapshot" "RNLAB_PERMISSIONS")"
  assert_text_contains "$permissions_snapshot" "$permissions_label" "permissions_snapshot_version=2"
  assert_text_contains "$permissions_snapshot" "$permissions_label" "permissions_snapshot_status=pass"

  etc_fact="$(permissions_fact_text "$permissions_snapshot" "/etc/rustynet")"
  state_fact="$(permissions_fact_text "$permissions_snapshot" "/var/lib/rustynet")"
  run_fact="$(permissions_fact_text "$permissions_snapshot" "/run/rustynet")"
  permissions_fact_require "$permissions_snapshot" "/etc/rustynet/credentials" "$permissions_label" '^700$' '^root$' '^root$' '^directory$' || return 1
  permissions_fact_require "$permissions_snapshot" "/etc/rustynet/credentials/wg_key_passphrase.cred" "$permissions_label" '^600$' '^root$' '^root$' '^regular file$' || return 1
  permissions_fact_require "$permissions_snapshot" "/etc/rustynet/credentials/signing_key_passphrase.cred" "$permissions_label" '^600$' '^root$' '^root$' '^regular file$' || return 1
  permissions_fact_require "$permissions_snapshot" "/var/lib/rustynet/keys/wireguard.key.enc" "$permissions_label" '^600$' '^rustynetd$' '^rustynetd$' '^regular file$' || return 1
  permissions_fact_require "$permissions_snapshot" "/run/rustynet/wireguard.key" "$permissions_label" '^600$' '^rustynetd$' '^rustynetd$' '^regular file$' || return 1
  permissions_fact_require "$permissions_snapshot" "/var/lib/rustynet/keys/wireguard.pub" "$permissions_label" '^644$' '^(root|rustynetd)$' '^(root|rustynetd)$' '^regular file$' || return 1
  permissions_fact_require "$permissions_snapshot" "/var/lib/rustynet/membership.snapshot" "$permissions_label" '^600$' '^rustynetd$' '^rustynetd$' '^regular file$' || return 1
  permissions_fact_require "$permissions_snapshot" "/var/lib/rustynet/membership.log" "$permissions_label" '^600$' '^rustynetd$' '^rustynetd$' '^regular file$' || return 1
  permissions_fact_require "$permissions_snapshot" "/var/lib/rustynet/membership.watermark" "$permissions_label" '^600$' '^rustynetd$' '^rustynetd$' '^regular file$' || return 1
  permissions_fact_require "$permissions_snapshot" "/etc/rustynet/assignment.pub" "$permissions_label" '^644$' '^root$' '^root$' '^regular file$' || return 1
  permissions_fact_require "$permissions_snapshot" "/etc/rustynet/traversal.pub" "$permissions_label" '^644$' '^root$' '^root$' '^regular file$' || return 1
  permissions_fact_require "$permissions_snapshot" "/etc/rustynet/trust-evidence.pub" "$permissions_label" '^644$' '^root$' '^root$' '^regular file$' || return 1
  permissions_fact_require "$permissions_snapshot" "/etc/rustynet/dns-zone.pub" "$permissions_label" '^644$' '^root$' '^root$' '^regular file$' || return 1
  permissions_fact_require "$permissions_snapshot" "/etc/rustynet/assignment-refresh.env" "$permissions_label" '^600$' '^root$' '^root$' '^regular file$' || return 1
  permissions_fact_require "$permissions_snapshot" "/var/lib/rustynet/rustynetd.assignment" "$permissions_label" '^640$' '^root$' '^rustynetd$' '^regular file$' || return 1
  permissions_fact_require "$permissions_snapshot" "/var/lib/rustynet/rustynetd.traversal" "$permissions_label" '^640$' '^root$' '^rustynetd$' '^regular file$' || return 1
  permissions_fact_require "$permissions_snapshot" "/var/lib/rustynet/rustynetd.trust" "$permissions_label" '^600$' '^root$' '^root$' '^regular file$' || return 1
  permissions_fact_require "$permissions_snapshot" "/var/lib/rustynet/rustynetd.dns-zone" "$permissions_label" '^640$' '^root$' '^rustynetd$' '^regular file$' || return 1
  permissions_fact_require "$permissions_snapshot" "/var/lib/rustynet/rustynetd.assignment.watermark" "$permissions_label" '^(600|640)$' '^(root|rustynetd)$' '^(root|rustynetd)$' '^regular file$' || return 1
  permissions_fact_require "$permissions_snapshot" "/var/lib/rustynet/rustynetd.traversal.watermark" "$permissions_label" '^(600|640)$' '^(root|rustynetd)$' '^(root|rustynetd)$' '^regular file$' || return 1
  permissions_fact_require "$permissions_snapshot" "/var/lib/rustynet/rustynetd.trust.watermark" "$permissions_label" '^(600|640)$' '^(root|rustynetd)$' '^(root|rustynetd)$' '^regular file$' || return 1
  permissions_fact_require "$permissions_snapshot" "/var/lib/rustynet/rustynetd.dns-zone.watermark" "$permissions_label" '^(600|640)$' '^(root|rustynetd)$' '^(root|rustynetd)$' '^regular file$' || return 1
  permissions_fact_require_if_present "$permissions_snapshot" "/etc/rustynet/assignment.signing.secret" "$permissions_label" '^600$' '^root$' '^root$' '^regular file$' || return 1
  permissions_fact_require_if_present "$permissions_snapshot" "/etc/rustynet/trust-evidence.key" "$permissions_label" '^600$' '^root$' '^root$' '^regular file$' || return 1
  permissions_fact_require_absent "$permissions_snapshot" "/var/lib/rustynet/keys/wireguard.passphrase" "$permissions_label" || return 1
  permissions_fact_require_absent "$permissions_snapshot" "/etc/rustynet/wireguard.passphrase" "$permissions_label" || return 1
  permissions_fact_require_absent "$permissions_snapshot" "/etc/rustynet/signing_key_passphrase" "$permissions_label" || return 1

  if [[ "$(snapshot_field_value "$etc_fact" "present")" != "1" || "$(snapshot_field_value "$etc_fact" "type")" != "directory" ]]; then
    printf '%s missing /etc/rustynet directory evidence\n' "$permissions_label" >&2
    return 1
  fi
  if [[ "$(snapshot_field_value "$state_fact" "present")" != "1" || "$(snapshot_field_value "$state_fact" "type")" != "directory" ]]; then
    printf '%s missing /var/lib/rustynet directory evidence\n' "$permissions_label" >&2
    return 1
  fi
  if [[ "$(snapshot_field_value "$run_fact" "present")" != "1" || "$(snapshot_field_value "$run_fact" "type")" != "directory" ]]; then
    printf '%s missing /run/rustynet directory evidence\n' "$permissions_label" >&2
    return 1
  fi
  if [[ "$(snapshot_field_value "$etc_fact" "owner")" != "root" || ! "$(snapshot_field_value "$etc_fact" "group")" =~ ^(root|rustynetd)$ ]]; then
    printf '%s unexpected /etc/rustynet ownership\n' "$permissions_label" >&2
    return 1
  fi
  if ! [[ "$(snapshot_field_value "$state_fact" "owner")" =~ ^(root|rustynetd)$ ]]; then
    printf '%s unexpected /var/lib/rustynet owner\n' "$permissions_label" >&2
    return 1
  fi
  if ! [[ "$(snapshot_field_value "$run_fact" "owner")" =~ ^(root|rustynetd)$ ]]; then
    printf '%s unexpected /run/rustynet owner\n' "$permissions_label" >&2
    return 1
  fi
  assert_mode_not_world_accessible "$(snapshot_field_value "$etc_fact" "mode")" "$permissions_label" "/etc/rustynet" || return 1
  assert_mode_not_world_accessible "$(snapshot_field_value "$state_fact" "mode")" "$permissions_label" "/var/lib/rustynet" || return 1
  assert_mode_not_world_accessible "$(snapshot_field_value "$run_fact" "mode")" "$permissions_label" "/run/rustynet" || return 1
}

live_lab_assert_dns_health() {
  local snapshot="$1"
  local node_id="$2"
  local target="$3"
  local dns_state dns_label
  local resolv_conf_target systemd_resolved_service managed_dns_service resolvectl_available probe_count

  dns_label="dns health (${node_id})"
  if [[ "$snapshot" == *"dns_state_target="* ]]; then
    assert_text_contains "$snapshot" "dns snapshot (${node_id})" "dns_state_target=${target}"
  fi
  if [[ "$snapshot" == *"dns_state_collected_at_utc="* ]]; then
    assert_text_contains "$snapshot" "dns snapshot (${node_id})" "dns_state_collected_at_utc="
  fi

  dns_state="$(snapshot_section_or_self_text "$snapshot" "RNLAB_DNS_STATE")"
  assert_text_contains "$dns_state" "$dns_label" "dns_state_version=1"
  assert_text_contains "$dns_state" "$dns_label" "resolv_conf_begin"
  assert_text_contains "$dns_state" "$dns_label" "resolvectl_status_begin"
  assert_text_contains "$dns_state" "$dns_label" "systemd_resolved_service=active"
  assert_text_contains "$dns_state" "$dns_label" "managed_dns_service=active"
  assert_text_contains "$dns_state" "$dns_label" "resolvectl_available=1"

  resolv_conf_target="$(snapshot_field_value "$dns_state" "resolv_conf_target")"
  systemd_resolved_service="$(snapshot_field_value "$dns_state" "systemd_resolved_service")"
  managed_dns_service="$(snapshot_field_value "$dns_state" "managed_dns_service")"
  resolvectl_available="$(snapshot_field_value "$dns_state" "resolvectl_available")"
  probe_count="$(snapshot_field_value "$dns_state" "probe_count")"

  if [[ -z "$resolv_conf_target" ]]; then
    printf '%s missing resolv_conf_target\n' "$dns_label" >&2
    return 1
  fi
  if [[ "$systemd_resolved_service" != "active" ]]; then
    printf '%s expected systemd-resolved active, got %s\n' "$dns_label" "${systemd_resolved_service:-missing}" >&2
    return 1
  fi
  if [[ "$managed_dns_service" != "active" ]]; then
    printf '%s expected rustynetd-managed-dns active, got %s\n' "$dns_label" "${managed_dns_service:-missing}" >&2
    return 1
  fi
  if [[ "$resolvectl_available" != "1" ]]; then
    printf '%s expected resolvectl availability, got %s\n' "$dns_label" "${resolvectl_available:-missing}" >&2
    return 1
  fi
  if [[ ! "$probe_count" =~ ^[0-9]+$ ]] || (( probe_count < 1 )); then
    printf '%s expected at least one DNS probe, got %s\n' "$dns_label" "${probe_count:-missing}" >&2
    return 1
  fi
}

live_lab_wait_for_dns_convergence() {
  local target="$1"
  local node_id="$2"
  local attempts="${3:-20}"
  local sleep_secs="${4:-3}"
  local attempt snapshot

  for ((attempt = 1; attempt <= attempts; attempt++)); do
    snapshot="$(live_lab_collect_dns_snapshot "$target")" || snapshot=""
    if [[ -n "$snapshot" ]] && live_lab_assert_dns_health \
      "$snapshot" \
      "$node_id" \
      "$target" >/dev/null 2>&1; then
      printf '%s' "$snapshot"
      return 0
    fi
    if [[ "$attempt" -lt "$attempts" ]]; then
      sleep "$sleep_secs"
    fi
  done

  snapshot="$(live_lab_collect_dns_snapshot "$target")" || snapshot=""
  printf '%s' "$snapshot"
  return 1
}

live_lab_assert_signed_state_health() {
  local snapshot="$1"
  local node_id="$2"
  local target="$3"
  local signed_state signed_label netcheck_text

  signed_label="signed state (${node_id})"
  if [[ "$snapshot" == *"signed_state_target="* ]]; then
    assert_text_contains "$snapshot" "signed state snapshot (${node_id})" "signed_state_target=${target}"
  fi
  if [[ "$snapshot" == *"signed_state_node_id="* ]]; then
    assert_text_contains "$snapshot" "signed state snapshot (${node_id})" "signed_state_node_id=${node_id}"
  fi
  if [[ "$snapshot" == *"signed_state_collected_at_utc="* ]]; then
    assert_text_contains "$snapshot" "signed state snapshot (${node_id})" "signed_state_collected_at_utc="
  fi

  signed_state="$(snapshot_section_or_self_text "$snapshot" "RNLAB_SIGNED_STATE")"
  assert_text_contains "$signed_state" "$signed_label" "signed_state_snapshot_version=1"
  assert_text_contains "$signed_state" "$signed_label" "signed_state_node_id=${node_id}"
  assert_text_contains "$signed_state" "$signed_label" "artifact_chain_result=pass"
  assert_text_contains "$signed_state" "$signed_label" "signed_state_health=pass"
  assert_text_contains "$signed_state" "$signed_label" "signed_artifact_chain_status=pass"
  assert_text_contains "$signed_state" "$signed_label" "signed_artifact_chain_ok"
  assert_text_contains "$signed_state" "$signed_label" "netcheck_rc=0"
  assert_text_contains "$signed_state" "$signed_label" "assignment_verify_rc=0"
  assert_text_contains "$signed_state" "$signed_label" "traversal_verify_rc=0"
  assert_text_contains "$signed_state" "$signed_label" "trust_verify_rc=0"
  assert_text_contains "$signed_state" "$signed_label" "dns_zone_verify_rc=0"

  netcheck_text="$(snapshot_named_block_text "$signed_state" "netcheck")"
  assert_text_contains "$netcheck_text" "$signed_label" "traversal_error=none"
  assert_text_absent "$netcheck_text" "$signed_label" "traversal_alarm_state=critical"
  assert_text_absent "$netcheck_text" "$signed_label" "traversal_alarm_state=error"
  assert_text_absent "$netcheck_text" "$signed_label" "traversal_alarm_state=missing"
  assert_text_absent "$netcheck_text" "$signed_label" "dns_alarm_state=critical"
  assert_text_absent "$netcheck_text" "$signed_label" "dns_alarm_state=error"
  assert_text_absent "$netcheck_text" "$signed_label" "dns_alarm_state=missing"
}

live_lab_wait_for_signed_state_convergence() {
  local target="$1"
  local node_id="$2"
  local role="${3:-}"
  local zone_name="${4:-${RUSTYNET_DNS_ZONE_NAME:-rustynet}}"
  local max_age_secs="${5:-${CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS:-900}}"
  local max_clock_skew_secs="${6:-${CROSS_NETWORK_MAX_TIME_SKEW_SECS:-2}}"
  local attempts="${7:-20}"
  local sleep_secs="${8:-3}"
  local attempt snapshot

  for ((attempt = 1; attempt <= attempts; attempt++)); do
    snapshot="$(live_lab_collect_signed_state_snapshot "$target" "$node_id" "$role" "$zone_name" "$max_age_secs" "$max_clock_skew_secs")" || snapshot=""
    if [[ -n "$snapshot" ]] && live_lab_assert_signed_state_health \
      "$snapshot" \
      "$node_id" \
      "$target" >/dev/null 2>&1; then
      printf '%s' "$snapshot"
      return 0
    fi
    if [[ "$attempt" -lt "$attempts" ]]; then
      sleep "$sleep_secs"
    fi
  done

  snapshot="$(live_lab_collect_signed_state_snapshot "$target" "$node_id" "$role" "$zone_name" "$max_age_secs" "$max_clock_skew_secs")" || snapshot=""
  printf '%s' "$snapshot"
  return 1
}

live_lab_assert_dns_zone_health() {
  local snapshot="$1"
  local node_id="$2"
  local target="$3"
  local dns_zone dns_label status_text inspect_text
  local status_rc dns_inspect_rc dns_zone_verify_rc
  local dns_zone_bundle_present dns_zone_verifier_present dns_zone_watermark_present

  dns_label="dns zone (${node_id})"
  if [[ "$snapshot" == *"dns_zone_target="* ]]; then
    assert_text_contains "$snapshot" "dns zone snapshot (${node_id})" "dns_zone_target=${target}"
  fi
  if [[ "$snapshot" == *"dns_zone_node_id="* ]]; then
    assert_text_contains "$snapshot" "dns zone snapshot (${node_id})" "dns_zone_node_id=${node_id}"
  fi
  if [[ "$snapshot" == *"dns_zone_collected_at_utc="* ]]; then
    assert_text_contains "$snapshot" "dns zone snapshot (${node_id})" "dns_zone_collected_at_utc="
  fi

  dns_zone="$(snapshot_section_or_self_text "$snapshot" "RNLAB_DNS_ZONE")"
  assert_text_contains "$dns_zone" "$dns_label" "dns_zone_snapshot_version=1"
  assert_text_contains "$dns_zone" "$dns_label" "dns_zone_node_id=${node_id}"
  assert_text_contains "$dns_zone" "$dns_label" "dns_zone_bundle_present=1"
  assert_text_contains "$dns_zone" "$dns_label" "dns_zone_verifier_present=1"
  assert_text_contains "$dns_zone" "$dns_label" "dns_zone_watermark_present=1"

  status_rc="$(snapshot_field_value "$dns_zone" "status_rc")"
  dns_inspect_rc="$(snapshot_field_value "$dns_zone" "dns_inspect_rc")"
  dns_zone_verify_rc="$(snapshot_field_value "$dns_zone" "dns_zone_verify_rc")"
  dns_zone_bundle_present="$(snapshot_field_value "$dns_zone" "dns_zone_bundle_present")"
  dns_zone_verifier_present="$(snapshot_field_value "$dns_zone" "dns_zone_verifier_present")"
  dns_zone_watermark_present="$(snapshot_field_value "$dns_zone" "dns_zone_watermark_present")"

  if [[ "$status_rc" != "0" ]]; then
    printf '%s expected rustynet status rc=0, got %s\n' "$dns_label" "${status_rc:-missing}" >&2
    return 1
  fi
  if [[ "$dns_inspect_rc" != "0" ]]; then
    printf '%s expected dns inspect rc=0, got %s\n' "$dns_label" "${dns_inspect_rc:-missing}" >&2
    return 1
  fi
  if [[ "$dns_zone_verify_rc" != "0" ]]; then
    printf '%s expected dns zone verify rc=0, got %s\n' "$dns_label" "${dns_zone_verify_rc:-missing}" >&2
    return 1
  fi
  if [[ "$dns_zone_bundle_present" != "1" || "$dns_zone_verifier_present" != "1" || "$dns_zone_watermark_present" != "1" ]]; then
    printf '%s expected bundle, verifier, and watermark presence\n' "$dns_label" >&2
    return 1
  fi

  status_text="$(snapshot_named_block_text "$dns_zone" "status")"
  inspect_text="$(snapshot_named_block_text "$dns_zone" "dns_inspect")"
  assert_text_contains "$status_text" "$dns_label" "node_id=${node_id}"
  assert_text_contains "$status_text" "$dns_label" "dns_zone_state=valid"
  assert_text_contains "$status_text" "$dns_label" "dns_zone_error=none"
  assert_text_contains "$status_text" "$dns_label" "dns_alarm_state=ok"
  assert_text_contains "$inspect_text" "$dns_label" "dns inspect: state=valid"
}

live_lab_wait_for_dns_zone_convergence() {
  local target="$1"
  local node_id="$2"
  local zone_name="${3:-${RUSTYNET_DNS_ZONE_NAME:-rustynet}}"
  local attempts="${4:-20}"
  local sleep_secs="${5:-3}"
  local attempt snapshot

  for ((attempt = 1; attempt <= attempts; attempt++)); do
    snapshot="$(live_lab_collect_dns_zone_snapshot "$target" "$node_id" "$zone_name")" || snapshot=""
    if [[ -n "$snapshot" ]] && live_lab_assert_dns_zone_health \
      "$snapshot" \
      "$node_id" \
      "$target" >/dev/null 2>&1; then
      printf '%s' "$snapshot"
      return 0
    fi
    if [[ "$attempt" -lt "$attempts" ]]; then
      sleep "$sleep_secs"
    fi
  done

  snapshot="$(live_lab_collect_dns_zone_snapshot "$target" "$node_id" "$zone_name")" || snapshot=""
  printf '%s' "$snapshot"
  return 1
}

live_lab_assert_firewall_policy() {
  local snapshot="$1"
  local node_id="$2"
  local target="$3"
  local role="$4"
  local firewall firewall_label firewall_ruleset
  local nft_tables_rc nft_ruleset_rc

  firewall_label="firewall policy (${node_id})"
  if [[ "$snapshot" == *"firewall_target="* ]]; then
    assert_text_contains "$snapshot" "firewall snapshot (${node_id})" "firewall_target=${target}"
  fi
  if [[ "$snapshot" == *"firewall_node_id="* ]]; then
    assert_text_contains "$snapshot" "firewall snapshot (${node_id})" "firewall_node_id=${node_id}"
  fi
  if [[ -n "$role" && "$snapshot" == *"firewall_role="* ]]; then
    assert_text_contains "$snapshot" "firewall snapshot (${node_id})" "firewall_role=${role}"
  fi

  firewall="$(snapshot_section_or_self_text "$snapshot" "RNLAB_FIREWALL")"
  assert_text_contains "$firewall" "$firewall_label" "firewall_snapshot_version=1"
  assert_text_contains "$firewall" "$firewall_label" "firewall_health=pass"
  assert_text_contains "$firewall" "$firewall_label" "firewall_status=pass"

  nft_tables_rc="$(snapshot_field_value "$firewall" "nft_tables_rc")"
  nft_ruleset_rc="$(snapshot_field_value "$firewall" "nft_ruleset_rc")"
  if [[ "$nft_tables_rc" != "0" ]]; then
    printf '%s expected nft list tables rc=0, got %s\n' "$firewall_label" "${nft_tables_rc:-missing}" >&2
    return 1
  fi
  if [[ "$nft_ruleset_rc" != "0" ]]; then
    printf '%s expected nft list ruleset rc=0, got %s\n' "$firewall_label" "${nft_ruleset_rc:-missing}" >&2
    return 1
  fi

  firewall_ruleset="$(snapshot_named_block_text "$firewall" "nft_ruleset")"
  if [[ -z "$(printf '%s' "$firewall_ruleset" | tr -d '[:space:]')" ]]; then
    printf '%s missing nft ruleset output\n' "$firewall_label" >&2
    return 1
  fi
  if ! grep -Eq 'table[[:space:]]+inet[[:space:]]+rustynet_g[0-9]+' <<<"$firewall_ruleset"; then
    printf '%s missing rustynet inet firewall table\n' "$firewall_label" >&2
    return 1
  fi
  if ! grep -Eq 'chain[[:space:]]+killswitch' <<<"$firewall_ruleset"; then
    printf '%s missing killswitch chain\n' "$firewall_label" >&2
    return 1
  fi
  if ! grep -Eq 'hook[[:space:]]+output' <<<"$firewall_ruleset"; then
    printf '%s missing output hook\n' "$firewall_label" >&2
    return 1
  fi
  if ! grep -Eq 'policy[[:space:]]+drop' <<<"$firewall_ruleset"; then
    printf '%s missing drop policy\n' "$firewall_label" >&2
    return 1
  fi
  if ! grep -Eq 'udp[[:space:]]+dport[[:space:]]+53.*oifname[[:space:]]+!=[[:space:]]+"?rustynet0"?[[:space:]]+drop' <<<"$firewall_ruleset"; then
    printf '%s missing UDP DNS fail-closed rule\n' "$firewall_label" >&2
    return 1
  fi
  if ! grep -Eq 'tcp[[:space:]]+dport[[:space:]]+53.*oifname[[:space:]]+!=[[:space:]]+"?rustynet0"?[[:space:]]+drop' <<<"$firewall_ruleset"; then
    printf '%s missing TCP DNS fail-closed rule\n' "$firewall_label" >&2
    return 1
  fi
  if ! grep -Eq 'udp[[:space:]]+dport[[:space:]]+53[[:space:]]+accept' <<<"$firewall_ruleset"; then
    printf '%s missing UDP DNS allow rule\n' "$firewall_label" >&2
    return 1
  fi
  if ! grep -Eq 'tcp[[:space:]]+dport[[:space:]]+53[[:space:]]+accept' <<<"$firewall_ruleset"; then
    printf '%s missing TCP DNS allow rule\n' "$firewall_label" >&2
    return 1
  fi

  if [[ "$role" == "exit" || "$role" == "admin" ]]; then
    if ! grep -Eq 'table[[:space:]]+ip[[:space:]]+rustynet_nat_g[0-9]+' <<<"$firewall_ruleset"; then
      printf '%s missing rustynet NAT table for exit role\n' "$firewall_label" >&2
      return 1
    fi
    if ! grep -Eq 'chain[[:space:]]+forward' <<<"$firewall_ruleset"; then
      printf '%s missing forward chain for exit role\n' "$firewall_label" >&2
      return 1
    fi
    if ! grep -Eq 'iifname[[:space:]]+"?rustynet0"?[[:space:]]+oifname[[:space:]]+[^ ]+[[:space:]]+accept' <<<"$firewall_ruleset"; then
      printf '%s missing rustynet forward accept rule for exit role\n' "$firewall_label" >&2
      return 1
    fi
    if ! grep -Eq 'chain[[:space:]]+postrouting' <<<"$firewall_ruleset"; then
      printf '%s missing postrouting chain for exit role\n' "$firewall_label" >&2
      return 1
    fi
    if ! grep -Eq 'masquerade' <<<"$firewall_ruleset"; then
      printf '%s missing masquerade rule for exit role\n' "$firewall_label" >&2
      return 1
    fi
  fi
}

live_lab_assert_runtime_spec() {
  local snapshot="$1"
  local node_id="$2"
  local target="$3"
  local role="$4"
  local expected_membership_nodes="$5"
  local exit_node_id="$6"
  local status route_check secret_hygiene
  local status_label route_label hygiene_label

  status_label="baseline status (${node_id})"
  route_label="route check (${node_id})"
  hygiene_label="plaintext check (${node_id})"

  assert_text_contains "$snapshot" "runtime snapshot (${node_id})" "node_snapshot_version=1"
  assert_text_contains "$snapshot" "runtime snapshot (${node_id})" "target=${target}"
  assert_text_contains "$snapshot" "runtime snapshot (${node_id})" "node_id=${node_id}"
  assert_text_contains "$snapshot" "runtime snapshot (${node_id})" "role=${role}"

  status="$(snapshot_section_text "$snapshot" "RNLAB_STATUS")"
  route_check="$(snapshot_section_text "$snapshot" "RNLAB_ROUTE_POLICY")"
  secret_hygiene="$(snapshot_section_text "$snapshot" "RNLAB_SECRET_HYGIENE")"

  assert_text_contains "$status" "$status_label" "transport_socket_identity_state=authoritative_backend_shared_transport"
  assert_text_contains "$status" "$status_label" "transport_socket_identity_error=none"
  assert_text_contains "$status" "$status_label" "encrypted_key_store=true"
  assert_text_contains "$status" "$status_label" "auto_tunnel_enforce=true"
  assert_text_contains "$status" "$status_label" "membership_active_nodes=${expected_membership_nodes}"
  assert_text_absent "$status" "$status_label" "does not yet implement route application"
  assert_text_absent "$status" "$status_label" "does not yet implement exit mode"

  assert_text_contains "$route_check" "$route_label" "route_policy_version=1"
  assert_text_contains "$secret_hygiene" "$hygiene_label" "daemon_socket=present"
  assert_text_contains "$secret_hygiene" "$hygiene_label" "result=no-plaintext-passphrase-files"

  if [[ "$role" == "client" ]]; then
    assert_text_contains "$status" "$status_label" "exit_node=${exit_node_id}"
    assert_text_contains "$route_check" "$route_label" "actual_route_device=rustynet0"
    assert_text_contains "$route_check" "$route_label" "actual_route_table=51820"
    assert_text_contains "$route_check" "$route_label" "expected_next_hop_match=pass"
  fi
}

assert_no_managed_dns_service_errors() {
  local log_path="$1"
  local label="$2"
  assert_log_absent_patterns \
    "$log_path" \
    "$label" \
    "$MANAGED_DNS_FATAL_PATTERN_1" \
    "$MANAGED_DNS_FATAL_PATTERN_2" \
    "$MANAGED_DNS_FATAL_PATTERN_3"
}

stage_run_live_managed_dns() {
  local canonical_report canonical_log stage_report stage_log
  local label
  canonical_report="$ROOT_DIR/artifacts/phase10/source/managed_dns_report.json"
  canonical_log="$ROOT_DIR/artifacts/phase10/source/managed_dns_report.log"
  stage_report="$REPORT_DIR/live_linux_managed_dns_report.json"
  stage_log="$REPORT_DIR/live_linux_managed_dns.log"
  local -a cmd=(
    env "RUSTYNET_EXPECTED_GIT_COMMIT=$(current_run_git_commit)"
    bash "$ROOT_DIR/scripts/e2e/live_linux_managed_dns_test.sh"
    --ssh-identity-file "$SSH_IDENTITY_FILE"
    --signer-host "$(node_target_for_label exit)"
    --signer-node-id "$(node_id_for_label exit)"
    --client-host "$(node_target_for_label client)"
    --client-node-id "$(node_id_for_label client)"
  )
  while IFS= read -r label; do
    [[ -n "$label" ]] || continue
    cmd+=(
      --managed-peer "$(node_id_for_label "$label")|$(node_target_for_label "$label")"
    )
  done < <(managed_peer_labels)
  cmd+=(
    --ssh-allow-cidrs "$SSH_ALLOW_CIDRS"
    --report-path "$stage_report"
    --log-path "$stage_log"
  )
  "${cmd[@]}" || return 1
  assert_json_report_status_pass "$stage_report" "live managed DNS" || return 1
  assert_no_managed_dns_service_errors "$stage_log" "live managed DNS" || return 1
  mkdir -p "$(dirname "$canonical_report")" || return 1
  cp "$stage_report" "$canonical_report" || return 1
  cp "$stage_log" "$canonical_log" || return 1
}

run_periodic_managed_dns_refresh() {
  local checkpoint_label="$1"
  local refresh_report refresh_log
  local label
  refresh_report="$REPORT_DIR/live_linux_managed_dns_refresh_${checkpoint_label}.json"
  refresh_log="$REPORT_DIR/live_linux_managed_dns_refresh_${checkpoint_label}.log"
  local -a cmd=(
    env "RUSTYNET_EXPECTED_GIT_COMMIT=$(current_run_git_commit)"
    bash "$ROOT_DIR/scripts/e2e/live_linux_managed_dns_test.sh"
    --ssh-identity-file "$SSH_IDENTITY_FILE"
    --signer-host "$(node_target_for_label exit)"
    --signer-node-id "$(node_id_for_label exit)"
    --client-host "$(node_target_for_label client)"
    --client-node-id "$(node_id_for_label client)"
  )
  while IFS= read -r label; do
    [[ -n "$label" ]] || continue
    cmd+=(
      --managed-peer "$(node_id_for_label "$label")|$(node_target_for_label "$label")"
    )
  done < <(managed_peer_labels)
  cmd+=(
    --ssh-allow-cidrs "$SSH_ALLOW_CIDRS"
    --report-path "$refresh_report"
    --log-path "$refresh_log"
  )
  "${cmd[@]}" || return 1
  assert_json_report_status_pass "$refresh_report" "managed DNS refresh (${checkpoint_label})" || return 1
  assert_no_managed_dns_service_errors "$refresh_log" "managed DNS refresh (${checkpoint_label})" || return 1
}

assert_no_dns_zone_stale_status() {
  local log_path="$1"
  local label="$2"
  assert_log_absent_patterns \
    "$log_path" \
    "$label" \
    'dns_zone_state=invalid' \
    'dns_zone_bundle_is_stale'
}

assert_client_dns_zone_valid_in_log() {
  local log_path="$1"
  local label="$2"
  local client_node_id pattern
  client_node_id="$(node_id_for_label client)"
  pattern="node_id=${client_node_id} .*dns_zone_state=valid .*dns_zone_error=none"
  assert_log_contains_pattern "$log_path" "$label" "$pattern"
}

stage_run_cross_network_direct_remote_exit() {
  local nat_profile="${1:-baseline_lan}"
  local report_path="${2:-$REPORT_DIR/cross_network_direct_remote_exit_report.json}"
  local log_path="${3:-$REPORT_DIR/cross_network_direct_remote_exit.log}"
  local client_underlay_ip exit_underlay_ip
  client_underlay_ip="$(cross_network_underlay_ip_for_label client)"
  exit_underlay_ip="$(cross_network_underlay_ip_for_label exit)"
  local -a cmd=(
    env "RUSTYNET_EXPECTED_GIT_COMMIT=$(current_run_git_commit)"
    bash "$ROOT_DIR/scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh"
    --ssh-identity-file "$SSH_IDENTITY_FILE" \
    --client-host "$(node_target_for_label client)" \
    --exit-host "$(node_target_for_label exit)" \
    --client-node-id "$(node_id_for_label client)" \
    --exit-node-id "$(node_id_for_label exit)" \
    --client-network-id "$(cross_network_network_id_for_label client)" \
    --exit-network-id "$(cross_network_network_id_for_label exit)" \
    --client-underlay-ip "$client_underlay_ip" \
    --exit-underlay-ip "$exit_underlay_ip" \
    --nat-profile "$nat_profile" \
    --impairment-profile "$CROSS_NETWORK_IMPAIRMENT_PROFILE" \
    --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
    --report-path "$report_path" \
    --log-path "$log_path"
  )
  run_cross_network_stage_with_impairment direct "${cmd[@]}"
}

stage_run_cross_network_relay_remote_exit() {
  local nat_profile="${1:-baseline_lan}"
  local report_path="${2:-$REPORT_DIR/cross_network_relay_remote_exit_report.json}"
  local log_path="${3:-$REPORT_DIR/cross_network_relay_remote_exit.log}"
  local relay_label relay_underlay_ip
  if ! relay_label="$(cross_network_relay_label)"; then
    printf 'cross-network relay remote-exit validation requires entry or aux target\n' >&2
    return 1
  fi
  relay_underlay_ip="$(cross_network_override_underlay_ip_for_label relay)"
  if [[ -z "$relay_underlay_ip" ]]; then
    relay_underlay_ip="$(cross_network_underlay_ip_for_label "$relay_label")"
  fi
  local -a cmd=(
    env "RUSTYNET_EXPECTED_GIT_COMMIT=$(current_run_git_commit)"
    bash "$ROOT_DIR/scripts/e2e/live_linux_cross_network_relay_remote_exit_test.sh"
    --ssh-identity-file "$SSH_IDENTITY_FILE" \
    --client-host "$(node_target_for_label client)" \
    --exit-host "$(node_target_for_label exit)" \
    --relay-host "$(node_target_for_label "$relay_label")" \
    --client-node-id "$(node_id_for_label client)" \
    --exit-node-id "$(node_id_for_label exit)" \
    --relay-node-id "$(node_id_for_label "$relay_label")" \
    --client-network-id "$(cross_network_network_id_for_label client)" \
    --exit-network-id "$(cross_network_network_id_for_label exit)" \
    --relay-network-id "$(cross_network_network_id_for_label "$relay_label")" \
    --client-underlay-ip "$(cross_network_underlay_ip_for_label client)" \
    --exit-underlay-ip "$(cross_network_underlay_ip_for_label exit)" \
    --relay-underlay-ip "$relay_underlay_ip" \
    --nat-profile "$nat_profile" \
    --impairment-profile "$CROSS_NETWORK_IMPAIRMENT_PROFILE" \
    --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
    --report-path "$report_path" \
    --log-path "$log_path"
  )
  run_cross_network_stage_with_impairment relay "${cmd[@]}"
}

stage_run_cross_network_failback_roaming() {
  local nat_profile="${1:-baseline_lan}"
  local report_path="${2:-$REPORT_DIR/cross_network_failback_roaming_report.json}"
  local log_path="${3:-$REPORT_DIR/cross_network_failback_roaming.log}"
  local relay_label relay_underlay_ip
  if ! relay_label="$(cross_network_relay_label)"; then
    printf 'cross-network failback and roaming validation requires entry or aux target\n' >&2
    return 1
  fi
  relay_underlay_ip="$(cross_network_override_underlay_ip_for_label relay)"
  if [[ -z "$relay_underlay_ip" ]]; then
    relay_underlay_ip="$(cross_network_underlay_ip_for_label "$relay_label")"
  fi
  local -a cmd=(
    env "RUSTYNET_EXPECTED_GIT_COMMIT=$(current_run_git_commit)"
    bash "$ROOT_DIR/scripts/e2e/live_linux_cross_network_failback_roaming_test.sh"
    --ssh-identity-file "$SSH_IDENTITY_FILE" \
    --client-host "$(node_target_for_label client)" \
    --exit-host "$(node_target_for_label exit)" \
    --relay-host "$(node_target_for_label "$relay_label")" \
    --client-node-id "$(node_id_for_label client)" \
    --exit-node-id "$(node_id_for_label exit)" \
    --relay-node-id "$(node_id_for_label "$relay_label")" \
    --client-network-id "$(cross_network_network_id_for_label client)" \
    --exit-network-id "$(cross_network_network_id_for_label exit)" \
    --relay-network-id "$(cross_network_network_id_for_label "$relay_label")" \
    --client-underlay-ip "$(cross_network_underlay_ip_for_label client)" \
    --exit-underlay-ip "$(cross_network_underlay_ip_for_label exit)" \
    --relay-underlay-ip "$relay_underlay_ip" \
    --nat-profile "$nat_profile" \
    --impairment-profile "$CROSS_NETWORK_IMPAIRMENT_PROFILE" \
    --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
    --report-path "$report_path" \
    --log-path "$log_path"
  )
  run_cross_network_stage_with_impairment failback "${cmd[@]}"
}

stage_run_cross_network_traversal_adversarial() {
  local nat_profile="${1:-baseline_lan}"
  local report_path="${2:-$REPORT_DIR/cross_network_traversal_adversarial_report.json}"
  local log_path="${3:-$REPORT_DIR/cross_network_traversal_adversarial.log}"
  local probe_label
  if ! probe_label="$(cross_network_probe_label)"; then
    printf 'cross-network traversal adversarial validation requires entry or aux target\n' >&2
    return 1
  fi
  local -a cmd=(
    env "RUSTYNET_EXPECTED_GIT_COMMIT=$(current_run_git_commit)"
    bash "$ROOT_DIR/scripts/e2e/live_linux_cross_network_traversal_adversarial_test.sh"
    --ssh-identity-file "$SSH_IDENTITY_FILE" \
    --client-host "$(node_target_for_label client)" \
    --exit-host "$(node_target_for_label exit)" \
    --probe-host "$(node_target_for_label "$probe_label")" \
    --client-network-id "$(cross_network_network_id_for_label client)" \
    --exit-network-id "$(cross_network_network_id_for_label exit)" \
    --nat-profile "$nat_profile" \
    --impairment-profile "$CROSS_NETWORK_IMPAIRMENT_PROFILE" \
    --report-path "$report_path" \
    --log-path "$log_path"
  )
  run_cross_network_stage_with_impairment adversarial "${cmd[@]}"
}

stage_run_cross_network_remote_exit_dns() {
  local nat_profile="${1:-baseline_lan}"
  local report_path="${2:-$REPORT_DIR/cross_network_remote_exit_dns_report.json}"
  local log_path="${3:-$REPORT_DIR/cross_network_remote_exit_dns.log}"
  local client_underlay_ip exit_underlay_ip
  client_underlay_ip="$(cross_network_underlay_ip_for_label client)"
  exit_underlay_ip="$(cross_network_underlay_ip_for_label exit)"
  local -a cmd=(
    env "RUSTYNET_EXPECTED_GIT_COMMIT=$(current_run_git_commit)"
    bash "$ROOT_DIR/scripts/e2e/live_linux_cross_network_remote_exit_dns_test.sh"
    --ssh-identity-file "$SSH_IDENTITY_FILE" \
    --client-host "$(node_target_for_label client)" \
    --exit-host "$(node_target_for_label exit)" \
    --client-node-id "$(node_id_for_label client)" \
    --exit-node-id "$(node_id_for_label exit)" \
    --client-network-id "$(cross_network_network_id_for_label client)" \
    --exit-network-id "$(cross_network_network_id_for_label exit)" \
    --client-underlay-ip "$client_underlay_ip" \
    --exit-underlay-ip "$exit_underlay_ip" \
    --nat-profile "$nat_profile" \
    --impairment-profile "$CROSS_NETWORK_IMPAIRMENT_PROFILE" \
    --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
    --report-path "$report_path" \
    --log-path "$log_path"
  )
  run_cross_network_stage_with_impairment dns "${cmd[@]}"
}

stage_run_cross_network_remote_exit_soak() {
  local nat_profile="${1:-baseline_lan}"
  local report_path="${2:-$REPORT_DIR/cross_network_remote_exit_soak_report.json}"
  local log_path="${3:-$REPORT_DIR/cross_network_remote_exit_soak.log}"
  local client_underlay_ip exit_underlay_ip
  client_underlay_ip="$(cross_network_underlay_ip_for_label client)"
  exit_underlay_ip="$(cross_network_underlay_ip_for_label exit)"
  local -a cmd=(
    env "RUSTYNET_EXPECTED_GIT_COMMIT=$(current_run_git_commit)"
    bash "$ROOT_DIR/scripts/e2e/live_linux_cross_network_remote_exit_soak_test.sh"
    --ssh-identity-file "$SSH_IDENTITY_FILE" \
    --client-host "$(node_target_for_label client)" \
    --exit-host "$(node_target_for_label exit)" \
    --client-node-id "$(node_id_for_label client)" \
    --exit-node-id "$(node_id_for_label exit)" \
    --client-network-id "$(cross_network_network_id_for_label client)" \
    --exit-network-id "$(cross_network_network_id_for_label exit)" \
    --client-underlay-ip "$client_underlay_ip" \
    --exit-underlay-ip "$exit_underlay_ip" \
    --nat-profile "$nat_profile" \
    --impairment-profile "$CROSS_NETWORK_IMPAIRMENT_PROFILE" \
    --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
    --report-path "$report_path" \
    --log-path "$log_path"
  )
  run_cross_network_stage_with_impairment soak "${cmd[@]}"
}

stage_run_cross_network_controller_switch() {
  local nat_profile="${1:-baseline_lan}"
  local report_path="${2:-$REPORT_DIR/cross_network_controller_switch_report.json}"
  local log_path="${3:-$REPORT_DIR/cross_network_controller_switch.log}"
  local relay_label relay_underlay_ip
  if ! relay_label="$(cross_network_relay_label)"; then
    printf 'cross-network controller-switch validation requires entry or aux target\n' >&2
    return 1
  fi
  relay_underlay_ip="$(cross_network_override_underlay_ip_for_label relay)"
  if [[ -z "$relay_underlay_ip" ]]; then
    relay_underlay_ip="$(cross_network_underlay_ip_for_label "$relay_label")"
  fi
  local -a cmd=(
    env "RUSTYNET_EXPECTED_GIT_COMMIT=$(current_run_git_commit)"
    bash "$ROOT_DIR/scripts/e2e/live_linux_cross_network_controller_switch_test.sh"
    --ssh-identity-file "$SSH_IDENTITY_FILE" \
    --client-host "$(node_target_for_label client)" \
    --exit-host "$(node_target_for_label exit)" \
    --relay-host "$(node_target_for_label "$relay_label")" \
    --client-node-id "$(node_id_for_label client)" \
    --exit-node-id "$(node_id_for_label exit)" \
    --relay-node-id "$(node_id_for_label "$relay_label")" \
    --client-network-id "$(cross_network_network_id_for_label client)" \
    --exit-network-id "$(cross_network_network_id_for_label exit)" \
    --relay-network-id "$(cross_network_network_id_for_label "$relay_label")" \
    --client-underlay-ip "$(cross_network_underlay_ip_for_label client)" \
    --exit-underlay-ip "$(cross_network_underlay_ip_for_label exit)" \
    --relay-underlay-ip "$relay_underlay_ip" \
    --nat-profile "$nat_profile" \
    --impairment-profile "$CROSS_NETWORK_IMPAIRMENT_PROFILE" \
    --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
    --report-path "$report_path" \
    --log-path "$log_path"
  )
  run_cross_network_stage_with_impairment controller_switch "${cmd[@]}"
}

stage_run_cross_network_node_network_switch() {
  local nat_profile="${1:-baseline_lan}"
  local report_path="${2:-$REPORT_DIR/cross_network_node_network_switch_report.json}"
  local log_path="${3:-$REPORT_DIR/cross_network_node_network_switch.log}"
  local client_underlay_ip exit_underlay_ip
  client_underlay_ip="$(cross_network_underlay_ip_for_label client)"
  exit_underlay_ip="$(cross_network_underlay_ip_for_label exit)"
  local -a cmd=(
    env "RUSTYNET_EXPECTED_GIT_COMMIT=$(current_run_git_commit)"
    bash "$ROOT_DIR/scripts/e2e/live_linux_cross_network_node_network_switch_test.sh"
    --ssh-identity-file "$SSH_IDENTITY_FILE" \
    --client-host "$(node_target_for_label client)" \
    --exit-host "$(node_target_for_label exit)" \
    --client-node-id "$(node_id_for_label client)" \
    --exit-node-id "$(node_id_for_label exit)" \
    --client-network-id "$(cross_network_network_id_for_label client)" \
    --exit-network-id "$(cross_network_network_id_for_label exit)" \
    --client-underlay-ip "$client_underlay_ip" \
    --exit-underlay-ip "$exit_underlay_ip" \
    --nat-profile "$nat_profile" \
    --impairment-profile "$CROSS_NETWORK_IMPAIRMENT_PROFILE" \
    --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
    --report-path "$report_path" \
    --log-path "$log_path"
  )
  run_cross_network_stage_with_impairment node_switch "${cmd[@]}"
}

cross_network_preflight_worker() {
  local label="$1"
  local target="$2"
  local node_id="$3"
  local _role="$4"
  local stage_dir capability_path
  local remote_unix local_unix skew
  local cmd
  local required_user_cmds=(rustynet rustynetd wg systemctl ss ip nft journalctl)
  local required_root_cmds=(wg systemctl ss ip nft journalctl)
  local time_snapshot time_rc time_path time_section
  local process_snapshot process_rc process_path
  local socket_snapshot socket_rc socket_path
  local permissions_snapshot permissions_rc permissions_path
  local signed_state_snapshot signed_state_rc signed_state_path route_snapshot endpoint_snapshot
  local route_policy_snapshot route_policy_rc route_policy_path
  local dns_state_snapshot dns_state_rc dns_state_path
  local dns_zone_snapshot dns_zone_rc dns_zone_path
  local node_snapshot node_snapshot_rc
  local global_ipv4 hostname_resolution_snapshot plaintext_snapshot
  local remote_src discovery_script_path discovery_remote_path discovery_local_path discovery_validation_path
  local discovery_hash

  stage_dir="$(parallel_stage_dir cross_network_preflight)"
  capability_path="${stage_dir}/capabilities-${label}.txt"
  : > "$capability_path"

  live_lab_push_sudo_password "$target"
  live_lab_wait_for_daemon_socket "$target"
  set +e
  dns_state_snapshot="$(live_lab_wait_for_dns_convergence "$target" "$node_id")"
  dns_state_rc=$?
  set -e
  dns_state_path="$(stage_worker_write_artifact "$label" "dns_state.txt" "$(printf 'capture_rc=%s\n%s\n' "$dns_state_rc" "$dns_state_snapshot")")" || return 1
  if [[ "$dns_state_rc" -ne 0 ]]; then
    printf 'dns health did not converge for %s (%s)\n' "$label" "$target" >&2
    return "$dns_state_rc"
  fi
  local_unix="${CROSS_NETWORK_PREFLIGHT_REFERENCE_UNIX:-0}"
  if [[ ! "$local_unix" =~ ^[0-9]+$ ]] || (( local_unix <= 0 )); then
    printf 'invalid preflight local unix reference for %s (%s): %s\n' "$label" "$target" "$local_unix" >&2
    return 1
  fi
  set +e
  time_snapshot="$(live_lab_collect_time_snapshot "$target" "$node_id" "$_role" "$local_unix" "$CROSS_NETWORK_MAX_TIME_SKEW_SECS" 2>&1)"
  time_rc=$?
  set -e
  time_path="$(stage_worker_write_artifact "$label" "time.txt" "$(printf 'capture_rc=%s\n%s\n' "$time_rc" "$time_snapshot")")" || return 1
  if [[ "$time_rc" -ne 0 ]]; then
    printf 'time snapshot capture failed for %s (%s)\n' "$label" "$target" >&2
    return "$time_rc"
  fi
  live_lab_assert_time_sync "$time_snapshot" "$node_id" "$target" || return 1
  time_section="$(snapshot_section_or_self_text "$time_snapshot" "RNLAB_TIME")"
  remote_unix="$(snapshot_field_value "$time_section" "remote_unix_now")"
  skew="$(snapshot_field_value "$time_section" "clock_skew_secs")"
  if [[ ! "$remote_unix" =~ ^[0-9]+$ || ! "$skew" =~ ^[0-9]+$ ]]; then
    printf 'time snapshot missing parsed skew data for %s (%s)\n' "$label" "$target" >&2
    return 1
  fi

  set +e
  process_snapshot="$(live_lab_collect_process_snapshot "$target" "$node_id" "$_role" 2>&1)"
  process_rc=$?
  set -e
  process_path="$(stage_worker_write_artifact "$label" "process.txt" "$(printf 'capture_rc=%s\n%s\n' "$process_rc" "$process_snapshot")")" || return 1
  [[ "$process_rc" -eq 0 ]] || return "$process_rc"
  live_lab_assert_process_health "$process_snapshot" "$node_id" "$target" "$_role" || return 1

  set +e
  socket_snapshot="$(live_lab_collect_socket_snapshot "$target" "$node_id" "$_role" 2>&1)"
  socket_rc=$?
  set -e
  socket_path="$(stage_worker_write_artifact "$label" "socket.txt" "$(printf 'capture_rc=%s\n%s\n' "$socket_rc" "$socket_snapshot")")" || return 1
  [[ "$socket_rc" -eq 0 ]] || return "$socket_rc"
  live_lab_assert_socket_health "$socket_snapshot" "$node_id" "$target" "$_role" || return 1

  set +e
  permissions_snapshot="$(live_lab_collect_permissions_snapshot "$target" "$node_id" "$_role" 2>&1)"
  permissions_rc=$?
  set -e
  permissions_path="$(stage_worker_write_artifact "$label" "permissions.txt" "$(printf 'capture_rc=%s\n%s\n' "$permissions_rc" "$permissions_snapshot")")" || return 1
  [[ "$permissions_rc" -eq 0 ]] || return "$permissions_rc"
  live_lab_assert_permissions_hardening "$permissions_snapshot" "$node_id" "$target" "$_role" || return 1

  if [[ "$CROSS_NETWORK_IMPAIRMENT_PROFILE" != "none" ]]; then
    required_user_cmds+=(tc)
    required_root_cmds+=(tc)
  fi

  for cmd in "${required_user_cmds[@]}"; do
    if ! live_lab_capture "$target" "command -v '$cmd'" >/dev/null 2>&1; then
      printf 'missing required user command on %s (%s): %s\n' "$label" "$target" "$cmd" >&2
      return 1
    fi
  done
  for cmd in "${required_root_cmds[@]}"; do
    if ! live_lab_run_root "$target" "root command -v '$cmd' >/dev/null"; then
      printf 'missing required root command on %s (%s): %s\n' "$label" "$target" "$cmd" >&2
      return 1
    fi
  done

  remote_src="$(live_lab_remote_src_dir "$target")"
  discovery_script_path="${remote_src}/scripts/operations/collect_network_discovery_info.sh"
  if ! live_lab_run_root "$target" "root test -f '$discovery_script_path'"; then
    printf 'missing discovery script on %s (%s): %s\n' "$label" "$target" "$discovery_script_path" >&2
    return 1
  fi
  if [[ "$CROSS_NETWORK_IMPAIRMENT_PROFILE" != "none" ]]; then
    if ! live_lab_run_root "$target" "root test -f '${remote_src}/scripts/e2e/apply_cross_network_impairment_profile.sh'"; then
      printf 'missing impairment profile script on %s (%s)\n' "$label" "$target" >&2
      return 1
    fi
  fi

  global_ipv4="$(live_lab_capture "$target" "ip -4 -o addr show up scope global | awk '{print \$4; exit}' | cut -d/ -f1" | tr -d '[:space:]')"
  if [[ -z "$global_ipv4" ]]; then
    printf 'missing global IPv4 address on %s (%s)\n' "$label" "$target" >&2
    return 1
  fi
  if ! live_lab_capture "$target" "ip -4 route show default | awk '/^default/{found=1} END{exit(found?0:1)}'" >/dev/null 2>&1; then
    printf 'missing default IPv4 route on %s (%s)\n' "$label" "$target" >&2
    return 1
  fi
  hostname_resolution_snapshot="$(live_lab_capture "$target" 'current_hostname="$(hostname)"; getent hosts "$current_hostname" 2>/dev/null | head -n 1 || true')"
  if [[ -z "$(printf '%s' "$hostname_resolution_snapshot" | tr -d '[:space:]')" ]]; then
    printf 'hostname does not resolve locally on %s (%s); fix /etc/hosts or local resolver\n' "$label" "$target" >&2
    return 1
  fi

  set +e
  dns_zone_snapshot="$(live_lab_wait_for_dns_zone_convergence "$target" "$node_id")"
  dns_zone_rc=$?
  set -e
  dns_zone_path="$(stage_worker_write_artifact "$label" "dns_zone.txt" "$(printf 'capture_rc=%s\n%s\n' "$dns_zone_rc" "$dns_zone_snapshot")")" || return 1
  if [[ "$dns_zone_rc" -ne 0 ]]; then
    printf 'dns zone health did not converge for %s (%s)\n' "$label" "$target" >&2
    return "$dns_zone_rc"
  fi

  set +e
  signed_state_snapshot="$(live_lab_wait_for_signed_state_convergence "$target" "$node_id" "$_role")"
  signed_state_rc=$?
  set -e
  signed_state_path="$(stage_worker_write_artifact "$label" "signed_state.txt" "$(printf 'capture_rc=%s\n%s\n' "$signed_state_rc" "$signed_state_snapshot")")" || return 1
  if [[ "$signed_state_rc" -ne 0 ]]; then
    printf 'signed state did not converge for %s (%s)\n' "$label" "$target" >&2
    return "$signed_state_rc"
  fi

  live_lab_run_root "$target" "root test -S /run/rustynet/rustynetd.sock"
  live_lab_run_root "$target" "root systemctl is-active --quiet rustynetd.service"
  live_lab_run_root "$target" "root systemctl is-active --quiet rustynetd-privileged-helper.service"
  plaintext_snapshot="$(live_lab_no_plaintext_passphrase_check "$target" || true)"
  if [[ "$plaintext_snapshot" != *"no-plaintext-passphrase-files"* ]]; then
    printf 'plaintext passphrase files detected on %s (%s)\n' "$label" "$target" >&2
    return 1
  fi

  discovery_remote_path="/tmp/rn-cross-network-discovery-${label}.json"
  discovery_local_path="${stage_dir}/discovery-${label}.json"
  discovery_validation_path="${stage_dir}/discovery-${label}.md"
  live_lab_run_root "$target" "root bash '$discovery_script_path' --quiet --output '$discovery_remote_path'"
  live_lab_scp_from "$target" "$discovery_remote_path" "$discovery_local_path"
  live_lab_run_root "$target" "root rustynet ops secure-remove --path '$discovery_remote_path' >/dev/null 2>&1 || root rm -f '$discovery_remote_path'" || true
  cargo run --quiet -p rustynet-cli -- ops validate-network-discovery-bundle \
    --bundle "$discovery_local_path" \
    --max-age-seconds "$CROSS_NETWORK_DISCOVERY_MAX_AGE_SECS" \
    --require-verifier-keys \
    --require-daemon-active \
    --require-socket-present \
    --output "$discovery_validation_path"
  discovery_hash="$(cargo run --quiet -p rustynet-cli -- ops sha256-file --path "$discovery_local_path")"

  set +e
  route_policy_snapshot="$(live_lab_collect_route_policy "$target" 2>&1)"
  route_policy_rc=$?
  set -e
  [[ "$route_policy_rc" -eq 0 ]] || return "$route_policy_rc"
  [[ "$dns_state_rc" -eq 0 ]] || return "$dns_state_rc"
  set +e
  node_snapshot="$(live_lab_collect_node_snapshot "$target" "$node_id" "$_role" 2>&1)"
  node_snapshot_rc=$?
  set -e
  [[ "$node_snapshot_rc" -eq 0 ]] || return "$node_snapshot_rc"
  stage_worker_write_artifact "$label" "snapshot.txt" "$(printf 'capture_rc=%s\n%s\n' "$node_snapshot_rc" "$node_snapshot")" >/dev/null || return 1
  route_policy_path="$(stage_worker_write_artifact "$label" "route_policy.txt" "$(printf 'capture_rc=%s\n%s\n' "$route_policy_rc" "$route_policy_snapshot")")" || return 1
  route_snapshot="$(awk '
    /route_get_begin/ { capture=1; next }
    /route_get_end/ { capture=0; next }
    capture { print }
  ' <<<"$route_policy_snapshot" | tr -s ' ' | tr '\n' ';')"
  endpoint_snapshot="$(live_lab_capture_root "$target" "root wg show rustynet0 endpoints || true" || true)"

  printf 'label=%s\n' "$label" >> "$capability_path"
  printf 'target=%s\n' "$target" >> "$capability_path"
  printf 'node_id=%s\n' "$node_id" >> "$capability_path"
  printf 'local_unix=%s\n' "$local_unix" >> "$capability_path"
  printf 'remote_unix=%s\n' "$remote_unix" >> "$capability_path"
  printf 'clock_skew_secs=%s\n' "$skew" >> "$capability_path"
  printf 'max_clock_skew_secs=%s\n' "$CROSS_NETWORK_MAX_TIME_SKEW_SECS" >> "$capability_path"
  printf 'time_path=%s\n' "$time_path" >> "$capability_path"
  printf 'process_path=%s\n' "$process_path" >> "$capability_path"
  printf 'socket_path=%s\n' "$socket_path" >> "$capability_path"
  printf 'permissions_path=%s\n' "$permissions_path" >> "$capability_path"
  printf 'signed_artifact_max_age_secs=%s\n' "$CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS" >> "$capability_path"
  printf 'discovery_bundle_max_age_secs=%s\n' "$CROSS_NETWORK_DISCOVERY_MAX_AGE_SECS" >> "$capability_path"
  printf 'global_ipv4=%s\n' "$global_ipv4" >> "$capability_path"
  printf 'discovery_bundle_path=%s\n' "$discovery_local_path" >> "$capability_path"
  printf 'discovery_bundle_sha256=%s\n' "$discovery_hash" >> "$capability_path"
  printf 'discovery_validation_report=%s\n' "$discovery_validation_path" >> "$capability_path"
  printf 'hostname_resolution_snapshot=%s\n' "$(printf '%s' "$hostname_resolution_snapshot" | tr -s ' ' | tr '\n' ';')" >> "$capability_path"
  printf 'dns_zone_snapshot=%s\n' "$(printf '%s' "$dns_zone_snapshot" | tr -s ' ' | tr '\n' ';')" >> "$capability_path"
  printf 'dns_zone_path=%s\n' "$dns_zone_path" >> "$capability_path"
  printf 'signed_state_snapshot=%s\n' "$(printf '%s' "$signed_state_snapshot" | tr -s ' ' | tr '\n' ';')" >> "$capability_path"
  printf 'signed_state_path=%s\n' "$signed_state_path" >> "$capability_path"
  printf 'plaintext_snapshot=%s\n' "$(printf '%s' "$plaintext_snapshot" | tr -s ' ' | tr '\n' ';')" >> "$capability_path"
  printf 'route_snapshot=%s\n' "$(printf '%s' "$route_snapshot" | tr -s ' ' | tr '\n' ';')" >> "$capability_path"
  printf 'route_policy_path=%s\n' "$route_policy_path" >> "$capability_path"
  printf 'dns_state_path=%s\n' "$dns_state_path" >> "$capability_path"
  printf 'endpoint_snapshot=%s\n' "$(printf '%s' "$endpoint_snapshot" | tr -s ' ' | tr '\n' ';')" >> "$capability_path"
}

stage_run_cross_network_preflight() {
  local stage_dir report_path
  CROSS_NETWORK_PREFLIGHT_REFERENCE_UNIX="$(date +%s)"
  export CROSS_NETWORK_PREFLIGHT_REFERENCE_UNIX
  run_parallel_node_stage cross_network_preflight cross_network_preflight_worker

  stage_dir="$(parallel_stage_dir cross_network_preflight)"
  report_path="$REPORT_DIR/cross_network_preflight_report.json"
  cargo run --quiet -p rustynet-cli -- ops write-cross-network-preflight-report \
    --nodes-tsv "$NODES_TSV" \
    --stage-dir "$stage_dir" \
    --output "$report_path" \
    --reference-unix "$CROSS_NETWORK_PREFLIGHT_REFERENCE_UNIX" \
    --max-clock-skew-secs "$CROSS_NETWORK_MAX_TIME_SKEW_SECS" \
    --discovery-max-age-secs "$CROSS_NETWORK_DISCOVERY_MAX_AGE_SECS" \
    --signed-artifact-max-age-secs "$CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS" >/dev/null
}

stage_run_cross_network_nat_matrix() {
  local output_path="$REPORT_DIR/cross_network_remote_exit_nat_matrix_validation.md"
  cargo run --quiet -p rustynet-cli -- ops validate-cross-network-nat-matrix \
    --artifact-dir "$REPORT_DIR" \
    --required-nat-profiles "$CROSS_NETWORK_REQUIRED_NAT_PROFILES" \
    --expected-git-commit "$(current_run_git_commit)" \
    --require-pass-status \
    --output "$output_path"
}

stage_generate_fresh_install_os_matrix_report() {
  local commit_short role_report canonical_report canonical_source_dir
  local canonical_bootstrap_log canonical_baseline_log canonical_two_hop_report
  local canonical_role_switch_report canonical_lan_toggle_report canonical_exit_handoff_report
  local required_path
  if ! has_five_node_release_gate_topology; then
    printf 'fresh install OS matrix report generation requires the full five-node topology (entry, aux, and extra targets)\n' >&2
    return 1
  fi
  commit_short="$(current_run_git_commit_short)"
  role_report="$REPORT_DIR/role_switch_matrix_report_${commit_short}.json"
  canonical_report="$ROOT_DIR/artifacts/phase10/fresh_install_os_matrix_report.json"
  canonical_source_dir="$ROOT_DIR/artifacts/phase10/source/fresh_install_os_matrix"
  cargo run --quiet -p rustynet-cli -- ops rebind-linux-fresh-install-os-matrix-inputs \
    --dest-dir "$canonical_source_dir" \
    --bootstrap-log "$LOG_DIR/bootstrap_hosts.log" \
    --baseline-log "$LOG_DIR/validate_baseline_runtime.log" \
    --two-hop-report "$REPORT_DIR/live_linux_two_hop_report.json" \
    --role-switch-report "$role_report" \
    --lan-toggle-report "$REPORT_DIR/live_linux_lan_toggle_report.json" \
    --exit-handoff-report "$REPORT_DIR/live_linux_exit_handoff_report.json" >/dev/null
  canonical_bootstrap_log="$canonical_source_dir/bootstrap_hosts.log"
  canonical_baseline_log="$canonical_source_dir/validate_baseline_runtime.log"
  canonical_two_hop_report="$canonical_source_dir/live_linux_two_hop_report.json"
  canonical_role_switch_report="$canonical_source_dir/$(basename "$role_report")"
  canonical_lan_toggle_report="$canonical_source_dir/live_linux_lan_toggle_report.json"
  canonical_exit_handoff_report="$canonical_source_dir/live_linux_exit_handoff_report.json"
  for required_path in \
    "$canonical_bootstrap_log" \
    "$canonical_baseline_log" \
    "$canonical_two_hop_report" \
    "$canonical_role_switch_report" \
    "$canonical_lan_toggle_report" \
    "$canonical_exit_handoff_report"; do
    if [[ ! -f "$required_path" ]]; then
      printf 'fresh install OS matrix canonicalized input missing: %s\n' "$required_path" >&2
      return 1
    fi
  done
  cargo run --quiet -p rustynet-cli -- ops generate-linux-fresh-install-os-matrix-report \
    --output "$canonical_report" \
    --environment "linux-live-lab-orchestrator:${NETWORK_ID}" \
    --source-mode "$SOURCE_MODE" \
    --expected-git-commit-file "$STATE_DIR/git_head.txt" \
    --git-status-file "$STATE_DIR/git_status.txt" \
    --bootstrap-log "$canonical_bootstrap_log" \
    --baseline-log "$canonical_baseline_log" \
    --two-hop-report "$canonical_two_hop_report" \
    --role-switch-report "$canonical_role_switch_report" \
    --lan-toggle-report "$canonical_lan_toggle_report" \
    --exit-handoff-report "$canonical_exit_handoff_report" \
    --exit-node-id "$(node_id_for_label exit)" \
    --client-node-id "$(node_id_for_label client)" \
    --ubuntu-node-id "$(node_id_for_label entry)" \
    --fedora-node-id "$(node_id_for_label aux)" \
    --mint-node-id "$(node_id_for_label extra)"
  cp "$canonical_report" "$REPORT_DIR/fresh_install_os_matrix_report.json"
}

ssh_wait_for_host() {
  local target="$1"
  # Freshly restarted UTM guests can take several minutes before SSH is ready.
  # Keep the wait bounded, but long enough to cover a cold boot without
  # treating transient startup lag as a hard failure.
  local attempts="${2:-240}"
  local sleep_secs="${3:-5}"
  local attempt
  local rc
  local last_error=""
  local error_log
  error_log="$(mktemp "${TMPDIR:-/tmp}/rn-ssh-wait.XXXXXX")" || return 1
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    : > "$error_log"
    if live_lab_can_use_ssh_transport; then
      if live_lab_ssh_via_ssh "$target" "true" 15 >"$error_log" 2>&1; then
        rm -f "$error_log"
        return 0
      fi
      rc=$?
    else
      if live_lab_ssh "$target" "true" 15 >"$error_log" 2>&1; then
        rm -f "$error_log"
        return 0
      fi
      rc=$?
    fi
    last_error="$(cat "$error_log")"
    if [[ "$rc" -ne 255 ]]; then
      if [[ -n "$last_error" ]]; then
        printf '%s\n' "$last_error" >&2
      fi
      rm -f "$error_log"
      return "$rc"
    fi
    if [[ "$attempt" -lt "$attempts" ]]; then
      sleep "$sleep_secs"
    fi
  done
  if [[ -n "$last_error" ]]; then
    printf '%s\n' "$last_error" >&2
  fi
  rm -f "$error_log"
  return 1
}

capture_boot_id() {
  local target="$1"
  live_lab_capture "$target" "cat /proc/sys/kernel/random/boot_id" | tr -d '[:space:]'
}

capture_boot_id_with_retry() {
  local target="$1"
  local attempts="${2:-24}"
  local sleep_secs="${3:-2}"
  local attempt boot_id
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    boot_id="$(capture_boot_id "$target" || true)"
    if [[ "$boot_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
      printf '%s' "$boot_id"
      return 0
    fi
    sleep "$sleep_secs"
  done
  return 1
}

run_host_reboot() {
  local target="$1"
  live_lab_push_sudo_password "$target"
  live_lab_ssh "$target" "sudo -n systemctl reboot" 20 >/dev/null 2>&1 || true
}

stage_run_extended_soak() {
  local two_hop_pre_report="$REPORT_DIR/live_linux_two_hop_soak_pre_reboot_report.json"
  local two_hop_pre_log="$REPORT_DIR/live_linux_two_hop_soak_pre_reboot.log"
  local handoff_report="$REPORT_DIR/live_linux_exit_handoff_soak_report.json"
  local handoff_log="$REPORT_DIR/live_linux_exit_handoff_soak.log"
  local lan_report="$REPORT_DIR/live_linux_lan_toggle_soak_report.json"
  local lan_log="$REPORT_DIR/live_linux_lan_toggle_soak.log"
  local reboot_report="$REPORT_DIR/live_linux_reboot_recovery_report.json"
  local reboot_log="$REPORT_DIR/live_linux_reboot_recovery.log"
  run_periodic_managed_dns_refresh "soak_pre_two_hop" || return 1
  RUSTYNET_EXPECTED_GIT_COMMIT="$(current_run_git_commit)" \
  bash "$ROOT_DIR/scripts/e2e/live_linux_two_hop_test.sh" \
    --ssh-identity-file "$SSH_IDENTITY_FILE" \
    --known-hosts "$SSH_KNOWN_HOSTS_FILE" \
    --final-exit-host "$(node_target_for_label exit)" \
    --final-exit-node-id "$(node_id_for_label exit)" \
    --client-host "$(node_target_for_label client)" \
    --client-node-id "$(node_id_for_label client)" \
    --entry-host "$(node_target_for_label entry)" \
    --entry-node-id "$(node_id_for_label entry)" \
    --second-client-host "$(node_target_for_label aux)" \
    --second-client-node-id "$(node_id_for_label aux)" \
    --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
    --report-path "$two_hop_pre_report" \
    --log-path "$two_hop_pre_log" || return 1
  assert_json_report_status_pass "$two_hop_pre_report" "extended soak pre-reboot two-hop" || return 1
  assert_no_managed_dns_service_errors "$two_hop_pre_log" "extended soak pre-reboot two-hop" || return 1
  assert_no_dns_zone_stale_status "$two_hop_pre_log" "extended soak pre-reboot two-hop" || return 1
  assert_client_dns_zone_valid_in_log "$two_hop_pre_log" "extended soak pre-reboot two-hop" || return 1

  run_periodic_managed_dns_refresh "soak_pre_exit_handoff" || return 1
  RUSTYNET_EXPECTED_GIT_COMMIT="$(current_run_git_commit)" \
  bash "$ROOT_DIR/scripts/e2e/live_linux_exit_handoff_test.sh" \
    --ssh-identity-file "$SSH_IDENTITY_FILE" \
    --known-hosts "$SSH_KNOWN_HOSTS_FILE" \
    --exit-a-host "$(node_target_for_label exit)" \
    --exit-a-node-id "$(node_id_for_label exit)" \
    --client-host "$(node_target_for_label client)" \
    --client-node-id "$(node_id_for_label client)" \
    --exit-b-host "$(node_target_for_label entry)" \
    --exit-b-node-id "$(node_id_for_label entry)" \
    --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
    --switch-iteration 60 \
    --monitor-iterations 180 \
    --report-path "$handoff_report" \
    --log-path "$handoff_log" \
    --monitor-log "$REPORT_DIR/live_linux_exit_handoff_soak_monitor.log" || return 1
  assert_json_report_status_pass "$handoff_report" "extended soak exit handoff" || return 1
  assert_no_managed_dns_service_errors "$handoff_log" "extended soak exit handoff" || return 1
  assert_no_dns_zone_stale_status "$handoff_log" "extended soak exit handoff" || return 1
  assert_client_dns_zone_valid_in_log "$handoff_log" "extended soak exit handoff" || return 1

  run_periodic_managed_dns_refresh "soak_pre_lan_toggle" || return 1
  RUSTYNET_EXPECTED_GIT_COMMIT="$(current_run_git_commit)" \
  bash "$ROOT_DIR/scripts/e2e/live_linux_lan_toggle_test.sh" \
    --ssh-identity-file "$SSH_IDENTITY_FILE" \
    --exit-host "$(node_target_for_label exit)" \
    --exit-node-id "$(node_id_for_label exit)" \
    --client-host "$(node_target_for_label client)" \
    --client-node-id "$(node_id_for_label client)" \
    --blind-exit-host "$(node_target_for_label aux)" \
    --blind-exit-node-id "$(node_id_for_label aux)" \
    --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
    --report-path "$lan_report" \
    --log-path "$lan_log" || return 1
  assert_json_report_status_pass "$lan_report" "extended soak lan toggle" || return 1
  assert_no_managed_dns_service_errors "$lan_log" "extended soak lan toggle" || return 1
  assert_no_dns_zone_stale_status "$lan_log" "extended soak lan toggle" || return 1
  assert_client_dns_zone_valid_in_log "$lan_log" "extended soak lan toggle" || return 1

  run_periodic_managed_dns_refresh "soak_pre_reboot_recovery" || return 1
  stage_run_reboot_recovery_report || return 1
  assert_json_report_status_pass "$reboot_report" "extended soak reboot recovery" || return 1
  assert_no_managed_dns_service_errors "$reboot_log" "extended soak reboot recovery" || return 1

  if [[ -f "$REPORT_DIR/live_linux_two_hop_soak_post_exit_reboot.log" ]]; then
    assert_no_managed_dns_service_errors "$REPORT_DIR/live_linux_two_hop_soak_post_exit_reboot.log" "extended soak post-exit-reboot two-hop" || return 1
    assert_no_dns_zone_stale_status "$REPORT_DIR/live_linux_two_hop_soak_post_exit_reboot.log" "extended soak post-exit-reboot two-hop" || return 1
    assert_client_dns_zone_valid_in_log "$REPORT_DIR/live_linux_two_hop_soak_post_exit_reboot.log" "extended soak post-exit-reboot two-hop" || return 1
  fi
  if [[ -f "$REPORT_DIR/live_linux_two_hop_soak_post_client_reboot.log" ]]; then
    assert_no_managed_dns_service_errors "$REPORT_DIR/live_linux_two_hop_soak_post_client_reboot.log" "extended soak post-client-reboot two-hop" || return 1
    assert_no_dns_zone_stale_status "$REPORT_DIR/live_linux_two_hop_soak_post_client_reboot.log" "extended soak post-client-reboot two-hop" || return 1
    assert_client_dns_zone_valid_in_log "$REPORT_DIR/live_linux_two_hop_soak_post_client_reboot.log" "extended soak post-client-reboot two-hop" || return 1
  fi
  if [[ -f "$REPORT_DIR/live_linux_two_hop_soak_salvage.log" ]]; then
    assert_no_managed_dns_service_errors "$REPORT_DIR/live_linux_two_hop_soak_salvage.log" "extended soak salvage two-hop" || return 1
    assert_no_dns_zone_stale_status "$REPORT_DIR/live_linux_two_hop_soak_salvage.log" "extended soak salvage two-hop" || return 1
    assert_client_dns_zone_valid_in_log "$REPORT_DIR/live_linux_two_hop_soak_salvage.log" "extended soak salvage two-hop" || return 1
  fi
}

stage_run_reboot_recovery_report() {
  local exit_target client_target entry_target aux_target extra_target
  local exit_pre exit_post client_pre client_post
  local exit_return="pass" exit_boot_change="pass" client_return="pass" client_boot_change="pass"
  local post_exit_dns_refresh="skipped" post_client_dns_refresh="skipped"
  local post_exit_twohop="skipped" post_client_twohop="skipped" salvage_twohop="skipped"
  local reboot_wait_attempts=96
  local reboot_wait_sleep_secs=5
  local observations_file="$STATE_DIR/reboot_observations.txt"
  local reboot_report="$REPORT_DIR/live_linux_reboot_recovery_report.json"
  local reboot_log="$REPORT_DIR/live_linux_reboot_recovery.log"
  : > "$observations_file"
  : > "$reboot_log"

  exec > >(tee -a "$reboot_log") 2>&1

  exit_target="$(node_target_for_label exit)"
  client_target="$(node_target_for_label client)"
  entry_target="$(node_target_for_label entry)"
  aux_target="$(node_target_for_label aux)"
  extra_target=""
  if has_label extra; then
    extra_target="$(node_target_for_label extra)"
  fi

  if ! exit_pre="$(capture_boot_id_with_retry "$exit_target")"; then
    exit_pre=""
    exit_return="fail"
    exit_boot_change="fail"
    printf 'exit_pre_capture=fail\n' | tee -a "$observations_file"
  fi
  if ! client_pre="$(capture_boot_id_with_retry "$client_target")"; then
    client_pre=""
    client_return="fail"
    client_boot_change="fail"
    printf 'client_pre_capture=fail\n' | tee -a "$observations_file"
  fi
  printf 'exit_pre=%s\nclient_pre=%s\n' "$exit_pre" "$client_pre" | tee -a "$observations_file"

  printf '[reboot] exit target %s\n' "$exit_target"
  run_host_reboot "$exit_target"
  if ssh_wait_for_host "$exit_target" "$reboot_wait_attempts" "$reboot_wait_sleep_secs"; then
    if exit_post="$(capture_boot_id_with_retry "$exit_target")"; then
      printf 'exit_post=%s\n' "$exit_post" | tee -a "$observations_file"
    else
      exit_post=""
      printf 'exit_post_capture=fail\nexit_post=\n' | tee -a "$observations_file"
    fi
    if [[ -z "$exit_pre" || "$exit_post" == "$exit_pre" || -z "$exit_post" ]]; then
      exit_boot_change="fail"
    fi
  else
    exit_return="fail"
    exit_boot_change="fail"
    printf 'exit_reboot_wait=fail\n' | tee -a "$observations_file"
  fi

  if [[ "$exit_return" == "pass" && "$exit_boot_change" == "pass" ]]; then
    if run_periodic_managed_dns_refresh "soak_post_exit_reboot_pre_two_hop"; then
      post_exit_dns_refresh="pass"
    if has_label extra; then
      if RUSTYNET_EXPECTED_GIT_COMMIT="$(current_run_git_commit)" \
        bash "$ROOT_DIR/scripts/e2e/live_linux_two_hop_test.sh" \
          --ssh-identity-file "$SSH_IDENTITY_FILE" \
          --known-hosts "$SSH_KNOWN_HOSTS_FILE" \
          --final-exit-host "$exit_target" \
          --final-exit-node-id "$(node_id_for_label exit)" \
          --client-host "$client_target" \
          --client-node-id "$(node_id_for_label client)" \
          --entry-host "$entry_target" \
          --entry-node-id "$(node_id_for_label entry)" \
          --second-client-host "$extra_target" \
          --second-client-node-id "$(node_id_for_label extra)" \
          --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
          --report-path "$REPORT_DIR/live_linux_two_hop_soak_post_exit_reboot_report.json" \
          --log-path "$REPORT_DIR/live_linux_two_hop_soak_post_exit_reboot.log"; then
        post_exit_twohop="pass"
      else
        post_exit_twohop="fail"
      fi
    else
      if RUSTYNET_EXPECTED_GIT_COMMIT="$(current_run_git_commit)" \
        bash "$ROOT_DIR/scripts/e2e/live_linux_two_hop_test.sh" \
          --ssh-identity-file "$SSH_IDENTITY_FILE" \
          --known-hosts "$SSH_KNOWN_HOSTS_FILE" \
          --final-exit-host "$exit_target" \
          --final-exit-node-id "$(node_id_for_label exit)" \
          --client-host "$client_target" \
          --client-node-id "$(node_id_for_label client)" \
          --entry-host "$entry_target" \
          --entry-node-id "$(node_id_for_label entry)" \
          --second-client-host "$aux_target" \
          --second-client-node-id "$(node_id_for_label aux)" \
          --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
          --report-path "$REPORT_DIR/live_linux_two_hop_soak_post_exit_reboot_report.json" \
          --log-path "$REPORT_DIR/live_linux_two_hop_soak_post_exit_reboot.log"; then
        post_exit_twohop="pass"
      else
        post_exit_twohop="fail"
      fi
    fi
    else
      post_exit_dns_refresh="fail"
      post_exit_twohop="fail"
      printf 'post_exit_dns_refresh=fail\n' | tee -a "$observations_file"
    fi
  else
    post_exit_twohop="fail"
  fi

  printf '[reboot] client target %s\n' "$client_target"
  run_host_reboot "$client_target"
  if ssh_wait_for_host "$client_target" "$reboot_wait_attempts" "$reboot_wait_sleep_secs"; then
    if client_post="$(capture_boot_id_with_retry "$client_target")"; then
      printf 'client_post=%s\n' "$client_post" | tee -a "$observations_file"
    else
      client_post=""
      printf 'client_post_capture=fail\nclient_post=\n' | tee -a "$observations_file"
    fi
    if [[ -z "$client_pre" || "$client_post" == "$client_pre" || -z "$client_post" ]]; then
      client_boot_change="fail"
    fi
  else
    client_return="fail"
    client_boot_change="fail"
    printf 'client_reboot_wait=fail\n' | tee -a "$observations_file"
    arp -an | rg "$(printf '%s' "$(live_lab_resolved_target_address "$client_target")" | sed 's/\./\\./g')" | tee -a "$observations_file" || true
    cargo run --quiet -p rustynet-cli -- ops scan-ipv4-port-range \
      --network-prefix 192.168.18 \
      --start-host 1 \
      --end-host 254 \
      --port 22 \
      --timeout-ms 80 \
      --output-key 'ssh_port22_hosts=' | tee -a "$observations_file"
  fi

  if [[ "$client_return" == "pass" && "$client_boot_change" == "pass" ]]; then
    if run_periodic_managed_dns_refresh "soak_post_client_reboot_pre_two_hop"; then
      post_client_dns_refresh="pass"
    if has_label extra; then
      if RUSTYNET_EXPECTED_GIT_COMMIT="$(current_run_git_commit)" \
        bash "$ROOT_DIR/scripts/e2e/live_linux_two_hop_test.sh" \
          --ssh-identity-file "$SSH_IDENTITY_FILE" \
          --known-hosts "$SSH_KNOWN_HOSTS_FILE" \
          --final-exit-host "$exit_target" \
          --final-exit-node-id "$(node_id_for_label exit)" \
          --client-host "$client_target" \
          --client-node-id "$(node_id_for_label client)" \
          --entry-host "$entry_target" \
          --entry-node-id "$(node_id_for_label entry)" \
          --second-client-host "$extra_target" \
          --second-client-node-id "$(node_id_for_label extra)" \
          --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
          --report-path "$REPORT_DIR/live_linux_two_hop_soak_post_client_reboot_report.json" \
          --log-path "$REPORT_DIR/live_linux_two_hop_soak_post_client_reboot.log"; then
        post_client_twohop="pass"
      else
        post_client_twohop="fail"
      fi
    else
      if RUSTYNET_EXPECTED_GIT_COMMIT="$(current_run_git_commit)" \
        bash "$ROOT_DIR/scripts/e2e/live_linux_two_hop_test.sh" \
          --ssh-identity-file "$SSH_IDENTITY_FILE" \
          --known-hosts "$SSH_KNOWN_HOSTS_FILE" \
          --final-exit-host "$exit_target" \
          --final-exit-node-id "$(node_id_for_label exit)" \
          --client-host "$client_target" \
          --client-node-id "$(node_id_for_label client)" \
          --entry-host "$entry_target" \
          --entry-node-id "$(node_id_for_label entry)" \
          --second-client-host "$aux_target" \
          --second-client-node-id "$(node_id_for_label aux)" \
          --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
          --report-path "$REPORT_DIR/live_linux_two_hop_soak_post_client_reboot_report.json" \
          --log-path "$REPORT_DIR/live_linux_two_hop_soak_post_client_reboot.log"; then
        post_client_twohop="pass"
      else
        post_client_twohop="fail"
      fi
    fi
    else
      post_client_dns_refresh="fail"
      post_client_twohop="fail"
      printf 'post_client_dns_refresh=fail\n' | tee -a "$observations_file"
    fi
  else
    post_client_twohop="fail"
  fi

  if [[ "$client_return" == "fail" && -n "$extra_target" ]]; then
    if RUSTYNET_EXPECTED_GIT_COMMIT="$(current_run_git_commit)" \
      bash "$ROOT_DIR/scripts/e2e/live_linux_two_hop_test.sh" \
        --ssh-identity-file "$SSH_IDENTITY_FILE" \
        --known-hosts "$SSH_KNOWN_HOSTS_FILE" \
        --final-exit-host "$exit_target" \
        --final-exit-node-id "$(node_id_for_label exit)" \
        --client-host "$aux_target" \
        --client-node-id "$(node_id_for_label aux)" \
        --entry-host "$entry_target" \
        --entry-node-id "$(node_id_for_label entry)" \
        --second-client-host "$extra_target" \
        --second-client-node-id "$(node_id_for_label extra)" \
        --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
        --report-path "$REPORT_DIR/live_linux_two_hop_soak_salvage_report.json" \
        --log-path "$REPORT_DIR/live_linux_two_hop_soak_salvage.log"; then
      salvage_twohop="pass"
    else
      salvage_twohop="fail"
    fi
  elif [[ -n "$extra_target" ]]; then
    salvage_twohop="skipped"
  fi

  cargo run --quiet -p rustynet-cli -- ops write-live-linux-reboot-recovery-report \
    --report-path "$reboot_report" \
    --observations-path "$observations_file" \
    --exit-pre "$exit_pre" \
    --exit-post "$exit_post" \
    --client-pre "$client_pre" \
    --client-post "$client_post" \
    --exit-return "$exit_return" \
    --exit-boot-change "$exit_boot_change" \
    --post-exit-dns-refresh "$post_exit_dns_refresh" \
    --post-exit-twohop "$post_exit_twohop" \
    --client-return "$client_return" \
    --client-boot-change "$client_boot_change" \
    --post-client-dns-refresh "$post_client_dns_refresh" \
    --post-client-twohop "$post_client_twohop" \
    --salvage-twohop "$salvage_twohop" >/dev/null
}

write_run_summary() {
  local finished_at_unix finished_at_local finished_at_utc elapsed_secs elapsed_human
  finished_at_unix="$(date +%s)"
  finished_at_local="$(date '+%Y-%m-%d %H:%M:%S %Z')"
  finished_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  elapsed_secs=$((finished_at_unix - RUN_STARTED_AT_UNIX))
  elapsed_human="$(format_elapsed_duration "$elapsed_secs")"
  cargo run --quiet -p rustynet-cli -- ops write-live-linux-lab-run-summary \
    --nodes-tsv "$NODES_TSV" \
    --stages-tsv "$STAGE_TSV" \
    --summary-json "$SUMMARY_JSON" \
    --summary-md "$SUMMARY_MD" \
    --run-id "$RUN_ID" \
    --network-id "$NETWORK_ID" \
    --report-dir "$REPORT_DIR" \
    --overall-status "$OVERALL_STATUS" \
    --started-at-local "$RUN_STARTED_AT_LOCAL" \
    --started-at-utc "$RUN_STARTED_AT_UTC" \
    --started-at-unix "$RUN_STARTED_AT_UNIX" \
    --finished-at-local "$finished_at_local" \
    --finished-at-utc "$finished_at_utc" \
    --finished-at-unix "$finished_at_unix" \
    --elapsed-secs "$elapsed_secs" \
    --elapsed-human "$elapsed_human" >/dev/null
}

refresh_failure_digest() {
  if [[ ! -f "$NODES_TSV" || ! -f "$STAGE_TSV" ]]; then
    return 0
  fi
  if ! cargo run --quiet -p rustynet-cli -- ops generate-live-linux-lab-failure-digest \
    --nodes-tsv "$NODES_TSV" \
    --stages-tsv "$STAGE_TSV" \
    --report-dir "$REPORT_DIR" \
    --run-id "$RUN_ID" \
    --network-id "$NETWORK_ID" \
    --overall-status "$OVERALL_STATUS" \
    --output-json "$FAILURE_DIGEST_JSON" \
    --output-md "$FAILURE_DIGEST_MD" >/dev/null; then
    printf 'warning: failed to refresh condensed failure digest at %s\n' "$FAILURE_DIGEST_MD" >&2
  fi
}

cleanup_local_password_files() {
  return 0
}

orchestrator_cleanup() {
  cleanup_local_password_files
  live_lab_cleanup
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --profile) PROFILE_PATH="$2"; shift 2 ;;
      --source-mode) SOURCE_MODE="$2"; SOURCE_MODE_EXPLICIT=1; shift 2 ;;
      --use-origin-main) SOURCE_MODE="origin-main"; SOURCE_MODE_EXPLICIT=1; shift ;;
      --use-local-head) SOURCE_MODE="local-head"; SOURCE_MODE_EXPLICIT=1; shift ;;
      --exit-target) EXIT_TARGET="$2"; shift 2 ;;
      --client-target) CLIENT_TARGET="$2"; shift 2 ;;
      --entry-target) ENTRY_TARGET="$2"; ENTRY_TARGET_DECLARED=1; shift 2 ;;
      --aux-target) AUX_TARGET="$2"; AUX_TARGET_DECLARED=1; shift 2 ;;
      --extra-target) EXTRA_TARGET="$2"; EXTRA_TARGET_DECLARED=1; shift 2 ;;
      --fifth-client-target) FIFTH_CLIENT_TARGET="$2"; FIFTH_CLIENT_TARGET_DECLARED=1; shift 2 ;;
      --ssh-identity-file) SSH_IDENTITY_FILE="$2"; shift 2 ;;
      --ssh-password-file)
        printf 'error: --ssh-password-file has been removed. Use --ssh-identity-file with SSH key-based auth.\n' >&2
        exit 2
        ;;
      --sudo-password-file)
        printf 'error: --sudo-password-file has been removed from this harness.\n' >&2
        exit 2
        ;;
      --ssh-known-hosts-file) SSH_KNOWN_HOSTS_FILE="$2"; shift 2 ;;
      --network-id) NETWORK_ID="$2"; shift 2 ;;
      --ssh-allow-cidrs) SSH_ALLOW_CIDRS="$2"; shift 2 ;;
      --traversal-ttl-secs) TRAVERSAL_TTL_SECS="$2"; shift 2 ;;
      --repo-ref)
        REPO_REF="$2"
        if [[ "$SOURCE_MODE_EXPLICIT" -eq 0 ]]; then
          SOURCE_MODE="ref"
          SOURCE_MODE_EXPLICIT=1
        fi
        shift 2
        ;;
      --report-dir) REPORT_DIR="$2"; LOG_DIR="$REPORT_DIR/logs"; VERIFICATION_DIR="$REPORT_DIR/verification"; STATE_DIR="$REPORT_DIR/state"; SUMMARY_JSON="$REPORT_DIR/run_summary.json"; SUMMARY_MD="$REPORT_DIR/run_summary.md"; FAILURE_DIGEST_JSON="$REPORT_DIR/failure_digest.json"; FAILURE_DIGEST_MD="$REPORT_DIR/failure_digest.md"; STAGE_TSV="$STATE_DIR/stages.tsv"; NODES_TSV="$STATE_DIR/nodes.tsv"; SOURCE_ARCHIVE="$STATE_DIR/rustynet-source.tar.gz"; PUBKEYS_TSV="$STATE_DIR/pubkeys.tsv"; ONEHOP_STATE_ENV="$STATE_DIR/onehop_state.env"; shift 2 ;;
      --setup-only) SETUP_ONLY=1; shift ;;
      --skip-setup) SKIP_SETUP=1; shift ;;
      --preserve-report-state) PRESERVE_REPORT_STATE=1; shift ;;
      --resume-from) RESUME_FROM_STAGE="$2"; shift 2 ;;
      --rerun-stage) RERUN_STAGE="$2"; shift 2 ;;
      --max-parallel-node-workers) MAX_PARALLEL_NODE_WORKERS="$2"; shift 2 ;;
      --skip-gates) RUN_LOCAL_GATES=0; shift ;;
      --skip-soak) RUN_SOAK=0; shift ;;
      --skip-cross-network) CROSS_NETWORK_MODE="skip"; shift ;;
      --force-cross-network) CROSS_NETWORK_MODE="force"; shift ;;
      --cross-network-nat-profiles) CROSS_NETWORK_NAT_PROFILES="$2"; shift 2 ;;
      --cross-network-required-nat-profiles) CROSS_NETWORK_REQUIRED_NAT_PROFILES="$2"; shift 2 ;;
      --cross-network-impairment-profile) CROSS_NETWORK_IMPAIRMENT_PROFILE="$2"; shift 2 ;;
      --cross-network-max-time-skew-secs) CROSS_NETWORK_MAX_TIME_SKEW_SECS="$2"; shift 2 ;;
      --cross-network-discovery-max-age-secs) CROSS_NETWORK_DISCOVERY_MAX_AGE_SECS="$2"; shift 2 ;;
      --cross-network-signed-artifact-max-age-secs) CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS="$2"; shift 2 ;;
      --cross-network-client-underlay-ip) CROSS_NETWORK_CLIENT_UNDERLAY_IP="$2"; shift 2 ;;
      --cross-network-exit-underlay-ip) CROSS_NETWORK_EXIT_UNDERLAY_IP="$2"; shift 2 ;;
      --cross-network-relay-underlay-ip) CROSS_NETWORK_RELAY_UNDERLAY_IP="$2"; shift 2 ;;
      --cross-network-probe-underlay-ip) CROSS_NETWORK_PROBE_UNDERLAY_IP="$2"; shift 2 ;;
      --reboot-hard-fail) SOAK_HARD_FAIL=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
  done
}

prompt_missing_inputs() {
  if [[ -z "$EXIT_TARGET" ]]; then
    EXIT_TARGET="$(prompt_value 'Primary exit node (user@host or host)')"
  fi
  if [[ -z "$CLIENT_TARGET" ]]; then
    CLIENT_TARGET="$(prompt_value 'Primary client node (user@host or host)')"
  fi
  if [[ -z "$ENTRY_TARGET" ]]; then
    if [[ "$ENTRY_TARGET_DECLARED" -eq 0 ]]; then
      ENTRY_TARGET="$(prompt_value 'Entry relay / alternate exit node (user@host or host, blank to skip advanced tests)')"
    fi
  fi
  if [[ -z "$AUX_TARGET" ]]; then
    if [[ "$AUX_TARGET_DECLARED" -eq 0 ]]; then
      AUX_TARGET="$(prompt_value 'Auxiliary client / blind-exit node (user@host or host, blank to skip advanced tests)')"
    fi
  fi
  if [[ -z "$EXTRA_TARGET" ]]; then
    if [[ "$EXTRA_TARGET_DECLARED" -eq 0 ]]; then
      EXTRA_TARGET="$(prompt_value 'Optional extra client node (user@host or host, blank if none)')"
    fi
  fi
  if [[ -z "$FIFTH_CLIENT_TARGET" ]]; then
    if [[ "$FIFTH_CLIENT_TARGET_DECLARED" -eq 0 ]]; then
      FIFTH_CLIENT_TARGET="$(prompt_value 'Optional fifth client node for six-node labs (user@host or host, blank if none)')"
    fi
  fi
}

maybe_prompt_for_default_profile() {
  if [[ -n "$PROFILE_PATH" ]]; then
    return 0
  fi
  if [[ -n "$EXIT_TARGET" || -n "$CLIENT_TARGET" || -n "$ENTRY_TARGET" || -n "$AUX_TARGET" || -n "$EXTRA_TARGET" || -n "$FIFTH_CLIENT_TARGET" ]]; then
    return 0
  fi
  if [[ ! -t 0 || ! -t 1 ]]; then
    return 0
  fi
  if [[ ! -f "$DEFAULT_PROFILE_PATH" ]]; then
    return 0
  fi
  if prompt_yes_no "Use saved VM lab profile (${DEFAULT_PROFILE_PATH})?" "y"; then
    PROFILE_PATH="$DEFAULT_PROFILE_PATH"
  fi
}

maybe_prompt_for_source_mode() {
  if [[ "$SOURCE_MODE_EXPLICIT" -eq 1 ]]; then
    return 0
  fi
  if [[ "$SOURCE_MODE" != "local-head" || "$REPO_REF" != "HEAD" ]]; then
    return 0
  fi
  if [[ ! -t 0 || ! -t 1 ]]; then
    return 0
  fi
  if prompt_yes_no "Update from latest git instead of local committed HEAD?" "n"; then
    prompt_for_git_branch_source
  else
    SOURCE_MODE="local-head"
    REPO_REF="HEAD"
  fi
}

normalize_targets() {
  EXIT_TARGET="$(normalize_target exit "$EXIT_TARGET")"
  CLIENT_TARGET="$(normalize_target client "$CLIENT_TARGET")"
  if [[ -n "$ENTRY_TARGET" ]]; then
    ENTRY_TARGET="$(normalize_target entry "$ENTRY_TARGET")"
  fi
  if [[ -n "$AUX_TARGET" ]]; then
    AUX_TARGET="$(normalize_target aux "$AUX_TARGET")"
  fi
  if [[ -n "$EXTRA_TARGET" ]]; then
    EXTRA_TARGET="$(normalize_target extra "$EXTRA_TARGET")"
  fi
  if [[ -n "$FIFTH_CLIENT_TARGET" ]]; then
    FIFTH_CLIENT_TARGET="$(normalize_target fifth_client "$FIFTH_CLIENT_TARGET")"
  fi
}

ensure_password_inputs() {
  local ssh_file
  ensure_password_file "$SSH_IDENTITY_FILE" 'SSH private key path' ssh_file
  SSH_IDENTITY_FILE="$ssh_file"
}

ensure_known_hosts_input() {
  local default_path="${HOME}/.ssh/known_hosts"
  if [[ -z "$SSH_KNOWN_HOSTS_FILE" && -f "$default_path" ]]; then
    SSH_KNOWN_HOSTS_FILE="$default_path"
  fi
  if [[ -z "$SSH_KNOWN_HOSTS_FILE" && -t 0 && -t 1 ]]; then
    SSH_KNOWN_HOSTS_FILE="$(prompt_value 'Pinned SSH known_hosts file' "$default_path")"
  fi
  if [[ -z "$SSH_KNOWN_HOSTS_FILE" ]]; then
    printf 'a pinned SSH known_hosts file is required\n' >&2
    exit 2
  fi
  if [[ ! -f "$SSH_KNOWN_HOSTS_FILE" ]]; then
    printf 'missing pinned SSH known_hosts file: %s\n' "$SSH_KNOWN_HOSTS_FILE" >&2
    exit 2
  fi
  if [[ -L "$SSH_KNOWN_HOSTS_FILE" ]]; then
    printf 'pinned SSH known_hosts file must not be a symlink: %s\n' "$SSH_KNOWN_HOSTS_FILE" >&2
    exit 2
  fi
  if ! cargo run --quiet -p rustynet-cli -- ops check-local-file-mode \
    --path "$SSH_KNOWN_HOSTS_FILE" \
    --policy no-group-world-write \
    --label 'pinned SSH known_hosts file' >/dev/null
  then
    exit 2
  fi
}

remember_temp_password_files() {
  return 0
}

main() {
  parse_args "$@"
  printf 'run started: %s (utc: %s)\n' "$RUN_STARTED_AT_LOCAL" "$RUN_STARTED_AT_UTC"
  if [[ "$SETUP_ONLY" -eq 1 && "$SKIP_SETUP" -eq 1 ]]; then
    printf '--setup-only and --skip-setup cannot be used together\n' >&2
    exit 2
  fi
  if [[ -n "$RESUME_FROM_STAGE" && -n "$RERUN_STAGE" ]]; then
    printf '--resume-from and --rerun-stage cannot be used together\n' >&2
    exit 2
  fi
  if [[ -n "$RESUME_FROM_STAGE" && "$SETUP_ONLY" -ne 1 ]]; then
    printf '--resume-from is only supported with --setup-only\n' >&2
    exit 2
  fi
  if [[ -n "$RERUN_STAGE" && "$SETUP_ONLY" -ne 1 ]]; then
    printf '--rerun-stage is only supported with --setup-only\n' >&2
    exit 2
  fi
  if [[ ! "$MAX_PARALLEL_NODE_WORKERS" =~ ^[0-9]+$ ]] || (( MAX_PARALLEL_NODE_WORKERS <= 0 )); then
    printf '--max-parallel-node-workers must be a positive integer (got: %s)\n' "$MAX_PARALLEL_NODE_WORKERS" >&2
    exit 2
  fi
  if [[ -n "$RESUME_FROM_STAGE" ]]; then
    is_setup_stage_name "$RESUME_FROM_STAGE" || {
      printf 'unsupported setup stage for --resume-from: %s\n' "$RESUME_FROM_STAGE" >&2
      exit 2
    }
    PRESERVE_REPORT_STATE=1
  fi
  if [[ -n "$RERUN_STAGE" ]]; then
    is_setup_stage_name "$RERUN_STAGE" || {
      printf 'unsupported setup stage for --rerun-stage: %s\n' "$RERUN_STAGE" >&2
      exit 2
    }
    PRESERVE_REPORT_STATE=1
  fi
  maybe_prompt_for_default_profile
  if [[ -n "$PROFILE_PATH" ]]; then
    load_profile_file "$PROFILE_PATH"
  fi
  maybe_prompt_for_source_mode
  mkdir -p "$LOG_DIR" "$VERIFICATION_DIR" "$STATE_DIR"
  if [[ "$PRESERVE_REPORT_STATE" -eq 0 ]]; then
    : > "$STAGE_TSV"
  elif [[ ! -f "$STAGE_TSV" ]]; then
    : > "$STAGE_TSV"
  fi
  if [[ -n "$RESUME_FROM_STAGE" ]]; then
    reset_setup_stage_state "$RESUME_FROM_STAGE" resume
  elif [[ -n "$RERUN_STAGE" ]]; then
    reset_setup_stage_state "$RERUN_STAGE" rerun
  fi
  prompt_missing_inputs
  normalize_targets
  export EXIT_TARGET CLIENT_TARGET ENTRY_TARGET AUX_TARGET EXTRA_TARGET FIFTH_CLIENT_TARGET
  export EXIT_UTM_NAME CLIENT_UTM_NAME ENTRY_UTM_NAME AUX_UTM_NAME EXTRA_UTM_NAME FIFTH_CLIENT_UTM_NAME
  auto_adjust_default_ssh_allow_cidrs_for_targets
  ensure_password_inputs
  ensure_known_hosts_input
  remember_temp_password_files
  export LIVE_LAB_PINNED_KNOWN_HOSTS_FILE="$SSH_KNOWN_HOSTS_FILE"
  build_nodes_file
  refresh_failure_digest
  validate_topology_inputs
  validate_source_mode
  validate_positive_integer "traversal TTL seconds" "$TRAVERSAL_TTL_SECS"
  validate_positive_integer "cross-network max time skew seconds" "$CROSS_NETWORK_MAX_TIME_SKEW_SECS"
  validate_positive_integer "cross-network discovery max age seconds" "$CROSS_NETWORK_DISCOVERY_MAX_AGE_SECS"
  validate_positive_integer "cross-network signed artifact max age seconds" "$CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS"
  if (( CROSS_NETWORK_MAX_TIME_SKEW_SECS > 30 )); then
    printf 'cross-network max time skew seconds must be <= 30 (got: %s)\n' "$CROSS_NETWORK_MAX_TIME_SKEW_SECS" >&2
    exit 2
  fi
  if (( CROSS_NETWORK_DISCOVERY_MAX_AGE_SECS > 86400 )); then
    printf 'cross-network discovery max age seconds must be <= 86400 (got: %s)\n' "$CROSS_NETWORK_DISCOVERY_MAX_AGE_SECS" >&2
    exit 2
  fi
  if (( CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS > 86400 )); then
    printf 'cross-network signed artifact max age seconds must be <= 86400 (got: %s)\n' "$CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS" >&2
    exit 2
  fi
  if [[ -n "$CROSS_NETWORK_CLIENT_UNDERLAY_IP" ]]; then
    cargo run --quiet -p rustynet-cli -- ops validate-ipv4-address --ip "$CROSS_NETWORK_CLIENT_UNDERLAY_IP" >/dev/null
  fi
  if [[ -n "$CROSS_NETWORK_EXIT_UNDERLAY_IP" ]]; then
    cargo run --quiet -p rustynet-cli -- ops validate-ipv4-address --ip "$CROSS_NETWORK_EXIT_UNDERLAY_IP" >/dev/null
  fi
  if [[ -n "$CROSS_NETWORK_RELAY_UNDERLAY_IP" ]]; then
    cargo run --quiet -p rustynet-cli -- ops validate-ipv4-address --ip "$CROSS_NETWORK_RELAY_UNDERLAY_IP" >/dev/null
  fi
  if [[ -n "$CROSS_NETWORK_PROBE_UNDERLAY_IP" ]]; then
    cargo run --quiet -p rustynet-cli -- ops validate-ipv4-address --ip "$CROSS_NETWORK_PROBE_UNDERLAY_IP" >/dev/null
  fi
  prepare_cross_network_profile_config
  if (( TRAVERSAL_TTL_SECS > 120 )); then
    printf 'traversal TTL seconds must be <= 120 (got: %s)\n' "$TRAVERSAL_TTL_SECS" >&2
    exit 2
  fi

  if [[ $(node_count) -lt 2 ]]; then
    printf 'at least exit and client targets are required\n' >&2
    exit 2
  fi

  live_lab_init "rustynet-live-lab" "$SSH_IDENTITY_FILE"
  register_cleanup_targets
  trap orchestrator_cleanup EXIT

  if [[ "$DRY_RUN" -eq 1 ]]; then
    record_stage_skip "preflight" "hard" "dry-run: not executed"
    record_stage_skip "prepare_source_archive" "hard" "dry-run: not executed"
    record_stage_skip "verify_ssh_reachability" "hard" "dry-run: not executed"
    record_stage_skip "prime_remote_access" "hard" "dry-run: not executed"
    record_stage_skip "cleanup_hosts" "hard" "dry-run: not executed"
    record_stage_skip "bootstrap_hosts" "hard" "dry-run: not executed"
    record_stage_skip "collect_pubkeys" "hard" "dry-run: not executed"
    record_stage_skip "membership_setup" "hard" "dry-run: not executed"
    record_stage_skip "distribute_membership_state" "hard" "dry-run: not executed"
    record_stage_skip "issue_and_distribute_assignments" "hard" "dry-run: not executed"
    record_stage_skip "issue_and_distribute_traversal" "hard" "dry-run: not executed"
    record_stage_skip "issue_and_distribute_dns_zone" "hard" "dry-run: not executed"
    record_stage_skip "enforce_baseline_runtime" "hard" "dry-run: not executed"
    record_stage_skip "validate_baseline_runtime" "hard" "dry-run: not executed"
    if has_five_node_release_gate_topology; then
      record_stage_skip "live_role_switch_matrix" "hard" "dry-run: not executed"
    else
      record_stage_skip "live_role_switch_matrix" "hard" "dry-run: skipped because the five-node release-gate topology is not configured"
    fi
    if has_label entry; then
      record_stage_skip "live_exit_handoff" "hard" "dry-run: not executed"
    fi
    if has_four_node_live_topology; then
      record_stage_skip "live_two_hop" "hard" "dry-run: not executed"
      record_stage_skip "live_lan_toggle" "hard" "dry-run: not executed"
    fi
    record_stage_skip "live_managed_dns" "hard" "dry-run: not executed"
    if has_five_node_release_gate_topology; then
      record_stage_skip "fresh_install_os_matrix_report" "hard" "dry-run: not executed"
    else
      record_stage_skip "fresh_install_os_matrix_report" "hard" "dry-run: skipped because the five-node release-gate topology is not configured"
    fi
    if [[ "$RUN_LOCAL_GATES" -eq 1 ]]; then
      if has_five_node_release_gate_topology; then
        record_stage_skip "local_full_gate_suite" "hard" "dry-run: not executed"
      else
        record_stage_skip "local_full_gate_suite" "hard" "dry-run: skipped because the five-node release-gate topology is not configured"
      fi
    fi
    if has_four_node_live_topology && [[ "$RUN_SOAK" -eq 1 ]]; then
      record_stage_skip "extended_soak" "hard" "dry-run: not executed"
    fi
    if cross_network_stages_applicable; then
      local nat_profile nat_idx stage_suffix
      record_stage_skip "cross_network_preflight" "hard" "dry-run: not executed"
      for nat_idx in "${!CROSS_NETWORK_NAT_PROFILE_LIST[@]}"; do
        nat_profile="${CROSS_NETWORK_NAT_PROFILE_LIST[$nat_idx]}"
        stage_suffix="$(cross_network_stage_suffix_for_profile_index "$nat_idx" "$nat_profile")"
        record_stage_skip "cross_network_direct_remote_exit${stage_suffix}" "hard" "dry-run: not executed"
        if cross_network_relay_label >/dev/null 2>&1; then
          record_stage_skip "cross_network_relay_remote_exit${stage_suffix}" "hard" "dry-run: not executed"
          record_stage_skip "cross_network_failback_roaming${stage_suffix}" "hard" "dry-run: not executed"
          record_stage_skip "cross_network_controller_switch${stage_suffix}" "hard" "dry-run: not executed"
        else
          record_stage_skip "cross_network_relay_remote_exit${stage_suffix}" "hard" "dry-run: skipped because entry or aux target is not configured"
          record_stage_skip "cross_network_failback_roaming${stage_suffix}" "hard" "dry-run: skipped because entry or aux target is not configured"
          record_stage_skip "cross_network_controller_switch${stage_suffix}" "hard" "dry-run: skipped because entry or aux target is not configured"
        fi
        record_stage_skip "cross_network_node_network_switch${stage_suffix}" "hard" "dry-run: not executed"
        if cross_network_probe_label >/dev/null 2>&1; then
          record_stage_skip "cross_network_traversal_adversarial${stage_suffix}" "hard" "dry-run: not executed"
        else
          record_stage_skip "cross_network_traversal_adversarial${stage_suffix}" "hard" "dry-run: skipped because entry or aux target is not configured"
        fi
        record_stage_skip "cross_network_remote_exit_dns${stage_suffix}" "hard" "dry-run: not executed"
        record_stage_skip "cross_network_remote_exit_soak${stage_suffix}" "hard" "dry-run: not executed"
      done
      record_stage_skip "cross_network_nat_matrix" "hard" "dry-run: not executed"
    else
      local nat_profile nat_idx stage_suffix
      record_stage_skip "cross_network_preflight" "hard" "dry-run: skipped because ${CROSS_NETWORK_SKIP_REASON}"
      for nat_idx in "${!CROSS_NETWORK_NAT_PROFILE_LIST[@]}"; do
        nat_profile="${CROSS_NETWORK_NAT_PROFILE_LIST[$nat_idx]}"
        stage_suffix="$(cross_network_stage_suffix_for_profile_index "$nat_idx" "$nat_profile")"
        record_stage_skip "cross_network_direct_remote_exit${stage_suffix}" "hard" "dry-run: skipped because ${CROSS_NETWORK_SKIP_REASON}"
        record_stage_skip "cross_network_relay_remote_exit${stage_suffix}" "hard" "dry-run: skipped because ${CROSS_NETWORK_SKIP_REASON}"
        record_stage_skip "cross_network_failback_roaming${stage_suffix}" "hard" "dry-run: skipped because ${CROSS_NETWORK_SKIP_REASON}"
        record_stage_skip "cross_network_controller_switch${stage_suffix}" "hard" "dry-run: skipped because ${CROSS_NETWORK_SKIP_REASON}"
        record_stage_skip "cross_network_node_network_switch${stage_suffix}" "hard" "dry-run: skipped because ${CROSS_NETWORK_SKIP_REASON}"
        record_stage_skip "cross_network_traversal_adversarial${stage_suffix}" "hard" "dry-run: skipped because ${CROSS_NETWORK_SKIP_REASON}"
        record_stage_skip "cross_network_remote_exit_dns${stage_suffix}" "hard" "dry-run: skipped because ${CROSS_NETWORK_SKIP_REASON}"
        record_stage_skip "cross_network_remote_exit_soak${stage_suffix}" "hard" "dry-run: skipped because ${CROSS_NETWORK_SKIP_REASON}"
      done
      record_stage_skip "cross_network_nat_matrix" "hard" "dry-run: skipped because ${CROSS_NETWORK_SKIP_REASON}"
    fi
    write_run_summary
    printf 'elapsed: %s\n' "$(format_elapsed_duration "$(( $(date +%s) - RUN_STARTED_AT_UNIX ))")"
    printf 'dry-run summary: %s\n' "$SUMMARY_MD"
    printf 'failure digest: %s\n' "$FAILURE_DIGEST_MD"
    return 0
  fi

  if [[ "$SKIP_SETUP" -eq 0 ]]; then
    if [[ -z "$RESUME_FROM_STAGE" && -z "$RERUN_STAGE" ]]; then
      run_stage hard preflight 'verify local prerequisites' stage_preflight
    else
      run_setup_stage hard preflight 'verify local prerequisites' stage_preflight || return 1
    fi
    stage_run_fresh_bootstrap_and_network_setup || return 1
  fi

  if [[ "$SETUP_ONLY" -eq 1 ]]; then
    write_run_summary
    printf 'elapsed: %s\n' "$(format_elapsed_duration "$(( $(date +%s) - RUN_STARTED_AT_UNIX ))")"
    printf 'setup summary: %s\n' "$SUMMARY_MD"
    printf 'failure digest: %s\n' "$FAILURE_DIGEST_MD"
    return 0
  fi

  if has_five_node_release_gate_topology; then
    run_stage hard live_role_switch_matrix 'run controlled role switch validation' stage_run_live_role_switch_matrix
  else
    record_stage_skip live_role_switch_matrix hard 'requires the full five-node topology (entry, aux, and extra targets)'
  fi

  if has_label entry; then
    run_stage hard live_exit_handoff 'run live exit handoff validation' stage_run_live_exit_handoff
  else
    record_stage_skip live_exit_handoff hard 'requires entry or aux target'
  fi

  if has_four_node_live_topology; then
    run_stage hard live_two_hop 'run live two-hop validation' stage_run_live_two_hop
    run_stage hard live_lan_toggle 'run LAN access toggle / blind-exit validation' stage_run_live_lan_toggle
  else
    record_stage_skip live_two_hop hard 'requires entry and aux targets'
    record_stage_skip live_lan_toggle hard 'requires aux target'
  fi
  run_stage hard live_managed_dns 'run live managed DNS validation' stage_run_live_managed_dns

  if has_five_node_release_gate_topology; then
    run_stage hard fresh_install_os_matrix_report 'generate commit-bound fresh install OS matrix report' stage_generate_fresh_install_os_matrix_report
  else
    record_stage_skip fresh_install_os_matrix_report hard 'requires the full five-node topology (entry, aux, and extra targets)'
  fi

  if [[ "$RUN_LOCAL_GATES" -eq 1 ]]; then
    if has_five_node_release_gate_topology; then
      run_stage hard local_full_gate_suite 'run local full security gate suite' stage_run_local_full_gate_suite
    else
      record_stage_skip local_full_gate_suite hard 'requires the full five-node topology for complete commit-bound release-gate evidence'
    fi
  else
    record_stage_skip local_full_gate_suite hard 'skipped by --skip-gates'
  fi

  if has_four_node_live_topology; then
    if [[ "$RUN_SOAK" -eq 1 ]]; then
      run_stage hard extended_soak 'run extended soak and reboot recovery validation' stage_run_extended_soak
    else
      record_stage_skip extended_soak hard 'skipped by --skip-soak'
    fi
  else
    record_stage_skip extended_soak hard 'requires entry and aux targets'
  fi

  local cross_network_stage_rc=0 stage_rc=0
  if cross_network_stages_applicable; then
    local nat_profile nat_idx stage_suffix profile_report profile_log
    set +e
    run_stage hard cross_network_preflight 'verify cross-network validator prerequisites (time skew, DNS health, cryptographic signed-state verification, daemon health, discovery bundle validation, required binaries/services)' stage_run_cross_network_preflight
    stage_rc=$?
    if [[ "$stage_rc" -ne 0 && "$cross_network_stage_rc" -eq 0 ]]; then
      cross_network_stage_rc="$stage_rc"
    fi
    if [[ "$cross_network_stage_rc" -eq 0 ]]; then
      for nat_idx in "${!CROSS_NETWORK_NAT_PROFILE_LIST[@]}"; do
        nat_profile="${CROSS_NETWORK_NAT_PROFILE_LIST[$nat_idx]}"
        stage_suffix="$(cross_network_stage_suffix_for_profile_index "$nat_idx" "$nat_profile")"

        profile_report="$(cross_network_report_path_for_profile "cross_network_direct_remote_exit_report.json" "$nat_idx" "$nat_profile")"
        profile_log="$(cross_network_log_path_for_profile "cross_network_direct_remote_exit.log" "$nat_idx" "$nat_profile")"
        run_stage hard "cross_network_direct_remote_exit${stage_suffix}" "run cross-network direct remote-exit validation (nat_profile=${nat_profile})" stage_run_cross_network_direct_remote_exit "$nat_profile" "$profile_report" "$profile_log"
        stage_rc=$?
        if [[ "$stage_rc" -ne 0 && "$cross_network_stage_rc" -eq 0 ]]; then
          cross_network_stage_rc="$stage_rc"
          break
        fi

        profile_report="$(cross_network_report_path_for_profile "cross_network_node_network_switch_report.json" "$nat_idx" "$nat_profile")"
        profile_log="$(cross_network_log_path_for_profile "cross_network_node_network_switch.log" "$nat_idx" "$nat_profile")"
        run_stage hard "cross_network_node_network_switch${stage_suffix}" "run cross-network node underlay-switch validation (nat_profile=${nat_profile})" stage_run_cross_network_node_network_switch "$nat_profile" "$profile_report" "$profile_log"
        stage_rc=$?
        if [[ "$stage_rc" -ne 0 && "$cross_network_stage_rc" -eq 0 ]]; then
          cross_network_stage_rc="$stage_rc"
          break
        fi

        if cross_network_relay_label >/dev/null 2>&1; then
          profile_report="$(cross_network_report_path_for_profile "cross_network_relay_remote_exit_report.json" "$nat_idx" "$nat_profile")"
          profile_log="$(cross_network_log_path_for_profile "cross_network_relay_remote_exit.log" "$nat_idx" "$nat_profile")"
          run_stage hard "cross_network_relay_remote_exit${stage_suffix}" "run cross-network relay remote-exit validation (nat_profile=${nat_profile})" stage_run_cross_network_relay_remote_exit "$nat_profile" "$profile_report" "$profile_log"
          stage_rc=$?
          if [[ "$stage_rc" -ne 0 && "$cross_network_stage_rc" -eq 0 ]]; then
            cross_network_stage_rc="$stage_rc"
            break
          fi
          profile_report="$(cross_network_report_path_for_profile "cross_network_failback_roaming_report.json" "$nat_idx" "$nat_profile")"
          profile_log="$(cross_network_log_path_for_profile "cross_network_failback_roaming.log" "$nat_idx" "$nat_profile")"
          run_stage hard "cross_network_failback_roaming${stage_suffix}" "run cross-network failback and endpoint-roaming validation (nat_profile=${nat_profile})" stage_run_cross_network_failback_roaming "$nat_profile" "$profile_report" "$profile_log"
          stage_rc=$?
          if [[ "$stage_rc" -ne 0 && "$cross_network_stage_rc" -eq 0 ]]; then
            cross_network_stage_rc="$stage_rc"
            break
          fi
          profile_report="$(cross_network_report_path_for_profile "cross_network_controller_switch_report.json" "$nat_idx" "$nat_profile")"
          profile_log="$(cross_network_log_path_for_profile "cross_network_controller_switch.log" "$nat_idx" "$nat_profile")"
          run_stage hard "cross_network_controller_switch${stage_suffix}" "run cross-network controller-switch validation (nat_profile=${nat_profile})" stage_run_cross_network_controller_switch "$nat_profile" "$profile_report" "$profile_log"
          stage_rc=$?
          if [[ "$stage_rc" -ne 0 && "$cross_network_stage_rc" -eq 0 ]]; then
            cross_network_stage_rc="$stage_rc"
            break
          fi
        else
          record_stage_skip "cross_network_relay_remote_exit${stage_suffix}" hard 'requires entry or aux target'
          record_stage_skip "cross_network_failback_roaming${stage_suffix}" hard 'requires entry or aux target'
          record_stage_skip "cross_network_controller_switch${stage_suffix}" hard 'requires entry or aux target'
        fi
        if cross_network_probe_label >/dev/null 2>&1; then
          profile_report="$(cross_network_report_path_for_profile "cross_network_traversal_adversarial_report.json" "$nat_idx" "$nat_profile")"
          profile_log="$(cross_network_log_path_for_profile "cross_network_traversal_adversarial.log" "$nat_idx" "$nat_profile")"
          run_stage hard "cross_network_traversal_adversarial${stage_suffix}" "run cross-network traversal adversarial validation (nat_profile=${nat_profile})" stage_run_cross_network_traversal_adversarial "$nat_profile" "$profile_report" "$profile_log"
          stage_rc=$?
          if [[ "$stage_rc" -ne 0 && "$cross_network_stage_rc" -eq 0 ]]; then
            cross_network_stage_rc="$stage_rc"
            break
          fi
        else
          record_stage_skip "cross_network_traversal_adversarial${stage_suffix}" hard 'requires entry or aux target'
        fi

        profile_report="$(cross_network_report_path_for_profile "cross_network_remote_exit_dns_report.json" "$nat_idx" "$nat_profile")"
        profile_log="$(cross_network_log_path_for_profile "cross_network_remote_exit_dns.log" "$nat_idx" "$nat_profile")"
        run_stage hard "cross_network_remote_exit_dns${stage_suffix}" "run cross-network remote-exit DNS validation (nat_profile=${nat_profile})" stage_run_cross_network_remote_exit_dns "$nat_profile" "$profile_report" "$profile_log"
        stage_rc=$?
        if [[ "$stage_rc" -ne 0 && "$cross_network_stage_rc" -eq 0 ]]; then
          cross_network_stage_rc="$stage_rc"
          break
        fi

        profile_report="$(cross_network_report_path_for_profile "cross_network_remote_exit_soak_report.json" "$nat_idx" "$nat_profile")"
        profile_log="$(cross_network_log_path_for_profile "cross_network_remote_exit_soak.log" "$nat_idx" "$nat_profile")"
        run_stage hard "cross_network_remote_exit_soak${stage_suffix}" "run cross-network remote-exit soak stability validation (nat_profile=${nat_profile})" stage_run_cross_network_remote_exit_soak "$nat_profile" "$profile_report" "$profile_log"
        stage_rc=$?
        if [[ "$stage_rc" -ne 0 && "$cross_network_stage_rc" -eq 0 ]]; then
          cross_network_stage_rc="$stage_rc"
          break
        fi
      done
    fi
    if [[ "$cross_network_stage_rc" -eq 0 ]]; then
      run_stage hard cross_network_nat_matrix "validate cross-network NAT matrix coverage (${CROSS_NETWORK_REQUIRED_NAT_PROFILES})" stage_run_cross_network_nat_matrix
      stage_rc=$?
      if [[ "$stage_rc" -ne 0 && "$cross_network_stage_rc" -eq 0 ]]; then
        cross_network_stage_rc="$stage_rc"
      fi
    fi
    set -e
  else
    local nat_profile nat_idx stage_suffix
    record_stage_skip cross_network_preflight hard "$CROSS_NETWORK_SKIP_REASON"
    for nat_idx in "${!CROSS_NETWORK_NAT_PROFILE_LIST[@]}"; do
      nat_profile="${CROSS_NETWORK_NAT_PROFILE_LIST[$nat_idx]}"
      stage_suffix="$(cross_network_stage_suffix_for_profile_index "$nat_idx" "$nat_profile")"
      record_stage_skip "cross_network_direct_remote_exit${stage_suffix}" hard "$CROSS_NETWORK_SKIP_REASON"
      record_stage_skip "cross_network_relay_remote_exit${stage_suffix}" hard "$CROSS_NETWORK_SKIP_REASON"
      record_stage_skip "cross_network_failback_roaming${stage_suffix}" hard "$CROSS_NETWORK_SKIP_REASON"
      record_stage_skip "cross_network_controller_switch${stage_suffix}" hard "$CROSS_NETWORK_SKIP_REASON"
      record_stage_skip "cross_network_node_network_switch${stage_suffix}" hard "$CROSS_NETWORK_SKIP_REASON"
      record_stage_skip "cross_network_traversal_adversarial${stage_suffix}" hard "$CROSS_NETWORK_SKIP_REASON"
      record_stage_skip "cross_network_remote_exit_dns${stage_suffix}" hard "$CROSS_NETWORK_SKIP_REASON"
      record_stage_skip "cross_network_remote_exit_soak${stage_suffix}" hard "$CROSS_NETWORK_SKIP_REASON"
    done
    record_stage_skip cross_network_nat_matrix hard "$CROSS_NETWORK_SKIP_REASON"
  fi

  if [[ "$cross_network_stage_rc" -ne 0 ]]; then
    write_run_summary
    return "$cross_network_stage_rc"
  fi

  write_run_summary
  printf 'elapsed: %s\n' "$(format_elapsed_duration "$(( $(date +%s) - RUN_STARTED_AT_UNIX ))")"
  printf 'run summary: %s\n' "$SUMMARY_MD"
  printf 'run summary json: %s\n' "$SUMMARY_JSON"
  printf 'failure digest: %s\n' "$FAILURE_DIGEST_MD"
  if [[ "$OVERALL_STATUS" == "fail" ]]; then
    return 1
  fi
  return 0
}

main "$@"
