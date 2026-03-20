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
REPO_REF="working-tree"
SOURCE_MODE="working-tree"
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
ENTRY_TARGET_DECLARED=0
AUX_TARGET_DECLARED=0
EXTRA_TARGET_DECLARED=0
PROFILE_PATH=""
DEFAULT_PROFILE_PATH="${ROOT_DIR}/profiles/live_lab/default_four_node.env"
SOURCE_MODE_EXPLICIT=0
TRAVERSAL_TTL_SECS=120
CROSS_NETWORK_NAT_PROFILES="${RUSTYNET_CROSS_NETWORK_NAT_PROFILES:-baseline_lan}"
CROSS_NETWORK_REQUIRED_NAT_PROFILES="${RUSTYNET_CROSS_NETWORK_REQUIRED_NAT_PROFILES:-}"
CROSS_NETWORK_IMPAIRMENT_PROFILE="${RUSTYNET_CROSS_NETWORK_IMPAIRMENT_PROFILE:-none}"
CROSS_NETWORK_MAX_TIME_SKEW_SECS="${RUSTYNET_CROSS_NETWORK_MAX_TIME_SKEW_SECS:-2}"
CROSS_NETWORK_DISCOVERY_MAX_AGE_SECS="${RUSTYNET_CROSS_NETWORK_DISCOVERY_MAX_AGE_SECS:-900}"
CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS="${RUSTYNET_CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS:-900}"
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
  - use local working tree, or
  - update from latest git and pick a branch from a numbered list

options:
  --profile <path>               Load saved lab profile (.env-style)
  --source-mode <mode>           Source mode: working-tree | local-head | origin-main
  --use-origin-main              Fetch and archive latest committed origin/main
  --use-local-head               Archive local committed HEAD instead of working tree
  --exit-target <user@ip|ip>     Primary exit node target
  --client-target <user@ip|ip>   Primary client node target
  --entry-target <user@ip|ip>    Entry relay / alternate exit target
  --aux-target <user@ip|ip>      Auxiliary client / blind-exit target
  --extra-target <user@ip|ip>    Optional extra client target
  --ssh-identity-file <path>     SSH private key for key-based authentication
  --ssh-password-file <path>     Deprecated alias of --ssh-identity-file
  --sudo-password-file <path>    Deprecated alias of --ssh-identity-file
  --ssh-known-hosts-file <path>  Pinned SSH known_hosts file (defaults to ~/.ssh/known_hosts)
  --network-id <id>              Override generated network ID
  --ssh-allow-cidrs <cidrs>      SSH management CIDRs (default: ${SSH_ALLOW_CIDRS})
  --repo-ref <ref>               Explicit git ref to archive (implies source-mode=ref)
  --report-dir <path>            Override report output directory
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
  --reboot-hard-fail             Treat reboot soak failures as hard failures
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
  for item in "${items[@]}"; do
    trimmed="$(trim_ascii "$item")"
    [[ -n "$trimmed" ]] || continue
    if ! is_valid_profile_label "$trimmed"; then
      printf 'invalid profile label: %s\n' "$trimmed" >&2
      return 1
    fi
    duplicate=0
    for existing in "${parsed[@]}"; do
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
      ENTRY_TARGET)
        ENTRY_TARGET_DECLARED=1
        [[ -z "$ENTRY_TARGET" ]] && ENTRY_TARGET="$value"
        ;;
      AUX_TARGET)
        AUX_TARGET_DECLARED=1
        [[ -z "$AUX_TARGET" ]] && AUX_TARGET="$value"
        ;;
      EXTRA_TARGET)
        EXTRA_TARGET_DECLARED=1
        [[ -z "$EXTRA_TARGET" ]] && EXTRA_TARGET="$value"
        ;;
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
      SOURCE_MODE)
        if [[ "$SOURCE_MODE" == "working-tree" && "$SOURCE_MODE_EXPLICIT" -eq 0 ]]; then
          SOURCE_MODE="$value"
        fi
        SOURCE_MODE_EXPLICIT=1
        ;;
      REPO_REF)
        if [[ "$REPO_REF" == "working-tree" ]]; then
          REPO_REF="$value"
        fi
        SOURCE_MODE="ref"
        SOURCE_MODE_EXPLICIT=1
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
    if [[ -z "$REPO_REF" || "$REPO_REF" == "working-tree" ]]; then
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

cross_network_network_id_for_label() {
  local label="$1"
  printf '%s-%s' "$NETWORK_ID" "$label"
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
    direct|dns|soak)
      printf '%s\n' client exit
      ;;
    relay|failback)
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
  client_addr="$(live_lab_target_address "$client_target")"
  exit_addr="$(live_lab_target_address "$exit_target")"
  set +e
  python3 - "$client_addr" "$exit_addr" <<'PY'
import ipaddress
import sys

try:
    client_ip = ipaddress.ip_address(sys.argv[1])
    exit_ip = ipaddress.ip_address(sys.argv[2])
except ValueError:
    raise SystemExit(2)

if client_ip.version != exit_ip.version:
    raise SystemExit(1)

prefix = 24 if client_ip.version == 4 else 64
client_net = ipaddress.ip_network(f"{client_ip}/{prefix}", strict=False)
exit_net = ipaddress.ip_network(f"{exit_ip}/{prefix}", strict=False)
raise SystemExit(0 if client_net == exit_net else 1)
PY
  same_prefix_rc=$?
  set -e
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
  if ! python3 - "$selected_path" <<'PY'
import os
import stat
import sys

path = sys.argv[1]
st = os.stat(path, follow_symlinks=False)
mode = stat.S_IMODE(st.st_mode)
if mode & 0o077:
    raise SystemExit(f"file must be owner-only (0400/0600): {path} ({mode:03o})")
PY
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
  python3 - <<'PY'
import re
import sys

line_redact_patterns = (
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY", re.IGNORECASE),
    re.compile(r"PRIVATE KEY-----", re.IGNORECASE),
)
value_redact_patterns = (
    re.compile(r"(?i)\b(passphrase|password|secret|token)\b(\s*[:=]\s*)(\S+)"),
)

for raw_line in sys.stdin:
    line = raw_line.rstrip("\n")
    if any(pattern.search(line) for pattern in line_redact_patterns):
        print("[REDACTED sensitive key material]")
        continue
    redacted = line
    for pattern in value_redact_patterns:
        redacted = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}<redacted>", redacted)
    print(redacted)
PY
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

collect_cross_network_failure_forensics() {
  local stage_name="$1"
  local collected_at stage_dir node_dir label target node_id role manifest_path
  collected_at="$(date -u +%Y%m%dT%H%M%SZ)"
  stage_dir="$REPORT_DIR/forensics/${stage_name}/${collected_at}"
  mkdir -p "$stage_dir"

  while IFS=$'\t' read -r label target node_id role; do
    [[ -n "$target" ]] || continue
    node_dir="$stage_dir/${label}"
    mkdir -p "$node_dir"

    capture_forensics_root "$target" "root date -u +%Y-%m-%dT%H:%M:%SZ || true; root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet status || true" "$node_dir/status.txt" || true
    capture_forensics_user "$target" "ip -4 route show table main || true; ip -4 route show table 51820 || true; ip -4 route get 1.1.1.1 || true" "$node_dir/routes.txt" || true
    capture_forensics_user "$target" "ip -br addr || true; ip -br link || true" "$node_dir/interfaces.txt" || true
    capture_forensics_root "$target" "root wg show rustynet0 endpoints || true" "$node_dir/wg_endpoints.txt" || true
    capture_forensics_root "$target" "root nft list ruleset || true" "$node_dir/nft_ruleset.txt" || true
    capture_forensics_root "$target" "root ss -tulpn || true" "$node_dir/ss_tulpn.txt" || true
    capture_forensics_root "$target" "root ls -l /run/rustynet || true; root test -S /run/rustynet/rustynetd.sock && echo daemon_socket_present || echo daemon_socket_missing" "$node_dir/daemon_socket.txt" || true
    capture_forensics_root "$target" "root systemctl status rustynetd.service rustynetd-privileged-helper.service --no-pager -l || true" "$node_dir/systemd_status.txt" || true
    capture_forensics_root "$target" "root journalctl -u rustynetd.service -u rustynetd-privileged-helper.service -n 250 --no-pager --output=short-iso || true" "$node_dir/journal_tail.txt" || true
    {
      printf 'label=%s\n' "$label"
      printf 'target=%s\n' "$target"
      printf 'node_id=%s\n' "$node_id"
      printf 'role=%s\n' "$role"
    } > "$node_dir/node_identity.txt"
  done < "$NODES_TSV"

  manifest_path="$stage_dir/manifest.json"
  python3 - "$stage_name" "$collected_at" "$stage_dir" "$manifest_path" <<'PY'
import json
import sys
from pathlib import Path

stage_name = sys.argv[1]
collected_at = sys.argv[2]
stage_dir = Path(sys.argv[3]).resolve()
manifest_path = Path(sys.argv[4]).resolve()

nodes = []
for node_dir in sorted(path for path in stage_dir.iterdir() if path.is_dir()):
    files = [str(path.resolve()) for path in sorted(node_dir.glob("*")) if path.is_file()]
    nodes.append(
        {
            "label": node_dir.name,
            "files": files,
        }
    )

payload = {
    "schema_version": 1,
    "mode": "cross_network_failure_forensics",
    "stage": stage_name,
    "collected_at_utc": collected_at,
    "bundle_dir": str(stage_dir),
    "nodes": nodes,
}
manifest_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY

  printf '%s' "$stage_dir"
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
  set +e
  (
    "$@"
  ) 2>&1 | tee -a "$log_path"
  rc=$?
  set -e
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

parallel_stage_scope_matches() {
  local scope="$1"
  local label="$2"
  case "$scope" in
    all) return 0 ;;
    non_exit)
      [[ "$label" != "exit" ]]
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
  local label target node_id role pid log_path rc

  case "$scope" in
    all|non_exit)
      ;;
    *)
      printf 'unsupported parallel scope: %s\n' "$scope" >&2
      return 1
      ;;
  esac

  stage_dir="$(parallel_stage_dir "$stage_name")"
  workers_tsv="${stage_dir}/workers.tsv"
  results_tsv="${stage_dir}/results.tsv"
  rm -rf "$stage_dir"
  mkdir -p "$stage_dir"
  : > "$workers_tsv"
  : > "$results_tsv"

  while IFS=$'\t' read -r label target node_id role; do
    if ! parallel_stage_scope_matches "$scope" "$label"; then
      continue
    fi
    log_path="${stage_dir}/${label}.log"
    (
      set -euo pipefail
      live_lab_prepare_worker_known_hosts "${stage_name}.${label}"
      "$worker_fn" "$label" "$target" "$node_id" "$role"
    ) >"$log_path" 2>&1 &
    pid=$!
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$label" "$target" "$node_id" "$role" "$pid" "$log_path" >> "$workers_tsv"
    worker_count=$((worker_count + 1))
  done < "$NODES_TSV"

  if [[ "$worker_count" -eq 0 ]]; then
    printf '[parallel:%s] no workers matched scope=%s\n' "$stage_name" "$scope"
    return 0
  fi

  while IFS=$'\t' read -r label target node_id role pid log_path; do
    if wait "$pid"; then
      rc=0
    else
      rc=$?
      failed=1
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$label" "$target" "$node_id" "$role" "$rc" "$log_path" >> "$results_tsv"
    printf '[parallel:%s] %s %s rc=%s\n' "$stage_name" "$label" "$target" "$rc"
    printf -- '----- %s/%s (%s %s) BEGIN -----\n' "$stage_name" "$label" "$node_id" "$role"
    cat "$log_path"
    printf -- '\n----- %s/%s END -----\n' "$stage_name" "$label"
  done < "$workers_tsv"

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
run_root pkill -f 'apt-get update' >/dev/null 2>&1 || true
run_root pkill -f '/usr/lib/apt/methods/' >/dev/null 2>&1 || true
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
rm -rf "${HOME}/Rustynet"
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
  if ! command -v llvm-config >/dev/null 2>&1 && ! command -v llvm-config-19 >/dev/null 2>&1; then
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

run_apt_update_hardened() {
  local attempt
  local apt_log
  local -a apt_network_opts
  apt_network_opts=(
    -o Acquire::Retries=3
    -o Acquire::http::Timeout=20
    -o Acquire::https::Timeout=20
  )
  if [[ -z "$(ip -6 route show default 2>/dev/null | head -n 1)" ]]; then
    apt_network_opts+=(-o Acquire::ForceIPv4=true)
  fi
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
    -o Acquire::http::Timeout=20
    -o Acquire::https::Timeout=20
  )
  if [[ -z "$(ip -6 route show default 2>/dev/null | head -n 1)" ]]; then
    apt_network_opts+=(-o Acquire::ForceIPv4=true)
  fi
  if [[ "$#" -eq 0 ]]; then
    echo "run_apt_install_hardened requires package names" >&2
    return 2
  fi
  for attempt in $(seq 1 3); do
    if run_root_timed 2400 env DEBIAN_FRONTEND=noninteractive apt-get \
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
    if run_local_timed 60 curl --fail --silent --show-error --head "${endpoint}" >/dev/null 2>&1; then
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
    if run_local_timed 1800 rustup toolchain install "${channel}" --profile minimal --component rustfmt --component clippy; then
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
run_root env RUSTYNET_INSTALL_SOURCE_ROOT="${HOME}/Rustynet" \
  rustynet ops e2e-bootstrap-host \
  --role "${ROLE}" \
  --node-id "${NODE_ID}" \
  --network-id "${NETWORK_ID}" \
  --src-dir "${HOME}/Rustynet" \
  --ssh-allow-cidrs "${SSH_ALLOW_CIDRS}" \
  --skip-apt
EOF_BOOTSTRAP
  chmod 700 "$STATE_DIR/rn_bootstrap.sh"

  cat > "$STATE_DIR/rn_issue_assignments.sh" <<'EOF_ASSIGN'
#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: rn_issue_assignments.sh <env-file>" >&2
  exit 2
fi

source "$1"

run_root() {
  sudo -n "$@"
}

PASS_FILE="$(mktemp /tmp/rn-assignment-passphrase.XXXXXX)"
cleanup() {
  if [[ -f "$PASS_FILE" ]]; then
    run_root rustynet ops secure-remove --path "$PASS_FILE" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

run_root rustynet ops materialize-signing-passphrase --output "$PASS_FILE"
run_root chmod 0600 "$PASS_FILE"

ISSUE_DIR="/run/rustynet/assignment-issue"
run_root rm -rf "$ISSUE_DIR"
run_root install -d -m 0700 "$ISSUE_DIR"

issue_bundle() {
  local target_node_id="$1"
  local exit_node_id="$2"
  local output_name="rn-assignment-${target_node_id}.assignment"
  local -a args
  args=(
    rustynet assignment issue
    --target-node-id "$target_node_id"
    --nodes "$NODES_SPEC"
    --allow "$ALLOW_SPEC"
    --signing-secret /etc/rustynet/assignment.signing.secret
    --signing-secret-passphrase-file "$PASS_FILE"
    --output "$ISSUE_DIR/$output_name"
    --verifier-key-output "$ISSUE_DIR/rn-assignment.pub"
    --ttl-secs 300
  )
  if [[ -n "$exit_node_id" && "$exit_node_id" != "-" ]]; then
    args+=(--exit-node-id "$exit_node_id")
  fi
  run_root "${args[@]}"
}

OLD_IFS="$IFS"
IFS=';'
set -- $ASSIGNMENTS_SPEC
IFS="$OLD_IFS"
for entry in "$@"; do
  [[ -n "$entry" ]] || continue
  target_node_id="${entry%%|*}"
  exit_node_id="${entry#*|}"
  issue_bundle "$target_node_id" "$exit_node_id"
done
EOF_ASSIGN
  chmod 700 "$STATE_DIR/rn_issue_assignments.sh"

  cat > "$STATE_DIR/rn_issue_traversal.sh" <<'EOF_TRAV'
#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: rn_issue_traversal.sh <env-file>" >&2
  exit 2
fi

source "$1"

run_root() {
  sudo -n "$@"
}

PASS_FILE="$(mktemp /tmp/rn-traversal-passphrase.XXXXXX)"
cleanup() {
  if [[ -f "$PASS_FILE" ]]; then
    run_root rustynet ops secure-remove --path "$PASS_FILE" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

run_root rustynet ops materialize-signing-passphrase --output "$PASS_FILE"
run_root chmod 0600 "$PASS_FILE"

ISSUE_DIR="/run/rustynet/traversal-issue"
run_root rm -rf "$ISSUE_DIR"
run_root install -d -m 0700 "$ISSUE_DIR"
SNAPSHOT_GENERATED_AT="$(date +%s)"
SNAPSHOT_NONCE="$((SNAPSHOT_GENERATED_AT * 1000 + 1))"

declare -a node_ids=()
declare -A endpoint_by_node=()
OLD_IFS="$IFS"
IFS=';'
set -- $NODES_SPEC
IFS="$OLD_IFS"
for entry in "$@"; do
  [[ -n "$entry" ]] || continue
  IFS='|' read -r node_id endpoint _rest <<< "$entry"
  [[ -n "$node_id" && -n "$endpoint" ]] || continue
  node_ids+=("$node_id")
  endpoint_by_node["$node_id"]="$endpoint"
done

if [[ "${#node_ids[@]}" -lt 2 ]]; then
  echo "traversal issue requires at least two nodes in NODES_SPEC" >&2
  exit 1
fi

issue_pair_bundle() {
  local source_node_id="$1"
  local target_node_id="$2"
  local target_endpoint="${endpoint_by_node[$target_node_id]}"
  local relay_id="relay-${target_node_id}"
  local output_name="rn-traversal-${source_node_id}-${target_node_id}.bundle"
  if [[ ! "$TRAVERSAL_TTL_SECS" =~ ^[0-9]+$ ]] || (( TRAVERSAL_TTL_SECS <= 0 || TRAVERSAL_TTL_SECS > 120 )); then
    echo "TRAVERSAL_TTL_SECS must be a positive integer <= 120 (got: ${TRAVERSAL_TTL_SECS})" >&2
    exit 2
  fi
  run_root rustynet traversal issue \
    --source-node-id "$source_node_id" \
    --target-node-id "$target_node_id" \
    --nodes "$NODES_SPEC" \
    --allow "$ALLOW_SPEC" \
    --signing-secret /etc/rustynet/assignment.signing.secret \
    --signing-secret-passphrase-file "$PASS_FILE" \
    --candidates "host|${target_endpoint}|900;relay|${target_endpoint}|700|${relay_id}" \
    --generated-at "$SNAPSHOT_GENERATED_AT" \
    --nonce "$SNAPSHOT_NONCE" \
    --output "$ISSUE_DIR/$output_name" \
    --verifier-key-output "$ISSUE_DIR/rn-traversal.pub" \
    --ttl-secs "$TRAVERSAL_TTL_SECS"
}

declare -a allow_sources=()
declare -a allow_targets=()
OLD_IFS="$IFS"
IFS=';'
set -- $ALLOW_SPEC
IFS="$OLD_IFS"
for entry in "$@"; do
  [[ -n "$entry" ]] || continue
  IFS='|' read -r source_node_id target_node_id <<< "$entry"
  [[ -n "$source_node_id" && -n "$target_node_id" ]] || continue
  if [[ -z "${endpoint_by_node[$target_node_id]:-}" ]]; then
    echo "target node ${target_node_id} from ALLOW_SPEC is missing in NODES_SPEC" >&2
    exit 1
  fi
  issue_pair_bundle "$source_node_id" "$target_node_id"
  allow_sources+=("$source_node_id")
  allow_targets+=("$target_node_id")
done

for node_id in "${node_ids[@]}"; do
  aggregate_path="$ISSUE_DIR/rn-traversal-${node_id}.traversal"
  run_root rm -f "$aggregate_path"
  run_root sh -c ': > "$1"' sh "$aggregate_path"
  for idx in "${!allow_sources[@]}"; do
    source_node_id="${allow_sources[$idx]}"
    target_node_id="${allow_targets[$idx]}"
    if [[ "$source_node_id" == "$node_id" ]]; then
      pair_path="$ISSUE_DIR/rn-traversal-${source_node_id}-${target_node_id}.bundle"
      run_root sh -c 'cat "$1" >> "$2"' sh "$pair_path" "$aggregate_path"
      run_root sh -c 'printf "\n" >> "$1"' sh "$aggregate_path"
    fi
  done
done
EOF_TRAV
  chmod 700 "$STATE_DIR/rn_issue_traversal.sh"
}

prime_remote_access() {
  run_parallel_node_stage prime_remote_access prime_remote_access_worker
}

prime_remote_access_worker() {
  local label="$1"
  local target="$2"
  printf '[prime-remote] %s %s\n' "$label" "$target"
  live_lab_push_sudo_password "$target"
}

stage_preflight() {
  require_cmd bash
  require_cmd git
  require_cmd tar
  require_cmd expect
  require_cmd python3
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
  write_remote_scripts
  printf 'source mode: %s\n' "$(describe_source_mode)"
  if [[ "$SOURCE_MODE" == "working-tree" ]]; then
    COPYFILE_DISABLE=1 tar -C "$ROOT_DIR" \
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

stage_cleanup_hosts() {
  run_parallel_node_stage cleanup_hosts cleanup_host_worker
}

cleanup_host_worker() {
  local label="$1"
  local target="$2"
  printf '[cleanup] %s %s\n' "$label" "$target"
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
  live_lab_push_sudo_password "$target"
  env_path="$STATE_DIR/bootstrap-${label}.env"
  cat > "$env_path" <<EOF_ENV
ROLE=${role}
NODE_ID=${node_id}
NETWORK_ID=${NETWORK_ID}
SSH_ALLOW_CIDRS=${SSH_ALLOW_CIDRS}
SOURCE_ARCHIVE=/tmp/rn_source.tar.gz
EOF_ENV
  printf '[bootstrap] %s %s (%s %s)\n' "$label" "$target" "$node_id" "$role"
  live_lab_scp_to "$STATE_DIR/rn_bootstrap.sh" "$target" "/tmp/rn_bootstrap.sh"
  live_lab_scp_to "$env_path" "$target" "/tmp/rn_bootstrap.env"
  live_lab_scp_to "$SOURCE_ARCHIVE" "$target" "/tmp/rn_source.tar.gz"
  live_lab_ssh "$target" "chmod 700 /tmp/rn_bootstrap.sh && bash /tmp/rn_bootstrap.sh /tmp/rn_bootstrap.env"
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
  pub_hex="$(live_lab_collect_pubkey_hex "$target")"
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
      nodes_spec="${node_id}|$(live_lab_target_address "$target"):51820|${pub_hex}"
      first="0"
    else
      nodes_spec="${nodes_spec};${node_id}|$(live_lab_target_address "$target"):51820|${pub_hex}"
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
  live_lab_run_root "$exit_target" "root test -f /var/lib/rustynet/membership.snapshot && root test -f /var/lib/rustynet/membership.log && root test -f /var/lib/rustynet/membership.watermark && root chown root:root /var/lib/rustynet/membership.snapshot /var/lib/rustynet/membership.log /var/lib/rustynet/membership.watermark && root chmod 0600 /var/lib/rustynet/membership.snapshot /var/lib/rustynet/membership.log /var/lib/rustynet/membership.watermark" || return 1
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
  live_lab_run_root "$target" "root install -m 0600 -o root -g root /tmp/rn-membership.snapshot /var/lib/rustynet/membership.snapshot && root install -m 0600 -o root -g root /tmp/rn-membership.log /var/lib/rustynet/membership.log && root rm -f /var/lib/rustynet/membership.watermark /tmp/rn-membership.snapshot /tmp/rn-membership.log"
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
  live_lab_scp_to "$STATE_DIR/rn_issue_assignments.sh" "$exit_target" "/tmp/rn_issue_assignments.sh" || return 1
  live_lab_scp_to "$env_path" "$exit_target" "/tmp/rn_issue_assignments.env" || return 1
  live_lab_run_root "$exit_target" "root chmod 700 /tmp/rn_issue_assignments.sh && root bash /tmp/rn_issue_assignments.sh /tmp/rn_issue_assignments.env && root rm -f /tmp/rn_issue_assignments.sh /tmp/rn_issue_assignments.env" || return 1

  verifier_local="$STATE_DIR/assignment.pub"
  live_lab_capture_root "$exit_target" "root cat /run/rustynet/assignment-issue/rn-assignment.pub" > "$verifier_local" || return 1
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
  live_lab_capture_root "$exit_target" "root cat /run/rustynet/assignment-issue/rn-assignment-${node_id}.assignment" > "$bundle_local"
  live_lab_install_assignment_bundle "$target" "$STATE_DIR/assignment.pub" "$bundle_local"
  if [[ "$node_id" == "$exit_node_id" ]]; then
    live_lab_write_assignment_refresh_env "$refresh_env" "$node_id" "$NODES_SPEC" "$ALLOW_SPEC"
  else
    live_lab_write_assignment_refresh_env "$refresh_env" "$node_id" "$NODES_SPEC" "$ALLOW_SPEC" "$exit_node_id"
  fi
  live_lab_install_assignment_refresh_env "$target" "$refresh_env"
}

stage_issue_and_distribute_traversal() {
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
  live_lab_scp_to "$STATE_DIR/rn_issue_traversal.sh" "$exit_target" "/tmp/rn_issue_traversal.sh" || return 1
  live_lab_scp_to "$env_path" "$exit_target" "/tmp/rn_issue_traversal.env" || return 1
  live_lab_run_root "$exit_target" "root chmod 700 /tmp/rn_issue_traversal.sh && root bash /tmp/rn_issue_traversal.sh /tmp/rn_issue_traversal.env && root rm -f /tmp/rn_issue_traversal.sh /tmp/rn_issue_traversal.env" || return 1

  verifier_local="$STATE_DIR/traversal.pub"
  live_lab_capture_root "$exit_target" "root cat /run/rustynet/traversal-issue/rn-traversal.pub" > "$verifier_local" || return 1
  run_parallel_node_stage issue_and_distribute_traversal distribute_traversal_worker
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
  live_lab_capture_root "$exit_target" "root cat /run/rustynet/traversal-issue/rn-traversal-${node_id}.traversal" > "$bundle_local"
  live_lab_scp_to "$STATE_DIR/traversal.pub" "$target" "/tmp/rn-traversal.pub"
  live_lab_scp_to "$bundle_local" "$target" "/tmp/rn-traversal.bundle"
  live_lab_run_root "$target" "root install -m 0644 -o root -g root /tmp/rn-traversal.pub /etc/rustynet/traversal.pub && root install -m 0640 -o root -g rustynetd /tmp/rn-traversal.bundle /var/lib/rustynet/rustynetd.traversal && root rm -f /var/lib/rustynet/rustynetd.traversal.watermark /tmp/rn-traversal.pub /tmp/rn-traversal.bundle"
}

stage_enforce_baseline_runtime() {
  run_parallel_node_stage enforce_baseline_runtime enforce_runtime_worker
  live_lab_retry_root "$(node_target_for_label exit)" "root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 0.0.0.0/0" 10 2 || return 1
  sleep 5
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

stage_validate_baseline_runtime() {
  local nft_rules
  run_parallel_node_stage validate_baseline_runtime validate_runtime_worker
  nft_rules="$(live_lab_capture_root "$(node_target_for_label exit)" "root nft list ruleset || true")" || return 1
  printf '[exit-nft]\n%s\n' "$nft_rules"
  grep -Eq 'masquerade|rustynet' <<<"$nft_rules" || return 1
}

validate_runtime_worker() {
  local _label="$1"
  local target="$2"
  local node_id="$3"
  local role="$4"
  local status route_check no_plaintext
  status="$(live_lab_status "$target")"
  printf '[status] %s %s\n%s\n' "$node_id" "$target" "$status"
  if [[ "$role" == "client" ]]; then
    route_check="$(live_lab_capture "$target" "ip -4 route get 1.1.1.1 || true")"
    printf '[route] %s %s\n%s\n' "$node_id" "$target" "$route_check"
    grep -Fq 'dev rustynet0' <<<"$route_check"
  fi
  no_plaintext="$(live_lab_no_plaintext_passphrase_check "$target")"
  printf '[plaintext-check] %s %s\n%s\n' "$node_id" "$target" "$no_plaintext"
  grep -Fq 'no-plaintext-passphrase-files' <<<"$no_plaintext"
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
  git -C "$ROOT_DIR" status --short --untracked-files=no -- \
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
    printf 'local full gate suite refuses source-tree drift: local checkout has tracked changes outside generated evidence paths, so local gate results would not be commit-bound\n' >&2
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

stage_run_live_managed_dns() {
  local canonical_report canonical_log
  canonical_report="$ROOT_DIR/artifacts/phase10/source/managed_dns_report.json"
  canonical_log="$ROOT_DIR/artifacts/phase10/source/managed_dns_report.log"
  RUSTYNET_EXPECTED_GIT_COMMIT="$(current_run_git_commit)" \
  bash "$ROOT_DIR/scripts/e2e/live_linux_managed_dns_test.sh" \
    --ssh-identity-file "$SSH_IDENTITY_FILE" \
    --signer-host "$(node_target_for_label exit)" \
    --signer-node-id "$(node_id_for_label exit)" \
    --client-host "$(node_target_for_label client)" \
    --client-node-id "$(node_id_for_label client)" \
    --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
    --report-path "$REPORT_DIR/live_linux_managed_dns_report.json" \
    --log-path "$REPORT_DIR/live_linux_managed_dns.log"
  mkdir -p "$(dirname "$canonical_report")"
  cp "$REPORT_DIR/live_linux_managed_dns_report.json" "$canonical_report"
  cp "$REPORT_DIR/live_linux_managed_dns.log" "$canonical_log"
}

stage_run_cross_network_direct_remote_exit() {
  local nat_profile="${1:-baseline_lan}"
  local report_path="${2:-$REPORT_DIR/cross_network_direct_remote_exit_report.json}"
  local log_path="${3:-$REPORT_DIR/cross_network_direct_remote_exit.log}"
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
  local relay_label
  if ! relay_label="$(cross_network_relay_label)"; then
    printf 'cross-network relay remote-exit validation requires entry or aux target\n' >&2
    return 1
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
  local relay_label
  if ! relay_label="$(cross_network_relay_label)"; then
    printf 'cross-network failback and roaming validation requires entry or aux target\n' >&2
    return 1
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
    --nat-profile "$nat_profile" \
    --impairment-profile "$CROSS_NETWORK_IMPAIRMENT_PROFILE" \
    --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
    --report-path "$report_path" \
    --log-path "$log_path"
  )
  run_cross_network_stage_with_impairment soak "${cmd[@]}"
}

cross_network_verify_signed_artifact_chain() {
  local target="$1"
  local node_id="$2"
  live_lab_capture_root "$target" "
set -euo pipefail
root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet assignment verify \
  --bundle /var/lib/rustynet/rustynetd.assignment \
  --verifier-key /etc/rustynet/assignment.pub \
  --watermark /var/lib/rustynet/rustynetd.assignment.watermark \
  --expected-node-id '${node_id}' \
  --max-age-secs '${CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS}' \
  --max-clock-skew-secs '${CROSS_NETWORK_MAX_TIME_SKEW_SECS}'
root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet traversal verify \
  --bundle /var/lib/rustynet/rustynetd.traversal \
  --verifier-key /etc/rustynet/traversal.pub \
  --watermark /var/lib/rustynet/rustynetd.traversal.watermark \
  --expected-source-node-id '${node_id}' \
  --max-age-secs '${CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS}' \
  --max-clock-skew-secs '${CROSS_NETWORK_MAX_TIME_SKEW_SECS}'
root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet trust verify \
  --evidence /var/lib/rustynet/rustynetd.trust \
  --verifier-key /etc/rustynet/trust-evidence.pub \
  --watermark /var/lib/rustynet/rustynetd.trust.watermark \
  --max-age-secs '${CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS}' \
  --max-clock-skew-secs '${CROSS_NETWORK_MAX_TIME_SKEW_SECS}'
root env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet dns zone verify \
  --bundle /var/lib/rustynet/rustynetd.dns-zone \
  --verifier-key /etc/rustynet/dns-zone.pub \
  --expected-zone-name rustynet \
  --expected-subject-node-id '${node_id}'
echo signed_artifact_chain_ok
"
}

cross_network_preflight_worker() {
  local label="$1"
  local target="$2"
  local node_id="$3"
  local _role="$4"
  local stage_dir capability_path
  local remote_unix local_unix skew
  local cmd
  local required_user_cmds=(rustynet rustynetd wg systemctl ss python3 ip nft journalctl)
  local required_root_cmds=(wg systemctl ss ip nft journalctl)
  local signed_state_snapshot route_snapshot endpoint_snapshot
  local global_ipv4 hostname_resolution_snapshot plaintext_snapshot
  local remote_src discovery_script_path discovery_remote_path discovery_local_path discovery_validation_path
  local discovery_hash

  stage_dir="$(parallel_stage_dir cross_network_preflight)"
  capability_path="${stage_dir}/capabilities-${label}.txt"
  : > "$capability_path"

  live_lab_push_sudo_password "$target"
  live_lab_wait_for_daemon_socket "$target"
  local_unix="${CROSS_NETWORK_PREFLIGHT_REFERENCE_UNIX:-0}"
  if [[ ! "$local_unix" =~ ^[0-9]+$ ]] || (( local_unix <= 0 )); then
    printf 'invalid preflight local unix reference for %s (%s): %s\n' "$label" "$target" "$local_unix" >&2
    return 1
  fi
  remote_unix="$(live_lab_capture "$target" "date -u +%s" | tr -d '[:space:]')"
  if [[ ! "$remote_unix" =~ ^[0-9]+$ ]]; then
    printf 'unable to read remote unix timestamp for %s (%s)\n' "$label" "$target" >&2
    return 1
  fi
  if (( local_unix >= remote_unix )); then
    skew=$((local_unix - remote_unix))
  else
    skew=$((remote_unix - local_unix))
  fi
  if (( skew > CROSS_NETWORK_MAX_TIME_SKEW_SECS )); then
    printf 'clock skew too large for %s (%s): skew=%ss max=%ss\n' "$label" "$target" "$skew" "$CROSS_NETWORK_MAX_TIME_SKEW_SECS" >&2
    return 1
  fi

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

  signed_state_snapshot="$(cross_network_verify_signed_artifact_chain "$target" "$node_id")"
  if [[ "$signed_state_snapshot" != *"signed_artifact_chain_ok"* ]]; then
    printf 'signed artifact chain verification failed on %s (%s)\n' "$label" "$target" >&2
    return 1
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
  python3 "$ROOT_DIR/scripts/ci/validate_network_discovery_bundle.py" \
    --bundle "$discovery_local_path" \
    --max-age-seconds "$CROSS_NETWORK_DISCOVERY_MAX_AGE_SECS" \
    --require-verifier-keys \
    --require-daemon-active \
    --require-socket-present \
    --output "$discovery_validation_path"
  discovery_hash="$(python3 - "$discovery_local_path" <<'PY'
import hashlib
import sys

path = sys.argv[1]
with open(path, "rb") as handle:
    print(hashlib.sha256(handle.read()).hexdigest())
PY
)"

  route_snapshot="$(live_lab_capture "$target" "ip -4 route get 1.1.1.1 || true" || true)"
  endpoint_snapshot="$(live_lab_capture_root "$target" "root wg show rustynet0 endpoints || true" || true)"

  printf 'label=%s\n' "$label" >> "$capability_path"
  printf 'target=%s\n' "$target" >> "$capability_path"
  printf 'node_id=%s\n' "$node_id" >> "$capability_path"
  printf 'local_unix=%s\n' "$local_unix" >> "$capability_path"
  printf 'remote_unix=%s\n' "$remote_unix" >> "$capability_path"
  printf 'clock_skew_secs=%s\n' "$skew" >> "$capability_path"
  printf 'max_clock_skew_secs=%s\n' "$CROSS_NETWORK_MAX_TIME_SKEW_SECS" >> "$capability_path"
  printf 'signed_artifact_max_age_secs=%s\n' "$CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS" >> "$capability_path"
  printf 'discovery_bundle_max_age_secs=%s\n' "$CROSS_NETWORK_DISCOVERY_MAX_AGE_SECS" >> "$capability_path"
  printf 'global_ipv4=%s\n' "$global_ipv4" >> "$capability_path"
  printf 'discovery_bundle_path=%s\n' "$discovery_local_path" >> "$capability_path"
  printf 'discovery_bundle_sha256=%s\n' "$discovery_hash" >> "$capability_path"
  printf 'discovery_validation_report=%s\n' "$discovery_validation_path" >> "$capability_path"
  printf 'hostname_resolution_snapshot=%s\n' "$(printf '%s' "$hostname_resolution_snapshot" | tr -s ' ' | tr '\n' ';')" >> "$capability_path"
  printf 'signed_state_snapshot=%s\n' "$(printf '%s' "$signed_state_snapshot" | tr -s ' ' | tr '\n' ';')" >> "$capability_path"
  printf 'plaintext_snapshot=%s\n' "$(printf '%s' "$plaintext_snapshot" | tr -s ' ' | tr '\n' ';')" >> "$capability_path"
  printf 'route_snapshot=%s\n' "$(printf '%s' "$route_snapshot" | tr -s ' ' | tr '\n' ';')" >> "$capability_path"
  printf 'endpoint_snapshot=%s\n' "$(printf '%s' "$endpoint_snapshot" | tr -s ' ' | tr '\n' ';')" >> "$capability_path"
}

stage_run_cross_network_preflight() {
  local stage_dir report_path
  CROSS_NETWORK_PREFLIGHT_REFERENCE_UNIX="$(date +%s)"
  export CROSS_NETWORK_PREFLIGHT_REFERENCE_UNIX
  run_parallel_node_stage cross_network_preflight cross_network_preflight_worker

  stage_dir="$(parallel_stage_dir cross_network_preflight)"
  report_path="$REPORT_DIR/cross_network_preflight_report.json"
  python3 - "$NODES_TSV" "$stage_dir" "$report_path" "$CROSS_NETWORK_PREFLIGHT_REFERENCE_UNIX" "$CROSS_NETWORK_MAX_TIME_SKEW_SECS" "$CROSS_NETWORK_DISCOVERY_MAX_AGE_SECS" "$CROSS_NETWORK_SIGNED_ARTIFACT_MAX_AGE_SECS" <<'PY'
import json
import sys
from pathlib import Path

nodes_tsv = Path(sys.argv[1])
stage_dir = Path(sys.argv[2])
report_path = Path(sys.argv[3])
reference_unix = int(sys.argv[4])
max_skew = int(sys.argv[5])
discovery_max_age = int(sys.argv[6])
signed_artifact_max_age = int(sys.argv[7])

nodes = []
for line in nodes_tsv.read_text(encoding="utf-8").splitlines():
    parts = line.split("\t")
    if len(parts) != 4:
        continue
    label, target, node_id, role = parts
    capability_file = stage_dir / f"capabilities-{label}.txt"
    nodes.append(
        {
            "label": label,
            "target": target,
            "node_id": node_id,
            "role": role,
            "capability_file": str(capability_file.resolve()),
            "capability_file_exists": capability_file.exists(),
        }
    )

payload = {
    "schema_version": 1,
    "mode": "cross_network_preflight",
    "reference_unix": reference_unix,
    "max_clock_skew_secs": max_skew,
    "discovery_max_age_secs": discovery_max_age,
    "signed_artifact_max_age_secs": signed_artifact_max_age,
    "nodes": nodes,
}
report_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
}

stage_run_cross_network_nat_matrix() {
  local output_path="$REPORT_DIR/cross_network_remote_exit_nat_matrix_validation.md"
  python3 "$ROOT_DIR/scripts/ci/validate_cross_network_nat_matrix.py" \
    --artifact-dir "$REPORT_DIR" \
    --required-nat-profiles "$CROSS_NETWORK_REQUIRED_NAT_PROFILES" \
    --expected-git-commit "$(current_run_git_commit)" \
    --require-pass-status \
    --output "$output_path"
}

stage_generate_fresh_install_os_matrix_report() {
  local commit_short role_report canonical_report canonical_source_dir manifest_json
  local canonical_bootstrap_log canonical_baseline_log canonical_two_hop_report
  local canonical_role_switch_report canonical_lan_toggle_report canonical_exit_handoff_report
  if ! has_five_node_release_gate_topology; then
    printf 'fresh install OS matrix report generation requires the full five-node topology (entry, aux, and extra targets)\n' >&2
    return 1
  fi
  commit_short="$(current_run_git_commit_short)"
  role_report="$REPORT_DIR/role_switch_matrix_report_${commit_short}.json"
  canonical_report="$ROOT_DIR/artifacts/phase10/fresh_install_os_matrix_report.json"
  canonical_source_dir="$ROOT_DIR/artifacts/phase10/source/fresh_install_os_matrix"
  manifest_json="$STATE_DIR/fresh_install_os_matrix_inputs.json"
  python3 "$ROOT_DIR/scripts/e2e/rebind_linux_fresh_install_os_matrix_inputs.py" \
    --dest-dir "$canonical_source_dir" \
    --bootstrap-log "$LOG_DIR/bootstrap_hosts.log" \
    --baseline-log "$LOG_DIR/validate_baseline_runtime.log" \
    --two-hop-report "$REPORT_DIR/live_linux_two_hop_report.json" \
    --role-switch-report "$role_report" \
    --lan-toggle-report "$REPORT_DIR/live_linux_lan_toggle_report.json" \
    --exit-handoff-report "$REPORT_DIR/live_linux_exit_handoff_report.json" > "$manifest_json"
  canonical_bootstrap_log="$(python3 - "$manifest_json" <<'PY'
import json
import sys
print(json.loads(open(sys.argv[1], encoding="utf-8").read())["bootstrap_log"])
PY
)"
  canonical_baseline_log="$(python3 - "$manifest_json" <<'PY'
import json
import sys
print(json.loads(open(sys.argv[1], encoding="utf-8").read())["baseline_log"])
PY
)"
  canonical_two_hop_report="$(python3 - "$manifest_json" <<'PY'
import json
import sys
print(json.loads(open(sys.argv[1], encoding="utf-8").read())["two_hop_report"])
PY
)"
  canonical_role_switch_report="$(python3 - "$manifest_json" <<'PY'
import json
import sys
print(json.loads(open(sys.argv[1], encoding="utf-8").read())["role_switch_report"])
PY
)"
  canonical_lan_toggle_report="$(python3 - "$manifest_json" <<'PY'
import json
import sys
print(json.loads(open(sys.argv[1], encoding="utf-8").read())["lan_toggle_report"])
PY
)"
  canonical_exit_handoff_report="$(python3 - "$manifest_json" <<'PY'
import json
import sys
print(json.loads(open(sys.argv[1], encoding="utf-8").read())["exit_handoff_report"])
PY
)"
  python3 "$ROOT_DIR/scripts/e2e/generate_linux_fresh_install_os_matrix_report.py" \
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
  local attempts="${2:-36}"
  local sleep_secs="${3:-5}"
  local attempt
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    if live_lab_ssh "$target" "true" 15 >/dev/null 2>&1; then
      return 0
    fi
    sleep "$sleep_secs"
  done
  return 1
}

capture_boot_id() {
  local target="$1"
  live_lab_capture "$target" "cat /proc/sys/kernel/random/boot_id" | tr -d '[:space:]'
}

run_host_reboot() {
  local target="$1"
  live_lab_push_sudo_password "$target"
  live_lab_ssh "$target" "sudo -n systemctl reboot" 20 >/dev/null 2>&1 || true
}

stage_run_extended_soak() {
  local handoff_rc=0 two_hop_rc=0 lan_rc=0 reboot_rc=0 severity_name="soft"
  if [[ "$SOAK_HARD_FAIL" -eq 1 ]]; then
    severity_name="hard"
  fi
  RUSTYNET_EXPECTED_GIT_COMMIT="$(current_run_git_commit)" \
  bash "$ROOT_DIR/scripts/e2e/live_linux_two_hop_test.sh" \
    --ssh-identity-file "$SSH_IDENTITY_FILE" \
    --final-exit-host "$(node_target_for_label exit)" \
    --final-exit-node-id "$(node_id_for_label exit)" \
    --client-host "$(node_target_for_label client)" \
    --client-node-id "$(node_id_for_label client)" \
    --entry-host "$(node_target_for_label entry)" \
    --entry-node-id "$(node_id_for_label entry)" \
    --second-client-host "$(node_target_for_label aux)" \
    --second-client-node-id "$(node_id_for_label aux)" \
    --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
    --report-path "$REPORT_DIR/live_linux_two_hop_soak_pre_reboot_report.json" \
    --log-path "$REPORT_DIR/live_linux_two_hop_soak_pre_reboot.log"

  RUSTYNET_EXPECTED_GIT_COMMIT="$(current_run_git_commit)" \
  bash "$ROOT_DIR/scripts/e2e/live_linux_exit_handoff_test.sh" \
    --ssh-identity-file "$SSH_IDENTITY_FILE" \
    --exit-a-host "$(node_target_for_label exit)" \
    --exit-a-node-id "$(node_id_for_label exit)" \
    --client-host "$(node_target_for_label client)" \
    --client-node-id "$(node_id_for_label client)" \
    --exit-b-host "$(node_target_for_label entry)" \
    --exit-b-node-id "$(node_id_for_label entry)" \
    --ssh-allow-cidrs "$SSH_ALLOW_CIDRS" \
    --switch-iteration 60 \
    --monitor-iterations 180 \
    --report-path "$REPORT_DIR/live_linux_exit_handoff_soak_report.json" \
    --log-path "$REPORT_DIR/live_linux_exit_handoff_soak.log" \
    --monitor-log "$REPORT_DIR/live_linux_exit_handoff_soak_monitor.log"

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
    --report-path "$REPORT_DIR/live_linux_lan_toggle_soak_report.json" \
    --log-path "$REPORT_DIR/live_linux_lan_toggle_soak.log"

  stage_run_reboot_recovery_report
}

stage_run_reboot_recovery_report() {
  local exit_target client_target entry_target aux_target extra_target
  local exit_pre exit_post client_pre client_post
  local exit_return="pass" exit_boot_change="pass" client_return="pass" client_boot_change="pass"
  local post_exit_twohop="skipped" post_client_twohop="skipped" salvage_twohop="skipped"
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

  exit_pre="$(capture_boot_id "$exit_target")"
  client_pre="$(capture_boot_id "$client_target")"
  printf 'exit_pre=%s\nclient_pre=%s\n' "$exit_pre" "$client_pre" | tee -a "$observations_file"

  printf '[reboot] exit target %s\n' "$exit_target"
  run_host_reboot "$exit_target"
  if ssh_wait_for_host "$exit_target" 48 5; then
    exit_post="$(capture_boot_id "$exit_target")"
    printf 'exit_post=%s\n' "$exit_post" | tee -a "$observations_file"
    if [[ "$exit_post" == "$exit_pre" || -z "$exit_post" ]]; then
      exit_boot_change="fail"
    fi
  else
    exit_return="fail"
    exit_boot_change="fail"
    printf 'exit_reboot_wait=fail\n' | tee -a "$observations_file"
  fi

  if [[ "$exit_return" == "pass" && "$exit_boot_change" == "pass" ]]; then
    if has_label extra; then
      RUSTYNET_EXPECTED_GIT_COMMIT="$(current_run_git_commit)" \
      bash "$ROOT_DIR/scripts/e2e/live_linux_two_hop_test.sh" \
        --ssh-identity-file "$SSH_IDENTITY_FILE" \
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
        --log-path "$REPORT_DIR/live_linux_two_hop_soak_post_exit_reboot.log"
    else
      RUSTYNET_EXPECTED_GIT_COMMIT="$(current_run_git_commit)" \
      bash "$ROOT_DIR/scripts/e2e/live_linux_two_hop_test.sh" \
        --ssh-identity-file "$SSH_IDENTITY_FILE" \
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
        --log-path "$REPORT_DIR/live_linux_two_hop_soak_post_exit_reboot.log"
    fi
    post_exit_twohop="pass"
  else
    post_exit_twohop="fail"
  fi

  printf '[reboot] client target %s\n' "$client_target"
  run_host_reboot "$client_target"
  if ssh_wait_for_host "$client_target" 48 5; then
    client_post="$(capture_boot_id "$client_target")"
    printf 'client_post=%s\n' "$client_post" | tee -a "$observations_file"
    if [[ "$client_post" == "$client_pre" || -z "$client_post" ]]; then
      client_boot_change="fail"
    fi
  else
    client_return="fail"
    client_boot_change="fail"
    printf 'client_reboot_wait=fail\n' | tee -a "$observations_file"
    arp -an | rg "$(printf '%s' "$(live_lab_target_address "$client_target")" | sed 's/\./\\./g')" | tee -a "$observations_file" || true
    python3 - <<'PY' | tee -a "$observations_file"
import socket
hits = []
for i in range(1, 255):
    host = f'192.168.18.{i}'
    s = socket.socket()
    s.settimeout(0.08)
    rc = s.connect_ex((host, 22))
    s.close()
    if rc == 0:
        hits.append(host)
print('ssh_port22_hosts=' + ','.join(hits))
PY
  fi

  if [[ "$client_return" == "pass" && "$client_boot_change" == "pass" ]]; then
    if has_label extra; then
      RUSTYNET_EXPECTED_GIT_COMMIT="$(current_run_git_commit)" \
      bash "$ROOT_DIR/scripts/e2e/live_linux_two_hop_test.sh" \
        --ssh-identity-file "$SSH_IDENTITY_FILE" \
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
        --log-path "$REPORT_DIR/live_linux_two_hop_soak_post_client_reboot.log"
    else
      RUSTYNET_EXPECTED_GIT_COMMIT="$(current_run_git_commit)" \
      bash "$ROOT_DIR/scripts/e2e/live_linux_two_hop_test.sh" \
        --ssh-identity-file "$SSH_IDENTITY_FILE" \
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
        --log-path "$REPORT_DIR/live_linux_two_hop_soak_post_client_reboot.log"
    fi
    post_client_twohop="pass"
  else
    post_client_twohop="fail"
  fi

  if [[ "$client_return" == "fail" && -n "$extra_target" ]]; then
    RUSTYNET_EXPECTED_GIT_COMMIT="$(current_run_git_commit)" \
    bash "$ROOT_DIR/scripts/e2e/live_linux_two_hop_test.sh" \
      --ssh-identity-file "$SSH_IDENTITY_FILE" \
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
      --log-path "$REPORT_DIR/live_linux_two_hop_soak_salvage.log"
    salvage_twohop="pass"
  elif [[ -n "$extra_target" ]]; then
    salvage_twohop="skipped"
  fi

  python3 - "$reboot_report" "$observations_file" "$exit_pre" "$exit_post" "$client_pre" "$client_post" "$exit_return" "$exit_boot_change" "$post_exit_twohop" "$client_return" "$client_boot_change" "$post_client_twohop" "$salvage_twohop" <<'PY'
import json
import sys
from pathlib import Path

(report_path, observations_path, exit_pre, exit_post, client_pre, client_post, exit_return, exit_boot_change, post_exit_twohop,
 client_return, client_boot_change, post_client_twohop, salvage_twohop) = sys.argv[1:]
observations = Path(observations_path).read_text(encoding='utf-8', errors='ignore')
checks = {
    'exit_reboot_returns': exit_return,
    'exit_boot_id_changes': exit_boot_change,
    'post_exit_reboot_twohop': post_exit_twohop,
    'client_reboot_returns': client_return,
    'client_boot_id_changes': client_boot_change,
    'post_client_reboot_twohop': post_client_twohop,
    'client_failure_salvage_twohop': salvage_twohop,
}
relevant = [value for value in checks.values() if value != 'skipped']
status = 'pass' if relevant and all(value == 'pass' for value in relevant) else 'fail'
failure_reason_map = {
    'exit_reboot_returns': 'exit did not return on SSH after reboot',
    'exit_boot_id_changes': 'exit reboot was not proven by a new boot_id',
    'post_exit_reboot_twohop': 'two-hop validation failed after exit reboot',
    'client_reboot_returns': 'client did not return on SSH after reboot',
    'client_boot_id_changes': 'client reboot was not proven by a new boot_id',
    'post_client_reboot_twohop': 'two-hop validation failed after client reboot',
    'client_failure_salvage_twohop': 'salvage two-hop validation failed after the client reboot outage',
}
failure_reasons = [
    failure_reason_map[name]
    for name, value in checks.items()
    if value == 'fail'
]
for observation_line in observations.splitlines():
    observation_line = observation_line.strip()
    if not observation_line:
        continue
    if observation_line == 'client_reboot_wait=fail':
        failure_reasons.append('client reboot wait timed out')
    elif observation_line == 'exit_reboot_wait=fail':
        failure_reasons.append('exit reboot wait timed out')
    elif observation_line == 'exit_post=':
        failure_reasons.append('exit post-reboot boot_id capture was empty')
    elif observation_line == 'client_post=':
        failure_reasons.append('client post-reboot boot_id capture was empty')
report = {
    'schema_version': 1,
    'mode': 'live_linux_reboot_recovery',
    'status': status,
    'checks': checks,
    'boot_ids': {
        'exit_pre': exit_pre,
        'exit_post': exit_post,
        'client_pre': client_pre,
        'client_post': client_post,
    },
    'failure_reasons': failure_reasons,
    'observations': observations.strip(),
}
Path(report_path).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
if status != 'pass':
    raise SystemExit(1)
PY
}

write_run_summary() {
  local finished_at_unix finished_at_local finished_at_utc elapsed_secs elapsed_human
  finished_at_unix="$(date +%s)"
  finished_at_local="$(date '+%Y-%m-%d %H:%M:%S %Z')"
  finished_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  elapsed_secs=$((finished_at_unix - RUN_STARTED_AT_UNIX))
  elapsed_human="$(format_elapsed_duration "$elapsed_secs")"
  python3 - "$NODES_TSV" "$STAGE_TSV" "$SUMMARY_JSON" "$SUMMARY_MD" "$RUN_ID" "$NETWORK_ID" "$REPORT_DIR" "$OVERALL_STATUS" "$RUN_STARTED_AT_LOCAL" "$RUN_STARTED_AT_UTC" "$RUN_STARTED_AT_UNIX" "$finished_at_local" "$finished_at_utc" "$finished_at_unix" "$elapsed_secs" "$elapsed_human" <<'PY'
import csv
import json
import sys
from pathlib import Path

(nodes_tsv, stages_tsv, summary_json, summary_md, run_id, network_id, report_dir, overall_status,
 started_at_local, started_at_utc, started_at_unix, finished_at_local, finished_at_utc, finished_at_unix,
 elapsed_secs, elapsed_human) = sys.argv[1:]

nodes = []
with open(nodes_tsv, newline='', encoding='utf-8') as fh:
    reader = csv.reader(fh, delimiter='\t')
    for row in reader:
        if not row:
            continue
        label, target, node_id, role = row
        nodes.append({
            'label': label,
            'target': target,
            'node_id': node_id,
            'bootstrap_role': role,
        })

stages = []
with open(stages_tsv, newline='', encoding='utf-8') as fh:
    reader = csv.reader(fh, delimiter='\t')
    for row in reader:
        if not row:
            continue
        stage_name, severity, status, rc, log_path, message, started_at, finished_at = row
        stages.append({
            'stage': stage_name,
            'severity': severity,
            'status': status,
            'rc': int(rc),
            'log_path': log_path,
            'message': message,
            'started_at': started_at,
            'finished_at': finished_at,
        })

summary = {
    'schema_version': 1,
    'run_id': run_id,
    'network_id': network_id,
    'report_dir': report_dir,
    'overall_status': overall_status,
    'started_at_local': started_at_local,
    'started_at_utc': started_at_utc,
    'started_at_unix': int(started_at_unix),
    'finished_at_local': finished_at_local,
    'finished_at_utc': finished_at_utc,
    'finished_at_unix': int(finished_at_unix),
    'elapsed_secs': int(elapsed_secs),
    'elapsed_human': elapsed_human,
    'nodes': nodes,
    'stages': stages,
}
Path(summary_json).write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')

lines = []
lines.append(f'# Live Linux Lab Orchestrator Summary ({run_id})')
lines.append('')
lines.append(f'- overall_status: `{overall_status}`')
lines.append(f'- network_id: `{network_id}`')
lines.append(f'- report_dir: `{report_dir}`')
lines.append(f'- started_at_local: `{started_at_local}`')
lines.append(f'- started_at_utc: `{started_at_utc}`')
lines.append(f'- finished_at_local: `{finished_at_local}`')
lines.append(f'- finished_at_utc: `{finished_at_utc}`')
lines.append(f'- elapsed: `{elapsed_human}`')
lines.append('')
lines.append('## Nodes')
lines.append('')
for node in nodes:
    lines.append(f"- `{node['label']}`: `{node['target']}` (`{node['node_id']}`, bootstrap role `{node['bootstrap_role']}`)")
lines.append('')
lines.append('## Stages')
lines.append('')
for stage in stages:
    lines.append(
        f"- `{stage['stage']}` [{stage['severity']}] -> `{stage['status']}` (rc={stage['rc']})"
    )
    lines.append(f"  log: `{stage['log_path']}`")
    lines.append(f"  detail: {stage['message']}")
Path(summary_md).write_text('\n'.join(lines) + '\n', encoding='utf-8')
PY
}

refresh_failure_digest() {
  if [[ ! -f "$NODES_TSV" || ! -f "$STAGE_TSV" ]]; then
    return 0
  fi
  if [[ ! -f "$ROOT_DIR/scripts/e2e/generate_live_linux_lab_failure_digest.py" ]]; then
    return 0
  fi
  if ! python3 "$ROOT_DIR/scripts/e2e/generate_live_linux_lab_failure_digest.py" \
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
      --entry-target) ENTRY_TARGET="$2"; shift 2 ;;
      --aux-target) AUX_TARGET="$2"; shift 2 ;;
      --extra-target) EXTRA_TARGET="$2"; shift 2 ;;
      --ssh-identity-file) SSH_IDENTITY_FILE="$2"; shift 2 ;;
      --ssh-password-file) SSH_IDENTITY_FILE="$2"; shift 2 ;;
      --sudo-password-file) SSH_IDENTITY_FILE="$2"; shift 2 ;;
      --ssh-known-hosts-file) SSH_KNOWN_HOSTS_FILE="$2"; shift 2 ;;
      --network-id) NETWORK_ID="$2"; shift 2 ;;
      --ssh-allow-cidrs) SSH_ALLOW_CIDRS="$2"; shift 2 ;;
      --traversal-ttl-secs) TRAVERSAL_TTL_SECS="$2"; shift 2 ;;
      --repo-ref) REPO_REF="$2"; SOURCE_MODE="ref"; SOURCE_MODE_EXPLICIT=1; shift 2 ;;
      --report-dir) REPORT_DIR="$2"; LOG_DIR="$REPORT_DIR/logs"; VERIFICATION_DIR="$REPORT_DIR/verification"; STATE_DIR="$REPORT_DIR/state"; SUMMARY_JSON="$REPORT_DIR/run_summary.json"; SUMMARY_MD="$REPORT_DIR/run_summary.md"; FAILURE_DIGEST_JSON="$REPORT_DIR/failure_digest.json"; FAILURE_DIGEST_MD="$REPORT_DIR/failure_digest.md"; STAGE_TSV="$STATE_DIR/stages.tsv"; NODES_TSV="$STATE_DIR/nodes.tsv"; SOURCE_ARCHIVE="$STATE_DIR/rustynet-source.tar.gz"; PUBKEYS_TSV="$STATE_DIR/pubkeys.tsv"; ONEHOP_STATE_ENV="$STATE_DIR/onehop_state.env"; shift 2 ;;
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
      --reboot-hard-fail) SOAK_HARD_FAIL=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
  done
}

prompt_missing_inputs() {
  if [[ -z "$EXIT_TARGET" ]]; then
    EXIT_TARGET="$(prompt_value 'Primary exit node (user@ip or ip)')"
  fi
  if [[ -z "$CLIENT_TARGET" ]]; then
    CLIENT_TARGET="$(prompt_value 'Primary client node (user@ip or ip)')"
  fi
  if [[ -z "$ENTRY_TARGET" ]]; then
    if [[ "$ENTRY_TARGET_DECLARED" -eq 0 ]]; then
      ENTRY_TARGET="$(prompt_value 'Entry relay / alternate exit node (user@ip or ip, blank to skip advanced tests)')"
    fi
  fi
  if [[ -z "$AUX_TARGET" ]]; then
    if [[ "$AUX_TARGET_DECLARED" -eq 0 ]]; then
      AUX_TARGET="$(prompt_value 'Auxiliary client / blind-exit node (user@ip or ip, blank to skip advanced tests)')"
    fi
  fi
  if [[ -z "$EXTRA_TARGET" ]]; then
    if [[ "$EXTRA_TARGET_DECLARED" -eq 0 ]]; then
      EXTRA_TARGET="$(prompt_value 'Optional extra client node (user@ip or ip, blank if none)')"
    fi
  fi
}

maybe_prompt_for_default_profile() {
  if [[ -n "$PROFILE_PATH" ]]; then
    return 0
  fi
  if [[ -n "$EXIT_TARGET" || -n "$CLIENT_TARGET" || -n "$ENTRY_TARGET" || -n "$AUX_TARGET" || -n "$EXTRA_TARGET" ]]; then
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
  if [[ "$SOURCE_MODE" != "working-tree" || "$REPO_REF" != "working-tree" ]]; then
    return 0
  fi
  if [[ ! -t 0 || ! -t 1 ]]; then
    return 0
  fi
  if prompt_yes_no "Update from latest git instead of local working tree?" "n"; then
    prompt_for_git_branch_source
  else
    SOURCE_MODE="working-tree"
    REPO_REF="working-tree"
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
  if ! python3 - "$SSH_KNOWN_HOSTS_FILE" <<'PY'
import os
import stat
import sys

path = sys.argv[1]
st = os.stat(path, follow_symlinks=False)
mode = stat.S_IMODE(st.st_mode)
if mode & 0o022:
    raise SystemExit(f"pinned SSH known_hosts file must not be group/world writable: {path} ({mode:03o})")
PY
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
  maybe_prompt_for_default_profile
  if [[ -n "$PROFILE_PATH" ]]; then
    load_profile_file "$PROFILE_PATH"
  fi
  maybe_prompt_for_source_mode
  mkdir -p "$LOG_DIR" "$VERIFICATION_DIR" "$STATE_DIR"
  : > "$STAGE_TSV"
  prompt_missing_inputs
  normalize_targets
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
    record_stage_skip "prime_remote_access" "hard" "dry-run: not executed"
    record_stage_skip "cleanup_hosts" "hard" "dry-run: not executed"
    record_stage_skip "bootstrap_hosts" "hard" "dry-run: not executed"
    record_stage_skip "collect_pubkeys" "hard" "dry-run: not executed"
    record_stage_skip "membership_setup" "hard" "dry-run: not executed"
    record_stage_skip "distribute_membership_state" "hard" "dry-run: not executed"
    record_stage_skip "issue_and_distribute_assignments" "hard" "dry-run: not executed"
    record_stage_skip "issue_and_distribute_traversal" "hard" "dry-run: not executed"
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
      record_stage_skip "extended_soak" "soft" "dry-run: not executed"
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
        else
          record_stage_skip "cross_network_relay_remote_exit${stage_suffix}" "hard" "dry-run: skipped because entry or aux target is not configured"
          record_stage_skip "cross_network_failback_roaming${stage_suffix}" "hard" "dry-run: skipped because entry or aux target is not configured"
        fi
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

  run_stage hard preflight 'verify local prerequisites' stage_preflight
  run_stage hard prepare_source_archive 'package local source tree for remote install' stage_prepare_source_archive
  run_stage hard prime_remote_access 'push sudo credentials to all targets' prime_remote_access
  run_stage hard cleanup_hosts 'remove prior RustyNet state from targets' stage_cleanup_hosts
  run_stage hard bootstrap_hosts 'fresh install and bootstrap RustyNet on all targets' stage_bootstrap_hosts
  run_stage hard collect_pubkeys 'collect WireGuard public keys from all targets' stage_collect_pubkeys
  run_stage hard membership_setup 'apply signed membership updates on primary exit' stage_membership_setup
  run_stage hard distribute_membership_state 'export and install membership state to peers' stage_distribute_membership_state
  run_stage hard issue_and_distribute_assignments 'issue signed one-hop assignments and install refresh env files' stage_issue_and_distribute_assignments
  run_stage hard issue_and_distribute_traversal 'issue and distribute signed traversal bundles for all managed peers' stage_issue_and_distribute_traversal
  run_stage hard enforce_baseline_runtime 'enforce baseline runtime roles and advertise exit route' stage_enforce_baseline_runtime
  run_stage hard validate_baseline_runtime 'validate one-hop routing and no-plaintext-passphrase state' stage_validate_baseline_runtime

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
      if [[ "$SOAK_HARD_FAIL" -eq 1 ]]; then
        run_stage hard extended_soak 'run extended soak and reboot recovery validation' stage_run_extended_soak
      else
        run_stage soft extended_soak 'run extended soak and reboot recovery validation' stage_run_extended_soak
      fi
    else
      record_stage_skip extended_soak soft 'skipped by --skip-soak'
    fi
  else
    record_stage_skip extended_soak soft 'requires entry and aux targets'
  fi

  local cross_network_stage_rc=0 stage_rc=0
  if cross_network_stages_applicable; then
    local nat_profile nat_idx stage_suffix profile_report profile_log
    set +e
    run_stage hard cross_network_preflight 'verify cross-network validator prerequisites (time skew, cryptographic signed-state verification, daemon health, discovery bundle validation, required binaries/services)' stage_run_cross_network_preflight
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
        else
          record_stage_skip "cross_network_relay_remote_exit${stage_suffix}" hard 'requires entry or aux target'
          record_stage_skip "cross_network_failback_roaming${stage_suffix}" hard 'requires entry or aux target'
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
