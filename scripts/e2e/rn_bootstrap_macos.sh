#!/usr/bin/env bash
# rn_bootstrap_macos.sh — Orchestrator-side wrapper that drives the
# reviewed macOS bootstrap (`scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh`)
# from the cross-OS lab orchestrator (Phase 23).
#
# This script runs on the *target* macOS host. The orchestrator scp's
# it along with the source archive, then invokes it with the lab inputs.
# The wrapper:
#
#   1. Parses CLI args (`--node-id`, `--network-id`, `--node-role`,
#      `--ssh-allow-cidrs`).
#   2. Validates every input against a strict allowlist (no shell
#      construction with untrusted values).
#   3. Derives the per-node `utun` interface name using the same FNV-1a
#      32-bit hash as the Rust adapter (`utun_index_for_node_id` in
#      crates/rustynet-cli/.../macos_install.rs). This keeps a single
#      hardened execution path: the bash wrapper and the Rust adapter
#      must produce bit-identical interface names for a given node_id.
#   4. Writes the bootstrap env file consumed by
#      `Bootstrap-RustyNetMacos.sh` (and forwards `DAEMON_NODE_ROLE` +
#      `SSH_ALLOW_CIDRS` so the launchd plist install picks them up).
#   5. Extracts the source archive into `/private/var/tmp/rn_build`.
#   6. Invokes the reviewed bootstrap script with `sudo`.
#   7. Polls for the daemon Unix socket to appear (40 s × 1 s).
#
# Idempotency: every step is safe to re-run.  The reviewed bootstrap
# itself skips already-present prereqs and reseeds only when the
# canonical file is missing; the build dir is wiped each run so a fresh
# source tree always replaces the previous extraction.
#
# Fail-closed: `set -euo pipefail` plus strict input validation plus
# explicit non-zero exits on missing inputs or stale state.

set -euo pipefail

# ── CLI parsing ───────────────────────────────────────────────────────────────
NODE_ID=""
NETWORK_ID=""
NODE_ROLE=""
SSH_ALLOW_CIDRS=""
SOURCE_ARCHIVE_PATH="/private/var/tmp/rustynet_src.tar.gz"
BUILD_DIR="/private/var/tmp/rn_build"
ENV_FILE_PATH="/private/var/tmp/rn_macos_bootstrap.env"

usage() {
  cat >&2 <<'USAGE'
usage: rn_bootstrap_macos.sh \
    --node-id <id> \
    --network-id <id> \
    --node-role <client|exit|entry|aux|extra|fifth_client> \
    [--ssh-allow-cidrs <csv-cidrs>] \
    [--source-archive <path>] \
    [--build-dir <path>] \
    [--env-file <path>]

Runs the reviewed macOS bootstrap (Bootstrap-RustyNetMacos.sh +
Install-RustyNetMacosService.sh) with the orchestrator-provided
NODE_ID / NETWORK_ID / NODE_ROLE / SSH_ALLOW_CIDRS values and a
deterministic per-node utun interface name.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --node-id)         NODE_ID="${2:-}";              shift 2 ;;
    --network-id)      NETWORK_ID="${2:-}";           shift 2 ;;
    --node-role)       NODE_ROLE="${2:-}";            shift 2 ;;
    --ssh-allow-cidrs) SSH_ALLOW_CIDRS="${2:-}";      shift 2 ;;
    --source-archive)  SOURCE_ARCHIVE_PATH="${2:-}";  shift 2 ;;
    --build-dir)       BUILD_DIR="${2:-}";            shift 2 ;;
    --env-file)        ENV_FILE_PATH="${2:-}";        shift 2 ;;
    -h|--help)         usage; exit 0 ;;
    *) printf 'rn_bootstrap_macos.sh: unknown argument: %s\n' "$1" >&2; usage; exit 2 ;;
  esac
done

# ── Input validation (strict allowlists, no shell metacharacters) ─────────────
require_value() {
  local label="$1"
  local value="$2"
  if [[ -z "$value" ]]; then
    printf 'rn_bootstrap_macos.sh: %s is required\n' "$label" >&2
    exit 2
  fi
}

validate_identifier() {
  local label="$1"
  local value="$2"
  if [[ ${#value} -gt 128 ]]; then
    printf 'rn_bootstrap_macos.sh: %s exceeds 128 chars\n' "$label" >&2
    exit 2
  fi
  if [[ ! "$value" =~ ^[A-Za-z0-9._-]+$ ]]; then
    printf 'rn_bootstrap_macos.sh: %s must match [A-Za-z0-9._-]+ (received: %q)\n' \
      "$label" "$value" >&2
    exit 2
  fi
}

validate_node_role() {
  local value="$1"
  case "$value" in
    client|exit|entry|aux|extra|fifth_client) ;;
    *) printf 'rn_bootstrap_macos.sh: --node-role must be one of client|exit|entry|aux|extra|fifth_client (received: %q)\n' \
         "$value" >&2; exit 2 ;;
  esac
}

validate_ssh_allow_cidrs() {
  local value="$1"
  # Empty is allowed (SSH fail-open rule remains disabled).
  if [[ -z "$value" ]]; then
    return 0
  fi
  if [[ ${#value} -gt 1024 ]]; then
    printf 'rn_bootstrap_macos.sh: --ssh-allow-cidrs exceeds 1024 chars\n' >&2
    exit 2
  fi
  # Comma-separated IPv4/IPv6 CIDRs; reject anything outside the
  # reviewed charset so we cannot smuggle shell metacharacters into the
  # downstream plist.
  if [[ ! "$value" =~ ^[A-Fa-f0-9:./,]+$ ]]; then
    printf 'rn_bootstrap_macos.sh: --ssh-allow-cidrs must contain only hex/colon/dot/slash/comma (received: %q)\n' \
      "$value" >&2
    exit 2
  fi
}

validate_path_argument() {
  local label="$1"
  local value="$2"
  if [[ -z "$value" ]]; then
    printf 'rn_bootstrap_macos.sh: %s must be non-empty\n' "$label" >&2
    exit 2
  fi
  if [[ "$value" != /* ]]; then
    printf 'rn_bootstrap_macos.sh: %s must be an absolute path (received: %q)\n' \
      "$label" "$value" >&2
    exit 2
  fi
  case "$value" in
    *$'\n'*|*$'\r'*|*' '*|*'`'*|*'$'*|*'"'*|*"'"*|*';'*|*'&'*|*'|'*|*'<'*|*'>'*)
      printf 'rn_bootstrap_macos.sh: %s contains shell-unsafe characters (received: %q)\n' \
        "$label" "$value" >&2
      exit 2
      ;;
  esac
}

require_value "--node-id" "$NODE_ID"
require_value "--network-id" "$NETWORK_ID"
require_value "--node-role" "$NODE_ROLE"
validate_identifier "--node-id" "$NODE_ID"
validate_identifier "--network-id" "$NETWORK_ID"
validate_node_role "$NODE_ROLE"
validate_ssh_allow_cidrs "$SSH_ALLOW_CIDRS"
validate_path_argument "--source-archive" "$SOURCE_ARCHIVE_PATH"
validate_path_argument "--build-dir" "$BUILD_DIR"
validate_path_argument "--env-file" "$ENV_FILE_PATH"

# ── FNV-1a 32-bit utun index (must match Rust adapter) ───────────────────────
#
# Rust reference:
#   crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install.rs
#     fn utun_index_for_node_id(node_id: &str) -> u16 {
#         let mut hash: u32 = 2_166_136_261;
#         for byte in node_id.bytes() {
#             hash ^= u32::from(byte);
#             hash = hash.wrapping_mul(16_777_619);
#         }
#         (hash % 4086) as u16 + 10
#     }
#
# Both implementations MUST produce the same value for a given node_id so
# the orchestrator's enforce_runtime step (which calls the Rust adapter)
# and this bootstrap (which calls the bash hash) reference the same utun
# device. A divergence would mean the daemon's bootstrap plist names one
# interface, the enforce-runtime plist names another, and the WireGuard
# tunnel comes up on a different utun than the privileged helper expects.
fnv1a_utun_index() {
  local s="$1"
  local hash=2166136261
  local i len byte
  len="${#s}"
  for (( i = 0; i < len; i++ )); do
    printf -v byte '%d' "'${s:i:1}"
    hash=$(( hash ^ byte ))
    hash=$(( (hash * 16777619) & 0xFFFFFFFF ))
  done
  printf '%d' $(( (hash % 4086) + 10 ))
}

fnv1a_utun_name() {
  local s="$1"
  local index
  index="$(fnv1a_utun_index "$s")"
  printf 'utun%s' "$index"
}

# ── Parity guard: known-input expected-output assertions ─────────────────────
#
# These pins fire if the FNV-1a constants drift in either the bash side
# (above) or the Rust side (macos_install.rs). They are deliberately
# computed from inputs already in the lab inventory so that lab-wide
# bootstraps trip the guard before any host gets a divergent utun name.
assert_known_utun_index() {
  local input="$1"
  local expected="$2"
  local actual
  actual="$(fnv1a_utun_index "$input")"
  if [[ "$actual" != "$expected" ]]; then
    printf 'rn_bootstrap_macos.sh: FNV-1a utun index drift detected: input=%q expected=%s actual=%s\n' \
      "$input" "$expected" "$actual" >&2
    printf 'rn_bootstrap_macos.sh: bash and Rust hash implementations must produce identical values\n' >&2
    exit 1
  fi
}

# Known good values: see the Rust tests in macos_install.rs
# `utun_index_is_deterministic` + `utun_index_avoids_reserved_range`.
# Computed by running both implementations and pinning the result.
assert_known_utun_index "macos-client-1" "3912"
assert_known_utun_index "exit-1"         "2369"
assert_known_utun_index "client-1"       "3466"

# ── Derive WG_INTERFACE for this node ────────────────────────────────────────
WG_INTERFACE="$(fnv1a_utun_name "$NODE_ID")"
# Defense-in-depth: validate the derived name shape matches what
# Install-RustyNetMacosService.sh accepts (^utun[0-9]+$, ≤15 chars).
if [[ ! "$WG_INTERFACE" =~ ^utun[0-9]+$ ]]; then
  printf 'rn_bootstrap_macos.sh: derived WG_INTERFACE %q does not match ^utun[0-9]+$\n' \
    "$WG_INTERFACE" >&2
  exit 1
fi
if [[ ${#WG_INTERFACE} -gt 15 ]]; then
  printf 'rn_bootstrap_macos.sh: derived WG_INTERFACE %q exceeds 15-char IFNAMSIZ\n' \
    "$WG_INTERFACE" >&2
  exit 1
fi

# ── Map orchestrator role -> daemon NodeRole ────────────────────────────────
#
# Mirrors `NodeRole::daemon_node_role_for_platform(Macos)` in
# crates/rustynet-cli/src/vm_lab/orchestrator/role.rs. The bash side has
# to stay in sync because Bootstrap-RustyNetMacos.sh refuses to start
# the daemon without an explicit DAEMON_NODE_ROLE in {admin, client,
# blind_exit}. macOS lab nodes always run as client (no relay/exit
# parity yet); the exit role maps to blind_exit because the wizard
# disallows full exit on macOS.
daemon_node_role_for_macos() {
  case "$1" in
    exit) printf 'blind_exit' ;;
    client|entry|aux|extra|fifth_client) printf 'client' ;;
    *) printf 'rn_bootstrap_macos.sh: cannot map role %q to a macOS daemon role\n' \
         "$1" >&2; exit 1 ;;
  esac
}

DAEMON_NODE_ROLE="$(daemon_node_role_for_macos "$NODE_ROLE")"

# ── Source archive presence check ────────────────────────────────────────────
if [[ ! -f "$SOURCE_ARCHIVE_PATH" ]]; then
  printf 'rn_bootstrap_macos.sh: source archive missing at %s\n' "$SOURCE_ARCHIVE_PATH" >&2
  exit 1
fi

# ── Extract source archive (always fresh) ───────────────────────────────────
# rm + mkdir is idempotent: every run starts from a clean BUILD_DIR so a
# stale build tree from a previous bootstrap cannot mask a fresh source
# update.
sudo -n rm -rf "$BUILD_DIR"
sudo -n mkdir -p "$BUILD_DIR"
sudo -n tar -xzf "$SOURCE_ARCHIVE_PATH" -C "$BUILD_DIR"

BOOTSTRAP_SCRIPT="$BUILD_DIR/scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh"
if [[ ! -f "$BOOTSTRAP_SCRIPT" ]]; then
  printf 'rn_bootstrap_macos.sh: bootstrap script missing after extract: %s\n' \
    "$BOOTSTRAP_SCRIPT" >&2
  exit 1
fi

# ── Write env file consumed by Bootstrap-RustyNetMacos.sh ────────────────────
# Bootstrap-RustyNetMacos.sh sources this file (line 43); the variables
# it reads are: ROLE, DAEMON_NODE_ROLE, NODE_ID, NETWORK_ID,
# SSH_ALLOW_CIDRS, SOURCE_ARCHIVE, and the optional SKIP_BUILD /
# WG_INTERFACE overrides.
#
# We deliberately write each KEY=VALUE pair via printf with %q so any
# adversarial characters that made it past validation above still get
# shell-escaped inside the env file (defence in depth — the env file is
# `source`d, not parsed as KV).
write_env_assignment() {
  local key="$1"
  local value="$2"
  printf '%s=%q\n' "$key" "$value"
}

{
  printf '# rn_bootstrap_macos.sh — generated for node %q on %s\n' \
    "$NODE_ID" "$(date -u +%FT%TZ)"
  write_env_assignment "ROLE" "$NODE_ROLE"
  write_env_assignment "DAEMON_NODE_ROLE" "$DAEMON_NODE_ROLE"
  write_env_assignment "NODE_ID" "$NODE_ID"
  write_env_assignment "NETWORK_ID" "$NETWORK_ID"
  write_env_assignment "SSH_ALLOW_CIDRS" "$SSH_ALLOW_CIDRS"
  write_env_assignment "SOURCE_ARCHIVE" "$SOURCE_ARCHIVE_PATH"
  write_env_assignment "WG_INTERFACE" "$WG_INTERFACE"
} > "$ENV_FILE_PATH"
chmod 0600 "$ENV_FILE_PATH"

# ── Invoke the reviewed bootstrap ───────────────────────────────────────────
# argv-only exec via sudo + bash; no shell construction of the script
# path or env file path (both are absolute, validated).
sudo -n bash "$BOOTSTRAP_SCRIPT" "$ENV_FILE_PATH"

# ── Poll for the daemon socket ──────────────────────────────────────────────
#
# Mirrors `wait_for_macos_daemon_socket` in macos_install.rs:
# launchctl bootstrap returns before the daemon binds its socket, so the
# next orchestrator stage (collect_pubkeys) must not start until the
# socket file is present. 40 iterations × 1 s matches the Rust adapter.
wait_for_macos_daemon_socket() {
  local socket="/private/var/run/rustynet/rustynetd.sock"
  local attempt
  for attempt in $(seq 1 40); do
    if sudo -n test -S "$socket"; then
      printf 'rn_bootstrap_macos.sh: daemon socket ready at %s (attempt %d)\n' \
        "$socket" "$attempt"
      return 0
    fi
    sleep 1
  done
  printf 'rn_bootstrap_macos.sh: daemon socket %s did not appear within 40 s of bootstrap completion\n' \
    "$socket" >&2
  return 1
}

wait_for_macos_daemon_socket
exit 0
