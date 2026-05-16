# L1 — start.sh modularization (GAP-10).
#
# This file holds the platform-agnostic helpers that start.sh needs
# regardless of whether the host is a Linux runtime host or a macOS
# operator host. Functions here MUST NOT execute privileged commands
# or branch on host-specific binaries. Platform-specific logic lives
# in `linux.sh` / `macos.sh`.
#
# Sourcing contract:
#   * start.sh sets ROOT_DIR before sourcing this file
#   * start.sh sets HOST_OS to `uname -s` output before sourcing
#   * Every function name here must remain stable — start.sh and the
#     per-platform modules call them by name. Renaming a function is
#     a breaking change.
#
# Security boundary:
#   * No function in this file may exec a binary with attacker-
#     controlled argv. The common layer is shell-pure: it formats
#     strings, tests path prefixes, and returns sentinel exit codes.
#   * Path prefix tests are normalised to known reviewed roots; do
#     not extend them ad-hoc.
#
# shellcheck disable=SC2034
# Intentional: some constants below are exported into the start.sh
# scope and consumed there.

# -------- structured output -------------------------------------------------

# Format an informational line. Writes to stdout.
print_info() {
  printf '[info] %s\n' "$*"
}

# Format a warning. Writes to stderr so transcripts can separate
# non-fatal anomalies from primary output.
print_warn() {
  printf '[warn] %s\n' "$*" >&2
}

# Format an error. Writes to stderr. Callers decide whether to exit;
# this helper never terminates the script on its own.
print_err() {
  printf '[error] %s\n' "$*" >&2
}

# -------- host-profile predicates -------------------------------------------

# True iff the host is a Linux runtime host. Pure: only reads HOST_OS.
is_linux_host() {
  [[ "${HOST_OS}" == "Linux" ]]
}

# True iff the host is a macOS operator/lab host.
is_macos_host() {
  [[ "${HOST_OS}" == "Darwin" ]]
}

# -------- reviewed path classifiers -----------------------------------------

# Reviewed Linux runtime root prefixes. Pinned here so any future
# extension is a deliberate edit reviewed in this file alone.
__RUSTYNET_LINUX_RUNTIME_ROOTS=(
  "/etc/rustynet"
  "/var/lib/rustynet"
  "/run/rustynet"
  "/var/log/rustynet"
)

# True iff the path lives under one of the reviewed Linux runtime
# roots. Used to detect "macOS config has Linux-rooted paths leaking
# in" drift (see `validate_macos_passphrase_source_contract`).
path_in_linux_runtime_roots() {
  local value="$1"
  local root
  for root in "${__RUSTYNET_LINUX_RUNTIME_ROOTS[@]}"; do
    if [[ "${value}" == "${root}" || "${value}" == "${root}"/* ]]; then
      return 0
    fi
  done
  return 1
}

# -------- macOS Keychain account-name sanitisation --------------------------

# macOS Keychain account names must match [A-Za-z0-9._-]+. The
# sanitiser replaces every non-matching character with `-`, strips
# ONE leading and ONE trailing dash (matching the historical
# start.sh semantics; consecutive dashes are preserved internally),
# and falls back to a reviewed default ONLY when the post-strip
# value is the empty string. Pure string transformation; no side
# effects, no Keychain calls.
#
# Note on degenerate inputs: pathological inputs like "@@@" map to
# `---` → strip-one-leading → `--` → strip-one-trailing → `-`, which
# is the pre-existing behaviour. All current callers prefix with the
# literal `wg-passphrase-` (always valid chars), so the degenerate
# case can only be reached by a hand-edited operator config.
sanitize_macos_keychain_account() {
  local value="$1"
  value="${value//[^A-Za-z0-9._-]/-}"
  value="${value#-}"
  value="${value%-}"
  if [[ -z "${value}" ]]; then
    value="rustynet-passphrase"
  fi
  printf '%s' "${value}"
}

# -------- argument hygiene ---------------------------------------------------

# True iff the given string is one of: 0 / 1 / true / false / yes /
# no. Used to validate operator-supplied boolean toggles before they
# reach the daemon argv. Case-insensitive.
__rustynet_is_bool_token() {
  local raw="${1:-}"
  local lower="${raw,,}"
  case "${lower}" in
    0|1|true|false|yes|no) return 0 ;;
    *) return 1 ;;
  esac
}

# Normalise a bool-ish token into 0/1. Returns the canonical form on
# stdout and exits 0 iff the input was a known bool token. Used by
# the per-platform modules to canonicalise toggle args before
# rewriting env files.
__rustynet_canonical_bool() {
  local raw="${1:-}"
  local lower="${raw,,}"
  case "${lower}" in
    1|true|yes) printf '1' ;;
    0|false|no) printf '0' ;;
    *) return 1 ;;
  esac
}
