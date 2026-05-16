# L1 — start.sh modularization (GAP-10).
#
# This file holds macOS-operator-host-specific routines extracted
# from start.sh. The first slice landed `common.sh` and this
# scaffold; the bulk of the macOS launchd / pfctl / Keychain wiring
# still lives in start.sh and will migrate here incrementally.
#
# Sourcing contract:
#   * start.sh sources `common.sh` first, then this file. The common
#     helpers (`print_info`, `is_macos_host`, …) are already in scope.
#   * Every function added here MUST guard with `is_macos_host` early
#     so a stray source on a Linux host is a no-op rather than a
#     foot-gun.
#   * Keychain access uses the `security` binary with argv-only
#     invocation. No shell-string construction with operator-supplied
#     values.

if ! declare -F is_macos_host >/dev/null 2>&1; then
  printf '[error] %s\n' \
    "scripts/start/macos.sh requires scripts/start/common.sh to be sourced first" >&2
  return 1 2>/dev/null || exit 1
fi

if ! is_macos_host && [[ "${RUSTYNET_DEBUG_MODULE_SOURCING:-0}" == "1" ]]; then
  # Default-quiet on non-target platforms — debug aid only. Set
  # RUSTYNET_DEBUG_MODULE_SOURCING=1 to see it.
  print_warn "scripts/start/macos.sh sourced on non-macOS host (HOST_OS=${HOST_OS}); functions will be no-ops"
fi

# Reviewed macOS Keychain service name for the WireGuard passphrase.
# Pinned here so any future Keychain-account rotation references one
# canonical service identity. The account portion is per-device and
# constructed via `sanitize_macos_keychain_account` in common.sh.
RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE="net.rustynet.wg-key-passphrase"
RUSTYNET_MACOS_SIGNING_PASSPHRASE_KEYCHAIN_SERVICE="net.rustynet.signing-key-passphrase"

# True iff a Keychain entry exists for the given service+account.
# Argv-only `security find-generic-password` invocation; no shell
# construction with operator-supplied values. Always returns 1 off
# macOS or when either argument is empty.
rustynet_macos_keychain_entry_exists() {
  if ! is_macos_host; then
    return 1
  fi
  local service="${1:-}"
  local account="${2:-}"
  if [[ -z "${service}" || -z "${account}" ]]; then
    return 1
  fi
  security find-generic-password \
    -s "${service}" \
    -a "${account}" \
    >/dev/null 2>&1
}
