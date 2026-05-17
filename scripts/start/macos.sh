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

# Guard + initialize/sanitize the per-device Keychain account name used
# for the WireGuard passphrase entry. Idempotent: if the caller already
# set WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT, the value is re-sanitized
# through the common helper rather than trusted as-is. No-op on
# non-macOS hosts so a stray call from a shared code path is safe.
ensure_macos_keychain_passphrase_account() {
  if ! is_macos_host; then
    return 0
  fi
  if [[ -z "${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}" ]]; then
    WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT="$(sanitize_macos_keychain_account "wg-passphrase-${DEVICE_NODE_ID}")"
  else
    WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT="$(sanitize_macos_keychain_account "${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}")"
  fi
}

# Return 0 iff a Keychain entry for the WireGuard passphrase exists for
# the current account. Always returns 1 off macOS or when the account
# var is unset. Argv-only `security` invocation; no shell-string
# construction with operator-supplied values.
macos_keychain_passphrase_exists() {
  if ! is_macos_host; then
    return 1
  fi
  if [[ -z "${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}" ]]; then
    return 1
  fi
  security find-generic-password \
    -s "${MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE}" \
    -a "${WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT}" >/dev/null 2>&1
}

# Apply macOS-host profile defaults. Sets HOST_PROFILE and pins the
# canonical per-user macOS runtime/state/log paths consumed by the
# rest of start.sh. Guarded so a stray call on a non-macOS host is a
# no-op rather than clobbering Linux state.
__rustynet_macos_apply_profile_defaults() {
  if ! is_macos_host; then
    return 0
  fi
  HOST_PROFILE="macos"

  SOCKET_PATH="${MACOS_RUNTIME_BASE}/rustynetd.sock"
  STATE_PATH="${MACOS_STATE_BASE}/rustynetd.state"
  TRUST_EVIDENCE_PATH="${MACOS_STATE_BASE}/trust/rustynetd.trust"
  TRUST_VERIFIER_KEY_PATH="${MACOS_STATE_BASE}/trust/trust-evidence.pub"
  TRUST_WATERMARK_PATH="${MACOS_STATE_BASE}/trust/rustynetd.trust.watermark"
  AUTO_TUNNEL_BUNDLE_PATH="${MACOS_STATE_BASE}/assignment/rustynetd.assignment"
  AUTO_TUNNEL_VERIFIER_KEY_PATH="${MACOS_STATE_BASE}/assignment/assignment.pub"
  AUTO_TUNNEL_WATERMARK_PATH="${MACOS_STATE_BASE}/assignment/rustynetd.assignment.watermark"
  TRAVERSAL_BUNDLE_PATH="${MACOS_STATE_BASE}/traversal/rustynetd.traversal"
  TRAVERSAL_VERIFIER_KEY_PATH="${MACOS_STATE_BASE}/traversal/traversal.pub"
  TRAVERSAL_WATERMARK_PATH="${MACOS_STATE_BASE}/traversal/rustynetd.traversal.watermark"
  WG_PRIVATE_KEY_PATH="${MACOS_STATE_BASE}/keys/wireguard.key"
  WG_ENCRYPTED_PRIVATE_KEY_PATH="${MACOS_STATE_BASE}/keys/wireguard.key.enc"
  WG_KEY_PASSPHRASE_PATH="${MACOS_STATE_BASE}/keys/wireguard.passphrase"
  WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH="${MACOS_STATE_BASE}/keys/wg_key_passphrase.cred"
  SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH="${MACOS_STATE_BASE}/keys/signing_key_passphrase.cred"
  WG_PUBLIC_KEY_PATH="${MACOS_STATE_BASE}/keys/wireguard.pub"
  WG_INTERFACE="utun9"
  MEMBERSHIP_SNAPSHOT_PATH="${MACOS_STATE_BASE}/membership/membership.snapshot"
  MEMBERSHIP_LOG_PATH="${MACOS_STATE_BASE}/membership/membership.log"
  MEMBERSHIP_WATERMARK_PATH="${MACOS_STATE_BASE}/membership/membership.watermark"
  MEMBERSHIP_OWNER_SIGNING_KEY_PATH="${MACOS_STATE_BASE}/membership/membership.owner.key"
  TRUST_SIGNER_KEY_PATH="${MACOS_STATE_BASE}/trust/trust-evidence.key"
  PRIVILEGED_HELPER_SOCKET_PATH="${MACOS_RUNTIME_BASE}/rustynetd-privileged.sock"
  MANUAL_PEER_AUDIT_LOG="${MACOS_LOG_BASE}/manual-peer-override.log"
  WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT="$(sanitize_macos_keychain_account "wg-passphrase-${DEVICE_NODE_ID}")"
  MANUAL_PEER_OVERRIDE="0"
}

# Exact-match validator for a macOS-canonical path variable. Fails
# closed: missing or non-canonical values abort start.sh rather than
# silently rewriting under the operator. Used only by the macOS
# enforce-storage-policy variant below; lives here so the macOS
# storage-policy boundary is self-contained in this module.
require_macos_path_var_exact() {
  local var_name="$1"
  local expected="$2"
  local current="${!var_name:-}"
  if [[ -z "${current}" ]]; then
    print_err "Missing required macOS path setting ${var_name}; expected '${expected}'."
    exit 1
  fi
  if [[ "${current}" != "${expected}" ]]; then
    print_err "Non-canonical macOS path for ${var_name}: '${current}' (expected '${expected}')."
    print_info "Update ${CONFIG_FILE} to canonical macOS paths before continuing."
    exit 1
  fi
}

# macOS variant of enforce_host_storage_policy. Pins HOST_PROFILE,
# validates every canonical macOS runtime/state/log path is the
# reviewed value, ensures the Keychain account name is sanitized,
# checks WG_INTERFACE matches `utunN`, and rejects the legacy
# manual-peer-override break-glass. Guarded so a stray call on a
# non-macOS host is a no-op — non-macOS hosts dispatch elsewhere.
__rustynet_macos_enforce_host_storage_policy() {
  if ! is_macos_host; then
    return 0
  fi
  HOST_PROFILE="macos"
  require_macos_path_var_exact SOCKET_PATH "${MACOS_RUNTIME_BASE}/rustynetd.sock"
  require_macos_path_var_exact STATE_PATH "${MACOS_STATE_BASE}/rustynetd.state"
  require_macos_path_var_exact TRUST_EVIDENCE_PATH "${MACOS_STATE_BASE}/trust/rustynetd.trust"
  require_macos_path_var_exact TRUST_VERIFIER_KEY_PATH "${MACOS_STATE_BASE}/trust/trust-evidence.pub"
  require_macos_path_var_exact TRUST_WATERMARK_PATH "${MACOS_STATE_BASE}/trust/rustynetd.trust.watermark"
  require_macos_path_var_exact AUTO_TUNNEL_BUNDLE_PATH "${MACOS_STATE_BASE}/assignment/rustynetd.assignment"
  require_macos_path_var_exact AUTO_TUNNEL_VERIFIER_KEY_PATH "${MACOS_STATE_BASE}/assignment/assignment.pub"
  require_macos_path_var_exact AUTO_TUNNEL_WATERMARK_PATH "${MACOS_STATE_BASE}/assignment/rustynetd.assignment.watermark"
  require_macos_path_var_exact TRAVERSAL_BUNDLE_PATH "${MACOS_STATE_BASE}/traversal/rustynetd.traversal"
  require_macos_path_var_exact TRAVERSAL_VERIFIER_KEY_PATH "${MACOS_STATE_BASE}/traversal/traversal.pub"
  require_macos_path_var_exact TRAVERSAL_WATERMARK_PATH "${MACOS_STATE_BASE}/traversal/rustynetd.traversal.watermark"
  require_macos_path_var_exact WG_PRIVATE_KEY_PATH "${MACOS_STATE_BASE}/keys/wireguard.key"
  require_macos_path_var_exact WG_ENCRYPTED_PRIVATE_KEY_PATH "${MACOS_STATE_BASE}/keys/wireguard.key.enc"
  require_macos_path_var_exact WG_KEY_PASSPHRASE_PATH "${MACOS_STATE_BASE}/keys/wireguard.passphrase"
  require_macos_path_var_exact WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH "${MACOS_STATE_BASE}/keys/wg_key_passphrase.cred"
  require_macos_path_var_exact SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH "${MACOS_STATE_BASE}/keys/signing_key_passphrase.cred"
  require_macos_path_var_exact WG_PUBLIC_KEY_PATH "${MACOS_STATE_BASE}/keys/wireguard.pub"
  require_macos_path_var_exact PRIVILEGED_HELPER_SOCKET_PATH "${MACOS_RUNTIME_BASE}/rustynetd-privileged.sock"
  require_macos_path_var_exact MEMBERSHIP_SNAPSHOT_PATH "${MACOS_STATE_BASE}/membership/membership.snapshot"
  require_macos_path_var_exact MEMBERSHIP_LOG_PATH "${MACOS_STATE_BASE}/membership/membership.log"
  require_macos_path_var_exact MEMBERSHIP_WATERMARK_PATH "${MACOS_STATE_BASE}/membership/membership.watermark"
  require_macos_path_var_exact MEMBERSHIP_OWNER_SIGNING_KEY_PATH "${MACOS_STATE_BASE}/membership/membership.owner.key"
  require_macos_path_var_exact TRUST_SIGNER_KEY_PATH "${MACOS_STATE_BASE}/trust/trust-evidence.key"
  require_macos_path_var_exact MANUAL_PEER_AUDIT_LOG "${MACOS_LOG_BASE}/manual-peer-override.log"
  ensure_macos_keychain_passphrase_account

  if [[ ! "${WG_INTERFACE}" =~ ^utun[0-9]+$ ]]; then
    print_err "WG_INTERFACE '${WG_INTERFACE}' is invalid for macOS; expected pattern utunN."
    exit 1
  fi

  if [[ "${MANUAL_PEER_OVERRIDE}" != "0" ]]; then
    print_err "Manual peer break-glass override is no longer supported."
    print_info "Set MANUAL_PEER_OVERRIDE=0 in ${CONFIG_FILE}."
    exit 1
  fi
}
