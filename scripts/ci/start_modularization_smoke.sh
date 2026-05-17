#!/usr/bin/env bash
# L1 — start.sh modularization smoke test.
#
# Verifies that:
#   1. start.sh and each module under scripts/start/ are syntactically
#      valid bash (`bash -n`).
#   2. Sourcing common.sh + linux.sh + macos.sh succeeds and the
#      reviewed public functions are defined.
#   3. The reviewed common-layer helpers return the expected results
#      for the test inputs we pin here.
#
# Run via `./scripts/ci/start_modularization_smoke.sh`. Exit codes
# follow the X6 taxonomy: 0 success, 1 generic failure, 70 transient
# (none expected here).

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

failed=0
note() { printf '  %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; failed=$((failed + 1)); }
pass() { printf '[ ok ] %s\n' "$*"; }

# ---- 1. syntax checks -------------------------------------------------------

for f in start.sh scripts/start/common.sh scripts/start/linux.sh scripts/start/macos.sh; do
  if [[ ! -f "${f}" ]]; then
    fail "missing required file: ${f}"
    continue
  fi
  if bash -n "${f}"; then
    pass "bash -n ${f}"
  else
    fail "bash -n ${f}"
  fi
done

# ---- 2. module sourcing under both HOST_OS values --------------------------

for host_os in Linux Darwin; do
  out=$(
    HOST_OS="${host_os}" ROOT_DIR="${ROOT_DIR}" \
    bash -c '
      set -euo pipefail
      ROOT_DIR="'"${ROOT_DIR}"'"
      HOST_OS="'"${host_os}"'"
      . "${ROOT_DIR}/scripts/start/common.sh"
      . "${ROOT_DIR}/scripts/start/linux.sh"
      . "${ROOT_DIR}/scripts/start/macos.sh"
      # Module-sourcing check: ensure both function names are defined
      # after sourcing common+linux+macos (so callers that depend on
      # the legacy names still find them).
      for fn in print_info print_warn print_err is_linux_host is_macos_host \
                path_in_linux_runtime_roots sanitize_macos_keychain_account \
                ensure_macos_keychain_passphrase_account \
                macos_keychain_passphrase_exists; do
        if ! declare -F "${fn}" >/dev/null; then
          echo "MISSING_FUNCTION:${fn}"
          exit 1
        fi
      done
      echo OK
    ' 2>&1
  ) || { fail "module-sourcing under HOST_OS=${host_os}: ${out}"; continue; }
  if grep -q "^OK$" <<<"${out}"; then
    pass "module-sourcing under HOST_OS=${host_os}"
  else
    fail "module-sourcing under HOST_OS=${host_os}: ${out}"
  fi
done

# ---- 3. behaviour pin checks -----------------------------------------------

# path_in_linux_runtime_roots
check_path_classifier() {
  local input="$1"
  local expected="$2"   # "in" or "out"
  local out
  out=$(
    HOST_OS=Linux ROOT_DIR="${ROOT_DIR}" \
    bash -c '
      . "'"${ROOT_DIR}"'/scripts/start/common.sh"
      if path_in_linux_runtime_roots "'"${input}"'"; then
        echo "in"
      else
        echo "out"
      fi
    '
  )
  if [[ "${out}" == "${expected}" ]]; then
    pass "path_in_linux_runtime_roots ${input} -> ${expected}"
  else
    fail "path_in_linux_runtime_roots ${input} expected=${expected} got=${out}"
  fi
}

check_path_classifier "/etc/rustynet" in
check_path_classifier "/etc/rustynet/foo" in
check_path_classifier "/var/lib/rustynet/x" in
check_path_classifier "/run/rustynet/foo" in
check_path_classifier "/var/log/rustynet/y" in
check_path_classifier "/tmp/x" out
check_path_classifier "/etc/rustynet-other/foo" out
check_path_classifier "" out

# sanitize_macos_keychain_account
check_sanitiser() {
  local input="$1"
  local expected="$2"
  local out
  out=$(
    HOST_OS=Darwin ROOT_DIR="${ROOT_DIR}" \
    bash -c '
      . "'"${ROOT_DIR}"'/scripts/start/common.sh"
      sanitize_macos_keychain_account "'"${input}"'"
    '
  )
  if [[ "${out}" == "${expected}" ]]; then
    pass "sanitize_macos_keychain_account ${input} -> ${expected}"
  else
    fail "sanitize_macos_keychain_account ${input} expected=${expected} got=${out}"
  fi
}

check_sanitiser "clean-account" "clean-account"
check_sanitiser "with spaces" "with-spaces"
check_sanitiser "with@special!chars" "with-special-chars"
check_sanitiser "-leading-and-trailing-" "leading-and-trailing"
check_sanitiser "@@@" "-"  # pre-existing single-strip semantics; degenerate case
check_sanitiser "" "rustynet-passphrase"

# ---- 4. apply_host_profile_defaults per-platform dispatch -------------------
#
# Pin that:
#   * the Linux variant threads LINUX_* credential paths through to the
#     canonical runtime vars and sets HOST_PROFILE=linux
#   * the macOS variant pins canonical macOS paths and WG_INTERFACE=utun9
#     and sets HOST_PROFILE=macos
#   * any other HOST_OS lands on HOST_PROFILE=unsupported
#
# The fixture sources common+linux+macos modules, seeds the LINUX_* /
# MACOS_* constants that normally live at top-level in start.sh, defines
# a dispatcher matching start.sh's, and asserts on the resulting state.

run_profile_fixture() {
  local host_os="$1"
  HOST_OS="${host_os}" ROOT_DIR="${ROOT_DIR}" \
  bash -c '
    set -euo pipefail
    ROOT_DIR="'"${ROOT_DIR}"'"
    HOST_OS="'"${host_os}"'"
    . "${ROOT_DIR}/scripts/start/common.sh"
    . "${ROOT_DIR}/scripts/start/linux.sh"
    . "${ROOT_DIR}/scripts/start/macos.sh"

    # Seed constants that normally live near the top of start.sh. Pinned
    # values here must stay in sync with the real defaults.
    LINUX_WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH="/etc/rustynet/credentials/wg_key_passphrase.cred"
    LINUX_SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH="/etc/rustynet/credentials/signing_key_passphrase.cred"
    MACOS_STATE_BASE="${HOME}/Library/Application Support/rustynet"
    MACOS_RUNTIME_BASE="${HOME}/Library/Caches/rustynet"
    MACOS_LOG_BASE="${HOME}/Library/Logs/rustynet"
    DEVICE_NODE_ID="smoke-node"

    HOST_PROFILE=""
    WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH=""
    SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH=""
    WG_INTERFACE=""

    apply_host_profile_defaults() {
      if is_linux_host; then
        __rustynet_linux_apply_profile_defaults
        return
      fi
      if is_macos_host; then
        __rustynet_macos_apply_profile_defaults
        return
      fi
      HOST_PROFILE="unsupported"
    }

    apply_host_profile_defaults
    printf "HOST_PROFILE=%s\n" "${HOST_PROFILE}"
    printf "WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH=%s\n" "${WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}"
    printf "SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH=%s\n" "${SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH}"
    printf "WG_INTERFACE=%s\n" "${WG_INTERFACE}"
  '
}

check_profile_field() {
  local label="$1"
  local fixture_output="$2"
  local field="$3"
  local expected="$4"
  local got
  got=$(grep -E "^${field}=" <<<"${fixture_output}" | head -n1 | cut -d= -f2-)
  if [[ "${got}" == "${expected}" ]]; then
    pass "${label}: ${field}=${expected}"
  else
    fail "${label}: ${field} expected='${expected}' got='${got}'"
  fi
}

# Linux fixture
if linux_out=$(run_profile_fixture Linux 2>&1); then
  check_profile_field "apply_host_profile_defaults(Linux)" "${linux_out}" \
    HOST_PROFILE "linux"
  check_profile_field "apply_host_profile_defaults(Linux)" "${linux_out}" \
    WG_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH \
    "/etc/rustynet/credentials/wg_key_passphrase.cred"
  check_profile_field "apply_host_profile_defaults(Linux)" "${linux_out}" \
    SIGNING_KEY_PASSPHRASE_CREDENTIAL_BLOB_PATH \
    "/etc/rustynet/credentials/signing_key_passphrase.cred"
else
  fail "apply_host_profile_defaults(Linux) fixture failed: ${linux_out}"
fi

# Darwin fixture
if darwin_out=$(run_profile_fixture Darwin 2>&1); then
  check_profile_field "apply_host_profile_defaults(Darwin)" "${darwin_out}" \
    HOST_PROFILE "macos"
  check_profile_field "apply_host_profile_defaults(Darwin)" "${darwin_out}" \
    WG_INTERFACE "utun9"
else
  fail "apply_host_profile_defaults(Darwin) fixture failed: ${darwin_out}"
fi

# FreeBSD (any non-Linux non-Darwin) fixture
if freebsd_out=$(run_profile_fixture FreeBSD 2>&1); then
  check_profile_field "apply_host_profile_defaults(FreeBSD)" "${freebsd_out}" \
    HOST_PROFILE "unsupported"
else
  fail "apply_host_profile_defaults(FreeBSD) fixture failed: ${freebsd_out}"
fi

# ---- summary ---------------------------------------------------------------

if [[ ${failed} -eq 0 ]]; then
  printf '\nstart.sh modularization smoke: PASS\n'
  exit 0
fi
printf '\nstart.sh modularization smoke: FAIL (%d check(s))\n' "${failed}" >&2
exit 1
