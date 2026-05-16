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
      for fn in print_info print_warn print_err is_linux_host is_macos_host \
                path_in_linux_runtime_roots sanitize_macos_keychain_account; do
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

# ---- summary ---------------------------------------------------------------

if [[ ${failed} -eq 0 ]]; then
  printf '\nstart.sh modularization smoke: PASS\n'
  exit 0
fi
printf '\nstart.sh modularization smoke: FAIL (%d check(s))\n' "${failed}" >&2
exit 1
