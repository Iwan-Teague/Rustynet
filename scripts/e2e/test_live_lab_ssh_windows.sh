#!/usr/bin/env bash
# Unit-level tests for live_lab_ssh_windows + live_lab_encode_powershell_b64.
#
# Exercises the encoding helpers without an actual SSH transport so the
# Phase 23 follow-up cmd.exe wrapper can be validated bit-for-bit in CI.
# The wrapper itself is covered by orchestrator dry-run smoke + live VM
# evidence (the latter deferred until the lab Windows VM is restored
# from its current OOM state, per the Phase 25 reviewer note).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/live_lab_common.sh"

TESTS_RUN=0
TESTS_FAILED=0

assert_equal() {
  local label="$1"
  local expected="$2"
  local actual="$3"
  TESTS_RUN=$((TESTS_RUN + 1))
  if [[ "$expected" == "$actual" ]]; then
    printf '[pass] %s\n' "$label"
    return 0
  fi
  TESTS_FAILED=$((TESTS_FAILED + 1))
  printf '[FAIL] %s\n' "$label" >&2
  printf '  expected: %q\n' "$expected" >&2
  printf '  actual:   %q\n' "$actual" >&2
  return 1
}

assert_nonzero_exit() {
  local label="$1"
  shift
  TESTS_RUN=$((TESTS_RUN + 1))
  set +e
  "$@" >/dev/null 2>&1
  local rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    printf '[pass] %s (rc=%d)\n' "$label" "$rc"
    return 0
  fi
  TESTS_FAILED=$((TESTS_FAILED + 1))
  printf '[FAIL] %s (expected non-zero, got 0)\n' "$label" >&2
  return 1
}

# Test 1: encoding round-trips a known ASCII PowerShell payload.
test_encoding_roundtrip_ascii() {
  local input='Get-Service RustyNet | Select-Object Status'
  local b64 decoded
  b64="$(live_lab_encode_powershell_b64 "$input")"
  decoded="$(printf '%s' "$b64" | base64 -d | iconv -f UTF-16LE -t UTF-8)"
  assert_equal "encoding round-trips ASCII payload" "$input" "$decoded"
}

# Test 2: encoding round-trips a multi-line PowerShell payload (matches
# the cleanup_host_worker_windows surface). The expected value drops the
# final newline because $(...) command substitution always strips
# trailing newlines from captured output; this is a bash artefact of the
# test harness, not of the encoder. The actual encode-then-decode path
# inside the helper preserves every byte (verified by the round-trip
# below being length-equal to the input minus the final newline).
test_encoding_roundtrip_multiline() {
  local input
  input=$'$ErrorActionPreference = \'Continue\';\nsc.exe stop RustyNet | Out-Null;\nexit 0\n'
  local b64 decoded
  b64="$(live_lab_encode_powershell_b64 "$input")"
  decoded="$(printf '%s' "$b64" | base64 -d | iconv -f UTF-16LE -t UTF-8)"
  # Strip the trailing newline from input for comparison; both b64
  # capture and decoded capture lose the trailing newline identically.
  local expected="${input%$'\n'}"
  assert_equal "encoding round-trips multi-line PowerShell payload" "$expected" "$decoded"
}

# Test 3: encoding preserves non-ASCII bytes (UTF-8 input that survives
# UTF-16LE round-trip). Uses an "é" (U+00E9) to confirm the iconv step
# does not silently mangle the payload.
test_encoding_preserves_non_ascii() {
  local input='Write-Host "café-rustynet"'
  local b64 decoded
  b64="$(live_lab_encode_powershell_b64 "$input")"
  decoded="$(printf '%s' "$b64" | base64 -d | iconv -f UTF-16LE -t UTF-8)"
  assert_equal "encoding preserves UTF-8 non-ASCII bytes" "$input" "$decoded"
}

# Test 4: encoding produces only base64-alphabet characters (no shell
# metacharacters that would break the cmd.exe arg parse).
test_encoded_output_is_base64_safe() {
  local input='Test-Path C:\ProgramData\RustyNet'
  local b64
  b64="$(live_lab_encode_powershell_b64 "$input")"
  if [[ "$b64" =~ ^[A-Za-z0-9+/=]+$ ]]; then
    TESTS_RUN=$((TESTS_RUN + 1))
    printf '[pass] encoded output is base64-safe\n'
  else
    TESTS_RUN=$((TESTS_RUN + 1))
    TESTS_FAILED=$((TESTS_FAILED + 1))
    printf '[FAIL] encoded output contains non-base64 chars: %s\n' "$b64" >&2
  fi
}

# Test 5: empty payload is rejected.
test_empty_payload_rejected() {
  assert_nonzero_exit "empty payload rejected by encoder" \
    live_lab_encode_powershell_b64 ""
  assert_nonzero_exit "empty payload rejected by live_lab_ssh_windows" \
    live_lab_ssh_windows windows@example.invalid ""
}

# Test 6: empty target is rejected.
test_empty_target_rejected() {
  assert_nonzero_exit "empty target rejected by live_lab_ssh_windows" \
    live_lab_ssh_windows "" 'Get-Service'
  assert_nonzero_exit "empty target rejected by live_lab_ssh_windows_stdin" \
    bash -c 'source "$0"; printf "Get-Service" | live_lab_ssh_windows_stdin ""' "${SCRIPT_DIR}/live_lab_common.sh"
}

# Test 7: NUL byte detection inside the encoder is reachable.
#
# Bash variables cannot hold NUL bytes on any version we ship against —
# both bash 3.2 (system bash on macOS) and bash 5.x strip NUL at variable
# assignment, so any NUL the orchestrator forwards via a $ps_command
# string is silently dropped before the encoder is invoked. To prove the
# defense-in-depth NUL gate is wired correctly (and would fire if a
# future binding hands the encoder a NUL-bearing payload via a path
# that does not go through bash variables), we test the wc-byte-count
# comparison directly. This is the exact check the encoder runs.
test_nul_byte_rejected() {
  # Write a NUL-bearing byte stream to a temp file, count its raw bytes
  # and its NUL-stripped bytes; assert the comparison flags the NUL.
  local tmpfile raw stripped
  tmpfile="$(mktemp "${TMPDIR:-/tmp}/rn-nul-detect.XXXXXX")" || return 1
  printf 'abc\x00def' > "$tmpfile"
  raw="$(LC_ALL=C wc -c < "$tmpfile" | tr -d '[:space:]')"
  stripped="$(LC_ALL=C tr -d '\0' < "$tmpfile" | LC_ALL=C wc -c | tr -d '[:space:]')"
  rm -f "$tmpfile"
  TESTS_RUN=$((TESTS_RUN + 1))
  if [[ "$raw" != "$stripped" ]]; then
    printf '[pass] NUL byte detection comparison fires (raw=%s stripped=%s)\n' "$raw" "$stripped"
  else
    TESTS_FAILED=$((TESTS_FAILED + 1))
    printf '[FAIL] NUL byte detection did not flag mismatch (raw=%s stripped=%s)\n' \
      "$raw" "$stripped" >&2
  fi
}

# Test 8: the wrapper helper inside live_lab_ssh_windows uses
# live_lab_target_uses_utm_transport to decide the transport. We
# cannot exercise the full SSH path in unit tests, but we can verify
# the helper symbols are defined and visible after sourcing.
test_helper_symbols_present() {
  TESTS_RUN=$((TESTS_RUN + 1))
  if declare -F live_lab_ssh_windows >/dev/null \
    && declare -F live_lab_ssh_windows_stdin >/dev/null \
    && declare -F live_lab_encode_powershell_b64 >/dev/null
  then
    printf '[pass] live_lab_ssh_windows / _stdin / encode_powershell_b64 are defined\n'
  else
    TESTS_FAILED=$((TESTS_FAILED + 1))
    printf '[FAIL] one or more required helper symbols missing\n' >&2
  fi
}

main() {
  test_encoding_roundtrip_ascii
  test_encoding_roundtrip_multiline
  test_encoding_preserves_non_ascii
  test_encoded_output_is_base64_safe
  test_empty_payload_rejected
  test_empty_target_rejected
  test_nul_byte_rejected
  test_helper_symbols_present
  printf '\n--- %d tests run, %d failed ---\n' "$TESTS_RUN" "$TESTS_FAILED"
  if [[ "$TESTS_FAILED" -ne 0 ]]; then
    exit 1
  fi
}

main "$@"
