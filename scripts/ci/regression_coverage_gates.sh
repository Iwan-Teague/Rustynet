#!/usr/bin/env bash
# X7. Per-platform regression-coverage gate.
#
# For each reviewed verifier module under crates/rustynetd, runs the
# matching `cargo test` filter and asserts the passing-test count is
# at least the pinned floor. Catches the silent-regression shape
# where a refactor removes whole groups of drift tests but the green
# build still claims "all tests pass".
#
# The floors are intentionally generous — they pin against silent
# *removal* of test groups, not against deliberate consolidation. To
# raise a floor, run the test, observe the new count, and update the
# corresponding `EXPECTED_*` value in this script with a paired
# commit message explaining the bump.
#
# Exit code: 0 = all floors met; 1 = any floor breached or any test
# failed; 64 = bad-args.

set -euo pipefail

usage() {
  cat <<'USAGE'
usage: regression_coverage_gates.sh [--platform <linux|macos|windows|all>] [--verbose]

Options:
  --platform   Restrict checks to one platform group. Default: all.
  --verbose    Echo the cargo invocations and per-module counts.
  -h, --help   This message.
USAGE
}

PLATFORM="all"
VERBOSE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --platform)
      PLATFORM="${2:-}"
      shift 2
      ;;
    --verbose)
      VERBOSE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "regression_coverage_gates: unknown arg $1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

case "${PLATFORM}" in
  all|linux|macos|windows) ;;
  *)
    echo "regression_coverage_gates: --platform must be linux|macos|windows|all (got ${PLATFORM})" >&2
    exit 64
    ;;
esac

# Pinned floors. Each entry: <module>:<expected-min-passing>.
# Updating a floor is a deliberate act — commit message must say why.
LINUX_FLOORS=(
  # Floor bumped 19→27 on X4 coverage parity sweep: 8 new tests
  # covering the reviewed-roots-list snapshot, schema_version pin,
  # Missing-variant serde round-trip, unknown-tag rejection, high
  # mode-bit masking, symlink-before-dir-check ordering, symlink +
  # mode drift first-fault precedence, and the vacuous-truth
  # documented behavior for empty-roots.
  "linux_runtime_acls:27"
  # Floor bumped 30→33 on L8 wire-up: 3 new pins on the reviewed
  # rustynetd.service unit (ExecStartPre killswitch-boot-check,
  # LoadCredentialEncrypted lines, MemoryDenyWriteExecute=true).
  "linux_service_hardening:33"
  "linux_dns_failclosed:45"
  # Floor bumped 10→24 on X4 coverage expansion: 14 new tests
  # covering freshness boundary, missing-peer aggregation, exotic
  # peer-id chars, schema_version pin, per-variant serde round-trip.
  "linux_mesh_status:24"
  # Floor bumped 15→24 on X4 coverage parity sweep: 9 new tests
  # covering schema_version pin, per-variant serde round-trip on
  # Ok/Invalid/Forbidden, unknown-status-tag rejection, unknown-
  # requirement-string rejection, multi-entry drift aggregation
  # (no short-circuit), Forbidden status on required entry, and
  # AbsentAsExpected status on required entry (collector-bug
  # contradiction).
  "linux_key_custody:24"
  # Floor bumped 3→22 on X4 coverage parity sweep: 19 new tests
  # covering applicability/reason invariants, schema pin,
  # determinism, serde round-trip + value-level round trip, drift
  # mutation detection across each field, and a canonical
  # serialized snapshot pin.
  "linux_authenticode:22"
  # New module from L8: 21 tests pinning the boot-time killswitch
  # invariant (evaluator + nft-ruleset parser + off-Linux blocker).
  "linux_killswitch_boot:21"
)

# macOS coverage floors. macOS is a control-plane platform today, not
# a production dataplane host — the verifier surface is thinner than
# Linux / Windows. These floors lock the current baseline so a refactor
# that silently drops drift tests trips the gate. Future expansion of
# any single module follows the same X4 coverage-parity pattern: add
# named drift tests, bump the floor in the same commit.
MACOS_FLOORS=(
  # Floor bumped 8→16 on X4 coverage parity sweep: 8 new tests
  # covering reviewed-roots-list snapshot, schema_version pin,
  # per-variant serde round-trip on Drifted + Missing, unknown-
  # status-tag rejection, symlink-before-dir-check ordering,
  # symlink + mode-drift first-fault precedence, and the
  # vacuous-truth documented behavior for empty-roots.
  "macos_runtime_acls:16"
  "macos_service_hardening:9"
  # Floor bumped 8→16 on X4 coverage parity sweep: 8 new tests
  # covering schema_version pin, IPv4 link-local (cloud metadata)
  # rejection, IPv6 link-local rejection, IPv4-mapped IPv6 external
  # rejection, full 127.0.0.0/8 loopback range acceptance,
  # multi-directive search/domain parser ordering, bare-nameserver
  # parser tolerance, and no-dedup-across-nameservers in the
  # aggregated drift_reasons output.
  "macos_dns_failclosed:16"
  # Floor bumped 3→9 on X4 coverage parity sweep: 6 new tests
  # covering schema_version pin, default-state-path fallback,
  # custom state-path echo through the report, and per-variant
  # serde round-trip on Ok + IntegrityMismatch + InvalidFormat.
  "macos_mesh_status:9"
  # Floor bumped 2→11 on X4 coverage parity sweep: 8 new tests
  # covering schema_version pin, reviewed-entry-paths canonical
  # snapshot (off-macOS), per-variant serde round-trip on Missing/
  # Invalid/Forbidden/AbsentAsExpected, unknown-status-tag
  # rejection, and the overall_ok={Ok|AbsentAsExpected only}
  # contract from both sides.
  "macos_key_custody:11"
  # Floor bumped 2→7 on X4 stub-coverage sweep: 5 new tests pinning
  # schema_version, the applicable=false posture (must flip if a
  # future codesign --verify probe lands), the reason-text shape
  # (Authenticode / Gatekeeper / launch-time mentions), deterministic
  # output across calls (no hidden state), and the current
  # unknown-fields-tolerated serde behavior.
  "macos_authenticode:7"
)

# Note: `windows_runtime_acls` is not a standalone module — Windows
# ACL coverage lives inside `windows_service_hardening` + `windows_paths`.
# Keep the gate aligned with what's actually a top-level test module.
WINDOWS_FLOORS=(
  "windows_service_hardening:33"
  # Floor bumped 56→67 on W3 RA suppression evaluator: 11 new
  # tests pinning router-advertisement / IPv6-default-route
  # observation contract.
  "windows_dns_failclosed:67"
  # Floor bumped 14→23 on X4 coverage parity sweep: 9 new tests
  # covering schema_version pin, per-variant serde round-trip on
  # IntegrityMismatch + InvalidFormat, unknown-load_status-tag
  # rejection, freshness boundary (age==max accepts, age=max+1
  # rejects with both numbers in reason), no-expectations vacuous
  # truth, no-dedup on duplicate expected_peer_ids, and confirmation
  # that lan_access_enabled + selected_exit_node fields don't gate
  # the drift verdict today.
  "windows_mesh_status:23"
  # Floor bumped 18→24 on X4 coverage parity sweep: 6 new tests
  # covering schema_version pin, per-variant serde round-trip on
  # Missing + Invalid + AbsentAsExpected, unknown-status-tag
  # rejection, and the no-dedup-across-entries contract for
  # repeated-shape drift reasons.
  "windows_key_custody:24"
  "windows_authenticode:38"
  # New module from W4: 17 tests pinning the registry-key ACL
  # drift evaluator (forbidden principals, requirement
  # invariants, SDDL grant detection, snapshot lists).
  "windows_registry_acls:17"
  # New floor from X4: SDDL grant/deny matcher + runtime-path
  # validator coverage parity sweep. 46 baseline tests + 15 new
  # named drift tests = 61 total pinned.
  "windows_paths:61"
)

run_module() {
  local module="$1"
  local floor="$2"
  local log
  log="$(mktemp)"
  if [[ ${VERBOSE} -eq 1 ]]; then
    echo "  -> cargo test --package rustynetd --lib ${module} (floor=${floor})"
  fi
  if ! cargo test --package rustynetd --lib --quiet "${module}::" >"${log}" 2>&1; then
    echo "regression_coverage_gates: cargo test failed for module=${module}" >&2
    tail -50 "${log}" >&2
    rm -f "${log}"
    return 1
  fi
  # `cargo test --quiet` summary line: "test result: ok. N passed; …"
  local passed
  passed="$(grep -E '^test result:' "${log}" \
    | awk '{print $4}' \
    | head -n1)"
  rm -f "${log}"
  if [[ -z "${passed}" ]]; then
    echo "regression_coverage_gates: could not parse pass count for module=${module}" >&2
    return 1
  fi
  if (( passed < floor )); then
    echo "regression_coverage_gates: FAIL module=${module} passed=${passed} floor=${floor}" >&2
    return 1
  fi
  if [[ ${VERBOSE} -eq 1 ]]; then
    echo "     OK module=${module} passed=${passed} floor=${floor}"
  fi
  return 0
}

run_group() {
  local label="$1"
  shift
  local -a floors=("$@")
  local failures=0
  echo "regression_coverage_gates: group=${label} modules=${#floors[@]}"
  for entry in "${floors[@]}"; do
    local module="${entry%%:*}"
    local floor="${entry##*:}"
    if ! run_module "${module}" "${floor}"; then
      failures=$((failures + 1))
    fi
  done
  return ${failures}
}

OVERALL=0

if [[ "${PLATFORM}" == "linux" || "${PLATFORM}" == "all" ]]; then
  if ! run_group "linux" "${LINUX_FLOORS[@]}"; then
    OVERALL=1
  fi
fi

if [[ "${PLATFORM}" == "macos" || "${PLATFORM}" == "all" ]]; then
  if ! run_group "macos" "${MACOS_FLOORS[@]}"; then
    OVERALL=1
  fi
fi

if [[ "${PLATFORM}" == "windows" || "${PLATFORM}" == "all" ]]; then
  if ! run_group "windows" "${WINDOWS_FLOORS[@]}"; then
    OVERALL=1
  fi
fi

if [[ ${OVERALL} -eq 0 ]]; then
  echo "regression_coverage_gates: PASS — all floors met"
else
  echo "regression_coverage_gates: FAIL — see per-module rows above" >&2
fi

exit ${OVERALL}
