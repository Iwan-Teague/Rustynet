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
usage: regression_coverage_gates.sh [--platform <linux|windows|all>] [--verbose]

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
  all|linux|windows) ;;
  *)
    echo "regression_coverage_gates: --platform must be linux|windows|all (got ${PLATFORM})" >&2
    exit 64
    ;;
esac

# Pinned floors. Each entry: <module>:<expected-min-passing>.
# Updating a floor is a deliberate act — commit message must say why.
LINUX_FLOORS=(
  "linux_runtime_acls:19"
  "linux_service_hardening:30"
  "linux_dns_failclosed:45"
  "linux_mesh_status:10"
  "linux_key_custody:15"
  "linux_authenticode:3"
)

# Note: `windows_runtime_acls` is not a standalone module — Windows
# ACL coverage lives inside `windows_service_hardening` + `windows_paths`.
# Keep the gate aligned with what's actually a top-level test module.
WINDOWS_FLOORS=(
  "windows_service_hardening:33"
  "windows_dns_failclosed:32"
  "windows_mesh_status:14"
  "windows_key_custody:18"
  "windows_authenticode:21"
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
