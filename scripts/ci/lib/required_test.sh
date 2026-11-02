# shellcheck shell=bash
# Shared zero-match guard for scripts/ci gates. SOURCE this file; do not execute it.
#
# WHY: `cargo test <filter>` exits 0 when <filter> matches no test at all
# ("running 0 tests", "test result: ok. 0 passed"). A gate that only checks
# cargo's exit status therefore reports success having proven nothing the
# moment a test is renamed, deleted, moved behind a cfg or a default-off
# feature, or the filter is mistyped. Fail-closed rule (CLAUDE.md section 3):
# a gate that ran zero tests is a gate defect, never a pass.
#
# USAGE (from a script that lives in scripts/ci/):
#
#   # shellcheck source=lib/required_test.sh
#   source "$(dirname "${BASH_SOURCE[0]}")/lib/required_test.sh"
#   run_required_test -p rustynetd --lib some_module::tests::some_test -- --nocapture
#
# run_required_test forwards its argv to `cargo test` verbatim (argv-only: no
# eval, no string-built command line, so a filter containing spaces or shell
# metacharacters is passed as ONE argument). It prints cargo's output and
# returns non-zero when cargo itself fails OR when the passed-test total, summed
# over every "test result: ok. N passed;" summary line cargo printed (one per
# test target), is below 1. Several targets may run for one invocation; the
# filter only has to match in at least one of them, but it must match.
#
# scripts/ci/test_required_test_lib.sh is the self-test that proves both
# directions (a zero-match run fails, a real run passes).

# Reads cargo-test output on stdin; prints the total number of passed tests.
# Only line-anchored libtest summary lines count: a test printing a look-alike
# string under --nocapture is normally indented or mid-line and is ignored.
required_test_count_passed() {
  awk '/^test result: ok\. [0-9]+ passed;/ { total += $4 } END { print total + 0 }'
}

# required_test_assert_ran <captured-cargo-output> <cargo test args...>
# Returns 1 (and says so on stderr) when the output shows zero passed tests.
required_test_assert_ran() {
  local out="$1"
  shift
  local passed
  passed="$(required_test_count_passed <<<"$out")"
  if [ "$passed" -lt 1 ]; then
    echo "GATE DEFECT: test filter matched zero tests (passed=0), so nothing was proven: cargo test $*" >&2
    return 1
  fi
}

# run_required_test <cargo test args...>
run_required_test() {
  local out
  # Capture first and check cargo's OWN exit status (never pipe a gate into a
  # filter: the pipeline would report the filter's status, QH-16).
  out="$(cargo test "$@" 2>&1)" || {
    printf '%s\n' "$out"
    return 1
  }
  printf '%s\n' "$out"
  required_test_assert_ran "$out" "$@"
}
