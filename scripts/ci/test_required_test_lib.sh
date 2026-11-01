#!/usr/bin/env bash
# Self-test for scripts/ci/lib/required_test.sh (the zero-match guard) and for the
# gates that depend on it. Hermetic: a fake `cargo` on PATH replays canned
# libtest output, so no compilation happens and no network or toolchain is needed.
#
# Proves both directions for every case:
#   - a run whose filter matched zero tests (cargo still exits 0) is REJECTED;
#   - a run with real passed tests is ACCEPTED;
#   - a failing cargo run is rejected, argv reaches cargo unmangled, and a
#     look-alike "test result" line printed by a test cannot satisfy the guard;
#   - each gate that sources the guard fails with "GATE DEFECT" when cargo
#     reports zero tests, and the shim-friendly ones pass when it reports tests.
#
# Usage: scripts/ci/test_required_test_lib.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
shim_dir="${work}/shim"
mkdir -p "$shim_dir"

# Fake cargo. FAKE_CARGO_MODE selects the canned output; every invocation also
# records its argv (one argument per line, NUL-free) to FAKE_CARGO_ARGV_LOG.
cat > "${shim_dir}/cargo" <<'SHIM'
#!/usr/bin/env bash
if [ -n "${FAKE_CARGO_ARGV_LOG:-}" ]; then
  { printf 'ARGV-START\n'; printf '%s\n' "$@"; } >> "$FAKE_CARGO_ARGV_LOG"
fi
case "${FAKE_CARGO_MODE:-pass}" in
  pass)
    printf 'running 2 tests\ntest a ... ok\ntest b ... ok\n\n'
    printf 'test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 0.00s\n'
    ;;
  zero)
    printf 'running 0 tests\n\n'
    printf 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s\n'
    ;;
  ignored_only)
    printf 'running 1 test\ntest a ... ignored\n\n'
    printf 'test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s\n'
    ;;
  mixed)
    printf 'running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.00s\n\n'
    printf 'running 3 tests\n\ntest result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n'
    ;;
  no_summary)
    printf 'error: no test target matches pattern\n'
    ;;
  spoof)
    # A test printing a look-alike summary under --nocapture (indented / mid-line)
    # while the real summary says zero passed.
    printf 'running 1 test\n  test result: ok. 9 passed; 0 failed\nnote: test result: ok. 9 passed; x\n'
    printf 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s\n'
    ;;
  fail)
    printf 'running 2 tests\ntest result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n'
    exit 101
    ;;
  *)
    echo "unknown FAKE_CARGO_MODE" >&2
    exit 2
    ;;
esac
SHIM
chmod 0755 "${shim_dir}/cargo"

failures=0
note_failure() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

export PATH="${shim_dir}:${PATH}"
export FAKE_CARGO_ARGV_LOG="${work}/argv.log"

# shellcheck source=lib/required_test.sh
source "${SCRIPT_DIR}/lib/required_test.sh"

# expect <accept|reject> <mode> <label> <run_required_test args...>
expect() {
  local want="$1" mode="$2" label="$3"
  shift 3
  local rc=0
  FAKE_CARGO_MODE="$mode" run_required_test "$@" >"${work}/out.txt" 2>"${work}/err.txt" || rc=$?
  if [ "$want" = accept ] && [ "$rc" -ne 0 ]; then
    note_failure "${label}: expected accept, got exit ${rc}"
  elif [ "$want" = reject ] && [ "$rc" -eq 0 ]; then
    note_failure "${label}: expected reject, got exit 0"
  else
    echo "ok: ${label} (${want})"
  fi
}

expect accept pass         "real passed tests"                -p rustynetd some_filter
expect accept mixed        "filter matches in one of two targets" -p rustynetd --lib some_filter
expect reject zero         "zero-match run (cargo exit 0)"    -p rustynetd no_such_test
expect reject ignored_only "only ignored tests (0 passed)"    -p rustynetd only_ignored
expect reject no_summary   "no libtest summary at all"        -p rustynetd weird
expect reject spoof        "look-alike summary printed by a test" -p rustynetd spoof
expect reject fail         "cargo exits non-zero"             -p rustynetd failing

# The zero-match rejection must say so on stderr (operators grep for GATE DEFECT).
FAKE_CARGO_MODE=zero run_required_test -p rustynetd no_such_test >/dev/null 2>"${work}/err.txt" || true
if ! grep -q 'GATE DEFECT: test filter matched zero tests' "${work}/err.txt"; then
  note_failure "zero-match rejection did not print the GATE DEFECT line"
fi

# argv-safety: arguments reach cargo as individual, unmangled arguments and are
# never re-parsed by a shell (the $(...) must not execute).
: > "${FAKE_CARGO_ARGV_LOG}"
canary="${work}/canary-created"
FAKE_CARGO_MODE=pass run_required_test -p 'a b' '*' "\$(touch ${canary})" ';touch x' >/dev/null
expected_argv="$(printf 'ARGV-START\ntest\n-p\na b\n*\n$(touch %s)\n;touch x\n' "$canary")"
if [ "$(cat "${FAKE_CARGO_ARGV_LOG}")" != "$expected_argv" ]; then
  note_failure "argv was altered on the way to cargo"
fi
if [ -e "$canary" ] || [ -e "${work}/x" ] || [ -e x ]; then
  note_failure "argument content was executed by a shell"
fi

# Gate-level proof: every gate that sources the guard must reject a zero-match
# cargo with GATE DEFECT. Gates whose remaining steps need only the shim
# (rg checks over the checked-in tree, cargo run/clippy no-ops) must also pass
# when cargo reports real tests. anchor_live_lab_gates additionally needs
# dry-run report files that a shim cannot produce, so it is reject-only here.
reject_only="anchor_live_lab_gates.sh"
# Gates whose STATIC pre-checks (rg over the checked-in tree) already fail before
# any cargo test runs, independent of this guard. Listed explicitly, never
# skipped silently: the self-test asserts each still fails for the recorded
# reason, so the day the pre-check is repaired this test fails and demands the
# entry be removed (re-enabling the full zero-match / real-test proof). The
# guard wiring is still checked statically for these.
#   anchor_secret_redaction_gates.sh: pattern 1 matches new test-fixture
#   literals in vm_lab/orchestrator/role_validation/anchor.rs (not emissions)
#   that the gate's single-file exemption does not cover.
precheck_blocked="anchor_secret_redaction_gates.sh"
cd "$REPO_ROOT"
for gate in $(grep -l 'lib/required_test.sh' scripts/ci/*.sh | sort); do
  name="$(basename "$gate")"
  case "$name" in
    test_required_test_lib.sh|gate_exit_code_gates.sh) continue ;;
  esac
  case " ${precheck_blocked} " in
    *" ${name} "*)
      if ! grep -q 'run_required_test' "$gate"; then
        note_failure "${name}: does not use run_required_test"
      fi
      rc=0
      FAKE_CARGO_MODE=pass bash "$gate" >"${work}/gate.out" 2>&1 || rc=$?
      if [ "$rc" -eq 0 ]; then
        note_failure "${name}: static pre-check no longer blocks it; remove it from precheck_blocked so the full proof runs"
      elif ! grep -q 'appears to expose token/secret context' "${work}/gate.out"; then
        note_failure "${name}: failed for a different reason than the recorded pre-check block: $(tail -3 "${work}/gate.out" | tr '\n' ' ')"
      else
        echo "NOTE: ${name} is blocked by its own static pre-check (pre-existing); zero-match guard wiring verified statically only"
      fi
      continue
      ;;
  esac
  rc=0
  FAKE_CARGO_MODE=zero bash "$gate" >"${work}/gate.out" 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then
    note_failure "${name}: passed with zero tests run (guard not effective)"
  elif ! grep -q 'GATE DEFECT: test filter matched zero tests' "${work}/gate.out"; then
    note_failure "${name}: failed for a reason other than the zero-match guard: $(tail -3 "${work}/gate.out" | tr '\n' ' ')"
  else
    echo "ok: ${name} rejects zero-match"
  fi
  case " ${reject_only} " in
    *" ${name} "*) continue ;;
  esac
  rc=0
  FAKE_CARGO_MODE=pass bash "$gate" >"${work}/gate.out" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    note_failure "${name}: failed with real tests reported: $(tail -3 "${work}/gate.out" | tr '\n' ' ')"
  else
    echo "ok: ${name} accepts real tests"
  fi
done

if [ "$failures" -ne 0 ]; then
  echo "test_required_test_lib: FAILED (${failures} failure(s))" >&2
  exit 1
fi
echo "test_required_test_lib: PASSED"
