#!/usr/bin/env bash
# test_pipefail_sigpipe_race_witness.sh — deterministic SIGPIPE-race witness
# for `set -o pipefail` scripts that consume a producer with `grep -q`.
#
# Race: `grep -q` exits at the first match and closes the pipe read end while
# the producer is still writing; the producer's next write raises SIGPIPE
# (exit 141), pipefail promotes that to the pipeline status, and a MATCH is
# read as NO-match. Two failure directions:
#   - match-required-to-pass sites go flaky-red
#     (seen live: "GATE DEFECT: test filter matched zero tests" in
#     scripts/ci/role_taxonomy_gates.sh run_required_test, 1 in 5 macOS runs);
#   - the mirrored `if producer | grep -q BAD; then fail; fi` reads BAD-present
#     as clean (FAIL-OPEN).
#
# Fixture: >1 MB of producer output with the match on the FIRST line, so the
# consumer always exits long before the producer drains (>> pipe buffer), which
# makes the race deterministic (validated 10/10 on macOS arm64, bash 5.x).
#
# Witnessed BY NAME: run_required_test() from scripts/ci/role_taxonomy_gates.sh
# and classify() from scripts/loop/opencode_loop.sh are extracted from the live
# files and run against stubs, so reverting the grep -q fix fails this witness.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATES_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd "$GATES_DIR/../.." && pwd)"

pass=0
fail=0
ok()  { pass=$((pass + 1)); echo "  ok: $*"; }
bad() { fail=$((fail + 1)); echo "  FAIL: $*"; }

# >1 MB fixture, match on the first line.
make_fixture() {
  { printf 'test result: ok. 3 passed; 0 failed; 0 ignored; 0 filtered\n'
    head -c 1048576 /dev/zero | tr '\0' 'x'
    printf '\n'; }
}
FIX="$(make_fixture)"
echo "fixture: ${#FIX} bytes, match on line 1"

echo "[1] OLD flaky pattern: printf ... | grep -Eq under pipefail (10 runs)"
old_misreads=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if printf '%s\n' "$FIX" | grep -Eq 'test result: ok'; then :; else
    old_misreads=$((old_misreads + 1))
  fi
done
if [ "$old_misreads" -eq 10 ]; then
  ok "old pattern misread a MATCH as no-match in 10/10 runs (reproduced deterministically)"
else
  bad "old pattern misread only $old_misreads/10 runs (expected 10/10)"
fi

echo "[2] FIXED variable form: grep -Eq PATTERN <<<\"\$var\""
if grep -Eq 'test result: ok' <<<"$FIX"; then
  ok "herestring form reads the match, rc=0, no producer to SIGPIPE"
else
  bad "herestring form failed to read the match"
fi

echo "[3] FIXED command form: producer | grep -E PATTERN >/dev/null (no -q)"
if printf '%s\n' "$FIX" | grep -E 'test result: ok' >/dev/null; then
  ok "no-q >/dev/null form drains the pipe, rc=0"
else
  bad "no-q >/dev/null form failed"
fi

echo "[4] OLD fail-open mirror: if producer | grep -qv '^exec '; then fail (5 runs)"
BADFIX="$({ printf 'set -euo pipefail filler\n'; head -c 1048576 /dev/zero | tr '\0' 'y'; printf '\n'; })"
old_passes_wrongly=0
for _ in 1 2 3 4 5; do
  if printf '%s\n' "$BADFIX" | grep -qv '^exec '; then :; else
    old_passes_wrongly=$((old_passes_wrongly + 1))
  fi
done
if [ "$old_passes_wrongly" -eq 5 ]; then
  ok "old fail-open mirror swallowed bad content in 5/5 runs (fail-open reproduced)"
else
  bad "old fail-open mirror swallowed only $old_passes_wrongly/5 runs (expected 5/5)"
fi

echo "[5] FIXED fail-open mirror: producer | grep -v '^exec ' >/dev/null"
if printf '%s\n' "$BADFIX" | grep -v '^exec ' >/dev/null; then
  ok "fixed mirror detects the bad content, rc=0"
else
  bad "fixed mirror failed to detect bad content"
fi

echo "[6] run_required_test from scripts/ci/role_taxonomy_gates.sh (by name)"
rt_fn="$(sed -n '/^run_required_test() {/,/^}/p' "$GATES_DIR/role_taxonomy_gates.sh")"
if [ -z "$rt_fn" ] || ! grep -q 'GATE DEFECT' <<<"$rt_fn"; then
  bad "could not extract run_required_test from role_taxonomy_gates.sh"
else
  eval "$rt_fn"
  cargo() { printf '%s\n' "$FIX"; }  # stub: match on line 1, >1 MB total
  if run_required_test --stub demo::tests::witness >/dev/null 2>&1; then
    ok "run_required_test passes a filtered run whose output exceeds the pipe buffer"
  else
    bad "run_required_test hit the SIGPIPE race and reported GATE DEFECT on a passing run"
  fi
fi

echo "[7] classify() from scripts/loop/opencode_loop.sh (by name)"
cl_fn="$(sed -n '/^classify() {/,/^}/p' "$REPO_DIR/scripts/loop/opencode_loop.sh")"
if [ -z "$cl_fn" ]; then
  bad "could not extract classify() from opencode_loop.sh"
else
  eval "$cl_fn"
  REPORT="$( { printf 'Overall status: **pass**\n'; head -c 1048576 /dev/zero | tr '\0' 'p'; printf '\n'; })"
  verdict="$(classify "$REPORT")"
  if [ "$verdict" = "pass" ]; then
    ok "classify() verdicts a >1 MB passing report as pass"
  else
    bad "classify() verdicted a passing report as '$verdict' (SIGPIPE ate the pass branch)"
  fi
fi

echo
echo "witness summary: pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
