#!/usr/bin/env bash
# Self-test for scripts/ci/windows_cross_compile_gate.sh: the gate must never
# report PASS (or exit 0) when it compiled zero crates.
#
# Hermetic: fake `rustup`, `cargo` and mingw linker binaries are placed on a
# sanitized PATH (only the handful of coreutils the gate needs are symlinked in,
# so a real mingw/rustup installed on the host cannot leak into a case).
#
# Cases (expected exit):
#   no rustup cargo                          -> 65  (nothing checked)
#   rustup present, no Windows target        -> 65
#   Windows gnu target but no mingw linker   -> 65  (the leg is skipped; zero legs ran)
#   Windows gnu target + linker, cargo ok    -> 0   (PASS names crate/leg counts)
#   Windows gnu target + linker, cargo fails -> 1   (compile regression)
#
# Usage: scripts/ci/test_windows_cross_compile_gate.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# WINDOWS_GATE_UNDER_TEST lets a reviewer point the same cases at another copy of
# the gate (e.g. the pre-fix version) to see them fail.
GATE="${WINDOWS_GATE_UNDER_TEST:-${SCRIPT_DIR}/windows_cross_compile_gate.sh}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tools="${work}/tools"
linker_dir="${work}/linker"
fake_home="${work}/home"
mkdir -p "$tools" "$linker_dir" "$fake_home"

# Only the external commands the gate needs; resolved from the host PATH now.
for tool in bash dirname grep cat head tail tr sed rm mktemp env; do
  src="$(command -v "$tool")"
  ln -s "$src" "${tools}/${tool}"
done

cat > "${tools}/rustup" <<'SHIM'
#!/usr/bin/env bash
# FAKE_RUSTUP_MODE: none | no_targets | gnu
case "$1" in
  which)
    if [ "${FAKE_RUSTUP_MODE:-none}" = none ]; then exit 1; fi
    printf '%s\n' "${FAKE_CARGO_PATH}"
    ;;
  target)
    case "${FAKE_RUSTUP_MODE:-none}" in
      none) exit 1 ;;
      no_targets) printf 'x86_64-unknown-linux-gnu\n' ;;
      gnu) printf 'x86_64-unknown-linux-gnu\nx86_64-pc-windows-gnu\n' ;;
    esac
    ;;
  *) exit 2 ;;
esac
SHIM
cat > "${tools}/cargo" <<'SHIM'
#!/usr/bin/env bash
if [ "${FAKE_CARGO_FAIL:-0}" = 1 ]; then
  echo "error: could not compile (fake)" >&2
  exit 101
fi
exit 0
SHIM
printf '#!/usr/bin/env bash\nexit 0\n' > "${linker_dir}/x86_64-w64-mingw32-gcc"
chmod 0755 "${tools}/rustup" "${tools}/cargo" "${linker_dir}/x86_64-w64-mingw32-gcc"

failures=0
note_failure() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

# run_case <label> <want_exit> <rustup_mode> <with_linker 0|1> <cargo_fail 0|1> [must-contain]
run_case() {
  local label="$1" want="$2" mode="$3" with_linker="$4" cargo_fail="$5" needle="${6:-}"
  local path_value="$tools"
  if [ "$with_linker" = 1 ]; then
    path_value="${tools}:${linker_dir}"
  fi
  local rc=0
  # Fresh HOME: the gate probes "$HOME/.rustup/toolchains/..." first.
  env -i PATH="$path_value" HOME="$fake_home" \
    FAKE_RUSTUP_MODE="$mode" FAKE_CARGO_PATH="${tools}/cargo" FAKE_CARGO_FAIL="$cargo_fail" \
    "${tools}/bash" "$GATE" >"${work}/out.txt" 2>&1 || rc=$?
  if [ "$rc" -ne "$want" ]; then
    note_failure "${label}: expected exit ${want}, got ${rc}: $(tail -3 "${work}/out.txt" | tr '\n' ' ')"
    return
  fi
  if [ "$want" -eq 0 ] && grep -q '^SKIP' "${work}/out.txt" && ! grep -q '^PASS:' "${work}/out.txt"; then
    note_failure "${label}: exit 0 without a PASS line"
    return
  fi
  if [ -n "$needle" ] && ! grep -q -- "$needle" "${work}/out.txt"; then
    note_failure "${label}: output lacks expected text '${needle}'"
    return
  fi
  echo "ok: ${label} (exit ${rc})"
}

run_case "no rustup cargo is a failure, not a skip"       65 none       0 0 "checked ZERO crates"
run_case "no installed Windows target is a failure"        65 no_targets 0 0 "no Windows targets installed"
run_case "Windows target without linker runs zero legs"    65 gnu        0 0 "every leg was skipped"
run_case "linker present and cargo ok passes with counts"   0 gnu        1 0 "PASS: Windows cross-compile gate passed (13 crate check(s) across 1 leg(s))"
run_case "compile regression still exits 1"                 1 gnu        1 1 "FAIL: Windows cross-compile gate failed"

if [ "$failures" -ne 0 ]; then
  echo "test_windows_cross_compile_gate: FAILED (${failures} failure(s))" >&2
  exit 1
fi
echo "test_windows_cross_compile_gate: PASSED"
