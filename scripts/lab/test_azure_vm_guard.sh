#!/usr/bin/env bash
# Witness tests for azure_vm_guard.sh: stubbed az/ssh/osascript on PATH, throwaway state dir.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
GUARD="$HERE/azure_vm_guard.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
BIN="$TMP/bin"; mkdir -p "$BIN"
cat > "$BIN/az" <<'STUB'
#!/usr/bin/env bash
echo "az $*" >> "$STUB_LOG"
case "$*" in
  *get-instance-view*) printf '%s' "${STUB_POWER-}"; exit 0 ;;
  *deallocate*) exit "${STUB_DEALLOC_RC:-0}" ;;
esac
exit 0
STUB
cat > "$BIN/ssh" <<'STUB'
#!/usr/bin/env bash
echo "ssh $*" >> "$STUB_LOG"
[ "${STUB_SSH_FAIL:-0}" = 1 ] && exit 255
echo "rc=${STUB_PGREP_RC:-1}"; exit 0
STUB
printf '#!/usr/bin/env bash\nexit 0\n' > "$BIN/osascript"
chmod 755 "$BIN"/*
pass=0; fail=0
run() { # run <label> <want-exit> <want-dealloc 0|1> [env assignments...]
  local label="$1" want="$2" wantd="$3"; shift 3
  export STUB_LOG="$TMP/calls.log" AZ_GUARD_STATE="$TMP/state" AZ_GUARD_NOTIFY=0
  rm -rf "$TMP/state" "$STUB_LOG"; : > "$STUB_LOG"
  unset STUB_POWER STUB_SSH_FAIL STUB_PGREP_RC STUB_DEALLOC_RC LEASE_OFFSET
  for kv in "$@"; do export "$kv"; done
  if [ -n "${LEASE_OFFSET:-}" ]; then mkdir -p "$TMP/state"; echo $(( $(date +%s) + LEASE_OFFSET )) > "$TMP/state/azure-vm.lease"; fi
  PATH="$BIN:$PATH" bash "$GUARD" ${GUARD_ARGS:-} > "$TMP/out.txt" 2>&1; got=$?
  local d=0; grep -q "az vm deallocate" "$STUB_LOG" && d=1
  if [ "$got" -eq "$want" ] && [ "$d" -eq "$wantd" ]; then echo "ok   $label"; pass=$((pass+1))
  else echo "FAIL $label (exit $got want $want, deallocate $d want $wantd)"; fail=$((fail+1)); fi
}
run "already deallocated: nothing to do"            0 0 STUB_POWER=PowerState/deallocated
run "deallocating: nothing to do"                   0 0 STUB_POWER=PowerState/deallocating
run "running, no lease, no run => DEALLOCATE"       0 1 STUB_POWER=PowerState/running STUB_PGREP_RC=1
run "running + valid lease => keep"                 0 0 STUB_POWER=PowerState/running STUB_PGREP_RC=1 LEASE_OFFSET=3600
run "running + EXPIRED lease, no run => DEALLOCATE" 0 1 STUB_POWER=PowerState/running STUB_PGREP_RC=1 LEASE_OFFSET=-60
run "running + active run on lab host => keep"      0 0 STUB_POWER=PowerState/running STUB_PGREP_RC=0
run "stopped-but-allocated (still billed) => DEALLOCATE" 0 1 STUB_POWER=PowerState/stopped STUB_PGREP_RC=1
run "lab host unreachable => assume no run, DEALLOCATE"  0 1 STUB_POWER=PowerState/running STUB_SSH_FAIL=1
run "az cannot read state => exit 2, no action"     2 0 STUB_POWER=
run "deallocate fails => exit 2"                    2 1 STUB_POWER=PowerState/running STUB_PGREP_RC=1 STUB_DEALLOC_RC=1
GUARD_ARGS=--dry-run run "dry-run never deallocates" 0 0 STUB_POWER=PowerState/running STUB_PGREP_RC=1
unset GUARD_ARGS
# the lease is removed when the guard deallocates
export STUB_LOG="$TMP/calls.log" AZ_GUARD_STATE="$TMP/state2" AZ_GUARD_NOTIFY=0
mkdir -p "$TMP/state2"; echo $(( $(date +%s) - 10 )) > "$TMP/state2/azure-vm.lease"
STUB_POWER=PowerState/running STUB_PGREP_RC=1 PATH="$BIN:$PATH" bash "$GUARD" >/dev/null 2>&1
if [ ! -e "$TMP/state2/azure-vm.lease" ]; then echo "ok   expired lease file removed on deallocate"; pass=$((pass+1)); else echo "FAIL lease not removed"; fail=$((fail+1)); fi
# the pgrep pattern must be bracketed (self-match over ssh)
if grep -q "\[v\]m-lab-orchestrate-live-lab" "$GUARD"; then echo "ok   remote pgrep pattern is bracketed"; pass=$((pass+1)); else echo "FAIL pgrep pattern not bracketed"; fail=$((fail+1)); fi
echo "== azure_vm_guard tests: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
