#!/bin/bash
#
# guest_clock_skew_probe.sh — read-only pre-run lab clock-skew diagnostic.
#
# Why this exists: a clock-skewed lab guest silently wastes a 30-45 minute
# live-lab run. Skew breaks signed-bundle freshness and certificate validity,
# and the orchestrator does not flag it loudly — the run just fails deep in a
# validation stage with a confusing error. Real incident: ubuntu-utm-1 once ran
# ~13.2 hours skewed and burned a full run before anyone noticed. This probe
# checks every reachable guest's clock BEFORE a run so a skewed guest is caught
# in seconds instead of after a wasted run.
#
# It is strictly READ-ONLY: it only runs `date +%s` over SSH. It never touches a
# guest clock or any other state, and it never uses sudo.
#
# Skew is measured against the local clock of the machine running this probe, so
# that machine must itself be NTP-synced for the numbers to mean anything (a
# skew reported here is "guest relative to this machine", not "guest relative to
# true UTC").
#
# Exit codes:
#   0 = every reachable guest is within the fail threshold (warnings allowed)
#   2 = at least one reachable guest exceeds the fail threshold
#   (unreachable guests alone never cause a non-zero exit; they are a separate,
#    reported condition)
#
set -uo pipefail

INVENTORY="documents/operations/active/vm_lab_inventory.json"
SSH_IDENTITY="${HOME}/.ssh/rustynet_lab_ed25519"
WARN_SKEW_SECS=5
FAIL_SKEW_SECS=60
DEFAULT_USER="debian"

usage() {
  cat <<'USAGE'
Usage: guest_clock_skew_probe.sh [options]

Read-only diagnostic: SSH each lab guest, read its clock, and flag any whose
skew relative to THIS machine's clock exceeds a threshold. Assumes the local
machine is NTP-synced. Modifies nothing on any guest.

Options:
  --inventory <path>        Inventory JSON (default: documents/operations/active/vm_lab_inventory.json)
  --ssh-identity-file <path> SSH private key for guests (default: ~/.ssh/rustynet_lab_ed25519)
  --warn-skew-secs <n>      Warn threshold in seconds (default: 5)
  --fail-skew-secs <n>      Fail threshold in seconds (default: 60)
  -h, --help                Show this help and exit 0

Exit: 0 = all reachable guests within the fail threshold; 2 = at least one
reachable guest exceeds it. Unreachable guests alone never fail the probe.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --inventory)          INVENTORY="${2:?--inventory needs a value}"; shift 2 ;;
    --ssh-identity-file)  SSH_IDENTITY="${2:?--ssh-identity-file needs a value}"; shift 2 ;;
    --warn-skew-secs)     WARN_SKEW_SECS="${2:?--warn-skew-secs needs a value}"; shift 2 ;;
    --fail-skew-secs)     FAIL_SKEW_SECS="${2:?--fail-skew-secs needs a value}"; shift 2 ;;
    -h|--help)            usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage >&2; exit 64 ;;
  esac
done

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required to parse the inventory (the inventory has quoted, comma-bearing fields that awk cannot split safely)" >&2
  exit 64
fi
if [ ! -f "$INVENTORY" ]; then
  echo "error: inventory not found: $INVENTORY" >&2
  exit 64
fi

# Emit one TAB-separated "alias<TAB>user<TAB>host" line per guest that has a
# usable address. Address preference: first live IP, then ssh_target (with any
# leading "user@" stripped), then last_known_ip. User preference: the "user@"
# in ssh_target, then ssh_user, then the default. python3 does the parsing so
# quoted comma-bearing fields are handled correctly.
guest_lines="$(python3 - "$INVENTORY" "$DEFAULT_USER" <<'PY'
import json, sys
inv_path, default_user = sys.argv[1], sys.argv[2]
with open(inv_path) as fh:
    inv = json.load(fh)
for e in inv.get("entries", []):
    alias = (e.get("alias") or "").strip()
    if not alias:
        continue
    target = (e.get("ssh_target") or "").strip()
    user = ""
    host = ""
    if "@" in target:
        user, host = target.split("@", 1)
    else:
        host = target
    live = e.get("live_ips") or []
    if live:
        host = str(live[0]).strip()
    if not host:
        host = (e.get("last_known_ip") or "").strip()
    if not user:
        user = (e.get("ssh_user") or "").strip() or default_user
    if not host:
        continue
    print(f"{alias}\t{user}\t{host}")
PY
)"

if [ -z "$guest_lines" ]; then
  echo "error: no guests with a usable address found in $INVENTORY" >&2
  exit 64
fi

printf '%-24s %-12s %-9s %s\n' "ALIAS" "REACHABLE" "SKEW_S" "VERDICT"
printf '%-24s %-12s %-9s %s\n' "------------------------" "------------" "---------" "-------"

total=0
reachable=0
unreachable=0
warned=0
failed=0

while IFS=$'\t' read -r alias user host; do
  [ -n "$alias" ] || continue
  total=$((total + 1))
  local_epoch="$(date +%s)"
  # `-n` redirects ssh's stdin from /dev/null. Without it, ssh would consume the
  # rest of the loop's heredoc input and only the first guest would be probed.
  guest_epoch="$(ssh -n -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes \
    -i "$SSH_IDENTITY" "${user}@${host}" 'date +%s' 2>/dev/null)"

  if ! printf '%s' "$guest_epoch" | grep -Eq '^[0-9]+$'; then
    unreachable=$((unreachable + 1))
    printf '%-24s %-12s %-9s %s\n' "$alias" "no" "-" "unreachable"
    continue
  fi

  reachable=$((reachable + 1))
  skew=$((local_epoch - guest_epoch))
  abs=${skew#-}
  if [ "$abs" -gt "$FAIL_SKEW_SECS" ]; then
    failed=$((failed + 1))
    verdict="FAIL"
  elif [ "$abs" -gt "$WARN_SKEW_SECS" ]; then
    warned=$((warned + 1))
    verdict="WARN"
  else
    verdict="ok"
  fi
  printf '%-24s %-12s %-9s %s\n' "$alias" "yes" "$skew" "$verdict"
done <<EOF
$guest_lines
EOF

echo
echo "summary: ${total} guest(s) | ${reachable} reachable, ${unreachable} unreachable | ${warned} warn, ${failed} fail (thresholds: warn>${WARN_SKEW_SECS}s, fail>${FAIL_SKEW_SECS}s)"

if [ "$failed" -gt 0 ]; then
  echo "VERDICT: NO-GO — ${failed} reachable guest(s) exceed the fail threshold; sync their clocks before running a live lab."
  exit 2
fi
echo "VERDICT: GO — no reachable guest exceeds the fail threshold."
exit 0
