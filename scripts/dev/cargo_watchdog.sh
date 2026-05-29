#!/usr/bin/env bash
# cargo_watchdog.sh — run a long-running build/test command but FAIL FAST and
# LOUDLY instead of hanging forever.
#
# Why this exists: a backgrounded `cargo` can wedge in ways that never produce
# a completion signal — most commonly a FULL DISK (cargo blocks/!errors writing
# artifacts) or contention on the `target/` build lock. A wedged process sits at
# 0% CPU and looks identical to one doing work, so "just wait for it" can wait
# forever. This wrapper turns every such condition into a prompt, explicit
# exit, so the caller's normal completion notification fires.
#
# It also fixes a subtler footgun: piping `cargo ... | tail` discards cargo's
# exit code (you get tail's) and most of its output. This wrapper runs the
# command directly, tees full output to a log, and exits with the command's
# REAL status.
#
# Usage:
#   scripts/dev/cargo_watchdog.sh -- cargo test -p rustynet-cli --bin rustynet-cli vm_lab::orchestrator
#
# Env knobs (all seconds / GiB):
#   WATCHDOG_STALL_SECS   no progress (no log growth AND no rustc) for this long => kill   (default 240)
#   WATCHDOG_MAX_SECS     hard wall-clock cap                                              (default 2400)
#   WATCHDOG_POLL_SECS    sampling interval                                                (default 15)
#   WATCHDOG_MIN_FREE_GIB abort before starting / kill mid-run if free space drops below   (default 5)
#   WATCHDOG_LOG          log file path                                          (default mktemp)
#
# Exit codes: the wrapped command's own code on normal completion; 28 on
# disk-space abort (ENOSPC-ish); 124 on stall or timeout (matches GNU timeout).
set -u

STALL_SECS=${WATCHDOG_STALL_SECS:-240}
MAX_SECS=${WATCHDOG_MAX_SECS:-2400}
POLL_SECS=${WATCHDOG_POLL_SECS:-15}
MIN_FREE_GIB=${WATCHDOG_MIN_FREE_GIB:-5}

# Strip a leading `--` separator if present.
if [ "${1:-}" = "--" ]; then shift; fi
if [ "$#" -eq 0 ]; then
  echo "cargo_watchdog: no command given" >&2
  echo "usage: cargo_watchdog.sh -- <command...>" >&2
  exit 2
fi

LOG=${WATCHDOG_LOG:-$(mktemp -t cargo_watchdog.XXXXXX)}

# Free GiB on the filesystem backing the current directory.
free_gib() {
  df -g . 2>/dev/null | awk 'NR==2 {print $4; exit}'
}

# Pre-flight: refuse to start a build with no room to write artifacts — that is
# exactly the condition that produces an invisible wedge.
free_now=$(free_gib)
if [ -n "${free_now:-}" ] && [ "$free_now" -lt "$MIN_FREE_GIB" ]; then
  echo "cargo_watchdog: ABORT — only ${free_now} GiB free (< ${MIN_FREE_GIB} GiB); a build now would wedge on a full disk." >&2
  echo "cargo_watchdog: reclaim space (e.g. rm -rf target/debug/incremental, prune old artifacts/) and retry." >&2
  exit 28
fi

echo "cargo_watchdog: starting (stall=${STALL_SECS}s max=${MAX_SECS}s free=${free_now:-?}GiB) -> log ${LOG}"
echo "cargo_watchdog: cmd: $*"

# Run in its own process group so we can kill the whole cargo+rustc tree.
set -m
( "$@" ) >"$LOG" 2>&1 &
CMD_PID=$!

# 0 if any live rustc process descends from $1.
has_rustc_descendant() {
  local root=$1 map rustcs pid cur guard
  rustcs=$(pgrep -x rustc 2>/dev/null) || return 1
  [ -z "$rustcs" ] && return 1
  map=$(ps -Ao pid=,ppid= 2>/dev/null)
  for pid in $rustcs; do
    cur=$pid; guard=0
    while [ -n "$cur" ] && [ "$cur" != "0" ] && [ "$cur" != "1" ] && [ "$guard" -lt 64 ]; do
      [ "$cur" = "$root" ] && return 0
      cur=$(awk -v p="$cur" '$1==p{print $2; exit}' <<<"$map")
      guard=$((guard + 1))
    done
  done
  return 1
}

kill_tree() {
  kill -TERM -"$CMD_PID" 2>/dev/null
  sleep 2
  kill -KILL -"$CMD_PID" 2>/dev/null
}

start=$(date +%s)
last_progress=$start
last_size=0

while :; do
  if ! kill -0 "$CMD_PID" 2>/dev/null; then
    wait "$CMD_PID"; rc=$?
    echo "----- cargo_watchdog: command exited rc=${rc} -----"
    tail -n 60 "$LOG"
    exit "$rc"
  fi

  now=$(date +%s)

  # Disk check mid-run: a build that fills the disk will wedge silently.
  fg=$(free_gib)
  if [ -n "${fg:-}" ] && [ "$fg" -lt "$MIN_FREE_GIB" ]; then
    echo "----- cargo_watchdog: DISK LOW (${fg} GiB < ${MIN_FREE_GIB}); killing to avoid a silent wedge -----"
    tail -n 40 "$LOG"
    kill_tree
    exit 28
  fi

  # Progress = log grew OR a rustc compiler is actively running under our tree.
  size=$(wc -c <"$LOG" 2>/dev/null | tr -d ' ')
  progressed=0
  if [ "${size:-0}" -gt "$last_size" ]; then progressed=1; last_size=${size:-0}; fi
  if has_rustc_descendant "$CMD_PID"; then progressed=1; fi
  if [ "$progressed" -eq 1 ]; then last_progress=$now; fi

  if [ $((now - last_progress)) -ge "$STALL_SECS" ]; then
    echo "----- cargo_watchdog: STALLED — no log growth and no rustc activity for ${STALL_SECS}s; killing -----"
    echo "(likely build-lock contention or a hung child; check for other cargo runs)"
    tail -n 40 "$LOG"
    kill_tree
    exit 124
  fi

  if [ $((now - start)) -ge "$MAX_SECS" ]; then
    echo "----- cargo_watchdog: TIMEOUT after ${MAX_SECS}s; killing -----"
    tail -n 40 "$LOG"
    kill_tree
    exit 124
  fi

  sleep "$POLL_SECS"
done
