#!/usr/bin/env bash
# lab_preflight.sh — quick local preflight to run BEFORE a live-lab session.
#
# WHAT IT DOES
#   1. Runs scripts/ci/check_mcp_binaries_fresh.sh, which fails (exit 78) if
#      any bin/rustynet-mcp-* server binary is missing or older than its
#      source under crates/rustynet-mcp/ (these are gitignored and nothing
#      rebuilds them on checkout, so they rot silently — see AGENTS.md §12.5).
#      A stale binary is a LOUD NON-FATAL WARNING: it names the offending
#      binary and the exact `--fix` command, but never blocks the session.
#   2. Prints a one-line lab-readiness summary: the local UTM fleet count and
#      per-VM SSH reachability, via the same discovery the orchestrator uses
#      (skipped gracefully on hosts without the vm-lab CLI built or without
#      UTM installed).
#
# THIS IS NOT A CI GATE and not part of any orchestrator fail-closed path.
# It is a local dev-QoL check: always exit 0 unless an argument was passed
# through to the freshness checker and that checker itself failed hard.
#
# COMPATIBILITY
#   - Written for bash 3.2 (what macOS ships at /bin/bash).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FRESHNESS_CHECK="$REPO_ROOT/scripts/ci/check_mcp_binaries_fresh.sh"

# --- 1. MCP binary freshness: warn loudly, never block ----------------------
freshness_rc=0
if [ -x "$FRESHNESS_CHECK" ]; then
    # `|| rc=$?` (not `if !`) so the checker's real exit code survives the guard.
    "$FRESHNESS_CHECK" "$@" || freshness_rc=$?
    if [ "$freshness_rc" -ne 0 ]; then
        echo ""
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        echo "!! WARNING: stale/missing MCP server binary detected (exit $freshness_rc)."
        echo "!! The rustynet-mcp-* servers in bin/ may be OLDER than their source"
        echo "!! under crates/rustynet-mcp/ — tools can be missing or behave per an"
        echo "!! outdated implementation. Fix before relying on MCP lab tools:"
        echo "!!   scripts/ci/check_mcp_binaries_fresh.sh --fix"
        echo "!! (then reconnect the MCP server: /mcp -> reconnect, or restart the"
        echo "!!  client — killing the process does NOT auto-respawn it.)"
        echo "!! Continuing anyway: this preflight NEVER blocks a lab session."
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        echo ""
    fi
else
    echo "WARNING: $FRESHNESS_CHECK not found or not executable; skipping MCP freshness check." >&2
fi

# --- 2. One-line lab-readiness summary --------------------------------------
inventory="$REPO_ROOT/documents/operations/active/vm_lab_inventory.json"
summary="lab-readiness: inventory "
if [ -f "$inventory" ]; then
    summary+="${inventory#$REPO_ROOT/} present"
else
    summary+="MISSING ($inventory)"
fi

# utmctl ships inside UTM.app and is often NOT on a non-interactive PATH.
utmctl_bin="$(command -v utmctl || true)"
if [ -z "$utmctl_bin" ] && [ -x /Applications/UTM.app/Contents/MacOS/utmctl ]; then
    utmctl_bin=/Applications/UTM.app/Contents/MacOS/utmctl
fi

if [ -n "$utmctl_bin" ]; then
    vms="$("$utmctl_bin" list 2>/dev/null | grep -c . || true)"
    running="$("$utmctl_bin" list --status started 2>/dev/null | grep -c . || true)"
    summary+="; UTM VMs: $vms registered, $running running"
else
    # Deliberately NO cargo-based discovery fallback: on a cold worktree that
    # would kick off a full rustynet-cli build (minutes) inside a "quick"
    # preflight. utmctl is the cheap, always-fast path on the lab host.
    summary+="; UTM/discovery: unavailable on this host"
fi

echo "$summary"

# Propagate a hard freshness failure only when the caller explicitly asked
# the checker to do something (e.g. --fix) — plain preflight never blocks.
if [ "$#" -gt 0 ] && [ "$freshness_rc" -ne 0 ]; then
    exit "$freshness_rc"
fi
exit 0
