# L1 — start.sh modularization (GAP-10).
#
# This file holds Linux-runtime-host-specific routines extracted from
# start.sh. The first slice landed `common.sh` and this scaffold; the
# bulk of the Linux dataplane wiring (systemd unit install, nftables
# programming, signed-state refresh service installation) still lives
# in start.sh and will migrate here incrementally so each move can be
# reviewed against the Linux-only integration test.
#
# Sourcing contract:
#   * start.sh sources `common.sh` first, then this file. The common
#     helpers (`print_info`, `is_linux_host`, …) are already in scope.
#   * Every function added here MUST guard with `is_linux_host` early
#     so a stray source on a macOS host is a no-op rather than a
#     foot-gun.
#   * Privileged execution (`run_root`, `systemctl`, `nft`) stays
#     argv-only — no shell-string construction with operator-supplied
#     values. This matches the rest of the privileged-helper
#     boundary policy.

# Confirm the common layer is loaded. If a future refactor sources
# this file standalone (e.g. for shellcheck), we fail fast with a
# clear message rather than silently breaking on an undefined
# function.
if ! declare -F is_linux_host >/dev/null 2>&1; then
  printf '[error] %s\n' \
    "scripts/start/linux.sh requires scripts/start/common.sh to be sourced first" >&2
  return 1 2>/dev/null || exit 1
fi

# Linux-only sanity: print a warning if we were sourced on a macOS
# host. We don't refuse — the file's functions all guard internally —
# but a top-level warning helps debug accidental cross-source.
if ! is_linux_host && [[ "${RUSTYNET_DEBUG_MODULE_SOURCING:-0}" == "1" ]]; then
  # Default-quiet on non-target platforms — the warning is a debug
  # aid only. Set RUSTYNET_DEBUG_MODULE_SOURCING=1 to see it.
  print_warn "scripts/start/linux.sh sourced on non-Linux host (HOST_OS=${HOST_OS}); functions will be no-ops"
fi

# Reviewed Linux runtime constants. The per-function migrations from
# start.sh will reference these so the canonical paths are pinned in
# one place.
RUSTYNET_LINUX_SYSTEMD_UNIT_DIR="/etc/systemd/system"
RUSTYNET_LINUX_DAEMON_UNIT_NAME="rustynetd.service"
RUSTYNET_LINUX_PRIVILEGED_HELPER_UNIT_NAME="rustynetd-privileged-helper.service"
RUSTYNET_LINUX_ASSIGNMENT_REFRESH_UNIT_NAME="rustynetd-assignment-refresh.service"
RUSTYNET_LINUX_ASSIGNMENT_REFRESH_TIMER_NAME="rustynetd-assignment-refresh.timer"
RUSTYNET_LINUX_TRUST_REFRESH_UNIT_NAME="rustynetd-trust-refresh.service"
RUSTYNET_LINUX_TRUST_REFRESH_TIMER_NAME="rustynetd-trust-refresh.timer"
RUSTYNET_LINUX_MANAGED_DNS_UNIT_NAME="rustynetd-managed-dns.service"

# True iff the reviewed Linux killswitch table is currently
# programmed. Uses the `linux-killswitch-boot-check` subcommand
# behind the scenes so this helper does not need to invoke `nft`
# directly. Fail-closed: returns 1 if the daemon binary is missing
# OR if the check reports drift OR if the host is not Linux.
rustynet_linux_killswitch_programmed() {
  if ! is_linux_host; then
    return 1
  fi
  local daemon_bin="/usr/local/bin/rustynetd"
  if [[ ! -x "${daemon_bin}" ]]; then
    return 1
  fi
  "${daemon_bin}" linux-killswitch-boot-check --no-fail-on-drift \
    >/dev/null 2>&1 || return 1
  # When --no-fail-on-drift is set, the binary returns 0 regardless
  # and prints a JSON report. We re-run without that flag to get the
  # actual drift signal.
  "${daemon_bin}" linux-killswitch-boot-check >/dev/null 2>&1
}
