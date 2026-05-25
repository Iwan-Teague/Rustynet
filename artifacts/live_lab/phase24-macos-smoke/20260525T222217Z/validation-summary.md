# Phase 24 macOS bring-up smoke — validation summary

**Run UTC**: 2026-05-25T22:22:17Z (host: macs-Virtual-Machine.local)
**Target VM**: `mac@192.168.64.18` (utun3912 for `macos-client-1`)
**Profile**: `profiles/live_lab/generated_vm_lab_20260525T222217Z_phase24_macos_smoke.env`
**Commit under test**: `f20a66a` (Phase 24 macOS bring-up smoke + bootstrap gap fold-ins) + `8f37848` (Phase 25 Windows bootstrap evidence)
**Outcome**: **BLOCKED — Phase 24 acceptance criteria not satisfied.**

## Phase 24 acceptance vs observed

| Criterion | Observed | Status |
|---|---|---|
| macOS daemon `state=ExitActive` | `state=FailClosed`, `bootstrap_error=reconcile failure threshold exceeded`, root cause `utun helper recvmsg failed: Resource temporarily unavailable (os error 35)` | **fail** |
| `path_live_proven=true` after 60s | `path_live_proven=false`, `path_mode=fail_closed` | **fail** |
| `membership_active_nodes >= 6` (on macOS daemon) | `membership_active_nodes=none` (daemon never accepted snapshot — dataplane apply blocks reconcile before membership is bound) | **fail** |
| Recent WireGuard handshake with >=1 Debian peer | utun3912 is never created by the daemon (privileged-helper times out); `ifconfig` shows zero utun interfaces | **fail** |
| `live_linux_mixed_topology_test` reports `pass` with macOS in topology | Stage never reached. Phase 24 acceptance also requires a Windows host in the same topology; the Windows VM is documented as paging-exhausted (Phase 25 evidence `artifacts/live_lab/phase25-windows-bootstrap/20260525T215328Z/validation-summary.md`), so the orchestrator's `live_mixed_topology` would skip with `requires entry + aux + extra labels with one Linux + one macOS + one Windows host`. | **fail / blocked** |

The five Debian peers (exit-1 + client-1/2/4/5) DO complete bootstrap, see the
6-node membership snapshot (`membership_active_nodes=6` after manual snapshot
distribution from exit-1), and reach `state=DataplaneApplied`. macOS is the
sole node that never reaches a healthy state. See `linux-peer-state.log` for
the five-Debian snapshot.

## Gaps surfaced during validation

Phase 24's three fix targets (`A` wireguard.key dual-path, `B`
`--trust-max-age-secs=86400` default, `C` `/private/var/run/rustynet`
recreate) ARE in the script tree at `f20a66a` and the script-level fixes
work. But the full bring-up path on a real fresh macOS VM hits five
additional gaps that Phase 24 did not catch (the Phase 24 commit message
acknowledges the agent did not exercise live bring-up).

### Gap D — `timeout(1)` binary missing on stock macOS
- **Surface**: orchestrator's `prime_remote_access` stage runs
  `if timeout 15 sudo -n -k true ...` (live_lab_common.sh:1376). macOS
  ships no GNU `timeout`; only BSD `time`. SSH non-login PATH on macOS
  does not include `/usr/local/bin` or `/opt/homebrew/bin` (verified
  by `ssh mac@... 'echo $PATH'` → `/usr/bin:/bin:/usr/sbin:/sbin`).
- **Reproduction**: orchestrator log shows
  `passwordless sudo (sudo -n) is required for live lab automation`
  (the verify wrapper conflates timeout's rc=127 with sudo failure).
- **Fix landed in this commit**: `Bootstrap-RustyNetMacos.sh`
  `install_brew_packages()` adds `coreutils` to the brew install list
  and symlinks `/opt/homebrew/bin/gtimeout` to `/usr/local/bin/timeout`
  alongside the existing `wireguard-go` symlink. The live-lab VM was
  patched by writing a portable perl-based `/usr/local/bin/timeout` shim
  + `/etc/zshenv` PATH prefix; both routes converge on `which timeout`
  succeeding from an SSH non-login shell.

### Gap E — `SUDO_USER=root` when bootstrap is invoked via nested sudo
- **Surface**: `Bootstrap-RustyNetMacos.sh:67`
  `REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || whoami)}"`. The
  orchestrator wrapper (`scripts/e2e/rn_bootstrap_macos.sh:315`) runs
  `sudo -n bash Bootstrap-RustyNetMacos.sh`. Bootstrap-RustyNetMacos.sh
  internally runs `sudo bash Install-RustyNetMacosService.sh`. When the
  outer ssh side already sudo'd to root, SUDO_USER inside the inner
  bootstrap is `root` (not `mac`), so `as_user brew install ...`
  becomes `sudo -u root brew install` → Homebrew refuses ("Running
  Homebrew as root is extremely dangerous and no longer supported").
- **Reproduction**: orchestrator's parallel-bootstrap aux.log captures
  this loop verbatim across all three retries.
- **Fix landed in this commit**: `Bootstrap-RustyNetMacos.sh` prefers
  `logname` (which tracks the original login session uid through nested
  sudo) over `SUDO_USER`, and only falls back to SUDO_USER when it is
  set AND not `root`. Final fallback is `whoami`.

### Gap F — `RUSTYNET_WG_BINARY_PATH` not exported for bootstrap-time `key init`
- **Surface**: bootstrap's `generate_wireguard_keys()` invokes
  `sudo -u rustynetd ${RUSTYNETD_BIN} key init`. The rustynetd binary's
  `resolve_wireguard_binary_path()` (`key_material.rs:51`) defaults to
  `/usr/bin/wg`, which does not exist on macOS (the brew install lives
  at `/opt/homebrew/bin/wg`). The launchd plist already exports
  `RUSTYNET_WG_BINARY_PATH=${BREW_PREFIX}/bin/wg` for the daemon's
  runtime invocations, but the bootstrap-time `key init` runs as a
  fresh sudo without that env.
- **Reproduction**: bootstrap error
  `rustynetd startup failed [generic_failure (1)]: wg binary canonicalization failed for /usr/bin/wg: No such file or directory (os error 2)`.
- **Fix landed in this commit**: `generate_wireguard_keys()` now passes
  `RUSTYNET_WG_BINARY_PATH=${BREW_PREFIX}/bin/wg` as an explicit env
  assignment to the `sudo -u rustynetd` invocation. (`sudo -u <user>
  VAR=value cmd` syntax passes the var as a sudo env assignment, not a
  shell var, so it survives the env-stripping.)

### Gap G — `BREW_PREFIX` empty in `SKIP_BUILD=1` branch
- **Surface**: When `SKIP_BUILD=1` is set, the main script branch skips
  `install_prereqs` (and therefore `setup_bootstrap_path`), so
  `BREW_PREFIX` (initialised to `""` at line 62) is never populated
  before `generate_wireguard_keys` and `install_launchd_service` use it.
  Bash's `${BREW_PREFIX}/bin/wg` collapses to `/bin/wg` and key init
  fails with `wg binary canonicalization failed for /bin/wg`.
- **Reproduction**: documented in `orchestrator-runs.log`; also
  reproduced standalone via `sudo SKIP_BUILD=1 bash Bootstrap-RustyNetMacos.sh env-file`.
- **Fix landed in this commit**: SKIP_BUILD=1 branch now runs the same
  brew-prefix detection loop (`/opt/homebrew` then `/usr/local`) before
  any helper that references `${BREW_PREFIX}`. Hard-fails if brew is
  not found on either prefix.

### Gap H — `key init` requires OS secure store the rustynetd account cannot reach
- **Surface**: `rustynetd key init` calls
  `key_custody_manager(... PlatformOsSecureStore ...).with_fallback_policy(RequireOsSecureStore)`
  on macOS (`key_material.rs:528`). `PlatformOsSecureStore::store_key`
  invokes `security_framework::passwords::set_generic_password` which
  writes to the calling user's *default* keychain (a per-login-session
  keychain). The rustynetd service account (uid 500, created via
  `dscl`) has no GUI session, no login keychain, no default-keychain
  binding → set_generic_password returns OsStoreUnavailable and the
  `RequireOsSecureStore` fallback policy hard-fails.
- **Reproduction**: bootstrap error
  `rustynetd startup failed [generic_failure (1)]: encrypt key failed: os secure store unavailable`.
  Reproduced as both `sudo -u rustynetd` and as `sudo` (uid=0); same
  failure either way, since neither root nor rustynetd has a default
  user-keychain initialised on a non-interactive host.
- **Workaround applied during validation (NOT a code fix)**: the VM was
  brought to plaintext-only key custody by generating wireguard.key via
  `wg genkey`, skipping the encrypted-key + passphrase pair entirely.
  `Install-RustyNetMacosService.sh` already gates the encrypted-key plist
  fragment on `[[ -f .../wireguard.passphrase ]]`, so without the
  passphrase file the daemon launches with `--wg-private-key` only.
- **Status**: NOT fixed in this commit — it needs a rustynetd code
  change. The cleanest fix is for `PlatformOsSecureStore::store_key`
  on macOS to use the *System* keychain via the `security` CLI
  (`security add-generic-password -a ... -s ... /Library/Keychains/System.keychain`)
  when running as root, rather than always going through
  security-framework's default-keychain path. The
  `load_macos_generic_password` companion already has this fallback
  (it tries security-framework first, then shells to `security`); the
  store path needs the symmetric treatment. Filing this as a
  follow-up issue is the right next step; trying to fix it here would
  blow scope.

### Gap I — macOS privileged-helper RNUF handshake never replies
- **Surface**: With keys + membership snapshot in place and the daemon
  launched, the daemon's dataplane reconcile calls
  `send_rnuf_and_recv_fd(privileged_helper_socket, "utun3912", 30s)`.
  The helper accepts the connection and reads the RNUF frame, but the
  `recv_fd_from_stream` call in the daemon times out and the helper
  never writes an SCM_RIGHTS reply. Daemon error:
  `utun helper recvmsg failed: Resource temporarily unavailable (os error 35)`.
- **Reproduction**: see `macos-helper-bug-repro.log`. Running the
  helper standalone (`/usr/local/bin/rustynetd privileged-helper
  --socket /tmp/test-helper.sock --allowed-uid 500 --allowed-gid 500
  --timeout-ms 30000`) and sending a single RNUF frame from python
  + `select.select(... 5s)` reproduces the deadlock: the client sends
  14 bytes, then `select` returns "TIMEOUT (helper never replied)".
  utun3912 itself is openable on this VM (verified by running
  `wireguard-go --foreground utun3912` directly — interface appears
  in `ifconfig`), so the kernel allows the interface; the bug is
  in the helper's reply path.
- **Status**: NOT fixed in this commit — also a rustynetd code change.
  The helper's `handle_utun_open_request` reads the RNUF frame, then
  calls `open_utun_and_send_fd(&stream, interface_name)`. The most
  likely root cause is that `SyncDevice::open` on `utun3912` succeeds
  in returning a fd but the subsequent `send_fd_via_stream` write is
  silently dropped (or never invoked because of an unguarded error
  path that returns Err before sending and Err is not propagated as
  a reply). This warrants a focused fix-bug + add-test cycle.

## What this commit DOES contain

1. **`scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh`**: fold-ins
   for Gaps D, E, F, G — script-level fixes that take the bootstrap
   path through prereqs and up to the rustynetd `key init` call
   without the regressions the live run surfaced. Gaps H and I block
   the run past that point and need separate rustynetd patches.

2. **`profiles/live_lab/generated_vm_lab_20260525T222217Z_phase24_macos_smoke.env`**:
   a 6-node mixed profile (5 Debian + 1 macOS, no Windows) for
   repeating this validation once gaps H + I are addressed. The Phase
   24 commit's `phase24_mixed.env` cannot complete because Windows is
   blocked; this profile reaches max membership without that label.

3. **`artifacts/live_lab/phase24-macos-smoke/20260525T222217Z/`**:
   evidence dir.

## Recommended next steps

- File rustynetd issue for Gap H (System keychain on macOS for
  service-account key custody). Suggested fix path:
  `store_macos_generic_password` should try System keychain via the
  `security` CLI when `set_generic_password` returns OsStoreUnavailable,
  mirroring the load-side fallback already present in `load_macos_generic_password`.
- File rustynetd issue for Gap I (helper RNUF reply path on macOS).
  Suggested approach: add a unit test that drives the helper via a
  UnixStream pair with an in-memory mock of `SyncDevice::open` and
  asserts the SCM_RIGHTS reply lands. The standalone reproduction in
  `macos-helper-bug-repro.log` (helper + python RNUF probe) is the
  minimal integration test.
- After both rustynetd patches land, re-run this validation; the
  bootstrap script gaps D-G are already covered by this commit so
  the script side will not regress.
- For mixed_topology coverage (the only Phase 24 acceptance criterion
  that requires Windows), reviving the Windows VM is operator
  territory — see the Phase 25 evidence summary for the paging-file
  exhaustion that has to be resolved on the VM itself.
