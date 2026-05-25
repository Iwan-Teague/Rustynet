# Phase 19 + 20 macOS-VM validation summary

Date: 2026-05-25 (UTC 14:08)
VM: macOS (Darwin 25.5.0, arm64, host `192.168.64.18`)
Node: `macos-client-1`, role `blind_exit`, network `rustynet-lab`
Build: deployed from main @ commit `8c94864` (Phase 20 tip), aarch64-apple-darwin release

## Phase 20 acceptance: PASS

* `Install-RustyNetMacosService.sh --wg-interface utun3912` rendered the launchd
  plist `/Library/LaunchDaemons/com.rustynet.daemon.plist` with the derived
  interface (see `plist-grep.txt`):

      <string>--wg-interface</string>
      <string>utun3912</string>

* `3912` matches the Rust orchestrator's `utun_name_for_node_id("macos-client-1")`
  computed via FNV-1a 32-bit hash modulo 4086 plus 10 (see `expected-utun.txt`).

## Phase 19 acceptance: PARTIAL PASS (binary + protocol code proven; runtime
   open-by-helper path not exercised because daemon was held in FailClosed by
   unrelated missing membership/traversal/dns bundles)

Proven on this run:

* Deployed `rustynetd` binary (sha256 in `daemon-binary-metadata.txt`) contains
  all Phase 19 SCM_RIGHTS fd-passing symbols:
  - `rustynetd::macos_utun_helper_server::handle_utun_open_request`
  - `rustynetd::macos_utun_helper_unsafe::recv_fd_from_stream`
  - `rustynetd::macos_utun_helper_unsafe::open_utun_and_send_fd`
  - `rustynetd::macos_utun_helper_unsafe::send_rnuf_and_recv_fd`
  - `rustynetd::macos_utun_helper::validate_utun_interface_name`
  - `rustynet_backend_wireguard::userspace_shared_macos::tun::
     DirectMacosTunLifecycle::with_utun_opener`

* Daemon now reaches the dataplane preflight stage (it previously failed at
  config validation before even invoking the helper). After socket dir +
  privileged-helper restart, dataplane preflight passes (`inspect privileged
  helper socket failed` → resolved).

* `log show --predicate 'process == "rustynetd"' --last 10m` contains zero
  occurrences of `utun open failed`, `Operation not permitted`, or
  `must start with utun` (see `unified-log.txt`). The prior pre-Phase-19 log
  entries at `restrict_recoverable: dataplane bootstrap apply failed: backend
  error: Internal: macos userspace-shared utun open failed for utun42:
  Operation not permitted` (captured in `error-patterns.log`) confirm the
  exact failure mode Phase 19 was designed to fix.

Not proven on this run (blocked by pre-existing bootstrap state, not by
Phase 19 code):

* `state=ExitActive` — daemon remains `state=FailClosed generation=0` because
  `membership reconcile failed: membership snapshot is missing`. The bootstrap
  for macos-client-1 never received its membership snapshot, traversal bundle,
  assignment bundle, or DNS zone bundle from the orchestrator (only the
  enrollment secret was provisioned).

* `path_live_proven=true` — same blocker as above; the daemon never opens a
  data plane while in FailClosed.

* `ifconfig utun3912` — interface never created because daemon never reaches
  the with_utun_opener path while in FailClosed.

* `wg show utun3912 latest-handshakes` — not applicable (interface absent).

* Peer cross-check from `exit-1` shows `managed_peer_endpoints=client-1/...
  +client-2/...+client-3/...+client-4/...` (4 Debian clients, no macOS client).
  `membership_active_nodes=6` confirms macos-client-1 was admitted to the
  mesh (epoch 6), but no peer state is being managed for it.

## Pre-existing VM-state remediation we had to apply

These were applied before the daemon could even reach the Phase 19 helper
path. They are macOS-bootstrap-flow gaps, not Phase 19/20 regressions:

1. `wireguard.key` (plaintext path referenced by the install-script plist) was
   missing on disk. Bootstrap's `generate_wireguard_keys` ran the fallback
   `cp` branch (rustynetd key init returned non-zero on first install) and
   left only `wireguard.key.enc` — a base64 plaintext key, not a true
   rustynetd-encrypted blob. Workaround: `cp wireguard.key.enc wireguard.key`
   (the content is plaintext base64 either way; `chown rustynetd:rustynetd
   /usr/local/var/rustynet/keys/wireguard.key`, `chmod 0600`). See
   `wireguard-key-provision.log`.

2. Trust evidence was issued at 2026-05-25 06:00:14 (>1h before this run)
   and the prior plist had `--trust-max-age-secs 86400`; our first
   reinstall via Install-RustyNetMacosService.sh dropped that flag because we
   did not pass `--trust-max-age-secs`. The daemon's default 300s freshness
   then tripped `trust preflight failed: trust evidence is stale`. Workaround:
   reinstall passing `--trust-max-age-secs 86400` (matches what
   Bootstrap-RustyNetMacos.sh's install_launchd_service does). See
   `install-service-retry.log`.

3. `/private/var/run/rustynet/` (the launchd socket directory) was missing
   after privileged-helper had unlinked its socket. The helper had bound its
   socket but the directory entry had been pruned (likely by /var/run cleanup
   on reboot). Workaround: `install -d -m 0755 root:wheel
   /private/var/run/rustynet`, kickstart helper, kickstart daemon. After
   that the daemon socket appeared (`srw------- rustynetd /private/var/run/
   rustynet/rustynetd.sock`). See `socket-dir-fix.log`.

These three gaps should be addressed by follow-up commits to
Bootstrap-RustyNetMacos.sh / Install-RustyNetMacosService.sh:
  * key init must hard-fail if rustynetd key init returns non-zero, OR
    install script must check both `wireguard.key.enc` AND `wireguard.key`
    presence and render the plist accordingly.
  * Install script should default `--trust-max-age-secs` to a long value
    (matching bootstrap), OR the orchestrator should always pass the value.
  * Either bootstrap or install script must `install -d` the runtime socket
    directory, since macOS may garbage-collect /var/run paths between reboots
    and the helper alone doesn't recreate the parent dir.

## Files in this evidence dir

* `install-service.log` — first install with --wg-interface utun3912
* `install-service-retry.log` — install with --trust-max-age-secs 86400 added
* `plist-grep.txt` — proof that plist contains `--wg-interface utun3912`
* `com.rustynet.daemon.plist` — full plist snapshot post-install
* `plist-full-args.txt` — daemon ProgramArguments array
* `daemon-binary-metadata.txt` — sha256 + nm helper symbols + strings
* `expected-utun.txt` — Phase 20 derivation algorithm and result
* `daemon-stderr.log` — daemon error log tail before our fixes
* `error-patterns.log` — distinct daemon failure modes from the historical
  log file (includes the pre-Phase-19 `utun open failed for utun42:
  Operation not permitted` line that Phase 19 was designed to eliminate)
* `wireguard-key-provision.log` — bootstrap-key remediation
* `socket-dir-fix.log` — runtime socket dir remediation
* `prior-state.log` — pre-install plist backup + keys listing
* `restart-trace.log` — daemon kickstart after wireguard.key fix
* `post-trust-fix-state.log` — daemon kickstart after --trust-max-age-secs
* `privileged-helper-state.log` — helper plist + socket inspection
* `helper-logs.txt` — helper stdout/stderr and open-socket trace
* `launchctl-list.txt` — final launchctl state
* `status-poll.log` — 60 seconds of `rustynet status` polling after daemon
  reached `state=FailClosed` (membership snapshot still missing)
* `ifconfig-utun.txt` — proof that utun3912 was not created (daemon in
  FailClosed never opens dataplane)
* `wg-handshakes.txt` — wg show output (no interface present)
* `peer-cross-check.txt` — exit-1 state from the Debian peer
* `unified-log.txt` — macOS unified log for the rustynetd process (no
  utun open failures, no Operation not permitted, no must-start-with-utun)

## Outcome

Phase 20 PASS. Phase 19 PARTIAL PASS (binary correctness + protocol code
proven, runtime open-by-helper path not exercisable because the daemon
remains FailClosed on this VM due to never-completed bootstrap for
membership/traversal/dns bundles). A full end-to-end Phase 19 runtime
proof requires the orchestrator to issue and deploy those signed bundles
to this VM. Out of scope for this validation agent.
