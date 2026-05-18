# Platform Improvement Backlog (Debian + Windows, excluding NAT traversal)

**Status:** Active backlog
**Generated:** 2026-05-14

## Purpose

Itemized backlog of code-only improvements for the Debian (Linux) and
Windows ports of Rustynet, plus cross-platform items that improve both at
once. Explicitly **excludes** NAT traversal, UDP hole punching, and relay
work — those are tracked in
[PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md](./PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md).

Each item is a self-contained code slice with bounded blast radius:
* one source area
* one acceptance criterion (test + behaviour)
* live-lab confirmation on the current commit before push

Order within each section is rough priority (highest leverage first).

## Status legend

* `[ ]` open
* `[~]` in progress
* `[x]` done — must include commit SHA

## Source-of-truth links

When an item is sourced from another active plan, the citation is included
inline. Cross-reference with:
* [CrossPlatformSecurityGapRemediationPlan_2026-03-05.md](./CrossPlatformSecurityGapRemediationPlan_2026-03-05.md)
* [SecurityHardeningAudit_2026-04-28.md](./SecurityHardeningAudit_2026-04-28.md)
* [WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md](./WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md)
* [WindowsExitAndRelayDeltaPlan_2026-05-10.md](./WindowsExitAndRelayDeltaPlan_2026-05-10.md)
* [SerializationFormatHardeningPlan_2026-03-25.md](./SerializationFormatHardeningPlan_2026-03-25.md)
* [VmLabCapabilityReportingPlan_2026-04-14.md](./VmLabCapabilityReportingPlan_2026-04-14.md)
* [OpenWorkIndex_2026-04-17.md](./OpenWorkIndex_2026-04-17.md)

---

## Section 1 — Debian / Linux (rustynet-on-Linux dataplane host)

### L1. `start.sh` modularization (GAP-10)

* `[~]` Scaffolding slice landed (commit pending). New
  `scripts/start/` directory holds:
  - `common.sh` — platform-agnostic helpers: `print_info`,
    `print_warn`, `print_err`, `is_linux_host`, `is_macos_host`,
    `path_in_linux_runtime_roots` (loop-based against a pinned
    reviewed-roots list — replaces the inline four-prefix test),
    `sanitize_macos_keychain_account`, plus crate-internal
    `__rustynet_is_bool_token` / `__rustynet_canonical_bool` for
    future env-rewriter calls.
  - `linux.sh` — Linux-runtime scaffolds: reviewed systemd unit
    constants pinned and `rustynet_linux_killswitch_programmed`
    helper that wraps the new `linux-killswitch-boot-check`
    subcommand from L8. Sourcing requires `common.sh` first; fails
    fast if missing.
  - `macos.sh` — macOS scaffolds: reviewed Keychain service
    constants and `rustynet_macos_keychain_entry_exists` argv-only
    helper for the `security` binary. Sourcing requires `common.sh`
    first; fails fast if missing.
  - `start.sh` sources all three modules with hard-fail on missing
    `common.sh` (no inline-fallback that would defeat the audit
    boundary). The duplicated inline helpers (`print_info` /
    `print_warn` / `print_err` / `is_linux_host` / `is_macos_host` /
    `path_in_linux_runtime_roots` / `sanitize_macos_keychain_account`)
    are removed from start.sh and now live only in `common.sh`.
  Operator-visible behaviour is unchanged: `./start.sh --help`
  produces the same output, and the smoke gate
  `scripts/ci/start_modularization_smoke.sh` runs `bash -n` on each
  module, sources all three under both `HOST_OS=Linux` and
  `HOST_OS=Darwin`, and pins the behaviour of
  `path_in_linux_runtime_roots` (8 input shapes including
  `/etc/rustynet-other/foo` boundary case and empty input) and
  `sanitize_macos_keychain_account` (6 shapes including degenerate
  all-bad-chars input). All checks pass today.
* `[~]` `apply_host_profile_defaults` split landed (commit 201dc2f).
  `__rustynet_linux_apply_profile_defaults` lives in
  `scripts/start/linux.sh`,
  `__rustynet_macos_apply_profile_defaults` lives in
  `scripts/start/macos.sh`, and `start.sh` retains a thin
  dispatcher. The smoke gate has 6 new dispatch checks pinning
  Linux→HOST_PROFILE=linux + LINUX_* credential paths,
  Darwin→HOST_PROFILE=macos + WG_INTERFACE=utun9,
  FreeBSD→HOST_PROFILE=unsupported. Operator-visible behaviour of
  `./start.sh --help` unchanged.
* `[~]` macOS Keychain helpers extracted (commit b2fdc11).
  `ensure_macos_keychain_passphrase_account` and
  `macos_keychain_passphrase_exists` now live in
  `scripts/start/macos.sh` with `is_macos_host` early-return guards;
  smoke gate extended with 2 new module-sourcing declare-F asserts.
  Call sites inside start.sh (lines 210, 1687, 1848, 2263, 2285,
  3416) all sit downstream of the macos.sh source point — no
  call-site edits needed. Operator-visible behaviour unchanged.
* `[~]` `enforce_host_storage_policy` extracted per-platform
  (commit ecfd597). `__rustynet_linux_enforce_host_storage_policy`
  in `linux.sh`, `__rustynet_macos_enforce_host_storage_policy` in
  `macos.sh`; `require_macos_path_var_exact` moved alongside its
  sole caller. start.sh retains a 3-branch dispatcher (linux /
  macos / unsupported). Smoke gate now has 32 checks (+7 dispatch
  assertions). Operator-visible behaviour unchanged.
* `[x]` pfctl extraction audit: NO-OP confirmed. start.sh contains
  only `doctor_require_cmd pfctl` (line 1593) and the `pfctl_bin`
  path-resolver (lines 2227-2269); both already sit inside
  macOS-guarded blocks and there are NO standalone
  `apply_managed_dns_routing` / `clear_managed_dns_routing`
  wrappers in start.sh today. The original backlog entry was based
  on a wrong assumption — no migration is needed. Removed from
  remaining scope.
* `[ ]` Remaining scope (separate slices): systemd-unit install +
  launchd plist install paths already dispatch to Rust
  (`rustynet ops write-daemon-env` etc.) so those big blocks are
  NOT actually shell-to-Rust migrations. No further shell-only
  blocks identified at this time.

### L2. `linux_runtime_acls.rs` security-relevant drift coverage

* `[x]` (Commit a924229.) Scope adjustment: the original L2 entry
  conflated nftables runtime-ACL drift (which lives in `phase10.rs` and
  `privileged_helper.rs`) with the filesystem-ACL `linux_runtime_acls`
  module (which verifies `/var/lib/rustynet` and `/etc/rustynet`
  ownership / mode bits). This slice covers the filesystem-ACL surface;
  nftables IPv6 parity + named-chain integrity is a separate slice that
  requires touching the path controller's bring-up logic.
* 9 new tests pin: setuid/setgid drift on the state root (privilege-
  escalation hazard); world-writable state root (catastrophic local-
  user read/write); state root owned by root instead of rustynetd
  (daemon can't write StateDirectoryMode=0700); config root owned by
  rustynetd instead of root (daemon must not own its own config
  directory); 0o000 mode (would break daemon startup); first-fault
  ordering (mode > uid > gid); and the AND-of-statuses
  `overall_ok` invariant. (Commit a924229.)
* nftables IPv6 parity + named-chain integrity work is now tracked
  separately — promoting to its own backlog entry below or leaving
  for `phase10.rs` future work.

### L3. `linux_service_hardening.rs` systemd sandbox-flag pinning

* `[x]` Audit-only slice landed in commit 818f494. 18 new per-directive
  drift tests pin `MemoryDenyWriteExecute=yes`,
  `CapabilityBoundingSet=""`, `AmbientCapabilities=""`, `UMask=0077`,
  `User=rustynetd`, `Group=rustynetd`, `ProtectHome=yes`,
  `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`,
  `PrivateTmp=yes`, `PrivateDevices=yes`, `LockPersonality=yes`,
  `RestrictSUIDSGID=yes`, `RestrictRealtime=yes`,
  `SystemCallArchitectures=native`, `ProtectSystem=strict`,
  `ProtectControlGroups=yes`, `NoNewPrivileges=yes`. Each drift case
  flips the directive to a representative weak value and asserts the
  evaluator marks the unit drifted. Snapshot test
  `evaluator_reviewed_directives_cover_complete_hardening_envelope`
  pins the exact 19-key shape of `REVIEWED_HARDENING_DIRECTIVES` so
  silent removal of a reviewed directive trips a named failure.
* Note: production `scripts/systemd/rustynetd.service` does NOT
  currently set `MemoryDenyWriteExecute=` — the evaluator already
  flags this, but the orchestrator standard flow does not invoke
  `linux-service-hardening-check`, so the lab pipeline does not catch
  the drift today. Unit-file alignment + check wiring tracked as a
  follow-up slice rather than rolled into the audit-only commit.

### L4. `linux_dns_failclosed.rs` race + edge cases

* `[~]` Audit-only slice landed in commit d082221. 16 new tests pin the
  loopback-only evaluator against off-loopback shapes the production
  `/etc/resolv.conf` path can produce:
  - `127.0.0.53` systemd-resolved stub accepted (loopback)
  - long-form IPv6 loopback `0:0:0:0:0:0:0:1` accepted
  - full `127.0.0.0/8` range accepted (pins `is_loopback` contract)
  - `0.0.0.0` / `::` unspecified rejected
  - IPv4 link-local `169.254.169.254` (cloud-metadata) rejected
  - IPv6 link-local `fe80::1` (RA-installed resolver) rejected
  - `::ffff:8.8.8.8` IPv4-mapped IPv6 rejected
  - mixed loopback+external: exactly one drift naming the external
  - zone-id-suffixed `fe80::1%eth0` surfaces as parse failure
  - bracketed `[::1]` surfaces as parse failure
  - parser tolerates leading whitespace before keyword
  - parser ignores `options` / `sortlist` / `lookup` / `family` lines
  - parser drops bare `nameserver` with no address
  - inline comment attached to nameserver value caught as parse failure
  - `schema_version` pinned at 1 (deliberate-bump guard)
* `[x]` Commit 255cff4. Remaining scope landed: snapshot expanded
  with `systemd_resolved_stub_present` (read from
  `/run/systemd/resolve/stub-resolv.conf`) and
  `network_manager_dns_mode` (parsed from `[main] dns=` in
  `/etc/NetworkManager/NetworkManager.conf`). Both `#[serde(default)]`
  for forward-compat; schema_version stays at 1. New evaluator flags
  stub-race on 127.0.0.53 conflict and NM precedence drift on
  `dns=default` / empty / unknown backends. `dns=none` /
  `systemd-resolved` / `dnsmasq` accepted. 17 new tests (3 race + 7
  precedence + 7 INI-parser shapes).

### L5. `linux_mesh_status.rs` typed-schema fail-closed parser

* `[x]` (Commit d1433e1.) On audit, `linux_mesh_status.rs` was already
  using a typed `LinuxMeshStatusReport` struct and the underlying
  `resilience::load_session_snapshot` parser was already a strict
  line-by-line state-file parser (no dynamic `serde_json::Value` walks
  involved). What was missing was test coverage that pins the
  fail-closed contract. 16 new schema-drift tests now cover unknown
  lines, missing/invalid required fields, oversize payload, digest
  mismatch, integrity-mismatch propagation through the collector,
  state-path echo in the report, and drift-reason enumeration. The
  regression contract is now explicit so a future refactor cannot
  silently relax fail-closed behaviour.

### L6. `linux_key_custody.rs` passphrase-file pinning

* `[x]` Commit 8e1e64e. Extended the verifier from 4-entry WG-key-only
  coverage to 8-entry coverage that pins systemd's encrypted-credential
  store (the real source of the runtime WG passphrase + the
  membership-owner signing-key passphrase):
  - `/etc/rustynet/credentials/` dir (0700 root:root)
  - `wg_key_passphrase.cred` (0600 root:root)
  - `signing_key_passphrase.cred` (0600 root:root)
  - `/var/lib/rustynet/keys/wireguard.passphrase` (must be ABSENT)
  Plus 7 new tests + canonical 8-entry path snapshot. Before this slice
  the verifier silently passed when those paths had wrong perms,
  missing files, or rustynetd-owned credential files — now those drift
  shapes are named rejections.
* `[ ]` Remaining scope (separate slice): cross-boot stability test
  (write → reboot fixture → read → match) + assertion that no plaintext
  passphrase survives a normal-shutdown daemon restart. Requires
  fixtures or a live-lab harness rather than pure unit tests.

### L7. Linux exit ACL IPv6 parity

* `[~]` Audit-only slice landed in commit dbf0565. On audit, the Linux
  exit-node programming uses two nftables families intentionally:
  - `inet` for killswitch + forward (covers IPv4 + IPv6)
  - `ip` for NAT/masquerade postrouting (IPv4 only)
  There is no `ip6` NAT sibling — the fail-closed posture is the
  kernel disable `/proc/sys/net/ipv6/conf/all/disable_ipv6=1`, gated
  by `ApplyOptions.ipv6_parity_supported`. Production default in
  `daemon.rs` is `ipv6_parity_supported=false`, which forces the
  kernel disable.
  6 new tests pin the security-bar invariant against the DryRunSystem
  operation log:
  - parity=false serve-exit-node logs `hard_disable_ipv6_egress` +
    `apply_nat_forwarding`
  - parity=true serve-exit-node omits `hard_disable_ipv6_egress`
  - parity=false full-tunnel logs `hard_disable_ipv6_egress`
  - ordering: kernel disable runs before `assert_exit_policy` /
    `set_exit_mode`
  - `nft_family_for_ip` + `ManagementCidr::nft_family` v4→"ip",
    v6→"ip6" snapshot
  - parity false→true flip rolls back the kernel disable
* `[ ]` Remaining scope (separate slice): introduce an `ip6` NAT
  sibling table + raise the default to `ipv6_parity_supported=true`.
  Needs live-lab validation since the IPv6 NAT programming changes
  what packets actually traverse the exit node.

### L8. Linux killswitch boot-time enforcement

* `[~]` Audit-only slice landed (commit pending). New
  `rustynetd::linux_killswitch_boot` module + `rustynetd
  linux-killswitch-boot-check` subcommand verify the boot-time
  invariant: *if* the WireGuard tunnel interface is present in
  `/sys/class/net`, the reviewed `inet rustynet` killswitch table
  with chains `killswitch` and `forward` plus loopback + est/rel
  rule fragments MUST be in place. The reverse case (table present,
  iface absent) and the cold-boot pre-up window (both absent) pass.
  Off-Linux the verifier sets `host_observable=false` and surfaces a
  clear blocker rather than claiming overall_ok.
  - Pure `evaluate_linux_killswitch_boot_snapshot` evaluator
  - `parse_nft_ruleset_for_killswitch` text parser for `nft list
    ruleset` output (no shelling out at test time)
  - Off-host collector returns the unobservable-host snapshot
  - 21 tests: clean / pre-boot / leak-window / missing chain x2 /
    missing rule fragment x2 / chain-missing suppresses fragment
    noise / aggregation / build-report / schema_version pin /
    parser shapes including unrelated-table isolation / off-Linux
    collector blocker / reviewed-list snapshot tests
  - CLI: `rustynetd linux-killswitch-boot-check [--iface <name>]
    [--no-fail-on-drift]`. Designed to be wired as `ExecStartPre=` on
    the rustynetd unit and (future) on a `network-online.target`-
    ordered service so the daemon refuses to bring the WG iface up
    when the killswitch isn't programmed yet.
* `[~]` Wire-up landed (commit pending). The reviewed
  `scripts/systemd/rustynetd.service` now invokes
  `linux-killswitch-boot-check --iface ${RUSTYNET_WG_INTERFACE}` as
  an `ExecStartPre=` (without `--no-fail-on-drift`, by design). On a
  daemon restart where the iface was left up but the killswitch
  table was flushed, systemd refuses to start the daemon until an
  operator brings the iface down — fail-closed by construction. 3
  new unit-file pins in `linux_service_hardening` lock the
  contract: ExecStartPre presence + no `--no-fail-on-drift` +
  `--iface` flag; encrypted-credential `LoadCredentialEncrypted=`
  lines; `MemoryDenyWriteExecute=true`. Regression-coverage gate
  bumped from `linux_service_hardening:30` → `:33` and added a new
  `linux_killswitch_boot:21` floor.
* `[ ]` Remaining scope (separate slice): netns-lab integration
  test that reboots a node mid-tunnel + asserts no unprotected
  egress packets observed in the bring-up window.

---

## Section 2 — Windows (rustynet-on-Windows host + dataplane)

### W1. PowerShell helper machine-readable JSON outputs

* `[~]` In progress. (Slice 1 = commit 09df8f4 — Collect helper.) Goal:
  `Bootstrap-RustyNetWindows.ps1`, `Install-RustyNetWindowsService.ps1`,
  `Verify-RustyNetWindowsBootstrap.ps1`,
  `Collect-RustyNetWindowsDiagnostics.ps1` each write a fail-closed JSON
  result on **both** success and top-level failure with shape parity so
  consumers deserialize either branch through a single typed view.
* Source: Phase 1 of
  [WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md](./WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md).
* Slice progress:
  * `[x]` Collect helper: success manifest now emits `status='pass'` +
    `reason=''` alongside the existing fields; failure manifest
    unchanged. Typed `WindowsDiagnosticsManifestView` in
    `crates/rustynet-cli/src/vm_lab/bootstrap/windows.rs` parses both
    branches and rejects shape drift (unknown status value,
    `status='fail'` with empty reason, missing required field, wrong
    field type). 8 unit tests cover the parser. (Commit 09df8f4.)
  * `[x]` Verify helper: failure manifest schema_version bumped
    1 → 3 for parity with the success report at the tail of the
    script. Typed `WindowsVerifyReportView` parses both branches and
    rejects shape drift (wrong schema_version, unknown status, fail/
    blocked without reason, missing required field, wrong field type).
    9 unit tests cover the parser including the
    `windows-runtime-backend-explicitly-unsupported` blocked-status
    path. (Commit 5b27a53.)
  * `[x]` Install helper: shape already consistent at
    schema_version=1 on both branches; this slice adds typed
    `WindowsInstallReportView` parsing both branches and rejecting
    shape drift (wrong schema_version, blocked status which Install
    never emits, fail without reason, missing required field, wrong
    field type). 9 unit tests cover the parser. (Commit 9d12735.)
  * `[~]` Bootstrap helper per-phase shape audit (multiple JSON
    shapes; largest helper surface). Sub-slice progress:
    * `[x]` prepare-transport phase: typed
      `WindowsPrepareTransportReportView` covers both branches (helper
      emits the full field set on every code path via
      `New-PrepareTransportFailureReport`). Parser fail-closes on
      unknown status, fail without reason, missing/wrong-type field,
      and the `host_key_present=true` with empty host_key drift case.
      9 unit tests. (Commit 74ac13d.)
    * `[x]` build-release phase: typed `WindowsBuildReleaseReportView`
      covers both branches (helper writes the full schema_version=2
      manifest on every code path via `Write-BuildReleaseReport`).
      Parser fail-closes on wrong schema_version, wrong phase, unknown
      status, fail without reason, fail with exit_code=0 (internal
      invariant), unknown `toolchain_scope`, missing/wrong-type field.
      12 unit tests. (Commit b2878f1.)
    * `[ ]` sync-source / install-release / restart-runtime /
      verify-runtime / collect-diagnostics / all phases — these
      helpers do not yet emit structured JSON on success, so the
      next sub-slices need to add the helper-side writers before
      adding typed views.

### W2. `windows_service_hardening.rs` SDDL + SidType drift hardening

* `[x]` (Commit 88325dc.) On audit, the existing evaluator already
  enforces every check the W2 acceptance criterion called for:
  REVIEWED_SERVICE_SID_TYPES rejects `none`; the
  FORBIDDEN_WELL_KNOWN_SDDL_PRINCIPALS deny-list in
  `crates/rustynetd/src/windows_paths.rs` covers WD/AU/BU;
  `interactive_process=true` is rejected regardless of `start_name`;
  `failure_action_count=0` is rejected; the binary ACL is delegated to
  `evaluate_windows_runtime_acl_sddl` which enforces `D:P` + SY + BA +
  reviewed-owner-only. The gap was per-principal, per-invariant test
  coverage in this module's own test suite. 9 new tests now pin: WD /
  AU / BU principals each rejected with the principal named in the
  reason; missing SY / BA principals rejected with the precise required
  reason; unreviewed owner rejected; S-1-5-80-* service-SID owner
  accepted; `interactive_process=true` + `start_name=LocalSystem`
  rejected (pins the historical SYSTEM-interactive-session footgun);
  D:P protected DACL is pinned as the contract. B.8.1
  SidType=restricted feasibility was closed as "not feasible" in
  SecurityHardeningAudit on 2026-05-05, so the evaluator continues to
  accept either `unrestricted` or `restricted`.

### W3. `windows_dns_failclosed.rs` IPv6 NRPT + RA suppression

* `[~]` Audit-only slice landed in commit 966546c. 11 new NRPT-side
  IPv6 tests pin the loopback-only contract against IPv6 name-server
  shapes Get-DnsClientNrptRule can return:
  - `::1` single-server root rule accepted
  - `0:0:0:0:0:0:0:1` long-form loopback accepted
  - dual-stack rule (127.0.0.1 + ::1) accepted
  - `fe80::1` link-local NRPT rejected (+ root coverage drift)
  - `::` IPv6 unspecified rejected
  - `2606:4700:4700::1111` IPv6 external rejected
  - `ff02::1` IPv6 multicast rejected
  - `::ffff:8.8.8.8` IPv4-mapped external rejected
  - mixed loopback+external IPv6 rule rejected (+ root drift)
  - secondary IPv6 external rule isolated drift (root stays clean)
  - root rule covered by `::1`-only accepted
* `[~]` Sibling-coverage evaluator landed (commit pending). New
  `evaluate_nrpt_ipv6_sibling_coverage` pass (independent of the
  main `evaluate_windows_dns_failclosed_snapshot` so existing
  callers/fixtures are unaffected) walks every NRPT rule, computes
  the union of loopback name-server address-families per namespace,
  and surfaces drift when any namespace lacks a v4-loopback or
  v6-loopback sibling. Three drift shapes pinned with operator-
  facing reasons explaining the leak path (A queries / AAAA queries
  / both fall through to host default DNS). Namespace iteration via
  BTreeMap → stable sorted reasons across runs. 10 new tests pin
  the contract: dual-stack in one rule, dual-stack across two
  rules (union semantics), v4-only flagged, v6-only flagged,
  no-loopback-at-all flagged, two namespaces in stable order, empty
  namespaces ignored, unsupported schema_version rejected, empty
  snapshot tolerated, mixed-rule union semantics with one covered +
  one uncovered namespace.
* `[~]` CLI wire-up landed (commit pending). The `rustynetd
  windows-dns-failclosed-check` subcommand now accepts
  `--enforce-ipv6-sibling-rules`. When set, the sibling evaluator
  runs alongside the main pass and any siblings drift is folded
  into the report's `drift_reasons` with an `ipv6-sibling:` prefix
  so operators can tell which evaluator fired. Default off for
  back-compat. 3 new flag-handler tests + help-text pin.
* `[~]` Router Advertisement suppression evaluator landed (commit
  1afcd12). New `evaluate_router_advertisement_suppression` pure
  evaluator independent of the main + sibling passes. Snapshot
  schema extended (forward-compat via `#[serde(default)]`) with:
  - `WindowsRouterAdvertisementObservation { schema_version,
    interfaces: Vec<WindowsInterfaceRaState> }`
  - `WindowsInterfaceRaState { interface_alias, interface_index,
    router_discovery_enabled, ipv6_default_route_sources }`
  - `WindowsDnsFailclosedSnapshot.router_advertisement_observation:
    Option<WindowsRouterAdvertisementObservation>`
  Drift shapes pinned: None observation → fail closed;
  `router_discovery_enabled=true` → drift; `ra`-sourced IPv6
  default route → drift; observation schema_version mismatch →
  drift. 11 new tests including BTreeMap-stable interface order +
  forward-compat with legacy JSON. `windows_dns_failclosed`
  coverage floor: 56 → 67.
* `[ ]` Remaining scope (separate slice): CLI subcommand wire-up
  (`--enforce-ra-suppression` flag mirroring
  `--enforce-ipv6-sibling-rules`) + PowerShell collector that
  surfaces the RA / default-route state.

### W4. `windows_runtime_acls.rs` registry + service ACL drift extension

* `[~]` Commit f31b9f2. Split the SDDL principal matcher into
  `sddl_grants_principal` (allow ACEs only) + `sddl_denies_principal`
  (deny ACEs only); the underlying matcher now exact-matches the ACE
  type token (`A` ≠ `AU` audit, `D` ≠ `XD` callback-deny). Previously
  the substring scan treated allow and deny ACEs as identical, so an
  inserted deny ACE for LocalSystem or Builtin Administrators would
  silently pass evaluation. The runtime-ACL evaluator now rejects:
  - deny ACE for SY (LocalSystem)
  - deny ACE for BA (Builtin Administrators)
  …while still permitting explicit deny ACEs for World (`(D;;FA;;;WD)`)
  because they strengthen the protection rather than weakening it.
  13 new tests including deny-ACE coverage, PAI inheritance form,
  SACL audit isolation from DACL drift, anonymous + user-SID owner
  rejection, DPAPI blob WD rejection, an 8-entry reviewed-root path
  snapshot, and a `schema_version=1` deliberate-bump guard.
* `[~]` Registry-ACL evaluator + typed snapshot landed (commit
  5eb1e3d). New module `crates/rustynetd/src/windows_registry_acls.rs`
  owns the evaluator over an observed-registry-ACL snapshot:
  - `REVIEWED_REGISTRY_KEY_PATHS` constant pinning the reviewed
    HKLM RustyNet service keys.
  - `FORBIDDEN_PRINCIPALS_REGISTRY = ["WD", "AU", "BU", "AN"]`
    pinning the broader-than-reviewed Windows principals.
  - `WindowsRegistryKeyAclStatus { Ok / Missing / Invalid /
    Unobserved }` typed status enum.
  - `WindowsRegistryKeyEntry { label, key_path, requirement,
    status }` + `WindowsRegistryAclReport` shapes.
  - `evaluate_windows_registry_acls` pure evaluator with
    fail-closed shapes: required+Missing/Unobserved → drift;
    Invalid → drift; Ok with forbidden-principal grant → drift;
    unknown requirement string → drift; empty entries →
    fail closed. Optional+Missing tolerated.
  - Cross-platform stub collector returns Unobserved entries with
    a "collector not yet wired" reason so overall_ok=false until
    the Win32 piece lands.
  17 new tests + a snapshot test pinning the reviewed-keys list +
  forbidden-principals list. `windows_registry_acls` gate floor
  added at :17.
* `[ ]` Remaining scope (separate slice): Win32 collector in
  `rustynet-windows-native` that calls `RegGetKeySecurity` +
  `ConvertSecurityDescriptorToStringSecurityDescriptor` to populate
  the snapshot with real SDDLs. Service-config DACL drift via the
  Win32 API; not landable as a pure-Rust
  audit extension.

### W5. `windows_authenticode.rs` thumbprint pinning + revocation deny-list

* `[~]` Policy + evaluator + report-schema slice landed (commit
  pending). New components:
  - `WindowsAuthenticodeThumbprintPolicy { allowlist_sha256,
    denylist_sha256 }` with `Default` + `Serialize`/`Deserialize` and
    a `normalise_thumbprint` helper that strips whitespace / colons /
    dashes and lowercases, rejecting anything that isn't a 64-char
    hex SHA-256 thumbprint.
  - `evaluate_thumbprint_policy(observed, &policy) -> Vec<reason>`
    pure evaluator with explicit fail-closed shapes:
    - `None` observation → fail closed (thumbprint extraction failed
      but a pinned policy is in effect)
    - malformed observation → fail closed
    - denylist hit → fail closed (denylist takes precedence over
      allowlist; revocation always wins)
    - allowlist enabled and observed thumbprint not on list → fail
      closed
    - malformed allowlist / denylist entries surface as drift so
      operators see typos in their reviewed lists
  - `WindowsAuthenticodeReport` extended with
    `signer_thumbprint_sha256: Option<String>` and
    `thumbprint_policy_applied: Option<WindowsAuthenticodeThumbprintPolicy>`,
    both `#[serde(default)]` for forward-compat.
  - New `inspect_authenticode_signature_with_thumbprint_policy(path,
    policy)` API that threads the policy through; legacy
    `inspect_authenticode_signature(path)` delegates with `None`
    policy for back-compat. When a policy is supplied, `overall_ok`
    requires presence + chain-verified + policy-satisfied.
  17 new tests: 5 normalisation (clean / uppercase / Microsoft
  separator style / short input / non-hex) + 12 policy evaluator
  (empty-allowlist clean / off-allowlist reject / on-allowlist
  accept / denylist-takes-precedence / case+separator normalised
  denylist match / None-observation fail-closed / malformed
  observation fail-closed / malformed allowlist drift / malformed
  denylist drift / allowlist-disabled+clean-denylist passes /
  default empty-state snapshot / policy serde round-trip).
* `[ ]` Remaining scope (separate slice): native thumbprint EXTRACTOR
  in `rustynet_windows_native`. The Windows extractor needs to call
  `CryptQueryObject` on the PE → `CryptMsgGetParam` for the SignerInfo
  → derive the signer cert from the SignedData → compute
  `CertGetCertificateContextProperty(CERT_SHA256_HASH_PROP_ID)` and
  surface the lowercase hex via a new
  `extract_signer_thumbprint_sha256(path) -> Result<String, String>`
  function. Until that lands, every observation is `None` and any
  caller that supplies a policy gets a fail-closed result — which is
  the correct security posture for rollout.

### W6. `windows_key_custody.rs` DPAPI LocalMachine rotation tests

* `[x]` Commit 255cff4. 7 new tests pin post-rotation custody
  invariants: success with reviewed ACL; world-writable principal on
  rotated blob; unreviewed owner; partial rotation (encrypted-key
  mid-rename, briefly missing); rotation that left plaintext-key file
  present; temp-suffix extension drift (`.dpapi.tmp` instead of
  `.dpapi`); DACL widened to Authenticated Users.

### W7. Windows install-release real runtime path (substantial)

* `[ ]` Currently a protective stub returning
  `runtime-host-not-yet-implemented` per the VmLab capability evaluator
  (`crates/rustynet-cli/src/vm_lab/capability.rs`). Wiring a real
  Windows service/config host into `rustynetd` is the gating piece for
  Windows-as-dataplane outside of NAT-traversal scope.
* Source: VmLab cookbook + WindowsExitAndRelayDeltaPlan.
* Acceptance: large slice; should be tackled after W1-W6 land.

### W8. Windows mesh status hardening

* `[x]` Commit 255cff4. On audit, the parser side was already using
  the typed `WindowsMeshSnapshotLoad` enum shared with Linux via
  `resilience::load_session_snapshot` — the L5 fail-closed tests
  already cover the underlying state-file parser. What was missing
  was reviewed-root enforcement on the collector itself. The
  `ensure_state_path_under_reviewed_root` helper existed but was
  `#[allow(dead_code)]` and never invoked, so the collector accepted
  any state path the orchestrator passed (including %TEMP%, UNC
  shares, world-writable locations). Now the collector calls the
  validator as the first action; out-of-root paths surface as
  `InvalidFormat` snapshots before any filesystem read. 3 new tests
  pin the contract: arbitrary `/tmp/...` path, user-writable
  `%TEMP%` path, UNC `\\fileserver\…` path.

---

## Section 3 — Cross-platform (both Debian and Windows benefit)

### X1. `rustynet status` / `rustynet netcheck` `--json` flag

* `[x]` Add `--json` flag that emits the existing status/netcheck data
  as machine-readable JSON. (Commit 50a8b80.) The CLI converts the
  daemon's `prefix: key1=value1 ...` line into a JSON object with
  `prefix` plus one string field per key/value pair (lossless;
  consumers do their own numeric coercion). On daemon error or
  unrecognised shape, the CLI emits a minimal `{"ok":false,"error":...}`
  or a tagged fallback so downstream `jq` pipelines fail parse-fast on
  shape drift. 15 unit tests cover the renderer, flag extraction, and
  the command whitelist.

### X2. Phase A typed-schema continuation

* `[~]` Incremental progress (commit pending). First of the four
  NDJSON consumers in `ops_phase9.rs` migrated to
  `read_ndjson_typed<T>`: `dr_drills.ndjson` now goes through the
  new `Phase9DrDrillView` typed view that pins:
  - required `executed_at_utc: String` (serde fail-closed when
    missing or non-string)
  - optional `evidence_mode: Option<String>` (typed Option keeps
    the legacy `phase9_require_measured_mode` semantics)
  - `#[serde(flatten)] extra: Map<String, Value>` to carry the
    untyped fields the downstream Map-based helpers still walk
  - `into_value_map()` bridge that re-merges the typed fields back
    into a `Map<String, Value>` for the downstream code, lossless
  6 new tests pin the migration: clean line accepted, missing
  `executed_at_utc` rejected at the typed boundary with the file
  label in the error, wrong-type `executed_at_utc` rejected,
  missing `evidence_mode` accepted as `None`, `into_value_map`
  round-trips all fields, and `into_value_map` omits a `None`
  evidence_mode. `#[allow(dead_code)]` removed from
  `read_ndjson_typed` now that it has a real call-site.
* `[~]` All four `ops_phase9.rs` NDJSON consumers now migrated to
  typed views (commit pending). Added three more typed views
  matching the dr_drills shape:
  - `Phase9IncidentDrillView` — same `executed_at_utc` reviewed
    contract as Phase9DrDrillView
  - `Phase9SloWindowView` — `window_end_utc` required-string field
  - `Phase9PerformanceSampleView` — both `measured_at_utc`
    (reviewed) and `timestamp_utc` (legacy alias) captured as
    `Option<String>`; `resolved_timestamp_utc()` applies the
    precedence and the downstream loop surfaces the legacy
    "missing or invalid UTC field" reason verbatim if both are
    absent. Each typed view exposes `into_value_map()` for the
    Map-based downstream consumers.
  10 new tests across the three views (clean line / missing
  required field / into_value_map round-trip on each + extras for
  the performance-view precedence shape). `read_ndjson_objects`
  marked `#[allow(dead_code)]` with a doc-comment noting it
  remains as a verified reference impl for future migrations.
* `[~]` Two more typed-view migrations landed (commit b8f48da):
  - `NetworkDiscoveryBundleView` in `ops_network_discovery.rs`
    pins `schema_version: u64`, `purpose: String`, `collected_at_unix:
    u64`. The recursive `validate_no_secrets` walker STAYS a
    generic Value walk by design (must remain generic to catch
    arbitrary nested keys).
  - `FreshInstallOsMatrixReportView` in
    `ops_fresh_install_os_matrix.rs` pins `schema_version`,
    `evidence_mode`, `environment`, `captured_at_unix`,
    `git_commit`; remaining fields via `#[serde(flatten)] extra`.
  Each view exposes `into_value_map()` for downstream Map-based
  helpers. 8 new tests (4 per module): clean-line accepted,
  missing-required-field rejected, wrong-type rejected,
  `into_value_map` round-trip.
* `[~]` First X2 slice on `ops_cross_network_reports.rs` landed
  (commit 9a77aeb). Migrated `validate_soak_monitor_summary_artifact`
  to `CrossNetworkSoakMonitorSummaryView` (19 required u64 + 8
  required String fields + `#[serde(flatten)] extra` + lossless
  `into_value_map()` bridge). 4 new tests pin: clean parse,
  missing-required-field rejected, wrong-type rejected,
  into_value_map round-trip.
* `[~]` Second X2 slice on `ops_cross_network_reports.rs` landed
  (commit 50e2bda). Migrated the top-level `validate_report_payload`
  walker to `CrossNetworkReportPayloadView` (15 typed fields: 1
  required String `suite` + 8 optional scalars + 4 optional nested
  `Map<String, Value>` slots + 2 optional `Vec<Value>` artifact
  lists, plus `#[serde(flatten)] extra`). The 5 named helpers
  (`path_evidence_from_status_line`, `path_evidence_from_report`,
  `artifact_list_has_basename`, `resolve_optional_path_evidence`,
  `value_as_non_empty_string`) were INTENTIONALLY left as `Value`
  walks — rationale: the first parses inline KEY=VALUE strings,
  the second reads a sidecar JSON, the others are generic 1-line
  helpers over `&[Value]` / `Option<&Value>`. The walker now drives
  these helpers from typed-shape-pinned `Map`/`Vec` slots instead
  of `payload.as_object().get(...).as_array()` walks. 4 new tests.
* `[~]` Third X2 slice on `ops_cross_network_reports.rs` landed
  (commit ba49ed8). Migrated `validate_ssh_trust_summary_artifact`
  (key=value text parser, not JSON) to
  `CrossNetworkSshTrustSummaryView` + `CrossNetworkSshTrustTargetView`
  substruct (18 typed slots: 5 top-level `Option<String>` scalars
  + `Option<usize>` `target_count` + `Option<String>` `target_count_raw`
  + `Vec<CrossNetworkSshTrustTargetView>` of 6 `Option<String>`
  per-target scalars; plus `extra: HashMap<String, String>` ride-through).
  4 new tests pin clean parse, missing required field, wrong-type,
  into_key_value_map round-trip.
* `[ ]` Remaining Phase A walks in
  `ops_cross_network_reports.rs` (future slices):
  - the 5 helpers above (kept as `Value` walks intentionally — only
    migrate if a future restructuring makes typed views worth it)
  - `validate_report_paths` post-parse `git_commit`/`status` re-walk
  - nested `path_evidence` block walkers
* `[x]` ops_live_lab_failure_digest.rs typed-view migration
  landed (commit b2f8b1c). Added 4 typed views
  (`DigestNodeView`, `DigestFailedWorkerView` with 13 typed fields,
  `DigestStageEntryView` with 12, `LiveLabFailureDigestView` with
  10) covering the full failure-digest report shape. All 5 of the
  module's Value walks eliminated; JSON output now goes through
  `serde_json::to_string_pretty(&digest)` against the typed
  struct. 17 new tests pin clean parse / missing-required-field /
  wrong-type / `into_value_map` round-trip per view + a
  null-bridge round-trip for `first_failure: Option<...>`.
* `[~]` First X2 slice on `ops_live_lab_orchestrator.rs` landed
  (commit 6469306). Migrated `is_plaintext_no_leak_report` and its
  caller `execute_ops_verify_no_leak_dataplane_report` to
  `LiveLabOrchestratorNoLeakReportView` (2 required typed fields:
  `status: String` + `checks: Map<String, Value>`, plus `extra`
  flatten and an `into_value_map()` bridge). 11 new tests pin the
  contract (5 view-shape tests + 5 report-validator tests + 1
  serde round-trip). Walks removed from this validator: 4
  `.get/as_str/as_object` calls + caller's manual
  `payload.as_object()` adapter.
* `[~]` Second X2 slice on `ops_live_lab_orchestrator.rs` landed
  (commit 60b05cb). Migrated
  `execute_ops_write_live_linux_lab_run_summary` (lines
  1432-1700, the prime next target) to FOUR typed views:
  - `RunSummaryNodeView` (4 typed fields: label, target, node_id,
    bootstrap_role)
  - `RunSummaryWorkerView` (12 typed fields: 11 strings + rc:i64)
  - `RunSummaryStageView` (10 typed fields: 7 strings + rc:i64
    + failed_worker_count:u64 + worker_results: Vec<...>)
  - `LiveLabRunSummaryView` (14 typed fields: 8 strings + 4 u64
    + nodes/stages arrays)
  16 new tests (clean parse / missing-required / wrong-type /
  into_value_map round-trip per view).
* `[~]` Third X2 slice on `ops_live_lab_orchestrator.rs` landed
  (commit 185b213). Migrated
  `execute_ops_validate_cross_network_forensics_bundle` (lines
  1090-1275, the prime next target) to THREE typed views:
  - `CrossNetworkForensicsManifestView` (4 typed fields with
    serde-default to preserve missing-field-tolerant legacy
    semantics)
  - `CrossNetworkForensicsNodeReportView` (7 required typed
    fields)
  - `CrossNetworkForensicsBundleValidationView` (16 required
    typed fields)
  15 new tests; target fn now has ZERO Value walks.
* `[~]` Fourth X2 slice on `ops_live_lab_orchestrator.rs` landed
  (commit 8a42e8f). Migrated
  `execute_ops_write_live_linux_server_ip_bypass_report` (the
  next prime target from the remaining-walks list) to THREE
  typed views:
  - `LiveLinuxServerIpBypassChecksView` (5 typed `pass`/`fail`
    slots + an `overall_status` helper that names each slot
    explicitly so a future field drop trips a per-slot test).
  - `LiveLinuxServerIpBypassEvidenceView` (6 `String` + 2
    `Vec<String>` slots covering the evidence block).
  - `LiveLinuxServerIpBypassReportView` (10 typed fields
    including nested check + evidence views).
  Removes the two trailing `Value` walks (overall-status
  calculation + status echo on return). 7 new tests pin the
  contract (clean serde round-trip / overall_status pass + fail
  per-slot / missing required field / wrong-type / writer-output
  parsed back through the typed view / fail-path-route).
* `[~]` Fifth X2 slice on `ops_live_lab_orchestrator.rs` landed
  (commit 58e2700). Migrated
  `execute_ops_write_live_linux_control_surface_report` (the
  next prime target after the server-IP-bypass slice) to SIX
  typed views:
  - `LiveLinuxControlSurfaceHostChecksView` (4 pass/fail slots)
  - `LiveLinuxControlSurfaceHostEvidenceView` (3 String + 1
    `Vec<String>` slot)
  - `LiveLinuxControlSurfaceHostResultView` (per-host combo)
  - `LiveLinuxControlSurfaceAggregateChecksView` (5 pass/fail
    slots = 4 all_X reductions + remote-DNS probe verdict)
  - `LiveLinuxControlSurfaceEvidenceView` (1 slot)
  - `LiveLinuxControlSurfaceReportView` (10 typed top-level
    fields)
  Removes 8 trailing `Value` walks (4 per-host check fetches
  × 4 all_X aggregations + status-return echo). `hosts` stays
  `Map<String, Value>` so caller-supplied host_labels insertion
  order is preserved (the workspace's serde_json is built with
  `preserve_order`); per-host shape pinned via separate typed-view
  tests. 6 new tests including a host-label-order regression test
  that would fire if a future refactor swapped `Map<String, Value>`
  for a `BTreeMap`-backed alternative.
* `[~]` Sixth X2 slice on `ops_live_lab_orchestrator.rs` landed
  (commit a724fba). Migrated
  `execute_ops_write_live_linux_endpoint_hijack_report` to
  THREE typed views:
  - `LiveLinuxEndpointHijackChecksView` (7 pass/fail slots +
    `overall_status` helper)
  - `LiveLinuxEndpointHijackEvidenceView` (8 typed String slots)
  - `LiveLinuxEndpointHijackReportView` (9 typed top-level fields)
  Removes 2 trailing `Value` walks (overall-status compute +
  status-return echo). 6 new tests pin the contract (round-trip /
  per-slot fail / missing required / wrong-type / writer-output
  parsed back through the typed view).
* `[~]` Seventh X2 slice on `ops_live_lab_orchestrator.rs` landed
  (commit 1f38e59). Migrated
  `execute_ops_write_real_wireguard_exitnode_e2e_report` to TWO
  typed views:
  - `RealWireguardExitnodeE2eChecksView` (6 pass/fail slots +
    `overall_status` helper)
  - `RealWireguardExitnodeE2eReportView` (8 typed top-level fields,
    no evidence sub-block)
  Removes 2 trailing `Value` walks. 5 new tests including
  environment-default fallback semantics pin.
* `[~]` Eighth X2 slice on `ops_live_lab_orchestrator.rs` landed
  (commit 02a9e04). Migrated
  `execute_ops_write_real_wireguard_no_leak_under_load_report`
  to THREE typed views:
  - `RealWireguardNoLeakUnderLoadChecksView` (6 pass/fail slots +
    `overall_status` helper)
  - `RealWireguardNoLeakUnderLoadMetricsView` (3 u64 counter
    slots — pins counter type so a future widen to
    `Value::String` trips a test)
  - `RealWireguardNoLeakUnderLoadReportView` (10 typed top-level
    fields including a `Vec<String>` source_artifacts list)
  Removes 2 trailing `Value` walks. 6 new tests including a
  numeric-source-artifact regression that pins the typed
  `Vec<String>` boundary against future schema drift.
* `[~]` Ninth X2 slice on `ops_live_lab_orchestrator.rs` landed
  (commit e94edcb). Migrated
  `execute_ops_write_active_network_signed_state_tamper_report`
  to FOUR typed views:
  - `ActiveNetworkSignedStateTamperChecksView` (5 pass/fail slots
    + `overall_status` helper)
  - `ActiveNetworkSignedStateTamperHostsView` (typed exit_host +
    client_host pair)
  - `ActiveNetworkSignedStateTamperEvidenceView` (3 typed slots)
  - `ActiveNetworkSignedStateTamperReportView` (9 typed top-level
    fields)
  Removes 2 trailing `Value` walks. 6 new tests including a
  writer-integration test that re-parses output through the typed
  view to pin host-pair round-trip.
* `[~]` Tenth X2 slice on `ops_live_lab_orchestrator.rs` landed
  (commit 8812b9d). Migrated
  `execute_ops_write_active_network_rogue_path_hijack_report`
  to FOUR typed views:
  - `ActiveNetworkRoguePathHijackChecksView` (7 pass/fail slots
    + `overall_status` helper)
  - `ActiveNetworkRoguePathHijackHostsView` (typed exit/client
    host pair, kept separate from the signed-state-tamper
    siblings to keep experiment-specific evolution decoupled)
  - `ActiveNetworkRoguePathHijackEvidenceView` (6 typed slots)
  - `ActiveNetworkRoguePathHijackReportView` (10 typed top-level
    fields including the rogue_endpoint_ip echo)
  Removes 2 trailing `Value` walks. 5 new tests including a
  writer-integration test that re-parses through the typed view.
  Closes the writer side of the X2 Phase A list.
* `[ ]` Remaining Phase A walks in `ops_live_lab_orchestrator.rs`
  (2 production walks across 1 helper + 1 intentional generic
  JSON-pointer reader):
  - `e2e_dns_query` (helper)
  - `execute_ops_read_json_field` (intentional generic shape-agnostic
    JSON-pointer reader — must stay Value-walk)
* Each is an incremental slice.

### X3. Logging hardening audit (no-secret-leakage sweep)

* `[x]` `crates/rustynetd/src/secret_log_audit.rs` — static source-walk
  audit gate covering every `.rs` file under `crates/rustynetd/src/`
  and `crates/rustynet-cli/src/`. Two complementary detection forms:
  - **Forbidden placeholder tokens** inside log/print/format macros:
    `passphrase_bytes`, `private_key_bytes`, `signing_key_bytes`,
    `wrapped_secret`, `decrypted_secret`, `plaintext_key`,
    `raw_passphrase`, `secret_bytes`. Catches the common shape where
    a debug-time `eprintln!("...{passphrase_bytes:?}")` slips through
    review. Matches `{token}`, `{token:?}`, `{token:x?}` placeholder
    forms; ignores commented-out lines and path-only log strings.
  - **Forbidden `Debug` derive / impl** on canonical secret-bearing
    types (`PassphraseMaterial`, `WrappedKeyMaterial`,
    `RuntimePrivateKey`, `SigningKeyMaterial`). The no-`Debug`-derive
    pattern is the structural guarantee that `{:?}` cannot leak inner
    bytes; the audit pins it so a future refactor that adds
    `#[derive(Debug)]` trips a named test failure.
  Sweep over current tree found zero offenders. 12 self-tests pin the
  audit logic itself (positive + negative shapes for each scan).
  Audit module is allow-listed from the placeholder scan because it
  necessarily mentions the forbidden tokens as constants.
* `[~]` X3 extension landed (commit 38441fc). Three new scanners +
  workspace sweeps:
  - `scan_source_for_hex_encoded_secret_log_sites` — flags
    `hex::encode(forbidden_ident)` and `format!("{:02x}…",
    forbidden_ident[..])` shapes inside log macros.
  - `scan_source_for_base64_encoded_secret_log_sites` — flags
    `base64::*encode(forbidden_ident)` / `STANDARD.encode(...)`
    shapes inside log macros (covers legacy and fully-qualified
    forms).
  - `scan_source_for_display_on_secret_types` — mirrors the
    existing Debug scanner; forbids `impl Display for X` /
    `impl fmt::Display for X` / `impl ToString for X` for the
    canonical secret-bearing types.
  3 new workspace sweeps + 13 new self-tests. Sweep over the
  current tree found 0 offenders; no allowlist extensions needed.
* `[~]` X3 extension #2 landed (commit 8bc02ce). Converts the
  grep-based static analysis in
  `scripts/ci/security_regression_gates.sh` into a typed Rust
  scanner: `scan_source_for_secret_material_equality` flags
  `==`/`!=` against forbidden tokens (token / csrf / session_key /
  nonce / mac / hmac / session_id / signature) unless `ct_eq`
  appears on the line OR the (file,line) is in a structured
  `REVIEWED_SECRET_EQUALITY_EXCEPTIONS` allowlist with per-entry
  justification. Removes fragile `// EXCEPTION:` magic-comment
  allowlist. Workspace sweep finds 0 unallowed hits today. Shell
  script shrunk from 56 lines to ~10. 6+ self-tests pin the
  scanner positive/negative shapes.

### X4. Test coverage gaps in `*_runtime_acls.rs` / `*_service_hardening.rs` / `*_dns_failclosed.rs`

* `[~]` `windows_dns_failclosed` parity slice landed (commit
  pending). 14 new tests close shape parity with the Linux side:
  - IPv4 link-local interface DNS (`169.254.169.254`,
    cloud-metadata) → reject
  - IPv6 link-local interface DNS (`fe80::1`,
    RA-installed) → reject
  - IPv4 / IPv6 unspecified interface DNS (`0.0.0.0`, `::`) → reject
  - NRPT rule forwarding to IPv6 link-local → reject
  - NRPT rule forwarding to `::ffff:8.8.8.8` IPv4-mapped external
    → reject (catches the "looks loopback-adjacent" leak)
  - NRPT rule forwarding to `fe80::1%6` zoneid-suffixed link-local
    → unparseable / drift
  - NRPT rule forwarding to bracketed `[::1]` URL form → unparseable
  - Multiple off-loopback entries on one interface → each surfaces
    independently (no short-circuit)
  - Empty snapshot (no interfaces, no NRPT rules) → missing
    root-coverage drift
  - Sub-namespace-only NRPT rule with no root rule → missing
    root-coverage drift
  - Root rule plus clean sub-namespace rule → pass
  - `schema_version=0` (downgrade) → reject with the observed
    value in the reason
  - IPv6-family interface carrying IPv4 address → family-mismatch /
    unparseable drift
  Module test count: 32 → 46. Regression-coverage gate floor bumped
  accordingly. Also bumped `windows_authenticode:21→38` floor that
  was lagging the W5 thumbprint-policy expansion.
* `[~]` `windows_paths` test coverage parity sweep landed (commit
  3c0053a). 15 new named drift tests covering the SDDL grant/deny
  matcher (`sddl_grants_principal`, `sddl_denies_principal` —
  including the substring-match negative), the local-secret ACL
  evaluator (WD/AU/BU/AN forbidden-grant rejection + missing-owner
  / missing-DACL rejection + service-SID + LocalSystem accept),
  and the runtime-path validator (UNC reject, user-temp reject,
  canonical ProgramData accept). `windows_paths` test count
  46 → 61; new regression-coverage floor `windows_paths:61` added.
* `[~]` Linux-side coverage expansion sweep (commits 2d2e963,
  1c8be79, 22e38b4):
  - `linux_authenticode` test count 3 → 22 (+19 named drift tests
    covering applicability/reason invariants, schema_version pin,
    determinism, serde round-trip + value-level round trip, drift
    mutation detection per field, canonical serialized snapshot
    pin). Floor bumped from 3 → 22.
  - `linux_mesh_status` test count 10 → 24 (+14 tests covering
    freshness boundary (==max accepted, max+1 rejected, 0/0 case),
    missing-peer aggregation, exotic peer-id chars, schema_version
    pin, per-variant serde round-trip with `load_status` tag,
    forgiving-schema forward-compat). Floor bumped 10 → 24.
  - `linux_runtime_acls` test count 19 → 27 (+8 named drift tests
    covering reviewed-roots-list snapshot, schema_version pin,
    Missing-variant serde round-trip, unknown-tag rejection, high
    mode-bit masking, symlink-before-dir-check ordering, symlink +
    mode drift first-fault precedence, vacuous-truth documented
    behavior on empty-roots). Floor bumped 19 → 27.
  - `linux_key_custody` test count 15 → 24 (+9 named drift tests
    covering schema_version pin, per-variant serde round-trip on
    Ok/Invalid/Forbidden, unknown-status-tag rejection,
    unknown-requirement-string rejection, multi-entry drift
    aggregation (no short-circuit), Forbidden-on-required-entry
    inverted shape, AbsentAsExpected-on-required-entry collector
    bug shape). Floor bumped 15 → 24.
* `[ ]` Remaining scope (separate slice): consider whether a
  dedicated `windows_runtime_acls.rs` module is justified now that
  the SDDL surface has explicit drift coverage. Today the
  `windows_paths` + `windows_service_hardening` split holds up;
  pulling the SDDL helpers into a third module would add little
  value beyond reshuffling. Defer until a future addition makes
  the dedicated module worth it.

### X5. Membership evidence + runbook automation

* `[x]` Commit pending. `rustynet membership generate-evidence` now
  emits two additional artifacts alongside the existing conformance
  / negative / recovery reports + audit-integrity log:
  - `membership_evidence_diff.json` — structured delta vs the prior
    `membership_conformance_report.json` at the same output path.
    Records `prior_evidence_present`, `prior_parse_error`, and
    every prior_*/current_*/delta triple for epoch, entries,
    active-node count, state-root (with `state_root_changed` bool),
    and `captured_at_unix` (`captured_at_delta_secs`). Prior_*
    fields are JSON `null` on first run so consumers can distinguish
    "no prior" from "prior=0".
  - `membership_conformance_report.prior.json` — byte-for-byte
    snapshot of the prior conformance report (when present) so the
    diff is reproducible.
  - `membership_audit_replay.json` — self-contained operator-facing
    JSON pointing at the audit log file. Records environment,
    captured_at_unix, epoch, entries_count, active_node_count,
    state_root, audit_log_path, source_log_path, replay_status="ok".
    Does NOT re-encode log entry bodies (those live in the audit
    log file) — security invariant pinned by a key-allowlist test
    that fails if a future refactor adds an `entries` field.
  12 new tests pin the artifact shapes: parser round-trip + 2
  fail-closed shapes for the prior-evidence reader; 6 diff-builder
  shapes including null-prior first-run, positive/negative deltas,
  state-root-changed false case, environment-escaping safety, and
  JSON round-trip; 3 audit-replay shapes including the no-leak
  invariant.

### X6. CLI ergonomics + exit-code taxonomy

* `[~]` Shared `rustynetd::exit_codes::ExitCode` enum landed
  (commit pending). Six-variant taxonomy aligned with
  `sysexits.h`: 0/`success`, 1/`generic_failure`, 64/`bad_args`,
  65/`config_error`, 70/`transient_failure`, 78/`policy_reject`.
  Each variant carries `as_i32()` + `label()` + `operator_hint()`
  helpers plus a `Display` impl. Two top-level entry points use
  the taxonomy today:
  - `crates/rustynetd/src/main.rs` →
    `classify_top_level_error` maps the startup-error string to a
    taxonomy bucket and exits with the matching numeric code.
  - `crates/rustynet-cli/src/main.rs` →
    `classify_cli_error` maps `execute()` failures + adds an
    operator-facing hint and a JSON `exit_code` / `exit_label`
    pair when `--json` is in scope.
  21 tests pin the contract: numeric values, label stability,
  pairwise distinctness, sysexits.h alignment, operator-hint
  retry-safety wording, plus per-classifier test coverage for both
  entry points (bad args / policy reject / config / transient /
  generic fallback / precedence ordering).
* `[x]` Runbook: `documents/operations/CliExitCodeTaxonomy.md`
  documents the operator decision rules, the CI retry contract
  (retry only on 70), and the systemd integration guidance
  (`RestartPreventExitStatus=64 65 78`). Initial runbook landed
  with the shared taxonomy in commit f48681b; surface-coverage
  section refreshed to reflect the round-2 batches that migrated
  every bin/*.rs binary off legacy `exit(1)` (commit pending).
* `[~]` First batch of bin/ binaries migrated (commit pending):
  - `security_regression_gates.rs` — repo-root resolve →
    ConfigError(65); cargo-spawn failure → TransientFailure(70);
    subprocess code passes through.
  - `active_network_security_gates.rs` — same pattern.
  - `no_leak_dataplane_gate.rs` — platform-mismatch ("requires
    Linux") and root-required preconditions now exit
    PolicyReject(78) instead of `1`; uid/cmd helpers exit
    ConfigError / TransientFailure as appropriate; subprocess
    codes pass through so the inner CLI's X6 taxonomy bucket
    bubbles up intact.
  Each bin imports `rustynetd::exit_codes::ExitCode` and uses
  `as_i32()` + the Display impl to print `error [label (N)]: ...`.
  Pattern documented in commit; ~57 more bin/ binaries remain on
  legacy `exit(1)`. Each future migration is a small,
  independently-reviewed change.
* `[~]` Parallel-batch migration: 29 more bin/ binaries threaded
  in one batch (commits f6e71fc, 3366e22, a073b12, 1b47a2b):
  - phase-gate bins (11): `phase[1,3-10]_gates.rs`,
    `phase10_cross_network_exit_gates.rs`,
    `phase10_hp2_gates.rs` — uniformly repo-root→ConfigError /
    cargo-spawn→TransientFailure / subprocess→pass-through.
  - collect bins (6): `collect_phase1_measured_env.rs`,
    `collect_phase9_raw_evidence.rs`, `collect_platform_probe.rs`,
    `collect_platform_parity_bundle.rs`,
    `collect_linux_reconnect_bundle.rs`,
    `collect_network_discovery_info.rs` — same shape plus
    classify_local_error for the two with richer argv surfaces.
  - release/security/membership bins (7): `membership_gates.rs`,
    `membership_incident_drill.rs`,
    `supply_chain_integrity_gates.rs`,
    `release_readiness_gates.rs`, `role_auth_matrix_gates.rs`,
    `fresh_install_os_matrix_release_gate.rs`,
    `traversal_adversarial_gates.rs` — security-sensitive
    binaries map fail-closed verdicts (tampering, attestation,
    integrity, drift) to PolicyReject(78) instead of through-pass
    so retry-only-on-70 CI loops never accidentally retry a real
    fail-closed verdict.
  - live-linux tests (5): `live_linux_{lan_toggle, managed_dns,
    server_ip_bypass, control_surface_exposure,
    endpoint_hijack}_test.rs` — verbatim `classify_live_lab_error`
    helper from the existing exemplars. 4 of the 5 also got an
    `Result<(), i32>` → `Result<(), String>` conversion so the
    classifier sees real error messages instead of pre-translated
    integers.
  Combined coverage: 37 of ~60 bin/ binaries now on the X6
  taxonomy (out of an initial 0).
* `[x]` Round 2 parallel batch completes the X6 bin/ migration
  (commits 34d0960, 44980f7, e525668, dd63287). All ~71 bin/*.rs
  binaries under `crates/rustynet-cli/src/bin/` now classify their
  failure shapes through `rustynetd::exit_codes::ExitCode`:
  - check_* (8): bootstrap_ci_tools + 7 check_*; dep-exception,
    unsafe-detected, backend-boundary-leak → PolicyReject
  - generate_* + real_wireguard_*_e2e (8): e2e leak/hijack/tamper/
    signature-mismatch verdicts → PolicyReject
  - run_/install/misc (8): perf-regression, macos-only-host
    mismatch, install hardened-contract violation → PolicyReject
  - validation/cross-network/misc (10): release attestation
    failure, secrets-hygiene leak, trust-CLI decrypt failure → PolicyReject
  In every batch, subprocess exit codes pass through unchanged so
  inner taxonomy bubbles survive the wrapper.
* `[~]` Shell→Rust gate conversion: `scripts/ci/membership_gates.sh`
  JSON-validation (commit 18521df). Replaces grep/jq-style shell
  assertions on the Phase 10 membership report with a typed Rust
  subcommand `rustynet ops verify-membership-phase10-report
  [--report-path <path>]`. New `MembershipPhase10ReportView`
  serde view pins two required fields (status, evidence_mode);
  missing file → ConfigError(65); malformed JSON → ConfigError(65);
  missing required field → ConfigError(65); `status=fail` →
  PolicyReject(78). 5 new tests pin the verdict shapes. Shell
  script shrunk 37→25 lines, now a thin dispatcher.
* W3 wire-up: `--enforce-ra-suppression` flag (commit 527d14f)
  threads the W3 Router Advertisement evaluator into the
  `windows-dns-failclosed-check` subcommand alongside
  `--enforce-ipv6-sibling-rules`. 3 new flag-handler tests + help
  pin.
* W4 wire-up: new `rustynetd windows-registry-acls-check
  [--no-fail-on-drift]` subcommand (commit 527d14f) calls the W4
  stub collector. Today defaults fail-closed because the Win32
  RegGetKeySecurity probe is still a follow-up slice. 4 new tests
  pin the flag handler + default verdict.

### X7. CI gate enhancements

* `[x]` Commit 255cff4 follow-up: `scripts/ci/regression_coverage_gates.sh`
  runs each platform-specific verifier module's tests and asserts the
  passing-test count is at least the pinned floor. 11 modules pinned
  today: 6 Linux (`linux_runtime_acls`, `linux_service_hardening`,
  `linux_dns_failclosed`, `linux_mesh_status`, `linux_key_custody`,
  `linux_authenticode`) + 5 Windows (`windows_service_hardening`,
  `windows_dns_failclosed`, `windows_mesh_status`, `windows_key_custody`,
  `windows_authenticode`). Floors set to current pass counts so any
  refactor that silently removes a drift-test group trips a named
  failure. `--platform linux|windows|all` flag scopes to one group.
  Exit code taxonomy: 0 ok / 1 floor breach / 64 bad args.

---

## Working order proposal

Order chosen for breadth-first wins, low blast radius first:

1. **X1** `--json` on status/netcheck — cross-platform, low risk, high
   operator value.
2. **L5** Linux mesh-status typed view — small Phase A slice, cleans
   up a Linux validator.
3. **W1** PowerShell helper JSON outputs — unblocks W7 (Windows runtime
   path) and the VM-lab orchestration story.
4. **W2** Windows service hardening SDDL/SidType drift — bounded test
   coverage growth.
5. **L2** Linux runtime-ACL IPv6 + chain integrity drift.
6. **L1** start.sh modularization (GAP-10) — bigger, do it after the
   smaller wins.
7. **X3** logging-hardening audit — broad cross-cutting sweep, do this
   after the platform-specific drift detectors are tight.
8. **X2** Phase A continuation in parallel with the above.
9. **W7** Windows install-release real runtime path — largest piece,
   tackle once W1-W6 are landed.

Each item gets:
- code + tests on a fresh commit
- cargo fmt/clippy/test + workspace gate sweep
- live-lab confirmation (`ops vm-lab-orchestrate-live-lab`) on the
  current commit before push
- mark `[x]` here with the commit SHA on landing

---

## Out of scope for this backlog

- NAT traversal / UDP hole punching / relay work — see
  PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md.
- Live cross-network evidence collection — see Phase E of
  PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md and the OpenWorkIndex
  P0 items. Needs distinct-WAN topology that the in-tree 3-VM lab
  cannot synthesize.
- Fresh-install OS matrix evidence refresh — needs Debian/Ubuntu/
  Fedora/Mint VMs.
