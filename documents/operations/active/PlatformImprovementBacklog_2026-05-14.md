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
* `[ ]` Remaining scope (separate slice): incrementally migrate the
  larger platform-specific blocks from start.sh into the
  per-platform modules:
  - systemd-unit install / `run_root` calls → `linux.sh`
  - launchd plist install / `pfctl` programming / Keychain
    secret-store wiring → `macos.sh`
  - `apply_host_profile_defaults` (currently a 40-line cond block in
    start.sh) → split into `__linux_apply_profile_defaults` and
    `__macos_apply_profile_defaults` in the respective modules
  Each future migration adds another smoke-test check that pins
  the migrated function's reviewed behaviour.

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
* `[ ]` Remaining Phase A typed views (next slices):
  - cross-network reports (`ops_cross_network_reports.rs` — large)
  - live-lab summary / failure digest (further `Value` walks)
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
* `[ ]` Remaining scope (separate slice): bring
  `windows_runtime_acls` to standalone module parity with Linux
  (today the Windows ACL surface lives inside
  `windows_service_hardening` and `windows_paths`). Add a dedicated
  `windows_runtime_acls.rs` module if/when the surface justifies it.

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
* `[ ]` Runbook: `documents/operations/CliExitCodeTaxonomy.md`
  documents the operator decision rules, the CI retry contract
  (retry only on 70), and the systemd integration guidance
  (`RestartPreventExitStatus=64 65 78`).
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
* `[ ]` Remaining scope (separate slice): continue threading
  through the remaining ~23 bin/ binaries under
  `crates/rustynet-cli/src/bin/`.

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
