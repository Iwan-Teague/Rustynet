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

* `[ ]` Split `start.sh` into `scripts/start/common.sh`,
  `scripts/start/linux.sh`, `scripts/start/macos.sh`. Keep shared policy
  validation in the common layer.
* Source: GAP-10 in
  [CrossPlatformSecurityGapRemediationPlan_2026-03-05.md](./CrossPlatformSecurityGapRemediationPlan_2026-03-05.md).
* Why: reduces blast radius when macOS-only patches accidentally break
  Linux paths.
* Acceptance: every existing start.sh integration test passes; nothing
  changes in operator-visible behaviour; net file count grows but no
  single file owns >40% of the prior surface.

### L2. `linux_runtime_acls.rs` IPv6 + named-chain integrity hardening

* `[ ]` Extend the runtime-ACL drift detector to assert:
  - IPv6 parity for the v4 rules already covered (drop-all default-deny,
    tunnel-only egress)
  - named-chain integrity (every chain that should exist is present and
    in the expected `rustynet-*` hook)
  - socket-activation rule presence on systemd-managed deployments
* Acceptance: new unit tests, snapshot-fixture coverage, no behaviour
  change for currently-passing systems.

### L3. `linux_service_hardening.rs` systemd sandbox-flag pinning

* `[ ]` Extend the systemd-unit drift signature to assert pinned values
  for `MemoryDenyWriteExecute=yes`, `RestrictNamespaces=`,
  `SystemCallFilter=`, `CapabilityBoundingSet=`, `NoNewPrivileges=yes`.
* Acceptance: new unit tests cover present + drifted + missing cases;
  fixture covers a representative Debian 12 service file.

### L4. `linux_dns_failclosed.rs` race + edge cases

* `[ ]` Race-on-startup hardening: detect `systemd-resolved` listening
  before the rustynet resolver claims its socket; reject NetworkManager
  precedence overrides; add link-local resolver bypass scenario.
* Acceptance: new unit tests with fixture snapshots for each race shape.

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

* `[ ]` Tighten passphrase-file mode/owner check (already 0600 + owner
  match); add cross-boot stability tests (write → reboot fixture → read
  → match) and assert no plaintext passphrase survives a normal-shutdown
  daemon restart.

### L7. Linux exit ACL IPv6 parity

* `[ ]` Audit exit-node ACL/firewall programming for IPv6 gaps (any rule
  that's IPv4-only must have an IPv6 sibling unless explicitly scoped).
* Acceptance: new gate test enumerates `ip` vs `ip6` rule counts and
  fails closed when a security-bar rule is v4-only.

### L8. Linux killswitch boot-time enforcement

* `[ ]` Make sure the killswitch nftables rules apply *before* the
  WireGuard interface comes up at boot; today the systemd-unit ordering
  is mostly correct, but there's a small window where traffic could leak
  if the unit is restarted.
* Acceptance: integration test reboots a netns lab node and asserts no
  unprotected egress packets observed in the bring-up window.

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
  * `[ ]` Install helper: success-path shape parity audit + typed view
    (next slice; shape already consistent at schema_version=1, just
    needs typed view + tests).
  * `[ ]` Bootstrap helper per-phase shape audit (multiple JSON
    shapes; largest helper surface).

### W2. `windows_service_hardening.rs` SDDL + SidType drift hardening

* `[ ]` Extend the SCM-side drift signature to pin:
  - `ServiceSidType=restricted` (or the strictest tier the platform
    permits — re-check B.8.1 status in SecurityHardeningAudit)
  - SDDL deny-list for the dangerous principals already named in the
    constant set (WD, AU, BU)
  - non-interactive `LocalSystem` (today usually so, but assert)
* Acceptance: existing tests pass; new tests cover drifted SDDL, missing
  SidType, interactive flag set.

### W3. `windows_dns_failclosed.rs` IPv6 NRPT + RA suppression

* `[ ]` Extend the NRPT validator to require an IPv6 sibling rule for
  every IPv4 NRPT entry that maps the rustynet zone; add on-link Router
  Advertisement suppression check (no native IPv6 default route during
  protected mode); reject newer NRPT rule shapes that bypass the
  loopback resolver.
* Acceptance: new unit tests + fixture snapshots.

### W4. `windows_runtime_acls.rs` registry + service ACL drift extension

* `[ ]` Match Linux runtime-ACL coverage: registry keys under
  `HKLM\\SYSTEM\\CurrentControlSet\\Services\\RustyNet*` ACL drift,
  service config-store DACL drift.

### W5. `windows_authenticode.rs` thumbprint pinning + revocation deny-list

* `[ ]` Today the validator only reports a "trusted" boolean. Pin by
  Authenticode cert thumbprint; add deny-list of revoked thumbprints; on
  unknown thumbprint, fail closed with a precise reason code.
* Acceptance: positive (matched thumbprint) + negative (revoked,
  unknown) + drift tests.

### W6. `windows_key_custody.rs` DPAPI LocalMachine rotation tests

* `[ ]` DPAPI LocalMachine scope was just landed in `425faa4`. Add tests
  that exercise DPAPI blob rotation + cross-restart re-decryption + the
  fail-closed path when the LocalMachine key is unavailable.

### W7. Windows install-release real runtime path (substantial)

* `[ ]` Currently a protective stub returning
  `runtime-host-not-yet-implemented` per the VmLab capability evaluator
  (`crates/rustynet-cli/src/vm_lab/capability.rs`). Wiring a real
  Windows service/config host into `rustynetd` is the gating piece for
  Windows-as-dataplane outside of NAT-traversal scope.
* Source: VmLab cookbook + WindowsExitAndRelayDeltaPlan.
* Acceptance: large slice; should be tackled after W1-W6 land.

### W8. Windows mesh status hardening

* `[ ]` Typed-schema parse for the mesh-state file the Windows side
  emits; reject malformed/replayed snapshots; mirror L5 on the Windows
  side.

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

* `[ ]` Remaining Phase A typed views per
  [SerializationFormatHardeningPlan_2026-03-25.md](./SerializationFormatHardeningPlan_2026-03-25.md):
  - cross-network reports (`ops_cross_network_reports.rs` — large)
  - discovery bundle validator (`ops_network_discovery.rs`)
  - live-lab summary / failure digest (further `Value` walks)
  - fresh-install OS matrix (`ops_fresh_install_os_matrix.rs`)
  - migrate the four NDJSON consumers in `ops_phase9.rs` to
    `read_ndjson_typed<T>`
* Each is an incremental slice.

### X3. Logging hardening audit (no-secret-leakage sweep)

* `[ ]` Sweep `daemon.rs`, `phase10.rs`, `key_material.rs`, helper
  output for accidental secret leakage in error paths. Add structured
  redaction at the log emit boundary. Add a unit-test pattern that
  asserts known-secret bytes never appear in any error string.

### X4. Test coverage gaps in `*_runtime_acls.rs` / `*_service_hardening.rs` / `*_dns_failclosed.rs`

* `[ ]` Linux side is fairly well-covered; Windows side has fewer
  positive + drift tests. Bring Windows coverage to Linux parity. This
  pairs naturally with the W2/W3/W4 hardening items.

### X5. Membership evidence + runbook automation

* `[ ]` `rustynet membership generate-evidence` already emits JSON;
  extend with diff-since-last-evidence + auto-included audit-log replay
  artifact so the runbook can be a single command.

### X6. CLI ergonomics + exit-code taxonomy

* `[ ]` Standardize exit codes across all `rustynet` / `rustynet-cli`
  surfaces:
  - `0` success
  - `64` invalid input / bad CLI args
  - `65` configuration error
  - `70` transient / retry-safe failure
  - `78` policy / fail-closed reject
  Document the taxonomy in a runbook; thread through every entry point.

### X7. CI gate enhancements

* `[ ]` Add per-platform regression-coverage gates: a script that for
  each of {linux, windows} runs the platform-specific `*_drift_*`
  tests and fails closed on missing fixtures or test counts below a
  pinned floor.

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
