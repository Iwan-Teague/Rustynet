# Rustynet Unified TODO Ledger — 2026-07-10

Status: active repository-wide roll-up

Snapshot date: 2026-07-10

Priority: security first; evidence before claims

## 1. Purpose and tracking contract

This is the large, dated index of unfinished Rustynet work found across the
repository. It combines product, security, live-lab, `--node`, networking,
desktop parity, mobile, service-role, quality, performance, operations, and
release work into one execution view.

This file is a **roll-up, not a replacement for owning ledgers**. Update the
owning plan and this roll-up in the same change. When status conflicts:

1. `documents/Requirements.md` and `documents/SecurityMinimumBar.md` win.
2. The newest focused active ledger and current code/evidence win.
3. Historical session logs and old unchecked boxes do not become active work
   without re-verification.

Legend: `[ ]` open · `[x]` foundation already present · `BLOCKED` means an
external prerequisite is named. “Code complete” never means “live proven.”

## 2. Non-negotiable completion rules

- [ ] No release claim while a release-blocking role × OS cell is unproven.
- [ ] No security claim from unit tests alone where the control mutates a real
  OS, firewall, route table, service manager, key store, or network path.
- [ ] Every security control has an enforcement point, a negative test, and
  measured live evidence where applicable.
- [ ] No dry-run, reported skip, lifecycle-only check, management-plane ping,
  or config-text inspection is promoted as dataplane success.
- [ ] Failure, timeout, abort, incomplete evidence, unknown stage, or corrupt
  evidence dominates any contradictory pass field.
- [ ] Secrets never enter logs, process arguments, source archives, support
  bundles, world-readable files, or JSON FFI payloads.
- [ ] Signed state remains verify-before-apply, replay/rollback protected,
  atomic, fail-closed, and bound to the intended node/network/context.
- [ ] Rust remains the owning implementation. Shell is wrapper-only or retired;
  no second active security-sensitive execution path.
- [ ] Every completed item records commit, exact gate command, artifact path,
  target OS/version, topology/profile, and result in its owning ledger.

## 3. Critical path

Execute in this order unless a focused owning ledger requires a stricter
dependency:

- [ ] **P0 — repair evidence truth and close severe security stages.** Finish
  the stage contract, crash/replay tests, live relay forwarding, residue and
  platform security validators.
- [ ] **P0 — finish and prove the Rust `--node` engine.** Complete structural
  separation, durable evidence finalization, real cancellation, OS fixtures,
  then obtain clean paired Rust/baseline evidence before changing defaults.
- [ ] **P0 — establish the canonical lab network.** Dual-plane management and
  scenario networking; deterministic isolated multi-VM topology; no automatic
  bridge to the everyday LAN.
- [ ] **P0 — close desktop role parity.** Prove all supported role/capability
  cells on Linux, macOS, and Windows; resolve Windows exit and relay forwarding.
- [ ] **P1 — prove cross-network behavior.** NAT matrix, direct/relay/failback,
  DNS fail-closed, path capture, physical lab, and genuinely remote networks.
- [ ] **P1 — stabilize shared mobile core; then Android; then iOS.** Mobile v1
  is client-only and cannot inherit host-daemon assumptions.
- [ ] **P1 — close CI, coverage, fuzz, performance, service roles, evidence
  freshness, and release gates.**

## 4. Live-lab verification program

### 4.1 Stage and evidence infrastructure

- [x] Maintain one typed stage vocabulary and a run-scoped stage manifest.
- [x] Preserve terminal-state taxonomy, run-matrix upsert, and conclusion
  barrier foundations from the stage-contract program.
- [ ] Finish recorder validation: every planned stage must emit start and one
  terminal outcome; reject duplicates, disappearance, and post-final mutation.
- [ ] Route remaining bash stages through the shared per-stage recorder until
  bash is retired; expose truthful job state and heartbeat in `report_state`.
- [ ] Enforce coverage-as-code in CI with reviewed, expiring exceptions; do not
  merely generate the coverage report.
- [ ] Put security stages behind the abnormal-termination/conclusion barrier.
- [ ] Make evidence-contract completeness release-gating: manifest, stage rows,
  logs, report state, summary, parity snapshot, artifacts, hashes, and matrix
  row must agree.
- [ ] Add `StageCategory`, a dedicated SECURITY view, and accurate grouping to
  `rustynet-lab-monitor`.
- [ ] Make every supported `disabled_stages` toggle affect the real plan, or
  reject unsupported toggles. Remove the current misleading no-op behavior.
- [ ] Sync the security coverage ledger with the stage registry and current
  code after every security-stage batch.
- [ ] Add current stage-by-stage, OS-by-OS, distro/version, backend, and network
  profile coverage output. Distinguish never-run, never-passed, regressed,
  stale-green, blocked, and unsupported-by-design.
- [ ] Validate the TUI and MCP views against corrupt, missing, stale, concurrent,
  resumed, and aborted run data.
- [x] Fix the run-matrix updater rejecting the Linux umbrella OS family: a Rust
  `--node` Linux run finalized with `unrecognized OS family for fetched version
  'linux' (platform=linux); refusing Linux-umbrella evidence` and appended no
  `live_lab_run_matrix.csv` row, so even a green Linux `--node` run left no
  §10.9 evidence row (2026-07-11, runs `state/live-lab-smoke-setup-1..3`). Root
  cause was upstream, not the finalizer: `NodeAdapter::collect_os_version`
  (linux/macos/windows) did a single SSH probe and, on a transient
  first-connection timeout, silently degraded to a bare platform placeholder
  (`"linux"`/`"macos"`/`"windows"`) — which the finalizer's `normalize_os_family`
  correctly refuses, but the refusal then dropped the ENTIRE per-node append. Fix
  keeps the refusal (evidence truth) and repairs the source: the OS-version probe
  now retries transient SSH (`ssh::run_remote_retrying`, 3 attempts, 500ms→5s
  backoff), and the native orchestrator's collection loop validates each fetched
  version against the single `normalize_os_family` authority and fails loud,
  early, and attributably instead of recording a placeholder that silently voids
  the matrix append (mobile unsupported-by-design adapters are exempt). Regression
  tests: `normalize_os_family_rejects_bare_platform_umbrella_placeholders`,
  `normalize_os_family_accepts_real_fetched_distro_versions`,
  `run_remote_retrying_exhausts_attempts_and_returns_last_error`,
  `run_remote_retrying_clamps_zero_attempts_to_one`. Gates green on stable
  toolchain (pinned 1.88.0 undownloadable in this env): `cargo fmt --all --
  --check`, scoped `cargo check`/`cargo clippy -p rustynet-cli --all-targets
  --all-features -- -D warnings`, and `cargo test -p rustynet-cli`
  (2298 pass; the 3 unrelated failures are pre-existing environmental flakes —
  a load-sensitive process-timeout timing test that also fails on baseline, plus
  two UTM/`/tmp`-cleanup lab tests that pass in isolation). Live re-proof on a
  real `--node` run still pending lab access.
- [x] The 2026-07-10 quality-hardening commit `e4b3a0e` landed with two failing
  `rustynet-cli` tests — a stale `build_returns_canonical_security_stage_order`
  oracle (listed `ExitDemotionResidueValidation` before its declared dependency
  `ExitNatLifecycleValidation`) and two `transition_local_utm_vm_*` tests that
  shared a nanosecond-only temp-dir prefix and collided under the parallel test
  run. Fixed in `b204579`; full workspace gates green (2297 tests).

### 4.2 Routine verification ladder

- [ ] **L0 static/model gate:** format, check, strict Clippy, unit/integration,
  dependency policy, audit, deny, schema/registry drift, secret hygiene.
- [ ] **L1 deterministic Linux gate:** `crossnet_netns_v1`; NAT/filter/route,
  DNS, MTU, loss, reordering, v4/v6, direct/relay selection, leak capture.
- [ ] **L2 isolated multi-VM gate:** `isolated_multivm_v1`; distinct kernels,
  dual-plane NICs, controlled routers/services, Linux/macOS/Windows.
- [ ] **L3 dedicated physical lab:** controlled interface/VLAN/router/switch;
  DHCP, real offload/driver, UPnP/NAT-PMP/PCP, reboot, link and multicast.
- [ ] **L4 remote wild gate:** at least two genuinely distinct endpoint sites
  plus third-site STUN/relay; ISP, hotspot/cellular, CGNAT, IPv6, roaming, and
  hostile/public-access cases.
- [ ] Require L0–L2 for normal integration claims; L3–L4 for release and “works
  in the wild” claims.

### 4.3 Per-run stage checklist

- [ ] Freeze commit/source mode, inventory, node identities, OS versions,
  clocks, UTM versions, network profile, host VPN/proxy state, and toolchains.
- [ ] Audit network attachment before mutation; preflight approved profile;
  reject silent Shared/Bridged fallback and unapproved interfaces.
- [ ] Prove SSH/control reachability only as management readiness, never as
  product traffic evidence.
- [ ] Clean prior state; then assert absence of daemon/relay processes,
  interfaces, routes, firewall/NAT rules, DNS state, services, and key residue.
- [ ] Bootstrap with exact node identity; verify service hardening, permissions,
  key custody, code signing, and clock tolerance before bundle issuance.
- [ ] Initialize membership and verifier roots; distribute verifier before
  bundle; prove signature, network/node binding, freshness, and replay guards.
- [ ] Enforce baseline; prove allowed all-pairs mesh traffic and active denial of
  unauthorized peers using packet capture, handshake counters, and routes.
- [ ] Exercise admin, client, anchor, exit, blind-exit, relay, NAS, and LLM
  cells assigned to the run; unexecuted cells remain `not_run`.
- [ ] Exercise two-hop, exit handoff, DNS fail-closed, LAN toggle, network flap,
  reboot recovery, enrollment restart, mixed topology, limiter flood, and soak.
- [ ] Exercise chaos/adversarial stages: clock, daemon fault, SIGSTOP/SIGCONT,
  crash recovery, membership/signed-state corruption, network impairment,
  privileged boundary, and resource exhaustion.
- [ ] Exercise cross-network direct, node-network switch, relay fallback,
  failback/roaming, controller switch, adversarial traversal, remote-exit DNS,
  NAT classification/matrix, and soak.
- [ ] Capture endpoint and router boundaries; prove expected direct/relay/exit
  path and zero protected/DNS/overlay leak over wrong interface.
- [ ] Collect redacted diagnostics before cleanup on failure.
- [ ] Always run cleanup; independently verify cleanup residue per OS.
- [ ] Seal evidence and append/upsert one run-matrix row; validate hashes and
  contradictions before returning pass.

### 4.4 Security-stage backlog

- [ ] `RR-01/02/03`: persist replay protection across daemon restart for trust,
  traversal, and enrollment paths; add rollback/corrupt-watermark negatives.
- [ ] `FCF-1`: kill process mid signed-state apply; prove atomic old-or-new state
  and fail-closed restart.
- [ ] `FCF-2`: corrupt persisted state; prove no permissive recovery/default.
- [ ] `FCF-3`: make keystore unavailable; prove daemon cannot apply or expose a
  weaker path.
- [ ] `RPT-01 / HP-3`: prove a real frame traverses relay on every supported OS;
  lifecycle/health alone is insufficient.
- [ ] `S3-10`: live deploy-time macOS code-sign and Windows Authenticode checks.
- [ ] `RSA-0063`: macOS bootstrap privilege-escalation residue validator and
  negative fixture.
- [ ] `KC-04`: Windows key-custody permission/ACL negative path.
- [ ] `PH-7`: macOS privileged-helper allowlist adversarial argv corpus.
- [ ] `KL-2/3/4`: macOS/Windows killswitch and v4/v6 leak parity with active
  probes plus capture.
- [ ] `KC-07`: macOS/Windows secrets-not-in-logs parity; fix and prove RSA-0080
  passphrase cleanup/secure disposal.
- [ ] `CNT-1`: live UPnP SSRF tests for SSDP LOCATION/control URLs.
- [ ] `PH-2/3`: fuzz the live privileged-helper IPC socket and prove cross-UID
  rejection.
- [ ] Add live proof for fixed membership revocation and revocation-blind ACL
  admission bugs; unit fixes alone do not close their threat coverage.
- [ ] Prove audit-chain integrity under removal, reorder, corruption, truncation,
  disk-full, and concurrent-writer conditions.

## 5. Complete the Rust-native `--node` engine

Owning ledger: [RustNativeNodeOrchestratorQualityAudit_2026-07-10.md](./RustNativeNodeOrchestratorQualityAudit_2026-07-10.md).

### 5.1 Remaining correctness and durability

- [ ] RNQ-02: create per-OS live residue fixtures covering process, service,
  interface, route, firewall/NAT, DNS, relay, and key-state leftovers.
- [ ] RNQ-05: fault-inject every evidence writer and finalizer; implement one
  fsync-backed multi-artifact finalization transaction or equivalent recovery
  protocol. No partial pass may survive power/process failure.
- [ ] RNQ-07: implement real process-isolated, cancellable stage deadlines.
  Timed-out privileged work must stop before cleanup; no detached worker.
- [ ] RNQ-09: real subprocess SIGTERM/SIGINT test proving diagnostics, cleanup,
  terminal evidence, and no post-signal mutation.
- [ ] RNQ-15: extract native executor and evidence/finalization blocks from the
  oversized `vm_lab/mod.rs` into narrow modules with explicit interfaces.
- [ ] RNQ-16: make registry metadata, plan construction, validators, docs, MCP,
  and historical oracle generation derive from one typed authority.
- [ ] RNQ-17: split lab robot/orchestrator from the product CLI crate and binary;
  update parser/dispatch, package boundaries, release artifacts, SBOM, signing,
  install paths, and CI so lab-only attack surface does not ship as product.
- [ ] RNQ-20: obtain Fedora passwordless-sudo lab prerequisite without weakening
  policy; run live bootstrap and residue proof.
- [x] Re-run the focused full-mesh topology on a valid shared scenario underlay
  (2026-07-11). Proven on the `mgmt_shared_smoke_v1` shared plane
  (192.168.64.0/24): `traffic_test_matrix` + `mesh_status_validation` green with
  `debian-headless-2:exit` + `debian-headless-4:client`. Evidence rows
  `livelab-1783793580-509e633` (first proof) and `livelab-1783800545-4d04af5`
  (latest), commit-clean, network profile + digest recorded. The 2026-07-10
  isolated-underlay run was not functional mesh proof; this is.
  - Fixed en route (release-blocker): Linux exit→client demotion left
    `net.ipv4.ip_forward=1` — `apply_nat_forwarding` re-captured
    `prior_ipv4_forwarding` on every re-enforce, clobbering the true baseline.
    Reconcile override (`696b8c5`) + capture-once guard (`9c425f5`);
    `exit_demotion_residue_validation` now PASS (live-proven).
  - Fixed 3 orchestrator false-failures unmasked as each upstream stage stopped
    failing: `blind_exit_dataplane_validation` gated to `NodeRole::BlindExit`
    (`0cec075`); `live_two_hop_validation` skips a topology without an entry hop
    (`1f57564`); `live_managed_dns` arg + `--known-hosts-file` wiring
    (`1b33e84`/`4d04af5`).
  - OPEN (well-characterized, tracked): `live_managed_dns_validation` still
    fails — the pinned-known_hosts lookup uses a `host:22` candidate that
    `ssh-keygen -F` will not match against the standard plain-host entry
    (`target_address` in `live_lab_support` does not strip the `:22` port
    suffix). Distinct SSH-pinning bug; intersects §8/§15 managed-DNS evidence.
  - Env note: the orchestrator needs `--utm-documents-root "<UTM images dir>"`
    when lab bundles live outside the default UTM documents root, or
    `discover_local_utm` reports only a stale bundle and fails alias selection.
- [ ] Prevent untracked required Rust modules from being silently absent in
  working-tree deployment, or give a precise preflight blocker before shipping.
- [x] Make the Rust `--node` `preflight` clock-skew probe resilient to transient
  SSH: a single first-connection `Operation timed out` hard-failed the whole run
  (cascade to skip-all + `cleanup` fail) because the probe was a single attempt
  (2026-07-11, observed on 2/3 `--node` runs whose first SSH hit
  `debian-headless-4`). On review the connect timeout was already bounded — the
  probe runs through `RemoteShellHost::run_argv` → `ssh::run_remote` →
  `base_ssh_command`, which sets `ConnectTimeout=15` (not the ~75s OS default the
  finding assumed) — so the real gap was the missing retry. Fix wraps ONLY the
  transport in a bounded `retry_transient` (3 attempts, 750ms backoff) in
  `stage/preflight.rs`; a non-zero exit / unparseable clock output stays
  deterministic (no retry) and still fails closed. Regression tests:
  `retry_transient_recovers_after_transient_failures`,
  `retry_transient_returns_last_error_after_exhausting_attempts`,
  `retry_transient_clamps_zero_attempts_to_one`. Scoped fmt/clippy(-D warnings)/
  preflight tests green on the stable toolchain. Live re-proof on a real `--node`
  run against `debian-headless-4` still pending lab access (see §6 stabilization
  item).

### 5.2 Platform adapter completeness

- [ ] Complete native macOS and Windows role evaluators still using partial or
  platform-gated paths.
- [ ] Complete anchor bundle-pull sub-surfaces: gossip seed and enrollment
  endpoint on macOS/Windows; Windows authoritative port mapping.
- [ ] Add explicit capability records for every adapter method and stage.
- [ ] Keep iOS/Android adapters fail-closed until mobile custody, lifecycle,
  connection, install, validator, and evidence contracts are reviewed.
- [ ] Design Android lab adapter around ADB/device control only as a lab channel;
  product management stays app-layer. Never treat ADB as production transport.
- [ ] Design iOS adapter around signed app/extension deployment and real-device
  control; document simulator limitations and any MDM dependency.

### 5.3 Rust-engine promotion and legacy retirement

- [ ] Produce clean paired bash/Rust functional-parity runs from the same commit,
  inventory, topology, and profiles.
- [ ] Require shared logical stage results, overall status, node count, role
  cells, cleanup state, and evidence completeness to match; explain intentional
  vocabulary differences.
- [ ] Obtain `overall_functional_parity_pass=true` with live Linux, macOS,
  Windows, cross-OS, security, chaos, and cross-network evidence.
- [ ] Flip default routing to Rust only after reviewed evidence; keep rollback
  time-bounded and observable.
- [ ] Remove bash implementation, legacy flags, stale docs, duplicate MCP paths,
  packaging, and tests after the stabilization window. Keep git history as the
  rollback mechanism.
- [ ] Refresh Rust-only remote E2E evidence proving argv-only execution and no
  active security-sensitive shell path.

## 6. Canonical VM and internet networking

Owning policy: [LiveLabVmConnectivityRulebook.md](../LiveLabVmConnectivityRulebook.md).

Implementation ledger: [LiveLabVmConnectivityImplementation_2026-07-10.md](./LiveLabVmConnectivityImplementation_2026-07-10.md).

- [x] Adopt dual-plane design: narrow management plane plus controlled scenario
  plane. Shared is management/bootstrap fallback; ordinary host-LAN bridging is
  not the default.
- [x] Give every VM a unique scenario IP on lab-owned subnets; keep
  `management_ip`, `scenario_ip`, `mesh_ip`, and `observed_egress_ip` distinct.
- [ ] Obtain explicit operator approval before applying the prepared UTM network
  mutations to real VMs; record pre/post snapshots and rollback evidence.
- [ ] Add/prove second scenario NICs across Linux, macOS, and Windows guests.
- [ ] Bind Rustynet endpoint discovery, listeners, routes, validators, and
  captures to the scenario NIC; forbid management-plane product traffic.
- [ ] Add deterministic DHCP, DNS, NTP, STUN, relay, gateway, MTU, IPv4, and IPv6
  services owned by the lab.
- [ ] Finish `double_nat_cgnat` for deterministic netns tests.
- [ ] Finish VXLAN modifiers needed for UPnP and native IPv6 scenarios.
- [ ] Implement management quarantine, link-down evidence mode, and out-of-band
  recovery; prove the management NIC cannot mask a leak.
- [ ] Validate macOS/Apple multi-NIC support in the chosen UTM backend before
  standardizing its profile.
- [ ] Build/prove dedicated physical-lab profile on an approved interface/VLAN;
  never auto-bridge to `en0` or the ordinary LAN.
- [ ] Build/prove remote-wild profile using independent sites and third-site
  relay/STUN; define cost, credentials, data retention, and teardown owners.
- [ ] Record and resolve rulebook owner decisions: approved host interfaces,
  address ranges, physical hardware, remote providers/sites, mobile/cellular
  participation, and evidence retention.
- [ ] Keep live audits read-only by default. Mutation must be typed, stopped-VM,
  transactional, rollback-capable, and re-audited after apply.
- [ ] Stabilize or replace `debian-headless-4` as a live-lab node: since the
  2026-07-10 Shared-networking migration it intermittently drops host→guest TCP
  reachability (>75s windows) at `192.168.64.10` while `fedora-utm-1` (`.20`)
  stays stable; it was initially absent from the host `arp` cache and carries
  many stale `live_ips`. Reset its Shared-net attachment or swap it for a stable
  guest before using it as a `--node` target (2026-07-11).

### 6.1 MCP and autonomous-agent network behavior

- [x] Expose typed audit, preflight, prepare/apply, and evidence surfaces through
  MCP rather than direct AppleScript or plist edits.
- [ ] Make every VM-creating/setup/orchestration MCP function require or derive a
  reviewed network profile; reject profileless mutation.
- [ ] Ensure MCP-created VMs use canonical management/scenario attachment,
  stable MACs, approved interfaces, and lab-owned subnets.
- [ ] Add a post-create/post-apply audit gate before a VM can enter inventory or
  run a product stage.
- [ ] Return exact network profile and drift/blocker evidence to MCP callers;
  never auto-heal by silently switching Shared/Bridged modes.
- [ ] Constrain DeepSeek/autonomous lab actions to approved typed operations;
  no repository writes, arbitrary commands, direct hypervisor config edits, or
  security decisions.
- [ ] Test MCP install/manifest sync and schema compatibility whenever network
  tools change.

## 7. Desktop role and platform parity

Owning ledger: [CrossPlatformRoleParityPlan_2026-06-21.md](./CrossPlatformRoleParityPlan_2026-06-21.md).

- [ ] Re-run all role cells under the canonical scenario plane; stale same-LAN
  evidence cannot prove the new topology.
- [ ] **Client:** complete Windows active client-traffic proof; retain macOS and
  Linux negative/leak evidence.
- [ ] **Admin:** refresh Linux/macOS/Windows live proof for signed issuance,
  revocation, quorum/policy, and no private-key leakage.
- [ ] **Anchor:** finish macOS/Windows gossip-seed and enrollment-endpoint proof;
  finish Windows authoritative port mapping; prove cold bundle pull and replay
  rejection.
- [ ] **Exit:** obtain a WinNAT/HNS-capable Windows environment, run active NAT,
  DNS fail-closed, IPv6 leak, demotion residue, and rollback tests. Keep current
  incapable guest as an honest blocked/negative environment.
- [ ] **Blind exit:** prove Linux live nftables apply and macOS PF hard-lock with
  active leak/route probes; keep Windows explicitly unsupported-by-design unless
  scope changes through reviewed architecture/security decision.
- [ ] **Relay:** prove live packet forwarding on Linux, macOS, and Windows paths
  where supported; lifecycle-only evidence remains partial.
- [ ] **Role transitions:** refresh LocalOnly macOS/Windows proof; design,
  implement, and prove SignedMembership transitions with deploy-before-advertise,
  teardown-before-revoke, replay safety, and irreversible transition rules.
- [ ] Keep the role matrix capability-aware. Unsupported-by-design and blocked
  environment are not failures, but neither may appear green.

## 8. Cross-network dataplane, traversal, relay, and DNS

- [ ] Finish orchestrator substrate wiring for Tier A netns, Tier B VXLAN, and
  Tier C cross-OS/slirp smoke with typed setup/teardown and fail-closed cleanup.
- [ ] Run NAT matrix: port-restricted cone, full cone, symmetric, double
  NAT/CGNAT, UPnP available/unavailable, v4-only, native IPv6, and mixed cases.
- [ ] Fix/root-cause the remaining phase10 cross-network runtime-init failures;
  produce six current reports: direct remote exit, relay remote exit, roaming
  failback, adversarial traversal, DNS fail-closed, and minimum 30-minute soak.
- [ ] Prove true two-hop traffic and intended path from packet capture, not
  config text.
- [ ] Strengthen LAN-toggle denial and Windows IPv6 leak checks with active
  off-tunnel probes and boundary capture.
- [ ] Flip anchor port mapping to `auto` only after real-router acceptance and
  role-conditional default tests.
- [ ] Add IPv6-first listeners and PCP-toward-CGN behavior; prove v6 bypass of
  v4 CGNAT without route/DNS leakage.
- [ ] Implement honest NAT behavior discovery and CGNAT detection; surface in
  status, wizard, diagnostics, and signed/gossip metadata without trusting it as
  authorization.
- [ ] Implement signed, replay-protected gossip-coordinated punch timing and
  prove direct path for port-restricted peers.
- [ ] Decide whether to authorize quiet sequential port-delta prediction after
  field evidence; keep broad port spraying banned.
- [ ] Decide whether to authorize opt-in encrypted endpoint mailbox recovery;
  document metadata, availability, abuse, replay, privacy, and kill-switch risks.
- [ ] Close relay malformed-frame, source-tuple binding, token replay, rate,
  flood, shutdown, and allocation lifecycle tests; then live-forward frames.
- [ ] Refresh managed-DNS live adversarial evidence: stale, replayed, forged,
  tampered, policy-invalid, route, resolver, and leak cases.

## 9. Android client program

Mobile v1 scope: client only. No admin signer, relay, exit, blind exit, anchor,
NAS, or LLM hosting.

### 9.1 Android foundation

- [ ] Create reviewed crate split: `rustynet-mobile-core`,
  `rustynet-mobile-ffi`, and `rustynet-backend-android`; keep host CLI/daemon
  assumptions out.
- [ ] Scaffold Android app, Gradle/Rust ABI build, JNI/C ABI bridge, ownership
  rules, stable error taxonomy, panic containment, and zero-copy/bounded buffers.
- [ ] Implement `VpnService` lifecycle, TUN FD handoff, route/DNS intent,
  foreground notification, connect/disconnect, and always-on/lockdown behavior.
- [ ] Protect every control/upstream socket before VPN routing; test that missing
  `protect()` fails closed rather than loops or leaks.
- [ ] Integrate Android Keystore; decide StrongBox requirements/fallback. Keep
  signing keys non-exportable where feasible and document wrapped-key boundary.
- [ ] Define backup exclusion, reinstall, device migration, lock-screen state,
  key invalidation, and enrollment-token destruction behavior.
- [ ] Implement signed membership/assignment/traversal/DNS ingestion with the
  same freshness, network/node binding, replay, rollback, and revocation rules.
- [ ] Implement full/split tunnel, Magic/managed DNS, remote-exit client, LAN
  policy, IPv4/IPv6, MTU, and fail-closed killswitch behavior.
- [ ] Implement network callback handling for Wi-Fi/cellular switch, captive
  portal, metered network, doze, sleep, background restriction, and reboot.
- [ ] Build bounded, redacted diagnostics/support bundles; no tokens, keys,
  plaintext payloads, or unrestricted device data.
- [ ] Add signed release, SBOM/provenance, Play policy/data-safety, min SDK/ABI,
  update, rollback, and reproducible build decisions.

### 9.2 Android verification

- [ ] Add unit/property/fuzz tests for FFI, signed input, lifecycle races,
  malformed packets, oversized data, cancellation, and secure-storage errors.
- [ ] Add emulator smoke only for API behavior; use physical devices for VPN,
  Keystore/StrongBox, OEM background policy, battery, Wi-Fi/cellular, and leak
  claims.
- [ ] Add `--node` Android lab capability and adapter only after the reviewed
  connection/install/validator model exists; ADB remains lab-only.
- [ ] Live stages: install/signature, enroll/replay, connect, peer traffic,
  remote exit, DNS, unauthorized denial, killswitch, Wi-Fi↔cellular roam,
  captive portal, sleep/doze, process kill, reboot, key invalidation,
  backup/restore, tamper, revocation, and redacted support bundle.
- [ ] Run across supported Android/API/OEM matrix and record battery/CPU/memory,
  tunnel availability, reconnect latency, and leak evidence.

## 10. iOS client program

### 10.1 iOS foundation

- [ ] Create `rustynet-backend-ios` plus shared mobile core/FFI crates; build an
  XCFramework or reviewed equivalent with deterministic signed artifacts.
- [ ] Scaffold containing app and `NEPacketTunnelProvider` extension; define App
  Group boundary and keep secrets out of shared preferences/files.
- [ ] Bridge `packetFlow` safely to Rust with bounded buffers, ownership,
  cancellation, panic containment, and extension memory limits.
- [ ] Define Keychain access group and accessibility class. Document what Secure
  Enclave can/cannot protect; never imply arbitrary WireGuard key operations are
  hardware-backed without proof.
- [ ] Implement connect/disconnect, on-demand rules, path monitor, full/split
  tunnel, managed DNS, remote exit, IPv4/IPv6, MTU, and killswitch semantics.
- [ ] Handle Wi-Fi/cellular changes, sleep, suspended extension, memory pressure,
  app update, device reboot, token expiry, and provider restart fail-closed.
- [ ] Reuse shared signed-state validation and anti-replay rules; container app
  must not become a weaker validation path than the extension.
- [ ] Build bounded redacted diagnostics through approved container/extension
  exchange; protect logs and OSLog privacy fields.
- [ ] Define entitlements, provisioning, team IDs, signing, TestFlight/App Store,
  privacy manifest, update, rollback, and minimum OS/device support.

### 10.2 iOS verification

- [ ] Unit/property/fuzz FFI and signed-input boundaries; test provider lifecycle,
  cancellation, malformed packets, memory pressure, and Keychain failures.
- [ ] Use simulator only for safe UI/logic tests. Use physical devices for
  Network Extension, Keychain class, background/suspension, Wi-Fi/cellular,
  battery, and leak claims.
- [ ] Add `--node` iOS adapter only after real-device install/control and
  validator evidence exist; document any MDM requirement.
- [ ] Live stages: signed install, enroll/replay, connect, peer traffic, remote
  exit, DNS, unauthorized denial, on-demand/killswitch, Wi-Fi↔cellular roam,
  sleep/suspend, extension kill, reboot, Keychain locked/unavailable, app update,
  tamper/revocation, and redacted support bundle.
- [ ] Run supported iPhone/iPad and OS matrix; capture reconnect, energy, memory,
  path, DNS, IPv4/IPv6, and leak evidence.

## 11. Shared mobile security and release gates

- [ ] Freeze mobile capability model: client-only v1; server refuses unsupported
  role assignment rather than silently downgrading.
- [ ] Freeze versioned C ABI/FFI contract with maximum sizes, ownership,
  threading, cancellation, zeroization, and error stability.
- [ ] Threat-model hostile apps, compromised UI process, rooted/jailbroken
  device, malicious Wi-Fi, captive portal, rollback, backup restore, log access,
  local IPC, extension death, and stolen unlocked device.
- [ ] Add mobile-specific enforcement/verification mapping to
  `SecurityMinimumBar.md` and platform support matrix.
- [ ] Prove cross-platform interoperability against Linux/macOS/Windows peers,
  exits, anchors, DNS, traversal, and relay using the canonical lab ladder.
- [ ] Define telemetry/privacy posture, consent, retention, crash reporting, and
  support-bundle handling before store submission.
- [ ] Gate release on independent mobile security review and remediation of all
  critical/high findings.

## 12. NAS and LLM service-hosting roles

- [x] NAS/LLM crates, core policy, installers, lifecycle, default-deny gates,
  daemon access-state materialization, and surface docs exist.
- [ ] Add MagicDNS service names such as `vault.nas.<mesh>` and
  `brain.llm.<mesh>` through signed zone policy.
- [ ] Run NAS Linux M5: deploy, advertise, authorize, backup, restore, namespace
  isolation, at-rest ciphertext, quota, revoke-severance, and undeploy.
- [ ] Run LLM Linux/Apple-silicon M5: deploy, authorize, no-API-key stream,
  model/quota/rate enforcement, exit coexistence, revoke-midstream, and undeploy.
- [ ] Implement and prove macOS/Windows service-role lifecycle, firewall,
  service manager, storage/custody, cleanup, and live evidence before parity
  cells can turn green.
- [ ] Freeze RustyBackup/RustyAI client contracts only after M5 evidence; keep
  companion-app program separate.

## 13. Broader security remediation

- [ ] Re-verify every open row in `SecurityAuditLedger_2026-06-18.md` against
  current code before implementation; update stale statuses instead of copying
  them forward.
- [ ] Resolve remaining high-severity live proof for membership revoke and
  macOS bootstrap privilege residue.
- [ ] Eliminate enrollment role silent downgrade and prove default-deny role
  assignment.
- [ ] Harden role-audit locking, append durability, chain validation, retention,
  and concurrent writers.
- [ ] Close sensitive persistence permission/ACL gaps across Unix and Windows.
- [ ] Replace/complete any admin authorizer scaffold; prove quorum, revocation,
  expiry, replay, and no single weak bypass.
- [ ] Define fail-closed empty-policy behavior and test unavailable/corrupt
  policy state.
- [ ] Validate all IPC CIDRs, lengths, versions, identities, and peer
  credentials before privileged mutation.
- [ ] Prove Windows private-key ACL application and startup root containment.
- [ ] Persist gossip replay watermark and recheck revocation/rate policy at use,
  not only admission.
- [ ] Close UPnP SSRF and privileged-helper process-kill scope risks.
- [ ] Persist traversal anti-replay and harden malicious candidate/signature/NAT
  viability inputs.
- [ ] Complete Windows Authenticode thumbprint extraction/verification in live
  deploy path.
- [ ] Wire service exposure strictly to signed authorization and current tunnel
  identity; revoke must sever active sessions.
- [ ] Validate backend endpoints, labels, routes, interfaces, and executable
  provenance at every trust boundary.
- [ ] Resolve the six owner decisions in the remediation plan, documenting
  security impact, owner, decision date, and expiry/review trigger.

## 14. Test coverage, fuzzing, and quality

- [ ] Add `cargo llvm-cov` per-crate baseline and CI ratchet; retain test-count
  floors as secondary drift checks, not coverage truth.
- [ ] Expand coverage gates to control, policy, crypto, DNS, sysinfo, traversal,
  gossip, enrollment, key rotation, relay, and backend crates.
- [ ] Extract pure parsers from `rustynet-sysinfo` IO; add malformed, missing,
  overflow, locale, encoding, and platform fixture tests.
- [ ] Add shared userspace/boringtun seam tests for handshake, anti-replay,
  cryptokey routing, unknown source, worker death, queue fairness, and errors.
- [ ] Add key-rotation drain clock/boundary tests and finalize-persist failure
  injection.
- [ ] Add traversal signature, candidate bounds, NAT viability, replay,
  prioritization, and failback property tests.
- [ ] Broaden property tests for canonical encodings, parser-never-panics,
  monotonic epochs/watermarks, route policy, idempotent cleanup, and transition
  matrices.
- [ ] Add fuzz targets for DNS, gossip, traversal, relay, privileged IPC,
  evidence/report parsers, mobile FFI, and service-host protocols.
- [ ] Run sanitizers/Miri where supported; document exclusions. Add deterministic
  fault injection for disk full, short write, fsync/rename failure, corrupt file,
  clock jump, cancellation, and subprocess death.
- [ ] Add regression tests for each live-lab defect before marking its fix done.

## 15. Serialization and schema hardening

- [x] Privileged-helper active path uses one bounded framed binary protocol; no
  active newline-JSON fallback.
- [x] DNS signer input uses strict canonical manifest parsing; adversarial local
  cases exist.
- [ ] Restore managed-DNS lab reachability and collect fresh live adversarial
  evidence before closing the DNS slice.
- [ ] Inventory and migrate remaining cross-network discovery/report artifact
  families to typed, versioned, bounded schemas with one-shot conversion only.
- [ ] Migrate measured source streams where integrity/ambiguity warrants it;
  preserve append and recovery semantics.
- [ ] Finish broader DNS artifact-family migration beyond the owned input parser.
- [ ] Ban indefinite dual readers, unknown-field acceptance at trust boundaries,
  unbounded allocations, and format-specific signature ambiguity.
- [ ] Add upgrade/downgrade, corrupt/truncated, oversized, unknown-version,
  duplicate-field, and canonical-byte tests for every schema.

## 16. CI, builds, dependencies, and supply chain

- [ ] Fix macOS `vm_lab` Gatekeeper/trustd subprocess flake with bounded,
  evidence-backed behavior; do not hide real failures with blanket skip.
- [ ] Fix Debian 13 and Linux real-WireGuard-E2E bootstrap so Cargo is reliably
  on PATH; turn both jobs green.
- [ ] Keep Windows build/security green; continuously run audit/deny rather than
  relying on historical proof.
- [ ] Run Linux/macOS/Windows build, test, Clippy, audit, deny, packaging, and
  platform-specific integration on current supported versions.
- [ ] Add Android/iOS build/sign/test jobs when mobile crates land; keep secrets
  in platform CI custody and verify artifacts after signing.
- [ ] Generate signed SBOM, provenance, checksums, dependency/license/advisory
  results, and reproducible-build metadata for every shipped artifact.
- [ ] Enforce toolchain/dependency pinning and controlled updates; document and
  time-bound exceptions.
- [ ] Remove lab-only crates/features from product packages after RNQ-17 split;
  verify SBOM and attack-surface reduction.

## 17. Performance and resource use

Owning ledger: [DataplanePerfBacklog_2026-06-12.md](./DataplanePerfBacklog_2026-06-12.md).

- [ ] Remove engine outcome-sink per-frame copies while preserving emission
  order, error semantics, handshake state, and test recording.
- [ ] Replace relay 100µs polling and per-frame global lock with await/cancel
  design; prove allocation shutdown and constant-time/auth ordering.
- [ ] Evaluate macOS utun `readv`/`writev` framing in third-party boundary;
  review unsafe use and short IO behavior before adoption.
- [ ] Add endpoint→peer index for larger meshes while preserving lowest-node-ID
  duplicate endpoint tie-break and fail-closed round-trip checks.
- [ ] Land deferred runtime-fingerprint memoization and gossip candidate-build
  guard after revalidating benefit and mutation invalidation.
- [ ] Establish live throughput, latency, loss, reconnect, relay, CPU, memory,
  allocation, syscall, battery/mobile energy, and soak budgets with regression
  gates. Never trade away security checks for benchmark wins.

## 18. Operator UX, diagnostics, MCP, monitor, and GUI

- [ ] Re-audit `DiagnosticFunctionsRoadmap.md` against current Rustynet
  architecture. Remove irrelevant assumptions, security-risky probes, duplicate
  functions, and features without a trustworthy cross-platform data source.
- [ ] Implement diagnostics as typed Rust functions with bounded execution,
  explicit privilege, redaction, timeouts, stable schemas, and platform support
  records. Never build commands by shell-string interpolation.
- [ ] Prioritize route/interface/DNS/MTU, listening-socket, firewall, service,
  IPC, key-permission, clock, resource-pressure, crash-loop, and Rustynet health
  diagnostics needed to explain live-lab failures.
- [ ] Separate observation from mutation. A diagnostic call must not repair,
  enroll, rewrite policy, alter routes/firewalls, or expose secrets.
- [ ] Add Windows operator-config atomic persistence and security validation;
  the current non-Unix unsupported path must remain fail-closed until ACL and
  durability semantics are implemented and tested.
- [ ] Complete cross-platform operator-menu behavior and clean install/upgrade
  tests; retire `start.sh` after the documented compatibility window.
- [ ] Finish the DeepSeek live-lab orchestration pipeline only with confined,
  allowlisted lab actions, bounded budgets, grounded evidence, untrusted-output
  handling, and main-agent ownership of code/security decisions.
- [ ] Audit every MCP function for authz, input bounds, path containment,
  command allowlists, timeout/cancellation, redaction, evidence provenance, and
  honest unsupported/blocked states.
- [ ] Keep MCP schemas, manifests, installer cache, repo context, stage registry,
  network profiles, platform support, and run-matrix vocabulary synchronized by
  drift tests.
- [ ] Make `rustynet-lab-monitor` a first-class independently gated crate or
  document why it remains outside the workspace; test start/stop/resume,
  concurrent readers, terminal restoration, stale data, and crash behavior.
- [ ] Reconcile the node-map GUI and any other UI with the same signed-state,
  role, capability, evidence, and redaction authorities. UI must never invent a
  green state or a second policy path.
- [ ] Review `rustynet-advisor` and Fable/intelligent-system outputs as
  untrusted advisory data; require deterministic validation before any proposed
  action reaches an enforcement path.
- [ ] Make `ops vm-lab-discover-local-utm` enumerate through `utmctl list`
  (authoritative — it sees every registered VM) instead of scanning the UTM
  container Documents root, which after the 2026-07-10 bundle relocation to
  `~/Desktop/OS_images/UTM images/` holds one stale bundle and either reports
  `bundle_count=1 / inventory_matched_count=0` or hits the 20s TCC scan timeout.
  This intermittently fails a `--node` run at `discover_local_utm` (`local UTM
  discovery did not report the selected aliases`) even when the inventory has
  correct `controller.bundle_path`/`utm_name` and the guests are reachable
  (2026-07-11).

## 19. Operations, evidence, and release

- [ ] Refresh fresh-install matrix on supported Linux distributions, macOS, and
  Windows from clean hosts; include clean install, one-hop, two-hop, role switch,
  uninstall, reinstall, upgrade, rollback, and residue.
- [ ] Refresh all phase9/phase10 reports from measured raw evidence with commit,
  schema, provenance, hashes, target identity, and no simulated fallback.
- [ ] Pass Security Minimum Bar, supply-chain, dependency, audit integrity,
  retention, SLO/error budget, performance, soak, incident, and recovery gates.
- [ ] Run backup/restore and disaster-recovery drills; publish measured RPO/RTO
  appropriate to the actual deployment architecture.
- [ ] Validate WireGuard remains adapter-only and obtain measured conformance and
  leakage evidence for any second non-simulated backend before promotion.
- [ ] Publish compatibility/support policy, crypto deprecation schedule,
  expiring exception policy, and post-quantum transition plan.
- [ ] Complete install/upgrade/uninstall/service-manager runbooks for every
  supported platform; commands must be safe, idempotent, and residue-checked.
- [ ] Define evidence retention, redaction, access control, deletion, and chain
  of custody for local, physical, remote, and mobile labs.
- [ ] Perform independent security review/red-team pass, remediate findings,
  rerun affected live stages, and capture final engineering/security/operations
  sign-off in `FinalLaunchChecklist.md`.

## 20. Platform expansion and future programs

- [ ] After desktop parity: implement `armv7-unknown-linux-gnueabihf` support;
  remove `AtomicU64` and 128-bit arithmetic blockers with reviewed portable
  behavior; test Pi Zero 2 W-class relay/exit/blind-exit targets.
- [ ] Maintain aarch64 Linux/macOS/Windows compile and live coverage where
  product-supported.
- [ ] Move Windows dataplane/backend from explicit unsupported/opt-in posture to
  release support only after WireGuard-NT install, readiness, runtime, ACL,
  service, DNS, route, leak, recovery, and conformance evidence is measured.
- [ ] Implement cross-platform default-gateway discovery where required by
  automatic port mapping; reject ambiguity instead of guessing.
- [ ] Implement NAS data-root permission verification on every supported service
  host platform; keep unsupported platforms blocked.
- [ ] Complete the real Windows gossip transport before claiming Windows
  distributed-coordination parity.
- [ ] Reconcile Fable/intelligent-system proposals with the security bar before
  promotion; experimental/advisory systems cannot silently mutate trust,
  policy, routing, membership, or evidence verdicts.
- [ ] Keep RustyBackup/RustyAI companion apps, additional service roles, and
  speculative backends as separately approved programs with explicit threat
  models and owners.

## 21. External blockers and owner decisions

- [ ] Approve and schedule real-VM application of the dual-plane network profile.
- [ ] Select approved dedicated physical interface/VLAN, router/switch hardware,
  and lab address plan.
- [ ] Select remote-wild sites/providers, cost ceiling, credentials owner,
  teardown policy, and evidence retention.
- [ ] Acquire or build a Windows guest/environment with WinNAT/HNS capabilities.
- [ ] Provide Fedora lab account with reviewed passwordless-sudo prerequisite or
  approved alternative bootstrap mechanism.
- [ ] Secure Android physical-device/OEM matrix and Apple developer account,
  entitlements, provisioning, and physical iOS devices.
- [ ] Decide gated traversal features: port-delta prediction and out-of-band
  endpoint mailbox.
- [ ] Decide Windows blind-exit scope. Current posture is unsupported-by-design.
- [ ] Assign release, security review, lab operations, mobile, and evidence
  retention owners with dates.

## 22. Definition of done

Rustynet is complete for a declared release scope only when:

- [ ] Every supported role × platform × capability cell has current live proof
  on the canonical network ladder; unsupported cells are explicit and enforced.
- [ ] The Rust `--node` engine is the single shipped orchestrator path, separated
  from product binaries, with durable truthful evidence and cancellation-safe
  cleanup.
- [ ] Deterministic NAT/multi-VM, dedicated physical, and genuinely remote wild
  evidence all pass for the claims made.
- [ ] Android and iOS meet the client-only mobile scope, security model, physical
  device matrix, release signing, store, privacy, lifecycle, and leak gates.
- [ ] All critical/high security findings are fixed and re-proven; lower-risk
  exceptions are owned, justified, time-bounded, and visible.
- [ ] CI, coverage, fuzz, performance, fresh install, upgrade/rollback,
  supply-chain, incident/DR, documentation, and final sign-offs are green.
- [ ] Final artifacts can be independently traced to source, toolchain, signed
  provenance, SBOM, measured evidence, and reviewed release decision.

## 23. Primary source map

- Requirements/security: `documents/Requirements.md`,
  `documents/SecurityMinimumBar.md`, `SecurityAuditLedger_2026-06-18.md`,
  `SecurityRemediationPlan_2026-06-19.md`,
  `SecurityStageBacklogStatusCheck_2026-07-04.md`.
- Lab truth: `LiveLabStageContractPlan_2026-07-03.md`,
  `LiveLabCoverageAndHonestyAudit_2026-06-25.md`,
  `LiveLabSecurityTestCoverage_2026-06-22.md`, wave ledgers, run matrix, and
  current artifacts.
- Rust engine: `RustNativeNodeOrchestratorQualityAudit_2026-07-10.md`,
  `RustNativeMultiPlatformOrchestratorPlan_2026-04-28.md`.
- Networking: `LiveLabVmConnectivityRulebook.md`,
  `LiveLabVmConnectivityImplementation_2026-07-10.md`,
  `CrossNetworkSubstrateIntegrationSpec_2026-06-21.md`, dataplane plan.
- Platform/roles: `CrossPlatformRoleParityPlan_2026-06-21.md`, roadmap and
  focused role ledgers, `PlatformSupportMatrix.md`.
- Mobile: `documents/mobile/RustynetMobileRoadmap_2026-04-17.md`, mobile
  architecture, imported implementation/FFI/security/lifecycle references,
  and current fail-closed iOS/Android adapter stubs.
- Quality/release: test coverage, serialization, shell-to-Rust, CI health,
  performance, service-hosting, release guardrails, and final launch checklist.

## 24. Update protocol

For each item completed:

1. Change code/tests/docs and the owning ledger.
2. Run scoped gates, then the proportionate workspace/platform/live gates.
3. Record exact evidence and blocker truth.
4. Update this roll-up: mark `[x]` only when its full sentence is proven.
5. If scope splits, create stable child IDs in the owning ledger and link them;
   do not hide unfinished tails behind a broad checked item.
