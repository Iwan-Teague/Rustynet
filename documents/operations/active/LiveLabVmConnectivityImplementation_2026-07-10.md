# Live-Lab VM Connectivity Implementation Ledger (2026-07-10)

Execution ledger for implementing
[LiveLabVmConnectivityRulebook.md](../LiveLabVmConnectivityRulebook.md)
(§15.8 slices). The rulebook owns policy; this ledger owns per-slice status and
evidence. Statuses use the rulebook §15.5 external vocabulary where applicable.

Rules honored throughout:

- Slice order is mandatory; no VM network mutation before Slice A acceptance.
- Real-VM application of Slice B requires explicit operator approval with the
  affected aliases, before/after plan, downtime, rollback path, and profile
  digest.
- Skipped work is never recorded as pass. External infrastructure that does not
  exist is `not_run` with the remaining plan stated.

## Slice A — read-only profile/audit foundation

Status: **accepted 2026-07-10** (all acceptance items below verified on this
working tree at base commit `b775156` + uncommitted Slice A changes).

| Item | Status | Evidence |
| --- | --- | --- |
| Typed profile model (`NetworkProfileId`, `AttachmentMode`, `ManagementPolicy`, `ScenarioSubstrate`, `InternetMode`, `EvidenceTier`, external status vocabulary) | done | `crates/rustynet-cli/src/vm_lab/network_profile.rs` |
| Strict TOML manifest parser (unknown fields, duplicate IDs, invalid enums, unsafe values, overlaps, malformed TOML all fail closed) | done | 16 unit tests in `network_profile.rs` |
| Canonical validated-profile digest (`sha256:`; formatting-invariant, semantics-sensitive) | done | `digest_is_stable_and_semantic` test |
| Reviewed secret-free manifests | done | `profiles/vm_lab/network/{mgmt_shared_smoke_v1,crossnet_netns_v1,isolated_multivm_v1,cgnat_collision_v1}.toml` |
| UTM QEMU/Apple config observation (backend, per-NIC mode/MAC/bridge interface, power state) | done | `network_audit.rs` via argv-only `plutil -extract` + `utmctl list`; fixture tests for QEMU Shared/Host Only/Bridged and Apple Shared/Bridged |
| Host route/VPN/proxy/interface observation | done | `parse_ifconfig`/`parse_netstat_routes`/`parse_scutil_proxy` + tests |
| Guest management address/route/DNS/MTU observation (Linux + macOS guests; Windows honestly `not_supported` in Slice A) | done | live audit collected 4 guests; per-guest status recorded |
| Backend capability matrix (Apple Host Only = not_supported; Apple multi-NIC = unproven, fail-closed) | done | `backend_attachment_support`/`backend_multi_nic_support` + tests |
| Address-overlap detection (mesh `100.64.0.0/10` vs simulator transit, host VPN routes vs profile subnets) | done | `cidr_overlap_math`, `host_vpn_route_collision_detected`, `netns_sim_wan_collision_detected` tests |
| Duplicate MAC/IP detection | done | `duplicate_mac_detected`, `inventory_duplicate_ip_and_stale_group_detected` tests |
| Stale-inventory detection (`network_group` label drift, duplicate recorded IPs) | done | same tests + live findings below |
| Atomic redacted `vm_network_evidence.json` writer (tmp+rename, 0600, serialized-secret guard) | done | `evidence_write_is_atomic_and_owner_only`, `secret_guard_blocks_leaks` tests |
| `rustynet ops vm-lab-network-audit` (read-only) | done | live run below |
| `rustynet ops vm-lab-network-preflight` (read-only, fail-closed) | done | live run below (exit 1 on drifted fleet, digest recorded) |
| Scoped gates | done | `cargo fmt --all -- --check` clean; `cargo clippy -p rustynet-cli --all-targets --all-features -- -D warnings` clean; 38 new unit tests pass; `cargo audit --deny warnings` + `cargo deny check bans licenses sources advisories` clean after adding the `toml` dependency |
| Live read-only audit against the real fleet | done | `state/vm_network_evidence.json` (schema 1, `overall_status=fail`, 9 errors/1 warning, UTM 4.6.5, 7 VMs, 4 guests collected, 0600, zero secrets, public addresses redacted) |

Read-only proof: the audit path contains no code that writes to UTM bundles,
`utmctl` mutating verbs, inventory, host routes, or firewalls; the only writes
are the evidence file (atomic, owner-only) and stdout.

### Live-audit baseline findings (2026-07-10, evidence `state/vm_network_evidence.json`)

The audit reproduced every rulebook §14 observation on the real fleet:

- Mixed attachments detected exactly: Shared (`debian-headless-2`,
  `rocky-utm-1`, `macos-utm-1`), Bridged with unpinned interface
  (`debian-headless-4`, `windows-utm-1`), Bridged to `en0` (`fedora-utm-1`,
  `ubuntu-utm-1`).
- Inventory duplicate IP: `windows-utm-1` + `ubuntu-utm-1` both record
  `10.230.76.57`.
- Stale `network_group` labels: `debian-headless-4`, `macos-utm-1`,
  `windows-utm-1`.
- netns simulator transit `100.64.0.0/24` collides with mesh `100.64.0.0/10`
  (declared at `scripts/vm_lab/netns_internet_sim.sh` `WAN_CIDR`).
- Host full-tunnel VPN condition recorded (utun default-route pattern).
- 4 unmanaged UTM VMs outside inventory (CentOS, Rocky, Windows XP,
  Windows XP Harness).

Pre-existing, unrelated test failures observed while gating (NOT Slice A
regressions; both live in the concurrent orchestrator-quality worktree
changes): `vm_lab::orchestrator::plan::tests::build_returns_canonical_security_stage_order`
(exit-validation stage-order expectation vs in-progress plan.rs edits) and
`source_archive_marker_matches_worktree_snapshot_commit` (worktree-state
sensitive; passes on re-run).

## Slice B — prepare/restore transaction

Status: **code accepted 2026-07-10 (local)** — engine, lease, rollback, and
fault-injection tests are done and green. **Real-VM application has NOT
happened**: it requires explicit operator approval (affected aliases,
before/after plan, downtime, rollback path, profile digest) and remains
`not_run` until granted.

| Item | Status | Evidence |
| --- | --- | --- |
| Journal-driven transaction engine (step-wise, persisted before/after each step, resumable) | done | `crates/rustynet-cli/src/vm_lab/network_prepare.rs` |
| Dry-run mutation plan (redacted; changes nothing, leaves no residue) | done | live dry-run against the real fleet: 4 VMs flagged WILL RECONFIGURE, 3 already compliant; no lease/txn dirs created |
| Explicit authorization boundary (`--approve-reconfigure`; absent → plan only) | done | command wiring + dry-run default |
| Atomic network lease (overlap refused, disjoint allowed, stale recovery via pid+command identity, never pid alone) | done | `overlapping_lease_refused_disjoint_allowed_stale_recovered` test |
| Run-scoped resource ownership + release-verifies-ownership | done | `LeaseStore::release` content check |
| Stopped-VM-only UTM configuration update | done | live port refuses apply/restore on a running VM; mock enforces the same invariant |
| Guest route/firewall configuration seam (typed `GuestNetworkPlan`; no shell from untrusted values) | done (executor fail-closed until Slice C site allocation) | `configure_guest` port hook + engine step |
| Secure rollback storage (0700 dir / 0600 files, under gitignored `state/`, full original config bytes) | done | `happy_path` permissions assertion |
| Verified rollback (byte-digest verification of restored configs + power states; corrupted snapshot refused) | done | `rollback_refuses_corrupted_snapshot` + restore assertions |
| Interrupted-transaction recovery (idempotent, journal-driven) | done | `process_interruption_recovery_is_idempotent` |
| Owned-resource-only cleanup (untouched VMs never rewritten) | done | rollback skip-intact logic + `fault_after_one_vm_stops_restores_everything` |
| `ops vm-lab-network-prepare` / `ops vm-lab-network-restore` | done | command registration + help |
| Fault injection: before stop / after one VM stops / after partial config / after start failure / after DHCP timeout / after evidence-write failure / after process interruption | done | 7 dedicated tests, all restoring full prior state (or honestly reporting rollback-incomplete with the lease held when the fault persists into rollback) |
| `en0` unrepresentable as a bridge target (profile layer + plan layer + render layer) | done | `en0_is_unrepresentable_as_target` |
| Scoped gates | done | fmt/clippy `-D warnings`/14 new tests green |

### Live application attempt (2026-07-10, operator-approved) — fail-closed, fully restored

Ran `vm-lab-network-prepare --profile mgmt_shared_smoke_v1 --approve-reconfigure`
(txn `txn-1783711299-90539`) against the real fleet. Outcome: the transaction
**correctly fail-closed and the fleet was fully restored** — but two real
engine defects were exposed and fixed, and the run did NOT complete the
migration. Honest detail:

- The apply to Shared **did take effect** — `debian-headless-4` came up on the
  Shared subnet (`192.168.64.10`, confirmed by SSH login; Windows `.14` and
  Fedora `.20` reachable).
- The run then FAILED at `wait_management` and rolled back **because the
  readiness probe used a raw `TcpStream` connect**, which macOS Local Network
  Privacy false-negatives for LAN IPs opened from inside the process
  (CLAUDE.md §12.3.1 — the `ssh` binary reaches them fine, a raw socket does
  not). So the transaction could not confirm a healthy guest and did the safe
  thing: roll back.
- The rollback then hit `rollback_incomplete` (the `90s` stop-timeout was too
  short for VMs that had just been restarted and were mid-boot), holding the
  lease as designed.
- `vm-lab-network-restore <txn>` then completed a **verified** restore:
  `outcome=restored_verified`, all four config files digest-verified back to
  Bridged, lease released, power states matching the originals.

**Fixes landed (code + unit-tested; live re-verification pending a new
approval):**

- `wait_management_ready` now probes with the real `ssh` binary
  (argv-only, host-key pinning preserved); `classify_ssh_probe` treats a
  completed handshake — including `Permission denied` / host-key rejection —
  as reachable, and only a connection-level failure (refused/timeout/no route)
  as not-ready. New `ssh_probe_classifier_treats_handshake_as_reachable` test.
- Rediscovery: candidates come from `utmctl ip-address` + ARP-by-MAC + the
  recorded host (the management address changes with the attachment), timeout
  raised to `420s`.
- Rollback robustness: `stop_vm` now force-stops (`utmctl stop --force`) after
  the graceful window; `VM_POWER_POLL_TIMEOUT_SECS` raised to `180s`.

**Current fleet state (2026-07-10):** all config files are Bridged (restore
verified the bytes), but `debian-headless-4` / `Windows` / `Fedora` were
observed still running on the Shared subnet at restore time (a UTM in-memory
caching artifact of the plist-edit mechanism). Whether a VM restart reasserts
the Bridged file was NOT tested (the operator declined the diagnostic
restart). **Known limitation / follow-up:** the rulebook §5/§13 mandates
mutation "through UTM's supported configuration interface"; the raw
`plutil -replace` used here is not that interface and can leave the running
attachment out of step with the file while UTM.app is running (rulebook §14).
The correct mechanism is UTM's AppleScript "Configuration Suite"
(`update configuration`) driven from the Rust transaction, or requiring UTM to
be quit during apply — a decision left to the operator (see the run report).

### Corrected re-run (2026-07-10, operator-approved "option A") — MIGRATION SUCCEEDED

Re-ran `vm-lab-network-prepare --profile mgmt_shared_smoke_v1
--approve-reconfigure` with the SSH-binary readiness probe (txn
`txn-1783721025-63223`). Outcome: **`applied` and verified for all 7 VMs.**

- The SSH probe confirmed every reconfigured guest on its new Shared IP:
  `debian-headless-4` → `192.168.64.10`, `Windows` → `192.168.64.14`,
  `Fedora` → `192.168.64.20` (log lines "management plane ready at …:22
  (ssh)"). No rollback.
- All four config files now read `Shared` (file and running attachment
  consistent this time — the earlier divergence was an artifact of restoring
  mid-boot, not a forward apply). `ubuntu` was Shared-configured while stopped
  and correctly left stopped. Lease released.
- Inventory refreshed via the sanctioned `--update-inventory-live-ips`
  (`ssh_target`/`last_known_ip` → the new Shared IPs for the 3 running guests).
- Post-migration read-only audit
  ([vm_network_evidence_postmigration_2026-07-10.json](./vm_network_evidence_postmigration_2026-07-10.json)):
  **every bridged finding cleared** — no `bridged_to_everyday_lan`
  (fedora/ubuntu were on en0), no `bridged_interface_unpinned`
  (debian-4/windows), no `duplicate_recorded_ip`. Secret-free (21 addresses
  redacted, 0 secrets).

| Item | Status | Evidence |
| --- | --- | --- |
| Apply to real VMs (migration to Shared `mgmt_shared_smoke_v1`) | **done + verified** | txn `txn-1783721025-63223` (`outcome=applied`); all 7 VMs `nic0=shared`; post-migration audit clears all bridged findings |
| Fail-closed + verified-rollback contract under a real failure | **proven live** | the first run (`txn-1783711299-90539`) refused unverifiable success, held the lease on incomplete rollback, and `restore` verified every config digest |
| SSH-binary readiness probe (fixes the macOS LNP raw-TCP false-negative) | **proven live** | the corrected re-run confirmed all guests over ssh and applied cleanly |

Residual audit findings after migration (NOT migration failures):

- **Host VPN collision (environmental):** the operator's host runs Tailscale on
  `utun9`, which uses `100.64.0.0/10` — the same range as the Rustynet mesh. The
  audit correctly flags the overlap (rulebook §10 records host VPN state). It
  affects host-based mesh evidence, not the lab guests' attachments.
- **Stale `network_group` labels (inventory hygiene follow-up):** the 3 migrated
  guests + `macos-utm-1` now carry labels describing their old networks. The
  `--update-inventory-live-ips` path updates observed IPs but not the declared
  `network_group` label, and there is no sanctioned CLI to update it — a real
  gap. The labels should become `utm-shared-192.168.64.0/24`; left for an
  operator decision rather than a hand-edit (CLAUDE.md §12.3).

## Slice C — orchestrator integration

Status: **core landed 2026-07-10**; scenario-NIC-dependent items are honestly
deferred (they require the approval-gated Slice B fleet application and the
§15.9 owner decisions) and are listed below as `not_run`.

| Item | Status | Evidence |
| --- | --- | --- |
| `--network-profile <id>` on `ops vm-lab-orchestrate-live-lab` (explicit or uniquely derived `mgmt_shared_smoke_v1`; no generic fallback) | done | `resolve_orchestration_network_profile` + flag wiring |
| Immutable per-run profile record `orchestration/network_profile.json` (id + canonical digest, written at launch on BOTH orchestrator paths; resume verifies instead of rewriting) | done | `ensure_orchestration_network_profile_record` |
| Launch-time read-only network audit into `orchestration/vm_network_evidence.json`; explicit profile enforces (non-`pass` audit stops the run before deployment); derived management-only default records without blocking until the fleet migration is approved | done | launch hook |
| Profile drift after launch fails immediately | done | digest re-verification at launch-resume + `PreflightStage` |
| Run-matrix schema: `network_profile_id`/`network_profile_digest`/`network_management_mode`/`network_scenario_substrate`/`network_address_family`/`network_internet_mode`/`network_evidence_path` | done | `live_lab_run_matrix.rs` columns + values from the launch record; documented in `LiveLabRunMatrix.md` |
| External status vocabulary | done (pre-existing stage-contract taxonomy already closed; `skipped` resolves before matrix write via the conclusion barrier; `NetworkEvidenceStatus` adds the profile-level vocabulary incl. `expected_fail`) | `live_lab_stage_registry.rs` + `network_profile.rs` |
| netns ordinary transit → `198.18.0.0/15` (`198.18.0.0/24` default), legacy `100.64.0.0/24` only via explicit `--wan-cidr` under `cgnat_collision_v1` | done | `netns_internet_sim.sh`, `netns_nat_classify.sh`, `netns_nat_filter.sh`, `netns_daemon_path.sh`, `stun_responder.py`; runbook updated |
| Tier 1 live evidence on the new transit | **pass** | [netns_transit_migration_evidence_2026-07-10.json](./netns_transit_migration_evidence_2026-07-10.json): build + positive/negative reachability + mapping 3/3 + filtering 9/9 + clean teardown on `debian-headless-2`; audit `netns_transit_mesh_collision` finding cleared |
| `double_nat_cgnat` | **not_run** (honest: the chained two-router site is still unimplemented; the simulator refuses it fail-loud) | simulator `exit 2` path |
| Management/scenario endpoint split in `orchestrator/context.rs`; scenario-NIC binding for endpoints/exit egress/DNS/captures; management-plane bypass capture assertions; capture lifecycle | **not_run** — requires scenario NICs on real VMs, which requires the approval-gated Slice B application (and Apple multi-NIC live proof, owner decision 5). The typed seams exist (`GuestNetworkPlan`, profile record, scenario substrate vocabulary); binding lands with the fleet migration window (rulebook §16 steps 6-7) | — |
| Daemon-status-not-sole-oracle + packet-capture/handshake evidence requirements | partially in place (profile `EvidencePolicy` declares capture/negative-reachability requirements; enforcement at stage level lands with the capture lifecycle above) | profile model |

## Slice D — MCP integration

Status: **done 2026-07-10** (code + tests; live MCP reconnect happens on the
next client reload per the usual `bin/` install flow).

| Item | Status | Evidence |
| --- | --- | --- |
| `audit_lab_network` (read-only, backed by `ops vm-lab-network-audit`) | done | `lab_state.rs` tool + dispatch |
| `prepare_lab_network` (dry-run plan by default; `approve_reconfigure=true` is the explicit caller authorization that maps 1:1 to the Rust transaction's `--approve-reconfigure`; autonomous loops must not set it) | done | tool description + dispatch |
| `restore_lab_network` (verified idempotent rollback; `list=true` enumerates) | done | tool + dispatch |
| Normal run functions verify-only | done | `start_live_lab_run` gained `network_profile` passthrough only; no mutation path |
| Remove direct MCP AppleScript/plist network mutation | done | `set_utm_vm_bridged_via_applescript` deleted |
| Deprecate `apply_vm_bridged_network` (refuses unconditionally, points at the sanctioned transaction) | done | `apply_vm_bridged_network_always_refuses_as_deprecated` test |
| `ensure_lab_ready(profile)` preserves + re-verifies the profile (verify-only; fail-closed via `vm-lab-network-preflight`; never "repairs" Shared into Bridged) | done | step-4 wiring |
| `preflight_check(profile)` returns network evidence path + canonical digest | done | audit section appended to the report |
| DeepSeek: unconditional `--skip-cross-network` removed — cross-network coverage runs by default; skipping is an explicit caller opt-out | done | `CrossNetworkRunOptions` + updated pinned test |
| DeepSeek: substrate/NAT-profiles/impairment/network-profile propagation (`--cross-network-substrate`, `--cross-network-nat-profiles`, `--cross-network-impairment-profile`, `--network-profile`) | done | `cross_network_options_propagate_and_opt_out_is_explicit` test |
| SOCKS bootstrap presence blocks evidence launches (live reverse-SOCKS tunnel → `start_live_lab_run` refuses unless dry-run) | done | `active_vm_internet_tunnels` gate |
| Recovery invalidates prior evidence + forces fresh preflight (`reset_vm_network`, `apply_host_route_fix` move `state/vm_network_evidence.json` aside) | done | `invalidate_network_evidence` |
| MCP reload/crash preserves lease + transaction truth | done | leases/journals are CLI-owned files under `state/`; MCP holds no in-memory network state |
| `mcp/mcp.json` sync (5 previously-unlisted networking tools + 3 new tools listed; network-profile contract documented; count fixed) | done | manifest |
| `scripts/mcp/install.sh`: builds/installs `rustynet-mcp-deepseek` too; install is now atomic (`cp` to `.new` + `mv`) per the running-binary corruption caveat | done | script |
| MCP test suites | done | 21+67+4+88+19 tests green; clippy `-D warnings` clean |

## Slice E — multi-VM and release tiers

Status: **locally-implementable items landed 2026-07-10**; everything needing
VM mutation, live multi-NIC proof, or external infrastructure is explicitly
`not_run` below — none of it is claimed.

| Item | Status | Evidence |
| --- | --- | --- |
| Generalize `vxlan_tier_b.sh` away from fixed `192.168.0.200-204` | done | underlay hosts are now required inputs (fail-loud, no fleet assumption); overlay migrated to the canonical plan (sites `172.20.x`, transit `198.18.1.x`); runbook + substrate spec updated |
| `isolated_multivm_v1` profile (separate-site VXLAN variant) | done (manifest + audit/preflight support) | `profiles/vm_lab/network/isolated_multivm_v1.toml` |
| Same-site variant | done (manifest) | `profiles/vm_lab/network/isolated_multivm_samesite_v1.toml`; all 5 manifests validate in the live audit |
| Deterministic DHCP/DNS/NTP service components | **not_run** — STUN + relay exist in the netns svc namespace; deterministic DHCP/DNS/NTP responders are unbuilt. Plan: add them to the netns/VXLAN svc node as lab-owned processes with run-scoped ownership markers, after the dual-plane migration window | — |
| Management quarantine / link-down security stages | **not_run** — requires scenario NICs on real VMs (approval-gated Slice B application + §15.9 owner decisions 4/5) | — |
| Linux/macOS/Windows multi-VM dual-plane proof | **not_run** — same gate; Apple-backend multi-NIC remains `unproven` in the capability matrix until the live probe | — |
| `dedicated_physical_lab_v1` (Tier 3) | **not_run** — blocked on §15.9 owner decisions 3/6 (approved host interface + lab router/switch acquisition). Deployment plan: dedicated USB/Thunderbolt NIC or VLAN on a managed switch, an OpenWrt-class router appliance for site segments + declared egress, then a `physical_lab_v1` manifest naming the allowlisted interface (never `en0`) | — |
| `remote_wild_v1` (Tier 4) | **not_run** — blocked on §15.9 owner decision 7 (provider/cost/data-retention/public-IP policy). Deployment plan: two endpoint sites on genuinely distinct networks (e.g. one cloud VM + one cellular/hotspot node) + relay/STUN on a third network, all enrolled through the standard token path | — |

No physical-lab, remote, cloud, or cellular evidence is claimed anywhere in
this program; the capability matrix and audit refuse to promote lower-tier
evidence.

## Final gate run (2026-07-10, working tree on base `b775156`)

- `cargo fmt --all -- --check` — pass.
- `cargo check --workspace --all-targets --all-features` — pass.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — pass.
- `cargo test --workspace --all-targets --all-features` — pass everywhere
  except one PRE-EXISTING failure unrelated to this program:
  `vm_lab::orchestrator::plan::tests::build_returns_canonical_security_stage_order`
  (exit-validation stage-order expectation vs the concurrent in-flight
  orchestrator-quality edits to `plan.rs`; both the test and `plan.rs` were
  already modified in the working tree before this program started).
  `source_archive_marker_matches_worktree_snapshot_commit` flaked once while
  files were being edited mid-run and passes on re-run.
- `cargo audit --deny warnings` + `cargo deny check bans licenses sources
  advisories` — pass (covers the new `toml` dependency).
- `scripts/ci/check_backend_boundary_leakage.sh` — PRE-EXISTING failure in
  `rustynet-control/src/credential_unwrap.rs` (WireGuard tokens in DPAPI doc
  comments, from installer commit `6f46a90`; not touched by this program).
- `scripts/ci/secrets_hygiene_gates.sh` — PRE-EXISTING failure
  (`Bootstrap-RustyNetMacos.sh:907` `rm -f` on a passphrase artifact; known
  RSA-0080, owner decision pending; not touched by this program).

End-to-end enforcement proof (2026-07-10): launching
`vm-lab-orchestrate-live-lab --network-profile isolated_multivm_v1` against
the current drifted fleet REFUSES before deployment (status `fail`, evidence
written); launching without the flag derives `mgmt_shared_smoke_v1`, records
`orchestration/network_profile.json` (digest
`sha256:ab06a230edea88e6…`, derived=true, enforced=false) +
`orchestration/vm_network_evidence.json`, and proceeds.

## Pending operator decisions / approvals

1. **Slice B real-VM application** — awaiting explicit approval; the exact
   plan is in the final report and reproducible via
   `rustynet ops vm-lab-network-prepare --profile mgmt_shared_smoke_v1 --dry-run`.
2. Rulebook §15.9 owner decisions 3–7 (physical interface allowlist, QEMU
   Host Only probe, Apple multi-NIC live proof, lab hardware, remote/cloud
   policy) remain open; nothing here forecloses them.
