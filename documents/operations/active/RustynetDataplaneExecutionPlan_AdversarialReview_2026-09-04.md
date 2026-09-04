# Adversarial Review — RustynetDataplaneExecutionPlan_2026-05-18.md vs Actual Tree

**Status:** UNTRUSTED — machine-generated adversarial verification pass. Every finding below was checked against the working tree at commit `87a81891101789047beb6dc82906a876bd5a9aaa` (branch `ai-edit/edit-1788543008538-26537-9`, 2026-09-04). Line numbers drift with later edits; re-check before citing any file:line pair. The review is docs-only: it reads code, it changes none, it proposes nothing that weakens a fail-closed control.

**Subject:** `documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md` (791 lines, last material amendment §4.1 on 2026-06-11).

**Method note:** the intended external grounded-agent verification (DeepSeek/Kimi/GLM via the AI-agent MCP) was unavailable at review time (402/429/timeout). All checks were instead run directly against the tree with git and grep: every cited commit SHA resolved with `git cat-file -t` and ancestry confirmed with `git merge-base --is-ancestor`; every cited file/symbol with targeted `grep`/`wc`. This is direct evidence, not model opinion.

---

## 1) Findings — stale, wrong, or dead citations

Each finding states the plan's claim, the tree reality, and a severity. `DONE` markers record where the plan's open/queued status has in fact shipped.

### F-01 — STUN environment variable name is wrong
- **Claim (§2.2):** STUN servers configurable via `RUSTYNETD_STUN_SERVERS`.
- **Reality:** no such identifier exists in the tree. The live names are `RUSTYNET_TRAVERSAL_STUN_SERVERS` (env) and `--traversal-stun-servers` (flag) — e.g. `crates/rustynetd/src/linux_killswitch_boot.rs:1360` and `crates/rustynet-cli/src/ops_e2e.rs:959`.
- **Severity:** High (operator-facing; the documented knob silently does nothing).
- **Fix direction:** plan text should name `RUSTYNET_TRAVERSAL_STUN_SERVERS`.

### F-02 — Gossip wire version stale (1 → 2)
- **Claim (§2.5 / D2.5):** `GOSSIP_BUNDLE_WIRE_VERSION=1`.
- **Reality:** `crates/rustynetd/src/peer_gossip.rs:77,104` — the constant is now `2` (bumped after the plan was written). Serialise/deserialise functions and `MAX_GOSSIP_DATAGRAM_BYTES = 4 * 1024` still match.
- **Severity:** Low (documentation staleness only; mechanism unchanged).

### F-03 — Role-preset table count stale (six → nine)
- **Claim (D12):** `ROLE_PRESET_TABLE` holds six presets `Client/Admin/Exit/BlindExit/Relay/Anchor`.
- **Reality:** `crates/rustynet-control/src/role_presets.rs:309` — nine entries; `Nas` and `Llm` were added (D13.a). Consistent with `Capability::ServesNas`/`Capability::ServesLlm` + `ServiceKind` in the same file (:225, :230, :426).
- **Severity:** Medium (the six-preset enumeration is used as the taxonomy reference in the plan).
- **DONE context:** D13.a (Nas/Llm presets + capabilities) has landed.

### F-04 — D13.b–e listed "queued", but the crates exist
- **Claim (D13):** only D13.a complete; D13.b–e "queued".
- **Reality:** `crates/rustynet-nas/` and `crates/rustynet-llm-gateway/` both exist with binaries, tests, and their gate scripts (`service_hosting_role_gates.sh`, `nas_default_deny_gates.sh`, `llm_default_deny_gates.sh`, `llm_exit_coexistence_gates.sh` all present under `scripts/ci/`). The plan's status is behind the code: the service-hosting roles have shipped beyond D13.a. Whether the *live-lab proof* half of D13 is complete is a separate question this static review cannot answer.
- **Severity:** Medium (status-vs-reality).
- **DONE marker:** D13.b–e code: LANDED. Live-lab evidence status: unverified here.

### F-05 — Role-transition file locations implied wrong (relocated to control/cli)
- **Claim (D12):** role machinery described alongside the daemon (`role_presets.rs`, `role_audit.rs`, `role_cli.rs`, `anchor_init.rs` without crate disambiguation).
- **Reality:** `role_presets.rs` and `role_audit.rs` live in `crates/rustynet-control/src/`; `role_cli.rs` and `anchor_init.rs` live in `crates/rustynet-cli/src/`. (Matches the CODE_MAP layering: domain in control, UX/tooling in cli.)
- **Severity:** Low (paths, not behaviour).

### F-06 — All role-machinery size counts stale (grown 2–3×)
- **Claim (D12):** `role_cli.rs` 640 lines + 30 tests; `role_audit.rs` ~550 lines + 14 tests; `transition_plan` 44 tests; `dataplane_candidates.rs` 13 tests.
- **Reality:** `role_cli.rs` ≈ 2022 lines / 56 tests; `role_audit.rs` 25 tests; `role_presets.rs` 93 tests; `dataplane_candidates.rs` 16 tests. All cited constants (`validate_transition` :598, `transition_plan` :603, `verify_role_audit_chain` role_audit.rs:412) are present; only the numbers are stale.
- **Severity:** Low.

### F-07 — start.sh role-preset wizard symbols not found
- **Claim (D11.d):** `start.sh` contains `prompt_role_preset`, `SETUP_ROLE_PRESET`, `normalize_role_preset`, `is_allowed_config_key`.
- **Reality:** none of the four identifiers appear in `start.sh` today. The wizard either moved into Rust (`rustynet operator menu`, `rustynet-advisor` / `anchor_init.rs` CLI path) or was renamed.
- **Severity:** Medium (cited implementation detail is gone from the named file).

### F-08 — Role-audit log path + env var not found
- **Claim (D12):** audit log at `/var/lib/rustynet/role_transitions.audit.log`, overridable via `RUSTYNET_ROLE_AUDIT_LOG_PATH`.
- **Reality:** neither the literal path nor that env name appears in the tree; only `MAX_ROLE_AUDIT_LOG_BYTES` (a size cap constant in `crates/rustynet-control/src/role_audit.rs`) matches. The audit chain mechanism itself (append-only, `verify_role_audit_chain`, 25 tests) is present and verified.
- **Severity:** Medium (a concrete operational artifact claimed at a path that does not exist as stated; either renamed or platform-dependent now).

### F-09 — Cited bash orchestrator scripts deleted (W5.7)
- **Claim (D4, D5.1):** `scripts/e2e/live_linux_cross_network_relay_remote_exit_test.sh`; bash `live_linux_lab_orchestrator.sh` (implied by the live-evidence section and `apply_nat_profile.sh` workflow).
- **Reality:** both scripts are gone. The bash orchestrator was retired in W5.7 (`documents/operations/active/BashOrchestratorRetirementProgram_2026-08-22.md`); the Rust `--node` engine is the only path. `apply_nat_profile.sh` and `netns_internet_sim.sh` DO survive and the three new NAT stage ids (`cross_network_cold_enroll` / `_anchor_renumber` / `_double_nat_anchor`), NAT profiles, and `--cross-network-substrate` all exist in the Rust engine under `crates/rustynet-cli/src/vm_lab/orchestrator/stage/cross_network/`.
- **Severity:** High for anything reading D5.1's runner instructions (the cited execution path no longer exists); the *stage/profile substrate* itself is verified live.
- **DONE context:** D5.1's substrate work landed and migrated engines; only its script citations are dead.

### F-10 — Operating-contract citations dead (§7)
- **Claim (§7):** operating contract anchored on `.claude/agent_cycle_log_2026-05-18.md` (cycle 59) and `PlatformImprovementBacklog_2026-05-14.md`.
- **Reality:** the `.claude/` cycle log does not exist in the tree (untracked scratch, gone). The backlog doc exists but is a dated historical document, not an active contract.
- **Severity:** Low (process citation, not code).

### F-11 — PlatformSupportMatrix.md path drift
- **Claim (§9):** cross-reference to `PlatformSupportMatrix.md` (implied under `documents/operations/active/` alongside the other §9 refs).
- **Reality:** the file lives at `documents/operations/PlatformSupportMatrix.md` (one level up, not in `active/`).
- **Severity:** Low (dead-as-written link).

### F-12 — `crates/rustynet-mobile-core` does not exist (§9)
- **Claim (§9):** cross-reference to `crates/rustynet-mobile-core` via the mobile roadmap.
- **Reality:** no such crate in the workspace (`crates/rustynet-mobile-core` absent). The mobile roadmap doc exists but the crate reference is dead.
- **Severity:** Low.

### F-13 — 25s relay keepalive unverified
- **Claim (§2.3):** zero-ingress relay uses a 25-second keepalive.
- **Reality:** no `25`-second keepalive constant found in `crates/rustynet-relay/src/` (`transport.rs`, `session.rs`). The relay itself is real and rate-limited as claimed; the specific keepalive interval could not be confirmed at any constant in the relay crate.
- **Severity:** Low (unconfirmed detail; not proven wrong).

### F-14 — Test-count claim "3046+ tests" is obsolete (§5.1 D5/D7/D9)
- **Claim (§5.1):** supporting code complete "as of 2026-05-19, 3046+ tests".
- **Reality:** the workspace suite is now ~10k tests (AGENTS.md §7 records 9897–10317 measured). The count is a historical snapshot presented as current status.
- **Severity:** Low (inflates nothing; understates if anything).

### F-15 — D7/D9/D10/D14 open statuses — CORRECT as far as verifiable
- **Claim:** D7 (Windows-as-exit live evidence), D9 (mixed-platform live), D10 (posture promotion), D14 (RFC 5780 NAT discovery, punch-now gossip, port-delta prediction, mailbox) remain open/queued.
- **Reality:** no contradicting evidence found: none of `RFC 5780`, punch-now, mailbox, or cold-contact mechanisms appear in `crates/`; D14's "Depends on D5.1, D5, D11" gating still reads as not-yet-started. The live-lab status matrix (`CrossPlatformRoleParityRefresh_2026-07-23.md`) independently corroborates that mac/win live proof remains the frontier.
- **Severity:** none — confirmed open.

---

## 2) Verified-correct claims (spot-check evidence)

These were checked and match the tree exactly; they are the load-bearing claims of the plan and they hold.

- **All 22 cited commit SHAs are real and ancestors of HEAD:** e0e9a96, 9062970, 5f76c8b, ab93726, 819f472, 2647785 (D2.3); b844faf (D2.4); 429dfa5 (D3); 3bcfdc1, 229b9c7 (D2.5); d2412ee, 0ec1096 (D2.7); 447e40e, 9a86a05 (D5.5); e3f55b7, d7c2c65 (D11); a1c064f, 56b1776, 27b0e39, 1c254ff, e1652c1 (D11 live fixes); 770b2ac (D12 relay action). **Zero fabricated SHAs** — every one resolved via `git cat-file -t` and passed `git merge-base --is-ancestor`.
- **D2.3 (uPnP/NAT-PMP/PCP):** LANDED. `NatPmpClient` (RFC 6886), PCP client (RFC 6887 — comment at `port_mapper.rs:56`), `UpnpIgd` now consolidated in `crates/rustynetd/src/port_mapper.rs` (72 tests); `PortMappingMode{Auto,Keepalive,Disabled}` (:2151) with Keepalive default (:2146); refresh constants `PORT_MAPPING_MIN_REFRESH_INTERVAL_SECS = 30` / `PORT_MAPPING_RECHECK_INTERVAL_SECS = 60` and `DaemonRuntime::maybe_refresh_port_mapping` (`daemon.rs:559,565,6891`); all five cited refresh tests present (`daemon.rs:20326,20346,20360,20382,28495,28534`).
- **D2.4 (IPv6 candidates):** LANDED. `crates/rustynetd/src/dataplane_candidates.rs` with `CandidateSet{v4_host, v6_host, v4_srflx, v6_srflx}` (:378–382), 16 tests.
- **D3 (relay client shared socket):** LANDED. `attach_authoritative_transport` at `crates/rustynetd/src/relay_client.rs:402`; no `RelayClient::bind(UdpSocket)` remains.
- **D2.5 (peer gossip primitives):** LANDED. `peer_gossip.rs` serialise/deserialise; `RUSTYNET_GOSSIP_PORT = 51821` (`gossip_transport.rs:60`); `MAX_GOSSIP_DATAGRAM_BYTES = 4 * 1024`; `IpcCommand::PushGossipBundle` (`ipc.rs:67`); `--gossip-watermark` + `RUSTYNET_GOSSIP_WATERMARK` (`rustynetd main.rs:3352`); `gossip_three_peer_mesh.rs:138` propagation test present.
- **D2.7 (enrollment tokens):** LANDED. CLI subcommands mint/verify/consume + admit (`rustynet-cli main.rs:216–221,564,602`); `rn-enroll` prefix, `EnrolleeAdmitContext`, `build_add_node_record_for_enrollee` in `crates/rustynet-control/src/enrollment.rs`; `IpcCommand::EnrollmentConsume` (`ipc.rs:77`); `enrollment_consume.rs` present; both integration tests present (`enrollment_two_peer_redeem.rs:110`, `enrollment_trust_propagation.rs:126`).
- **D4 (relay binary):** LANDED as code. `crates/rustynet-relay/src/{main,transport,session,rate_limit}.rs`; rate caps exactly as claimed — `max_pps = 10_000`, `max_bps = 100_000_000`, `max_sessions_per_node = 8` (`rate_limit.rs:19–21`).
- **D5.5 (ICE pair race):** LANDED. `TraversalEngine` (`traversal.rs:1338`), `execute_ice_pair_race` (`traversal.rs:1637`); both cited tests present (`ice_pair_race.rs:156`, `:456`).
- **D11 (anchor role):** LANDED. Anchor caps in `crates/rustynet-control/src/membership.rs`; `--anchor-bundle-pull-{addr,token-path,allow-lan}` flags (`rustynetd main.rs:3273–3299`); `anchor_init.rs` in cli; `IpcCommand::RouteRetract` (`ipc.rs:57`).
- **D12 (role taxonomy):** LANDED mechanically. `ROLE_PRESET_TABLE` (`role_presets.rs:309`), `validate_transition` (:598), `transition_plan` (:603), `verify_role_audit_chain` (`role_audit.rs:412`); systemd relay installer (`ops_install_systemd_relay.rs`, dry-run test `dry_run_install_reports_planned_steps`) + `scripts/systemd/rustynet-relay.service`; macOS relay installer (`ops_install_macos_relay.rs`, `dry_run_install_reports_planned_launchctl_steps`, `dry_run_uninstall_reports_planned_bootout`) + `scripts/launchd/com.rustynet.relay.plist`; `execute_platform_relay_service_action` (commit 770b2ac) in `ops_e2e.rs` + cli `main.rs`; Windows PS helpers `Install-RustyNetWindowsRelayService.ps1` / `Uninstall-RustyNetWindowsRelayService.ps1` present.
- **D6 (Windows traffic collector):** LANDED. `collect_node_id` + `RUSTYNETD_DAEMON_ARGS_JSON` + `rustynetd.env` parsing in `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_traffic.rs:69–98`.
- **§4.1 substrate references (amended 2026-06-11):** the three NAT stages, NAT profile labels (`port_restricted_cone`/`full_cone`/`symmetric`/`double_nat_cgnat`), modifiers, and `--cross-network-substrate={netns,vxlan,slirp}` all exist in the Rust `--node` engine; `apply_nat_profile.sh` + `netns_internet_sim.sh` survive.
- **two_hop evidence hygiene (per review instruction):** the genuine per-stage ledger `documents/operations/live_lab_node_stage_results.csv` shows `live_two_hop_validation` at **pass 134 / fail 121 / skip 559** — matching the known genuine ~134-pass figure. The plan does not currently cite a two_hop pass count; **any future citation must use the per-stage CSV figure (134), never the contaminated `live_lab_node_run_matrix.csv` column** (whose `linux_stage_two_hop` passes are dominated by the removed `traffic_test_matrix` alias mapping; that contamination is documented in AGENTS.md §12.3).

## 3) Considered, no issue

- **§3 non-goals** (no port-prediction, no TCP-443 primary, no exit-node in base plan): consistent with the tree — no such mechanisms found in `crates/`; nothing landed that contradicts the declared non-goals.
- **Fail-closed posture:** nothing in the plan's landed work weakens default-deny. The anchor port-mapping authority gate (`port_mapping_bring_up_skip_reason` fail-closed unless anchor.port_mapping_authoritative) is present as described. This review endorses no change to any fail-closed control.
- **§8 open-questions table** (port-mapping default still Keepalive, mailbox No, port-delta No, WG-over-TCP No): each "No" remains accurate — no mailbox, no port-delta prediction, no WG-over-TCP found.
- **§10 DoD (24h real soak):** aspirational gate; no contradiction found.
- **Status header "active ledger":** AGENTS.md §2 still lists this plan as the active cross-network dataplane ledger; that listing is accurate as a mandate, but see the verdict below on content staleness.

## 4) Verdict

**The plan's engineering substance is real — every commit SHA is genuine, every major track D2–D13 that claims completion has verifiable artifacts in the tree, and no claim was found fabricated — but its point-in-time details (env var names, wire version, table sizes, file locations, test counts, and two cited runner scripts) have drifted or died, and D13's "queued" status is behind code that has already shipped.**

**Refresh call:** this document needs a status-refresh pass (env-var names F-01, wire version F-02, taxonomy count F-03, D13 status F-04, script citations F-09, §7/§9 dead refs F-10/F-11/F-12) the next time it is edited — but it should **not** be archived: it remains the only document that explains *why* the traversal/relay/track architecture is shaped the way it is, and its non-goals and residual-gap analysis (§3, §4.1) are still the operative decision record. The refresh should be a targeted errata list, not a rewrite.

---

*Review generated 2026-09-04 against commit `87a81891101789047beb6dc82906a876bd5a9aaa`. Docs-only change; no code touched; no fail-closed control weakened or proposed for weakening. Self-verification of this document's own four key citations (F-01 env var, F-02 wire version, F-03 table location, two_hop CSV count) was re-run after drafting and passed.*
