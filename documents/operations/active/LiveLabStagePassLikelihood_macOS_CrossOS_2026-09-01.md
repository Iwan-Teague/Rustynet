# Live-Lab Stage Pass-Likelihood — macOS + Cross-OS never-passed cells on `--node` — 2026-09-01

**Status:** docs-only analysis (lab DOWN — no run launched, no live pass claimed). Grounded in a quote-aware parse of `documents/operations/live_lab_node_run_matrix.csv` (242 rows), the per-stage truth ledger `documents/operations/live_lab_node_stage_results.csv` (35,585 rows), the `--node` stage registry + plan builder + stage implementations under `crates/rustynet-cli/src/`, and the curated parity docs (`CrossPlatformRoleParityRefresh_2026-07-23.md` — the `--node` status of record — plus the ParityPlan and Roadmap). No `.rs` file was touched.

**Engine of record:** the Rust `--node` orchestrator. The bash archive (`live_lab_run_matrix.csv`) was never consulted. All "pass" claims below come from the stage's own report/per-stage rows or the curated refresh doc, never from a roll-up column alone (QH-07).

---

## 0. Headline

Of the ~30 macOS + cross-OS ledger columns with zero `pass` on `--node`:

- **6 are dead or feeder-less columns, not stages** (§4): `macos_keychain_key_custody`, `macos_runtime_acls`, `macos_service_hardening`, `macos_mesh_status`, `macos_authenticode`, `macos_hello_limiter_flood` are bash-dialect `special` columns whose live work moved to `--node` stages that already pass (`macos_stage_{runtime_acls,service_hardening,mesh_status,authenticode,key_custody}_check` = 18 pass each; `macos_stage_hello_limiter_flood` = 6 pass). They must not be reported as "stages that never pass."
- **~17 are skip-only WIRING cells** — the stage exists, is implemented (Linux passes the same stage), and skips on macOS because the run never dispatched it: the `--skip-linux-live-suite` fast path every mac/win target key sets drops the whole post-baseline suite (`plan.rs` `include()`: `StageSuite::Live => !skip_live_suite`, 61 → 19 stages), or no mac node was elected into the role the stage needs (`EnableRule::MacosExit` / `AnchorPlatform("macos")` / `RoleSwitchPlatform("macos")` / `BlindExitPlatform("macos")`), or an opt-in suite flag (`chaos`, `soak`) was never set.
- **1 is the big ENVIRONMENTAL blocker** — CP-1: the macOS UTM guest (Shared-NAT `192.168.65.101/24`) and the Debian nodes (host bridge100 `192.168.64.0/24`) have no L3 path between them (measured live 2026-08-29: pure-L3 pings 0/2 both ways with all daemons stopped). This caps `two_hop`, `traffic_test_matrix`, `macos_client`, and `cross_os_peer_visibility`.
- **~6 are genuine CODE gaps** — validators/adapter methods implemented for Linux only, which skip-with-reason by design on a macOS node: the exit-family checks (`ipv6_leak`, `exit_demotion_residue`, `exit_dns_failclosed`, `exit_nat_lifecycle`, `blind_exit_dataplane` — all `*_runtime_implemented` = Linux-only) and the orchestrator's active-exit-serving adapter (`active_exit.rs:184` — Linux + Windows, **not** macOS). Plus one real forward defect found live 2026-08-31: the macOS anchor's signed membership lacks `anchor.port_mapping_authoritative`.
- **1 is gated on Windows, not macOS** — `mixed_topology` needs all three platforms assigned; Windows has never bootstrapped on `--node` (CP-4).

Two ledger-treachery caveats that cut in BOTH directions:

1. **The 242-row ledger UNDERCOUNTS current progress.** The 2026-08-31 MAC-D1 milestone run (`labrun-1788266019601-1574-3`, commit `451f9730`) dispatched the three `MacosAnchor*` stages for the first time and passed `deploy_macos_anchor_profile` + `validate_macos_anchor_bundle_pull` + `anchor_validation` — but "the detached `ai_lab_run` orchestrator did not auto-append the tracked run-matrix row — a known workspace-root-resolution gap." So `macos_stage_anchor` reading "71 skip, 0 pass" is stale, not current truth.
2. **QH-07 flag on the macOS two_hop-adjacent claim:** the 8 `macos_stage_two_hop=fail` rows predate the 2026-07-27 QH-07 de-alias (the alias removal that cleaned `linux_stage_two_hop`), and the per-stage ledger shows **`live_two_hop_validation` has only ever `skip`ped on macOS (32/32) — the chained-exit validator itself has NEVER dispatched on macOS**. The 8 fails were written by `traffic_test_matrix` (mesh ping matrix; 19 macOS per-stage fails). Both stages require the same cross-subnet L3 adjacency whose absence was measured live, so the CP-1 ENVIRONMENTAL verdict is unaffected — but "macOS two_hop failed 8/8" is really "macOS mesh-ping failed; chained two-hop never ran."

---

## 1. Group 1 — macOS role / exit / anchor live cells

### `macos_stage_two_hop` — 8 fail / 24 skip / 0 pass
- **Citation:** run-matrix roll-up; per-stage truth `live_two_hop_validation` on macOS = 32 skip (last 2026-08-29T20:43:06Z), `traffic_test_matrix` on macOS = 19 fail / 13 skip with the CP-1 signature ("debian-headless-4 → macos-utm-1 (100.64.181.171): ping … failed (exit 1)").
- **Root cause:** **ENVIRONMENTAL** (CP-1, triaged 2026-08-29 in the refresh doc §2): no L3 path between the UTM Shared-NAT subnet and bridge100; WG endpoint packets cannot arrive in either direction. Code-side the macOS userspace-shared transport is implemented and unit-tested (`userspace_shared_macos/{socket,runtime,tun}.rs`).
- **Pass-likelihood: HIGH — but only after an operator network fix, and note it has never actually dispatched.** The validator's own guards are topology-based ("two-hop needs an `entry` hop and a second client…", `live_two_hop_validation.rs:33-61`), platform-neutral; Linux is 130 pass on the same stage.
- **Improvements (pre-condition is the operator `prepare_lab_network` bridged re-attach, not code):** (small) orchestrator fail-louder hardening already proposed in the refresh doc — pre-check endpoint-subnet reachability before `traffic_test_matrix` so a partitioned topology fails with "no L3 path <src>→<endpoint>" instead of packet-loss-looking output.

### `macos_stage_anchor` — 71 skip / 0 pass (STALE — see ledger caveat 1)
- **Citation:** refresh doc §1 anchor row (MAC-D1 rerun CONFIRMED 2026-08-31): `bootstrap_hosts`→`validate_baseline_runtime` all pass; `anchor_validation` graded `pass` on real delegated evidence in run `labrun-1788266019601-1574-3`.
- **Root cause of the skip history:** **WIRING** — `--skip-linux-live-suite` dropped the three `MacosAnchor*` stages from the plan, so MAC-D3's election-tightening check (`native.rs:376-383`) fail-closed-skipped. Fixed twice: plan-builder anchor-election awareness (`e3297391`) + election derived from the `--node` anchor assignment (`451f9730`, `plan.rs` `include()` MAC-D3 exception).
- **Remaining CODE defect:** `validate_macos_anchor_port_mapping_authority` fails for a real reason — the macOS anchor's signed membership lacks `anchor.port_mapping_authoritative` (Linux exit won the authority election). Same family as the exit-cell membership/role gap; the fix belongs in the owner-gated signed-capability-rewrite design (`MacosExitMembershipRoleFixDesign_2026-08-31.md`), not an ad-hoc patch.
- **Pass-likelihood: HIGH for `anchor_validation`/`bundle_pull` on the next anchor-elected run (already proven once).** `macos_stage_anchor` flipping to `pass` in the roll-up additionally needs the port-mapping-authority cell resolved: **MEDIUM** overall, **LOW** for the authority cell until the capability rewrite lands.

### `macos_stage_exit_handoff` — 32 skip / 0 pass
- **Citation:** per-stage `exit_handoff`/`active_exit` on macOS = 32 skip; skip text "active-exit runtime is not implemented for Macos" (`active_exit.rs:88-92`); predicate `active_exit_runtime_implemented` = Linux + Windows, explicitly NOT macOS (`active_exit.rs:177-201`, test `runtime_implemented_linux_and_windows_not_macos`).
- **Root cause:** **WIRING then CODE**. WIRING: only 32 macOS runs reached this stage region and a mac exit was first elected only 2026-08-28. CODE: the orchestrator's active-exit-serving adapter has no macOS implementation, so even an elected mac exit skips the handoff proof. The product daemon does enforce-time `pf` NAT on macOS (refresh §6) — the gap is in the orchestrator adapter, not the product.
- **Also gating:** the exit cell's `DnsFailclosed` baseline validator reds on macOS by design (owner-gated enforcement gap, `1278af04`), which keeps any macOS exit run overall-red regardless.
- **Pass-likelihood: LOW.**
- **Improvements (medium):** implement the macOS exit-serving methods on the orchestrator adapter (`adapter/macos.rs` + `active_exit.rs`) driving/asserting the product's enforce-time `pf` NAT — per refresh §6 (S2) this must carry an equivalent-strength end-to-end egress assertion, not a mechanism-translated nft assertion. Root fix for `DnsFailclosed` is the large, owner-gated macOS DNS enforcement design.

### `macos_stage_lan_toggle` — 32 skip / 0 pass
- **Citation:** `live_lan_toggle_validation.rs:49-52` — skips when "no blind_exit node is available in this topology"; `EnableRule::LinuxLiveSuite` semantics via the suite gate; never dispatched on macOS (32 skips = fast-path runs).
- **Root cause:** **WIRING** (fast path + no mac blind_exit topology in a full-suite run). The runtime supports macOS (`blind_exit_runtime_implemented` = Linux | Macos, `role_validation/blind_exit.rs:6`), and the mac blind_exit cell passed its runtime validation 2026-08-31.
- **Pass-likelihood: MEDIUM** — needs one full-suite (no `--skip-linux-live-suite`) run electing mac `blind_exit`; the toggle mechanism itself is platform-aware (LAN toggle = disable/enable the guest NIC — no nft dependency in the stage's guard).
- **Improvement:** none needed in code to attempt; budget one full Linux-suite-priced run.

### `macos_stage_role_switch_matrix` — 32 skip / 0 pass
- **Citation:** `role_switch_matrix.rs` — PerNode, platform-neutral (`execute` iterates all assignments, `collect_active_tunnels` implemented per platform incl. macOS at `adapter/macos_traffic.rs:381`); Linux = 483 pass.
- **Root cause:** **WIRING** — fast-path runs never dispatched it on macOS.
- **Pass-likelihood: HIGH** on the first full-suite run with a macOS node. No code work.

### `macos_stage_mixed_topology` — 32 skip / 0 pass
- **Citation:** `live_mixed_topology_validation.rs:50-53` — skips unless "every platform in the matrix is assigned a node"; Linux per-stage = 700 skip, 0 pass/0 fail — **never dispatched anywhere**.
- **Root cause:** **WIRING + ENVIRONMENTAL/HARDWARE-by-proxy** — requires healthy Linux + macOS + Windows simultaneously; Windows bootstrap is CP-4-blocked (WinGet Configuration, `Bootstrap-RustyNetWindows.ps1:1130`).
- **Pass-likelihood: LOW** (until CP-4 clears; not a macOS defect).
- **Improvement:** none macOS-side; unblock W-FIX-1 first.

### `macos_stage_reboot_recovery` — 32 skip / 0 pass
- **Citation:** `live_reboot_recovery_validation.rs` — platform-aware ssh users incl. macOS `admin` (`:144-147`); Linux = 176 pass.
- **Root cause:** **WIRING** (fast path).
- **Pass-likelihood: HIGH** on a full-suite run; no code work.

### `macos_stage_extended_soak` — 15 skip / 0 pass
- **Citation:** registry `extended_soak` spec — `EnableRule::SoakSuite`, and `TargetSelectors::resolves` defines SoakSuite as `soak_suite && !skip_linux_live_suite` with the comment "extended_soak only ever dispatches as part of the Linux live suite" (`live_lab_stage_registry.rs:336-346`); `live_extended_soak_validation.rs:44-47` additionally requires a second client. **Per-stage rows: zero, on every platform — the stage has NEVER dispatched.**
- **Root cause:** **WIRING** — the soak selector is never set by the default plan or the wrapper keys; `--skip-soak` is exposed but no enable flag is wired into the mac/win paths.
- **Pass-likelihood: MEDIUM** (code looks platform-aware; never exercised anywhere, so first dispatch is an unknown-unknown).
- **Improvement (small):** wire a `--enable-soak-suite` selector through `TargetSelectors`/the orchestrator flags and the mac/win target keys so the stage can at least be elected; expect a triage pass on first run.

### `macos_stage_chaos` — all not_run (242)
- **Citation:** chaos StageIds (`ChaosClockAttack` … `ChaosSignedStateAdversarial`, `stage/mod.rs:292-302`) are `StageSuite::Chaos`, included only under `--enable-chaos-suite` (`plan.rs` `include()`: `StageSuite::Chaos => !skip_live_suite && enable_chaos_suite`).
- **Root cause:** **WIRING** — opt-in never selected; the chaos stage code is platform-aware (per-platform ssh user incl. macOS, `chaos.rs:231-234`).
- **Pass-likelihood: MEDIUM** — never run on any platform on `--node`; first run is triage, and individual attacks may expose macOS gaps (e.g. clock/`sigstop` semantics differ). Not expected to pass N-of-N on first contact.
- **Improvement:** none required to attempt; treat first run as diagnosis (refresh §3 JOIN: "first sub-step is run it once and triage").

### `macos_stage_role_transition` — all not_run (242)
- **Citation:** election gate `EnableRule::RoleSwitchPlatform("macos")` (`live_lab_stage_registry.rs:1235-1236`); the orchestrator skip-reason string is explicit — "skipped: {macos_alias} is not elected for role transition (role_switch_platform != macos)" (`vm_lab/mod.rs:12676`); refresh §1 role-transition row: "⬛ never run on `--node`" both OS.
- **Root cause:** **WIRING** — `--role-switch-platform macos` has never been passed; the role-transition cell (LocalOnly flips + the restored `SignedMembership`-kind transitions, review S3) is unproven on either OS.
- **Pass-likelihood: MEDIUM** — the election knob exists and the transition validator is `transition_plan`-backed; but no `--node` dispatch has ever been observed, so treat first run as triage (verify the Rust plan actually dispatches a mac role-transition stage; the macOS-specific `validate_macos_role_transition` registry spec has no dedicated StageId — election wiring on the `--node` path is the thing to confirm first).
- **Improvement (small, confirm-then-fix):** verify a `--node` StageId dispatches the mac role-transition cell when `--role-switch-platform macos` is set; if it only exists in the legacy wrapper vocabulary, add the StageId + plan arm before spending a lab run.

---

## 2. Group 2 — macOS security / custody / dns `_check` cells

Context: the six baseline validators that DO run on macOS (`macos_stage_{dns_failclosed,runtime_acls,service_hardening,key_custody,mesh_status,authenticode}_check`) are 18 pass each (1 `DnsFailclosed` fail — the known owner-gated exit-posture gap). The cells below are the *post-baseline / exit-family* stage columns, all 32 skip / 0 pass.

### `macos_stage_secrets_not_in_logs` / `macos_stage_key_custody` / `macos_stage_enrollment_restart` — 32 skip each
- **Citation:** `live_secrets_not_in_logs_validation.rs` / `live_key_custody_validation.rs` / `live_enrollment_restart_validation.rs` — all platform-aware (Linux root / macOS admin / Windows administrator); Linux passes each (176 / 176 / 60). `enrollment_restart` additionally skips "no node in this topology is assigned the aux role" (`:36-39`).
- **Root cause:** **WIRING** (fast path; enrollment_restart also needs an `aux`-role node in the topology).
- **Pass-likelihood: HIGH** for secrets/key_custody; **MEDIUM-HIGH** for enrollment_restart (aux-role topology requirement). No code work.

### `macos_stage_network_flap` — 32 skip
- **Citation:** `live_network_flap_validation.rs` platform-aware; Linux = 180 pass / 121 fail — CP-2 (traversal self-sustenance: mesh fail-closes ~120 s after last distribution; `TraversalSelfSustenancePlan_2026-07-23.md` I3-I6 remaining).
- **Root cause:** **WIRING** for the macOS skips, but the stage is expected to **fail** on macOS too once dispatched, for the same CP-2 product gap.
- **Pass-likelihood: MEDIUM** — dispatch is trivial (full suite), but a green needs CP-2 landed (it is the one stage allowed RED for G1 but required GREEN for G2 on every OS).

### `macos_stage_ipv6_leak_check` — 32 skip
- **Citation:** skip text "not implemented for Macos" via `ipv6_leak_runtime_implemented` = Linux only (`role_validation/ipv6_leak.rs:17-19`); 22 macOS dispatches recorded (anchor + exit + client roles, 2026-07-19 → 2026-08-29), all skip. Linux = 507 pass.
- **Root cause:** **CODE** (deliberate fail-closed stub — no macOS IPv6-leak probe exists).
- **Pass-likelihood: LOW.**
- **Improvement (medium):** implement the macOS probe in `role_validation/ipv6_leak.rs` — probe a global v6 address while capturing on the egress interface (`tcpdump -i en0 ip6` + utun check), extend the predicate to `Macos`. **Pre-check first whether the UTM guest even has upstream IPv6** — if the lab NAT offers no v6 egress, this is ENVIRONMENTAL/HARDWARE and the honest disposition is a recorded skip-with-reason, not a new validator.

### `macos_stage_exit_demotion_residue_check` — 32 skip
- **Citation:** `exit_demotion_residue_runtime_implemented` = Linux only (`role_validation/exit_demotion_residue.rs:23-24`); 8 macOS exit dispatches (2026-08-28/29), all skip; Linux = 122 pass.
- **Root cause:** **CODE** (Linux-only probe: nft NAT teardown + forwarding restore after exit→client demotion).
- **Pass-likelihood: LOW.**
- **Improvement (medium):** macOS analogue in `exit_demotion_residue.rs` — snapshot `pfctl -s nat`/`-s rules` during exit and after demotion, assert the pf NAT anchor is gone and forwarding (`net.inet.ip.forwarding`) restored with the daemon still running; extend the predicate to `Macos`.

### `macos_stage_exit_dns_failclosed_check` — 32 skip
- **Citation:** `exit_dns_failclosed_runtime_implemented` = Linux only (`role_validation/exit_dns_failclosed.rs:28-30`); 8 macOS exit dispatches, all skip; Linux = 125 pass. Independent product blocker: the macOS DNS fail-closed **enforcement** gap (`MacosDnsFailclosedEnforcementGap_2026-08-28.md`, disposition `1278af04`) — the posture is written to files the OS does not consult (`/etc/resolv.conf` is a configd-generated shim); the baseline `DnsFailclosed` validator already reds on the macOS exit cell.
- **Root cause:** **CODE**, two layers — validator missing for macOS, and underneath it a real product enforcement leak that is owner-gated.
- **Pass-likelihood: LOWEST in the set.**
- **Improvement (large, owner-gated):** land the macOS DNS enforcement design first (scoped resolvers / pf redirect to the daemon's resolver, killswitch-consistent); only then implement the six-artifact macOS evaluator. Do not write a macOS validator that greens against unenforced posture — that would be a fake pass.

### `macos_stage_exit_nat_lifecycle_check` — 32 skip
- **Citation:** `exit_nat_lifecycle_runtime_implemented` = Linux only (`role_validation/exit_nat_lifecycle.rs:15-17`); 8 macOS exit dispatches, all skip; Linux = 124 pass.
- **Root cause:** **CODE** (two-phase nft NAT snapshot/teardown proof has no pf equivalent).
- **Pass-likelihood: LOW.**
- **Improvement (medium):** pf two-phase validator in `exit_nat_lifecycle.rs` — `pfctl -s nat` snapshot during active exit, daemon stop, second snapshot, merge + evaluate (mirror `validate_linux_exit_nat_lifecycle`'s shape); extend predicate to `Macos`.

### `macos_stage_blind_exit_dataplane_check` — 32 skip
- **Citation:** `blind_exit_dataplane_runtime_implemented` = Linux only (`role_validation/blind_exit_dataplane.rs:14-16`); the stage skips "no node executed this validation; N node(s) reported a runtime skip" (`blind_exit_dataplane_validation.rs:117-120`). Linux = 12 skip / 2 fail, **0 pass** (young stage everywhere).
- **Root cause:** **CODE** (nft ruleset capture + five subchecks has no pf analogue), and the stage is not green anywhere yet.
- **Pass-likelihood: LOW.**
- **Improvement (small-medium):** pf ruleset capture (`pfctl -s rules`) + mapping of the five subchecks (mesh-scoped forward, no NAT, no unrestricted forward, no own-egress) in `blind_exit_dataplane.rs`; extend predicate to `Macos`. Sequence after a Linux green exists so the macOS port is not the first-ever run.

---

## 3. Group 3 — cross-OS integration cells

### `cross_os_peer_visibility` — 19 fail / 15 skip / 0 pass
- **Citation:** fed on `--node` by `traffic_test_matrix` and `validate_macos_mesh_join` (`cross_os:` fields, registry `:991,:1074`); the fails carry the CP-1 signature (mac peer `100.64.181.171` unreachable from Debian peers).
- **Root cause:** **ENVIRONMENTAL** (CP-1) — same L3 partition; the column is the cross-OS face of it.
- **Pass-likelihood: HIGH** after the operator network re-attach, on a multi-platform run. No code.

### `cross_os_exit_path` — 34 skip / 0 pass
- **Citation:** fed by `exit_handoff`/`active_exit` (registry `cross_os: Some("cross_os_exit_path")`); `active_exit` skips for a macOS exit ("not implemented for Macos").
- **Root cause:** **CODE** (no macOS exit-serving adapter) + CP-1 underneath.
- **Pass-likelihood: LOW** until the macOS exit adapter lands (see §1 exit_handoff). Linux↔Windows exit-path is also unproven (Windows bootstrap CP-4), so the column needs two fixes to go green in the general case.

### `cross_os_role_switch` — 34 skip / 0 pass
- **Citation:** fed by `role_switch_matrix` (registry `cross_os` field); macOS side = the 32 WIRING skips of §1.
- **Root cause:** **WIRING** (fast path; multi-platform full-suite runs with roles on both platforms have not been priced).
- **Pass-likelihood: HIGH** on the first full multi-platform suite run — same fix as `macos_stage_role_switch_matrix`, zero code.

### `cross_os_lan_toggle` — all not_run (242)
- **Citation:** schema column exists (`live_lab_run_matrix.rs:206`) but the **only** registry spec with `cross_os: Some("cross_os_lan_toggle")` is the bash-dialect `live_lan_toggle` (registry `:1951`); the `--node` spec `live_lan_toggle_validation` (`:2019-2024` region) carries `logical: Some("lan_toggle")` and **no** `cross_os` field. On `--node` the column has no feeder.
- **Root cause:** **DEAD-ish / wiring gap** — legacy aggregate with no `--node` feeder, plus the underlying stage has never dispatched on macOS anyway.
- **Pass-likelihood: LOW** (structurally unfed).
- **Improvement (small):** add `cross_os: Some("cross_os_lan_toggle")` to the `--node` `live_lan_toggle_validation` registry spec so the aggregate is fed once the stage runs cross-platform; then it inherits §1 lan_toggle's MEDIUM.

### `cross_os_anchor_enrollment` — all not_run (242)
- **Citation:** column in the fixed schema (`live_lab_run_matrix.rs:209`); **no registry spec in either dialect carries `cross_os: Some("cross_os_anchor_enrollment")`** — no feeder exists at all.
- **Root cause:** **DEAD COLUMN** — superseded by `cross_os_anchor_bundle_pull` (fed by `anchor_validation`, 1 pass — the MAC-D1 milestone), which is the live anchor cross-OS cell.
- **Disposition:** report as dead; do not count as a never-passing stage.

---

## 4. Group 4 — dead-column determinations (all `not_run` × 242)

Verified against the `--node` plan builder (`plan.rs` `StageId::ALL` match — the only `Macos*` StageIds are `MacosAnchorProfileDeploy`, `MacosAnchorBundlePullValidation`, `MacosAnchorPortMappingAuthorityValidation`) and the `special_column`/`cross_os_column` feeders:

| Column | Verdict | Superseded by (live on `--node`) |
|---|---|---|
| `macos_keychain_key_custody` | **DEAD** (bash-era special of `validate_macos_key_custody`; no StageId) | `macos_stage_key_custody_check` — 18 pass |
| `macos_runtime_acls` | **DEAD** (special, no StageId) | `macos_stage_runtime_acls_check` — 18 pass |
| `macos_service_hardening` | **DEAD** (special, no StageId) | `macos_stage_service_hardening_check` — 18 pass |
| `macos_mesh_status` | **DEAD** (special, no StageId) | `macos_stage_mesh_status_check` — 18 pass |
| `macos_authenticode` | **DEAD** (special, no StageId) | `macos_stage_authenticode_check` — 18 pass |
| `macos_hello_limiter_flood` | **DEAD** (special, no StageId) | `macos_stage_hello_limiter_flood` — 6 pass via `LiveHelloLimiterFloodValidation` |
| `macos_pf_killswitch` | **DEAD — with a coverage caveat** (special of `validate_macos_exit_killswitch_precedence`; no StageId) | *Nothing.* Killswitch-precedence proof on a macOS exit has NO live `--node` successor — the exit-family validators are Linux-only (§2). Flag as a real coverage gap to fold into the macOS exit-serving work, not a clean supersession. |
| `cross_os_anchor_enrollment` | **DEAD** (no feeder in any dialect) | `cross_os_anchor_bundle_pull` — 1 pass |

Contrast: the other eight macOS `special` columns (`macos_membership_revoke_applies`, `macos_membership_signature_forgery`, `macos_gossip_revoked_readmit`, `macos_enrollment_replay`, `macos_privileged_helper_allowlist`, `macos_policy_default_deny`, `macos_revoked_peer_denied_e2e`, `macos_blind_exit_reversal_denied`) **are live** — 11 pass each, fed by `SecurityAuditValidation` (the eight Tier-0 daemon self-audits). Not dead; not part of this bucket.

---

## 5. Ranked quickest wins (most-likely-to-pass-with-least-work first)

1. **Full-suite macOS run, client role, no code changes** → expect first `--node` passes for `macos_stage_role_switch_matrix`, `macos_stage_reboot_recovery`, `macos_stage_secrets_not_in_logs`, `macos_stage_key_custody` (all HIGH; Linux-proven stages, platform-aware code). Cost: one full Linux-live-suite-priced run (~30-45 min) instead of the fast path.
2. **Same run, add an `aux`-role node** → `macos_stage_enrollment_restart` (MEDIUM-HIGH).
3. **Operator: `prepare_lab_network` bridged re-attach of macos-utm-1 onto the 192.168.64.0/24 segment** (explicit operator authorization per the LiveLabVmConnectivityRulebook — never an autonomous mutation), then a focused `rebuild_nodes` macOS run → CP-1 closes or refutes; `cross_os_peer_visibility`, `traffic_test_matrix`/`macos_client`, and (first-ever macOS dispatch of) `live_two_hop_validation` all unlock. No code.
4. **Anchor cell re-run with `anchor_platform=macos`** (fixes already landed: `e3297391`, `451f9730`) → `macos_stage_anchor` harvest; then fold the `anchor.port_mapping_authoritative` capability rewrite into `MacosExitMembershipRoleFixDesign_2026-08-31.md` (medium) to clear the one real anchor defect.
5. **mac `blind_exit` topology in a full-suite run** → `macos_stage_lan_toggle` (MEDIUM).
6. **Small wiring fixes:** `--enable-soak-suite` selector (so the never-dispatched `extended_soak` can run at all); `cross_os:` field on the `--node` `live_lan_toggle_validation` spec; confirm the `--role-switch-platform macos` `--node` dispatch exists, then elect it → `macos_stage_role_transition`. Each small; each needs a run to verify.
7. **Opt-in first-runs as triage:** `--enable-chaos-suite` with a mac node (MEDIUM, expect findings, not N-of-N green).
8. **Per-OS validator ports (each LOW today, each small-medium once its role is elected):** `blind_exit_dataplane` pf port (after a Linux green), `exit_nat_lifecycle` pf two-phase, `exit_demotion_residue` pf residue, `ipv6_leak` macOS probe (pre-check lab v6 egress first — may be environmental).
9. **macOS exit-serving adapter** (`active_exit.rs` + `adapter/macos.rs`, medium-large, with the S2 end-to-end egress assertion) → unlocks `macos_stage_exit_handoff` + `cross_os_exit_path` — but only after CP-1 and alongside:
10. **macOS DNS fail-closed enforcement design** (large, owner-gated) — the last blocker for any overall-green macOS exit run and for `macos_stage_exit_dns_failclosed_check`.
11. **Not macOS's problem:** `macos_stage_mixed_topology` waits on Windows bootstrap (W-FIX-1, CP-4).

---

## 6. Method notes

- Roll-up counts in §0/§2 from a `python3 csv.DictReader` parse (quote-aware per QH-07; `awk -F,` was not used). Per-stage truth from `live_lab_node_stage_results.csv` joined on `stage`+`platform`, with `error_detail` read where populated.
- Predicate support matrix read from `crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/*.rs` (`*_runtime_implemented`); plan inclusion from `vm_lab/orchestrator/plan.rs` (`include()`); election rules from `live_lab_stage_registry.rs` (`EnableRule`/`TargetSelectors`); dead-column determination from the `StageId` enum (`stage/mod.rs`) — registry specs without a StageId arm are not dispatched by the `--node` engine.
- Curated status: `CrossPlatformRoleParityRefresh_2026-07-23.md` (§1 matrix, §2 CP-1/CP-4 verdicts, §5 adapter gaps, §6 drift rules), with the ParityPlan (mandate) and Roadmap (per-cell design history) as background.

## 7. References

- Ledgers: `documents/operations/live_lab_node_run_matrix.csv` (engine of record), `documents/operations/live_lab_node_stage_results.csv` (per-stage truth). The bash archive was not consulted.
- Stage registry + dispatch: `crates/rustynet-cli/src/live_lab_stage_registry.rs`, `crates/rustynet-cli/src/live_lab_run_matrix.rs`, `crates/rustynet-cli/src/vm_lab/orchestrator/{plan.rs,stage/*.rs,role_validation/*.rs,adapter/*.rs}`.
- Owner-gated designs this doc points at: `MacosDnsFailclosedEnforcementGap_2026-08-28.md`, `MacosExitMembershipRoleFixDesign_2026-08-31.md`, `TraversalSelfSustenancePlan_2026-07-23.md`, `WindowsNodeBootstrapTriageVerdict_2026-08-28.md`.
