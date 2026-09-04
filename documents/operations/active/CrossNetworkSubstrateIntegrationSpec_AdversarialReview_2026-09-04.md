# Cross-Network Substrate Integration Spec — Adversarial Review (2026-09-04)

**Status:** UNTRUSTED adversarial review (docs-only, no code touched), 2026-09-04, working tree checked at commit `9e2f3d3dba69f944bf84e19955753156cd323a6f` (branch `ai-edit/edit-1788537230790-26537-4`). Target: `CrossNetworkSubstrateIntegrationSpec_2026-06-21.md` (892 ln, incl. its own §0/§0.4–§0.6 status refreshes dated 2026-08-27/28). Every claim below was verified by grep/read against this tree; unverifiable items are marked as such.

---

## Findings

**F1 — Line-number drift in the §0 seam citations (severity: LOW, stale).**
The §0 proposal (2026-07-19) and §0.6 blocker note cite pre-CN-landing line numbers that have since moved:
- `OrchestrationStage` "(`stage/mod.rs:207`)" → the trait is at `crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs:366`; line 207 is inside the stage catalog.
- `CrossNetworkSubstrate` enum + `run_cross_network_stage` "(`cross_network.rs:38,257`)" → now `:58` and `:277` in `stage/cross_network.rs`.
- CN-3's skip cite "`stage/cross_network.rs:506-511`" → `prepare_scenario_stage` is now at `:549`.
- §0.6's "`cross_network.rs:929-932`" (relay/probe from `entry`/`aux`) → `CrossNetworkTopology::resolve` is now at `:960`; the `ssh_params_for_any_role(ctx, &["entry", "aux"])` calls sit at ~`:963-965`. The `:944-949` cite now lands on `TopologyError`/the struct. Substance verified correct; lines stale.
- §0.6's "`cross_network.rs:1085-1105`" (`ssh_params_for_role`) → the fn is now at `:1109`.
- The one line cite that still matches: `:514-520` — `resolve_dispatchable_topology` at `:515`, distinct-/24 management-plane gate intact.

**F2 — §0/§0.1 cite `run_script_stage` as a live seam; CN-3 deleted it (severity: MEDIUM, internal contradiction).**
§0's preamble grounds the proposal in "`run_script_stage` (`cross_network.rs:418`)" and §0.1 says to delete "the `cargo run --bin` fan in `run_script_stage` (`cross_network.rs:418`)". The function has zero hits in the current tree — the deletion happened exactly as the CN-3 row records — but the §0 preamble is not annotated as historical, so a reader can mistake it for a present seam. The CN-3 row itself is accurate.

**F3 — `FinalCleanupStage` cite names the wrong file (severity: MEDIUM, misattributed).**
§0.3 says the always-run teardown mirrors "the `FinalCleanupStage` pattern, `native.rs:657`". `FinalCleanupStage` is *defined* at `crates/rustynet-cli/src/vm_lab/orchestrator/stage/final_cleanup.rs:8` (`pub struct FinalCleanupStage`); `orchestrator/native.rs` only constructs it (`:946`, `:977`), and `native.rs:657` is cross-build/glibc code. The pattern-reference is real; the file:line is not.

**F4 — §2 table still calls the Python probes "Production tooling" (severity: LOW, stale).**
§2 lists `nat_probe.py`, `nat_filter_probe.py`, `stun_responder.py` as production classification tooling. Python was removed 2026-07-13 (the spec's own banner says so) and none of the three files exist under `scripts/vm_lab/`; the STUN/NAT probes are now the Rust `rustynet-netns-probe` crate (present: `crates/rustynet-netns-probe/src/main.rs`). §2 predates that and was never annotated.

**F5 — §2's "sim refuses `double_nat_cgnat`" and the `netns_internet_sim.sh:189` `exit 2` cite are stale (severity: LOW, historical-cite drift).**
Current `scripts/vm_lab/netns_internet_sim.sh` (254 ln, not the "244 ln" the spec repeats): `double_nat_cgnat` is in the valid-profile list (`:91`) and has its own case at `:199-202` ("double_nat is built as a two-router chain by the caller"); the only `exit 2` in the file is invalid-impairment at `:173`. The refusal the CN-2/CN-4 rows typify ("the typed form of `netns_internet_sim.sh:189`'s `exit 2`") no longer exists at that line — the live refusal is the typed one in `netns.rs`/`substrate.rs`, which is what the rows claim landed. §2's "Does NOT implement `double_nat_cgnat` (refuses)" is now wrong about the sim.

**F6 — X1's cited commit `ae5c7ce` is unverifiable (severity: MEDIUM, citation integrity).**
The X1 status block cites commit `ae5c7ce` "(on `main`)" for the substrate selector + classification gate. `git cat-file -t ae5c7ce` fails and no `git log --all` hit exists in this tree — the object is not present, so the cite cannot be confirmed or refuted here. Moot in substance: that landing was orchestrator-`.sh`-only (the X1 note says so itself), and the `.sh` orchestrator was deleted in `c9ccf1a4` (verified: `git show --stat c9ccf1a4` → `scripts/e2e/live_linux_lab_orchestrator.sh | 9090 ----`), with W5.7's `e93a0e4f` carrying the rest (verified: 30 files, names the script) — the spec's CN-5 "cite the pair" instruction checks out.

**F7 — Test-count drift in the landed-rows (severity: LOW, stale numbers).**
CN-2 claims "38 netns unit tests" — `netns.rs` now carries 36 `#[test]` (substrate.rs carries 42). CN-3 claims "103 scenario tests" — the `scenario/` tree now carries 132. CN-2/§0.5 claim "three tests in `collect_pubkeys.rs`" — now 6. Tests grew/moved after the rows were written; the claims were presumably accurate at their landing dates but are no longer recountable.

**F8 — X1's daemon-path validator was built and then deleted; the §5 recipe now describes a dead artifact (severity: INFO, landed-then-removed).**
§5 X1 step 3 + the Increment-2 minting recipe (with `daemon.rs` line cites, `ops_e2e.rs:2576/:2694` etc.) target `scripts/vm_lab/netns_daemon_path.sh` — which CN-5 (TRACKC-FIX-1) records as deleted, and the file is indeed absent. The recipe's *daemon assertion targets* remain valid: `path_mode`, `path_live_proven`, `relay_session_state`, `stun_candidate_local_addrs`, `transport_socket_identity_state`, `traversal_error`, `dns_alarm_state` all appear in `rustynetd/src/daemon.rs`'s netcheck line (`:7322`). The X1 block should be marked superseded-by-CN-5 like §4.2/§4.3/§7 are.

**F9 — The sibling brief's fail-closed cite is CORRECT (severity: none — verification).**
`MacosCrossNetworkDecisionBrief_2026-09-03.md` cites `substrate.rs:2082-2099` for "vxlan fails closed on any non-Linux participant". Verified: `stage/cross_network/substrate.rs` `:2078-2081` carries the comment ("a non-Linux guest in an overlay-needing topology cannot be silently excluded … fail closed") and `:2082-2099` returns `StageOutcome::Failed` naming the offending alias when any assignment's platform is not `Linux`. The fail-closed control is intact and correctly cited by the sibling doc.

**F10 — X2's code path is LANDED (severity: none — DONE markers confirmed).**
Verified present, matching the CN-1..CN-4 rows: the three traits/structs (`CrossNetworkSubstrateProvider` `substrate.rs:673`, `NetLeafRunner` `:81` with provided `in_netns` `:100` + `validate_argv` `:152`, `SubstrateHandle` as a struct `:307`); `Support::UnsupportedModifier` `:440`; `NatApplyError::{Refused,Failed}` `:637`; `VxlanSubstrateProvider` impl `:1385`; `NetnsSubstrateProvider` + `MAPPING_GATE_PROFILES`/`FILTER_GATE_PROFILES` (`netns.rs:1263/:1269`); `SlirpSubstrateProvider` (`slirp.rs:62`, gateway `10.0.2.2` `:52`, `provisioned: false` `:102`, fail-closed default-route parsing `:151/:289`, `UnsupportedByDesign` + `NatApplyError::Refused` `:183/:209`); both lifecycle stages wired into the plan (`orchestrator/plan.rs:49`, `:402-403`, `:584-585`, `:995`); all 8 scenario modules under `stage/cross_network/scenario/` (plus `baseline.rs`, `endpoint_switch.rs`, `host.rs`, `provisioning.rs`, `remote_exit_common.rs`); the 8 `[[bin]]` shims, the 8 `.sh` validators, and `netns_nat_classify.sh`/`netns_nat_filter.sh` all absent; `live_lab_common.sh` survives at exactly 3,523 ln with `test_live_lab_ssh_windows.sh` present; `build_suite_command` retirement pinned by `vm_lab/mod.rs:44544` (`build_suite_command_rejects_retired_direct_suite`); no `--client-underlay-ip`-style CLI flags remain in `main.rs`; `--cross-network-substrate` parsed at `main.rs:4358/:4440` with usage strings `:20533/:20535`.

**F11 — The §0.4 substrate × profile `supports()` matrix is correct against the gates (severity: none — verified).**
`MAPPING_GATE_PROFILES` = the three shaping profiles, `FILTER_GATE_PROFILES` = the same three — `double_nat_cgnat` is in neither gate list, exactly matching "three of five live-proven; `double_nat_cgnat` still unproven (CN-4)". The netns CGNAT carrier chain exists as described (`rnsim-cgn-*`, carrier segment `100.64.<200+idx>.0/24`, `netns.rs:86-107`, `:543`, `:976-978`), including the documented deliberate 100.64/10 overlap.

**F12 — §0.6's live-proof blocker gates are real in code (severity: none — verified).**
`plan_overlay` returns `Ok(None)` below two /24 groups (`substrate.rs:746`, early return ~`:755`, plus a >24-group `Err`), and `VxlanSubstrateProvider::setup` short-circuits to an honest empty handle on `Ok(None)` (~`:1529-1532`). Combined with F1's confirmed entry/aux + distinct-/24 management-plane gates, §0.6's three-gate account matches the tree.

**F13 — Two scenario modules the spec never mentions (severity: INFO, staleness gap).**
`scenario/` also holds `acl_deny_failover_verdict.rs` and `traversal_hint_wire_replay_eval.rs` — post-CN-3 additions outside the CN-3 contract list. Not an error; the CN-3 row's inventory is complete *as of its landing* but the spec does not know about these.

**F14 — X3 remains unstarted, and the spec does not overclaim it (severity: none — verified).**
`cross_network_cold_enroll`, `cross_network_anchor_renumber`, `cross_network_double_nat_anchor` have zero hits in `crates/rustynet-cli/src/live_lab_stage_registry.rs` (the registry lives at the crate root, not under `vm_lab/`). No false DONE marker exists for X3.

**F15 — X1's "no CLI flag yet" note is correctly self-superseded (severity: none).**
The X1 block's own NOTE says `main.rs` lacks the flag "until X2 adds" it; §0.5 explicitly marks that stale and the flag is present (F10). Consistent within the spec.

---

## Verified correct (the load-bearing claims)

- CN-1..CN-5 all landed as the §0.4 rows claim: every named symbol, file, and deletion above checked out (F10/F11/F12).
- `c9ccf1a4` is the orchestrator deletion commit; `e93a0e4f` is the W5.7 retirement commit — "cite the pair" is right (F6).
- The sibling `MacosCrossNetworkDecisionBrief` cite `substrate.rs:2082-2099` is accurate; the vxlan substrate fails closed on non-Linux participants (F9).
- The fail-closed posture of the landed substrate matches the spec's §10 invariants: `validate_argv` rejects control characters; `in_netns` is a provided method with namespace-name allowlist validation (tests `substrate.rs:2939-3022` reject hostile names and control-char argv); slirp fails closed on unreadable/non-zero/unparseable routes; netns teardown sweep treats enumeration failure as failure; the vxlan Linux-only guard fails the stage rather than silently excluding a guest. **No landed or proposed wiring weakens a fail-closed control.**
- `apply_nat_profile.sh` retains `--enable-upnp`/`--enable-v6` (`:29`, `:34`), and `read-cross-network-report-fields` exists (`main.rs:2865` dispatch, `ops_cross_network_reports.rs:2852` executor).
- `netns_internet_sim.sh` is retained with `vm_lab/network_audit.rs:33` (`NETNS_SIM_SCRIPT_RELATIVE_PATH`) as its consumer, and its header records the `netns_daemon_path.sh` deletion — CN-5's tail account is exact.
- §0.5's "X1 'no CLI flag yet' is stale — do not rebuild it" and "§4.2/§4.3/§7 target a deleted file" warnings are correct.

## Considered, no issue

- §3's substrate↔validator mapping (netns = classification gate, vxlan = SSH e2e, slirp = cross-OS smoke): superseded in mechanism by §0 but not contradicted; the landed code honors the *spirit* (netns gates in-process; vxlan scenarios in-process behind the provider; slirp verify-only).
- §4.1's `--cross-network-substrate {netns,vxlan,slirp}` default `netns`: matches the flag's usage string.
- The CN-3 deviations list (a)–(o): spot-checked `ScenarioHost` (`scenario/host.rs`), baseline composition (`baseline.rs`), endpoint_switch (`endpoint_switch.rs`) — all present. Deviation (g)'s retirement test exists (`mod.rs:44544`).
- §10 security invariants: consistent with the landed enforcement points; nothing found that papers over a failure mode.
- The §0 banner's W5.7 warning and the owner-directive PARKED banner: accurate against the tree (bash orchestrator absent; `--node` engine is the engine of record).

## Self-verification

Four key citations re-grepped after drafting, all confirming: (1) "supports only Linux guests today" at `substrate.rs` `:2082-2099`; (2) `CrossNetworkSubstrateSetupStage`/`TeardownStage` wiring at `plan.rs:49/:402/:584/:995`; (3) `MAPPING_GATE_PROFILES`/`FILTER_GATE_PROFILES` at `netns.rs:1263/:1269`; (4) `pub struct FinalCleanupStage` at `stage/final_cleanup.rs:8`. Commit existence re-checked with `git cat-file -t` (`c9ccf1a4`, `e93a0e4f`, `56ec906c`, `9419cfb3`, `4b1d9467` = commit; `ae5c7ce` = missing).

## Verdict

The spec's own §0/§0.4–§0.6 refresh is substantially accurate — CN-1..CN-5 landed as claimed and the fail-closed controls held — but the document now carries three kinds of rot a reader must not absorb: drifted line cites (F1), two misattributed/dead seam cites (F2, F3), and stale §2/X1 content describing deleted Python/`exit 2`/`netns_daemon_path.sh` artifacts (F4, F5, F8) plus one unverifiable commit cite (F6). **The spec needs a staleness refresh (annotate §1–§2, §4–§7, and the X1 recipe as historical; fix F1–F3), not a rewrite.**
