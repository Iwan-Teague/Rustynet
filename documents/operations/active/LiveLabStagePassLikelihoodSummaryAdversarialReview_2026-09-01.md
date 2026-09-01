# LiveLabStagePassLikelihood Summary — Phase B Adversarial Review (2026-09-01)

Docs-only adversarial review of `LiveLabStagePassLikelihood_Summary_2026-09-01.md` §1 (the 21-row ranked table) and §2 (the six Phase C code candidates). Every file:line anchor below was re-read from this worktree at base commit `8acab546`; every ledger count below was re-derived with a quote-aware CSV reader over `documents/operations/live_lab_node_run_matrix.csv` (242 run rows) and `documents/operations/live_lab_node_stage_results.csv` (35,585 per-node stage rows). No lab run was executed; the lab was down when the reviewed summary was written and remains down for this review. No Windows host was available.

Verdict vocabulary: **READY** = the item's root cause, security posture, long-term direction, and ledger claims all survive verification as written. **READY-WITH-AMENDMENTS** = the item is worth doing but specific claims or wordings must be corrected first; exact replacement wording is given. **REJECT** = the item should not proceed in its stated form (none received that verdict).

## §0 Verdict table

| Item | Verdict | One-line reason |
| --- | --- | --- |
| §1 row 1 — full-suite macOS client run | READY | Ledger confirms `macos_stage_role_switch_matrix` 32 skip/0 pass and `cross_os_role_switch` 34 skip/0 pass; the unlock claim is exact. |
| §1 row 2 — `anchor_platform=macos` re-run | READY | `macos_stage_anchor` is 71 skip/0 pass, `cross_os_anchor_bundle_pull` is exactly 1 pass/71 skip/0 fail; commits `e3297391` and `451f9730` both exist. |
| §1 row 3 — chaos-suite selector flip | READY | `macos_stage_chaos` and `linux_relay_forwards_frame` are each 242/242 `not_run`; the opt-in flags exist (`vm_lab/mod.rs:1271`, `:1280`). |
| §1 row 4 — focused Linux blind-exit-dataplane run | READY | Per-node ledger: `blind_exit_dataplane_validation` on Linux is 12 skip / 2 fail — exactly as claimed. |
| §1 row 5 — relay_forwards_frame Disruptive opt-in | READY | Column is 242/242 `not_run`; `StageId::RelayForwardsFrameValidation` exists (`stage/mod.rs:266`). |
| §1 row 6 — macOS blind-exit topology run | READY | Column family (`macos_stage_lan_toggle`) exists; counts not re-tallied (§10). |
| §1 row 7 — same run + aux node | READY | Column family (`macos_stage_enrollment_restart`) exists; `StageId::LiveEnrollmentRestartValidation` is wired at `stage/mod.rs` (`live_enrollment_restart_validation`, Live/T2Resilience). |
| §1 row 8 — CP-1 bridged re-attach (macos-utm-1) | READY | Operator action; logic and downstream-unlock claims are internally consistent, live re-attach not re-probed (§10). |
| §1 row 9 — W-FIX-4 windows-utm-1 remediation | READY | `windows_stage_bootstrap` is 5 fail / 0 pass, exactly as claimed. |
| §1 row 10 — W-FIX-5 ubuntu-kvm-1 restore | READY | Host-down state not re-probed (§10); the unlock structure (winnat-* columns) is real. |
| §1 row 11 — CP-3 physical Windows device | READY | `promote_windows_exit_active` is a real registry spec (`live_lab_stage_registry.rs:1509`) with run-matrix oracle wiring (`live_lab_run_matrix.rs:4642`, `:4684`, `:4819`). |
| §2 candidate 1 — Windows live-identity status surface | READY-WITH-AMENDMENTS | Root cause as stated is refuted: the status surface already exists end-to-end; the real gap is narrower and the fix smaller (§1). |
| §2 candidate 2 — macOS exit-serving adapter | READY | Predicate, skip path, and daemon-side pf NAT all verified; two nuances worth recording (§2). |
| §2 candidate 3 — pf ports of four Linux-only validators | READY | All four Linux-only predicates verified at the cited lines; existing pfctl helpers make the port feasible (§3). |
| §2 candidate 4 — `--enable-soak-suite` selector | READY-WITH-AMENDMENTS | Claim verified except the `EnableRule::SoakSuite` anchor is stale by a few lines (rule at `:347`, not `:336-346`) (§4). |
| §2 candidate 5 — `cross_os_lan_toggle` on the `--node` spec | READY | Every anchor verified exactly, including the schema column and the absence of `cross_os` on the `--node` spec (§5). |
| §2 candidate 6 — confirm-then-fix mac role-transition dispatch | READY-WITH-AMENDMENTS | The "confirm" half is now DONE by this review — and the answer is the adverse one: there is no `--node` dispatch to confirm (§6). |

## §1 Candidate 1 — Windows live-identity status surface (for the enforce-time identity gate)

**1. Is the root cause correct? No — this is the review's principal refutation.** The summary's root cause (and the in-tree comments repeating it) says the Windows control CLI has no `status` subcommand and that "§4.7 is not satisfiable on Windows until a live status surface exists" (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_traffic.rs:94-101`; repeated at `node_adapter.rs` ~`:516-525`; partially in `adapter/windows.rs` ~`:288-293`). That is stale at the source level. The live surface exists today, end to end:

- The trust CLI dispatches a live status verb: `crates/rustynet-cli/src/bin/rustynet-windows-trust-cli.rs:133-136` routes `role status|show` to `execute_role_status()` (`:454`), which calls `send_command(IpcCommand::Status)` (`:442`, `:451-452`) over the daemon named pipe.
- The IPC command is wired: `crates/rustynetd/src/ipc.rs` defines `IpcCommand::Status` (`:41-42`), the `"status"` wire token (`:119`), and its parser arm (`:199`).
- The daemon's `Status` handler (`crates/rustynetd/src/daemon.rs`, arm at ~`:8992`) responds with a key=value summary that **already begins `node_id={} node_role={} state=…`** (format string at ~`:9112-9114`, first argument `self.local_node_id`).

What is actually missing is narrow: (a) `execute_role_status` receives the full key=value response but reduces it to `current role: …` via `resolve_preset_from_status`, discarding the `node_id=` field (`rustynet-windows-trust-cli.rs:454-476`); and (b) `windows_traffic::query_live_identity` never calls the status path at all — `collect_node_id` reads `--node-id` out of `RUSTYNETD_DAEMON_ARGS_JSON` in the config env-file via a PowerShell regex, which is exactly the config-file read the gate refuses to trust. **Amended root cause:** the identity gate on Windows fails closed not because no live surface exists, but because the orchestrator's identity collector does not consume the existing one.

**2. Is the stated option the most secure one? Yes, and the amendment preserves it.** The gate itself is correct and stays untouched: `enforce_identity_challenge` (`node_adapter.rs:463`, gate call at `:526`) rejects `Unverifiable`, `NodeIdMismatch`, and `NotLiveAssertion`, and its negative tests are present (`challenge_gate_fails_closed_when_no_expected_id` `:683`, `challenge_gate_rejects_substituted_node_with_mismatch_reason` `:664`, `challenge_gate_rejects_non_live_config_file_identity` `:695` — the doc's cited range `:685-697` covers it — `challenge_gate_propagates_evidence_gather_error_fail_closed` `:710`, `challenge_gate_admits_matching_live_identity` `:726`). Sourcing `IdentityEvidence::Live` from the daemon's own status response is a *strengthening*: the assertion then comes from the running process holding the keys rather than from a file an operator could have edited. No fail-closed path is weakened; the collector simply stops manufacturing a guaranteed-rejected `ConfigFile` value.

**3. Is it the best long-term choice? Yes — more so after amendment.** The amended fix is confined to the CLI/orchestrator side: have `query_live_identity` run the existing on-guest status path (the trust CLI, or a small raw verb that prints the `node_id=` line it already receives) over the SSH channel it already uses, parse `node_id=`, and return `IdentityEvidence::Live`. Optionally refresh the three stale doc-comments (the two above plus `adapter/windows.rs` ~`:288-293`, which understates the trust CLI's verb set) so the next auditor does not re-derive the same wrong premise. No daemon change is required at all. That is strictly smaller than the summary's M-sized "add a status subcommand" estimate.

**4. Do the ledger claims survive? Yes.** The dependency claim "needs row 9 first" is sound: `windows_stage_bootstrap` is 5 fail / 0 pass (quote-aware count), and no validator family can dispatch on a guest that never bootstrapped. The `_check`-family framing is right in substance; the cited registry region `:753-916` is loose — the registry carries no literal `windows_stage` names (only a comment at `:469`); those columns are platform-prefixed schema columns produced via `logical`/`special` fields, with the Windows specials (e.g. `validate_windows_named_pipe_acls` at `:1401`, `windows_dpapi_key_custody` at `:1423`) living further down. Imprecise, not wrong.

**5. File:line verification.** `windows_traffic.rs:94-101` VERIFIED (and its content STALE — see §9); `node_adapter.rs:516-524` VERIFIED as a comment block (fn at `:463`, call at `:526`); test anchor `:685-697` VERIFIED-as-range (fn at `:695`); registry `:753-916` VERIFIED-as-region/imprecise. Path correction: nothing here lives under `adapter/` that was claimed to — `active_exit.rs` is `vm_lab/orchestrator/stage/active_exit.rs`, not `adapter/active_exit.rs` (candidate 2's citation; repeated here because the same summary paragraph carries both).

**Replacement wording (amended).** Replace the candidate-1 root-cause sentence with: "The Windows daemon already exposes a live identity surface: `IpcCommand::Status` (`rustynetd/src/ipc.rs:41-42`, `:119`, `:199`) is answered by a handler that emits `node_id=` and `node_role=` as key=value (`rustynetd/src/daemon.rs`, Status arm ~`:8992`, format string ~`:9112`), and the trust CLI already obtains that response via `role status` (`rustynet-windows-trust-cli.rs:133-136`, `:454`) but discards the node-id field. The gap is that `windows_traffic::query_live_identity` (`windows_traffic.rs:94-101`) never consumes the surface and returns `IdentityEvidence::config_file` from the env-file instead. Fix: extend the orchestrator's Windows identity collector to run the on-guest status path over SSH and parse `node_id=` into `IdentityEvidence::Live`; keep the gate (`node_adapter.rs:463`, call `:526`, tests `:664-:726`) byte-for-byte unchanged; refresh the three stale comments that claim no status surface exists."

## §2 Candidate 2 — macOS exit-serving adapter

**1. Root cause correct? Yes.** `active_exit_runtime_implemented` (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/active_exit.rs:184-186`) admits only `Linux | Windows`; the comment block `:177-183` explains that macOS blind-exit pf NAT is applied at enforce-time and "does not fit this activate→assert→nat-session shape", so the macOS adapter hits the trait's fail-closed default. The skip is a *reported* skip, never a silent pass (`:88-92`, `StageOutcome::Skipped("active-exit runtime is not implemented for {exit_platform:?}")`), and the predicate's doc-comment `:191-201` correctly states promotion follows a live macOS run rather than preceding it. The named test exists: `runtime_implemented_linux_and_windows_not_macos` at `:310`. The cited line `active_exit.rs:184` is exact.

**2. Most secure option? The stated constraints are right and the daemon evidence confirms feasibility without weakening anything.** The product daemon already implements enforce-time macOS exit NAT: `crates/rustynetd/src/macos_exit_nat.rs` installs one NAT rule per mesh prefix into the `com.rustynet/nat` pf anchor, enables IPv4 forwarding, and — important for this candidate — ships a lifecycle verifier (`macos_exit_nat_lifecycle`) that checks exactly the observable exit-active state (`pfctl -a com.rustynet/nat -s nat` shows a `nat …` rule; `sysctl -n net.inet.ip.forwarding` reads 1). The killswitch-precedence machinery the summary wants folded in also exists daemon-side (`macos_exit_killswitch_precedence.rs`, anchor `com.apple/rustynet_g<N>`), alongside `macos_blind_exit.rs`, `macos_dns_failclosed.rs`, `macos_ipv6_leak.rs`, `macos_tandem_dns_redirect.rs`, `macos_dns_sc_protect.rs`. Keeping `active_exit_runtime_implemented = false` for macOS until a real end-to-end egress proof exists is the correct fail-closed posture and must not be pre-flipped.

**3. Best long-term choice? Yes, with one architectural note.** Because the daemon already ships `macos_exit_nat_lifecycle`, the orchestrator adapter should *assert that existing verifier's observable state* rather than re-deriving pf parsing in the CLI — one source of truth for what "exit active" means on macOS. The S2 requirement (end-to-end egress proof, not mechanism-translated nft assertions) remains the acceptance bar.

**Nuance to record (tension, not defect):** `active_exit.rs:177-183` says "a macOS Exit maps to the blind_exit role", while `macos_exit_nat.rs` implements NAT for the *regular* `exit` role on macOS. Both are true simultaneously — the daemon supports a regular macOS exit role, and the orchestrator currently maps its macOS exit slot onto blind_exit. The candidate's design should state explicitly which role the live proof exercises, since the pf anchors and verifier differ (`com.rustynet/nat` + forwarding for exit vs mesh-only blocking for blind_exit).

**4. Ledger claims survive? Yes.** Live proof targets `macos_stage_exit_handoff` + `cross_os_exit_path` after row 8: consistent with the registry's `cross_os_exit_path` markings (`:1009`, `:1018`) and the exit-handoff specs (`:1148`, `:1157`, `:1166`). The `macos_pf_killswitch` coverage-gap mention matches the macOS bucket doc's caveat.

**5. File:line verification.** `active_exit.rs:177-201` VERIFIED (region); `:88-92` VERIFIED; `:184` VERIFIED EXACT; test VERIFIED at `:310`. Path corrections: the file is `stage/active_exit.rs`, not `adapter/active_exit.rs`; the adapter module observed in-tree is `adapter/macos_traffic.rs` (an `adapter/macos.rs` was not confirmed — use the observed name or verify before citing).

## §3 Candidate 3 — pf ports of the four Linux-only role validators

**1. Root cause correct? Yes, all four anchors verified.** `role_validation/exit_nat_lifecycle.rs` — `exit_nat_lifecycle_runtime_implemented` at `:14-16` is `matches!(platform, VmGuestPlatform::Linux)` (doc cited `:15-17`, off by one line, same fn); the validator walks `discover_single_generated_nft_table` against `DEFAULT_MESH_CIDR` (100.64.0.0/10). `exit_demotion_residue.rs:23`, `blind_exit_dataplane.rs:14`, and `ipv6_leak.rs:17` all carry Linux-only predicates (the last with an explicit test `runtime_implemented_linux_only` at `:73-76` asserting `Macos`/`Windows` → false). All are fail-closed skips, exactly as summarized.

**2. Most secure option? Yes.** Porting means *extending* each `*_runtime_implemented` to `Macos` only when a real pf-based equivalent check exists — never loosening the subchecks. The blind-exit-dataplane five-subcheck structure and the killswitch-precedence interplay must carry over, not be reduced. Sequencing `blind_exit_dataplane` after the Linux stage is green (12 skip / 2 fail on Linux per the ledger) is the right order.

**3. Best long-term choice? Yes, with a feasibility assist the summary missed:** pf capture machinery already exists in this tree — `adapter/macos_traffic.rs`, `role_validation/blind_exit.rs`, `main.rs`, `vm_lab/mod.rs`, and the `live_linux_*` test bins all invoke `pfctl`. The ports should reuse those helpers rather than inventing new capture paths. The ipv6 pre-check (does the UTM macOS guest have v6 egress at all before writing a `tcpdump -i en0 ip6` probe?) stays mandatory.

**4. Ledger claims survive? Yes.** Linux `blind_exit_dataplane_validation` = 12 skip / 2 fail (per-node rows; the `linux_stage_blind_exit_dataplane_check` column exists), matching the summary's numbers exactly.

**5. File:line verification.** `exit_nat_lifecycle.rs:15-17` VERIFIED-with-1-line-shift (fn at `:14-16`); `exit_demotion_residue.rs:23-24` VERIFIED (`:23` is the predicate); `blind_exit_dataplane.rs:14-16` VERIFIED; `ipv6_leak.rs:17-19` VERIFIED.

## §4 Candidate 4 — `--enable-soak-suite` selector

**1. Root cause correct? Yes.** No enable flag exists for the soak suite: `vm_lab/mod.rs` exposes `skip_soak` (`:1131`), `enable_chaos_suite` (`:1271`), and `enable_relay_forwarding_validation` (`:1280`) — and nothing that enables soak. The election rule is `EnableRule::SoakSuite => self.soak_suite && !self.skip_linux_live_suite` at `live_lab_stage_registry.rs:347`, with the comment block at `:340-346` warning that extended_soak must not stay enabled or the terminal-outcome guarantee synthesizes a spurious aborted. The doc's cited range `:336-346` is STALE: the comment starts at `:340` and the rule itself is the line after it, `:347`. Everything else anchors cleanly: the stage needs a second client (`live_extended_soak_validation.rs:38-47`, skip text "the topology lacks the second client this soak requires" — doc cited `:44-47`, inside the region); `StageId::LiveExtendedSoakValidation => "extended_soak"` @ Soak/T2Resilience at `stage/mod.rs:267`; the registry spec's enable at `:2089`; the plan plumbing (`plan.rs` field `:146-147`, builder `:250-251`, suite filter `!skip_live_suite && !skip_soak` at `:313`, `soak_suite_stages()` at `:165`).

**2. Most secure option? Yes — and the amendment must keep the guard symmetric.** Any new `--enable-soak-suite` flag must preserve both halves of the existing rule: it must not dispatch when `skip_linux_live_suite` is set, and the terminal-outcome guarantee comment (`:340-346`) must be respected so a half-enabled soak cannot manufacture a false aborted/pass verdict. The selector should be opt-in only, never default-on.

**3. Best long-term choice? Yes** — mirroring the chaos/relay opt-in flags is the established pattern in this file, and soak (365 skip / 40 pass in the per-node ledger) is currently unreachable by any selector.

**4. Ledger claims survive? Yes.** "Needs a second client" verified at the skip site; no count claims made that fail.

**5. File:line verification.** `live_lab_stage_registry.rs:336-346` STALE — corrected to comment `:340-346`, rule `:347`. `live_extended_soak_validation.rs:44-47` VERIFIED (inside the actual region `:38-47`). All plan/`vm_lab/mod.rs` anchors VERIFIED as listed.

**Replacement wording (amended).** Replace the anchor citation with: "`EnableRule::SoakSuite` resolves to `soak_suite && !skip_linux_live_suite` at `live_lab_stage_registry.rs:347` (guarding comment `:340-346`); the skip reason sits at `:377-380`. The plan already plumbs `skip_soak` (`plan.rs:146-147`, `:250-251`, suite filter `:313`); only the enable direction is missing."

## §5 Candidate 5 — `cross_os: Some("cross_os_lan_toggle")` on the `--node` live LAN-toggle spec

**1. Root cause correct? Yes, exactly.** The `--node` spec `live_lan_toggle_validation` (`live_lab_stage_registry.rs:2018-2025`) carries `logical: Some("lan_toggle")` (`:2022`), `platform_rule: AllPlatforms` (`:2023`), and **no** `cross_os` field — while the bash-dialect spec `live_lan_toggle` (`:1948-1954`) carries `cross_os: Some("cross_os_lan_toggle")` at `:1951`. The schema column already exists (`live_lab_run_matrix.rs:206`), and the oracle mapping region (`~:4760-4777`, doc cited `:4764-4867`) handles the bash-dialect id. The dispatch-table comment at `stage/mod.rs:251` confirms the intent: "The bash-dialect mac/win cross_os_lan_toggle aggregate is a different (cross-OS) cell."

**2. Most secure option? The summary's guard is the right one and must be a hard requirement:** populate the aggregate column only from genuinely executed cross-OS data — never fabricate a verdict for a cell that did not run. Default-deny applies to evidence columns as much as to policy: an unearned `pass` in `cross_os_lan_toggle` would be worse than `not_run`.

**3. Best long-term choice? Yes** — the ledger schema already reserves the column; leaving the `--node` spec without it means the column stays permanently `not_run` while the engine of record runs the stage on all platforms.

**4. Ledger claims survive? Yes.** Verified precedent: every other cross-OS aggregate is a registry field on the producing spec (fields observed at `:521`, `:534`, `:547`, `:569`, `:579`, `:588`, `:672`, `:724`, `:733`, `:991`, `:1000`, `:1009`, `:1018`, `:1074`, `:1177`, `:1196`).

**5. File:line verification.** `:2019-2024` VERIFIED EXACT; `:1951` VERIFIED EXACT; `live_lab_run_matrix.rs:206` VERIFIED EXACT; mapping-test region VERIFIED.

## §6 Candidate 6 — confirm-then-fix: `--node` dispatch of macOS role-transition

**1. Root cause correct? The suspicion is confirmed — and this review performed the confirm step.** Findings, all from this worktree:

- The registry spec `validate_macos_role_transition` exists at `live_lab_stage_registry.rs:1235` with `enable: EnableRule::RoleSwitchPlatform("macos")` at `:1236` (plus `stream: PlatformStream::Macos`, `direct_platform: Some(("macos", "role_transition"))`, `budget_secs: 180`). The Windows twin uses `RoleSwitchPlatform("windows")` at `:1504`. Election resolution (`:335`, enum `:280`, skip string `:366`) and its tests (`:2762-2789`) are registry-level only.
- The `--node` engine's complete `StageId` enumeration (`stage/mod.rs:171-316`) contains **no role-transition stage of any name** — no `role_transition`, no mac/windows variant. There is a Linux `RoleSwitchMatrix` (`:219`) and that is all.
- `direct_platform`'s only structural consumer in the `--node` path is `live_lab_stage_manifest.rs:232`, where it sets `counts_as_check` — it does not create a plan arm.
- The validation's implementation lives in the legacy module at `vm_lab/mod.rs:12651+` (log path, skip outcome, and stage record for the name), with the skip branch `:12670-12682` ("not elected for role transition") — code the `--node` runner does not reach, since no `StageId` maps to it.
- The run-matrix side is fully wired for a stage that never runs: the oracle maps `"validate_macos_role_transition" => Some(("macos", "role_transition"))` (`live_lab_run_matrix.rs:4662`), populates `macos_stage_role_transition` (regression tests `:3406-3463`), and the ledger columns sit at 0-pass forever.

**Conclusion:** dispatch is not merely "unconfirmed" — it is absent. The "confirm" half of confirm-then-fix is now done; the answer is the adverse one, so the fix half is mandatory BEFORE any lab run: add a `StageId` + suite/tier placement + plan arm + runner dispatch that invokes the existing validation, keeping the `RoleSwitchPlatform("macos")` election gate and the skip-reason semantics identical. The legacy `vm_lab/mod.rs` block remains the reference implementation to port from.

**2. Most secure option? Yes.** Role transitions are signed-state, side-effect-bearing operations (§10.7 rules: service deploy before bundle, NAT teardown ordering, audit entries). Wiring dispatch must not bypass or parallel the election gate; the transition must run through the same signed-bundle path the legacy validation exercises. No new allow-path may exist without the election predicate.

**3. Best long-term choice? Yes** — the ledger schema, oracle mapping, and registry spec are all built for this stage; only the engine arm is missing. Deleting the columns instead would discard real acceptance criteria.

**4. Ledger claims survive? Yes.** The summary's skip reason quote matches `vm_lab/mod.rs:12670-12682` (doc cited `:12676`, inside the region).

**5. File:line verification.** `:1235-1236` VERIFIED EXACT; `:12676` VERIFIED-as-region; "no dedicated StageId" CONFIRMED by full enumeration; the summary's implication that a lab run might dispatch the stage today is REFUTED — it cannot.

## §7 Rows 1-11 verification table

| Row | Verdict | Correction |
| --- | --- | --- |
| 1 | VERIFIED | Counts exact: `macos_stage_role_switch_matrix` 210 not_run/32 skip/0 pass; `cross_os_role_switch` 208 not_run/34 skip/0 pass. |
| 2 | VERIFIED | `macos_stage_anchor` 171 not_run/71 skip/0 pass; `cross_os_anchor_bundle_pull` 1 pass/71 skip/0 fail; both SHAs exist. |
| 3 | VERIFIED | `macos_stage_chaos` 242/242 `not_run`; flags at `vm_lab/mod.rs:1271`/`:1280`. |
| 4 | VERIFIED | Linux `blind_exit_dataplane_validation` 12 skip/2 fail; single historical fail consistent with claim. |
| 5 | VERIFIED | `linux_relay_forwards_frame` 242/242 `not_run`; `StageId` at `stage/mod.rs:266` (Disruptive/T1Role). |
| 6 | VERIFIED (structure) | Column exists; count not re-tallied (§10). |
| 7 | VERIFIED (structure) | Column exists; `live_enrollment_restart_validation` wired at `stage/mod.rs` (Live/T2Resilience). |
| 8 | VERIFIED (logic) | Environmental claim not re-probed live (§10); downstream stage names real. |
| 9 | VERIFIED | `windows_stage_bootstrap` 237 not_run/5 fail/0 pass — exact. |
| 10 | VERIFIED (logic) | Host state not re-probed (§10); winnat-* columns real. |
| 11 | VERIFIED | `promote_windows_exit_active` spec at `live_lab_stage_registry.rs:1509`; oracle wiring at `live_lab_run_matrix.rs:4642`/`:4684`/`:4819`. |

## §8 Reordering

No reordering of the ranked table is required. Two effort-class corrections sharpen the ordering the summary already chose:

1. **Candidate 1 moves further ahead of the code queue.** With the status surface proven to exist end-to-end, the fix shrinks from M (new subcommand) to S (consume an existing response field from the CLI side; no daemon change). It was already first in §2; its lead over candidates 2-3 widens.
2. **Candidate 6 leaves the "confirm" phase entirely.** This review confirmed the adverse answer, so the remaining work is the mechanical port (StageId + plan arm + runner dispatch). It should be scheduled as a precondition of any macOS role-transition lab run (row 1's unlock), not as open research.

Rows 1-11 ordering stands: every count claim that motivated the ranking verified exactly, and no row's premise was refuted.

## §9 Claims that did not survive

1. **"The Windows control CLI has no `status` subcommand" / "no live daemon self-report is available" / "§4.7 is not satisfiable on Windows until a live status surface exists."** Refuted by `rustynet-windows-trust-cli.rs:133-136` + `:454` (live `role status` verb over `IpcCommand::Status`), `ipc.rs:41-42`/`:119`/`:199` (wired command), and the daemon Status handler's `node_id=`/`node_role=` key=value response (`daemon.rs` ~`:8992`, format ~`:9112`). The in-tree comments carrying this claim (`windows_traffic.rs:94-101`; `node_adapter.rs` ~`:516-525`; `adapter/windows.rs` ~`:288-293`, which also understates the verb set) are stale and should be corrected in the same change as candidate 1.
2. **Candidate 4's anchor `live_lab_stage_registry.rs:336-346`.** Stale: comment at `:340-346`, rule at `:347`.
3. **Candidate 1's test anchor `node_adapter.rs:685-697`.** Loose: `challenge_gate_rejects_non_live_config_file_identity` is the fn at `:695` (range covers it, but the fn start is the precise anchor).
4. **"`windows_stage_*_check` family at `live_lab_stage_registry.rs:753-916`."** Imprecise: the registry carries no literal `windows_stage` names; the columns are platform-prefixed schema columns derived from `logical`/`special` fields, with the Windows specials at `:1401`+.
5. **Two path claims:** `active_exit.rs` is under `vm_lab/orchestrator/stage/`, not `adapter/`; `live_lab_stage_registry.rs` and `live_lab_run_matrix.rs` are at `crates/rustynet-cli/src/` root, not under `vm_lab/orchestrator/`. One file name was unconfirmed as cited: `adapter/macos.rs` (the observed macOS adapter module is `adapter/macos_traffic.rs`).

## §10 What this review did not verify

- **No lab run was executed** and the lab was down throughout; no pass anywhere in this document is a live pass. All pass/fail/skip figures are historical ledger readings.
- **No Windows host was available**, so every Windows-runtime behavior cited (named-pipe status round trip on a live guest, `collect_node_id`'s PowerShell parse, bootstrap remediation) is verified at source level only, never executed.
- **Environmental/operator rows were not re-probed live:** row 8 (CP-1 bridged re-attach of macos-utm-1), row 10 (ubuntu-kvm-1 tailnet/LAN state), row 11 (CP-3 device availability), and row 9's UTM-console remediation steps are taken as recorded, with only their code-side and ledger-side premises verified.
- **The three same-day bucket docs were not re-derived line-by-line**; their claims were spot-checked at the code and ledger anchors the summary cites. The "~17 macOS wiring skips" figure and the per-row skip taxonomies were not independently re-counted.
- **Column counts for rows 6 and 7** (`macos_stage_lan_toggle`, `macos_stage_enrollment_restart`) were confirmed to exist but not tallied; the other nine rows' counts were re-derived exactly.
- **The candidate-2 role-mapping tension** (orchestrator comment says macOS exit maps to blind_exit; daemon implements regular-exit pf NAT) is recorded as an open design question for Phase C, not resolved here.
