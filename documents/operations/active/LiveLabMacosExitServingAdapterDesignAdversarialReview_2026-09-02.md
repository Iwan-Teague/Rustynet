# Adversarial Review — LiveLabMacosExitServingAdapterDesign_2026-09-02

**Scope.** Docs-only Phase-B adversarial review of `documents/operations/active/LiveLabMacosExitServingAdapterDesign_2026-09-02.md` (the "design"). The job is to REFUTE: every design decision was attacked against the actual tree in this worktree, with file:line evidence for every claim. No code was changed and no lab run was executed.

**Method.** The design document was read in full. Every file and line anchor it cites was opened and checked at the cited lines. The enforce-time call path (`rustynetd` daemon), the orchestrator role-mapping surface, the CLI evaluators, the stage registry, the adapter family, and every cited document were read at the cited (or corrected) lines. Ledger claims were cross-checked against `CrossPlatformRoleParityRefresh_2026-07-23.md` and the 2026-09-01 pass-likelihood documents. Git history for `active_exit.rs` was inspected to test the rollout claim. No macOS guest was booted; nothing below is live evidence.

**Result.** The design survives with material amendments. Its daemon-side premise is stronger than the design itself states (the regular-exit NAT path is real and enforced today, at `phase10.rs`), but two of its load-bearing assumptions are wrong as written: the orchestrator still maps a macOS `Exit` election to the `blind_exit` daemon posture, so the planned live run would prove the wrong role unless the design's scope is extended; and the "existing" CLI evaluators it plans to call are quarantined dead code. The killswitch fold-in as sequenced would strip the killswitch posture during exit-serving. Overall verdict: **READY-WITH-AMENDMENTS** (§9 lists the required replacements verbatim).

---

## §0 Verdicts per design decision

| # | Design decision | Verdict | One-line basis |
|---|---|---|---|
| D1 | Prove the **regular `exit` role**, not `blind_exit` | **ACCEPT-WITH-AMENDMENTS** | Daemon-side: correct and already enforced (`phase10.rs:4495-4530`, `:3877`). Orchestrator-side: `role.rs:160` / `:186-189` map a macOS `Exit` election to the `blind_exit` daemon role **today**, pinned by tests `:458-476` and `:508-545` — the design never cites `role.rs`, so its live run as written exercises the wrong posture. |
| D2 | Adapter **asserts the daemon's own lifecycle verifier**; never re-derives pf parsing in the CLI; never mutates the product firewall | **ACCEPT-WITH-AMENDMENTS** | Sound architecture (adopting the §2.3 note of the prior adversarial review). But the CLI evaluators it cites (`mod.rs:20076`, `:21271`) are `#[allow(dead_code)]`-quarantined since the W5.7 bash deletion — "reuse the existing evaluator" is not free; unquarantine must be in scope. Q1 should cite the in-tree `pfctl -ss` caution at `adapter/macos_traffic.rs:134-135`. |
| D3 | Two-phase S2 egress proof (burst + pf-state translation identity + sink-observed source) → fail-closed offline evaluation; dry-run can never pass | **ACCEPT** | Matches the Refresh §6 bar exactly (`:389-398`, "Lifecycle-proven ≠ egress-proven" at `:396`); the QH-25 artifact shape admits the macOS fields without touching Linux semantics; the fallback retains pf-state capture so it is not a quiet weakening. One sharpening required (A6): the sink must sit on the exit's egress-side segment (192.168.64.0/24 post-CP-1), never the pre-CP-1 Shared-NAT segment. |
| D4 | Restore `macos_pf_killswitch` coverage via the daemon's `macos-exit-killswitch-precedence-check` (PF-05) **inside the exit-serving stage** | **ACCEPT-WITH-AMENDMENTS** | The coverage gap is real and this is the right tool — but the check is **mutating** (flush + tamper + restore, module doc `:3-9`), requires root pfctl write, and its artifact records no live ruleset. Running it *during* exit-serving strips the killswitch posture mid-serving. Must be re-sequenced (before activation, or a declared window with restore verification). Its CLI evaluator is also quarantined (`mod.rs:21271`). |
| D5 | `active_exit_runtime_implemented` stays false for Macos until adapter real AND live pass; predicate flip is the **last commit, in the same change set as the run-matrix row** | **ACCEPT-WITH-AMENDMENTS** | Fail-closed posture correct and honest. But "same change set as the run-matrix row" is not literally enforceable: the orchestrator appends the matrix row at run time, attributing the deployed tree's commit + dirty state. The enforceable contract is: the flip commit lands committed and clean **before** the verifying run, and the appended row's `git_commit` must equal the flip commit. No precedent flip exists in history (this would be the first). |

**Overall: READY-WITH-AMENDMENTS.** The six amendments in §9 are required before implementation begins; none changes the design's architecture.

---

## §1 Attack 1 — The role decision (§2): is "regular exit, not blind_exit" right?

**The daemon-side premise is correct, and stronger than the design argues.** The design's central role claim rests on `macos_exit_nat.rs` implementing NAT for a regular exit. What the design does not cite is the enforce-time call path, which we verified end to end in `crates/rustynetd/src/phase10.rs`:

- `fn activate_exit_nat(&mut self, mesh_cidr)` at `phase10.rs:3877` is the real actuation point. It reads prior forwarding state fail-closed (`:3896-3909`, non-zero exit → `NatApplyFailed`), enables forwarding **first** (`:3913-3919`, sysctl key chosen by prefix family at `:3882-3886`), builds `MacosExitNatPfConfig` (`:3888-3890`), and loads the NAT anchor via `MacosPfLoadSpec::ExitNat` → `PrivilegedCommandProgram::MacosPfLoad` (`:3926-3933`; the comment at `:3922-3925` records that the privileged helper re-renders the rules from the reviewed builder and owns the temp file + pfctl invocation — the daemon never names a `pfctl -f` path). Load failure flushes the anchor (`-F all`) and restores forwarding (`:3934-3944`). After load it verifies via `Pfctl ["-a", anchor, "-s", "nat"]` (`:3961-3966`) plus `evaluate_macos_exit_nat_pf_rules` (`:3973`), and tears down fail-closed on drift (`:3949-3952`). `verify_exit_nat_anchor` spans `:3956-3981`; `teardown_exit_nat` at `:3987` flushes the anchor **before** restoring forwarding, so a failed restore leaves the anchor flushed (no residue).
- The role-apply dispatch at `phase10.rs:4485` (body `:4495-4541`) proves the design's role reading: the comment at `:4495-4496` records that the former proxy "conflated the two and made a regular macOS exit impossible to express" — a fixed defect. Today: a serving exit that is *not* blind exit takes the killswitch filter anchor **first** (`:4514-4520`, so NAT failure leaves egress blocked), then `activate_exit_nat` + DNS protection (`:4522-4529`); only `serve_exit_node && blind_exit` takes the irreversible blind-exit filter anchor (`:4497-4512`); a client tears down (`:4530-4539`). `rollback_nat_forwarding` (`:4543-4562`) tears NAT down before relaxing the filter — matching the AGENTS.md §10.7 ordering. Helper wiring is real: `privileged_helper.rs:1248` (argv decode), `:1944-1949` (validation), and `macos_pf_load_spec.rs:209` (`ExitNat` → `build_macos_exit_nat_pf_rules`).

So D1's *destination* is right: a regular macOS exit applies `com.rustynet/nat` + IPv4 forwarding at enforce time, on a hardened path with its own verification and teardown ordering.

**But the orchestrator cannot elect that posture today — this is the design's largest gap.** In `crates/rustynet-cli/src/vm_lab/orchestrator/role.rs`, the macOS daemon-role mapping at `:160` reads `NodeRole::Exit | NodeRole::BlindExit => Ok("blind_exit")`, and the macOS capability table at `:186-189` grants `Exit` the `[RoleCapability::BlindExit, RoleCapability::ExitServer]` pair. The module doc (`:38`) and the pinned tests `:458-476` (`is_supported_for_platform_macos_exit_maps_to_blind_exit_pf_posture`) and `:508-545` lock this mapping in. Meanwhile the *election* surface is fine: `native.rs:981-993` maps `exit_platform=macos` / a `macos-utm-1:exit` node entry to `("exit", NodeRole::Exit, ...)`, and `EnableRule::MacosExit` exists in `live_lab_stage_registry.rs` (`:259` enum, `:266` doc — "`macos_promote_exit` or `exit_platform=macos`", evaluated at `:329`). Consequence: `nodes=["macos-utm-1:exit", ...]` — the design's own §8 run recipe — **deploys the `blind_exit` daemon posture today**. A live run executed as written would produce a matrix row that proves blind_exit on macOS (already proven 2026-08-31, Refresh `:102`), not the regular-exit posture D1 exists to prove. The design's §2/§3/§7 never mention `role.rs`; the work is therefore under-scoped, and the stage's own comment block (`active_exit.rs:177-183`, mirrored at the skip text `:88-93`) is *accurate today for the orchestrator mapping* even though the daemon now supports more — the comment is not stale relative to what the orchestrator would do, only relative to what the daemon can do.

**Is there any blind_exit mapping baked into the plan/registry that the design misses?** No: the registry's macOS exit-cell stages (`live_lab_stage_registry.rs:1144`, `:1153`, `:1162`, `:1171`) gate on `EnableRule::MacosExit` only; the role mapping lives solely in `role.rs` (plus `active_exit.rs:177-183` prose). The fix is one remap plus its pinned tests — small, but it must be named.

**Verdict: D1 accepted only with the §9 A1 amendment** (role-mapping remap added to scope; phase10 path cited as the enforce-time proof).

---

## §2 Attack 2 — The adapter surface (§3)

**The snapshot subcommand exists with the claimed shape, and is runnable unprivileged.** `main.rs` dispatches `macos-exit-nat-lifecycle-snapshot` at `:454-456`; the implementation at `:2005-2050` requires `--mesh-cidr` (`:2033-2034`), accepts `--pf-anchor` defaulting to the daemon constant (`:2037-2039`), and emits the single-phase JSON to stdout (`:2043-2048`); the doc comment `:1998-2004` records the two-phase run/merge contract. The JSON fields the design assumes all exist in `macos_exit_nat_lifecycle.rs`: schema v1 (`:33`), default anchor `com.rustynet/nat` (`:39`), struct `:44-68` carrying `pf_anchor_present` (doc `:57-58`, field `:59`), `internal_prefix` (`:59`), `tunnel_forwarding`, `egress_forwarding`; `collect` `:94`, pure `build` `:118`, `merge` `:149` (producing `during_run{...}` + `after_stop{pf_anchor_present, forwarding_restored}`), fail-closed capture semantics per RSA-0031 (`:183-198`: pfctl exec failure reports the anchor present; sysctl failure reports "Unknown"). Capture commands are `pfctl -a <anchor> -s nat` (`:202`, non-zero exit → not-present) and `sysctl -n` (`:229`) — **both reads, both permitted to a non-root SSH user on macOS**, so the orchestrator can drive the snapshot without privilege escalation. The design's "assert, do not actuate" is consistent with all of this, and with the merge contract's after-stop requirement (anchor flushed).

**Stage sequencing: "assert, do not actuate" does not break activation ordering.** The stage's dependency on ExitHandoff (`active_exit.rs:47-49`) plus the daemon's own role-apply path mean that by the time `activate_exit_serving` runs, role enforcement has already applied (or failed to apply) the NAT anchor; the adapter merely observes it. There is no stage in the current registry that calls activate before roles are enforced — the design's Q3 concern (enforce-time ordering) is answerable: enforcement happens in the daemon's role-apply path *before* any stage-level assert can succeed, and the legitimate refresh trigger is the daemon's own `verify_exit_nat_anchor`/teardown, never an orchestrator-side pf command. The design's refusal to grow an orchestrator pf mutation path is correct and matches `adapter/macos_traffic.rs`, whose only pf mutation is the cleanup/reset command (`MACOS_RESET_COMMAND`, `:113-115`).

**pfctl state parsing feasibility: the design's Q1 humility is right, and the tree already contains a caution it should cite.** A tree-wide grep found **no** existing `pfctl -s state` translation parser or fixture; the only pf-listing code is `adapter/macos_traffic.rs`, which (a) enumerates anchors with `sudo -n pfctl -s Anchors` (`:113-115`), and (b) carries an explicit warning at `:134-135`: "Do not use `pfctl -a <anchor> -ss` here: on macOS an empty parent anchor can still print unrelated global connection state", with `-sr`/`-sn` probes at `:140-143` and unknown-state failing closed at `:934`. The design's plan (parse a *global* `pfctl -s state`, filter to the client's source address in Rust, fail closed on parse failure until a real fixture exists) is therefore the correct shape — global state is the reliable-but-broad surface, exactly what the in-tree caution implies — and the fail-closed-until-fixture posture is consistent with the design's own dry-run-never-passes rule. Amendment A3 adds the missing citations.

**The retry pattern citation is stale.** The design cites `windows_traffic.rs:283-298` for the 10×1.5s retry pattern. The actual code moved: the PowerShell retry script is at `:305-313`, the outer retry loop at `:318-332`, and the Rust-side identity check at `:314-328` (`:322-324` for the `is_none_or` match). Content exists; lines shifted ~+25. Corrected in A5.

**Verdict: accepted with amendments A3 and A5.**

---

## §3 Attack 3 — The S2 egress proof (§4)

**Is the bar stated correctly?** Yes. `CrossPlatformRoleParityRefresh_2026-07-23.md` §6 (`:385-400`) rules out waiving the egress proof for macOS: `:389-398` concede the *mechanism* divergence (pf NAT vs nft) but require an equivalent-strength end-to-end egress assertion, with the explicit rule "Lifecycle-proven ≠ egress-proven" at `:396`. The design's two-phase proof (client burst + pf-state translation identity + sink observation) meets that bar rather than negotiating it down.

**Is the sink constructible in the UTM lab?** With one sharpening, yes. After CP-1 (Refresh `:117-133`; the 2026-08-29 triage: macOS UTM Shared-NAT 192.168.65.0/24 vs Debian bridge100 192.168.64.0/24, no L3 path), the macOS exit sits on 192.168.64.0/24 and its egress-side source address is observable by anything on that segment: the Debian host (bridge100) or any bridged Debian guest. The sink **must** sit on that post-CP-1 egress segment; the pre-CP-1 Shared-NAT segment (192.168.65.0/24) is host-unobservable and cannot host the sink. The design does not say this; amendment A6 makes it explicit.

**Is the fallback quietly weaker?** No — the design already conditions the fallback on also capturing pf-state records, so the two-phase reachability proof never stands alone. Under the Refresh §6 equivalent-strength reading, "bursts fail with the anchor flushed, succeed with it present, plus pf translation records for the same traffic" is an equivalent-strength demonstration. The design's open question Q2 should nonetheless resolve to "sink, or fallback-with-pf-state" — never "fallback without pf-state" — and §9 A6 states that as a MUST.

**Does the QH-25 evidence shape admit the macOS fields?** Yes, without changing Linux evaluator semantics. The artifact fields (`active_exit.rs:255-285`: `exit_alias`, `client_alias`, `client_source`, `translated_side`, `observed_via`, `identity_proven`, `claim`) are additive; the identity computation (`:160-161`) is platform-neutral; the trait contract at `node_adapter.rs:330-350` already frames identity-vs-range as the QH-25 requirement, and the Windows adapter doc (`windows_traffic.rs:275-299`) shows the same shape serving a non-Linux platform today. The design routes the macOS evaluation through a *new* offline evaluator (rejecting artifacts lacking a live run id), so the Linux path is untouched — correct per the design's own one-execution-path rule.

**Verdict: accepted; one sharpening (A6).**

---

## §4 Attack 4 — The killswitch fold-in (§5): is Q4 actually a blocker?

**The check is mutating — the design does not say so.** `macos_exit_killswitch_precedence.rs`'s module doc (`:3-9`) is unambiguous: the check "snapshots the active RustyNet pf anchor, **flushes it**, proves the killswitch assertion fails, then **restores** the exact captured rules before returning." It therefore requires pfctl *write* (root or a privileged helper), unlike the lifecycle snapshot's read-only commands. The design's §5 sentence — run the check "inside the exit-serving stage" while exit-serving — would deliberately strip the killswitch filter posture **while the exit is serving untrusted egress**, then restore it. That is a self-inflicted killswitch outage window on the exact node the stage is supposed to be proving. It also contradicts the artifact contract: the written artifact (`:66`, write path; fields `schema_version`, `pf_anchor`, `baseline_assert{overall_ok, exit_code, reason}`, `tampered_assert`) records **no live ruleset**, and the CLI evaluator's own doc (`mod.rs:21261-21270`) states the tamper "is producer-side; the validator only enforces the audit-shape contract." Evaluating that artifact therefore proves the precedence *experiment* (baseline passes, tamper is detected), not the live exit-serving posture. The design's Q4 ("does PF-05 pass in exit-serving posture?") is answerable and **not** the blocker — the sequencing and privilege are.

**Q4 itself: PF-05 can pass in exit-serving posture, conditionally.** The evaluator (`:148`, PF-05 "Presence is not precedence", `:125-147`) requires the egress terminator (`block drop out quick all`, `:176`) to be *preceded* by qualifying pass rules. `classify_pf_egress_rule` (`:169-221`) treats a quick pass on a tunnel/loopback-contained interface as Contained (`:207-211`) and a narrowly-scoped quick pass as NarrowAllow (`:215-216`), where "narrowly scoped" means a bounded `from`/`to` other than `any` (`:238-260`) — a pass scoped `from 100.64.0.0/10` (the mesh CIDR the NAT builder emits in `macos_exit_nat.rs`) counts as narrow. So a correctly-shaped exit-mode killswitch anchor passes PF-05 while serving. Whether the *actual* daemon exit-mode killswitch rules take those shapes is unverified (no guest booted) and stays in §10.

**Required amendments:** re-sequence (A2) — run the precedence check **before** `activate_exit_serving` (baseline posture), or in an explicitly declared window with a post-check snapshot proving the restore; declare the root requirement; unquarantine the evaluator.

**One more finding: the evaluator is dead code.** `evaluate_macos_exit_killswitch_precedence_artifact` sits behind `#[allow(dead_code)]` at `mod.rs:21271` (quarantined since the W5.7 bash-branch deletion, "retained for the G2 native re-wire"). The design's "CLI evaluates via the existing evaluator" is directionally right but must state the unquarantine/re-wire as in-scope work. The same applies to `evaluate_macos_exit_nat_lifecycle_artifact` (`#[allow(dead_code)]` at `:20076`), which D2 depends on.

**Verdict: accepted with amendments A2 (mutation contract + re-sequencing + evaluator unquarantine).**

---

## §5 Attack 5 — The rollout contract (§6)

**"Predicate flip in the same change set as the run-matrix row" is not literally enforceable.** The orchestrator appends a matrix row to `documents/operations/live_lab_node_run_matrix.csv` *at run time*, attributing the git commit and dirty state of the tree it deployed (recorded in each run's provenance; per AGENTS.md §7, live-lab launches refuse a dirty tree absent `--allow-dirty`, and AGENTS.md §12.3 requires verifying the row exists). Therefore the row can never be *in* the flip's change set; the strongest enforceable contract is ordering + equality:

1. The flip commit (predicate extension + pinned-test inversion at `active_exit.rs:309-314`) lands committed and **clean** before the verifying run is launched.
2. The verifying run's appended row must name exactly that commit with a clean dirty state.
3. Pass/fail is read from the stage's own report artifact (status + data block), never from the column alone — per AGENTS.md §12.3's explicit warning that the column is not proof.

**Is there precedent?** No. Git history on `active_exit.rs` shows the predicate has never been flipped: recent touches are `b1c3989f` (QH-25 identity tightening), `b4793800` (MAC-D3 anchor validators), `8ec851a9` (MAC-D1) — none alter the predicate function. The 2026-08-31 blind_exit pass (Refresh `:102`, run `livelab-1788172934687-17194-11`, commit `7bdcfe60`) proves the run-record flow but not a flip. This will be the first flip, so the row-equality check must be explicit rather than borrowed from precedent.

**Does keeping the predicate false while the methods are real create a silent-mask path?** The residual risk is bounded and already structural: while the predicate is false, the stage reports skip (`active_exit.rs:88-93`, Skipped → Partial with the honest text), and the egress-proof section independently report-skips on probe failure (`:147-158`) — so a *real* failure inside a supposedly-working adapter cannot masquerade as the predicate skip once the adapter lands, because the skip text and the artifact set differ. The design's D5 posture (false until live pass) is the correct fail-closed default. The only silent-mask vector would be reading the column instead of the artifact — covered by amendment A4's step 3.

**Verdict: accepted with amendment A4 (ordering + row-equality contract replacing "same change set").**

---

## §6 Attack 6 — Security review

**Does the design widen the privileged-helper surface?** No. It adds no new privileged command: the lifecycle snapshot is read-only (`pfctl -a <anchor> -s nat`, `sysctl -n` — `macos_exit_nat_lifecycle.rs:202`, `:229`), driven through the existing daemon subcommand over the existing SSH path. NAT mutation remains exclusively inside the daemon's privileged-helper path (`MacosPfLoadSpec::ExitNat` → `PrivilegedCommandProgram::MacosPfLoad`, `phase10.rs:3926-3933`; helper decode/validate at `privileged_helper.rs:1248`, `:1944-1949`), which the design correctly refuses to duplicate.

**Does it add orchestrator-side pf mutation?** No — and it affirmatively forbids it (Q3's "orchestrator must not grow own pf mutation path"). The only pf interaction added to the orchestrator is *parsing* `pfctl -s state` output (read-only, non-root).

**One indirect privilege ask:** running the killswitch-precedence check requires pfctl write on the guest. That check already exists as a daemon subcommand (`main.rs:451-453`) and its tamper contract already assumes privileged execution; folding it into the stage does not create a new privileged surface, but the design must *declare* the root requirement it inherits (folded into A2) rather than leave it implicit.

**Does it weaken fail-closed skip semantics?** No. The reported-skip path (`active_exit.rs:88-93`, note at `:188`, doc `:191-201`) is preserved; D5 keeps the predicate false until live proof; the new evaluator rejects artifacts lacking a live run id, closing the dry-run-as-pass hole; parse failures fail closed (Q1 posture). The dead column name (`macos_pf_killswitch`) stays dead, per QH-07 and the macOS bucket doc's caveat (`:177`).

**Signed-state/revocation ordering:** the design's after-stop requirement (anchor flushed, forwarding restored) matches SecurityMinimumBar control 7 (`:529-533`: on revocation the daemon must tear down forwarding + NAT *before* the capability leaves local state; residue is release-blocking). The daemon already implements the ordering (`phase10.rs:3987` teardown flush-before-restore; rollback `:4543-4562` NAT-before-filter-relax), and the design's two-phase snapshot is exactly the verification that control demands.

**Finding: no new security defect introduced. One sequencing defect (§4/A2) that *would* have opened a killswitch outage window had the design been implemented as written — caught here, which is the point of this review.**

---

## §7 Attack 7 — Offline core (§7) and sequencing (§8)

**Module list is complete and correctly placed.** `adapter/macos_exit_traffic.rs` (parser + selector + three asserts) belongs in the orchestrator crate's adapter layer next to `linux_traffic.rs`/`windows_traffic.rs`; the parse/identity logic is offline-testable per the design's named-function list (`parse_macos_pf_state_translation_line`, `select_macos_client_nat_state`); the three assert branches mirror the trait surface (`node_adapter.rs:296-303`, `:309-316`, `:339-350`). Sink-capture format with `schema_version: 1` matches the established artifact convention.

**Daemon-side test reuse is real.** The lifecycle module's tests at `macos_exit_nat_lifecycle.rs:326-348` (design cited `:327-345`; same block) cover merge/fail-closed semantics; the CLI negative-test blocks at `mod.rs:45482-45604` and `:47199-47232` exist for the two evaluators — with the caveat (A2) that both evaluators are quarantined dead code, so "reuse" includes unquarantining them. The new `macos_two_phase_stage_reports_skip_while_predicate_false` test is the right pin for the D5 posture, complementing the existing pinned predicate test at `active_exit.rs:309-314`.

**CP-1 dependency is framed correctly.** Refresh `:117-133` (CP-1) and `:294` (blockers table) establish that without the bridged re-attach of `macos-utm-1` onto 192.168.64.0/24, no cross-OS traffic assertion involving the macOS node can pass — so sequencing the adapter's live proof behind CP-1 is not caution, it is necessity. The operator-authorization requirement (the design routes the re-attach through `prepare_lab_network`'s explicit approve path) matches the LiveLabVmConnectivityRulebook's mutation gating. The DNS fail-closed design dependency is correctly scoped to *overall-green* rather than adapter proof — consistent with the macOS bucket doc's owner-gated red (`:40-45`). The §8 run recipe's node list is valid *syntax* today (`native.rs:981-993` accepts `alias:exit`), but produces the wrong posture until A1's role remap lands — the recipe and the remap must land together.

**Verdict: accepted.**

---

## §8 Attack 8 — Anchor audit (every file:line the design cites)

Verdicts: **VERIFIED** (line/section correct), **STALE** (content exists, lines moved), **WRONG** (mislabel/wrong name). Corrections are mandatory in the design (A5).

| Design anchor | Verdict | Note |
|---|---|---|
| `active_exit.rs:95-171` (stage flow activate/assert/probe/session) | VERIFIED | activate `:99`, assert `:113`, probe+session `:131-171`. |
| `active_exit.rs:177-186` (macOS comment + predicate) | VERIFIED | comment block `:177-183`; predicate `:184-186` `matches!(platform, Linux \| Windows)`. |
| `active_exit.rs:188-189` (reported-skip filename/note) | VERIFIED | `REPORTED_SKIP_FILENAME` `:188`. |
| `active_exit.rs:191-201` (skip-note doc) | VERIFIED | |
| `active_exit.rs:248-302` (egress evidence JSON + write) | VERIFIED | fields `:255-285`, write `:290-302`. |
| `active_exit.rs:310` (pinned predicate test) | VERIFIED | `:309-314`. |
| `active_exit.rs:348` cited as a **negative** test | **WRONG (mislabel)** | `:348` is the **positive** identity-proven test (`egress_evidence_names_pair_and_identity_when_proven`). The negative pair is `:371` (weaker-claim) and `:406` (no-exit-node fail-closed). |
| `active_exit.rs:371`, `:406` | VERIFIED | as tests; `:371` is negative-ish (weaker claim), `:406` fail-closed. |
| `macos_exit_nat.rs:7-22, :33, :82, :121` | VERIFIED | module doc, anchor re-export, teardown-always, evaluator. |
| `macos_exit_nat_lifecycle.rs:33, :94, :149, :183-188, :202, :229, :260, :274, :297, :327-345` | VERIFIED | `:327-345` ≈ tests `:326-348` (same block). |
| `macos_exit_nat_lifecycle.rs:58` (`internal_prefix` field) | STALE (±1) | doc line `:57-58`; field `:59`. |
| `macos_exit_killswitch_precedence.rs:20, :21, :66, :127, :148, :169, :262, :272+` | VERIFIED | schema, prefix, write fn, PF-05 doc, evaluator, classify, select fns. |
| `main.rs:445-459, :451-453, :454-456, :457-459` | VERIFIED | dispatch block incl. snapshot `:454-456`, ipv6 `:457-459`. |
| `main.rs:1998-2004, :2005, :2035-2040` | VERIFIED | two-phase doc, impl start `:2005` (through `:2050`), flags `:2033-2039`. |
| `node_adapter.rs:282-284, :296(+297-302), :309, :322(323-327), :330-337, :339-350, :386` | VERIFIED | incl. probe Linux-client-only and QH-25 doc. |
| `adapter/macos.rs:78` (only shell_host) | VERIFIED | file holds only the shell-host helper; the pf-aware reset adapter lives in `adapter/macos_traffic.rs` (uncited by the design; see A3). |
| `adapter/linux_traffic.rs:549-552, :589, :600-605, :622-654, :674-723` | VERIFIED | probe `:549`, activate `:589`, assert `:622`, nat-session `:674`. |
| `adapter/windows_traffic.rs:187-216` | STALE | that span is the collect-active-tunnels region; collect fn at `:195`. |
| `adapter/windows_traffic.rs:265-308` | STALE | region roughly right; actual assert `:257-273`, doc `:275-299`, fn `:300`. |
| `adapter/windows_traffic.rs:279-281` (identity-in-Rust) | STALE | the identity comment/match is `:314-328` (`:322-324`); `:279-281` is inside the doc's scope bullets. |
| `adapter/windows_traffic.rs:283-298` (retry pattern) | STALE | retry is `:305-313` (script) + `:318-332` (outer loop). |
| `mod.rs:20076` (lifecycle evaluator; call `:12057`; tests `:45482-45604`) | VERIFIED, with caveat | fn at `:20077` behind `#[allow(dead_code)]` at `:20076` — quarantined dead code (W5.7). |
| `mod.rs:21267` (killswitch evaluator; call `:12268`; tests `:47199-47232`) | VERIFIED, with caveat | fn at `:21272` behind `#[allow(dead_code)]` at `:21271`; contract doc `:21261-21270`. |
| `live_lab_stage_registry.rs:1009, :1018, :1148, :1157, :1166` | VERIFIED (±1-4) | role_switch `:1009`; exit_handoff cross_os `:1018` (active_exit `:1021`); macOS cells `:1144`/`:1153`/`:1162`/`:1171`. |
| `live_lab_stage_registry.rs:143-145` (`cross_os_exit_path`) | VERIFIED | cross_os mapping present. |
| `LiveLabStagePassLikelihoodAdversarialReview_2026-09-01.md` (filename) | **WRONG (filename)** | Actual file: `LiveLabStagePassLikelihoodSummaryAdversarialReview_2026-09-01.md` (design omits "Summary"). Anchors inside (`:49-61`, `:51`, `:55`, `:57`, `:65`, `:161`) VERIFIED — incl. the §2.3 architectural note the design adopts (`:55`) and the role-mapping tension (`:57`, `:161`). |
| `LiveLabStagePassLikelihood_Summary_2026-09-01.md` rows (`:55, :60, :72, :102-109`) | VERIFIED | row 8 CP-1 `:55`; row 13 adapter `:60`, detail `:97-110`. |
| `LiveLabStagePassLikelihood_macOS_CrossOS_2026-09-01.md:40-45, :177, :188-196` | VERIFIED | exit_handoff skip census; `:177` dead-column caveat; quickest-wins. |
| `CrossPlatformRoleParityRefresh_2026-07-23.md:102, :117-133, :294, :389-398` | VERIFIED | blind_exit pass; CP-1; blocker; §6 rules incl. `:396`. |
| `SecurityMinimumBar.md:529-532` | VERIFIED | control 7 spans `:529-533`. |
| `NeverDispatchedLinuxStagesTriage_2026-08-27.md:443` | VERIFIED | `macos_pf_killswitch` in the dead-bash-dialect class. |
| `MacosDnsFailclosedEnforcementGap_2026-08-28.md` | VERIFIED | file exists. |

---

## §9 Required amendments (exact replacement wording)

**A1 — §2 (role decision) and §7 (work list): add the orchestrator role-mapping remap.** Insert after the paragraph establishing the regular-exit decision:

> "The daemon already enforces the regular-exit posture: `phase10.rs` `apply_nat_forwarding` (`:4495-4541`) takes the killswitch filter anchor first (`:4514-4520`), then `activate_exit_nat` (`:3877`) loads `com.rustynet/nat` via the privileged helper (`MacosPfLoadSpec::ExitNat` → `PrivilegedCommandProgram::MacosPfLoad`, `:3926-3933`) and verifies + fail-closes on drift (`:3961-3973`); teardown flushes before restoring forwarding (`:3987`). The orchestrator, however, still maps a macOS `Exit` election to the `blind_exit` daemon role — `orchestrator/role.rs:160` (`NodeRole::Exit | NodeRole::BlindExit => Ok("blind_exit")`), the macOS capability pair at `:186-189`, and the pinned tests at `:458-476` and `:508-545`. This work therefore includes remapping the macOS `Exit` daemon role to the regular-exit posture (daemon role `client` + `ExitServer`, matching the Linux mapping at `role.rs:202-215`), updating those pinned tests, and refreshing the stage comment at `active_exit.rs:177-183` — otherwise the §8 run recipe deploys blind_exit and proves an already-proven role."

**A2 — §5 (killswitch fold-in): declare the mutation and re-sequence.** Replace the sentence running the check "inside the exit-serving stage" with:

> "The precedence check is a mutating, root-required experiment: it snapshots the active anchor, flushes it, proves the assertion fails, and restores the exact rules (`macos_exit_killswitch_precedence.rs:3-9`). It is therefore run BEFORE `activate_exit_serving` (baseline posture), or in an explicitly declared window whose close is verified by a post-check lifecycle snapshot proving the restore; it is never run against a live exit-serving posture mid-serving. Its artifact records the experiment outcome only (baseline/tampered asserts; no live ruleset — evaluator contract `mod.rs:21261-21270`), so it proves the precedence property, not the live posture; the live posture is proven by the exit-serving stage's own asserts. Both CLI evaluators (`mod.rs:20076`, `mod.rs:21271`) are currently quarantined dead code (`#[allow(dead_code)]`, retained for the G2 re-wire); unquarantining and re-wiring them is in scope for this work."

**A3 — §3 (Q1): cite the in-tree pf-listing evidence.** Append to the Q1 paragraph:

> "In-tree precedent: `adapter/macos_traffic.rs` enumerates anchors via `sudo -n pfctl -s Anchors` (`:113-115`) and warns at `:134-135` not to use anchor-scoped `pfctl -a <anchor> -ss` on macOS, because an empty parent anchor can still print unrelated global connection state. Global `pfctl -s state` is therefore the reliable-but-broad surface; the parser filters to the client's source address in Rust and fails closed on any unparseable line until a captured fixture exists. No `pfctl -s state` parser or fixture exists in the tree today (verified by grep), so Q1 remains open exactly as stated."

**A4 — §6 (rollout): replace the same-change-set claim with the ordering + equality contract.** Replace:

> "…lands in the same change set as the run-matrix row carrying the live pass."

with:

> "The flip commit lands committed and with a clean tree BEFORE the verifying run is launched; the run's appended row in `live_lab_node_run_matrix.csv` must name exactly that commit with a clean dirty state (the orchestrator attributes the deployed tree's provenance at run time, so row and change set cannot be one commit's contents — equality of the row's `git_commit` with the flip commit is the enforceable check). Pass/fail is read from the stage's own report artifact (status + data block), never from the matrix column alone. This will be the first predicate flip in the stage's history (git log on `active_exit.rs`: `b1c3989f`, `b4793800`, `8ec851a9` — none flip the predicate), so the row-equality check is mandatory, not borrowed from precedent."

**A5 — §8 (anchor corrections), exact replacements:**
- `windows_traffic.rs:187-216` → `windows_traffic.rs:195` (collect_active_tunnels) and, where the nat-session retry was meant: `windows_traffic.rs:300` (fn), `:305-313` (script retry), `:318-332` (outer loop).
- `windows_traffic.rs:279-281` (identity-in-Rust) → `windows_traffic.rs:314-328` (match at `:322-324`); nat-session doc window → `windows_traffic.rs:275-299`; assert fn → `windows_traffic.rs:257-273`.
- `active_exit.rs:348` — relabel from "negative test" to "positive identity test (`egress_evidence_names_pair_and_identity_when_proven`); negative pair is `:371` and `:406`".
- `LiveLabStagePassLikelihoodAdversarialReview_2026-09-01.md` → `LiveLabStagePassLikelihoodSummaryAdversarialReview_2026-09-01.md` (all occurrences).
- `macos_exit_nat_lifecycle.rs:58` (internal_prefix field) → `:59` (doc comment `:57-58`).

**A6 — §4 (egress proof): name the sink-segment requirement and make the Q2 resolution a MUST.** Append:

> "The sink must observe the exit's egress-side segment: after CP-1 that is 192.168.64.0/24 (the Debian bridge100 host or any bridged guest on it); the pre-CP-1 Shared-NAT segment (192.168.65.0/24) is host-unobservable and can never host the sink. Q2 resolves to: sink observation, or the two-phase reachability fallback WITH pf-state capture — never the fallback without pf-state capture (the Refresh §6 equivalent-strength bar at `:389-398`, esp. `:396`, admits nothing weaker)."

---

## §10 What could not be verified

- **No lab run was executed and no macOS guest was booted** for this review; everything above is static, in-worktree evidence.
- The runtime shape of global `pfctl -s state` output on the lab's macOS build (translation-line format) — unverified; Q1 stands, and the fail-closed-until-fixture posture is the correct response (A3).
- The actual rule shapes of the daemon's exit-mode killswitch anchor on macOS — required to confirm the §4 conclusion that PF-05 *can* pass while serving; the classification analysis (`:169-221`, `:238-260`) shows the pass conditions but not that the deployed rules meet them.
- Whether the macOS guest's SSH user can obtain pfctl write (for the precedence check) — unverified; the design must declare the root requirement regardless (A2).
- CP-1 was not performed; the bridged re-attach of `macos-utm-1` onto 192.168.64.0/24 remains operator-authorized work outstanding (Refresh `:117-133`, `:294`).
- The matrix-row attribution flow was read from code and prior run records (e.g. the 2026-08-31 blind_exit row, Refresh `:102`), not exercised with a fresh run; the A4 equality check is derived from the recorded provenance fields' documented semantics.
