# Adversarial Review — LiveLabExtensibilityAssessment_2026-09-08 (2026-09-08)

**Status:** UNTRUSTED docs-only adversarial review of `LiveLabExtensibilityAssessment_2026-09-08.md`. No code changed. Reviewed at worktree HEAD `993ecf7a`; the assessment measured commit `0e649c65`, an ancestor contained in HEAD. Every number below was re-derived from the tree, not accepted from the doc. Method note: all paths are relative to `crates/rustynet-cli/src/vm_lab` unless stated; `VmGuestPlatform::` counts use the same exclusion glob the assessment used (`!orchestrator/adapter/**`) and were re-run at both `0e649c65` and HEAD with identical results.

**Verdict summary:** the measurements are mostly honest — five of six headline claims hold fully or directionally — but two are materially wrong (the `NodeAdapter` method count; the "pass while proving nothing" closure, which QH-81 reopens). The proposal set is worth building only reshaped: proposals 1–4 are sound and cheap; 5 is half the advertised size; 6 solves the right problem with the wrong mechanism; 7 should be cut; 8 is right but sequenced after 5's classification half. The single largest omission: the assessment's worst pain item, QH-80, gets a detection proposal but the actual fix (mint + distribute relay session material) is missing from the recommendation set entirely.

---

## Part 1 — Are the measurements real?

### M1. "Six touchpoints to add a stage" — **CONFIRMED**

`orchestrator/plan.rs:2-33` self-documents the six-step recipe. Re-verified each:

1. Catalog row in `define_stage_catalog!` (`orchestrator/stage/mod.rs:136-169` macro; rows from `:175`; e.g. the `RefreshSignedBundles` row at `:291`). The tier token is grammar-required by the macro — **compiler-forced**.
2. `OrchestrationStage` impl for the new `StageId` — **compiler-forced** (trait impl).
3. `Box::new(...)` arm in `build()`'s match (`plan.rs:391+`); the match's own comment says "compiler-enforced exhaustive" — **compiler-forced**.
4. Absolute count assert `assert_eq!(cli_ids.len(), 66)` at `vm_lab/mod.rs` ≈`:38989` — **test-forced**, not compiler.
5. `StageSpec` entry in `live_lab_stage_registry.rs` (struct at `:392+`), forced by `every_rust_state_machine_stage_id_is_registered` (`:2974-2982`) — **test-forced**.
6. The MCP `ORCHESTRATOR_STAGES` table (`crates/rustynet-mcp/src/bin/repo_context.rs:2080`) plus its EXPECTED list and the cross-crate test `orchestrator_stages_doc_matches_the_rust_planbuilder` (`:2277+`) — **test-forced, cross-crate**.

The doc's compiler-vs-hand-maintained attribution is accurate: 3 compiler-forced, 3 test-forced (one of which lives in a different crate). Nothing disputed.

### M2. "Up to 9 numeric count literals + 1 order list across 2 files" — **CONFIRMED**

Eight literals in `plan.rs` tests: `66`@`:615` (`build_returns_66_stages`), `75`@`:741` (chaos), `70`@`:762` (negative_control), `79`@`:800` (stack), `66`@`:817` (relay absent from default), `68`@`:830` (relay opt-in), `77`+`81`@`:884` (relay stacks) — plus the ninth `66` at `vm_lab/mod.rs`≈`:38989`, and the canonical-order list in `build_returns_canonical_security_stage_order` (`plan.rs:1006`). Exactly 9 literals + 1 order list across 2 files. (The derived-length pattern at `plan.rs:943-980` was not independently re-read; nothing below depends on it.)

### M3. "769 `VmGuestPlatform::` references outside adapter/" — number **CONFIRMED**, framing **MISLEADING**

The count is exactly 769 at both `0e649c65` and HEAD. But **310 of the 769 (40%) are inside `#[cfg(test)]` modules** — production references are 459. The assessment's own hotspot table silently uses production-only counts (e.g. "mod.rs 37": `vm_lab/mod.rs`'s `#[cfg(test)]` starts at line 9268 and exactly 37 refs precede it), so the doc's per-file table and its headline burden disagree with each other by ~1.7x. An "audit the 769" work item priced off the headline overstates the real surface by roughly two-thirds.

### M4. The triage the doc admits it skipped — **done here; doc's direction holds, magnitude halves**

The assessment's entire OS-axis verdict rests on the ratio of capability-gates (legitimate `match platform` sites) to behaviour-branches (inline per-OS logic that silently does the wrong thing on an unhandled OS), and it admits it never measured that ratio. I sampled **30 sites across 18 files**, chosen mechanically rather than by judgement: the top-6 files by reference count, sampled at their first, middle, and last match (18 sites), plus 12 further files at their first production-code match.

- **11 sites are inside test modules** (role.rs `:570`,`:889`; capability.rs `:2000`,`:3019`; anchor.rs `:862`,`:1223`; backlog.rs `:657`,`:860`; relay.rs `:1354`; host_cross_build.rs `:461`,`:601`) — neither class, pure test data.
- **7 are Class 1 capability gates** — the good pattern: role.rs `:86` (role-support matrix: Anchor/Admin/Relay → Linux only), overnight/backlog.rs `:96`, role_validation/relay.rs `:74` (`relay_lab_runtime_implemented`), connection.rs `:158` (`is_valid_for_platform`), native.rs `:348` (`is_lab_assignable_for_platform`), stage/live_mixed_topology_validation.rs `:37`, stage/active_exit.rs `:186` (`active_exit_runtime_implemented`). One smell worth its own ticket: native.rs `:348` reads `entry.platform.unwrap_or(VmGuestPlatform::Linux)` — a default-on-missing platform in a lab-assignability gate.
- **9 are Class 2 inline behaviour branches** — the pattern the doc wants gone: role_validation/anchor.rs `:109` (per-OS prog+snapshot path), relay.rs `:526` (per-OS relay start dispatch), stage/host_cross_build.rs `:96` (target-triple mapping), stage/preflight.rs `:191` (powershell vs unix argv), stage/security_audit_validation.rs `:102` and stage/exit_nat_lifecycle_validation.rs `:76` (per-OS daemon path), stage/live_lan_toggle_validation.rs `:209` (Linux-only ssh-params), stage/live_managed_dns_validation.rs `:176` (per-OS default SSH user), stage/anchor_validation.rs `:298` (per-platform coverage mode).
- **3 are neither** (enum `From` conversions at capability.rs `:504`, topology.rs `:94`; OS-string detection at network_audit.rs `:1756`).

Extrapolating the production-only sample: ~44% Class 1 / ~56% Class 2, i.e. **roughly 250 genuine behaviour-branch sites, not 769 and not 459**. The assessment's directional claim — Class 2 is substantial, and the stage-level sites skew heavily Class 2 — is **confirmed**. Its headline number is misleading, and any sizing derived from 769 (proposal 5's "audit" cost) is ~1.7-3x overstated.

### M5. "NodeAdapter has 53 methods" — **WRONG**

Counted in `adapter/node_adapter.rs`: the trait declares **42** `fn`s in the trait block (lines `:121`→`:520`), identical at `0e649c65` and HEAD, including default methods. The doc overstates the trait surface by 11 methods (~26%). Its secondary claim — the stub adapter implements only ~20 — is right (the stub at `stage/traffic_test_matrix.rs:390-484` implements 21). The direction of the argument (required surface ≪ trait surface) survives; the number does not. Whoever prices proposal 5's "grow the adapter" work from 53 will misbudget by a quarter.

### M6. "A stage can no longer pass while proving nothing" — **MISLEADING / OVERSTATED**

The schema facts check out: `StageOutcome` has 6 variants with `NotProven` blocking, `ReasonCode` carries 7 reasons, `Skipped` requires a reason. The QH-70 evaluator fix is real (`role_validation/mesh_status.rs:80-144` now judges `path_live_peer_count` / `path_latest_live_handshake_unix`). But QH-81 (`QualityHardeningTodo_2026-07-25.md:6774`) records that the empty-expectation rejection was **removed as unsatisfiable** — the daemon fills `expected_peer_ids` from advertised route CIDRs — and the daemon-side gap is open: "the MeshStatus validator cannot express a peer expectation at all… the peer-visibility check is structurally vacuous on every platform." So a vacuous pass remains structurally possible; what QH-70 closed is the skip-reason surface, not the proof surface. The doc cites QH-81's precursor in passing but still headlines the strong claim.

---

## Part 2 — Are the proposals right?

**P1 — derive the count pins, keep one absolute anchor. CORRECT, correctly sized.** Endorse. The derived pattern already exists (`plan.rs:943-980`); the work is mechanical. Cost the doc doesn't name: derived tests only catch *relative* drift, so the one retained absolute anchor (the default-plan 66) is not nostalgia, it is the only remaining tripwire against "someone quietly added a stage to the default plan." Make that explicit in the test comment.

**P2 — generate the MCP stage doc from StageId. CORRECT, under-costed.** Endorse the goal — it deletes touchpoint ⑥ entirely, and that touchpoint is the worst one (cross-crate, rots silently, three synced artifacts). Hidden cost: `rustynet-mcp/Cargo.toml` has **no rustynet-cli dependency** (deps: serde, serde_json, nix, socket2, ureq — it is deliberately tiny and boots fast), and `rustynet-cli` is the heaviest crate in the workspace. Importing `StageId` means either making the MCP binary depend on the CLI crate, extracting the catalog into a shared crate, or generating a checked-in artifact at build time. Any of the three is more work than the doc implies; the artifact option is cheapest and keeps the MCP's cold-start. Do it, but budget for the plumbing.

**P3 — shared test-context helper (empty_ctx). CORRECT, trivial.** Endorse, with a note: `empty_ctx` returning all-defaults is itself the smell — a dedicated test-support constructor on the orchestrator context (named for what a test needs, not what it lacks) is better than centralising the all-zero literal. Either way the duplication is real and the fix is one afternoon.

**P4 — mark or delete the android.rs / ios.rs stub adapters. CORRECT but only half-aimed.** Endorse **marking**, not deleting: both files are real scaffolding (android.rs 144 lines, ios.rs 142, ~2 `VmGuestPlatform::` refs each, no `unimplemented!` markers), they keep the adapter enum's exhaustiveness meaningful, and the mobile-client program (`MobileClientRoleAndLiveLabStages_2026-09-04.md`) will want them as the landing zone. Deleting buys ~300 lines and costs a future re-creation. The useful half of the proposal is the marker plus making the factory's error on them self-describing — that part is worth doing now.

**P5 — audit the 769 platform sites, move behaviour branches into NodeAdapter / a capability table. HALF RIGHT, HALF OVERSIZED.** Two separate proposals wearing one coat:
- *Classification:* correct and cheap — and M4 shows the real target list is ~250 production Class-2 sites, not 769. The audit output is exactly the seed of P8's ledger; do it first.
- *Migration:* over-sized as written. Moving per-OS command construction "into NodeAdapter methods" grows a trait that is already 42 methods (M5), and — the part the doc does not say — it **moves reviewed stage logic into adapter impl files**, i.e. the fail-closed argv/path construction that QH-01 spent a whole hardening program on migrates *away* from the stage file where its test lives, into `adapter/linux_install.rs`-style modules. The review surface shifts; it does not shrink. A capability table works for Class 1 gates (which are already fine); it cannot express "powershell.exe -NoProfile vs unix argv" — that is command construction and belongs behind the existing `RemoteCommand` seam. Migration should be opportunistic (only branches that already have a seam) not programmatic (not all ~250).

**P6 — typed `requires()` for environment preconditions. RIGHT PROBLEM, WRONG MECHANISM AS SPECIFIED.** The doc aims this at QH-80 and it would not have caught QH-80. Read QH-80 (`QualityHardeningTodo_2026-07-25.md:6678+`): the run's topology *had* a healthy elected relay — `deploy_relay_service` passed, `relay_validation` passed — and the failure was that the **minted traversal bundle contained no Relay candidate** (every mint site passed `relay_id: None`, `ops_e2e.rs:3773/3792/3946`) and no relay fleet/session material was distributed anywhere under `vm_lab`, so `load_relay_client` (`rustynetd/src/daemon.rs:4983`) returned `None`. A plan-builder-time `requires()` evaluates static facts — topology, roles, flags — and every one of those was satisfied. The missing fact is created *by a later stage during the run*. So as specified, P6 is a detection mechanism for a different, easier defect class, and the doc's own anchor case survives it.
  - **Does it solve or only detect QH-80?** Not even detect — see above. It detects "stage statically unreachable given flags/topology," which is still worth having (it would have caught the pre-QH-80 staleness defects like the removed relay env override), but the doc's framing oversells it.
  - **Would it have made the 3-hour dead end early?** No. The run failed 90 s in with `path_programmed_relay_peers=0`; the three hours went into root-causing *why*. An early failure with the same missing explanation is the same investigation moved left.
  - **Minimum useful design — two layers:**
    1. *Static `requires()`* on stages (roles present in topology, flags set), checked by the plan builder at construction. Catches config-level dead stages before any VM boots.
    2. *Producer-side post-conditions* where the fact becomes true: `refresh_signed_bundles` (and any mint/distribute stage) must return `NotProven` when the topology contains a Relay node but the minted bundle has no Relay candidate / the distributed fleet config is absent. This checks the QH-80 fact at the only point it is checkable, names the missing artifact in the reason code, and is what actually converts the 3-hour mystery into a 30-second named failure.
  - **Fail-closed question (see (a)):** as the doc specifies, an omitted `requires()` means the plan just proceeds. To stay consistent with the repo's fail-closed law the declaration must be **grammar-forced** — the catalog macro requires a `requires` entry per row, `requires(&[])` legal, absence a compile error — exactly the trick that already makes the tier token compiler-forced. And an *unevaluable* requirement (unknown fact) must refuse the plan, never warn-and-continue.

**P7 — data-driven plan inclusion. CUT.** The premise is real (`plan.rs:345-375` is a hand-written suite match plus per-stage retention exceptions), but the collapse is smaller than claimed: suite membership is already data (the catalog row's suite token); what the closure owns is suite→flag mapping plus exceptions, and the CLI flags (`enable_relay_forwarding_validation` etc.) stay in code regardless — so after P7 the closure doesn't disappear, it shrinks. What you pay: today the default plan is answerable by reading one 30-line function; after P7 it is scattered across 66 registry entries, and a single careless registry edit can silently include a disruptive stage in the default plan (see (a)). If ever done, the non-negotiable preconditions are the retained absolute default-plan anchor from P1 plus a generated, reviewed "default plan" artifact. Until someone shows a concrete pain worse than editing one readable function, this is reviewability sold for convenience.

**P8 — per-OS stage-parity ledger as a gate. CORRECT, MIS-SEQUENCED.** The concept is right — make "which OS does this stage support" a data row with an oracle instead of prose — and it is the natural sink for P5's classification output. Sequence it *after* the classification half of P5 (which produces its initial content); landing it first means hand-filling 66 rows against the very uncertainty the audit exists to resolve. Cost the doc doesn't name: it is another per-stage hand-maintained field of exactly the tedium class P1 is eliminating — acceptable only because it is oracle-checked, and that argument should be written down when it lands.

### (a) Security — proposals 6 and 7 against the fail-closed / default-deny law

Neither touches signed state, keys, or the dataplane; blast radius is the lab. But the run-matrix is release evidence, so changes to *what a green run means* are security-relevant.

- **P6 as specified is fail-open.** An omittable precondition declaration means the unsafe default (no declaration → no check → plan proceeds) is the zero-effort path, and the repo's law (`CLAUDE.md` §3: fail closed when state is missing; §10.4: missing context → deny) runs the other way. Fix: grammar-force the declaration via the catalog macro (same mechanism as the tier token), and make an unevaluable requirement a plan refusal, not a log line. With those two amendments P6 is net fail-closed-positive: it converts silent unreachability into a named refusal.
- **P7 concentrates plan composition into data with weaker review affordances.** Today, changing what the default plan runs means editing a reviewed `match` in one function; after P7 it means editing a row in a 66-entry table where a `suite:` token edit silently re-platforms a stage's inclusion. Default-deny reads directly onto this: the plan builder's posture should be "stage runs only if explicitly included," and the closure *is* that explicit list. P7 keeps the letter (still data-driven inclusion) while eroding the review property that makes the deny meaningful (one place to read, one diff to review). If built anyway: keep the single absolute default-plan count anchor, generate the default-plan manifest artifact into the report dir, and diff it in the run header.

### (b) Does P6 solve QH-80?

No — see P6 above. It neither solves nor detects the actual failure: the topology and flags were all correct; the defect was in the *content a later stage produced*. Only the producer-side post-condition layer catches it, and the actual QH-80 fix (orchestrator mints a Relay candidate into the traversal bundle and distributes fleet/session material — already scoped inside QH-80's own disposition) is a prerequisite for the stage ever passing. The assessment reviews the QH-80 story in detail and then omits the fix from its recommendation list; that is the set's biggest gap.

### (c) Ranking by expected value instead of pain

The doc ranks by where failures surface (runtime > test > compile). Ranked by (benefit × confidence) / cost:

1. **P1** — cheap, certain, kills a whole tedium class. Do first.
2. **P2** — deletes the worst touchpoint; cost is the cross-crate plumbing the doc omits.
3. **The QH-80 fix itself** (mint Relay candidate + distribute session material) — absent from the doc's list; highest raw value item in the whole space: it converts a permanently-red stage green.
4. **P6 redesigned as the two-layer design** (static requires grammar-forced + producer post-conditions) — the QH-80 class of silent-unreachable defects stops recurring; medium cost, vocabulary needs one careful design pass.
5. **P3** — trivial, do opportunistically.
6. **P4 (marking half)** — trivial, do opportunistically.
7. **P8** — after P5-classification seeds it.
8. **P5-classification only** — the audit to ~250 sites, feeding P8.
9. **P5-migration** — opportunistic, seam-by-seam, never programmatic.
10. **P7 — cut.**

Where I disagree with the doc: it calls P5 "the single highest-value OS-axis fix" (I halve it and demote it); it keeps P7 (I cut it); and it ranks its QH-80 detection proposal above the QH-80 fix, which it never proposes.

### (d) What is missing entirely

The assessment measures three axes (stage, OS, role-validators) and skips the rest of the extensibility space:

- **The role axis is unmeasured.** The parity mandate (`CrossPlatformRoleParityPlan`) is role-centric, yet "what does it cost to add a *role*" — role.rs support matrix, role presets, validators, adapter deployment, parity ledger column, CLI surface — is never counted. By the six-touchpoint standard this would be the doc's most mandate-relevant chapter.
- **The CLI/flag axis.** Opt-in stages are hand-wired three times: flag parse, plan-builder closure, help text. Same drift class as touchpoint ⑥, never counted.
- **The evidence-schema axis.** `StageSpec` mirrors five historical CSV columns (`direct_platform`, `logical`, `role`, `cross_os`, `special`) — adding a stage touches the *ledger schema*, not just the registry. The doc folds this into touchpoint ⑤ and misses that it is a different kind of coupling (evidence semantics, not code).
- **Removal/retirement cost.** The bash→`--node` migration was a retirement program; nothing in the doc measures how hard it is to *take a stage out* cleanly (count anchors actively fight removal).
- **The cross-network substrate axis** (netns/vxlan/slirp providers) is unmeasured — a fourth surface with its own enum-matching risk profile.

---

## Verdict

This proposal set is worth building only in reshaped form. The assessment's measurement discipline is genuinely good — file:line anchors that hold up, a self-documenting recipe it correctly credits — but its two most load-bearing numbers are wrong in opposite directions (769 hides 40% test code and ~200 legitimate gates; 42 methods became 53), and its flagship conclusion ("a stage can no longer pass while proving nothing") is reopened by its own cited QH-81. Of the eight proposals: build 1, 2, 3, and the marking half of 4 as written; split 5 and keep only its classification half; redesign 6 around grammar-forced declarations plus producer-side post-conditions, and land the actual QH-80 fix first — it is the highest-value item in the space and the doc omits it; sequence 8 after 5's classification; cut 7, whose convenience does not pay for scattering default-plan composition across 66 registry rows. Shortlist, in order: **P1 → P2 → QH-80 fix (mint + distribute) → P6-two-layer → P3 + P4-marking → P5-classification → P8 → opportunistic P5-migration.**

---

**Verification appendix (what was re-derived, how):** stage-catalog macro and tier-token grammar (`stage/mod.rs:136-301`); exhaustive-match comment (`plan.rs:391`); count-literal sites by direct read of `plan.rs:615-1006` and `vm_lab/mod.rs` test region; `VmGuestPlatform::` totals by glob count with `!orchestrator/adapter/**` at `0e649c65` and HEAD, cfg(test) split by per-file test-module line scan; the 30-site triage sample by the mechanical first/middle/last rule stated in M4; trait method count by counting `fn` declarations inside the `NodeAdapter` trait block at both commits; QH-70 evaluator fix and QH-81 reopening by reading `role_validation/mesh_status.rs:80-144` and `QualityHardeningTodo_2026-07-25.md:6473-6790`; QH-80 by reading its full entry plus the cited mint sites (`ops_e2e.rs:3773/3792/3939-3946`) and `rustynetd/src/daemon.rs:4983`; `rustynet-mcp` dependency surface from its `Cargo.toml`. UNVERIFIED items: the doc's derived-length pattern at `plan.rs:943-980` (not re-read); android/ios factory references (deletion claim assessed on scaffolding value, not call-graph reachability).
