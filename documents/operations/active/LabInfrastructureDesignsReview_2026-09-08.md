# Lab Infrastructure Designs Review — 2026-09-08

**Status:** UNTRUSTED adversarial design review (docs-only, no code changed).
**Scope:** `EvidenceOnPassDesign_2026-09-08.md` (QH-83) and
`PlatformInferMigrationDesign_2026-09-08.md` (QH-82 root cause).
**Method:** every count and file:line the two designs cite was re-measured
directly on this tree at commit `c8c10d20`. Both designs were written against
earlier trees; where line numbers drift, this review cites this tree.

---

## Part 1 — EvidenceOnPassDesign (QH-83)

### A. Is the problem statement true?

Yes, and — unusually for a design in this repo — **the numbers were counted,
not estimated, and they all reproduce**:

- **81 catalog stages, suite split exact.** Counted from the
  `define_stage_catalog!` rows in `orchestrator/stage/mod.rs`: 81 rows with
  `@ Suite`; Setup 17, Live 35, CrossNetwork 11, Chaos 9, NegativeControl 4,
  Disruptive 2, Soak 1, Cleanup 2. Matches the design's §1/§2 table exactly.
- **Exactly 2 stages append to their own log.** Production
  `append_stage_evidence_line` call sites: `stage/membership_init.rs:135` and
  `stage/mesh_status_validation.rs:124`. (A third hit at `evidence.rs:1452` is
  inside `#[cfg(test)]` — correctly excluded by the design.) So the naive
  "non-empty stage log for every stage" wrapper demotes 79 of 81 on the first
  live run — the design's flag-day arithmetic is right.
- **34 stage-tree files contain `fs::write`** — reproduced.
- **The seam behaves as described.** `runner.rs`: `catch_unwind` returns →
  pre-cleanup hook merge (~172) → `is_blocking` insert →
  `observer.stage_finished` (~189). The recorder truncates the per-stage log at
  `stage_started` (`evidence.rs:516`, `fs::write(&log_path, "")`, with
  remove-file fallback at 519–528) and appends the terminal verdict at
  `stage_finished`. A check placed after `stage_finished` would be vacuous;
  the design's placement (between `catch_unwind` and the hook merge) is the
  only sound one, and its test 8 pins exactly the wrong placement.
- **The reuse is real, not parallel.** `StageOutcome::NotProven { reason,
  detail }` exists with `is_blocking()` including it
  (`orchestrator/error.rs:~297–309`); `ReasonCode::MissingWitness` →
  `"missing_witness"` and `ReasonCode::UnreadableEvidence` →
  `"unreadable_evidence"` exist with stable tokens (`as_str`, ~245–261); the
  cascade (`skip_decision` rule 2, `runner.rs`~247–259), the TSV mapping
  (`NotProven` → `VmLabStageStatus::NotProven`, reason-led summary), the
  `run_instance_id` stamp, and the `Reused` digest seal are all present as the
  design claims. No new outcome kind is invented.
- One strengthening fact the design does not cite:
  `append_stage_evidence_line` already **refuses** empty/whitespace-only and
  newline-bearing lines (`evidence.rs:~199–210`), so a stage cannot even
  appease `StageLog` with blank filler through the sanctioned API.

**Q. Does the definition of "evidence" work for the real catalog?**
Mostly. The three-kind taxonomy (`StageLog` / `File` / `None{reason}`) covers
the catalog's actual shapes: 2 stages are `StageLog`-capable today, 34 files
write some on-disk artifact (`File` candidates), and the teardown/cleanup
family plus pure-orchestration steps have a legitimate `None` story the design
surfaces as an owner decision (§8.2 — the distribution-receipts question is
the right hard question to force). What the taxonomy does **not** cover well
is the macro-generated stage families — see D below.

**Q. Is the opt-out fail-closed?** For hand-written stages, yes, structurally:
the trait method has no default, so a new stage's new impl cannot compile
without declaring. Omitting a declaration is a compile error, not a silent
exemption — exactly what the task demands. But the guarantee weakens where one
impl serves many stages (D).

### B. Does the chosen option beat the rejected alternatives?

Yes on all four rejections:

- The audit's literal every-stage-log shape is correctly killed by the measured
  79/81 flag day, and the design is right that it also invites the
  constant-line appeasement.
- `Option<&str>` with a `None` default is correctly rejected — the
  zero-effort path would be the permissive one, the exact shape this repo cut
  a previous proposal for.
- Default-`StageLog` is correctly rejected: same flag day, and the opt-out
  reason would be unforced.
- A sidecar manifest is correctly rejected as a second source of truth that
  can drift from the impls.

### C. Fail-closed analysis of the design's own mechanisms

Strong. Absent declaration → compile error (hand-written stages). Absent/empty
artifact at run time → blocking `NotProven`, cascading. Malformed declaration
(absolute path, `..`, empty) → refused at `validate_plan`/`new` — stricter and
earlier than a mid-run demotion; `validate_plan` exists at `runner.rs:281` and
takes the stage slice, so the extension is implementable as written. Stale
content within a run is handled by the truncation-at-start behavior the design
verified, and across runs by the `run_instance_id` row stamp. Whitespace-only
= empty (§8.1) is the right call and is consistent with the append API's own
trim-and-refuse behavior.

**One hole (blocking): the totality claim is false for macro-family stages.**
The design's §1/§4 claim — "the compiler totals over `StageId`", "the 82nd
stage forces an 82nd declaration" — holds only where one struct implements
`OrchestrationStage` per stage. Measured: **71 impl sites cover the 81 catalog
IDs**, and at least two families are macro-generated structs carrying an
`id: StageId` **field** — `stage/cross_network.rs:159,176` (the 11
CrossNetwork stages) and `stage/chaos.rs:18,31` (the 9 Chaos stages). One
`evidence()` body therefore decides the witness policy for 20 of 81 stages,
and an 82nd stage added to such a family would **silently inherit the
family's declaration** — the exact silent-exemption shape the design exists to
prevent, reintroduced one abstraction layer away.

**Required change:** the design must specify how field-driven families declare
per-stage evidence. Two workable options, either is acceptable:

1. Make the evidence declaration a **column of `define_stage_catalog!`**
   (the macro already compile-totals a per-`StageId` exhaustive match for
   `tier()`), restoring "82nd row forces an 82nd declaration" literally; or
2. Require every multi-ID impl's `evidence()` to `match` on the stage id
   **exhaustively with no `_` arm**, stated in the design and pinned by a test
   that walks `StageId::ALL` and asserts each macro-family arm exists.

Without one of these, the design's central fail-closed property has a
documented exception covering a quarter of the catalog.

### D. Implementable as written?

Yes, with the macro-family decision above. Two non-blocking imprecisions:

- `context.rs:75` is `OrchestrationContextBinding.report_dir: String`;
  `OrchestrationContext::report_dir` is a `PathBuf` at `context.rs:193`. The
  runner-can-resolve-paths claim holds either way; cite `:193`.
- The negative-control suite (4 stages) passes **iff** a targeted operation
  fails — its witness is the inversion record, not a positive artifact. §6's
  batch list does not call this out; the per-suite triage will hit it, but
  saying so now prevents a wrong `None{reason}` default for a suite whose
  whole value is its evidence.

### E. What it missed

- The macro-family hole (C above) — the only material gap.
- It correctly declines to solve content quality (§7) and is honest that a
  constant line still appeases `StageLog`; the per-suite batch review is the
  compensating control and QH-83's own framing agrees.

### F. Effort and counts

Counts: verified, all reproduce. Effort ~3.5–5 days (1 day mechanical,
2.5–4 days judgment across 81 stages plus five live re-verify batches) is
believable given that 79 stages need a decision and the distribution-receipt
question (§8.2) alone is real wiring if the owner rules for receipts.

### Verdict — BUILD-WITH-CHANGES

- **Blocking:** specify per-stage evidence declaration for the macro-generated
  families (`cross_network.rs`, `chaos.rs`; audit for any other field-driven
  struct), via a catalog-macro column or an exhaustive no-`_` match, so the
  compile-forced totality the design promises actually covers 81/81.
- Nice-to-have: fix the `context.rs:75` citation; name the negative-control
  witness shape in §6.

---

## Part 2 — PlatformInferMigrationDesign (QH-82 root cause)

### A. Is the problem statement true?

Yes, verified on this tree:

- **`infer` ends in an unconditional `else { Self::Linux }`**
  (`vm_lab/mod.rs:2364–2366`), returns `Self`, and its arm order is
  Windows → macOS → iOS → Android — all as the design states. `parse`
  (`mod.rs:2316–2327`) is an exact-string table that rejects unknown values
  with `Err`, and its Linux arm is `linux|debian|ubuntu|fedora|mint` — the
  design's hint arm mirrors it correctly.
- **`infer` call sites: exactly 3, confirmed** (`mod.rs:2522` inside
  `effective_platform_profile`, `mod.rs:7502` the unmatched-local-UTM
  discovery branch, `topology.rs:229` `platform_for_entry`). The task's
  "is the call-site count right" — yes.
- **The three silent sites' line drift is real and correctly reported.** This
  tree: diagnose `mod.rs:3364` (inside `execute_ops_vm_lab_diagnose`,
  `-> Result<String, String>` at `:3343`, feeding `node_adapter_for`),
  relay filters `mod.rs:14188` and `mod.rs:14263` (both
  `e.platform.unwrap_or(VmGuestPlatform::Linux) == Linux` closures). The
  audit's `3019/13843/13918` are stale for this tree exactly as the design
  says.
- **The chain facts hold.** `effective_platform_profile` (2513–2535) is
  infallible and calls `infer` then `default_platform_profile`;
  `VmInventoryEntry.platform` is `Option` (`:2661`); `platform_profile()`
  (`:2669–2679`) wraps it. `Unsupported` variants exist for both
  `VmRemoteShell` (`:2385`) and `VmGuestExecMode` (`:2413`), so the discovery
  degradation (§2.2 class 3) is implementable as written. `topology.rs`'s
  `platform_for_entry` is `#[allow(dead_code)]` W5.7-quarantined, already
  returns `Option<TopologyPlatform>`, and its consumer
  `select_alias_by_platform` documents the None→caller-hard-error contract —
  the design's `?`-based sketch fits.
- **The audit numbers check out.** `PlatformBranchingAudit_2026-09-08.md`
  states 25 of 52 decision groups silently take the Linux arm; row #1 is the
  `infer` residue, row #18 the diagnose bypass, row #5 the readiness
  `_ => true`. Commit `f386b249` ("Fail closed when a node's platform is
  unrecorded in the orchestrator") landed the six R7 sites exactly as the
  design's §0 says.
- **Inventory sweep (my addition):** the current inventory has 14 entries and
  **3 lack `platform`** — `debian-headless-2`, `debian-headless-4`,
  `debian-lan-11`. All three are hint-bearing (`debian`), so all three infer
  `Some(Linux)` under the new hint arm. **No day-one live-lab breakage for the
  current fleet** — the migration's biggest practical risk is cleared, and the
  design should record this sweep so the next reader does not re-derive it.

### B. Does the chosen option beat the rejected alternatives?

Yes. The `Option`-over-`Result` argument is right (one failure kind; the
error text belongs to the caller, which has the alias). The
`Unknown`-variant rejection is the strongest part of the design and is
correct: adding a variant makes ~180 behaviour-branch matches total *today*,
destroying the compile-error property for genuinely new OSes and letting a
`_` wildcard absorb `Unknown` and the next OS in one arm — the audit's own
central thesis. The serde-surface argument (inventory files could carry
`"unknown"`) is also correct. Doing-nothing is correctly rejected:
`f386b249` stopped at six sites, three remain, and this design's §3 closes
all three with differentiated treatment.

### C. The task's specific questions

**Are the three treatments correct?**

1. **Diagnose (`:3364`) — explicit platform only, hard error.** Correct and
   the strictest defensible choice: the platform picks the adapter, so a
   guess runs wrong-OS probes against the node the operator is already
   worried about; the audit's row #18 sharpening (alias says `windows`, still
   gets the Linux adapter) is real. The fn is `Result`-shaped, so
   `ok_or_else(...)?` lands cleanly.
2. **Relay filters (`:14188`, `:14263`) — positive allowlist +
   enrich-existing-errors, NOT error-inside-the-filter.** This is the right
   answer to the task's warning that a selection filter failing closed
   selects nothing. Verified against the real functions: the filter's
   contract is "pick the Linux ones" from a mixed inventory (the standard lab
   contains Linux plus macOS/Windows guests), so hard-erroring on any
   unknown-platform entry would abort every legitimate mixed topology.
   Excluding unknowns lands the failure in the *existing, already-tested*
   error paths (`"no relay_capable Linux node in inventory"`, the
   ≥2-peers error), and appending the excluded aliases makes the cause
   actionable. "The unacceptable outcome was never 'no selection'; it was 'a
   selection made from a guess'" — agreed. Also correctly default-deny: a new
   platform variant is not silently Linux-eligible.
3. **Discovery (`:7502`) — `Unsupported` modes + note, not an error.**
   Correct: the branch runs for a local UTM VM with no inventory entry, there
   is no alias record to fix, and hard-erroring would let one oddly-named VM
   blind the whole discovery surface. `Unsupported` shell/exec modes refuse
   every downstream exec path through existing handling.

**The load-bearing question: can a caller `unwrap_or` the unknown back into
Linux, making the migration cosmetic?**

Partially guarded, not fully — and the design is honest about the mechanics
but overstates the result once:

- The **short path is closed**: converting `platform_profile()` to `Result`
  compiler-forces all 34 callers to name the unknown; the assertion-shaped
  majority becomes `?` with the same failure shape as a wrong platform.
- The **bypass is visible but not gated**: `infer(..).unwrap_or(
  VmGuestPlatform::Linux)` still compiles. The design's defense is that it is
  now "greppable" (`VmGuestPlatform::Linux` vs today's invisible
  `Self::Linux`) — true, but nothing in this repo greps it. A discipline that
  lives in prose is how the original `else { Self::Linux }` survived.
- The design's §4 claim "the old zero-effort path (Linux) no longer exists as
  an expression shorter than the fix" is **overstated**: direct
  `entry.platform.unwrap_or(Linux)` reads outside the migration surface (the
  audit's gate list — `mod.rs:3472`, `8096`, `34444`, `admin_issue.rs:4`,
  `backlog.rs:96`) are untouched and remain exactly that short. The design's
  own §6 concedes ~22 of 25 silent groups get nothing; §4's sentence should
  be scoped to the inference chain.

**Required change:** make the greppability a gate. Add a CI tripwire (the
`scripts/ci/` gate family already greps for such patterns) that fails on
`infer(` composed with `unwrap_or`/`unwrap_or_else` yielding
`VmGuestPlatform::Linux`, and on new `unwrap_or(VmGuestPlatform::Linux)`
occurrences outside the audit's known-remaining list. Without it, the
anti-`unwrap_or` property this whole design rests on is enforced by review
alone.

### D. Implementable as written?

Yes, with one counting correction and one pre-landing sweep:

- **The 34-site count is off by one.** Measured on this tree: **34 lines**
  total, of which **32 in `vm_lab/mod.rs`** (design says 33) plus 1 in
  `overnight/executor.rs` and 1 in `overnight/mod.rs`; the design's "35 raw
  hits include the definition/impl" is wrong (34 raw lines; the
  definition/impl are not matched by `.platform_profile()`). Harmless — the
  compiler totals the real set — but the design sells itself on measured
  counts and should carry the right ones. The named data-building sites
  (`30658`, `31281`, `31348`) and assertion sites (`11549`, `14963`,
  `15101`, `16373`, `16561`, `19341`) all reproduce; additional sites the
  design's ellipsis covers exist (`38230`, `40723`).
- **Hint-arm asymmetry is a known, accepted cost — record it.** The hint set
  (`linux|debian|ubuntu|fedora|mint`) excludes the lab's other distro
  families (`rocky`, `alma`, `rhel`, `centos`): a future platform-less
  Rocky entry fails closed at every resolution site until the inventory
  gains `platform`. That is the intended direction, but the design should
  say it as a named consequence (today it surfaces only inside the §5
  distro-caveat prose, where it reads as out of scope). The current
  inventory sweep above confirms no present entry is affected.

### E. What it missed

- The CI tripwire (C above) — the one change that makes the migration's
  central property durable rather than aspirational.
- §6's accounting is honest and correctly resists the temptation to claim the
  root-cause fix pays for the capability table: 2 of 25 auto-closed (rows
  #1, #18), row #5 closed on its None-path only, the two relay filters from
  the separate gate list, ~22 needing the R9/R6/R11 work. Verified against
  the audit's register rows; the "land inference first because evidence
  minted downstream of a lying `infer` is contaminated" sequencing argument
  is sound.

### F. Effort and counts

2–2.5 days (1.0 mechanical + 1.0–1.5 judgment including the 34-site review
and one live re-verify) is believable for a conversion whose mechanical half
is genuinely compiler-driven. Counts: `infer` sites exact; `.platform_profile()`
off by one as noted; inventory-day-one risk cleared by the sweep above.

### Verdict — BUILD-WITH-CHANGES

- **Blocking:** add the CI tripwire gating the `infer`→Linux unwrap and new
  `unwrap_or(VmGuestPlatform::Linux)` occurrences; without it the migration's
  anti-regression property is prose.
- **Blocking (cheap):** correct the 34/33/35 site counts, and scope §4's "no
  longer exists as an expression" claim to the inference chain.
- Nice-to-have: record the inventory sweep (3 platform-less entries, all
  debian-hinted, none broken) and name the Rocky-family hint gap as a
  deliberate fail-closed consequence.

---

## Summary

| Design | Verdict | Blocking changes |
| --- | --- | --- |
| EvidenceOnPass (QH-83) | BUILD-WITH-CHANGES | Per-stage evidence declaration for the macro-generated stage families (`cross_network.rs`, `chaos.rs`) — catalog column or exhaustive no-`_` match — so compile-forced totality covers 81/81, not 71 impls |
| PlatformInfer (QH-82) | BUILD-WITH-CHANGES | CI tripwire gating the `infer`→Linux unwrap path; correct the 34/33/35 site counts and scope the §4 "no zero-effort expression" claim |

Both designs are grounded — every load-bearing number I re-measured
reproduced, with two off-by-one-class exceptions. Both reuse existing
mechanisms (`NotProven`/`ReasonCode`; `Option`+`Result` propagation) rather
than inventing parallel ones. Both correctly reject the permissive
alternative at their decision point. Neither is buildable exactly as
written: the first has a totality hole covering a quarter of the catalog,
the second leaves its central guarantee enforced by nothing.
