# QH-22 — make the ledger's `first_failed_stage` chronological — plan — 2026-08-10

**Status: PLAN, pre-review.** Written against `HEAD = cadd02bd`, clean tree, all §7 gates
green at that commit. Every claim below was verified by reading the code at that commit; the
file:line is given so a reviewer can re-check rather than trust. Claims that are inferred
rather than executed are tagged **INFERRED**.

## 0. What QH-22 says, and why this plan does not do what it says

`QualityHardeningTodo_2026-07-25.md:1048-1077` records QH-22 as
**"the computation is correct, the naming is the defect"** and offers two fixes: rename the
field, **or** emit a genuinely chronological one.

That register entry is now **stale in one direction and still correct in the other**, and the
difference is the whole reason this plan exists:

- **The verifier half has already been fixed.** `live_lab_evidence_verifier.rs:310-313`
  carries a `started_at` field explicitly tagged `QH-22`, populated from `stages.tsv`
  (`:465`), and `:563-570` selects the first failure by
  `(started_at.is_empty(), started_at, stage)` — i.e. genuinely chronological, with
  empty timestamps sorting **last** and a name tiebreak. QH-22's text, which says the
  verifier "selects the first `Fail` while iterating `merged`… in key-sorted order", no
  longer describes the code.
- **The ledger half was not fixed.** `live_lab_run_matrix.rs:2366-2371` is still
  `stages.iter().find(|s| s.status == "fail")` over a `Vec` that
  `dedupe_stage_evidence` (`:2310-2324`) rebuilt from a `BTreeMap<String, _>` — so it is
  **alphabetically** first. `StageEvidence` (`:392-397`) has no timestamp field at all, so
  the ledger *structurally cannot* be chronological today.

So the two producers of this field now **disagree by construction**, which is worse than the
uniform-but-misnamed state QH-22 described. Renaming the ledger field would entrench that
disagreement. **This plan takes the second option: make the ledger chronological, matching
the verifier's already-landed rule.**

### The consequence QH-22 warned about, restated precisely

QH-22's ★ note says a verifier that deliberately mirrors the ledger's ordering provides
**zero corroboration** for that ordering. That remains true and this plan does not pretend
otherwise. What it does claim is narrower and worth stating exactly:

> Aligning the two rules makes their **agreement** detect *implementation* divergence — one
> path updated while the other is not — which is **exactly the defect that occurred here**
> and went unnoticed. It does **not** corroborate that the rule itself is right.

That distinction must survive into the code comment, or the next reader will over-trust the
check.

## 1. Why this is worth fixing before the next run

- The field is populated on **90 of 106** ledger rows, and it is the field triage starts from.
- It has already misdirected once: it named `cleanup` (a downstream artifact-collector bug,
  QH-21) when the real root cause was `preflight` failing **four seconds earlier** on a
  one-hour guest clock skew (`QualityHardeningTodo_2026-07-25.md:1051-1053`, `:1070-1073`).
- The divergence is **silent**: `live_lab_evidence_verifier.rs:702-704` computes
  `agreement_with_ledger_row` from `ledger_row_summary.overall_result == recomputed && p45.pass`
  — `first_failed_stage` is not compared at all. The verifier already recomputes the right
  answer into `recomputed_first_failed_stage` (`:713`) and then never checks it against the
  ledger.
- It is consumed downstream: `rustynet-lab-monitor/src/app.rs:63-76`, `:217`, `:274` drive
  the TUI's position-based failure breakdown off this value. A wrong value mis-attributes the
  failure in the monitor too.

This is the "produces misleading evidence rather than merely failing" class, so it is fixed
**before** the next re-baseline run, not after.

## 2. The three evidence sources, and which can carry a time

`build_row` merges three sources (`live_lab_run_matrix.rs:1111-1128`) before dedupe:

| Source | Site | Carries `started_at`? |
| --- | --- | --- |
| `state/stages.tsv` | `read_stage_evidence` `:1556-1566` | **Yes, but discarded today.** The row is filtered on `len() >= 8` and only `row[0]`, `row[2]`, `row[4]` are read. `started_at` is TSV index **6** (`live_lab_stage_recorder.rs:64-73` writes it 7th; `:94` parses `get(6)`). |
| `orchestration/orchestrate_result.json` | `read_orchestrator_outcome_evidence` `:1568+` | **No.** Measured across real artifacts: outcome objects carry exactly `artifacts`, `stage`, `status`, `summary`. |
| `config.extra_stage_outcomes` | `:1119-1128` | **No.** In-memory `LiveLabRunMatrixStageOutcome`, no time field. |

A fourth producer appends *after* dedupe: `apply_conclusion_barrier` (`:1311`, pushes a
`StageEvidence` at its `+27` offset) synthesises terminal outcomes for planned-but-missing
stages. Those have **no** timestamp by nature — the stage never ran.

**So chronological ordering is achievable for TSV-sourced stages and undefined for the other
three.** That is precisely why the verifier's tiebreak sorts empty timestamps **last**: a
stage with no time must never outrank a stage with one. The ledger must adopt the same rule,
not invent its own.

## 3. The change

### C1 — `StageEvidence` carries `started_at`

Add `started_at: String` to the struct (`:392-397`). Populate from `row[6]` in
`read_stage_evidence`; leave empty in the other three producers. This is the minimum that
makes chronology expressible.

### C2 — dedupe keeps the EARLIEST time

`dedupe_stage_evidence` (`:2310-2324`) merges duplicates by stage name. Its `and_modify` arm
must additionally keep the earliest non-empty `started_at`, mirroring the verifier at
`live_lab_evidence_verifier.rs:449-453`: take the incoming value if the existing one is empty,
or if the incoming is non-empty and lexically smaller.

Lexical comparison is correct **only** because the timestamps are fixed-width UTC
(`YYYY-MM-DDTHH:MM:SSZ`), which sorts lexically iff it sorts chronologically. The verifier
already relies on this. **If a source ever emits a local-time or variable-width stamp this
breaks silently** — call that out in the comment rather than assuming it.

### C3 — `first_failed_stage` selects chronologically

Replace the `find` at `:2366-2371` with a `min_by` over failures keyed
`(started_at.is_empty(), started_at.as_str(), stage.as_str())` — byte-identical in effect to
`live_lab_evidence_verifier.rs:566-571`. Keep the status predicate exactly as-is
(`status == "fail"`); this plan changes **which** failure is named, never **whether** the run
is considered failed.

### C4 — make the divergence loud

Extend `agreement_with_ledger_row` (`live_lab_evidence_verifier.rs:702-704`) to also require
`ledger_row_summary.first_failed_stage == recomputed_first_failed_stage`, with a comment
stating the limit from §0 — it catches implementation drift, not rule error.

**Guard against a false negative:** the ledger stores the field alias-preserving
(`live_lab_run_matrix.rs:1866` notes this), and the monitor strips `node::` prefixes before
use (`app.rs:76`). The comparison must therefore compare like with like, or every node-scoped
run reports disagreement. Confirm which side carries the alias before wiring this, and
normalise if they differ. **INFERRED** — verify before implementing; if they do differ, that
is itself a finding.

### C5 — tests

1. Two failures, times four seconds apart, alphabetically inverted (`cleanup` at T+4,
   `preflight` at T+0) — the historical case. Must name `preflight`.
2. A failure with a timestamp and a failure without — the timestamped one wins regardless of
   name.
3. Two failures, neither timestamped — falls back to name order (deterministic, not arbitrary).
4. Dedupe: the same stage seen twice keeps the earlier time.
5. Ledger and verifier agree on a fixture where alphabetical and chronological differ.

Each must be mutation-proven: revert to `find`, and to a naive `min_by_key(started_at)` that
lets an empty string win, and watch the right test go red.

## 4. Deliberately out of scope

- **`earliest_stage_time_from_rows` (`:2414-2416`) is a stub that always returns `None`**, with
  both parameters underscore-prefixed, so `earliest_stage_time` always falls through to
  re-reading the TSV (`:2391-2411`). C1 makes that stub implementable for the first time. It is
  **not** implemented here: it feeds the `run_started_utc` / `run_finished_utc` columns, so
  changing its source of truth is a separate behavioural change with its own blast radius and
  deserves its own evidence. Note it, do not fold it in.
- **No renaming.** QH-22's first option is rejected: the verifier already committed to
  chronological semantics, so renaming the ledger field would leave two producers of the same
  concept permanently disagreeing.
- **Historical rows are not rewritten.** The fix is forward-only, exactly as QH-37's alias
  removal was. The 90 populated rows keep alphabetical values and remain untrustworthy for
  triage; say so in the register rather than implying the ledger is now uniformly correct.

## 5. Definition of done

- All five tests pass and each is mutation-proven to discriminate.
- Full §7 gate set green, plus `./scripts/ci/lab_monitor_gates.sh` if the monitor is touched.
- QH-22 updated in place: mechanism corrected (its "verifier mirrors the ledger" text is
  stale), status set to resolved-forward-only, evidence recorded as commit + the mutation that
  actually ran.
- The forward-only limitation is stated in the register **and** in the code comment, so a
  future reader does not treat pre-fix rows as chronological.
