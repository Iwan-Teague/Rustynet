# Skips record no reason — plan — 2026-08-13

**Status: PLAN, unreviewed.** Read at `548c5d13`+. Written under the standing goal *"pass all
stages with good code, not happy-pass edits"* — this is the prerequisite for that goal, not a
side quest.

## 0. The defect

Every skipped stage records **no reason**. Measured on `relay-coverage-20260813h`:

```
skipped: 33
  33x  (no reason recorded)
```

(parsed positionally from `state/stages.tsv`, 8 fields, field 6 = summary; all empty)

The reason is not being dropped downstream — it never existed. `StageOutcome`
(`orchestrator/error.rs:211-217`) is:

```rust
pub enum StageOutcome {
    Passed,
    Failed(String),   // <- carries why
    Skipped,          // <- carries nothing
    NotRun,
    ...
}
```

`Failed` explains itself. `Skipped` cannot.

## 1. Why this blocks the goal

The lab's current shape is **24 pass / 1 fail / 33 skip**. Reaching "all stages pass" means
converting 33 skips, and today it is impossible to tell, from the evidence a run produces,
whether a given stage skipped because:

- no node was assigned the role it needs (fixable by electing a role),
- its platform is not in the topology (fixable by adding a guest),
- a dependency did not pass (fixable only upstream — a cascade),
- it is unsupported on the elected backend (not fixable at all),
- or the operator excluded it (`--skip-soak`, `--skip-cross-network`).

Those five have completely different remedies, and three of them look identical in the artifact.
The repo has already been burned by this exact shape: `enabled ≠ dispatched`, where a suite was
believed to be running while every stage cascade-skipped behind a dependency that had never
passed. A skip with no reason is that failure mode made permanent.

It also silently weakens the run's headline. A run reporting "24 passed" alongside 33 unexplained
skips reads as 24/25 rather than 24/58.

## 2. The change

### C1 — `Skipped(String)`

Change the variant to carry its reason, exactly as `Failed(String)` does.

**The point is that the compiler then forces it.** Measured scope: **96 construction sites across
33 files**, but only **2 match arms**. So the cost is mechanical breadth, and the benefit is that
an unexplained skip becomes *unwriteable* — you cannot forget a reason, because it will not
compile. A design where the reason is optional (a side channel, a `set_skip_reason` call)
reproduces the current defect the first time someone forgets.

### C2 — persist it

`stages.tsv` already has a summary field, and it is already populated for failures. Route the
skip reason into the same field so no schema change is needed. Verify the recorder writes it
rather than assuming — the field exists but is empty for every skip today, and that could be the
recorder rather than the source.

### C3 — say what kind of skip it is

Free-text alone will drift into uselessness ("skipped"). Reasons should state the *category*
plainly enough to be actioned: role-not-elected, platform-absent, dependency-not-satisfied,
backend-unsupported, operator-excluded. Whether that is a typed enum or a documented convention
is for review (§5 Q1) — a typed one is greppable and cannot drift, but adds a second thing to
keep in sync.

## 3. Blast radius

- 96 call sites, 33 files, 2 match arms. Mechanical, compiler-guided, no behaviour change:
  a skipped stage stays skipped and the run's pass/fail verdict is untouched.
- `stages.tsv` gains content in an existing column. Historical rows keep an empty summary, which
  is honest — those runs genuinely did not record one.
- No wire format, no ledger schema, no daemon change.
- Risk is breadth, not depth: 96 hand-written reasons is 96 chances to write something useless.
  §4.3 is the guard against that.

## 4. Tests, each with the mutation that proves it discriminates

1. A stage that skips for a missing role reports that reason in `stages.tsv`. *Mutation:* write
   the reason to the struct but not the file → fails. (Pins C2 specifically, since the field
   already exists and is already empty.)
2. Every `StageOutcome::Skipped` carries a non-empty reason. Enforced by the type, so the test is
   a characterization over the recorder: an empty-string reason is rejected. *Mutation:* pass
   `""` → fails.
3. The run summary distinguishes the skip categories rather than collapsing them. *Mutation:*
   map every category to one string → fails.
4. A cascade skip names the dependency that was not satisfied, not just "dependency failed".
   *Mutation:* drop the dependency name → fails. This is the one that would have made the
   documented `enabled ≠ dispatched` incident visible immediately.

## 5. Open questions for review

1. Typed category enum vs documented free-text convention (§C3)? Argue from how the reasons will
   be *consumed* — is anything expected to aggregate them, or are they for humans reading one
   run?
2. Is `stages.tsv`'s summary field genuinely free for skips, or does anything parse it
   positionally and assume empty-for-skip? A consumer that treats non-empty as failure would
   invert meaning. **This is the one that could break something; settle it before implementing.**
3. Should `NotRun` and the prior-pass variant carry reasons too, for the same argument? They have
   the same explain-yourself problem.
4. 96 hand-written reasons is a lot of prose. Should some be derived mechanically (e.g. the role
   gate already knows which role was missing) rather than typed by hand at each site?
5. Does the ledger's `not_run`/`skip` column vocabulary need to change in step, or is this purely
   the report artifact?

## 6. Definition of done

No `StageOutcome::Skipped` can be constructed without a reason; `stages.tsv` carries it for every
skip; the categories are distinguishable; every test above is mutation-proven; a live run shows
all skips explained; and the §7 gates pass. Success is measured by re-running the count in §0 and
getting **0x (no reason recorded)**.
