# Live-Lab Wave 1 — Integrated-Pipeline Honest Skips — Plan + Spec — 2026-06-25

Parent: `LiveLabCoverageAndHonestyAudit_2026-06-25.md` (§6 Wave 1; the integrated-
orchestrator finding). Author: Iwan-Teague. **Code-only, no live lab.** All changes
are in the rust-native orchestrator and are Linux-compilable + unit-testable.

## 0. The problem (one sentence)
In the rust-native `StageId` pipeline, the cross-OS "reported-skip" cells —
**Windows relay deploy + validation, macOS/Windows anchor bundle-pull runtime** —
return `StageOutcome::Passed` while recording the skipped per-OS work only in a
side-car `*.reported_skips.json`. So a Windows-relay / macOS-anchor run shows a
**green stage + green run**; the gap is visible only if a human opens the side-car
JSON. The parity diff (`orchestrator/parity.rs`) maps that straight to `Passed`.

## 1. Why this is the right fix (and why it's safe)
- `StageOutcome` already has `Skipped`, and `build_live_lab_run_report`
  (`parity.rs:66-75`) already maps **any Skipped stage → `RunStatus::Partial`** (not
  Passed). So returning `Skipped` from the degenerate stages immediately turns the
  run from green to **Partial** and the stage record from `Passed` to `Skipped` — no
  new enum variant or parity-mapping change required.
- The runner gates a downstream stage only on a dependency that `is_blocking()`
  (`runner.rs:48-52`), and `is_blocking()` is `Failed` only (`error.rs:198`). So a
  `Skipped` deploy_relay does **NOT** suppress relay_validation (or any downstream) —
  unlike the legacy `== Pass` gate fixed in Wave 0. Verified: no regression.
- The per-node real work is unaffected: a lab with a Linux relay + a Windows relay
  still deploys + validates the Linux relay; only the *stage-level* outcome becomes
  `Skipped` (honest: "this stage did not fully prove every node"), and the side-car
  still names exactly which nodes were skipped.

## 2. Findings → fixes

### F1.1 — `deploy_relay_service` returns Passed on reported-skip
- File: `crates/rustynet-cli/src/vm_lab/orchestrator/stage/deploy_relay.rs:137-142`.
- Now: `if failures.is_empty() { Passed } else { Failed(...) }` — ignores
  `reported_skips`.
- Fix: when `failures.is_empty()` AND `reported_skips` is non-empty, return
  `StageOutcome::Skipped` (the run goes Partial), with the skip note still written.
  When `reported_skips` is also empty (a genuine all-Linux deploy or an empty-relay
  lab), keep `Passed`. `failures` non-empty stays `Failed`.
- IMPORTANT: keep the empty-relay-lab skip-noop returning `Passed` (line 92-94) — a
  lab with no relay nodes legitimately has nothing to prove and must not turn the
  run Partial.

### F1.2 — `relay_validation` returns Passed on reported-skip
- File: `crates/rustynet-cli/src/vm_lab/orchestrator/stage/relay_validation.rs`
  (the reported-skip branch, ~:92-113, and the final outcome).
- Same fix: a reported-skipped relay-validation (Windows) yields stage `Skipped`,
  not `Passed`. Empty-relay-lab noop stays `Passed`. Hard validation failure stays
  `Failed`.

### F1.3 — `anchor_validation` returns Passed when runtime substages reported-skipped
- File: `crates/rustynet-cli/src/vm_lab/orchestrator/stage/anchor_validation.rs`
  (the runtime-substage reported-skip path, ~:171,188,210).
- Nuance: anchor **capability-advertisement** runs real on all OSes; only the
  **bundle-pull runtime substages** are reported-skipped on macOS/Windows. The stage
  must NOT claim a full `Passed` when a required runtime substage was skipped →
  return `Skipped`. The cap-advert work still ran (named in the outcome message + the
  side-car); the honest stage-level signal is "not fully proven" = `Skipped`. Empty-
  anchor-lab noop stays `Passed`; a real substage failure stays `Failed`.

### F1.4 — surface the skipped nodes in the stage outcome message (not only the side-car)
- For all three stages, the `Skipped` outcome should carry a message naming the
  skipped `(alias, platform)` pairs (e.g. `"reported-skipped <alias>(<platform>): …
  runtime not live-supported on this platform; run is Partial"`), so the skip is
  visible in the stage record / parity diff, not only in the side-car JSON. (Note:
  `StageOutcome::Skipped` is currently a unit variant — if a message is needed,
  prefer writing it to the stage's existing log/side-car AND keeping `Skipped`; do
  NOT change the `StageOutcome::Skipped` shape unless trivially clean, to avoid a
  wide enum-churn. If you DO add a message field, update `parity.rs:50`, `error.rs`,
  and all match sites + tests.)

## 3. Tests (add/adjust)
- `deploy_relay.rs`: a relay node whose platform is not `relay_lab_runtime_implemented`
  (Windows) + no failures ⇒ stage returns `Skipped` (currently the test only covers
  the side-car JSON content + the no-adapter Failed + empty-noop Passed). Add a
  reported-skip ⇒ Skipped test. Keep the empty-lab ⇒ Passed test.
- `relay_validation.rs` / `anchor_validation.rs`: analogous reported-skip ⇒ Skipped
  tests; keep empty-noop ⇒ Passed and failure ⇒ Failed.
- `parity.rs` / report: add/confirm a test that a run containing a `Skipped` stage
  yields `RunStatus::Partial` (build_live_lab_run_report already does this; assert it
  explicitly for the relay/anchor case if not covered).
- `runner.rs`: confirm (existing tests likely cover) that a `Skipped` dependency does
  NOT skip its dependents — add a focused test if missing.

## 4. Execution
This change is **small and tightly coupled** (one semantic decision applied to three
sibling stage files that share the runner/report contract), so it is implemented by a
**single** sub-agent owning all three stage files (+ any test touch in parity/runner),
for consistency — not a 3-way parallel split (which would risk three divergent skip
semantics). The reviewer then reads the diff, runs the full gate, and merges.

Owned files (single agent):
- `crates/rustynet-cli/src/vm_lab/orchestrator/stage/deploy_relay.rs`
- `crates/rustynet-cli/src/vm_lab/orchestrator/stage/relay_validation.rs`
- `crates/rustynet-cli/src/vm_lab/orchestrator/stage/anchor_validation.rs`
- (read-only / minimal-touch for an assertion test) `orchestrator/parity.rs`,
  `orchestrator/runner.rs` — only if a confirming test is added; do NOT change the
  `StageOutcome` enum shape unless §F1.4 trivially warrants it.

## 5. Gates
- `cargo fmt --all`
- `cargo clippy -p rustynet-cli --all-targets --all-features -- -D warnings`
- `cargo test -p rustynet-cli --bin rustynet-cli -- orchestrator::stage::deploy_relay orchestrator::stage::relay_validation orchestrator::stage::anchor_validation orchestrator::parity orchestrator::runner`

## 6. Definition of done (Wave 1)
- A run with a Windows relay (or a macOS/Windows anchor) no longer reports a green
  run: the deploy/validation/anchor stage records `Skipped` and the overall run is
  `RunStatus::Partial`, with the skipped nodes named.
- Empty-role labs still pass green (no false Partial).
- Hard failures still `Failed`; downstream stages still run after a `Skipped` dep.
- All gates green (excluding documented env-blocked tests). Committed as Iwan-Teague,
  pushed to `main`.

## 7. Out of scope (tracked, not built here)
- Threading **per-node role-runtime proof status into `NodeStatus`** so the role × OS
  *matrix* (not just the stage/run aggregate) shows each skipped cell — a richer
  follow-up; Wave 1 fixes the green-run/green-stage dishonesty, which is the headline.
