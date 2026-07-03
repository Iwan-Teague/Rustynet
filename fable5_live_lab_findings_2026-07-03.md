# Live Lab Findings — 2026-07-03 (Fable 5 agent)

Scope: end-to-end analysis of the live-lab system — both orchestrators, the monitor TUI, the run
matrix, the job/state plumbing, security-control coverage, and timers. Method: four parallel
read-only investigation passes over the real repo plus direct CSV analysis of
`documents/operations/live_lab_run_matrix.csv` (465 rows × 210 columns, 2026-05-27 → 2026-07-03)
and targeted first-hand verification of every load-bearing citation.

**Verification legend.** Claims marked *[verified]* were confirmed first-hand (direct grep/read of
the file, or direct computation over the CSV). Claims marked *[subagent]* come from a read-only
investigation pass whose headline conclusions I spot-checked but whose every line number I did not
independently re-derive. **DeepSeek was unreachable in this execution environment** (no API key
resolvable — expected per the sandbox caveat), so no finding here carries external DeepSeek
cross-verification; everything instead rests on direct repo inspection. One subagent claim was
caught being outright wrong and is corrected in the final section — treat that section as part of
the evidence standard of this document.

No file other than this one was created or modified.

---

## FINDING 1 — The live lab has no shared stage contract. Build one: a run-scoped Stage Manifest that every component consumes instead of hand-copying.

**Severity/Ambition: Highest. This is the structural defect underneath at least five of the other
findings, and fixing it makes an entire class of drift impossible rather than merely fixed-once.**

### What is actually true today

The name of a stage — the most basic unit of the whole system — has **no single owner**. I count at
least six independently hand-maintained copies of the stage vocabulary, none of which agree:

1. The bash orchestrator's dispatch functions (`scripts/e2e/live_linux_lab_orchestrator.sh`, no
   single list; names are implicit in ~8,800 lines of function dispatch; the only enumerable subset
   is `setup_stage_index()` at lines 1239–1255) *[subagent, spot-checked]*.
2. The Rust state-machine's `StageId` enum — 21 variants with their own naming dialect
   (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs:31-81`) *[subagent]*.
3. The mac/win sidecar stage names scattered through `crates/rustynet-cli/src/vm_lab/mod.rs`
   dispatch calls (e.g. `stage_windows_bundles_for_distribution` at mod.rs:8096, 8103, 8128, 8147;
   `distribute_windows_membership` at mod.rs:523, 14091, 18381) *[verified]*.
4. The monitor's hardcoded catalogs (~57 names across
   `crates/rustynet-lab-monitor/src/app.rs:571-650` and the `*_live_lab_catalog()` functions at
   app.rs:1863-1921) *[verified for the audit-stage region and the two names below]*.
5. Four separate match tables in the CSV writer totalling ~150+ hardcoded stage-name arms:
   `direct_platform_stage` (live_lab_run_matrix.rs:1222-1260), `logical_stage_name` (:1291-1331),
   `populate_cross_os_values` (:1391-1446), `set_special_stage_values` (:1448-1578) *[subagent;
   representative arms verified: :1226, :1518]*.
6. Docs (`documents/operations/LiveLabRunMatrix.md`, runbooks) *[subagent]*.

The predictable result, all verified first-hand:

- **The monitor tracks a stage that does not exist.** `distribute_windows_bundles` sits in the
  monitor catalog (app.rs:491, app.rs:613) and appears in **zero executing code anywhere in the
  repo** — a repo-wide grep finds it only in the monitor and in prompt documents. The real pipeline
  has *two* real stages where the monitor has one phantom: `stage_windows_bundles_for_distribution`
  and `distribute_windows_membership` (citations above). *[verified]*
- **Stages that really run — and really fail runs — are invisible.** The Windows/macOS audit
  stages are implemented and CSV-mapped (e.g. `validate_windows_enrollment_replay` implemented at
  vm_lab/mod.rs:14569 and :20089, CSV-mapped at live_lab_run_matrix.rs:1518), but the monitor's
  catalog carries **only** the `validate_linux_*` audit family (app.rs:1905-1919; no
  `validate_windows_*`/`validate_macos_*` audit entries exist anywhere in app.rs). These invisible
  stages are not hypothetical: `validate_windows_enrollment_replay`,
  `validate_windows_hello_limiter_flood`, `validate_windows_gossip_revoked_readmit` and five more
  of them appear as literal `first_failed_stage` values in the run matrix — i.e. the stage that
  killed a run has, in multiple recorded cases, no cell anywhere in the operator's UI. *[verified]*
- **Even "which stage failed" speaks three dialects.** The 53 distinct `first_failed_stage` values
  in the CSV mix bash names (`membership_setup`), Rust state-machine names (`membership_init`,
  `role_switch_matrix`, `relay_validation`, `traffic_test_matrix`, `vm_lab_setup_live_lab`,
  `restart_unready_vms`), and node-scoped composites
  (`debian-headless-1::validate_linux_hello_limiter_flood`). A consumer of this column cannot even
  join it against any one catalog in principle. *[verified]*
- **The two orchestrators disagree on the spelling of "skipped".** The Rust path converts
  `StageOutcome::Skipped` to `"skip"` (vm_lab/mod.rs:7046-7050 *[subagent]*), while the monitor's
  header math tests for `"skipped"` (ui/stage_grid.rs:106-109 *[verified]*), and the CSV contains
  both (`windows_stage_bootstrap` holds `skip`; other columns hold `skipped`) *[verified]*.
- **No component ever states the plan.** Neither orchestrator emits a machine-readable list of
  planned stages at run start; the plan is only discoverable implicitly as stages execute and land
  in `stages.tsv` *[subagent, consistent with everything above]*. So the monitor *cannot* render
  truth even in principle — it has nothing to render from except its own stale copy.

And the control experiment already exists inside the same codebase: the one view that **derives its
vocabulary from data instead of hardcoding it** — the Full Stage Matrix, which discovers
`{os}_stage_*` and one-off columns dynamically from the CSV header
(run_matrix.rs `discover_stage_suffixes` / `discover_oneoff_columns`, ~:737-796) — is also the one
view that did not drift. *[subagent]* The lesson is sitting right there.

### Why this is the highest-leverage fix

Every one of these is the *same* defect surfacing in a different organ: the phantom catalog entry,
the invisible failure-causing stages, the header math that can show 13/9, the un-joinable
`first_failed_stage`, the `skip`/`skipped` split, stale `disabled_stages` entries, the held-run
display drifting under config reload. Fixing them individually is whack-a-mole; each future stage
addition re-creates the drift. The operating contract's own standard (§10.1-style structural
prevention, "fix the root cause, not the symptom") points at a registry.

### The shape of the fix

**A. One registry, in Rust, in the tooling layer.** A single module (natural home: `rustynet-cli`,
which already owns the CSV writer and is called by the bash script) defining every stage as data:
canonical name, display group (PRE/BOOTSTRAP/LIVE), platform stream, gating predicate (as a
structured description, not prose), severity, default time budget, expected evidence artifacts,
CSV column mapping, security-control IDs it proves (see Finding 5), and **aliases** (historical
names: `distribute_windows_bundles`, `membership_init`-vs-`membership_setup`, node-scoped
composites parse as `node::stage`). The four match tables in `live_lab_run_matrix.rs` collapse into
this registry — they are already its closest approximation. Domain-boundary note: this is tooling,
not domain/policy code, so §8/§10.3 boundary rules are untouched.

**B. A run-scoped Stage Manifest, emitted at run start, as a data artifact.** Whichever path
launches a run writes `<report_dir>/orchestration/stage_manifest.json`: the resolved plan — every
stage the registry says could run, with `enabled | not_applicable(reason)` resolved from the actual
selectors/topology of *this* run, plus stream, budget, and severity. The Rust wrapper emits it
directly; the bash orchestrator gets it via a subcommand (`rustynet ops emit-stage-manifest ...`) —
precedent already exists, since the bash EXIT trap already shells out to
`ops append-orchestrator-run-to-matrix` (orchestrator.sh ~:8131-8139 *[verified]*).

**C. Everything downstream consumes the manifest, not a copy.**
- The **monitor** renders the Stage Grid, groups, and header math from the manifest found in the
  active/held report dir. This is the key move that makes the fix *possible at all*: the monitor is
  deliberately excluded from the workspace for license/offline reasons (root Cargo.toml:26-31
  *[verified]*), so build-time code sharing is undesirable — but a **run-time data contract**
  requires no shared crate. The hardcoded catalog is demoted to a fallback for pre-manifest report
  dirs, behind a CI equality test against the registry until it can be deleted.
- The **recorder** (stages.tsv / outcome writer) validates every recorded stage name against the
  manifest. An unknown name becomes a loud, visible defect row — not silence. Today's failure mode
  (45% of a real run's outcomes unknown to the UI) becomes structurally impossible.
- The **CSV appender** derives columns from the registry and maps historical rows through the alias
  table.
- **Header math** becomes well-defined for free: `enabled` = manifest-enabled, `completed` = final
  outcomes among manifest-enabled, `not_applicable` = a displayed third state — and because the
  manifest lives in the report dir, a held run's display is pinned to the config that launched it,
  which dissolves the config-reload divergence question (seed finding #6) without a separate
  snapshot mechanism.

**D. A drift gate.** A CI check that (1) asserts monitor-fallback-catalog == registry while the
fallback exists, and (2) greps both orchestrators' sources for recorded stage names absent from the
registry. Drift then fails a gate instead of waiting for a human to notice a 45%-invisible run.

**Migration order:** extract registry from the CSV writer's match tables → Rust wrapper emits
manifest → bash emits via subcommand → monitor consumes with fallback → drift gate → delete
fallback. Each step lands independently and is verifiable by existing runs.

---

## FINDING 2 — The run matrix has two writers and no owner; the interim writer is wrong 94% of the time it disagrees.

- **Severity/Ambition:** High; medium-large design change in `rustynet-cli`, not the monitor.
- **What:** One physical run appends two rows. The bash EXIT trap `orchestrator_cleanup()` calls
  `ops append-orchestrator-run-to-matrix` whenever `run_summary.json` exists (orchestrator.sh
  ~:8131-8139 *[verified]*), producing a row hardcoded as `command_name:
  "live-linux-lab-orchestrator"` with `extra_stage_outcomes: &[]`
  (live_lab_run_matrix.rs:362-368 *[verified]*). The Rust wrapper then appends its own fuller row
  (`command_name: "vm-lab-orchestrate-live-lab"`, sidecar outcomes merged as
  `extra_stage_outcomes`) at vm_lab/mod.rs:7055-7062 *[verified]*. Both funnel through the same
  `append_live_lab_run_matrix_row`, whose append lock (:1757-1845 *[subagent]*) prevents
  interleaving but not duplication; neither writer knows the other exists.
- **Evidence:** Of 465 rows, 123 duplicate groups share identical
  (report_dir, run_started_utc, run_finished_utc). 49 groups disagree on `overall_result`; in
  **46 of 49** the bash-side row is the more optimistic one *[verified — computed directly]*. The
  mechanism is inherent, not a race: the bash row is finalized at bash exit, *before* the mac/win
  sidecar stages have run, and `overall_result()` (live_lab_run_matrix.rs:1647-1661 *[subagent]*)
  can only judge the evidence it was given.
- **Impact:** Every consumer of the matrix (parity, sparklines, CUSUM flake detection, MCP
  `find_untested_work`, the auto-select-next-target key) ingests systematically optimistic
  duplicates. The monitor now papers over it display-side (dedup keyed on that triple,
  run_matrix.rs:413-448 — which keeps the *later* row and is therefore only coincidentally correct,
  because the optimistic row happens to be written first). Nothing protects any other consumer.
- **Approach:** Give the *run*, not the code path, ownership of the row. Cleanest design: the
  appender gains **upsert-by-run-key** semantics (report_dir + run_started_utc as the natural key)
  plus an explicit `row_role: interim | final` column. The bash-trap write becomes an interim
  record (useful for crash visibility — see Finding 3); the outermost supervisor's write is final
  and replaces it. Consumers filter on `final` (or latest-wins, now by contract instead of by
  accident). Alternative — suppressing the bash write when running under the wrapper (env flag) —
  is cheaper but fragile and loses the crash-visibility benefit; I'd argue for upsert.

---

## FINDING 3 — There is no terminal-state taxonomy: jobs, stages, and platform streams can all evaporate without a recorded ending.

- **Severity/Ambition:** High; touches job JSON schema, stages.tsv, CSV vocabulary, and monitor —
  best done as the "status enum" half of the Finding 1 contract.
- **What, three layers:**
  1. **Jobs** know only `running | done | crashed` (+ display-side `idle`); a job JSON claiming
     `running` with a dead PID is filtered from the active list (job_watcher.rs `is_running`
     pid-liveness check; `.retain(JobState::is_running)` ~:196 *[subagent]*) but the JSON itself is
     **never reconciled** — permanent limbo. The seeded real case (a security fail-closed gate
     correctly refusing auto-retry, worker dying, job stuck `running` forever, CSV row never
     written) is exactly this: "correctly blocked, needs a human" is indistinguishable from
     "silently gone". Notably, the repo-wide search for the fail-closed marker string found **no
     emitter in the orchestrator/MCP sources** *[subagent]* — consistent with it living in the
     job-worker layer and with that layer having no terminal state to record its decision in.
  2. **Stages** have an open, inconsistent status vocabulary. Observed in the CSV: `pass`, `fail`,
     `skip`, `skipped`, `not_run`, `na`, `unknown` — with no defined semantics distinguishing
     `not_run` / `na` / `skip`. Even the OS-presence columns speak status dialects:
     `windows_present` holds `not_run`(455)/`na`(5)/`pass`(1) while `macos_present` holds
     `yes`(4)/`pass`(55)/`not_run`(402) — a boolean column that has three vocabularies. *[verified]*
  3. **Streams:** per-node/parallel workers are awaited with a bare `wait $pid`
     (orchestrator.sh ~:2053) with **no stage-level timeout**; on external kill,
     `kill_background_workers` (~:8118-8126) SIGTERM/SIGKILLs without writing outcomes for
     in-flight stages *[subagent]*. So a hung `bootstrap_macos_host` can hold the run (or, under
     kill, vanish without a row) — the seeded finding #4 hypothesis is *plausible-by-construction*;
     I found no conclusion barrier that would prevent it. (I did not reproduce the abandonment
     live; flagged accordingly.)
- **Impact:** The monitor cannot distinguish "still running", "crashed", "abandoned", and "blocked
  pending operator review" — and the most safety-relevant state of the four (a security gate said
  *stop*) is the least visible. Fail-closed behavior deserves fail-*loud* bookkeeping.
- **Approach:** Define one closed status enum in the Finding 1 registry and use it in all three
  layers: stage statuses `pending | running | pass | fail | skipped | not_applicable | timed_out |
  aborted`; job states add `blocked_pending_review` and `aborted`; CSV `overall_result` gains
  `blocked`. Then two enforcement points: (1) a **conclusion barrier** in both orchestrators — the
  summary/manifest-close step writes an explicit `aborted`/`timed_out` outcome for every planned
  stage lacking one before the run may conclude; (2) **monitor-side reconciliation** — a `running`
  job whose PID is dead gets rewritten (or at minimum displayed) as `crashed`, or as
  `blocked_pending_review` when the fail-closed marker artifact is present in the report dir. The
  blocked state should render as its own color/row in Previous Runs — it is the one state that
  *demands* a human.

---

## FINDING 4 — Converge the two orchestrators on the recording contract first, not on the stages.

- **Severity/Ambition:** High ambition, but the insight is that the first step is small.
- **What:** The question "should bash and Rust converge?" is usually framed as "port 8,800 lines of
  bash stages to Rust" — a multi-month cliff nobody jumps. The evidence says the *acute* damage is
  not duplicate stage logic, it's duplicate *bookkeeping*: two CSV writers (Finding 2), two status
  vocabularies (`skip`/`skipped`), two naming dialects leaking into shared columns
  (`membership_init`, `traffic_test_matrix` et al. appear as `first_failed_stage` values in the
  shared matrix *[verified]*). Meanwhile the "hybrid production" `RustOrchestrator` wrapper is
  literally `#[allow(dead_code)]` (vm_lab/mod.rs:6508 *[verified]*) — the Rust pipeline's
  production role is partly aspirational while its vocabulary already pollutes shared data.
- **Approach:** Invert the migration. Step 1: both paths share one **recorder** — manifest +
  stages.tsv + CSV upsert live behind a single `rustynet-cli` subcommand surface that bash calls
  per-stage (it already calls Rust at exit; make it per-stage: `ops record-stage-start/finish`).
  From that moment the two pipelines are indistinguishable to every consumer, and all Finding 1/2/3
  guarantees hold regardless of which side executes a stage. Step 2: port stages incrementally
  behind the now-identical recording, starting with the setup stages the Rust path already
  duplicates. Step 3: registry aliases retire the Rust-dialect names from shared vocabulary until
  the port makes them canonical. This turns "converge someday" into a sequence where every
  increment pays for itself.

---

## FINDING 5 — Security-control coverage is tracked by prose, and the prose has holes. Make coverage machine-checkable.

- **Severity/Ambition:** High (this is the project's stated top priority); medium mechanism cost
  once Finding 1 exists.
- **What (gaps found):** *[subagent pass over SecurityMinimumBar.md cross-checked against the
  orchestrator; individual gaps consistent with the platform-support matrix and catalog greps]*
  - **nas/llm (SecMinBar §6.E)**: zero live-lab stages of any kind; proven only by CI gates.
  - **Secrets-not-in-logs and key custody**: live stages are Linux-only
    (`live_secrets_not_in_logs`, `live_key_custody`); DPAPI/Keychain custody has CSV columns and
    per-OS check stages in the catalogs, but no mac/win equivalent of the live journal-grep
    exists.
  - **blind_exit on Windows**: no live activation stage exists (platform table: "Not yet"); Windows
    has only the synthetic `validate_windows_blind_exit_reversal_denied` audit — i.e. the
    *irreversibility* invariant is protocol-proven, but the role itself has never been live-proven
    on Windows, and nothing marks that asymmetry.
  - **Privileged-boundary argv-only exec**: live coverage lives in an opt-in chaos sub-stage
    (requires the chaos suite flag) — a top-tier control whose only live exercise is skipped by
    default.
- **Impact:** §4 of the operating contract demands "an enforcement point *and* a verification
  method" per control — but nothing today can *list* which SecurityMinimumBar controls have live
  verification, so regressions in coverage (a stage disabled, skipped-by-default, or dropped in a
  refactor) are undetectable except by prose audit.
- **Approach:** Coverage-as-code on top of the Finding 1 registry: each registry entry carries
  `proves: [control-IDs]` (the audit stages already do this informally — "Proves RSA-0009",
  "Proves §6.D.2" — it just isn't data). Add a gate that joins SecurityMinimumBar control IDs
  against (a) registry entries claiming them and (b) recent run-matrix evidence that those stages
  actually executed and passed on each claimed OS. Output: a per-control × per-OS coverage matrix
  with explicit, reviewed exceptions (e.g. "nas/llm: CI-only until M4"). A control silently losing
  its live proof then fails a gate instead of an audit.

---

## FINDING 6 — Timer estimates: the two-tier design is right, but the fallback tier is badly stale and the statistic is wrong for its job.

- **Severity/Ambition:** Medium; small mechanism, real operator-facing noise. (Re-scoped from the
  investigation pass — see Corrections.)
- **What:** The monitor already prefers real P50s from `live_lab_stage_timings.csv` (2,137 records)
  and falls back to `default_stage_secs` only when a stage has **no passing history**
  (app.rs:316-321 → data/timings.rs `load_stage_timings`, pass-rows-only *[verified]*). Residual
  problems: (1) the fallback triggers precisely for stages that have *never passed* — i.e. exactly
  the new mac/win cells an operator is iterating on — and its values are wildly off reality
  (`local_full_gate_suite` real P50 ≈ 7,532s vs fallback 300s; `extended_soak` ≈ 3,471s vs 300s;
  `live_exit_handoff` ≈ 468s vs 300s; `issue_and_distribute_traversal`/`dns_zone` P50 ≈ 68s vs
  60s *[subagent P50s; mechanism verified]*). (2) The pass-only filter starves exactly those
  stages forever if they keep failing at, say, 20 minutes — the estimate stays 300s. (3) P50 is the
  wrong statistic for an "overdue" signal: half of *healthy* runs exceed it by definition.
- **Approach:** Budget = max(fallback, P90-of-all-terminal-outcomes × slack), stored per-stage in
  the Finding 1 manifest so orchestrator watchdogs and monitor display share one number; keep the
  hand-tuned table only as the cold-start floor, and regenerate it periodically *from* the timings
  CSV rather than by hand.

---

## FINDING 7 — Header math: `completed` and `enabled` are answers to different questions, and the held-run display answers them against the wrong config.

- **Severity/Ambition:** Medium; conceptually subsumed by Finding 1, worth naming because it needs
  a vocabulary decision, not a clamp.
- **What:** `enabled` filters the catalog by *current* config; `completed` filters the same catalog
  by *recorded outcome* (pass/fail/skipped), ignoring enablement (ui/stage_grid.rs:87-100
  *[verified]*). Two orthogonal filters over one list — "13/9" is not a bug in either number, it's
  the absence of a shared referent. A regression test already clamps the *bar fill*
  (stage_grid tests *[subagent]*), which is the tell: the display was patched, the semantics
  weren't. Compounding it, `refresh_state` reloads config from disk whenever no job is active
  (app.rs:652-658 *[verified]*), so a held run's denominator can drift under external config edits
  while its outcomes stay frozen.
- **Approach:** Three explicit states from the manifest snapshot of *that run* — ran / planned /
  not-applicable — rendered as `completed/planned` with NA shown separately; the held-run display
  reads the manifest in its report dir, never live config (live config only governs the *next* run
  preview). Previous Runs, Full Stage Matrix, and the CSV adopt the same three-way vocabulary via
  Finding 3's enum.

---

## FINDING 8 — The `area` string is a load-bearing mini-DSL parsed by substring matching in at least two places.

- **Severity/Ambition:** Small-medium bug class, cheap to kill while doing Finding 1.
- **What:** `wants_macos()`/`wants_windows()` gate stage display on `area.contains("macos"/"windows")`
  (monitor src/config.rs:113-126 *[verified]*), and target auto-selection derives **both OS and
  role** from substring matches on the same freeform label (app.rs:1647-1665: `contains("blind")`,
  `contains("relay")`, `contains("exit")`… *[verified]*). A label like "windows-adjacent linux
  relay check" silently changes what's displayed and what's targeted; `exit_platform`-style
  structured fields already exist and are also consulted, so the string parse is a redundant,
  weaker channel.
- **Approach:** Make `area` a display label with zero semantics. Whatever writes the config (the
  `a` auto-select already knows role+OS structurally) writes structured fields; gating and
  targeting read only those. If freeform entry must survive, parse it once at write time into the
  structured fields where a human can see and correct the interpretation.

---

## FINDING 9 — `disabled_stages` is write-only configuration: never validated, never pruned.

- **Severity/Ambition:** Small, but it compounds Finding 1's drift.
- **What:** Config load is bare TOML deserialization (monitor src/config.rs `load()` *[subagent;
  consistent with the file]*); no check that an entry names a real stage, no cleanup path. With a
  drifting catalog this decays silently in both directions: an entry can disable nothing (stage
  renamed — e.g. anything referencing `distribute_windows_bundles` semantics), or linger for
  stages that no longer exist, and the operator's Space-toggles accumulate forever.
- **Approach:** Validate against the registry on load; warn-and-prune unknown entries (surfacing
  the prune in the UI once). Trivial once Finding 1 exists; not worth bespoke machinery before it.

---

## FINDING 10 — Evidence is a convention, not a contract.

- **Severity/Ambition:** Medium; large payoff for triage automation (the DeepSeek pipeline and
  `grep_report` both feed on artifacts).
- **What:** A decent primitive exists (`stage_worker_write_artifact`, orchestrator.sh ~:1877-1895)
  but usage is per-stage ad hoc; forensics bundles exist only for cross-network stages (~:1362,
  :1408); the failure digest is global-per-run, not per-failed-stage (~:8097) *[subagent]*. The CSV
  bears this out: `evidence_bundle_path` is 458/465 "non-empty" but the values include `na`,
  absolute *and* repo-relative paths, one directory shared verbatim by 44 different rows, and
  `failure_digest_path` points sometimes at `failure_digest.md`, sometimes at
  `orchestrate_result.json` *[verified]*. "Non-empty" is doing a lot of unearned work.
- **Approach:** The registry (Finding 1) declares each stage's expected evidence set; the shared
  recorder (Finding 4) enforces presence at stage close and writes normalized repo-relative paths;
  failed stages get a per-stage digest the global digest merely indexes. This is what makes
  automated triage trustworthy instead of best-effort.

---

## Corrections, caveats, and what could not be cross-verified

- **Corrected subagent error (important):** one investigation pass reported "Windows absent from
  all runs; `windows_stage_*` columns never populated." **False** — verified directly:
  `windows_stage_bootstrap` has 50 pass / 5 fail / 3 skip rows; `windows_enrollment_replay` has 34
  populated rows including a real `fail`. The agent had generalized from the *node-identity*
  columns (`windows_*_target` etc.), 18 of which genuinely are empty in all rows. The 23
  all-empty columns are real; the conclusion drawn from them was not. Any figure above marked
  *[verified]* was computed after this correction.
- **Not independently reproduced:** the live abandonment of a hung platform stream (Finding 3,
  layer 3) is argued from the absence of any conclusion barrier in the code, not from a reproduced
  hang; and the exact emitter of the fail-closed "DO NOT retry" hint was not located (the string
  is absent from orchestrator/MCP sources searched), so its layer attribution is inference.
- **DeepSeek:** unreachable in this environment (no API key resolvable). Per instructions I did not
  attempt workarounds. Every claim above therefore rests on direct inspection (mine or a read-only
  subagent's, as marked) with no external DeepSeek cross-check. Subagent-only line numbers in the
  ~8,800-line bash script (e.g. :2053, :8118-8126, :1877-1895) are the most likely places for
  small citation drift; the surrounding claims were each corroborated by at least one directly
  verified fact.
- **Seeded fixes confirmed present** in the working tree (not re-reported as findings):
  `lab_is_actively_running()` spinner gate, recent-runs display dedup
  (run_matrix.rs:413-448), and the VM activity column + parity glyph (ui/vm_panel.rs:26, :45,
  :118, :151) — the earlier pass that "could not find" the VM panel fix was looking in app.rs.
