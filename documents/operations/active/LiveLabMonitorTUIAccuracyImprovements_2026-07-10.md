# Live-Lab Monitor TUI Accuracy Improvements — 2026-07-10

**Status:** Implemented; scoped tests green.
**Scope:** `rustynet-lab-monitor` data freshness, stage/test counts, resume/rerun correctness, VM metadata, and fail-loud source handling.

## Outcome

The monitor no longer presents locally inferred data as authoritative for an active or held run. Run facts come from the run-scoped manifest, live recorder, final result, inventory, and run-matrix schema. Missing or malformed run evidence is visible as waiting/error state.

## Changes

1. **Live recorder wins while a run is active.**
   - `state/stages.tsv` is always preferred for an active invocation.
   - `orchestrate_result.json` remains the completed-run authority and legacy fallback.
   - Fixes reused report directories showing an earlier invocation's final JSON while a new invocation runs.

2. **Resume/run-only manifests describe the current invocation.**
   - Rust `--node` manifest emission now atomically replaces the prior manifest in a reused report directory.
   - The TUI rereads the manifest every refresh, even when the report directory is unchanged.

3. **No active/held-run catalog substitution.**
   - Missing manifest: `WAITING FOR MANIFEST`.
   - Malformed/empty manifest: visible `DATA ERROR`.
   - Stage Grid stays empty until authoritative plan data exists.
   - The built-in catalog remains only as an explicitly labelled `LEGACY PREVIEW` when no report has been selected; it is never shown as live/held run evidence.

4. **Closed stage-status handling.**
   - One monitor-side parser owns `pending`, `running`, `pass`, `fail`, `skipped`, `not_run`, `reused`, `not_applicable`, `timed_out`, and `aborted` plus historical aliases.
   - Every terminal state advances active-stage inference.
   - Reused, failed/aborted/timed-out, skipped/not-applicable, not-run, pending, and unknown states now render distinctly.

5. **Truthful counts.**
   - Header separates current-run settled stages, current-run tests, and history-wide coverage.
   - Manifest schema v2 emits `counts_as_check`; current-run test totals are fetched from this field.
   - Schema-v1 manifests show `n/a` rather than guessing.
   - Synthetic stages are excluded from run groups/counts.
   - Pruned historical reports show CSV-only counts labelled `plan unavailable`; removed fabricated `PRE_STAGE_COUNT = 5` and bootstrap classification guesses.

6. **Visible freshness and errors.**
   - Header shows plan source, outcome source, and source age.
   - Source-load failures appear in the header/status bar instead of silently retaining stale data.

7. **VM data tightened.**
   - Host `utmctl list` is the primary VM membership/power source; every UTM VM is shown even when absent from lab inventory.
   - Inventory enriches matching host VMs with lab alias, IP, and platform; unmatched host VMs are visibly marked `host-only` with unknown metadata rather than dropped or guessed.
   - Inventory-only bundles missing from the host registry remain visible with power state `missing`.
   - Platform comes from inventory `platform`/`os`, never alias/username guessing.
   - SSH probe cadence is 5 seconds during an active lab and 30 seconds while idle.
   - Removed cryptic `P`, `S`, and `E` columns and unspaced icons. Full-width columns now say `POWER`, `ONLINE/SSH`, `LAB READY`, `RUN USE`, `ROLE`, `IP`, and `EVIDENCE`, using words such as `ON`, `READY`, `CURRENT`, and `PROVEN`.
   - Panel title shows fetched totals for all VMs, SSH-online VMs, lab-ready VMs, and current-run VMs. Removed the long duplicate `selected:` readiness text; row columns remain the status source.
   - `LAB READY` is fetched in a non-blocking background task every 60 seconds through canonical `vm-lab-preflight`; it uses the live-lab SSH identity when present and verifies guest access, `git`, `cargo`, `rustc`, `rustup`, passwordless privilege, and at least 1 GiB free disk. Fast UTM/TCP probing remains independent.
   - Canonical preflight now emits equivalent native checks for POSIX and PowerShell guests. POSIX checks include standard Rust/Homebrew paths; Windows checks use `Get-Command`, administrator-token detection, and system-drive free space.
   - `RUN USE` distinguishes `CURRENT`, `PREVIOUS`, and unused (`—`). `ROLE` uses only emitted current-run node assignments, structured selectors for legacy active runs, or authoritative previous-run matrix assignments. Planned/manual config never appears as an actual role.
   - Evidence is now a named word (`PROVEN`, `FAILED`, `FLAKY`, `UNPROVEN`) and appears only when the VM has an actual run-backed role.

8. **Human-readable held/live source state.**
   - Active recorder data displays `LIVE TSV · <age>`.
   - Completed evidence displays `PREVIOUS RUN · <human age>` (for example `22h ago`), not a large raw seconds counter that looks like a stuck realtime feed.

## Verification

- `cargo test --manifest-path crates/rustynet-lab-monitor/Cargo.toml` — **186 passed**.
- `cargo clippy --manifest-path crates/rustynet-lab-monitor/Cargo.toml --all-targets -- -D warnings` — **passed**.
- `cargo check -p rustynet-cli` — **passed** after cross-platform canonical preflight changes.
- `cargo clippy -p rustynet-cli --bin rustynet-cli -- -D warnings` — **passed**.
- `cargo test -p rustynet-cli --bin rustynet-cli vm_lab_preflight_builds_native_tool_checks_for_posix_and_windows` — **passed**.
- Live canonical preflight across all four currently SSH-online inventoried VMs produced truthful mixed state: `debian-headless-2` and `macos-utm-1` **ready**; `fedora-utm-1` **blocked** by missing passwordless privilege; `rocky-utm-1` **blocked** by missing passwordless privilege plus missing `git`/Rust toolchain. This confirms `ONLINE/SSH` and `LAB READY` are independent fetched facts.
- `cargo test -p rustynet-cli --bin rustynet-cli live_lab_stage_manifest::tests` — **12 passed**.
- Headless snapshot verified against the latest real report: `PREVIOUS RUN · 22h ago`, manifest-derived 14-stage plan, schema-v1 test count shown as `n/a`, and history-wide coverage `97/164`.
- Unsandboxed host snapshot fetched `utmctl list` and rendered all **11/11** UTM VMs; four host-only VMs absent from inventory remained visible. Idle snapshot showed only matrix-backed previous-run roles; unused VMs showed `run=— role=—`.

## Remaining boundary

The monitor polls stage state every 2 seconds. This is near-real-time, not event-stream real-time. File watching can reduce latency later, but polling remains the correctness fallback. UTM discovery requires host app access; a sandbox that denies UTM returns a visible `VM discovery` data error instead of silently showing an incomplete inventory list.

## Follow-up: input robustness + first-class gating (2026-07-13)

A dedicated input-robustness pass hardened every state-file parser to degrade gracefully (never panic, never false-green/incoherent) on corrupt, missing, empty, stale, partially-written, and concurrently-updated input, and made the workspace-excluded crate a first-class gated CI target. Full detail (the specific `?`-propagation/panic regressions fixed, the adversarial-input test coverage, and the `scripts/ci/lab_monitor_gates.sh` + `cross-platform-ci.yml` wiring) is in `LabMonitorTUIDesign_2026-06-29.md` §11 / §11.1 and the crate `README.md`.

## Follow-up: operator-reported accuracy/freshness audit (2026-07-16)

Triggered by an operator report ("a lot of the info is not updating properly and I'm not sure if info is accurately displayed"). Full chain trace (source → parser → app state → widget) for every panel, verified against a real, concurrently-running live-lab orchestrator (`twohop2`/`twohop3-run-*`) rather than static reading alone. The `scripts/ci/lab_monitor_gates.sh` + `cross-platform-ci.yml` wiring from the prior pass was re-verified and found genuinely intact (see workspace-exclusion verdict below) — the bugs found below are logical/runtime defects that fmt/clippy/build gates cannot catch on their own; only per-bug regression tests close that gap.

### Fixed this pass

1. **Crash detection blind spot for externally-launched jobs (highest severity — class 3, silently not-crashed).** `data/job_watcher.rs` / `app.rs`: `last_run_crashed` only ever consulted `job_state_by_id` (a lookup in `state/{deepseek-mcp,lab-monitor}-jobs/*.json`). A run launched outside this monitor — raw CLI, another session, **the normal way the live-lab orchestrator is actually started** — never gets a JSON record there at all, so this check unconditionally returned "not crashed" for the entire class of job the monitor exists to observe: a killed or crashed externally-launched run just read as plain `IDLE`. Fixed by adding `job_watcher::has_completion_marker` (the report dir's own `orchestrate_result.json` / `report_state.json.run_complete`) as the authoritative signal when no job-state JSON exists, extracted into a directly-testable `job_ended_crashed(repo_root, prev_job, report_dir)`. 4 new hermetic unit tests in `job_watcher.rs` (JSON-tracked and externally-launched, crashed and clean-finish, in all 4 combinations).
2. **`stages.tsv` column-shift on the active/running row (rustynet-cli, not this crate — the actual root cause).** The recorder's documented 8-column contract (`crates/rustynet-cli/src/live_lab_stage_recorder.rs`) puts `log_path` at column 4 and `summary` at column 5. Its `record_stage_finish` call site passes them correctly; its `record_stage_start` call site (`vm_lab/orchestrator/evidence.rs:395-402`) had them **swapped** — every `running` row wrote an empty `log_path` and put the real per-stage log path into the `summary` column instead. This is genuinely upstream of the monitor: `stage_reader.rs`'s positional parser was reading exactly the columns the recorder's own contract promises; the bug was in what the orchestrator wrote, not how the monitor read it. Fixed the two swapped arguments at the call site + added `stage_started_writes_log_path_not_summary_in_the_running_row` in `evidence.rs`'s own test module. This is what made the Stage Detail overlay show garbage (a raw log path) in the SUMMARY field for whichever stage was actively running.
3. **Uncentralized status parser regression (class 3-adjacent — real failures render neutral, not red).** `ui/stage_detail_overlay.rs`'s `status_color`/`status_symbol` re-implemented their own literal `"pass"/"fail"/"running"/"skipped"` match instead of dispatching through the crate's one canonical `StageStatus::parse` (via `stage_grid::cell_for_status`, now made `pub(crate)` and reused). Real terminal statuses the orchestrator actually emits — `aborted`, `timed_out`, `reused` — fell through to the neutral default (white, `[░░]`) in the one view meant to explain a stage's outcome in detail, regressing the 2026-07-10 doc's item 4 claim ("one parser owns pending/running/pass/fail/... plus historical aliases"). Fixed by delegating; added tests pinning `aborted`/`timed_out` → red `[✗✗]`, `reused` → cyan `[↺↺]`, and an unrecognized status never rendering green.
4. **Log panel silently stops following a new externally-launched run (class 3 — stale-as-current).** `app.rs`'s `refresh_state`: the `is_new_job` branch (what actually fires when a job is discovered for the first time — overwhelmingly an externally-launched run, since a monitor-launched run's `handle_start` already reset state at launch and sets `active_job` optimistically) never reset `log_scroll`/`log_scroll_anchor`. An operator who had scrolled up while reading a prior/idle-held run kept that exact offset once a brand-new run started, so the log panel silently stopped auto-following the new run's tail — matching the operator's complaint directly. Fixed by resetting both fields in the `is_new_job` branch and in `clear_stale_active_run_state` (the job-goes-idle transition, the smaller sibling gap). New `#[tokio::test]` in `app.rs` (built to be immune to the real concurrent orchestrator on this host — see note below).
5. **ETA never flips to "overdue" (class 3 — stale-as-current).** `app.rs`'s `estimated_group_remaining_secs` floored the active stage's remaining-time term at `.max(60)` — once a stage ran past its own estimated budget, the label stayed pinned at a plausible "~1m left" forever, whether it was 1 second or 20+ minutes overdue. Added `active_stage_overdue_secs()` + a `group_contains_active_stage` check so `stage_timer_labels()` renders an explicit `OVERDUE +Xm` once truly over budget, instead of a shrinking-then-flat-lined number that reads as healthy.
6. **`nas`/`llm` parity cells permanently indistinguishable from "never tested" (class 3).** `data/run_matrix.rs`: `nas`/`llm` (service-hosting roles, mid-rollout per the roadmap) have no column in `live_lab_run_matrix.csv` yet. `load_parity_matrix` collapsed "column doesn't exist in the schema at all" into the same `Unproven` bucket as "column exists, zero decisive rows yet" — a real schema-lag looked identical to "genuinely never run." Added `ParityState::NotInSchema` (rendered as magenta `n/a`/`?`/`N/A` distinctly from gray `Unproven` in `parity_panel.rs`/`stage_matrix_panel.rs`/`vm_panel.rs`), gated on the CSV having a genuinely non-empty, readable header row so a corrupt/missing file still degrades to the pre-existing lenient all-`Unproven` behavior (preserves the two existing adversarial-input tests for that case) rather than a wall of misleading `NotInSchema`.
7. **VM lab-readiness stuck on an unexplained generic message when `rustynet-cli` lacks `--features vm-lab` (high severity, independently reproduced live in this environment).** `data/vm_prober.rs`'s `probe_lab_readiness` shells out to `rustynet-cli ops vm-lab-preflight`. The entire `ops vm-lab-*` surface compiles only under the default-OFF `vm-lab` feature (RNQ-17); a binary built without it (confirmed live: `strings target/debug/rustynet-cli | grep -c vm-lab-preflight` → 0) just prints the generic top-level command list and exits 0 — no error, no JSON, nothing mentioning "vm-lab" at all. This previously fell into the same generic "preflight returned unreadable data" as any other parse failure, which can never resolve on its own no matter how long the monitor polls, with no hint at the actual actionable cause. Added `fallback_unreadable_preflight_detail`, which distinguishes this exact no-such-command shape (stdout never mentions "vm-lab" anywhere) from genuine garbled output, and now surfaces "rustynet-cli was built without --features vm-lab ... rebuild with: cargo build -p rustynet-cli --features vm-lab" directly in the LAB READY column's detail. 2 new tests using the real captured stdout shape.
8. **Reading the frozen legacy run-matrix ledger instead of the active per-engine one (highest severity — a near-term guarantee of the exact "info stopped updating" complaint, caught mid-migration).** Discovered via a concurrent, in-repo docs update surfaced during this pass: `documents/operations/LiveLabRunMatrix.md` and `crates/rustynet-cli/src/live_lab_run_matrix.rs` already define `documents/operations/live_lab_node_run_matrix.csv` as the Rust `--node` engine's **ACTIVE** ledger (`append_live_lab_run_matrix_row` routes to it automatically per run), with the old `documents/operations/live_lab_run_matrix.csv` now a **FROZEN ARCHIVE** the `--node` engine never appends to again — precisely because a blended file previously made the legacy archive's 52 historical `two_hop` passes look like `--node`-engine evidence, when that engine has never once passed it. `run_matrix.rs` (Parity Matrix / Prev Runs / Stage Matrix's sole data source) was hardcoded to the legacy path in 6 places. At the time of this review the new file did not yet exist on disk and the legacy file was still being actively appended (confirmed: a fresh row landed within 30 seconds of checking) — so this was not yet a live bug — but the moment the migration completes, every panel backed by this file would silently keep reading a ledger nothing writes to anymore, without any error or stale-indicator, reproducing the operator's exact complaint. Fixed proactively: `run_matrix_csv_path()` now prefers the node ledger whenever it exists on disk, falling back to the legacy path otherwise (so behavior is unchanged today, correct the moment the migration lands). 2 new tests (`node_ledger_is_preferred_over_the_legacy_ledger_when_both_exist`, `legacy_ledger_is_still_used_when_no_node_ledger_exists`).

### Confirmed NOT regressions (verified, not assumed)

Extensive re-verification this pass found these prior claims/hypotheses did **not** hold as bugs, and are recorded so a future pass doesn't re-litigate them: `vm_prober.rs` uses a real TCP connect (not `ssh`) for SSH reachability, which is fine on this host because the monitor runs directly under a shell, not the sandboxed Claude-Desktop MCP wrapper that macOS Local Network Privacy actually blocks (see `CLAUDE.md` §12.3.1 — a different process than this TUI); the 5s/30s VM-probe throttle is wired correctly (no inverted comparison); active-stage monotonicity and "columns not cleared between frames" (prior fixed bugs) both still hold under direct code trace; `run_matrix.rs`'s CSV columns are resolved by header name everywhere, never a hardcoded numeric index; the PROVEN/FLAKY classifier is a CUSUM-based recent-history model (not the simpler "latest row" rule the design doc describes — a doc-accuracy gap, not a behavior bug, corrected in `LabMonitorTUIDesign_2026-06-29.md` below); role/platform enrichment correctly matches `controller.utm_name`, not alias-vs-name equality.

### Recommended, not implemented (out of scope for this pass — flagged for a follow-up)

- **PID-reuse hardening** in `job_watcher::pid_is_alive` (`nix::kill` alone can't distinguish a live process from an unrelated one that reused the same PID after the original died) — needs a process start-time comparison, which has no cheap cross-platform (macOS + Linux) primitive in this crate's current dependency set; a real but narrow-window risk, worth a dedicated design pass rather than a quick patch.
- **Malformed-vs-absent CSV cell diagnostics** in `run_matrix.rs` (`decisive_history`/`is_decisive` currently treat any unrecognized non-empty token identically to a legitimate blank) — would need a distinct "unrecognized token" counter surfaced somewhere, not just silently folded into "no data."
- **Header "data source age" label clarity**: the header's `· 11m ago` can be misread as "the monitor hasn't refreshed in 11 minutes" when it actually means "the active stage has been running/the source file has been unchanged for 11 minutes" (a legitimately long single stage, not staleness). Cosmetic/labeling only — the underlying data is fresh every 2s tick.
- **`live_ips[0]` vs `ssh_target`** in `app.rs`'s `load_inventory_vms`: currently sources display/probe IP only from the static `ssh_target` inventory field, not the live-refreshed `live_ips` array. Fail-safe today (a stale IP just shows correctly as offline), but worth preferring `live_ips[0]` when present.
- **Duplicate UTM VM display names**: two distinct UUIDs can share a display name (confirmed live: two real "Windows XP Harness" guests on this host); harmless today since neither matches an inventory entry, but `VmStatus` doesn't carry `uuid`, so a future duplicate-named *registered* VM would be indistinguishable in the panel.

### Note on test hermeticity

Several new regression tests in this pass had to be built to explicitly avoid `App::refresh_state()`'s real, system-wide `ps`-based job discovery, which is genuinely (and correctly) sensitive to **any** real orchestrator process running anywhere on the host — confirmed firsthand when a live, unrelated `twohop3-run-*` orchestration started mid-investigation and made a naive test flaky. Where the fix under test was reachable as a small pure function (`job_ended_crashed`, `fallback_unreadable_preflight_detail`), tests call it directly; where an `App`-level integration test was the only reasonable shape (`log_scroll` reset), the fixture's `report_state.json.created_at_unix` is set far in the future so it deterministically outranks any real concurrent process in the "most recent job wins" sort.

### Verdict: workspace-exclusion gating gap

The root Cargo.toml exclusion is **not** the enabler of these bugs. `scripts/ci/lab_monitor_gates.sh` and its `cross-platform-ci.yml` wiring (macOS + Debian legs, no `paths`/`paths-ignore` filter narrowing the trigger) are genuinely present, genuinely run fmt/clippy/check/test on every push and PR, and were re-verified working end-to-end this pass. The real gap is that **fmt/clippy/build gates cannot catch logical/runtime accuracy defects** — every bug found and fixed in this pass (crash misclassification, a column-shift, an uncentralized status match, an unreset scroll offset, a floored ETA, a collapsed parity state, an underdiagnosed CLI-feature gap) compiled cleanly and passed clippy before it was fixed. The actual, actionable gating improvement is **regression-test density on exactly these properties** (freshness-on-tick, reset-on-new-run, unknown-never-renders-healthy, status-parser centralization) — which this pass adds 15 new tests toward — not a change to the exclusion or its CI wiring, both of which are working as designed.

## OPEN TODO — point the monitor at the `--node` run matrix only (2026-07-16)

**Done**, landed in two steps (see item 8 above for the first). `run_matrix.rs`'s
6 production read sites first resolved through `run_matrix_csv_path`, which
preferred `documents/operations/live_lab_node_run_matrix.csv` when present and
fell back to the legacy `documents/operations/live_lab_run_matrix.csv`
otherwise. That fallback has since been **removed**: the node ledger landed on
`main` (`b8304a1`), making the fallback branch unreachable on any current
checkout and, per this doc's own "unknown/stale rendered as current" rule, a
latent hazard if it ever *did* fire (a stale/pre-migration checkout silently
rendering the frozen archive as if it were current). `run_matrix_csv_path` now
returns `Option<PathBuf>` — `Some` only when the node ledger exists, `None`
otherwise, with **no** legacy path in the function at all. Every loader treats
`None` exactly as it already treated "file doesn't exist" — its existing
explicit empty/`n/a` default — never a read of the archive. Pinned by
`node_ledger_is_preferred_over_the_legacy_ledger_when_both_exist` (kept
unchanged — the node ledger still wins whenever it exists) and the new
`node_ledger_absent_returns_the_missing_default_never_the_legacy_archive`
(writes a decisive `pass` into the legacy file specifically so the test fails
loudly if a fallback is ever reintroduced). Every other test fixture in the
module was repointed from the legacy filename to the node-ledger filename so
they keep exercising the real parsing code instead of silently short-circuiting
on the now-permanently-absent legacy read.
