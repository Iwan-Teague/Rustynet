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
