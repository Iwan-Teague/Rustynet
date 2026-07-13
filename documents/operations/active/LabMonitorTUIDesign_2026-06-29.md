# Rustynet Lab Monitor TUI — Design Document

**Status:** implemented; accuracy hardening tracked in [LiveLabMonitorTUIAccuracyImprovements_2026-07-10.md](LiveLabMonitorTUIAccuracyImprovements_2026-07-10.md)
**Purpose:** Terminal UI for observing, controlling, and understanding the live-lab loop in real time — the GUI for the parity campaign.

---

## 1. What It Is

`rustynet-lab-monitor` is a Rust TUI application (binary of the same name, new workspace crate `crates/rustynet-lab-monitor/`) that gives a live, interactive view of the Rustynet live-lab loop. It reads the same state files that the orchestrator and MCP server write, and drives the same orchestrator binary that `deepseek_lab_run` uses. No MCP dependency at runtime.

Design aesthetic: terminal-native, pixelated block grid, retro-terminal color palette. Reference: `lazygit`, `bottom (btm)`, Claude CLI box headers, OpenCode pane layout. Every interactive element is keyboard-driven; mouse support optional.

---

## 2. Tech Stack

| Component | Crate | Version |
|-----------|-------|---------|
| TUI framework | `ratatui` | `0.28` |
| Terminal backend | `crossterm` | `0.28` |
| Async runtime | `tokio` | `1` (full) |
| JSON | `serde` + `serde_json` | `1` |
| CSV | `csv` | `1.3` |
| File watching | `notify` | `6` |
| Process control | `nix` (Unix) | `0.28` |
| Config | `toml` | `0.8` |
| Time | `chrono` | `0.4` |
| Logging | `tracing` + `tracing-subscriber` | `0.3` |

All already present in the workspace or trivially addable. Add `ratatui`, `notify`, `nix`, `toml` as new deps in the new crate's `Cargo.toml` only (not workspace-wide).

---

## 3. Screen Layout (120×40 reference terminal)

```
╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║  RUSTYNET LAB MONITOR   JOB: labrun-1782633562934-61854-0   AREA: macOS anchor   STATUS: ◉ RUNNING   ETA: ~18m left    ║
╠══════════════════════════════════╦══════════════════════════╦═══════════════════════════════════════════════════════════╣
║  STAGE GRID                      ║  VM STATUS               ║  PARITY MATRIX  (role × OS)                              ║
║                                  ║                          ║                                                           ║
║  SETUP  ████████████████  16/16  ║  ● deb-1  .200  READY   ║  ROLE        LINUX   macOS   WIN                         ║
║  [██][██][██][██][██][██][██]   ║  ● deb-2  .201  READY   ║  client      [ ██ ]  [ ██ ]  [ ░░ ]                       ║
║  [██][██][██][██][██][██][██]   ║  ● deb-3  .202  READY   ║  admin       [ ██ ]  [ ██ ]  [ ░░ ]                       ║
║  [██]                            ║  ● deb-4  .203  READY   ║  exit        [ ██ ]  [ ░░ ]  [ ░░ ]                       ║
║                                  ║  ● deb-5  .204  READY   ║  blind_exit  [ ██ ]  [ ░░ ]  [ ░░ ]                       ║
║  MAC ROLES  ░░░░░░░░░░  4/8     ║  ◉ macos  .210  ACTIVE  ║  relay       [ ██ ]  [ ██ ]  [ ░░ ]                       ║
║  [██][██][██][██][▓▓][░░][░░]  ║  ○ win-1  .211  OFFLINE ║  anchor      [ ██ ]  [ ██ ]  [ ░░ ]                       ║
║  [░░]                            ║                          ║  nas         [ ░░ ]  [ ░░ ]  [ ░░ ]                       ║
║                                  ╠══════════════════════════╣  llm         [ ░░ ]  [ ░░ ]  [ ░░ ]                       ║
║  SKIPPED  (7 stages)             ║  LOOP STATUS             ║                                                           ║
║  [  ][  ][  ][  ][  ][  ][  ]  ║  Cycle:  4 of ∞          ║  [ ██ ] PROVEN   [ ░░ ] UNPROVEN                          ║
║                                  ║  Area:   macOS anchor    ║  [ ▓▓ ] RUNNING  [    ] SKIPPED                          ║
║                                  ║  Flags:  skip_linux=YES  ║  [ ✗✗ ] FAILED                                           ║
╠══════════════════════════════════╩══════════════════════════╩═══════════════════════════════════════════════════════════╣
║  ACTIVE ▸ validate_macos_anchor_bundle_pull   [████████████████████░░░░░░░░░░]  22/35  ~4m remaining                   ║
╠══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╣
║  LOG ─ validate_macos_anchor_bundle_pull.log (tail)                                                                    ║
║  14:23:01  PASS  loopback byte-for-byte verified against reference                                                      ║
║  14:23:02  PASS  token gate: random token → 401 Unauthorized                                                            ║
║  14:23:03  PASS  LAN refused: 192.168.0.210:51822 → connection refused                                                 ║
║  14:23:04  INFO  checking secrets hygiene in bundle-pull response headers...                                            ║
║  14:23:05  PASS  no key material in response; content-type: application/octet-stream                                    ║
╠══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╣
║  Tab:panel   ^S:start/stop   ^L:logs   ^P:parity   ^V:vms   ^J:jobs   ^C:config   ^R:refresh   ?:help   q:quit         ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
```

---

## 4. Visual Language

### Stage cells
Each completed/pending stage = a 4-char colored block rendered as a text span:

| Symbol | Color | Meaning |
|--------|-------|---------|
| `[██]` | Green (bright) | Pass |
| `[✗✗]` | Red (bright) | Fail |
| `[▓▓]` | Yellow (blinking optional) | Active / in-progress |
| `[░░]` | Dark grey | Pending (not yet run) |
| `[  ]` | Grey (dim) | Skipped |

Cells wrap at a configurable column width (default: fill panel width). No borders between cells — tight grid, one space between columns.

### Parity matrix cells
Same color/symbol encoding but 6 chars wide `[ ██ ]` with label padding.

### Progress bars
Use Unicode block fill: `█` (full), `▓` (⅔), `░` (⅓), space (empty). Render as a simple string — no ratatui Gauge widget, to preserve the pixel aesthetic.

### Color palette
- Background: terminal default (transparent)
- Borders: `DarkGray`
- Active accent: `Cyan` (header, active stage name)
- Pass: `Green`
- Fail: `Red`
- Running: `Yellow`
- Dim: `DarkGray`
- Text: `White` (primary), `Gray` (secondary)

---

## 5. Panels and Keyboard Map

### Panels (Tab to cycle focus)
| Panel | Focus key | Description |
|-------|-----------|-------------|
| Stage Grid | `1` / Tab | Block grid of all stage outcomes for the current job |
| VM Status | `2` / `^V` | Per-VM power, SSH-online, live-lab readiness, run use, actual role, IP, and evidence |
| Parity Matrix | `3` / `^P` | role × OS proven-cell grid drawn from run-matrix CSV |
| Log Viewer | `4` / `^L` | Scrollable tail of the active-stage log file |
| Jobs Browser | `5` / `^J` | All `labrun-*` records, select to view history |
| Config | `6` / `^C` | Edit area, VM slots, flags before launching |

### Keyboard shortcuts
| Key | Action |
|-----|--------|
| `^S` | Start (if no job running) / Stop (confirmation prompt) running job |
| `^R` | Force refresh now (VM probe + state reload) |
| `?` | Help overlay (all bindings) |
| `q` / `^Q` | Quit |
| `↑↓` | Scroll focused panel |
| `Enter` | In jobs browser: select job to view |
| `Esc` | Close overlay / deselect |
| `r` | In jobs browser: refresh job list |

### Start/Stop mechanism
**Start:** reads config panel values → exec `rustynet ops vm-lab-orchestrate-live-lab <args>` via `tokio::process::Command` with own process group → record pgid in `state/monitor-launch.json`. Checks for a running singleton (reads `state/deepseek-mcp-jobs/*.json`) before spawning. Asks for confirmation.

**Stop:** reads pgid from job state JSON → `nix::sys::signal::killpg(pgid, SIGTERM)` → updates display. Asks for confirmation. Does NOT update the job state JSON (the MCP server or reconcile handles that).

---

## 6. Data Sources

### 6.1 Running job state
`state/deepseek-mcp-jobs/{job_id}.json`
- Fields: `job_id`, `state` (`running`|`done`|`crashed`), `pid`, `started_unix`, `area`, `report_dir`
- Poll: every 2s. Watch with `notify` for inotify/kqueue events.

### 6.2 Stage outcomes (current run)
`<report_dir>/state/stages.tsv` + `<report_dir>/orchestration/orchestrate_result.json`
- Active invocation: `stages.tsv` is authoritative and polled every 2 seconds; its `running` row names the active stage directly.
- Completed invocation: final JSON owns the verdict; TSV is crash-recovery fallback.
- Closed statuses: `pending | running | pass | fail | skipped | not_run | reused | not_applicable | timed_out | aborted`.
- Active/held plan: `stage_manifest.json`; missing → `WAITING FOR MANIFEST`, malformed → `DATA ERROR`. No local catalog substitution.
- Log/pipeline inference remains only for legacy pre-recorder reports.

### 6.3 Stage log (active stage)
`state/deepseek-lab-{job_id}/logs/{stage_name}.log`
- Tail last N lines for the log panel. Watch for appends.

### 6.4 Stage timings (ETA)
`documents/operations/live_lab_stage_timings.csv`
- Columns: `timestamp_utc, git_commit, git_dirty, stage, scope, duration_secs, outcome`
- On startup, load all `pass` rows, compute P50 `duration_secs` per `stage` name.
- ETA = sum of P50 for each stage in `outcomes[]` whose status is still `"pending"` (not yet in outcomes, or `status == ""`)
- Update ETA as stages complete and remaining set shrinks.

### 6.5 Parity matrix
`documents/operations/live_lab_run_matrix.csv`
- 150+ columns. Key columns: `overall_result`, `macos_present`, `windows_present`, and per-role-per-OS columns e.g. `macos_stage_anchor` (`pass`|`fail`|`not_run`|`na`).
- Load last 200 rows on startup. For each role × OS cell, find the most recent row where `overall_result = "pass"` and the role-OS stage column = `"pass"` → mark PROVEN.
- Refresh: on any new row (file watcher).

### 6.6 VM status
Fetch the complete host VM registry with `utmctl list`, then enrich matches from `documents/operations/active/vm_lab_inventory.json`.
- Every host UTM VM renders, including VMs absent from inventory (`host-only`).
- Inventory-only UTM records absent from the host registry render as `missing`.
- UTM list status supplies `started`/`stopped` power state.
- SSH reachability: TCP connect to port 22, 2s timeout.
- Poll: every 5s during an active run, every 30s while idle, or on manual refresh.
- Live-lab readiness: non-blocking canonical `vm-lab-preflight` every 60s for SSH-online inventoried VMs, using the lab SSH identity when present. Required facts are authenticated guest execution, `git`, `cargo`, `rustc`, `rustup`, passwordless privilege, and at least 1 GiB free disk.
- Display columns use full labels and words: `VM`, `OS`, `POWER`, `ONLINE/SSH`, `LAB READY`, `RUN USE`, `ROLE`, `IP`, `EVIDENCE`. No icon-only status columns.
- `RUN USE` is `CURRENT`, `PREVIOUS`, or `—`. `ROLE` is populated only from actual run assignment evidence: current manifest topology, structured selectors for an active legacy run, or latest run-matrix alias/role fields. Next-run config roles are not presented as current facts.
- `EVIDENCE` spells out `PROVEN`, `FAILED`, `FLAKY`, or `UNPROVEN`; it is blank when no run-backed role exists.

---

## 7. ETA Algorithm

```
load stage_timings.csv → Map<stage_name, Vec<duration_secs>> (pass rows only)
for each stage_name → p50 = median(durations) or 60s default

on each state refresh:
  completed = outcomes[].filter(status ∈ {pass, fail, skipped})
  active    = last outcome with status = running (or infer from log)
  pending   = all_expected_stages - completed - active

  eta_remaining = sum(p50[s] for s in pending)
  active_elapsed = now() - active_stage_start_unix  (from log timestamp)
  active_remaining = max(0, p50[active] - active_elapsed)

  total_eta = active_remaining + eta_remaining
```

`all_expected_stages` is the active/held run's manifest-enabled, non-synthetic stage list. No outcome-count or local-catalog inference is used for a selected report.

---

## 8. Config Panel

The config panel (key `^C`) is an in-app form for the next launch. Fields:

| Field | Type | Default |
|-------|------|---------|
| Area | text | last used |
| exit_vm | text | `debian-headless-1` |
| client_vm | text | `debian-headless-2` |
| macos_vm | text | `macos-utm-1` |
| windows_vm | text | `windows-utm-1` |
| relay_platform | select | `linux`/`macos`/`windows` |
| anchor_platform | select | same |
| exit_platform | select | same |
| admin_platform | select | same |
| blind_exit_platform | select | same |
| skip_linux_live_suite | bool | auto (true for mac/win areas) |
| rebuild_nodes | text | (comma-separated aliases) |
| triage_on_failure | bool | false |
| dry_run | bool | false |

Config is persisted to `state/monitor-config.toml` and loaded on startup.

---

## 9. Crate Structure

```
crates/rustynet-lab-monitor/
  Cargo.toml
  src/
    main.rs            — arg parse, config load, tokio runtime, run app
    app.rs             — App state, event loop, panel routing, tick()
    config.rs          — MonitorConfig struct, TOML load/save
    ui/
      mod.rs
      header.rs        — top status bar (job id, area, status, eta)
      stage_grid.rs    — block grid renderer
      vm_panel.rs      — VM status list
      parity_panel.rs  — role × OS grid from run_matrix
      log_panel.rs     — log tail viewer (scrollable)
      jobs_panel.rs    — jobs browser
      config_panel.rs  — config form
      status_bar.rs    — keyboard hint bar at bottom
      help_overlay.rs  — ^? help modal
    data/
      mod.rs
      job_watcher.rs   — watch deepseek-mcp-jobs/*.json; emit JobState events
      stage_reader.rs  — read/watch orchestrate_result.json → StageOutcome[]
      log_tailer.rs    — tail stage log files, emit line events
      timings.rs       — load stage_timings.csv, compute P50 per stage
      run_matrix.rs    — load run_matrix.csv, compute parity cell state
      vm_prober.rs     — async TCP+utmctl probes, emit VmStatus events
    control/
      mod.rs
      launcher.rs      — spawn orchestrator subprocess, record pgid
      stopper.rs       — SIGTERM the orchestrator pgid
```

Binary name: `rustynet-lab-monitor`  
No `default-run` change needed — this is a separate binary, not a subcommand of `rustynet-cli`.  
Add to workspace `Cargo.toml` members.

---

## 10. Non-Goals (for this version)

- No MCP server dependency at runtime (reads state files directly).
- No cross-platform Windows port for the monitor itself — macOS/Linux only (it runs on the lab host machine, which is the Mac).
- No web/HTTP interface.
- No agent integration (the agent talks to MCP; the monitor talks to state files).
- No in-app log editing or code patching.
- No automatic reconnect to a running session after monitor restart — it re-reads state from files on startup.

---

## 11. Gates

**This crate is EXCLUDED from the main Cargo workspace** (root `Cargo.toml`
`exclude = ["gui", "crates/rustynet-lab-monitor"]`), so the repo-wide
`cargo … --workspace` gates do **not** touch it. Gate it **standalone**, from
inside the crate directory (which has its own `Cargo.lock` and its own empty
`[workspace]` table):

```sh
cd crates/rustynet-lab-monitor
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo check --all-targets --locked
cargo test --locked
```

These four are wrapped by `scripts/ci/lab_monitor_gates.sh` and wired into
`.github/workflows/cross-platform-ci.yml` as a dedicated **"Lab monitor
standalone gates"** step on the **macOS** and **Debian (Linux)** legs — the two
OSes this tool supports (macOS/Linux only; no Windows port, §10). That makes the
excluded crate a **first-class gated target**: a fmt/clippy/check/test
regression fails CI exactly as a workspace regression would, rather than being
invisible to the `--workspace` gates. See also the crate `README.md`.

No new security-sensitive logic — no security gate-script extension needed. The
crate does not touch WireGuard, crypto, trust state, or ACL; it is an observer
and a process launcher.

### 11.1 Input robustness (2026-07-13)

The monitor reads exclusively **untrusted, concurrently-written** state files
(run manifest/result, `stages.tsv`, `report_state.json`, parallel `results.tsv`,
`vm_lab_inventory.json`, `utmctl list`, run-matrix CSV). Every parser is
hardened to **degrade gracefully** — never panic, never present a false-green or
an incoherent count — on corrupt, missing, empty, stale, partially-written, and
concurrently-updated input, with the failure surfaced as an explicit
waiting/degraded/error state (or a silently-skipped bad record) rather than a
plausible-looking guess. Regressions fixed in this pass:

- **`utmctl list` parsing** returned `Result` and `?`-bubbled on the first
  malformed row, blanking out discovery of **every** VM on the host; now
  best-effort per row (one bad row skipped, the rest survive), and the command's
  stdout is decoded lossily so a stray non-UTF8 byte in one VM name can't hide
  the others.
- **Job-state JSON scan** (`find_running_jobs_with_live_processes`)
  `?`-propagated on the first unreadable/corrupt/non-UTF8/directory-shaped
  `.json`, hiding a genuinely-running job sitting next to one stale file from a
  past crash; now best-effort per directory and per entry.
- **`truncate_session`** byte-sliced at `len() - 12` and panicked on any
  multi-byte-UTF8 session id straddling the cut; now char-counted.
- **`--repo-root` CLI parsing** indexed one past the end of argv when the flag
  was the last token; now returns a clear error.
- **Stage-log active-stage inference** `?`-errored on an unreadable/torn
  `orchestrate.log` or per-stage `.log`, freezing active-stage tracking for the
  whole run; now degrades to "no signal from this source" and falls through to
  the pipeline-position fallback.

Each fix ships with adversarial-input unit tests in the owning `src/data/*`
module (and `src/app.rs` / `src/main.rs`); the truncated-status-word test pins
that a torn status prefix like `"pas"` parses as `Unknown`, never a decisive
false pass/fail.

---

## 12. Open Questions

1. **Stage order / expected-stage list**: the orchestrator doesn't emit a stage manifest before running. Best approach: read the prior run's `orchestrate_result.json` to get the ordered list of stages, then fill in `pending` for stages not yet appearing in the current run's outcomes. Fallback: hardcode the known stage list from `get_orchestrator_stages`.

2. **Active-stage detection during a run**: `orchestrate_result.json` is written incrementally (each stage appended when it finishes). The currently-active stage is NOT in the JSON yet. Infer it from the most recent line in `orchestrate.log` matching `^\d{4}-\d{2}-\d{2}T.*STAGE:` or from the last `logs/{stage}.log` file whose mtime is within the last 60s.

3. **Singleton gate integration**: the monitor should warn (not block) if it detects a job already running before the user presses `^S` to launch. The MCP server's singleton gate enforces exclusion; the monitor is a courtesy check only.
