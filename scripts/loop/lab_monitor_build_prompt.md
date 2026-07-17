# Build Prompt — Rustynet Lab Monitor TUI

> Give this to an autonomous coding agent (Claude Code, OpenCode loop, etc.).
> The design doc is at `documents/operations/active/LabMonitorTUIDesign_2026-06-29.md`.
> Gates must pass before the task is done. Push to main (no PR).

---

```
You are Claude Code working on **Rustynet** — a Cargo workspace (edition 2024,
`unsafe_code = forbid`, resolver = "2") on macOS. Read CLAUDE.md + AGENTS.md
before touching code. This task has no security-sensitive logic; it is a new
observer/launcher TUI crate that reads state files and spawns a subprocess.

## TASK

Build `rustynet-lab-monitor`: a Rust TUI application that is the live GUI for
the Rustynet live-lab loop. It shows stage progress, VM state, and the role×OS
parity matrix in a pixelated terminal style, and lets the operator start/stop
the orchestrator.

Full design: `documents/operations/active/LabMonitorTUIDesign_2026-06-29.md`
(read it first — it has the screen layout, data sources, crate structure, and
all field/format details). This prompt is the complement: the exact steps,
formats, and constraints to build from scratch.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 0 — READ FIRST
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. CLAUDE.md + AGENTS.md (contract, constraints)
2. documents/operations/active/LabMonitorTUIDesign_2026-06-29.md (design spec)
3. Cargo.toml (workspace members list — you will add to it)
4. crates/rustynet-mcp/src/bin/ai_agent.rs lines around `build_orchestrator_args`
   (to see the exact CLI args the orchestrator takes — match them exactly)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1 — CREATE THE CRATE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Create `crates/rustynet-lab-monitor/Cargo.toml`:

```toml
[package]
name = "rustynet-lab-monitor"
version = "0.1.0"
edition = "2024"
description = "Terminal UI for the Rustynet live-lab loop"

[[bin]]
name = "rustynet-lab-monitor"
path = "src/main.rs"

[dependencies]
ratatui = "0.28"
crossterm = { version = "0.28", features = ["event-stream"] }
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
csv = "1.3"
notify = "6"
chrono = { version = "0.4", features = ["serde"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
toml = "0.8"
anyhow = "1"

[target.'cfg(unix)'.dependencies]
nix = { version = "0.28", features = ["signal", "process"] }
```

Add `"crates/rustynet-lab-monitor"` to the `members` list in the root
`Cargo.toml`. Do NOT add these deps to the workspace-wide `[workspace.dependencies]`
unless they are already there.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2 — DATA FORMATS (read these files to know the exact shapes)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### Job state JSON  (`state/deepseek-mcp-jobs/{job_id}.json`)
Read one of the existing files in that directory first to learn the exact fields.
Key fields you need: `job_id`, `state` (string: "running"|"done"|"crashed"),
`pid` (optional u32), `started_unix` (u64 epoch ms), `area` (string),
`report_dir` (string path).

### Orchestrate result (`state/deepseek-lab-{job_id}/orchestration/orchestrate_result.json`)
```json
{
  "overall_status": "partial",
  "report_dir": "...",
  "outcomes": [
    {
      "stage": "discover_local_utm",
      "status": "pass",   // "pass"|"fail"|"skipped"|"partial"
      "summary": "...",
      "artifacts": [...]
    },
    ...
  ]
}
```
This file is written incrementally — a stage is appended when it completes.
The ACTIVE stage is the one not yet in `outcomes[]`. Detect it from the log.

### Stage timings CSV (`documents/operations/live_lab_stage_timings.csv`)
```
timestamp_utc,git_commit,git_dirty,stage,scope,duration_secs,outcome
```
Load all rows where `outcome == "pass"`. Group by `stage`. P50 per stage = ETA.

### Run matrix CSV (`documents/operations/live_lab_run_matrix.csv`)
Wide CSV (150+ cols). Key columns for parity:
- `overall_result`: "pass"|"fail"
- `macos_present`, `windows_present`: "yes"|"no"|"na"
- Per-role-per-OS stage result columns (examples):
  - `macos_stage_anchor`, `macos_stage_relay`, `macos_stage_exit`, etc.
  - `windows_stage_anchor`, `windows_stage_relay`, etc.
  - `linux_stage_anchor`, `linux_stage_relay`, etc.
- Values in stage columns: "pass"|"fail"|"not_run"|"na"
For parity cell `(role, OS)`: scan rows newest-first; find first row where
`overall_result == "pass"` and `{os}_stage_{role} == "pass"` → PROVEN.
If any row has `{os}_stage_{role} == "fail"` → FAILED (show last failure).
Otherwise → UNPROVEN.

### VM inventory (`documents/operations/active/vm_lab_inventory.json`)
Read to get the list of VMs (alias, ip, ssh_user, ssh_port). Use this for
probing when no active job has a `discover_initial.json`.

### Active job topology (`state/deepseek-lab-{job_id}/orchestration/discover_initial.json`)
Has the per-alias IP and role assignments for the current run. Prefer this over
the inventory file when a job is running.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 3 — IMPLEMENT (file order)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Build in this order so `cargo check` passes at each step:

1. `src/config.rs` — MonitorConfig struct, TOML load/save to
   `state/monitor-config.toml`. Fields match the config panel in the design doc.

2. `src/data/timings.rs` — load stage_timings.csv, compute P50 per stage name.
   Return `HashMap<String, u64>` (stage → median_secs).

3. `src/data/run_matrix.rs` — load live_lab_run_matrix.csv (last 200 rows),
   return `HashMap<(Role, Os), ParityState>` where ParityState is
   `Proven | Failed | Unproven`. Handle missing columns gracefully (not all
   runs have all columns — parse with lenient CSV reader).

4. `src/data/job_watcher.rs` — scan `state/deepseek-mcp-jobs/` for *.json files,
   parse each, return the most-recently-started running job (or None). Implement
   a `watch()` async fn that polls every 2s and sends events on a `tokio::sync::watch`.

5. `src/data/stage_reader.rs` — given a `report_dir` path, read
   `orchestration/orchestrate_result.json`, return `Vec<StageOutcome>`. Watch the
   file with `notify` and resend on change. Infer active stage by reading
   `orchestrate.log` for the most recent `STAGE:` marker.

6. `src/data/log_tailer.rs` — given a log file path, tail last N lines.
   Watch for appends with `notify`. Emit new lines as they arrive.

7. `src/data/vm_prober.rs` — for each VM alias+IP, probe TCP:22 with 2s timeout.
   On macOS: also run `utmctl status {alias}` via `tokio::process::Command`.
   Return `VmStatus { alias, ip, ssh_ok, power_state }`. Run probes every 30s
   or on demand.

8. `src/control/launcher.rs` — build the orchestrator args from `MonitorConfig`
   (match `build_orchestrator_args` in `crates/rustynet-mcp/src/bin/ai_agent.rs`
   EXACTLY — same binary path, same flags), spawn via `tokio::process::Command`
   with `process_group(0)` so it gets its own pgid, record pgid in
   `state/monitor-launch.json`. Check for a running singleton first.

9. `src/control/stopper.rs` — read pgid from the running job's state JSON
   (field: look at actual job JSON for the pid field), send `SIGTERM` to the
   process group via `nix::sys::signal::killpg`.

10. `src/app.rs` — App struct holding all watcher handles and UI state.
    Main event loop: `crossterm::event::EventStream` for input + a
    `tokio::time::interval(Duration::from_secs(2))` tick. On tick: refresh
    all data sources, recompute ETA, update parity matrix. Panel routing.

11. `src/ui/` — one file per panel. Build with ratatui's `Frame::render_widget`.

12. `src/main.rs` — parse `--repo-root <path>` arg (default: current dir),
    init tracing to `state/monitor.log`, enter alternate screen, run app loop,
    restore terminal on exit (even on panic — use a `scopeguard`).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 4 — UI DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### Stage grid pixel blocks
Render each stage cell as a 4-char colored `Span`:
- Pass:    `[██]` in `Color::Green`
- Fail:    `[✗✗]` in `Color::Red`
- Active:  `[▓▓]` in `Color::Yellow` (use `Modifier::SLOW_BLINK` optional)
- Pending: `[░░]` in `Color::DarkGray`
- Skipped: `[  ]` in `Color::DarkGray` with `Modifier::DIM`

Wrap cells at `(panel_width - 2) / 5` cells per row. Group into sections:
SETUP stages first (setup/cleanup/bootstrap/membership/distribute/enforce/validate
prefix stages), then MAC ROLES stages, then WIN ROLES stages. Each section has
a section header line and its own progress mini-bar.

### Progress bar (active stage + overall)
Build as a plain `String`: `[` + `█` * filled + `░` * remaining + `]`
Width: panel_width - 20 chars. Append `N/M  ~Xm remaining`.

### Parity matrix
Render as a `Table` widget. Columns: Role | Linux | macOS | Windows.
Each cell is a `[██]`/`[░░]`/`[✗✗]`/`[  ]` span as above.
Row labels: client, admin, exit, blind_exit, relay, anchor, nas, llm.

### Log panel
`Paragraph::new(lines).scroll((scroll_offset, 0))`. Lines are pre-formatted
with timestamp + level + message. Highlight lines containing "FAIL"/"PASS"
with appropriate color. Arrow keys scroll.

### Header bar
Single line: `RUSTYNET LAB MONITOR  │  JOB: {id}  │  AREA: {area}  │
STATUS: {◉ RUNNING / ✓ DONE / ✗ FAILED / — IDLE}  │  ETA: {eta}`
Color the STATUS field green/red/yellow/grey. Right-align ETA.

### Status bar (bottom)
Fixed line with dim-colored keyboard hints. Change hint list based on focused
panel.

### Config form
Vertical list of labeled fields. Focused field has a cursor (use crossterm's
cursor show/hide). Tab moves between fields. Enter saves.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 5 — TERMINAL RESTORATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CRITICAL: the terminal MUST be restored on exit, including on panic.
Wrap the app in a helper that:
1. `crossterm::terminal::enable_raw_mode()?`
2. `execute!(stdout, crossterm::terminal::EnterAlternateScreen)?`
3. On drop (impl Drop, or scopeguard): disable_raw_mode + LeaveAlternateScreen
4. Set a panic hook that restores terminal before printing the panic message.
Use the ratatui `restore()` / `init()` pattern from ratatui 0.28 docs.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 6 — GATE AND COMMIT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Run in order, fix root cause on failure, re-gate:
1. `cargo fmt --all -- --check`
2. `cargo check --workspace --all-targets --all-features`
3. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
4. `cargo test --workspace --all-targets --all-features`
   (add unit tests for timings P50 calc, parity cell resolution, stage group logic)

Commit author: Iwan-Teague only. No Co-Authored-By trailer.
Push to main.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DESIGN CONSTRAINTS (DO NOT VIOLATE)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- `unsafe_code = forbid` is workspace-wide. Do not add `unsafe` blocks.
- No WireGuard types, no backend types, no crypto types in this crate.
- No unwrap()/expect() in non-test code — use `?` + anyhow::Error.
- Fail gracefully on missing state files (show "no active job" not a crash).
- No shell construction with user input — all subprocess args are built as
  `Vec<&str>` / `Vec<String>`, never passed to a shell.
- The orchestrator binary path: `target/debug/rustynet-cli` (or release path
  if `--release` flag is in config). Match the exact invocation from
  `build_orchestrator_args` in `crates/rustynet-mcp/src/bin/ai_agent.rs`.
- Do not add new features to other crates as part of this task — this is
  a new crate only.
- Keep AGENTS.md and CLAUDE.md byte-mirrored if you touch them.
  (You shouldn't need to — this crate is self-contained.)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DEFINITION OF DONE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

- `cargo build -p rustynet-lab-monitor` succeeds.
- All four gates pass.
- Running `./target/debug/rustynet-lab-monitor` (from repo root) renders the
  TUI without crashing, shows "no active job" state if none is running, and
  restores the terminal cleanly on `q`.
- Unit tests for: P50 timing calc, parity cell resolver (proven/unproven/failed),
  stage grouping (setup vs mac-roles vs win-roles), config TOML round-trip.
- The monitor app is committed and pushed to main.
```
