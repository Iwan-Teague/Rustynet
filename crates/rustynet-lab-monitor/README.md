# rustynet-lab-monitor

Terminal UI (TUI) for observing, controlling, and understanding the Rustynet
live-lab loop in real time. See
[`documents/operations/active/LabMonitorTUIDesign_2026-06-29.md`](../../documents/operations/active/LabMonitorTUIDesign_2026-06-29.md)
for the full design and
[`documents/operations/active/LiveLabMonitorTUIAccuracyImprovements_2026-07-10.md`](../../documents/operations/active/LiveLabMonitorTUIAccuracyImprovements_2026-07-10.md)
for the data-accuracy hardening history.

The monitor is a **read-only observer + process launcher**. It reads the same
state files the orchestrator and MCP server write (per-run
`stage_manifest.json`, `orchestrate_result.json`, `state/stages.tsv`,
`state/report_state.json`, the parallel `results.tsv`, `vm_lab_inventory.json`,
`utmctl list`, and `live_lab_run_matrix.csv` rows) and drives the same
orchestrator binary the live-lab loop uses. It touches no WireGuard, crypto,
trust-state, ACL, killswitch, exit-NAT, or DNS code — it is non-security tooling.

## Workspace exclusion — why this crate is standalone

`rustynet-lab-monitor` is **intentionally excluded** from the main Rustynet
Cargo workspace. See the root [`Cargo.toml`](../../Cargo.toml):

```toml
exclude = ["gui", "crates/rustynet-lab-monitor"]
```

The reason (also documented inline in that file): the TUI stack (`ratatui`,
`crossterm`, `notify`, …) pulls in a large transitive dependency tree with
assorted licenses, and the lab target VMs must not have to resolve UI-only
crates while building `rustynetd` / `rustynet-cli` offline. Keeping the monitor
out of the workspace keeps the security-gated workspace lean and its
`cargo deny` license/bans surface small.

This crate has its own `Cargo.lock` and its own `[workspace]` table (an empty
one in its `Cargo.toml`) so that cargo treats it as a self-contained workspace
root and does not try to attach it to the enclosing repo workspace (which would
otherwise error with *"believes it's in a workspace when it's not"* when this
checkout is nested inside another — e.g. a git worktree under `.claude/`).

## Building & gating (standalone)

Because it is workspace-excluded, the repo-wide `cargo … --workspace` gates
(§7 of `CLAUDE.md` / `AGENTS.md`) **never touch this crate**. Build and gate it
from **inside the crate directory**:

```sh
cd crates/rustynet-lab-monitor
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo check --all-targets --locked
cargo test --locked
```

### First-class CI gate

Those four gates are wrapped by
[`scripts/ci/lab_monitor_gates.sh`](../../scripts/ci/lab_monitor_gates.sh),
which is wired into
[`.github/workflows/cross-platform-ci.yml`](../../.github/workflows/cross-platform-ci.yml)
as a dedicated **"Lab monitor standalone gates"** step on both the **macOS**
and **Debian (Linux)** legs — the two OSes this tool supports (it is
macOS/Linux only; there is no Windows port, per the design doc's Non-Goals). A
fmt/clippy/check/test regression in the excluded crate therefore fails CI just
like a workspace regression would, instead of being invisible.

Run the same gate locally with:

```sh
./scripts/ci/lab_monitor_gates.sh
```

## Running

```sh
cd crates/rustynet-lab-monitor
cargo run                 # launches the TUI (reads state files under the repo root)
cargo run -- --repo-root /path/to/rustynet   # explicit repo root
cargo run -- --snapshot   # headless: print what the TUI would render, then exit
```

The `--snapshot` mode is used for scripted / CI verification of the monitor's
data model without a terminal.

## Input robustness

Every state-file parser is written to **degrade gracefully** — it never panics
and never presents a false-green or an incoherent count on corrupt, missing,
empty, stale, partially-written, or concurrently-updated input. Malformed run
evidence renders as an explicit waiting/degraded/error state rather than being
silently substituted with a plausible-looking local guess. These properties are
pinned by the adversarial-input unit tests in each `src/data/*` module (corrupt
JSON, torn writes, non-UTF8 bytes, ragged CSV rows, one bad file not hiding its
siblings, and truncated status words never reading as a decisive pass/fail).
