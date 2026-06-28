# Loop Wake Scripts

## Overview
`wake_on_event.sh` polls running orchestrator processes, detects completion, and writes structured state files. Hook scripts fire on pass/fail transitions.

## Files
```
scripts/loop/
  wake_on_event.sh          Main poller/watcher
  hooks/
    on_any.sh               Called on any completion (writes agent prompt)
    on_pass.sh              Called on pass → delegates to on_any.sh
    on_fail.sh              Called on fail → delegates to on_any.sh
  com.rustynet.loop-wake.plist  launchd plist (macOS scheduled task)
```

## Output
- `state/loop-wake.json` — current state (running jobs, last completed, next action)
- `state/loop-wake-prompt.md` — agent-ready brief for next invocation
- `state/loop-wake-known.tsv` — tracked PIDs for completion detection

## Usage

### Install the launchd watcher (runs every 30s)
```bash
cp scripts/loop/com.rustynet.loop-wake.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.rustynet.loop-wake.plist
```

### One-shot poll
```bash
./scripts/loop/wake_on_event.sh poll
```

### Continuous watch (foreground)
```bash
./scripts/loop/wake_on_event.sh watch -i 30
```

### Agent invocation pattern
When the agent starts, read `state/loop-wake.json` and `state/loop-wake-prompt.md` for context. The prompt file contains the last run's result and suggested next action.

## Limitations
- Cannot directly invoke the Zed AI agent — no programmatic API exists.
- The agent must be invoked by the user (or a scheduler that opens Zed).
- For true hands-free operation, pair with a `fswatch` on `state/loop-wake-prompt.md`
  that triggers a notification or auto-opens the agent prompt.

## Autonomous Loop (`drive_loop.sh`)

`drive_loop.sh` wraps the full deepseek pipeline into one command:

```bash
# macOS exit cell
./scripts/loop/drive_loop.sh "macOS exit" macos macos_promote_exit=true \
    exit_vm=debian-headless-1 client_vm=debian-headless-2 \
    entry_vm=debian-headless-3 macos_vm=macos-utm-1

# Windows anchor cell
./scripts/loop/drive_loop.sh "Windows anchor" windows \
    anchor_platform=windows windows_vm=windows-utm-1 \
    exit_vm=debian-headless-1 client_vm=debian-headless-2 \
    entry_vm=debian-headless-3
```

**Cycle:**
1. Calls `deepseek_lab_run` → auto-polls for report (~50min blocking)
2. Writes `state/loop-cycle-prompt.md` with report + patch instructions
3. You invoke the Zed agent, paste the prompt file as context
4. Agent verifies claims, patches, gates, commits, relaunches deepseek_lab_run
5. You re-run `drive_loop.sh` to capture the next cycle

## Fully Autonomous Loop (`auto_loop.sh`)

`auto_loop.sh` is the hands-free overnight driver. Unlike `drive_loop.sh` (which
you re-run each cycle), it **launches the first run itself, then shepherds**:
it classifies each report, pastes the action prompt into the Zed agent chat
(via `pbcopy` + AppleScript `Cmd-V` + Return), and waits for the agent to launch
the **next** run — a patch re-verify, or the next cell. It never re-launches the
same cell itself, so it neither spins on a passed cell nor double-launches
against the singleton gate.

```bash
# macOS anchor cell (the Linux suite is auto-skipped for mac/win areas)
./scripts/loop/auto_loop.sh "macOS anchor" macos=true anchor_platform=macos \
    macos_vm=macos-utm-1 exit_vm=debian-headless-1 client_vm=debian-headless-2

# Linux exit cell (Linux suite runs — it IS the cell)
./scripts/loop/auto_loop.sh "Linux exit" exit_platform=linux \
    exit_vm=debian-headless-1 client_vm=debian-headless-2
```

**Intelligent stage targeting (the point of the loop):**
- For a **mac/win area** the loop auto-adds `skip_linux_live_suite=true`, so each
  run executes setup (bootstrap + membership + signed-bundle distribution) then
  ONLY the targeted mac/win cell — skipping the ~30-45min Linux live suite that
  is pure waste when iterating a mac/win stage. Override with an explicit
  `skip_linux_live_suite=false`.
- The **FAIL** prompt tells the agent to patch → gate → commit → relaunch with
  `skip_linux_live_suite=true` + `rebuild_nodes=<patched_node>` — redeploy only
  the patched node and run only the cell that proves the fix (~10-15min).
- The **PASS** prompt tells the agent to sync docs/matrix, pick the next unproven
  cell via `find_untested_work`, and launch it (again skipping the Linux suite
  for mac/win), so the loop always progresses to the next area.
- For a **Linux cell** the suite is NOT skipped — there the Linux suite is the
  test.

**Cycle:**
1. Loop launches the first `deepseek_lab_run` (blocking poll keeps the MCP server
   alive so the detached orchestrator spawns — never `--no-poll` to launch).
2. Classifies the report (anchored on the report header: PASS / FAIL → triage /
   TIMED OUT / DRY-RUN), writes `state/loop-cycle-prompt.md`, pastes into Zed.
3. Agent verifies the (UNTRUSTED) triage, patches, gates, commits, relaunches.
4. Loop detects the agent's new job, polls it to completion, and repeats from 2.
5. If the agent stalls (no relaunch within the cap) the loop re-pastes as a nudge;
   it never relaunches the cell itself.

Requires the Zed app focused-and-frontmost for the AppleScript paste; grant
Accessibility/Automation permission to whatever runs the script.
