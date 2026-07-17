# Loop Wake Scripts

## Overview
`wake_on_event.sh` polls running orchestrator processes, detects completion, and writes structured state files. Hook scripts fire on pass/fail transitions.

## Files
```
scripts/loop/
  wake_on_event.sh          Main poller/watcher
  opencode_loop.sh          OpenCode-backed unattended loop runner
  opencode_report_review.sh OpenCode/tmux read-only report-review worker
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

`drive_loop.sh` wraps the full AI-agent MCP pipeline into one command:

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
1. Calls `ai_lab_run` → auto-polls for report (~50min blocking)
2. Writes `state/loop-cycle-prompt.md` with report + patch instructions
3. You invoke the Zed agent, paste the prompt file as context
4. Agent verifies claims, patches, gates, commits, relaunches ai_lab_run
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
  cell via `ai_next_live_lab_target`, and launch it (again skipping the
  Linux suite for mac/win), so the loop always progresses to the next area.
- For a **Linux cell** the suite is NOT skipped — there the Linux suite is the
  test.

**Cycle:**
1. Loop launches the first `ai_lab_run` (blocking poll keeps the MCP server
   alive so the detached orchestrator spawns — never `--no-poll` to launch).
2. Classifies the report (anchored on the report header: PASS / FAIL → triage /
   TIMED OUT / DRY-RUN), writes `state/loop-cycle-prompt.md`, pastes into Zed.
3. Agent verifies the (UNTRUSTED) triage, patches, gates, commits, relaunches.
4. Loop detects the agent's new job, polls it to completion, and repeats from 2.
5. If the agent stalls (no relaunch within the cap) the loop re-pastes as a nudge;
   it never relaunches the cell itself.

Before every paste, the script activates Zed and double-clicks the horizontal
center of the front window, `PROMPT_CLICK_Y_OFFSET` pixels above the bottom
(default `80`, delay `0.20`s), then pastes and submits. Grant
Accessibility/Automation permission to whatever runs the script.

## OpenCode Report Review Worker

`opencode_report_review.sh` is the transition path away from Zed automation. It
opens a separate tmux window, runs an OpenCode worker over a completed live-lab
report, writes a durable review, then optionally wakes the main OpenCode session.
Use this with live-lab runs launched as `triage_on_failure=false` so paid
AI-agent MCP triage is not called automatically.

`auto_loop.sh` now does this automatically on failed runs when
`OPENCODE_REVIEW_ON_FAIL=1` (default): it launches `ai_lab_run` with
`triage_on_failure=false`, calls this review worker when the run fails, waits for
the review, inlines the review into the next action prompt, and writes
`state/opencode-main-wake-prompt.md`. If `OPENCODE_MAIN_SESSION_ID` is set, the
review worker also wakes that main OpenCode session directly.

```bash
export OPENCODE_REVIEW_MODEL='opencode/deepseek-v4-flash-free'
export OPENCODE_TMUX_SESSION=rustynet-loop

./scripts/loop/opencode_report_review.sh \
    --job-id labrun-1782678473813-32981-0
```

Outputs:
- `state/opencode-report-reviews/<job_id>/report-review-prompt.md`
- `state/opencode-report-reviews/<job_id>/opencode-events.jsonl`
- `state/opencode-report-reviews/<job_id>/report-review.md`
- `state/opencode-report-reviews/<job_id>/status.json`
- `state/opencode-main-wake-prompt.md`

Optional wake-back to a main OpenCode session:

```bash
export OPENCODE_MAIN_SESSION_ID='<main-session-id>'
export OPENCODE_MAIN_MODEL='deepseek/deepseek-v4-pro'
export OPENCODE_MAIN_VARIANT=max
```

Dry-run prompt generation without calling OpenCode:

```bash
./scripts/loop/opencode_report_review.sh \
    --job-id labrun-1782678473813-32981-0 \
    --dry-run
```

Run in foreground instead of tmux:

```bash
./scripts/loop/opencode_report_review.sh \
    --job-id labrun-1782678473813-32981-0 \
    --no-tmux
```

The review worker is read-only by prompt contract. It must not patch, gate,
commit, or launch another lab. The main v4-pro loop agent remains reviewer of
record: it reads the review, verifies claims against repo/log evidence, patches,
gates, commits, then relaunches the focused `ai_lab_run`.

## OpenCode `/loop`

`.opencode/commands/loop.md` exposes a project slash command that delegates to
`scripts/loop/opencode_loop.sh`. The script is the real state machine: it
launches/polls lab runs, invokes the Flash review worker on failure, writes the
main v4-pro prompt with the inline review, calls `opencode run`, detects the next
`labrun-*` launched by the agent, then repeats.

Direct shell usage:

```bash
export OPENCODE_MAIN_MODEL='deepseek/deepseek-v4-pro'
export OPENCODE_MAIN_VARIANT=max
export OPENCODE_REVIEW_MODEL='opencode/deepseek-v4-flash-free'

./scripts/loop/opencode_loop.sh start "macOS exit" \
    macos=true macos_promote_exit=true macos_vm=macos-utm-1 \
    exit_vm=debian-headless-1 client_vm=debian-headless-2 entry_vm=debian-headless-3
```

OpenCode slash-command usage:

```text
/loop "macOS exit" macos=true macos_promote_exit=true macos_vm=macos-utm-1 exit_vm=debian-headless-1 client_vm=debian-headless-2 entry_vm=debian-headless-3
```

Useful safety knobs:

```bash
export OPENCODE_LOOP_MAX_CYCLES=1        # stop after one prompt cycle
export OPENCODE_LOOP_MAX_RUN_WAIT=5400   # lab poll cap
export OPENCODE_LOOP_MAX_AGENT_WAIT=7200 # patch-agent cap
export OPENCODE_LOOP_MAX_RELAUNCH_WAIT=120
export OPENCODE_LOOP_REPORT_INLINE_LIMIT=25000
export OPENCODE_LOOP_REVIEW_INLINE_LIMIT=25000
```

`once` mode launches/polls the first lab and writes the main prompt without
calling OpenCode:

```bash
./scripts/loop/opencode_loop.sh once "macOS exit" macos=true exit_platform=macos
```

Project OpenCode config defines two named agents:
- `rustynet-report-review`: free `opencode/deepseek-v4-flash-free`, read-only
  tools only, no bash/edit/task/web.
- `rustynet-loop-main`: DeepSeek API `deepseek/deepseek-v4-pro` max, 250-step patch/gate/
  relaunch agent. OpenCode 1.17 only exposes the bash tool when `bash=allow`, so
  command safety is enforced by the loop prompt and repo process, not by per-
  command OpenCode deny patterns. The loop writes the main-agent JSON event
  stream and status to `state/opencode-loop/main-agent-events.jsonl` and
  `state/opencode-loop/main-agent-status.json` so a stalled overnight run can be
  audited without terminal scrollback.

Main-agent stall controls:
- `OPENCODE_LOOP_MAIN_NO_EDIT_TIMEOUT` defaults to `2700` seconds. If the main
  agent has not used `edit` and has not launched a new `labrun-*`, the loop kills
  that attempt.
- `OPENCODE_LOOP_MAIN_AGENT_RETRIES` defaults to `2`. Retry prepends a watchdog
  prompt that forbids broad rediscovery and requires an edit or focused reverify
  relaunch quickly.
- Failure reverify JSON auto-adds `rebuild_nodes=<macos_vm|windows_vm>` when a
  target guest can be derived, so stale guest binaries are ruled out before the
  loop chases a source bug.
- The main-agent JSON event stream is written to
  `state/opencode-loop/main-agent-events.jsonl` on stderr from the shell
  function. This keeps command substitution stdout clean so only the detected
  `labrun-*` id is captured by the parent state machine.
- Lab polling has a local artifact fallback: if `ai_live_lab_result` still
  says a job is running but `orchestration/orchestrate_result.json` exists, the
  loop treats that artifact as terminal, extracts `overall_status` plus the first
  failed stage, and advances into Flash review / Pro patching instead of sleeping
  forever on a stale job record.

Current supervised smoke result:
- Lab job `labrun-1782685057348-21540-0` completed setup and macOS exit bring-up,
  then failed `validate_macos_exit_dns_failclosed`.
- Direct failure artifact:
  `state/deepseek-lab-labrun-1782685057348-21540-0/macos_exit_evidence/dns_leak_proof/pf_block_rules.json`
  reported missing `rustynet-dns-block-lan-udp` and
  `rustynet-dns-block-lan-tcp`.
- Flash review worked, but initial JSON extraction included raw tool output.
  The extractor now keeps only assistant `type=text` events and caps inline
  report/review text before waking the main agent.
