# Loop Scripts

OpenCode-backed unattended live-lab loop. (An earlier Zed-paste-driven mode —
`auto_loop.sh`/`drive_loop.sh`/`initial_prompt.md`/`wake_on_event.sh` pasting
prompts into a Zed agent chat via AppleScript, since Zed has no programmatic
API — has been removed; it is no longer in use.)

## Files
```
scripts/loop/
  opencode_loop.sh          OpenCode-backed unattended loop runner (the state machine)
  opencode_report_review.sh OpenCode/tmux read-only report-review worker
```

## OpenCode Report Review Worker

`opencode_report_review.sh` opens a separate tmux window, runs an OpenCode
worker over a completed live-lab report, writes a durable review, then
optionally wakes the main OpenCode session. Use this with live-lab runs
launched as `triage_on_failure=false` so paid AI-agent MCP triage is not
called automatically.

`opencode_loop.sh` does this automatically on failed runs when
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
