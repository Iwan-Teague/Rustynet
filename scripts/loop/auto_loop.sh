#!/usr/bin/env bash
# scripts/loop/auto_loop.sh — fully autonomous live-lab loop.
# See README.md for architecture. Run in a dedicated terminal.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && /bin/pwd -P)"
DRIVER="$REPO/scripts/mcp/drive_deepseek.py"
BIN="$REPO/bin/rustynet-mcp-deepseek"
PROMPT="$REPO/state/loop-cycle-prompt.md"
HISTORY="$REPO/state/loop-cycle-history.jsonl"
JOBS_DIR="$REPO/state/deepseek-mcp-jobs"
POLL=20
RELAUNCH_POLL=10
MAX_RUN_WAIT=5400
MAX_RELAUNCH_WAIT=900
PROMPT_CLICK_Y_OFFSET="${PROMPT_CLICK_Y_OFFSET:-80}"
PROMPT_CLICK_DELAY="${PROMPT_CLICK_DELAY:-0.20}"
CURRENT_ARGS_JSON=""
CURRENT_AREA=""
OPENCODE_REVIEW_ON_FAIL="${OPENCODE_REVIEW_ON_FAIL:-1}"
OPENCODE_REVIEW_SCRIPT="$REPO/scripts/loop/opencode_report_review.sh"

log() { printf '[AUTO %s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }
git_sha() { git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo "unknown"; }

# ── build deepseek_lab_run args JSON ──────────────────────────────────
build_args() {
    local area="$1"; shift
    python3 - "$area" "$@" <<'PY'
import json, sys

area = sys.argv[1]
bool_keys = {
    "macos", "windows", "macos_promote_exit", "allow_concurrent", "dry_run",
    "skip_linux_live_suite", "windows_only", "legacy_bash", "triage_on_failure",
}
str_keys = {
    "exit_vm", "client_vm", "entry_vm", "macos_vm", "windows_vm",
    "exit_platform", "relay_platform", "anchor_platform", "blind_exit_platform",
    "admin_platform", "rebuild_nodes",
}
out = {"area": area}
for pair in sys.argv[2:]:
    if "=" not in pair:
        continue
    key, val = pair.split("=", 1)
    if key in bool_keys:
        out[key] = val.strip().lower() in {"1", "true", "yes", "on"}
    elif key in str_keys and val:
        out[key] = val
print(json.dumps(out, separators=(",", ":")))
PY
}

extract_job_id() {
    python3 -c '
import re, sys
text = sys.stdin.read()
m = re.search(r"`(labrun-[^`]+)`", text) or re.search(r"\b(labrun-\d+-\d+-\d+)\b", text)
print(m.group(1) if m else "")
'
}

job_record_path() {
    local jid="$1"
    printf '%s/%s.json\n' "$JOBS_DIR" "$jid"
}

job_field() {
    local jid="$1" field="$2" default="${3:-}"
    python3 - "$JOBS_DIR" "$jid" "$field" "$default" <<'PY'
import json, pathlib, sys
jobs, jid, field, default = sys.argv[1:5]
path = pathlib.Path(jobs) / f"{jid}.json"
try:
    data = json.loads(path.read_text())
    value = data
    for part in field.split("."):
        value = value[part]
except Exception:
    print(default)
    raise SystemExit
if isinstance(value, (dict, list)):
    print(json.dumps(value, separators=(",", ":")))
elif value is None:
    print(default)
else:
    print(value)
PY
}

refresh_current_context() {
    local jid="$1" fallback_area="$2" fallback_args="$3"
    CURRENT_AREA="$(job_field "$jid" area "$fallback_area")"
    CURRENT_ARGS_JSON="$(job_field "$jid" request_args "$fallback_args")"
    [ -n "$CURRENT_AREA" ] || CURRENT_AREA="$fallback_area"
    [ -n "$CURRENT_ARGS_JSON" ] || CURRENT_ARGS_JSON="$fallback_args"
}

reverify_args_json() {
    local area="$1" rebuild_alias="$2" base="${CURRENT_ARGS_JSON:-}"
    [ -n "$base" ] || base="$(build_args "$area" "${LAUNCH_PARAMS[@]:-}")"
    python3 - "$area" "$rebuild_alias" "$base" <<'PY'
import json, sys

area, rebuild, raw = sys.argv[1:4]
try:
    args = json.loads(raw)
except Exception:
    args = {"area": area}
args["area"] = args.get("area") or area
lower = args["area"].lower()
if rebuild and rebuild != "unknown-node":
    args["rebuild_nodes"] = rebuild
if "linux" in lower and "macos" not in lower and "windows" not in lower:
    args.pop("skip_linux_live_suite", None)
else:
    args["skip_linux_live_suite"] = True
print(json.dumps(args, indent=2, sort_keys=True))
PY
}

review_output_path() {
    local jid="$1"
    printf '%s/state/opencode-report-reviews/%s/report-review.md\n' "$REPO" "$jid"
}

run_opencode_review_for_job() {
    local jid="$1"
    [ "${OPENCODE_REVIEW_ON_FAIL:-1}" = "1" ] || return 0
    [[ "$jid" == labrun-* ]] || return 0
    [ -x "$OPENCODE_REVIEW_SCRIPT" ] || {
        log "OpenCode review script missing/not executable: $OPENCODE_REVIEW_SCRIPT"
        return 0
    }
    log "running OpenCode report review for $jid..."
    if "$OPENCODE_REVIEW_SCRIPT" --job-id "$jid" --wait; then
        log "OpenCode report review complete for $jid"
    else
        log "OpenCode report review failed for $jid; continuing with raw lab report"
    fi
}

append_opencode_review_to_report() {
    local jid="$1" report="$2" review_path
    review_path="$(review_output_path "$jid")"
    if [ -s "$review_path" ]; then
        printf '%s\n\n---\n\n## OpenCode Flash Report Review\n\nReview file: `%s`\n\n%s\n' \
            "$report" "$review_path" "$(cat "$review_path")"
    else
        printf '%s\n' "$report"
    fi
}

# ── classify report ──────────────────────────────────────────────────
# Anchor on the deepseek_lab_run report HEADER markers (unambiguous) rather than
# grepping the body — a FAIL triage report contains the words "pass"/"fail" in
# its per-stage prose, which a loose body grep misclassifies. The headers come
# from deepseek.rs: "— PASS\n\nThe orchestration completed successfully",
# "— FAIL → triage", "— TIMED OUT after", "— DRY-RUN wiring check".
classify() {
    local report="$1"
    if   echo "$report" | grep -qiE 'DRY-RUN wiring check';                                  then echo "dryrun"
    elif echo "$report" | grep -qiE 'The orchestration completed successfully|— PASS|: PASS'; then echo "pass"
    elif echo "$report" | grep -qiE 'FAIL → triage|FAIL -> triage|FAIL \(triage disabled\)';  then echo "fail"
    elif echo "$report" | grep -qiE 'TIMED OUT after|still running|timed out after [0-9]';    then echo "timeout"
    else echo "unknown"; fi
}

# ── append cycle to history ──────────────────────────────────────────
record_history() {
    local cycle="$1" area="$2" result="$3" job="$4" sha="$5"
    python3 - "$HISTORY" "$cycle" "$(now_utc)" "$area" "$result" "$job" "$sha" <<'PY'
import json, sys
path, cycle, at, area, result, job, sha = sys.argv[1:8]
with open(path, "a", encoding="utf-8") as f:
    f.write(json.dumps({
        "cycle": int(cycle), "at": at, "area": area, "result": result,
        "job": job, "sha": sha,
    }, separators=(",", ":")) + "\n")
PY
}

# ── read last N cycles from history ──────────────────────────────────
recent_history() {
    local n="${1:-5}"
    if [ -f "$HISTORY" ]; then
        tail -n "$n" "$HISTORY" | python3 -c "
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        d = json.loads(line)
        print(f'  Cycle {d["cycle"]}: {d["result"]} ({d["area"]}) job={d["job"]} sha={d["sha"]}')
    except: pass
" 2>/dev/null || true
    else
        echo "  (no history yet)"
    fi
}

# ── derive rebuild_nodes alias from the launch params ──────────────────
rebuild_nodes_for() {
    # Return the node alias to rebuild for fast re-verify (~15min vs ~45min).
    # Intelligently picks the right VM based on the PLATFORM being tested,
    # not just the first param. Uses the area label (e.g. "Windows anchor"
    # -> windows-utm-1) and the platform selector flags.
    # Args: area_label (e.g. "Windows anchor", "macOS exit")
    local area_lower; area_lower=$(echo "${1:-}" | tr '[:upper:]' '[:lower:]')

    # Map platform -> VM alias from the current job request if available; fall
    # back to initial launch params for older job records.
    local win_vm="" mac_vm=""
    if [ -n "${CURRENT_ARGS_JSON:-}" ]; then
        win_vm=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("windows_vm",""))' "$CURRENT_ARGS_JSON" 2>/dev/null || true)
        mac_vm=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("macos_vm",""))' "$CURRENT_ARGS_JSON" 2>/dev/null || true)
    fi
    if [ -z "$win_vm$mac_vm" ]; then
        for pair in "${LAUNCH_PARAMS[@]:-}"; do
            local k="${pair%%=*}" v="${pair#*=}"
            case "$k" in
                windows_vm) win_vm="$v" ;;
                macos_vm)   mac_vm="$v" ;;
            esac
        done
    fi

    # Determine which platform this area targets
    if echo "$area_lower" | grep -q "windows"; then
        echo "${win_vm:-windows-utm-1}"
    elif echo "$area_lower" | grep -q "macos"; then
        echo "${mac_vm:-macos-utm-1}"
    else
        # Linux area or unknown — no single VM to rebuild
        echo ""
    fi
}

# ── write the agent prompt (incorporates generic_rustynet_prompt.md) ──
# ── write the agent prompt (incorporates generic_rustynet_prompt.md) ──
write_prompt() {
    local cycle="$1" area="$2" result="$3" report="$4" phase="$5" sha="$6"

    {
        printf '# Loop Cycle %s -- %s (%s)\n' "$cycle" "$area" "$result"
        printf '**Commit:** `%s` | **Phase:** %s | **Job:** `%s` | **Time:** %s\n\n' "$sha" "$phase" "$jid" "$(now_utc)"

        echo "## Current Run Metadata"
        printf -- '- Area: `%s`\n' "$area"
        printf -- '- Job record: `%s`\n' "$(job_record_path "$jid")"
        if [ -n "${CURRENT_ARGS_JSON:-}" ]; then
            echo "- Original deepseek_lab_run args:"
            printf '```json\n%s\n```\n' "$(printf '%s' "$CURRENT_ARGS_JSON" | python3 -m json.tool 2>/dev/null || printf '%s' "$CURRENT_ARGS_JSON")"
        fi
        echo ""

        echo "## Recent History"
        recent_history 5
        echo ""

        echo "## DeepSeek Report"
        printf '%s\n' "$report"
        echo ""
        echo "---"
        echo ""

        case "$result" in
            pass)
                cat << 'ENDPASS'
## Action - PASS (cell live-proven) — PROGRESS TO THE NEXT AREA

1. VERIFY the evidence (you, ~30s): confirm the row exists in
   live_lab_run_matrix.csv with overall_status + THIS cell PASS. Do not trust a
   green report without the matrix row.
2. SYNC docs: deepseek_doc_sync(change_summary="<role> proven live on <OS>",
   evidence="<run id / matrix row>"). Apply the reviewed edits only. Keep
   AGENTS.md and CLAUDE.md byte-mirrored; update the parity matrix cell
   (CrossPlatformRoleParityPlan) from ❌/🟡 to ✅.
3. PICK the next unproven cell: choose a role×OS still
   ❌/🟡 in the parity matrix. Prefer `deepseek_next_live_lab_target` because it
   returns exact supported `deepseek_lab_run` JSON. Do not re-run a green cell.
4. LAUNCH it — TEST ONLY THAT CELL, do not pay for the whole Linux lab:
   - mac/win cell:
       deepseek_lab_run(area="<role> <OS>", <OS>=true, <role>_platform=<OS>,
           <OS>_vm=..., exit_vm=..., client_vm=..., entry_vm=...,
           skip_linux_live_suite=true)
     skip_linux_live_suite=true runs setup + ONLY that mac/win cell, skipping the
     ~30-45min Linux live suite (already proven; re-running it is wasted time).
   - Linux cell:
       deepseek_lab_run(area="<role> linux", exit_platform=linux, ...)
     WITHOUT skip_linux_live_suite — there the Linux suite IS the cell.
   See scripts/loop/README.md for per-cell launch examples.
5. The auto_loop detects your launch and shepherds the next report. NEVER idle —
   keep exactly one run in flight at all times.
ENDPASS
                ;;
            fail)
    # Substitute REBUILD_ALIAS placeholder
    local rebuild_alias; rebuild_alias=$(rebuild_nodes_for "$area" 2>/dev/null || echo "")
    [ -z "$rebuild_alias" ] && rebuild_alias="unknown-node"
    local reverify_json; reverify_json="$(reverify_args_json "$area" "$rebuild_alias")"
                cat << 'ENDFAIL'
## Action - FAIL (needs patch)

### CRITICAL: DeepSeek output is UNTRUSTED
The triage report above proposes root cause + file:line + suspected fix.
DeepSeek proposes. YOU dispose. Every claim MUST be verified against the
real code before any patch. Use read_file, grep, find_definition to confirm
each cited file, function, and line actually says what the report claims.
The report may contain hallucinations. A single unverified claim applied
as a patch is a SECURITY INCIDENT.

### End-of-Run Protocol (from generic_rustynet_prompt.md section 1)
1. VERIFY the evidence (you, ~30s):
   - Confirm the matrix row exists in live_lab_run_matrix.csv.
   - VERIFY each cited claim against the real code with read_file and grep.
   - If any claim is wrong, discard it and do your own diagnosis.

2. PATCH the top finding (you, code + security judgment):
   - Security FIRST. Never weaken a control to make a stage pass.
   - Patch the root cause, not the symptom.
   - Follow AGENTS.md section 3 constraints: fail-closed, default-deny,
     no unwrap()/expect() in production paths, no TODO/FIXME placeholders.
   - Write tests that prove the fix where applicable.

3. GATE the fix:
   cargo run -p rustynet-xtask -- gates --affected
   (--affected scopes check/clippy/test to the changed crates + 1-hop dependents
   vs origin/main, incl. uncommitted; falls back to the full workspace if it
   cannot compute the set. Use plain `gates` for a security-sensitive change.)
   If gates fail: fix the root cause, re-gate. Never skip gates.

4. COMMIT and push:
   - Imperative mood, what AND why in the message.
   - Keep AGENTS.md and CLAUDE.md mirrored if you change either.

5. RE-LAUNCH the re-verify run — TEST ONLY WHAT YOU CHANGED.
   Use this exact JSON unless your patch touched a different node:
ENDFAIL
                printf '```json\n%s\n```\n' "$reverify_json"
                cat << 'ENDFAIL2'
   Call:
   deepseek_lab_run(<json above>)
   - skip_linux_live_suite=true SKIPS the entire ~30-45min Linux live suite
     (anchor/role-switch/exit-handoff/relay/two-hop/managed-dns/chaos). Setup
     (bootstrap + membership + signed-bundle distribution) STILL runs because the
     mac/win stages need the mesh — then ONLY the <role>_platform cell you patched
     runs. This is the minimal run that proves your fix.
   - rebuild_nodes redeploys code to ONLY the node you patched;
     the other nodes keep their daemon + state. Together with skip_linux_live_suite
     this is the fastest possible re-verify (~10-15min, not ~45min).
   - EXCEPTION: for a LINUX cell, do NOT pass skip_linux_live_suite — the Linux
     suite IS the cell under test there; use rebuild_nodes alone.
   - The auto_loop script will detect your relaunch and poll the result.

### Error type routing
- CODE defect (logic bug, missing cfg, bad parsing):
  -> Patch -> gate -> commit -> relaunch as above.
- ENV issue (VM down, SSH blocked, OOM, disk full):
  -> First call deepseek_reconcile_jobs(job_id="<job>") if a job looks stuck.
  -> Then call deepseek_recover_lab_environment(force=true) and poll
     deepseek_live_lab_result(job_id="<recovery job>").
  -> If unrecoverable after 3 attempts: write_loop_note the blocker,
     launch a DIFFERENT parity cell via deepseek_next_live_lab_target +
     deepseek_lab_run.
  -> NEVER loop on an unrecoverable env issue.
- UNKNOWN / insufficient triage:
  -> Run deepseek_live_lab with failure_context for a fresh triage.
  -> Ground-truth using deepseek_agent / report artifacts / daemon logs.
  -> Fan DeepSeek flash with deepseek_read("analyze this error...", context=...).
  -> If still blocked after 3 attempts: write_loop_note + switch cells.

### Launch timing
- The auto_loop script launched this run and waited for its report.
- Now you own the investigation and patch phase.
- Patch FIRST. Gate. Commit. THEN launch the re-verify run.
- Do NOT launch before the patch is committed.
- The re-verify run tests YOUR fix. Launch it with the patched code.
- After launching, the auto_loop detects it and polls the result.

### Division of Labor (from generic_rustynet_prompt.md section 0)
- YOU own: all code changes, the security call, gate decisions, commits.
- DeepSeek proposes: research, triage, doc edits. UNTRUSTED output, verify.
- The orchestrator owns: deterministic deploy/monitor. No LLM in that path.
ENDFAIL2
                ;;
            timeout)
                cat << 'ENDTIMEOUT'
## Action - TIMEOUT
Run exceeded the safety cap. Diagnose:
1. ps aux | grep rustynet-cli - is the orchestrator alive?
2. Run deepseek_reconcile_jobs(job_id="<job_id>"), then poll
   deepseek_live_lab_result(job_id="<job_id>") once more.
3. If stuck: deepseek_recover_lab_environment(force=true), then re-launch.
4. If progressing slowly: the build or a stage may be hung.
5. Pattern? The parity cell may need a lighter-weight test profile.
ENDTIMEOUT
                ;;
            *)
                cat << 'ENDUNKNOWN'
## Action - UNKNOWN
Unexpected result. Read the raw report. If setup failed: recover VMs,
re-launch. If the DeepSeek worker crashed: re-run deepseek_lab_run.
ENDUNKNOWN
                ;;
        esac

        echo ""
        echo "## Standing Orders (from generic_rustynet_prompt.md)"
        echo ""
        echo "### Absolute Rules"
        echo "- NEVER ask for confirmation. No 'should I?', 'let me know', 'I will wait'."
        echo "  You make every decision. The user is asleep."
        echo "- NEVER idle. A live-lab run MUST be in flight at every instant."
        echo "  The only valid exception is the ~5min session orientation."
        echo "- Security outranks everything. Fail closed on missing/invalid/stale"
        echo "  trust state. Default-deny all ACL/routes/trust flows. No unwrap()"
        echo "  or expect() in production paths. No custom crypto."
        echo "- DeepSeek output is UNTRUSTED. Every claim must be verified against"
        echo "  the real code before applying. DeepSeek never makes the security call."
        echo "- If you find a release-blocking security hole you cannot patch alone:"
        echo "  write_loop_note the finding, then CONTINUE WORKING on other cells."
        echo ""
        echo "### Launching the next run"
        echo "- After patching: gate, commit, relaunch deepseek_lab_run."
        echo "- For a mac/win re-verify: pass skip_linux_live_suite=true AND"
        echo "  rebuild_nodes=<patched_node> — runs setup + ONLY the patched cell,"
        echo "  skipping the ~30-45min Linux suite. Test only what changed."
        echo "- For a LINUX cell the Linux suite IS the test — do not skip it."
        echo "- If current cell is blocked on env: switch to another OS cell."
        echo "- Use deepseek_next_live_lab_target to see exact next-cell JSON."
        echo "- deepseek_lab_run auto-triages failures (flash then flash-verify then pro-review)."
        echo ""
        echo "### Goal"
        echo "- Prove EVERY node role on Linux AND macOS AND Windows."
        echo "- Nothing is done until the role x OS cell is green by live evidence."
        echo "- No OS may be a capability limiter."

    } > "$PROMPT"
    log "wrote $PROMPT ($(wc -c < "$PROMPT" | tr -d ' ') bytes)"
}
# ── AppleScript paste into Zed ───────────────────────────────────────
focus_zed_prompt_box() {
    osascript - "$PROMPT_CLICK_Y_OFFSET" "$PROMPT_CLICK_DELAY" <<'APPLESCRIPT' 2>/dev/null || return 1
on run argv
    set yOffset to (item 1 of argv) as integer
    set pauseSeconds to (item 2 of argv) as real
    tell application "Zed" to activate
    delay 0.8
    tell application "System Events"
        tell process "Zed"
            set frontmost to true
            if (count of windows) is 0 then return
            set {wx, wy} to position of window 1
            set {ww, wh} to size of window 1
            set clickX to wx + (ww div 2)
            set clickY to wy + wh - yOffset
            click at {clickX, clickY}
            delay pauseSeconds
            click at {clickX, clickY}
        end tell
    end tell
end run
APPLESCRIPT
}

# paste_zed [file]  — paste the given file (default: the per-cycle $PROMPT).
paste_zed() {
    local file="${1:-$PROMPT}"
    log "pasting into Zed ($file)..."
    pbcopy < "$file"
    if focus_zed_prompt_box; then
        log "focused Zed prompt box (${PROMPT_CLICK_Y_OFFSET}px above bottom, double-click)"
    else
        log "focus click failed; falling back to Cmd-V into active Zed window"
        osascript -e 'tell application "Zed" to activate' 2>/dev/null || true
        sleep 2
    fi
    osascript -e 'tell application "System Events" to tell process "Zed" to keystroke "v" using command down' 2>/dev/null || true
    sleep 0.5
    osascript -e 'tell application "System Events" to tell process "Zed" to keystroke return' 2>/dev/null || true
    log "paste done"
}

# ── detect new deepseek_lab_run job ───────────────────────────────────
detect_new_job() {
    local known="$1" waited=0
    log "waiting for agent to relaunch deepseek_lab_run..."
    while [ "$waited" -lt "$MAX_RELAUNCH_WAIT" ]; do
        sleep "$RELAUNCH_POLL"; waited=$((waited + RELAUNCH_POLL))
        [ ! -d "$JOBS_DIR" ] && continue
        local files
        files=$(ls -t "$JOBS_DIR"/labrun-*.json 2>/dev/null || true)
        for f in $files; do
            [ -f "$f" ] || continue
            local jid; jid=$(basename "$f" .json)
            if ! echo "$known" | grep -qF "$jid"; then
                local state; state=$(python3 -c "import json; print(json.load(open('$f')).get('state','?'))" 2>/dev/null || echo "?")
                if [ "$state" = "running" ] || [ "$state" = "done" ]; then
                    log "detected new job: $jid"
                    echo "$jid"; return 0
                fi
            fi
        done
        [ $((waited % 60)) -eq 0 ] && log "  waiting (${waited}s)..."
    done
    log "timeout — no relaunch detected"
    return 1
}

# ── poll deepseek_live_lab_result until report arrives ────────────────
poll_until_done() {
    local jid="$1" t0; t0=$(date +%s)
    log "polling $jid..."
    while true; do
        local r elapsed; elapsed=$(($(date +%s) - t0))
        # Bound the wait so an orphaned/hung re-verify can't spin forever overnight.
        if [ "$elapsed" -gt "$MAX_RUN_WAIT" ]; then
            log "poll of $jid exceeded ${MAX_RUN_WAIT}s — reconciling once before giving up"
            "$DRIVER" --bin "$BIN" --tool deepseek_reconcile_jobs \
                --args "{\"job_id\":\"$jid\"}" --no-poll >/dev/null 2>&1 || true
            r=$("$DRIVER" --bin "$BIN" --tool deepseek_live_lab_result \
                --args "{\"job_id\":\"$jid\"}" --no-poll 2>/dev/null || true)
            if [ -n "$r" ] && ! echo "$r" | grep -qi "still running"; then
                echo "$r"; return 0
            fi
            return 1
        fi
        if [ "$elapsed" -gt 0 ] && [ $((elapsed % 180)) -lt "$POLL" ]; then
            "$DRIVER" --bin "$BIN" --tool deepseek_reconcile_jobs \
                --args "{\"job_id\":\"$jid\"}" --no-poll >/dev/null 2>&1 || true
        fi
        r=$("$DRIVER" --bin "$BIN" --tool deepseek_live_lab_result \
            --args "{\"job_id\":\"$jid\"}" --no-poll 2>/dev/null) || { sleep "$POLL"; continue; }
        [ -z "$r" ] && { sleep "$POLL"; continue; }
        if echo "$r" | grep -qi "still running"; then
            [ $((elapsed % 120)) -lt "$POLL" ] && log "  [${elapsed}s] still running..."
            sleep "$POLL"; continue
        fi
        echo "$r"; return 0
    done
}

# ═══════════════════════════════════════════════════════════════════════
# Control model: the loop launches the FIRST run itself, then SHEPHERDS. Each
# cycle it classifies the latest report, pastes the action prompt into Zed, and
# waits for the AGENT to launch the NEXT run (a patch re-verify, or the next
# cell). It NEVER re-launches the same cell itself — doing so would spin forever
# on an already-passed cell and double-launch against the singleton gate. The
# agent owns every launch after the first; the loop turns each report into the
# next prompt and shepherds the agent's run to completion.
main() {
    local area="${1:?}"; shift
    local params=("$@")

    # Auto-enable skip_linux_live_suite for a mac/win area unless the operator set
    # it explicitly: re-proving the ~30-45min Linux live suite while iterating a
    # mac/win cell is wasted time. A Linux area keeps the suite (it IS the cell).
    local area_lower; area_lower=$(printf '%s' "$area" | tr '[:upper:]' '[:lower:]')
    local has_skip=""
    local has_triage=""
    for p in "${params[@]}"; do [ "${p%%=*}" = "skip_linux_live_suite" ] && has_skip=1; done
    for p in "${params[@]}"; do [ "${p%%=*}" = "triage_on_failure" ] && has_triage=1; done
    if [ -z "$has_skip" ] && printf '%s' "$area_lower" | grep -qE 'macos|windows'; then
        params+=("skip_linux_live_suite=true")
        log "auto-enabled skip_linux_live_suite=true for mac/win area '$area'"
    fi
    if [ -z "$has_triage" ] && [ "${OPENCODE_REVIEW_ON_FAIL:-1}" = "1" ]; then
        params+=("triage_on_failure=false")
        log "auto-disabled paid DeepSeek MCP triage; OpenCode report review handles failures"
    fi
    LAUNCH_PARAMS=("${params[@]}")  # global, used by rebuild_nodes_for()
    local args_json; args_json=$(build_args "$area" "${params[@]}")
    CURRENT_AREA="$area"
    CURRENT_ARGS_JSON="$args_json"
    local cycle=0

    mkdir -p "$JOBS_DIR" "$(dirname "$PROMPT")" "$(dirname "$HISTORY")"
    # Build + ATOMICALLY install the deepseek binary if missing. Never in-place
    # cp onto a running binary (truncates the mmap'd image and corrupts a live
    # server); cp to .new then mv -f is the atomic swap.
    [ -x "$BIN" ] || {
        log "building deepseek binary..."
        cargo build --release --bin rustynet-mcp-deepseek
        cp -f target/release/rustynet-mcp-deepseek "$BIN.new"
        mv -f "$BIN.new" "$BIN"
    }

    log "=== AUTO LOOP: $area ==="
    log "args: $args_json"

    # ── Orient the agent ONCE with the initial prompt (script-driven role) while
    #    the first run executes. Pastes the fenced prompt body from
    #    scripts/loop/initial_prompt.md if present; skip silently if absent. ──
    local init_src="$REPO/scripts/loop/initial_prompt.md"
    if [ -f "$init_src" ]; then
        local init_tmp; init_tmp="$(dirname "$PROMPT")/loop-initial-prompt.txt"
        awk '/^```/{f=!f; next} f' "$init_src" > "$init_tmp"
        [ -s "$init_tmp" ] || cp "$init_src" "$init_tmp"
        log "orienting agent with initial prompt"
        paste_zed "$init_tmp"
        sleep 3
    fi

    # ── Launch the FIRST run ourselves (blocking poll via drive_deepseek; the
    #    polling keeps the MCP server alive long enough for the detached
    #    orchestrator to spawn — never use --no-poll to launch). ──
    local jid="initial" report
    log "launching initial deepseek_lab_run..."
    report=$("$DRIVER" --bin "$BIN" --tool deepseek_lab_run \
        --args "$args_json" --poll-timeout "$MAX_RUN_WAIT" 2>&1) || {
        log "initial launch failed — retry once in 60s"; sleep 60
        report=$("$DRIVER" --bin "$BIN" --tool deepseek_lab_run \
            --args "$args_json" --poll-timeout "$MAX_RUN_WAIT" 2>&1) || {
            log "initial launch failed again — aborting"; return 1
        }
    }
    local parsed_jid; parsed_jid="$(printf '%s' "$report" | extract_job_id)"
    if [ -n "$parsed_jid" ]; then
        jid="$parsed_jid"
        refresh_current_context "$jid" "$area" "$args_json"
        area="$CURRENT_AREA"
        args_json="$CURRENT_ARGS_JSON"
    fi

    # ── Shepherd loop: classify -> prompt -> paste -> wait for the AGENT's next
    #    run -> poll it. The agent drives every launch from here on. ──
    while true; do
        cycle=$((cycle + 1))
        local sha; sha=$(git_sha)
        local result; result=$(classify "$report")
        local phase; if [ "$cycle" -eq 1 ]; then phase="initial"; else phase="reverify"; fi
        refresh_current_context "$jid" "$area" "$args_json"
        area="$CURRENT_AREA"
        args_json="$CURRENT_ARGS_JSON"
        log "=== CYCLE $cycle: $result (job=$jid, sha=$sha) ==="

        if [ "$result" = "fail" ]; then
            run_opencode_review_for_job "$jid"
            report="$(append_opencode_review_to_report "$jid" "$report")"
        fi

        record_history "$cycle" "$area" "$result" "$jid" "$sha"
        write_prompt "$cycle" "$area" "$result" "$report" "$phase" "$sha"

        # Snapshot known jobs BEFORE pasting, so the agent's post-paste launch is
        # guaranteed NEW (the agent only acts after reading the prompt).
        local known; known=$(ls "$JOBS_DIR"/labrun-*.json 2>/dev/null | xargs -n1 basename 2>/dev/null | sed 's/\.json//' | tr '\n' ' ' || true)
        paste_zed

        # Wait for the agent to launch the next run (patch re-verify, or next
        # cell). A timeout means the agent stalled — re-paste once as a nudge,
        # then keep waiting (do NOT re-launch the same cell ourselves).
        local new_jid
        if ! new_jid=$(detect_new_job "$known"); then
            log "no agent relaunch within ${MAX_RELAUNCH_WAIT}s — re-pasting as a nudge"
            paste_zed
            if ! new_jid=$(detect_new_job "$known"); then
                log "still no relaunch — agent may be mid-patch; keep waiting"
                continue
            fi
        fi
        jid="$new_jid"
        refresh_current_context "$jid" "$area" "$args_json"
        area="$CURRENT_AREA"
        args_json="$CURRENT_ARGS_JSON"

        # Poll the agent's run to completion; its report drives the next cycle.
        if ! report=$(poll_until_done "$new_jid"); then
            log "poll of $new_jid failed/timed out — re-pasting prompt and re-shepherding"
            report=$(printf '# Live-lab run `%s` — POLL TIMEOUT.\n\nThe re-verify run did not report within the cap. Check it: ps for the orchestrator, deepseek_reconcile_jobs, deepseek_live_lab_result(job_id="%s"). Recover or relaunch.' "$new_jid" "$new_jid")
        fi
    done
}

main "$@"
