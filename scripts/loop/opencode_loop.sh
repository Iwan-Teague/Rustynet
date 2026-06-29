#!/usr/bin/env bash
# scripts/loop/opencode_loop.sh
#
# OpenCode-backed unattended live-lab loop. This replaces GUI/Zed automation:
# the shell owns lab launch/poll/review state, and OpenCode owns the patching
# step in a durable terminal session.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && /bin/pwd -P)"
DRIVER="$REPO/scripts/mcp/drive_deepseek.py"
BIN="$REPO/bin/rustynet-mcp-deepseek"
JOBS_DIR="$REPO/state/deepseek-mcp-jobs"
STATE_DIR="$REPO/state/opencode-loop"
PROMPT="$STATE_DIR/main-prompt.md"
HISTORY="$STATE_DIR/history.jsonl"
MAIN_EVENTS="$STATE_DIR/main-agent-events.jsonl"
MAIN_STATUS="$STATE_DIR/main-agent-status.json"
MAIN_RUNS="$STATE_DIR/main-agent-runs.jsonl"
STOP_AFTER_CURRENT="$STATE_DIR/stop-after-current"

POLL="${OPENCODE_LOOP_POLL:-20}"
MAX_RUN_WAIT="${OPENCODE_LOOP_MAX_RUN_WAIT:-5400}"
MAX_AGENT_WAIT="${OPENCODE_LOOP_MAX_AGENT_WAIT:-7200}"
MAX_RELAUNCH_WAIT="${OPENCODE_LOOP_MAX_RELAUNCH_WAIT:-120}"
MAX_CYCLES="${OPENCODE_LOOP_MAX_CYCLES:-0}"
MAIN_NO_EDIT_TIMEOUT="${OPENCODE_LOOP_MAIN_NO_EDIT_TIMEOUT:-2700}"
MAIN_AGENT_RETRIES="${OPENCODE_LOOP_MAIN_AGENT_RETRIES:-2}"

OPENCODE_MAIN_MODEL="${OPENCODE_MAIN_MODEL:-deepseek/deepseek-v4-pro}"
OPENCODE_MAIN_VARIANT="${OPENCODE_MAIN_VARIANT:-max}"
OPENCODE_MAIN_AGENT="${OPENCODE_MAIN_AGENT:-rustynet-loop-main}"
OPENCODE_SESSION_ID="${OPENCODE_SESSION_ID:-}"
OPENCODE_ATTACH="${OPENCODE_ATTACH:-}"
OPENCODE_REVIEW_MODEL="${OPENCODE_REVIEW_MODEL:-opencode/deepseek-v4-flash-free}"
OPENCODE_REVIEW_ON_FAIL="${OPENCODE_REVIEW_ON_FAIL:-1}"
OPENCODE_LOOP_REPORT_INLINE_LIMIT="${OPENCODE_LOOP_REPORT_INLINE_LIMIT:-25000}"
OPENCODE_LOOP_REVIEW_INLINE_LIMIT="${OPENCODE_LOOP_REVIEW_INLINE_LIMIT:-25000}"

log() { printf '[OCLOOP %s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }
git_sha() { git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo "unknown"; }

load_deepseek_api_key() {
    local path key
    [ -n "${DEEPSEEK_API_KEY:-}" ] && return 0
    for path in "$HOME/Desktop/deepseek_api.md" "$HOME/.deepseek_api_key"; do
        [ -f "$path" ] || continue
        key="$(grep -Eo 'sk-[A-Za-z0-9_-]+' "$path" | head -1 || true)"
        if [ -n "$key" ]; then
            export DEEPSEEK_API_KEY="$key"
            return 0
        fi
    done
    return 0
}

usage() {
    cat >&2 <<'EOF'
Usage:
  scripts/loop/opencode_loop.sh start "macOS exit" key=value ...
  scripts/loop/opencode_loop.sh once  "macOS exit" key=value ...

Examples:
  OPENCODE_MAIN_MODEL='deepseek/deepseek-v4-pro' OPENCODE_MAIN_VARIANT=max \
  OPENCODE_REVIEW_MODEL='deepseek/deepseek-v4-flash' \
  scripts/loop/opencode_loop.sh start "macOS exit" \
    macos=true exit_platform=macos macos_vm=macos-utm-1 \
    exit_vm=debian-headless-1 client_vm=debian-headless-2 entry_vm=debian-headless-3

Env:
  OPENCODE_SESSION_ID              continue this main OpenCode session
  OPENCODE_MAIN_MODEL              default deepseek/deepseek-v4-pro
  OPENCODE_MAIN_VARIANT            default max
  OPENCODE_MAIN_AGENT              default rustynet-loop-main
  OPENCODE_ATTACH                  optional opencode server URL
  OPENCODE_REVIEW_MODEL            default opencode/deepseek-v4-flash-free
  OPENCODE_LOOP_MAX_CYCLES         0 = unlimited
  OPENCODE_LOOP_MAX_RUN_WAIT       default 5400s
  OPENCODE_LOOP_MAX_AGENT_WAIT     default 7200s
  OPENCODE_LOOP_MAX_RELAUNCH_WAIT  default 120s
  OPENCODE_LOOP_MAIN_NO_EDIT_TIMEOUT default 2700s, 0 disables
  OPENCODE_LOOP_MAIN_AGENT_RETRIES default 2
  OPENCODE_LOOP_REPORT_INLINE_LIMIT default 25000 bytes
  OPENCODE_LOOP_REVIEW_INLINE_LIMIT default 25000 bytes
  state/opencode-loop/stop-after-current requests graceful exit after current lab
EOF
}

validate_model_available() {
    local model="$1" label="$2"
    if ! opencode models 2>/dev/null | grep -Fxq "$model"; then
        log "$label model not visible to OpenCode: $model"
        log "visible models:"
        opencode models 2>/dev/null | sed 's/^/[OCLOOP model] /' >&2 || true
        log "Set ${label} model via OPENCODE_${label}_MODEL or configure provider before launching lab."
        return 1
    fi
}

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

is_labrun_id() {
    printf '%s' "$1" | grep -Eq '^labrun-[0-9]+-[0-9]+-[0-9]+$'
}

classify() {
    local report="$1"
    if echo "$report" | grep -qiE 'DRY-RUN wiring check'; then
        echo "dryrun"
    elif echo "$report" | grep -qiE 'The orchestration completed successfully|— PASS|: PASS|Overall status: \*\*pass\*\*'; then
        echo "pass"
    elif echo "$report" | grep -qiE 'FAIL → triage|FAIL -> triage|FAIL \(triage disabled\)|Overall status: \*\*fail\*\*|overall_status.*fail'; then
        echo "fail"
    elif echo "$report" | grep -qiE 'TIMED OUT after|still running|timed out after [0-9]|POLL TIMEOUT'; then
        echo "timeout"
    else
        echo "unknown"
    fi
}

trim_bytes() {
    local limit="$1"
    python3 -c '
import sys
limit = int(sys.argv[1])
text = sys.stdin.read()
raw = text.encode("utf-8")
if len(raw) <= limit:
    sys.stdout.write(text)
    raise SystemExit
head_len = max(limit // 2, 0)
tail_len = max(limit - head_len, 0)
head = raw[:head_len].decode("utf-8", errors="replace")
tail = raw[-tail_len:].decode("utf-8", errors="replace")
sys.stdout.write(head.rstrip())
sys.stdout.write("\n\n[truncated middle; read referenced report artifacts for full output]\n\n")
sys.stdout.write(tail.lstrip())
' "$limit"
}

sanitize_report() {
    sed -E '/^[[:space:]]*\[[0-9]+s\] Job `labrun-[^`]+` still running/d' | trim_bytes "$OPENCODE_LOOP_REPORT_INLINE_LIMIT"
}

sanitize_review() {
    trim_bytes "$OPENCODE_LOOP_REVIEW_INLINE_LIMIT"
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

known_jobs() {
    ls "$JOBS_DIR"/labrun-*.json 2>/dev/null | xargs -n1 basename 2>/dev/null | sed 's/\.json//' | tr '\n' ' ' || true
}

detect_new_job() {
    local known="$1" waited=0
    while [ "$waited" -lt "$MAX_RELAUNCH_WAIT" ]; do
        [ -d "$JOBS_DIR" ] || { sleep "$POLL"; waited=$((waited + POLL)); continue; }
        local files
        files=$(ls -t "$JOBS_DIR"/labrun-*.json 2>/dev/null || true)
        for f in $files; do
            [ -f "$f" ] || continue
            local jid state
            jid=$(basename "$f" .json)
            if ! echo "$known" | grep -qF "$jid"; then
                state=$(python3 -c "import json; print(json.load(open('$f')).get('state','?'))" 2>/dev/null || echo "?")
                if [ "$state" = "running" ] || [ "$state" = "done" ]; then
                    echo "$jid"
                    return 0
                fi
            fi
        done
        sleep "$POLL"
        waited=$((waited + POLL))
        [ $((waited % 120)) -eq 0 ] && log "waiting for OpenCode relaunch (${waited}s)..."
    done
    return 1
}

poll_until_done() {
    local jid="$1" t0
    t0=$(date +%s)
    log "polling $jid"
    while true; do
        local elapsed r
        elapsed=$(($(date +%s) - t0))
        if [ "$elapsed" -gt "$MAX_RUN_WAIT" ]; then
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
            local fallback
            fallback="$(local_completed_report "$jid" || true)"
            if [ -n "$fallback" ]; then
                echo "$fallback"; return 0
            fi
            [ $((elapsed % 120)) -lt "$POLL" ] && log "  [$elapsed s] still running"
            sleep "$POLL"; continue
        fi
        echo "$r"; return 0
    done
}

local_completed_report() {
    local jid="$1"
    python3 - "$REPO" "$JOBS_DIR" "$jid" <<'PY'
import json, os, pathlib, signal, sys
repo, jobs_dir, jid = sys.argv[1:4]
job_path = pathlib.Path(jobs_dir) / f"{jid}.json"
try:
    rec = json.loads(job_path.read_text())
except Exception:
    raise SystemExit(1)
report_dir = rec.get("report_dir")
if not report_dir:
    raise SystemExit(1)
report_path = pathlib.Path(report_dir)
if not report_path.is_absolute():
    report_path = pathlib.Path(repo) / report_path
result_path = report_path / "orchestration" / "orchestrate_result.json"
if not result_path.exists():
    raise SystemExit(1)
try:
    data = json.loads(result_path.read_text())
except Exception:
    raise SystemExit(1)
overall = str(data.get("overall_status") or "unknown").lower()
first_failed = None
for outcome in data.get("outcomes") or []:
    if str(outcome.get("status") or "").lower() == "fail":
        first_failed = outcome.get("stage")
        break
pid = rec.get("orchestrator_pid")
pid_note = ""
if isinstance(pid, int):
    try:
        os.kill(pid, 0)
        pid_note = f"Recorded orchestrator pid `{pid}` still exists; using completion artifact as source of truth."
    except ProcessLookupError:
        pid_note = f"Recorded orchestrator pid `{pid}` is gone; completion artifact is terminal."
    except PermissionError:
        pid_note = f"Recorded orchestrator pid `{pid}` exists but is not signalable; completion artifact is terminal."
failed = f"First failed stage: `{first_failed}`.\n" if first_failed else ""
print(
    f"# Live-lab run `{jid}` — LOCAL COMPLETION ARTIFACT\n\n"
    f"Overall status: **{overall}**.\n"
    f"{failed}\n"
    f"The job record was still `running`, but `{result_path}` exists. {pid_note}\n\n"
    f"Report dir: `{report_dir}`"
)
PY
}

run_lab() {
    local args_json="$1" report jid
    log "launching deepseek_lab_run: $args_json"
    report=$("$DRIVER" --bin "$BIN" --tool deepseek_lab_run \
        --args "$args_json" --poll-timeout "$MAX_RUN_WAIT" 2>&1) || {
        log "initial lab command failed"
        return 1
    }
    jid="$(printf '%s' "$report" | extract_job_id)"
    printf '%s\n%s\n' "$jid" "$report"
}

review_path_for() {
    printf '%s/state/opencode-report-reviews/%s/report-review.md\n' "$REPO" "$1"
}

run_review_if_needed() {
    local jid="$1" result="$2"
    [ "$result" = "fail" ] || return 0
    [ "$OPENCODE_REVIEW_ON_FAIL" = "1" ] || return 0
    OPENCODE_REVIEW_MODEL="$OPENCODE_REVIEW_MODEL" \
        "$REPO/scripts/loop/opencode_report_review.sh" --job-id "$jid" --wait
}

reverify_json() {
    local area="$1" args_json="$2"
    python3 - "$area" "$args_json" <<'PY'
import json, sys
area, raw = sys.argv[1:3]
try:
    args = json.loads(raw)
except Exception:
    args = {"area": area}
args.setdefault("area", area)
args["triage_on_failure"] = False
lower = args["area"].lower()
if "linux" not in lower or "macos" in lower or "windows" in lower:
    args["skip_linux_live_suite"] = True
if not args.get("rebuild_nodes"):
    wants_macos = (
        args.get("macos")
        or args.get("macos_promote_exit")
        or any(str(args.get(k, "")).lower() == "macos" for k in (
            "exit_platform", "relay_platform", "anchor_platform",
            "blind_exit_platform", "admin_platform",
        ))
        or "macos" in lower
    )
    wants_windows = (
        args.get("windows")
        or args.get("windows_only")
        or any(str(args.get(k, "")).lower() == "windows" for k in (
            "exit_platform", "relay_platform", "anchor_platform",
            "blind_exit_platform", "admin_platform",
        ))
        or "windows" in lower
    )
    if wants_macos and args.get("macos_vm"):
        args["rebuild_nodes"] = args["macos_vm"]
    elif wants_windows and args.get("windows_vm"):
        args["rebuild_nodes"] = args["windows_vm"]
print(json.dumps(args, indent=2, sort_keys=True))
PY
}

write_history() {
    local cycle="$1" jid="$2" area="$3" result="$4"
    if ! is_labrun_id "$jid"; then
        local extracted
        extracted="$(printf '%s' "$jid" | extract_job_id)"
        if is_labrun_id "$extracted"; then
            jid="$extracted"
        else
            log "refusing to write invalid job id to history: ${jid:0:80}"
            jid="invalid-job-id"
        fi
    fi
    python3 - "$HISTORY" "$cycle" "$(now_utc)" "$jid" "$area" "$result" "$(git_sha)" <<'PY'
import json, sys
path, cycle, at, jid, area, result, sha = sys.argv[1:8]
with open(path, "a", encoding="utf-8") as f:
    f.write(json.dumps({
        "cycle": int(cycle), "at": at, "job": jid, "area": area,
        "result": result, "sha": sha,
    }, separators=(",", ":")) + "\n")
PY
}

write_main_prompt() {
    local cycle="$1" jid="$2" area="$3" args_json="$4" result="$5" report="$6" review_path="$7"
    local exact_reverify report_dir orchestrate_result run_summary stage_logs evidence_dir clean_report clean_review
    exact_reverify="$(reverify_json "$area" "$args_json")"
    report_dir="$(job_field "$jid" report_dir "$REPO/state/deepseek-lab-$jid")"
    orchestrate_result="$report_dir/orchestration/orchestrate_result.json"
    run_summary="$report_dir/run_summary.md"
    stage_logs="$report_dir/logs"
    evidence_dir="$report_dir/macos_exit_evidence"
    clean_report="$(printf '%s\n' "$report" | sanitize_report)"
    if [ -s "$review_path" ]; then
        clean_review="$(sanitize_review < "$review_path")"
    else
        clean_review=""
    fi
    {
        printf '# Rustynet OpenCode Loop Cycle %s\n\n' "$cycle"
        printf -- '- Job: `%s`\n' "$jid"
        printf -- '- Area: `%s`\n' "$area"
        printf -- '- Result: `%s`\n' "$result"
        printf -- '- Commit: `%s`\n' "$(git_sha)"
        printf -- '- Time: `%s`\n\n' "$(now_utc)"
        printf -- '- Report dir: `%s`\n' "$report_dir"
        printf -- '- Orchestrate result: `%s`\n' "$orchestrate_result"
        printf -- '- Run summary: `%s`\n' "$run_summary"
        printf -- '- Stage logs: `%s`\n' "$stage_logs"
        printf -- '- Evidence dir: `%s`\n\n' "$evidence_dir"

        cat <<'EOF'
## Role
You are the main Rustynet live-lab loop agent running in OpenCode with DeepSeek
v4 Pro max reasoning. The shell loop owns lab launch/poll/review orchestration.
You own code changes, security judgment, gates, commits, and relaunching the next
focused `deepseek_lab_run`.

## Hard Rules
- Do not ask the user. The user is asleep.
- Verify every claim against repo/log evidence before patching.
- Security first: fail closed, default deny, no control weakening, no custom crypto.
- Patch root cause, not symptom.
- Run focused gates. Commit. Then relaunch `deepseek_lab_run`.
- Use `triage_on_failure=false`; OpenCode Flash review handles report summarizing.
- Stay focused: read listed artifacts first, then patch smallest verified root cause.
- Do not run host-only probes (`sudo`, `pfctl`, GUI commands) from the main agent.
- Tool budget: read the listed report artifacts, then at most 8 targeted source
  files before deciding. Do not keep broad-grepping once the failing stage and
  candidate owner file are known.
- Progress contract: make a real repo edit or launch a new `labrun-*` before
  the no-edit watchdog expires. If no code/docs patch is justified, write the
  exact evidence and relaunch the focused lab with `rebuild_nodes` to rule out a
  stale guest binary.
- If the Flash review is wrong, write the corrected root-cause note into your
  final answer, then patch the verified issue. Do not stop at analysis.
- A successful cycle must create one of these before exit: a new `labrun-*` job,
  or an explicit committed patch plus a command that failed to relaunch.
- Before launching the next lab, verify the current role x OS cell in
  live_lab_run_matrix.csv. If it is proven green, pick a different failed or
  unproven cell. Never repeat a proven cell unless doing an explicitly justified
  regression recheck after a related patch.

EOF

        echo "## Original deepseek_lab_run Args"
        printf '```json\n%s\n```\n\n' "$(printf '%s' "$args_json" | python3 -m json.tool 2>/dev/null || printf '%s' "$args_json")"

        echo "## Lab Report"
        printf '%s\n\n' "$clean_report"

        if [ -n "$clean_review" ]; then
            echo "## OpenCode Flash Review"
            printf 'Review file: `%s`\n\n' "$review_path"
            printf '%s\n' "$clean_review"
            echo ""
        fi

        case "$result" in
            pass)
                cat <<'EOF'
## Required Action: PASS
1. Verify live_lab_run_matrix.csv row exists and this cell is actually green.
2. Apply docs sync if needed.
3. Pick next unproven role x OS cell using `deepseek_next_live_lab_target`.
4. Launch the next `deepseek_lab_run` with `triage_on_failure=false`.
EOF
                ;;
            dryrun)
                cat <<'EOF'
## Required Action: DRY-RUN
Dry-run proves the launch/poll/report wiring only. It is not live evidence.
Launch the real focused `deepseek_lab_run` for the same area with
`dry_run=false` and `triage_on_failure=false`, or pick the next required live
cell if this was only a harness smoke.
EOF
                ;;
            fail)
                cat <<EOF
## Required Action: FAIL
1. Verify the Flash review and lab artifacts.
2. Patch the root cause.
3. Run focused gates.
4. Commit.
5. Relaunch a focused reverify run. Start from this JSON. It includes
   \`rebuild_nodes\` when the target guest can be derived; keep it unless the
   patched node is different:

\`\`\`json
$exact_reverify
\`\`\`
EOF
                ;;
            timeout|unknown)
                cat <<EOF
## Required Action: $result
1. Call deepseek_reconcile_jobs(job_id="$jid").
2. If lab env is stuck, call deepseek_recover_lab_environment(force=true).
3. Relaunch or switch cells only after evidence says it is safe.
EOF
                ;;
        esac
    } > "$PROMPT"
}

event_tool_count() {
    local tool="$1"
    python3 - "$MAIN_EVENTS" "$tool" <<'PY'
import json, pathlib, sys
path, wanted = pathlib.Path(sys.argv[1]), sys.argv[2]
count = 0
try:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
except FileNotFoundError:
    lines = []
for line in lines:
    try:
        obj = json.loads(line)
    except Exception:
        continue
    if obj.get("type") != "tool_use":
        continue
    part = obj.get("part") or {}
    name = obj.get("tool") or obj.get("name") or part.get("tool")
    if name == wanted:
        count += 1
print(count)
PY
}

detect_new_job_now() {
    local known="$1"
    [ -d "$JOBS_DIR" ] || return 1
    local f jid state
    for f in "$JOBS_DIR"/labrun-*.json; do
        [ -f "$f" ] || continue
        jid=$(basename "$f" .json)
        if ! echo "$known" | grep -qF "$jid"; then
            state=$(python3 -c "import json; print(json.load(open('$f')).get('state','?'))" 2>/dev/null || echo "?")
            if [ "$state" = "running" ] || [ "$state" = "done" ]; then
                printf '%s\n' "$jid"
                return 0
            fi
        fi
    done
    return 1
}

mark_main_status() {
    local state="$1" exit_code="$2" extra_key="${3:-}" extra_value="${4:-}"
    python3 - "$MAIN_STATUS" "$MAIN_EVENTS" "$MAIN_RUNS" "$state" "$exit_code" "$(now_utc)" "$extra_key" "$extra_value" <<'PY'
import json, pathlib, sys, time
path, events, runs, state, exit_code, finished, extra_key, extra_value = sys.argv[1:9]
try:
    data = json.load(open(path))
except Exception:
    data = {}
stats = {"tokens_total": 0, "tokens_input": 0, "tokens_output": 0, "tokens_reasoning": 0, "tokens_cache_read": 0, "tokens_cache_write": 0, "cost": 0.0}
events_path = pathlib.Path(events)
if events_path.exists():
    for line in events_path.read_text(errors="replace").splitlines():
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if ev.get("type") != "step_finish":
            continue
        tokens = ((ev.get("part") or {}).get("tokens") or {})
        cache = tokens.get("cache") or {}
        stats["tokens_total"] += int(tokens.get("total") or 0)
        stats["tokens_input"] += int(tokens.get("input") or 0)
        stats["tokens_output"] += int(tokens.get("output") or 0)
        stats["tokens_reasoning"] += int(tokens.get("reasoning") or 0)
        stats["tokens_cache_read"] += int(cache.get("read") or 0)
        stats["tokens_cache_write"] += int(cache.get("write") or 0)
        stats["cost"] += float((ev.get("part") or {}).get("cost") or 0.0)
data.update({
    "state": state,
    "exit_code": int(exit_code),
    "finished": finished,
    "finished_unix": int(time.time()),
    **stats,
})
if extra_key:
    data[extra_key] = extra_value
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
run = dict(data)
run["recorded_unix"] = int(time.time())
with open(runs, "a", encoding="utf-8") as f:
    json.dump(run, f, separators=(",", ":"))
    f.write("\n")
PY
}

prepend_retry_instruction() {
    local attempt="$1" tmp="$PROMPT.tmp"
    {
        printf '# Watchdog Retry %s\n\n' "$attempt"
        cat <<'EOF'
Previous OpenCode main-agent attempt ended without a timely edit or lab relaunch.
Do not restart broad discovery. Use the failure report, review, and listed
artifacts already below. Within the first 12 tool calls, do one of:
- edit the verified root-cause file,
- or relaunch the focused `deepseek_lab_run` with the provided JSON and
  `rebuild_nodes` if evidence says the guest binary was stale.

EOF
        cat "$PROMPT"
    } > "$tmp"
    mv "$tmp" "$PROMPT"
}

run_main_agent() {
    local known="$1" t0 rc pid
    t0=$(date +%s)
    python3 - "$MAIN_STATUS" "$(now_utc)" "$PROMPT" "$MAIN_EVENTS" \
        "$OPENCODE_MAIN_MODEL" "$OPENCODE_MAIN_VARIANT" "$OPENCODE_MAIN_AGENT" "$OPENCODE_SESSION_ID" <<'PY'
import json, sys, time
path, started, prompt, events, model, variant, agent, session_id = sys.argv[1:9]
with open(path, "w", encoding="utf-8") as f:
    json.dump({
        "state": "running",
        "started": started,
        "started_unix": int(time.time()),
        "prompt": prompt,
        "events": events,
        "model": model,
        "variant": variant,
        "opencode_agent": agent,
        "session_id": session_id,
        "harness": "opencode",
    }, f, indent=2)
    f.write("\n")
PY
    : > "$MAIN_EVENTS"
    local args=(run "Continue the Rustynet live-lab loop using the attached prompt. Patch/gate/commit, then launch the next focused deepseek_lab_run. Do not stop at analysis." --model "$OPENCODE_MAIN_MODEL" --variant "$OPENCODE_MAIN_VARIANT" --format json --file "$PROMPT")
    [ -n "$OPENCODE_SESSION_ID" ] && args+=(--session "$OPENCODE_SESSION_ID")
    [ -n "$OPENCODE_MAIN_AGENT" ] && args+=(--agent "$OPENCODE_MAIN_AGENT")
    [ -n "$OPENCODE_ATTACH" ] && args+=(--attach "$OPENCODE_ATTACH")
    log "starting OpenCode main agent: model=$OPENCODE_MAIN_MODEL variant=$OPENCODE_MAIN_VARIANT events=$MAIN_EVENTS"
    (
        set +e
        opencode "${args[@]}" 2>&1 | tee "$MAIN_EVENTS" >&2
        exit "${PIPESTATUS[0]}"
    ) &
    pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        local elapsed
        elapsed="$(($(date +%s) - t0))"
        if [ "$MAIN_NO_EDIT_TIMEOUT" -gt 0 ] && [ "$elapsed" -gt "$MAIN_NO_EDIT_TIMEOUT" ]; then
            local edit_count launched
            edit_count="$(event_tool_count edit)"
            launched="$(detect_new_job_now "$known" || true)"
            if [ "$edit_count" = "0" ] && [ -z "$launched" ]; then
                log "OpenCode main agent no-edit watchdog fired after ${elapsed}s; terminating pid=$pid"
                kill "$pid" 2>/dev/null || true
                sleep 2
                kill -9 "$pid" 2>/dev/null || true
                wait "$pid" 2>/dev/null || true
                mark_main_status "no_edit_timeout" 124 "elapsed_secs" "$elapsed"
                return 3
            fi
        fi
        if [ "$elapsed" -gt "$MAX_AGENT_WAIT" ]; then
            log "OpenCode main agent exceeded ${MAX_AGENT_WAIT}s; terminating pid=$pid"
            kill "$pid" 2>/dev/null || true
            sleep 2
            kill -9 "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            return 1
        fi
        sleep 5
    done
    set +e
    wait "$pid"
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
        log "OpenCode main agent exited rc=$rc"
        mark_main_status "failed" "$rc"
        return "$rc"
    fi
    local detected
    if detected="$(detect_new_job "$known")"; then
        mark_main_status "done" 0 "launched_job" "$detected"
        printf '%s\n' "$detected"
        return 0
    fi
    mark_main_status "no_relaunch" 0
    return 1
}

main() {
    local cmd="${1:-}"; shift || true
    case "$cmd" in
        start|once) ;;
        -h|--help|"") usage; exit 0 ;;
        *) usage; exit 2 ;;
    esac
    local area="${1:?missing area}"; shift
    local params=("$@")

    local area_lower has_skip="" has_triage=""
    area_lower=$(printf '%s' "$area" | tr '[:upper:]' '[:lower:]')
    local normalized=() saw_macos_exit_platform="" has_macos_promote="" has_macos_flag="" has_legacy=""
    for p in "${params[@]}"; do
        case "$p" in
            exit_platform=macos)
                if printf '%s' "$area_lower" | grep -q 'macos' && printf '%s' "$area_lower" | grep -q 'exit'; then
                    saw_macos_exit_platform=1
                    continue
                fi
                ;;
            macos_promote_exit=*) has_macos_promote=1 ;;
            macos=*) has_macos_flag=1 ;;
            legacy_bash=*) has_legacy=1 ;;
        esac
        normalized+=("$p")
    done
    params=("${normalized[@]}")
    if [ -n "$saw_macos_exit_platform" ]; then
        log "normalized macOS exit selector: exit_platform=macos -> macos_promote_exit=true (keeps Linux exit backbone)"
        [ -n "$has_macos_promote" ] || params+=("macos_promote_exit=true")
        [ -n "$has_macos_flag" ] || params+=("macos=true")
        [ -n "$has_legacy" ] || params+=("legacy_bash=true")
    fi
    for p in "${params[@]}"; do [ "${p%%=*}" = "skip_linux_live_suite" ] && has_skip=1; done
    for p in "${params[@]}"; do [ "${p%%=*}" = "triage_on_failure" ] && has_triage=1; done
    if [ -z "$has_skip" ] && printf '%s' "$area_lower" | grep -qE 'macos|windows'; then
        params+=("skip_linux_live_suite=true")
    fi
    [ -n "$has_triage" ] || params+=("triage_on_failure=false")

    mkdir -p "$STATE_DIR" "$JOBS_DIR"
    rm -f "$STOP_AFTER_CURRENT"
    load_deepseek_api_key
    validate_model_available "$OPENCODE_REVIEW_MODEL" "REVIEW"
    validate_model_available "$OPENCODE_MAIN_MODEL" "MAIN"
    local args_json cycle=0 jid report result current_area current_args review_path new_jid
    args_json=$(build_args "$area" "${params[@]}")

    local run_out
    run_out="$(run_lab "$args_json")"
    jid="$(printf '%s\n' "$run_out" | sed -n '1p')"
    report="$(printf '%s\n' "$run_out" | sed '1d')"
    [ -n "$jid" ] || jid="$(printf '%s' "$report" | extract_job_id)"

    while true; do
        cycle=$((cycle + 1))
        current_area="$(job_field "$jid" area "$area")"
        current_args="$(job_field "$jid" request_args "$args_json")"
        result="$(classify "$report")"
        review_path="$(review_path_for "$jid")"
        log "cycle=$cycle job=$jid area=$current_area result=$result"
        write_history "$cycle" "$jid" "$current_area" "$result"
        run_review_if_needed "$jid" "$result" || log "review failed; continuing"
        write_main_prompt "$cycle" "$jid" "$current_area" "$current_args" "$result" "$report" "$review_path"

        if [ -f "$STOP_AFTER_CURRENT" ]; then
            log "stop-after-current requested; exiting after completed job $jid"
            rm -f "$STOP_AFTER_CURRENT"
            exit 0
        fi

        [ "$cmd" = "once" ] && {
            log "once mode wrote prompt: $PROMPT"
            exit 0
        }
        [ "$MAX_CYCLES" -gt 0 ] && [ "$cycle" -ge "$MAX_CYCLES" ] && {
            log "max cycles reached: $MAX_CYCLES"
            exit 0
        }

        local known agent_attempt
        known="$(known_jobs)"
        new_jid=""
        agent_attempt=1
        while [ "$agent_attempt" -le "$MAIN_AGENT_RETRIES" ]; do
            if new_jid="$(run_main_agent "$known")"; then
                break
            fi
            log "main agent attempt $agent_attempt did not launch a new lab"
            agent_attempt=$((agent_attempt + 1))
            if [ "$agent_attempt" -le "$MAIN_AGENT_RETRIES" ]; then
                prepend_retry_instruction "$agent_attempt"
                log "retrying OpenCode main agent with watchdog prompt"
            fi
        done
        if [ -z "$new_jid" ]; then
            log "main agent did not launch a new lab after ${MAIN_AGENT_RETRIES} attempt(s); prompt remains at $PROMPT"
            exit 1
        fi
        jid="$new_jid"
        if ! report="$(poll_until_done "$jid")"; then
            report=$(printf '# Live-lab run `%s` — POLL TIMEOUT.\n\nRun deepseek_reconcile_jobs and recover before relaunching.' "$jid")
        fi
    done
}

main "$@"
