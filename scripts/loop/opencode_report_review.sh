#!/usr/bin/env bash
# scripts/loop/opencode_report_review.sh
#
# Launch a separate OpenCode terminal worker to review one completed live-lab
# failure report. The worker is read-only: it summarizes evidence and proposes
# likely root cause/fix direction, but does not patch, gate, commit, or launch
# another lab.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && /bin/pwd -P)"
JOBS_DIR="$REPO/state/deepseek-mcp-jobs"
REVIEWS_DIR="$REPO/state/opencode-report-reviews"

JOB_ID=""
REPORT_DIR=""
AREA=""
DRY_RUN=0

# opencode/deepseek-v4-flash-free (OpenCode's hosted free-tier proxy) is
# confirmed to hang indefinitely with zero output when invoked headlessly --
# never default to it. deepseek-direct/* is the confirmed-working provider.
OPENCODE_REVIEW_MODEL="${OPENCODE_REVIEW_MODEL:-deepseek-direct/deepseek-v4-flash}"
OPENCODE_REVIEW_AGENT="${OPENCODE_REVIEW_AGENT:-rustynet-report-review}"
OPENCODE_ATTACH="${OPENCODE_ATTACH:-}"
OPENCODE_TMUX_SESSION="${OPENCODE_TMUX_SESSION:-rustynet-loop}"
OPENCODE_MAIN_SESSION_ID="${OPENCODE_MAIN_SESSION_ID:-}"
OPENCODE_MAIN_MODEL="${OPENCODE_MAIN_MODEL:-deepseek/deepseek-v4-pro}"
OPENCODE_MAIN_VARIANT="${OPENCODE_MAIN_VARIANT:-max}"
OPENCODE_REVIEW_INLINE_LIMIT="${OPENCODE_REVIEW_INLINE_LIMIT:-60000}"
OPENCODE_REVIEW_WAIT_MAX="${OPENCODE_REVIEW_WAIT_MAX:-900}"

log() { printf '[OPENREVIEW %s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }

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
  scripts/loop/opencode_report_review.sh --job-id labrun-... [--report-dir state/deepseek-lab-...] [--area "macOS exit"] [--dry-run] [--wait] [--no-tmux]

Env:
  OPENCODE_REVIEW_MODEL      review model (default: deepseek-direct/deepseek-v4-flash)
  OPENCODE_REVIEW_AGENT      OpenCode agent name (default: rustynet-report-review)
  OPENCODE_ATTACH            optional OpenCode server URL for `opencode run --attach`
  OPENCODE_TMUX_SESSION      tmux session to open/reuse (default: rustynet-loop)
  OPENCODE_MAIN_SESSION_ID   optional main OpenCode session to wake after review
  OPENCODE_MAIN_MODEL        main model for wake message (default: deepseek/deepseek-v4-pro)
  OPENCODE_MAIN_VARIANT      main model variant (default: max)
  OPENCODE_REVIEW_INLINE_LIMIT bytes of review to inline in wake prompt (default: 60000)
  OPENCODE_REVIEW_WAIT_MAX   --wait cap in seconds (default: 900)
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --job-id)
            JOB_ID="${2:?missing --job-id value}"; shift 2 ;;
        --report-dir)
            REPORT_DIR="${2:?missing --report-dir value}"; shift 2 ;;
        --area)
            AREA="${2:?missing --area value}"; shift 2 ;;
        --dry-run)
            DRY_RUN=1; shift ;;
        --wait)
            WAIT=1; shift ;;
        --no-tmux)
            NO_TMUX=1; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            if [ -z "$JOB_ID" ]; then JOB_ID="$1"; shift; else usage; exit 2; fi ;;
    esac
done

WAIT="${WAIT:-0}"
NO_TMUX="${NO_TMUX:-0}"

[ -n "$JOB_ID" ] || { usage; exit 2; }

job_record="$JOBS_DIR/$JOB_ID.json"
if [ -f "$job_record" ]; then
    REPORT_DIR="${REPORT_DIR:-$(python3 - "$job_record" <<'PY'
import json, sys
try:
    print(json.load(open(sys.argv[1])).get("report_dir", ""))
except Exception:
    print("")
PY
)}"
    AREA="${AREA:-$(python3 - "$job_record" <<'PY'
import json, sys
try:
    print(json.load(open(sys.argv[1])).get("area", ""))
except Exception:
    print("")
PY
)}"
fi

[ -n "$REPORT_DIR" ] || REPORT_DIR="state/deepseek-lab-$JOB_ID"
[ -n "$AREA" ] || AREA="unknown live-lab area"

review_dir="$REVIEWS_DIR/$JOB_ID"
prompt="$review_dir/report-review-prompt.md"
output="$review_dir/report-review.md"
events="$review_dir/opencode-events.jsonl"
status="$review_dir/status.json"
worker="$review_dir/run_review.sh"
wake_prompt="$REPO/state/opencode-main-wake-prompt.md"

mkdir -p "$review_dir"

orchestrate_result="$REPORT_DIR/orchestration/orchestrate_result.json"
run_summary="$REPORT_DIR/run_summary.md"
matrix_row="$REPORT_DIR/state/live_lab_run_matrix_row.csv"
failed_stage="$(python3 - "$orchestrate_result" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except Exception:
    print("")
    raise SystemExit
for key in ("first_failed_stage", "failed_stage"):
    if data.get(key):
        print(data[key])
        raise SystemExit
for stage in data.get("stages", []) + data.get("outcomes", []):
    status = str(stage.get("status", "")).lower()
    if status and status not in {"pass", "passed", "ok", "skipped"}:
        print(stage.get("name") or stage.get("stage") or "")
        raise SystemExit
print("")
PY
)"

cat > "$prompt" <<EOF
# Rustynet Live-Lab Report Review

You are an OpenCode report-review worker for Rustynet. Use model context and repo
tools to review this completed live-lab run. You are READ-ONLY.

## Hard Boundaries
- Do NOT edit files.
- Do NOT run gates.
- Do NOT commit or push.
- Do NOT launch another live lab.
- Do NOT call paid AI-agent MCP proxy/triage tools unless the prompt explicitly says so.
- Your output is UNTRUSTED advisory material. The main v4-pro loop agent will verify every claim.

## Target
- Job: \`$JOB_ID\`
- Area: \`$AREA\`
- Report dir: \`$REPORT_DIR\`
- Failed stage hint: \`${failed_stage:-unknown}\`
- Job record: \`$job_record\`
- Orchestrate result: \`$orchestrate_result\`
- Run summary: \`$run_summary\`
- Matrix row: \`$matrix_row\`

## Required Work
1. Read the report artifacts above if present.
2. Identify the first failed stage and the exact failure message.
3. Inspect the relevant stage log(s), evidence JSON, and nearby repo code.
4. Separate CODE defect from ENV issue from UNKNOWN.
5. Cite every claim with file/log paths and line numbers when available.
6. Propose the smallest safe fix direction without weakening security controls.
7. Propose the focused reverify \`ai_lab_run\` JSON if enough info exists.

## Budget
- First read: orchestrate result, failed stage log, direct evidence JSON.
- Then read at most 3 targeted source files unless evidence is contradictory.
- Do not broad-grep the repo unless direct artifacts do not identify code.
- Output only the markdown report below. No raw tool output. No preamble.

## Output Format

# OpenCode Report Review: $JOB_ID

Verdict: code | env | unknown | pass | timeout
Area:
First failed stage:
Confidence: low | medium | high

## Evidence Read
- path: finding

## Confirmed Facts
- fact with citation

## Likely Root Cause
Short explanation with citation.

## Suspected Code / Config
- path:line or artifact path

## Safe Fix Direction
Concrete patch direction. Do not include huge diffs.

## Focused Reverify
JSON:
{ "area": "...", "triage_on_failure": false }

## Warnings / Blockers
- anything uncertain or unsafe
EOF

python3 - "$status" "$JOB_ID" "$AREA" "$REPORT_DIR" "$prompt" "$output" \
    "$OPENCODE_REVIEW_MODEL" "$OPENCODE_REVIEW_AGENT" "$OPENCODE_TMUX_SESSION" <<'PY'
import json, sys, time
path, job_id, area, report_dir, prompt, output, model, agent, tmux_session = sys.argv[1:10]
with open(path, "w", encoding="utf-8") as f:
    json.dump({
        "state": "prepared",
        "job_id": job_id,
        "area": area,
        "report_dir": report_dir,
        "prompt": prompt,
        "output": output,
        "model": model,
        "opencode_agent": agent,
        "tmux_session": tmux_session,
        "harness": "opencode",
        "prepared_unix": int(time.time()),
    }, f, indent=2)
    f.write("\n")
PY

cat > "$worker" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "$REPO"
echo "[OpenCode review] job=$JOB_ID area=$AREA"
echo "[OpenCode review] prompt=$prompt"
python3 - "$status" <<'PY'
import json, sys, time
path = sys.argv[1]
data = json.load(open(path))
data["state"] = "running"
data["started_unix"] = int(time.time())
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\\n")
PY
args=(run "Review this Rustynet live-lab failure report. Produce the requested markdown report only." --model "$OPENCODE_REVIEW_MODEL" --format json --file "$prompt")
if [ -n "$OPENCODE_REVIEW_AGENT" ]; then args+=(--agent "$OPENCODE_REVIEW_AGENT"); fi
if [ -n "$OPENCODE_ATTACH" ]; then args+=(--attach "$OPENCODE_ATTACH"); fi
set +e
opencode "\${args[@]}" 2>&1 | tee "$events"
rc=\${PIPESTATUS[0]}
set -e
python3 - "$events" "$output" <<'PY'
import json, pathlib, sys
events = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
chunks = []
if events.exists():
    for line in events.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            chunks.append(line)
            continue
        if ev.get("type") == "text":
            part = ev.get("part")
            if isinstance(part, dict) and part.get("type") == "text":
                text = part.get("text")
                if isinstance(text, str) and text.strip():
                    chunks.append(text)
                    continue
        if ev.get("type") == "message":
            msg = ev.get("message")
            if isinstance(msg, dict):
                for part in msg.get("parts", []):
                    if isinstance(part, dict) and part.get("type") == "text":
                        text = part.get("text")
                        if isinstance(text, str) and text.strip():
                            chunks.append(text)
text = "\\n".join(c for c in chunks if c.strip()).strip()
marker = "# OpenCode Report Review:"
if marker in text:
    text = text[text.index(marker):].strip()
if not text:
    text = "No assistant markdown text found in OpenCode JSON events. Inspect raw events: " + str(events)
out.write_text(text + ("\\n" if text else ""), encoding="utf-8")
PY
python3 - "$status" "$events" "\$rc" <<'PY'
import json, pathlib, sys, time
path, events, rc = sys.argv[1], sys.argv[2], int(sys.argv[3])
data = json.load(open(path))
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
data["state"] = "done" if rc == 0 else "failed"
data["exit_code"] = rc
data["finished_unix"] = int(time.time())
data.update(stats)
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\\n")
PY
python3 - "$wake_prompt" "$output" "$status" "$JOB_ID" "$AREA" "$REPORT_DIR" "$OPENCODE_REVIEW_INLINE_LIMIT" <<'PY'
import pathlib, sys
wake, output, status, job_id, area, report_dir, limit_s = sys.argv[1:8]
limit = int(limit_s)
review_path = pathlib.Path(output)
review = review_path.read_text(errors="replace") if review_path.exists() else ""
if len(review.encode("utf-8")) > limit:
    review = review.encode("utf-8")[:limit].decode("utf-8", errors="replace")
    review += "\n\n[truncated; read full review file]"
text = f"""# OpenCode Report Review Complete

The report-review worker finished. Continue the Rustynet live-lab loop now.

## Job
- Job: {job_id}
- Area: {area}
- Report dir: {report_dir}
- Review file: {output}
- Review status: {status}

## Required Action
1. Verify every review claim against real repo/log evidence.
2. Patch root cause. Security first: do not weaken fail-closed/default-deny controls.
3. Run focused gates.
4. Commit.
5. Relaunch focused ai_lab_run with triage_on_failure=false.

## Inline Review

{review}
"""
pathlib.Path(wake).write_text(text, encoding="utf-8")
PY
if [ -n "$OPENCODE_MAIN_SESSION_ID" ]; then
    main_args=(run "Review worker complete. Read the attached wake prompt and continue the Rustynet live-lab loop." --session "$OPENCODE_MAIN_SESSION_ID" --model "$OPENCODE_MAIN_MODEL" --variant "$OPENCODE_MAIN_VARIANT" --file "$wake_prompt")
    if [ -n "$OPENCODE_ATTACH" ]; then main_args+=(--attach "$OPENCODE_ATTACH"); fi
    opencode "\${main_args[@]}" || true
else
    echo "[OpenCode review] no OPENCODE_MAIN_SESSION_ID set; wake prompt written: $wake_prompt"
fi
echo "[OpenCode review] output=$output"
echo "[OpenCode review] status=$status"
exit "\$rc"
EOF
chmod +x "$worker"

if [ "$DRY_RUN" -eq 1 ]; then
    log "dry-run prepared review"
    log "prompt: $prompt"
    log "worker: $worker"
    log "output: $output"
    exit 0
fi

command -v opencode >/dev/null || { log "opencode not found"; exit 127; }
load_deepseek_api_key
if [ "$NO_TMUX" -ne 1 ]; then
    command -v tmux >/dev/null || { log "tmux not found; install with: brew install tmux"; exit 127; }
fi

if [ "$NO_TMUX" -eq 1 ]; then
    log "running OpenCode review in foreground"
    "$worker"
    log "foreground review complete"
    exit 0
fi

if ! tmux has-session -t "$OPENCODE_TMUX_SESSION" 2>/dev/null; then
    tmux new-session -d -s "$OPENCODE_TMUX_SESSION" -n main "cd '$REPO'; exec bash"
    log "created tmux session $OPENCODE_TMUX_SESSION"
fi

short_id="${JOB_ID#labrun-}"
short_id="${short_id%%-*}"
window="review-${short_id:-lab}"
tmux new-window -t "$OPENCODE_TMUX_SESSION" -n "$window" "$worker"

log "started OpenCode review in tmux session=$OPENCODE_TMUX_SESSION window=$window"
log "prompt: $prompt"
log "output: $output"
log "status: $status"

if [ "$WAIT" -eq 1 ]; then
    log "waiting for review completion..."
    wait_started="$(date +%s)"
    while true; do
        state="$(python3 - "$status" <<'PY'
import json, sys
try:
    print(json.load(open(sys.argv[1])).get("state", "unknown"))
except Exception:
    print("unknown")
PY
)"
        case "$state" in
            done)
                log "review complete"
                break ;;
            failed)
                log "review failed; see $status / $events"
                exit 1 ;;
        esac
        if [ "$(($(date +%s) - wait_started))" -gt "$OPENCODE_REVIEW_WAIT_MAX" ]; then
            log "review wait exceeded ${OPENCODE_REVIEW_WAIT_MAX}s; see tmux window $window"
            exit 1
        fi
        sleep 5
    done
fi
