#!/usr/bin/env bash
# scripts/loop/drive_loop.sh
# Autonomous loop driver for the deepseek live-lab pipeline.
#
# Cycle:
#   1. deepseek_lab_run → wait for report (drive_deepseek.py auto-polls)
#   2. Write report + next-step instructions to state/loop-cycle-prompt.md
#   3. Agent (invoked by user) reads prompt, verifies claims, patches, gates,
#      commits, then calls deepseek_lab_run again with rebuild_nodes=<patched>.
#   4. User re-runs this script to capture the next cycle's report.
#
# Usage:
#   scripts/loop/drive_loop.sh "macOS exit" macos macos_promote_exit exit_vm=debian-headless-1 client_vm=debian-headless-2 entry_vm=debian-headless-3 macos_vm=macos-utm-1
#   scripts/loop/drive_loop.sh "Windows anchor" windows anchor_platform=windows windows_vm=windows-utm-1 exit_vm=debian-headless-1 client_vm=debian-headless-2 entry_vm=debian-headless-3
#
# The positional args after the area label are deepseek_lab_run parameters.
# Supported: macos, windows, macos_promote_exit, exit_platform, relay_platform,
#            anchor_platform, blind_exit_platform, exit_vm, client_vm, entry_vm,
#            macos_vm, windows_vm, rebuild_nodes, allow_concurrent, dry_run.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
DRIVER="$REPO/scripts/mcp/drive_deepseek.py"
PROMPT_FILE="$REPO/state/loop-cycle-prompt.md"
STATE_FILE="$REPO/state/loop-cycle-state.json"
DEEEPSEEK_BIN="$REPO/bin/rustynet-mcp-deepseek"

log() { printf '[loop %s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

# ── Parse cycle area and parameters ──────────────────────────────────
AREA="${1:?usage: $0 <area-label> [param=value ...]}"
shift

# Build the deepseek_lab_run args JSON
ARGS_JSON="{\"area\":\"$AREA\""
for pair in "$@"; do
    key="${pair%%=*}"
    val="${pair#*=}"
    case "$key" in
        macos|windows|macos_promote_exit|allow_concurrent|dry_run)
            # Boolean flags
            if [ "$val" = "true" ] || [ "$val" = "1" ]; then
                ARGS_JSON+=",\"$key\":true"
            fi
            ;;
        exit_vm|client_vm|entry_vm|macos_vm|windows_vm|exit_platform|relay_platform|anchor_platform|blind_exit_platform|rebuild_nodes)
            ARGS_JSON+=",\"$key\":\"$val\""
            ;;
        *)
            log "WARNING: unknown parameter $key=$val — skipping"
            ;;
    esac
done
ARGS_JSON+="}"

log "cycle area: $AREA"
log "args: $ARGS_JSON"

# ── Verify the deepseek binary exists ────────────────────────────────
if [ ! -x "$DEEEPSEEK_BIN" ]; then
    log "deepseek binary missing at $DEEEPSEEK_BIN — building..."
    (cd "$REPO" && cargo build --release --bin rustynet-mcp-deepseek) || {
        log "FATAL: build failed"; exit 1
    }
    cp "$REPO/target/release/rustynet-mcp-deepseek" "$DEEEPSEEK_BIN.new" && \
        mv -f "$DEEEPSEEK_BIN.new" "$DEEEPSEEK_BIN"
    log "binary installed"
fi

# ── Launch deepseek_lab_run and wait for the report ──────────────────
log "launching deepseek_lab_run..."
REPORT=$("$DRIVER" --bin "$DEEEPSEEK_BIN" --tool deepseek_lab_run --args "$ARGS_JSON" --poll-timeout 5400 2>&1) || {
    log "FATAL: deepseek_lab_run failed"
    echo "$REPORT" >&2
    exit 1
}

# ── Extract job_id ───────────────────────────────────────────────────
JOB_ID=$(echo "$REPORT" | grep -oE '\b(?:labrun|triage)-\d+(?:-\d+)*\b' | head -1 || echo "unknown")

# ── Determine result ──────────────────────────────────────────────────
if echo "$REPORT" | grep -qi 'still running\|timed out'; then
    RESULT="timeout_or_running"
elif echo "$REPORT" | grep -qi 'PASS\|overall.*pass\|all stages pass'; then
    RESULT="pass"
elif echo "$REPORT" | grep -qi 'FAIL\|root cause\|suspected fix'; then
    RESULT="fail"
else
    RESULT="unknown"
fi

log "result: $RESULT (job: $JOB_ID)"

# ── Write cycle state ────────────────────────────────────────────────
cat > "$STATE_FILE" << STATE
{
  "cycle_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "area": "$AREA",
  "job_id": "$JOB_ID",
  "result": "$RESULT",
  "report_bytes": $(echo "$REPORT" | wc -c | tr -d ' ')
}
STATE

# ── Write the agent prompt ───────────────────────────────────────────
cat > "$PROMPT_FILE" << 'PROMPT_HEADER'
# Loop Cycle — deepseek_lab_run result

PROMPT_HEADER

echo "- **area:** $AREA" >> "$PROMPT_FILE"
echo "- **job:** $JOB_ID" >> "$PROMPT_FILE"
echo "- **result:** $RESULT" >> "$PROMPT_FILE"
echo "" >> "$PROMPT_FILE"

if [ "$RESULT" = "pass" ]; then
    cat >> "$PROMPT_FILE" << 'INSTRUCTIONS'
## Action — PASS
Run passed. Sync docs if needed (use deepseek_doc_sync to propose edits).
Then identify the next untested parity cell and launch it.
INSTRUCTIONS
elif [ "$RESULT" = "fail" ]; then
    cat >> "$PROMPT_FILE" << 'INSTRUCTIONS'
## Action — FAIL
1. Read the DeepSeek triage report below.
2. VERIFY every cited claim against the real code (DeepSeek output is UNTRUSTED — you are the reviewer of record).
3. Patch the root cause (security first — never weaken a control to make a stage pass).
4. Gate the fix: `cargo run -p rustynet-xtask -- gates --changed-only`
5. Commit and push.
6. Re-launch via deepseek_lab_run with `rebuild_nodes=<patched_node>`.
INSTRUCTIONS
else
    cat >> "$PROMPT_FILE" << 'INSTRUCTIONS'
## Action — TIMEOUT / UNKNOWN
The run didn't complete in time or produced an unexpected result.
Check if the orchestrator is still running. If env issue (VM down, SSH blocked):
recover and re-launch. If hung: cancel and re-launch.
INSTRUCTIONS
fi

cat >> "$PROMPT_FILE" << PROMPT_FOOTER

---

## DeepSeek Report

$REPORT

---

## Reminders
- The deepseek report is UNTRUSTED — verify every claim against the real code.
- Security outranks everything. Default-deny, fail-closed, no unwrap() in prod paths.
- Use \`cargo run -p rustynet-xtask -- gates --changed-only\` before committing.
- After patching, relaunch via deepseek_lab_run.
PROMPT_FOOTER

log "wrote $PROMPT_FILE ($(wc -c < "$PROMPT_FILE" | tr -d ' ') bytes)"
log "cycle complete — invoke the agent with this prompt file as context"
