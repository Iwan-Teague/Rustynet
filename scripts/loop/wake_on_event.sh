#!/usr/bin/env bash
# scripts/loop/wake_on_event.sh
# Polls live-lab runs and writes a structured state file. Designed to be
# sourced by the Zed agent or called by a launchd watch.
#
# Modes:
#   poll         — one-shot: scan all running jobs, write state/loop-wake.json
#   watch [-i N] — loop every N seconds (default 30), write state, fire hooks
#   hook <name>  — run a hook script from scripts/loop/hooks/<name>.sh
#
# Output:
#   state/loop-wake.json   — { running: [...], last_completed: {...}, next_action: "..." }
#
# Hooks (called when a run transitions to completed):
#   scripts/loop/hooks/on_pass.sh    $job_id $report_dir
#   scripts/loop/hooks/on_fail.sh    $job_id $report_dir $failed_stage
#   scripts/loop/hooks/on_any.sh     $job_id $report_dir $status
#
# Limitations:
#   - Can't directly invoke the Zed agent. Writes state files the agent reads.
#   - For true autonomous wake, pair with a launchd WatchPaths plist on the
#     report directory, or use `fswatch` on macOS.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STATE_DIR="$REPO_ROOT/state"
WAKE_FILE="$STATE_DIR/loop-wake.json"
KNOWN_FILE="$STATE_DIR/loop-wake-known.tsv"
HOOK_DIR="$REPO_ROOT/scripts/loop/hooks"
DEFAULT_INTERVAL=30

log() { printf '[wake %s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

# ── discover running orchestrator processes ──────────────────────────
discover_runs() {
    # Find rustynet-cli orchestrator processes with a --report-dir flag.
    ps aux | grep 'rustynet-cli.*vm-lab-orchestrate-live-lab' | grep -v grep | while read -r line; do
        local pid=$(echo "$line" | awk '{print $2}')
        local report_dir=$(echo "$line" | sed -n 's/.*--report-dir \([^ ]*\).*/\1/p')
        local elapsed=$(ps -o etime= -p "$pid" 2>/dev/null | tr -d ' ')
        [ -n "$report_dir" ] && printf '%s\t%s\t%s\n' "$pid" "$report_dir" "$elapsed"
    done
}

# ── classify run state ──────────────────────────────────────────────
classify_run() {
    local report_dir="$1"
    local stage_file="$report_dir/state/stages.tsv"
    if [ ! -f "$stage_file" ]; then
        echo "bootstrapping"
        return
    fi
    # Count pass/fail stages (guard against non-numeric)
    local pass; pass=$(grep -c $'	pass$' "$stage_file" 2>/dev/null) || pass=0
    local fail; fail=$(grep -c $'	fail$' "$stage_file" 2>/dev/null) || fail=0
    pass="${pass//[^0-9]/}"
    fail="${fail//[^0-9]/}"
    [ -z "$pass" ] && pass=0
    [ -z "$fail" ] && fail=0
    local last_stage; last_stage=$(tail -1 "$stage_file" 2>/dev/null | awk '{print $1}') || true
    local last_status; last_status=$(tail -1 "$stage_file" 2>/dev/null | awk '{print $3}') || true
    if [ "$fail" -gt 0 ] 2>/dev/null; then
        echo "failed:$last_stage"
    elif [ -f "$report_dir/failure_digest.md" ] && grep -q 'overall_status.*pass' "$report_dir/failure_digest.md" 2>/dev/null; then
        # The failure_digest might say pass even when still running — check for 'run complete' marker
        if grep -q 'no failed stage' "$report_dir/failure_digest.md" 2>/dev/null && [ "$last_status" = "pass" ]; then
            echo "passed"
        else
            echo "running:$last_stage"
        fi
    elif [ "$last_status" = "pass" ]; then
        echo "running:$last_stage"
    else
        echo "running:$last_stage"
    fi
}

# ── poll mode: one-shot scan ────────────────────────────────────────
poll() {
    local running_json="[]"
    local completed_json="null"
    local runs
    runs=$(discover_runs)
    log "discovered $(echo "$runs" | grep -c . || echo 0) running process(es)"

    if [ -n "$runs" ]; then
        running_json="["
        local first=true
        while IFS=$'\t' read -r pid dir elapsed; do
            [ -z "$pid" ] && continue
            local state=$(classify_run "$dir")
            local stages_count=$(tail -1 "$dir/state/stages.tsv" 2>/dev/null | wc -l || echo 0)
            $first || running_json+=","
            first=false
            running_json+="{\"pid\":\"$pid\",\"report_dir\":\"$dir\",\"elapsed\":\"$elapsed\",\"state\":\"$state\"}"
        done <<< "$runs"
        running_json+="]"
    fi

    # Check for recently completed runs (known runs no longer in ps)
    if [ -f "$KNOWN_FILE" ]; then
        while IFS=$'\t' read -r old_pid old_dir old_state; do
            if ! ps -p "$old_pid" >/dev/null 2>&1; then
                # Process gone — check final state
                local final_state=$(classify_run "$old_dir")
                if [ "$final_state" = "passed" ] || [[ "$final_state" == failed:* ]]; then
                    local failed_stage=""
                    [[ "$final_state" == failed:* ]] && failed_stage="${final_state#failed:}"
                    completed_json="{\"pid\":\"$old_pid\",\"report_dir\":\"$old_dir\",\"status\":\"$final_state\",\"failed_stage\":\"$failed_stage\"}"
                    log "run $old_pid completed: $final_state"

                    # Fire hooks
                    mkdir -p "$HOOK_DIR"
                    local hook_status="${final_state%%:*}"
                    [ "$hook_status" = "passed" ] && hook_status="pass"
                    [ "$hook_status" = "failed" ] && hook_status="fail"
                    [ -x "$HOOK_DIR/on_any.sh" ] && "$HOOK_DIR/on_any.sh" "$old_pid" "$old_dir" "$hook_status" || true
                    if [ "$hook_status" = "pass" ] && [ -x "$HOOK_DIR/on_pass.sh" ]; then
                        "$HOOK_DIR/on_pass.sh" "$old_pid" "$old_dir" || true
                    elif [ "$hook_status" = "fail" ] && [ -x "$HOOK_DIR/on_fail.sh" ]; then
                        "$HOOK_DIR/on_fail.sh" "$old_pid" "$old_dir" "$failed_stage" || true
                    fi
                fi
            fi
        done < "$KNOWN_FILE"
    fi

    # Write wake file
    local next_action="monitor"
    [ "$completed_json" != "null" ] && next_action="review_completed"

    cat > "$WAKE_FILE" << JSON
{
  "updated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "running": $running_json,
  "last_completed": $completed_json,
  "next_action": "$next_action"
}
JSON

    # Update known runs
    if [ -n "$runs" ]; then
        while IFS=$'\t' read -r pid dir elapsed; do
            [ -z "$pid" ] && continue
            local state=$(classify_run "$dir")
            printf '%s\t%s\t%s\n' "$pid" "$dir" "$state"
        done <<< "$runs"
    fi > "$KNOWN_FILE"

    log "wrote $WAKE_FILE"
}

# ── watch mode: loop ────────────────────────────────────────────────
watch() {
    local interval="$DEFAULT_INTERVAL"
    if [ "${1:-}" = "-i" ]; then
        interval="${2:-$DEFAULT_INTERVAL}"
    fi
    log "watching every ${interval}s (ctrl-c to stop)"
    while true; do
        poll
        sleep "$interval"
    done
}

# ── hook mode ───────────────────────────────────────────────────────
run_hook() {
    local hook_name="$1"
    local hook_script="$HOOK_DIR/$hook_name.sh"
    if [ -x "$hook_script" ]; then
        shift
        "$hook_script" "$@"
    else
        log "hook not found: $hook_script"
        return 1
    fi
}

# ── main ────────────────────────────────────────────────────────────
mkdir -p "$STATE_DIR" "$HOOK_DIR"

case "${1:-poll}" in
    poll)   poll ;;
    watch)  watch "${@:2}" ;;
    hook)   run_hook "${@:2}" ;;
    *)
        echo "usage: $0 {poll|watch [-i N]|hook <name> [args...]}" >&2
        exit 1
        ;;
esac
