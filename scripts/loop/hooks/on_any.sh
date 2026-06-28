#!/usr/bin/env bash
# scripts/loop/hooks/on_any.sh
# Called by wake_on_event.sh when a run transitions from running to completed.
# Args: $1=job_id/pid  $2=report_dir  $3=status (pass|fail)
set -euo pipefail

JOB_ID="${1:-?}"
REPORT_DIR="${2:-?}"
STATUS="${3:-?}"
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
PROMPT_FILE="$REPO_ROOT/state/loop-wake-prompt.md"

# ── gather key info from the report ─────────────────────────────────
failed_stage=""
failure_detail=""
if [ "$STATUS" = "fail" ]; then
    stage_file="$REPORT_DIR/state/stages.tsv"
    if [ -f "$stage_file" ]; then
        failed_stage=$(awk '$3=="fail"{print $1; exit}' "$stage_file")
    fi
    digest_file="$REPORT_DIR/failure_digest.md"
    if [ -f "$digest_file" ]; then
        failure_detail=$(grep -A2 'Failure Focus' "$digest_file" | tail -1 | sed 's/^- //' || true)
    fi
fi

stages_count=0
[ -f "$REPORT_DIR/state/stages.tsv" ] && stages_count=$(wc -l < "$REPORT_DIR/state/stages.tsv" | tr -d ' ')

# ── build the agent prompt ──────────────────────────────────────────
cat > "$PROMPT_FILE" << EOF
# Loop Wake — run $STATUS

- **job:** $JOB_ID
- **report_dir:** $REPORT_DIR
- **stages:** $stages_count
EOF

if [ "$STATUS" = "fail" ]; then
    cat >> "$PROMPT_FILE" << EOF
- **failed_stage:** $failed_stage
- **detail:** $failure_detail

## Action
Review the failure. If code defect: patch, gate, re-run. If env: recover and re-run.
EOF
else
    cat >> "$PROMPT_FILE" << EOF
## Action
Run passed. Sync docs if needed. Launch the next parity cell run.
EOF
fi

printf '[hook:on_any] wrote %s (status=%s)\n' "$PROMPT_FILE" "$STATUS"
