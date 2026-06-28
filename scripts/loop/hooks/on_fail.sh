#!/usr/bin/env bash
# scripts/loop/hooks/on_fail.sh
# Args: $1=job_id  $2=report_dir  $3=failed_stage
set -euo pipefail
exec "$(dirname "$0")/on_any.sh" "$1" "$2" "fail"
