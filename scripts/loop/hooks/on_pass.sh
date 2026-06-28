#!/usr/bin/env bash
# scripts/loop/hooks/on_pass.sh
# Args: $1=job_id  $2=report_dir
set -euo pipefail
exec "$(dirname "$0")/on_any.sh" "$1" "$2" "pass"
