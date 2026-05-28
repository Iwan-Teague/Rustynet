#!/usr/bin/env bash
# Usage: clean_old_runs.sh [--older-than-days N] [--dry-run]
# Removes lab run directories older than N days from artifacts/live_lab/.
# Never touches the run matrix CSV.
set -euo pipefail

OLDER_THAN_DAYS=14
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --older-than-days)
      if [[ ! "$2" =~ ^[0-9]+$ || "$2" -eq 0 ]]; then
        printf 'error: --older-than-days requires a positive integer (got: %s)\n' "$2" >&2
        exit 2
      fi
      OLDER_THAN_DAYS="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help)
      printf 'Usage: %s [--older-than-days N] [--dry-run]\n' "$(basename "$0")"
      printf '  --older-than-days N  remove run dirs older than N days (default: 14)\n'
      printf '  --dry-run            print what would be removed without deleting\n'
      exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB_RUNS_DIR="${ROOT_DIR}/artifacts/live_lab"

if [[ ! -d "$LAB_RUNS_DIR" ]]; then
  printf 'no lab runs directory at %s — nothing to clean\n' "$LAB_RUNS_DIR"
  exit 0
fi

total_freed_kb=0
count=0

while IFS= read -r -d '' dir; do
  size_kb="$(du -sk "$dir" 2>/dev/null | cut -f1 || echo 0)"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf 'would remove: %s (%s KB)\n' "$dir" "$size_kb"
  else
    printf 'removing: %s (%s KB)\n' "$dir" "$size_kb"
    rm -rf "$dir"
  fi
  total_freed_kb=$((total_freed_kb + size_kb))
  count=$((count + 1))
done < <(find "$LAB_RUNS_DIR" -mindepth 1 -maxdepth 1 -type d \
  -mtime "+${OLDER_THAN_DAYS}" -print0 2>/dev/null | sort -z)

local_mb=$(( total_freed_kb / 1024 ))

if [[ "$count" -eq 0 ]]; then
  printf 'no run directories older than %d days found under %s\n' "$OLDER_THAN_DAYS" "$LAB_RUNS_DIR"
elif [[ "$DRY_RUN" -eq 1 ]]; then
  printf 'dry run: would remove %d director%s, freeing ~%d MB (%d KB)\n' \
    "$count" "$([ "$count" -eq 1 ] && echo y || echo ies)" "$local_mb" "$total_freed_kb"
else
  printf 'removed %d director%s, freed ~%d MB (%d KB)\n' \
    "$count" "$([ "$count" -eq 1 ] && echo y || echo ies)" "$local_mb" "$total_freed_kb"
fi
