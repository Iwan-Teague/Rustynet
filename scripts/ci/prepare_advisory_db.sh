#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 <advisory_db_path>" >&2
  exit 2
fi

TARGET_DB="$1"
TARGET_DB_PARENT="$(dirname "$TARGET_DB")"
GLOBAL_DB="${HOME}/.cargo/advisory-db"
AUTO_FETCH="${RUSTYNET_AUDIT_DB_AUTO_FETCH:-1}"
ADVISORY_REMOTE="${RUSTYNET_AUDIT_DB_REMOTE:-https://github.com/RustSec/advisory-db.git}"

case "$TARGET_DB" in
  ""|"/"|".")
    echo "invalid advisory db target path: '$TARGET_DB'" >&2
    exit 2
    ;;
esac

is_valid_db() {
  local path="$1"
  [[ -d "$path" && -d "$path/crates" && -f "$path/support.toml" ]]
}

copy_from_source() {
  local source="$1"
  if ! is_valid_db "$source"; then
    return 1
  fi
  mkdir -p "$TARGET_DB_PARENT"
  rm -rf "${TARGET_DB}.tmp.copy.$$"
  cp -R "$source" "${TARGET_DB}.tmp.copy.$$"
  rm -rf "$TARGET_DB"
  mv "${TARGET_DB}.tmp.copy.$$" "$TARGET_DB"
}

if is_valid_db "$TARGET_DB"; then
  exit 0
fi

if copy_from_source "$GLOBAL_DB"; then
  exit 0
fi

if [[ "$AUTO_FETCH" != "1" ]]; then
  echo "advisory db missing at $TARGET_DB and auto-fetch disabled (RUSTYNET_AUDIT_DB_AUTO_FETCH=0)" >&2
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "advisory db missing and git is unavailable for bootstrap: $TARGET_DB" >&2
  exit 1
fi

mkdir -p "$TARGET_DB_PARENT"
tmp_db="${TARGET_DB}.tmp.clone.$$"
rm -rf "$tmp_db"
if ! git clone --depth 1 "$ADVISORY_REMOTE" "$tmp_db" >/dev/null 2>&1; then
  rm -rf "$tmp_db"
  echo "failed to clone advisory db from $ADVISORY_REMOTE" >&2
  exit 1
fi

if ! is_valid_db "$tmp_db"; then
  rm -rf "$tmp_db"
  echo "downloaded advisory db is invalid: $tmp_db" >&2
  exit 1
fi

rm -rf "$TARGET_DB"
mv "$tmp_db" "$TARGET_DB"

if ! is_valid_db "$TARGET_DB"; then
  echo "advisory db bootstrap produced invalid layout: $TARGET_DB" >&2
  exit 1
fi
