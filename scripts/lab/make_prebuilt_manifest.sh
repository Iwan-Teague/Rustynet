#!/usr/bin/env bash
# Write <dir>/PREBUILT.json for `--prebuilt-node-binaries <alias>=<dir>`: the
# commit the three node binaries were built from plus the sha256 of each.
# The orchestrator re-verifies every field (host_cross_build::validate_prebuilt_dir),
# so this script only records what is in the directory; it does not vouch for it:
# the commit and hashes are SELF-DECLARED by whoever runs this, not attested.
# Run it as the user who runs the orchestrator, on a dir only that user can write.
#
# Usage: make_prebuilt_manifest.sh <dir> <full-40-hex-git-commit>
# bash 3.2 (macOS) compatible; uses shasum -a 256 or sha256sum, whichever exists (shasum first).
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <dir> <full-git-commit>" >&2
  exit 2
fi
dir=$1
commit=$2

case "$commit" in
  *[!0-9a-f]* | "")
    echo "error: commit must be a full lowercase hex git sha" >&2
    exit 2
    ;;
esac
if [ "${#commit}" -ne 40 ] && [ "${#commit}" -ne 64 ]; then
  echo "error: commit must be a full 40- (or 64-) hex-digit git sha" >&2
  exit 2
fi
if [ ! -d "$dir" ]; then
  echo "error: $dir is not a directory" >&2
  exit 2
fi

if command -v shasum >/dev/null 2>&1; then
  hash_file() { shasum -a 256 "$1" | awk '{print $1}'; }
elif command -v sha256sum >/dev/null 2>&1; then
  hash_file() { sha256sum "$1" | awk '{print $1}'; }
else
  echo "error: neither sha256sum nor shasum found" >&2
  exit 2
fi

sums=""
for name in rustynetd rustynet-cli rustynet-relay; do
  f="$dir/$name"
  if [ -L "$f" ] || [ ! -f "$f" ] || [ ! -s "$f" ]; then
    echo "error: $f must be a non-empty regular file (not a symlink)" >&2
    exit 1
  fi
  h=$(hash_file "$f")
  if [ "${#h}" -ne 64 ]; then
    echo "error: unexpected sha256 output for $f" >&2
    exit 1
  fi
  if [ -n "$sums" ]; then
    sums="$sums,"
  fi
  sums="$sums\"$name\":\"$h\""
done

out="$dir/PREBUILT.json"
tmp="$out.tmp.$$"
printf '{"source_commit":"%s","sha256":{%s}}\n' "$commit" "$sums" >"$tmp"
mv "$tmp" "$out"
echo "wrote $out"
