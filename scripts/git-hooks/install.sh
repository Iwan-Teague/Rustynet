#!/bin/sh
# Point git at scripts/git-hooks/ for this clone.
#
# `core.hooksPath` is per-clone config, not tracked content, so a hook committed
# to the repo does nothing until someone runs this. That is a real gap — the one
# person who most needs the hook is the one who has not run it — so it is also
# checked by a test, and CI verifies the hook is executable and refuses a stale
# commit.
set -eu
root=$(git rev-parse --show-toplevel)
git -C "$root" config core.hooksPath scripts/git-hooks
chmod +x "$root/scripts/git-hooks/pre-commit"
printf 'hooks installed: core.hooksPath -> scripts/git-hooks\n'
printf 'verify with: git config core.hooksPath\n'
