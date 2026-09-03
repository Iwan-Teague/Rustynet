#!/bin/sh
# Fail if AGENTS.md and CLAUDE.md have drifted apart.
#
# The two files are intentionally byte-identical: different tools read each by
# literal path (Claude Code loads CLAUDE.md, the OpenCode/AGENTS.md convention
# loads AGENTS.md, and rustynet-mcp-repo-context reads AGENTS.md directly for
# gate definitions), so a silent divergence would hand two agents different
# contracts — different gate definitions, with neither side aware. The mirror
# held for thousands of commits by discipline alone; this script is the
# mechanical enforcement.
#
# Wired into:
#   - CI: the "Repo hygiene gates" step of .github/workflows/cross-platform-ci.yml
#   - the commit-staleness pre-commit hook: scripts/git-hooks/pre-commit

set -eu

root=$(git rev-parse --show-toplevel)

if cmp -s "$root/AGENTS.md" "$root/CLAUDE.md"; then
  echo "AGENTS.md == CLAUDE.md (mirror OK)"
  exit 0
fi

echo "FAIL: AGENTS.md and CLAUDE.md have diverged; they must stay byte-identical" >&2
echo "An agent reading one and an agent reading the other would receive different contracts." >&2
echo "Fix by applying the same edit to both files, identically (see AGENTS.md section 14)." >&2
diff -u "$root/AGENTS.md" "$root/CLAUDE.md" | head -60 >&2 || true
exit 1
