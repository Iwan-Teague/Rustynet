#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SKILL_SRC="$ROOT_DIR/tools/skills/rustynet-security-auditor"
CODEX_HOME_DIR="${CODEX_HOME:-$HOME/.codex}"
SKILL_DEST="$CODEX_HOME_DIR/skills/rustynet-security-auditor"

if [[ ! -f "$SKILL_SRC/SKILL.md" ]]; then
  echo "missing skill source: $SKILL_SRC/SKILL.md" >&2
  exit 1
fi

mkdir -p "$SKILL_DEST"
mkdir -p "$SKILL_DEST/agents" "$SKILL_DEST/references" "$SKILL_DEST/scripts"

cp "$SKILL_SRC/SKILL.md" "$SKILL_DEST/SKILL.md"
cp "$SKILL_SRC/agents/openai.yaml" "$SKILL_DEST/agents/openai.yaml"
cp "$SKILL_SRC/references/"* "$SKILL_DEST/references/"
cp "$SKILL_SRC/scripts/"*.py "$SKILL_DEST/scripts/"
chmod 0644 "$SKILL_DEST/SKILL.md" "$SKILL_DEST/agents/openai.yaml" "$SKILL_DEST/references/"*
chmod 0755 "$SKILL_DEST/scripts/"*.py

printf 'installed Rustynet skill to %s\n' "$SKILL_DEST"
