#!/usr/bin/env bash
# Setup development environment — install git hooks, verify toolchain.
# Run once after cloning or when toolchain requirements change.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

echo "==> Setting up Rustynet development environment"
echo ""

# ── 1. Verify toolchain ──────────────────────────────────────────────
echo "── Toolchain check ──"

check_cmd() {
    if command -v "$1" &>/dev/null; then
        echo "  ✅ $1 ($(command -v "$1"))"
    else
        echo "  ❌ $1 not found — please install it"
        return 1
    fi
}

MISSING=0
check_cmd cargo || MISSING=$((MISSING + 1))
check_cmd rustc || MISSING=$((MISSING + 1))
check_cmd git || MISSING=$((MISSING + 1))

# Optional but recommended
check_cmd cargo-audit 2>/dev/null || echo "  ⚠️  cargo-audit not found (install: cargo install cargo-audit)"
check_cmd cargo-deny 2>/dev/null || echo "  ⚠️  cargo-deny not found (install: cargo install cargo-deny)"

if [ "$MISSING" -gt 0 ]; then
    echo ""
    echo "❌ $MISSING required tools missing. Install them and re-run."
    exit 1
fi

# ── 2. Install git hooks ─────────────────────────────────────────────
echo ""
echo "── Git hooks ──"

HOOKS_DIR="$REPO_ROOT/.git/hooks"

# Pre-commit: run precheck on staged changes
cat > "$HOOKS_DIR/pre-commit" << 'PRECOMMIT'
#!/usr/bin/env bash
# Pre-commit hook: fast quality checks on staged changes
set -euo pipefail
REPO_ROOT="$(git rev-parse --show-toplevel)"
exec "$REPO_ROOT/scripts/dev/precheck.sh" --staged
PRECOMMIT
chmod +x "$HOOKS_DIR/pre-commit"
echo "  ✅ pre-commit → scripts/dev/precheck.sh --staged"

# Pre-push: run full gates on changed crates
cat > "$HOOKS_DIR/pre-push" << 'PREPUSH'
#!/usr/bin/env bash
# Pre-push hook: run fmt + check on changed crates before pushing
set -euo pipefail
REPO_ROOT="$(git rev-parse --show-toplevel)"
echo "==> Pre-push: running cargo fmt + check on changed crates"
cd "$REPO_ROOT"

# Get changed crates
CHANGED=$(git diff --name-only origin/main...HEAD 2>/dev/null | grep '^crates/' | cut -d'/' -f1-2 | sort -u || true)
if [ -z "$CHANGED" ]; then
    echo "  No crate changes detected. Skipping."
    exit 0
fi

echo "  Changed crates: $CHANGED"

# Build the -p flags
PKG_FLAGS=""
for crate in $CHANGED; do
    PKG_FLAGS="$PKG_FLAGS -p $(echo $crate | cut -d'/' -f2)"
done

echo "  Running: cargo fmt --check"
cargo fmt --all -- --check

echo "  Running: cargo check $PKG_FLAGS"
cargo check $PKG_FLAGS

echo "  ✅ Pre-push checks passed"
PREPUSH
chmod +x "$HOOKS_DIR/pre-push"
echo "  ✅ pre-push → cargo fmt + cargo check on changed crates"

# ── 3. Make dev scripts executable ────────────────────────────────────
chmod +x "$REPO_ROOT/scripts/dev/precheck.sh" 2>/dev/null || true
chmod +x "$REPO_ROOT/scripts/mcp/install.sh" 2>/dev/null || true

echo ""
echo "========================================"
echo "  Development environment ready!"
echo "========================================"
echo ""
echo "Quick reference:"
echo "  ./scripts/dev/precheck.sh        Fast local checks (~5s)"
echo "  cargo run -p rustynet-xtask -- gates   Full gate suite"
echo "  cargo run -p rustynet-xtask -- gates --skip-test  Skip slow tests"
echo ""
echo "Git hooks installed:"
echo "  pre-commit: runs precheck on staged changes"
echo "  pre-push:   runs cargo fmt + cargo check on changed crates"
echo ""
echo "To skip hooks temporarily: git commit --no-verify"
