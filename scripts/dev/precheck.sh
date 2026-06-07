#!/usr/bin/env bash
# Precheck — fast local quality check before committing or running full gates.
# Catches common mistakes that would fail CI. Runs in ~5 seconds.
#
# Usage:
#   ./scripts/dev/precheck.sh           # Check all changed files vs main
#   ./scripts/dev/precheck.sh --all     # Check entire workspace
#   ./scripts/dev/precheck.sh --staged  # Check staged changes only
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

MODE="diff"  # diff | all | staged
for arg in "$@"; do
    case "$arg" in
        --all) MODE="all" ;;
        --staged) MODE="staged" ;;
        *) echo "Unknown arg: $arg"; echo "Usage: $0 [--all|--staged]"; exit 1 ;;
    esac
done

PASS=0
FAIL=0

check() {
    local label="$1"; shift
    if "$@" 2>/dev/null; then
        echo "  ✅ $label"
        PASS=$((PASS + 1))
    else
        echo "  ❌ $label"
        FAIL=$((FAIL + 1))
    fi
}

get_rs_files() {
    if [ "$MODE" = "all" ]; then
        find crates -name '*.rs' -not -path '*/target/*'
    elif [ "$MODE" = "staged" ]; then
        git diff --cached --name-only --diff-filter=ACM | grep '\.rs$' || true
    else
        git diff --name-only --diff-filter=ACM HEAD | grep '\.rs$' || true
    fi
}

FILES=$(get_rs_files)

echo "==> Precheck ($MODE mode)"
echo ""

if [ -z "$FILES" ] && [ "$MODE" != "all" ]; then
    echo "  No Rust files changed. Nothing to check."
    exit 0
fi

# ── 1. No unwrap() in production code (exclude tests, build.rs) ──────
echo "── Checking for unwrap() in production code ──"
if [ "$MODE" = "all" ]; then
    # All files, exclude test modules and build scripts
    VIOLATIONS=$(find crates -name '*.rs' \
        -not -path '*/target/*' \
        -not -path '*/tests/*' \
        -exec grep -l '\.unwrap()' {} \; 2>/dev/null || true)
else
    VIOLATIONS=$(echo "$FILES" | grep -v '/tests/' | grep -v '/build\.rs' | while read -r f; do
        [ -z "$f" ] && continue
        grep -l '\.unwrap()' "$f" 2>/dev/null || true
    done)
fi
if [ -n "$VIOLATIONS" ]; then
    echo "  ⚠️  unwrap() found in production code:"
    echo "$VIOLATIONS" | while read -r f; do
        [ -z "$f" ] && continue
        echo "    $f:$(grep -n '\.unwrap()' "$f" | head -3)"
    done
    echo "  💡 unwrap() is only acceptable in tests, build.rs, and locally-provable invariants (§10.2)"
    FAIL=$((FAIL + 1))
else
    echo "  ✅ No unwrap() in production code"
    PASS=$((PASS + 1))
fi

# ── 2. No TODO/FIXME in changed files ────────────────────────────────
echo "── Checking for TODO/FIXME ──"
if [ "$MODE" = "all" ]; then
    VIOLATIONS=$(find crates -name '*.rs' -not -path '*/target/*' \
        -exec grep -Hn '//.*TODO\|//.*FIXME\|/\*.*TODO\|/\*.*FIXME' {} \; 2>/dev/null || true)
else
    VIOLATIONS=$(echo "$FILES" | while read -r f; do
        [ -z "$f" ] && continue
        grep -Hn '//.*TODO\|//.*FIXME\|/\*.*TODO\|/\*.*FIXME' "$f" 2>/dev/null || true
    done)
fi
if [ -n "$VIOLATIONS" ]; then
    echo "  ⚠️  TODO/FIXME found:"
    echo "$VIOLATIONS" | head -10
    echo "  💡 Completed deliverables must not contain TODO/FIXME (AGENTS.md §3, §9)"
    FAIL=$((FAIL + 1))
else
    echo "  ✅ No TODO/FIXME"
    PASS=$((PASS + 1))
fi

# ── 3. All new files have forbid(unsafe_code) ────────────────────────
echo "── Checking for #![forbid(unsafe_code)] ──"
MISSING_FORBID=""
if [ "$MODE" = "all" ]; then
    for f in $(find crates -name '*.rs' -not -path '*/target/*' -not -path '*/tests/*'); do
        if ! head -25 "$f" | grep -q 'forbid(unsafe_code)'; then
            # Only flag library/binary roots, not test fixtures
            case "$f" in
                */lib.rs|*/main.rs|*/mod.rs|*/bin/*.rs)
                    MISSING_FORBID="$MISSING_FORBID $f"
                    ;;
            esac
        fi
    done
else
    for f in $FILES; do
        [ -z "$f" ] && continue
        echo "$f" | grep -qE '(lib\.rs|main\.rs|mod\.rs|/bin/[^/]+\.rs)$' || continue
        if ! head -25 "$f" | grep -q 'forbid(unsafe_code)'; then
            MISSING_FORBID="$MISSING_FORBID $f"
        fi
    done
fi
if [ -n "$MISSING_FORBID" ]; then
    echo "  ⚠️  Missing #![forbid(unsafe_code)] in:"
    for f in $MISSING_FORBID; do echo "    $f"; done
    FAIL=$((FAIL + 1))
else
    echo "  ✅ All crate roots have forbid(unsafe_code)"
    PASS=$((PASS + 1))
fi

# ── 4. No dbg!() macros left in ──────────────────────────────────────
echo "── Checking for dbg!() macros ──"
if [ "$MODE" = "all" ]; then
    VIOLATIONS=$(grep -rn 'dbg!(' crates --include='*.rs' 2>/dev/null || true)
else
    VIOLATIONS=$(echo "$FILES" | while read -r f; do
        [ -z "$f" ] && continue
        grep -Hn 'dbg!(' "$f" 2>/dev/null || true
    done)
fi
if [ -n "$VIOLATIONS" ]; then
    echo "  ⚠️  dbg!() macros found (use tracing/log instead):"
    echo "$VIOLATIONS" | head -5
    FAIL=$((FAIL + 1))
else
    echo "  ✅ No dbg!() macros"
    PASS=$((PASS + 1))
fi

# ── 5. Check for common security mistakes ────────────────────────────
echo "── Security heuristics ──"

# Check for .to_string_lossy() on paths (potential encoding issues)
LOSSY=$(echo "$FILES" | while read -r f; do
    [ -z "$f" ] && continue
    grep -Hn 'to_string_lossy' "$f" 2>/dev/null || true
done)
if [ -n "$LOSSY" ]; then
    echo "  ⚠️  to_string_lossy() — review these (usually safe on file paths):"
    echo "$LOSSY" | head -5
    echo "  ℹ️  Usually safe when called on std::fs results. Flagged for review only."
else
    echo "  ✅ No suspicious path handling"
fi

# ── Summary ──────────────────────────────────────────────────────────
echo ""
echo "========================================"
echo "  Precheck: $PASS passed, $FAIL failed"
echo "========================================"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "Fix the failures above before running full gates."
    echo "Run full gates with: cargo run -p rustynet-xtask -- gates"
    exit 1
else
    echo "All prechecks passed. Ready for full gates."
    exit 0
fi
