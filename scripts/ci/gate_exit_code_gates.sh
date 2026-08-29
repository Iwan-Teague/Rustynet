#!/usr/bin/env bash
# QH-16: gate exit-code hygiene gates.
#
# A gate piped through `| tail` reports tail's exit status (0), masking a
# failing gate. This gate enforces the repo convention that every gate tool's
# OWN exit code is captured and checked:
#   1. every scripts/ci/*.sh starts with `set -euo pipefail`
#   2. no gate invocation is piped directly into an output filter outside a
#      command-substitution capture (capture lines check the exit separately
#      via the `$(...) ||` pattern)
#   3. a built-in self-test proves both directions: a masked pipeline is
#      detected as such, and the enforced capture pattern surfaces the real
#      exit code.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CI_DIR="$SCRIPT_DIR"

failures=0

note_failure() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}

# Emit violating lines from gate-script content on stdout (empty output = clean).
# A violating line: begins with a gate command and pipes into an output filter,
# outside a $(...) capture. Capture lines begin with VAR= (or `local X=`), so a
# line STARTING with the gate command is by construction not a capture. Lines
# inside a multi-line $( ... ) are out of scope for this line-level heuristic;
# no scripts/ci/*.sh uses that shape today (captured multi-command bodies use
# `|| { ...; return 1; }` instead).
scan_gate_lines() {
    local file="$1"
    local line=""
    local lineno=0
    while IFS= read -r line; do
        lineno=$((lineno + 1))
        case "$line" in
            \#*) continue ;;
        esac
        # Trim leading whitespace.
        local trimmed="${line#"${line%%[![:space:]]*}"}"
        case "$trimmed" in
            cargo\ *|cargo|./scripts/ci/*|bash\ scripts/ci/*|"${CI_DIR}"/*)
                case "$trimmed" in
                    *\|*tail*|*\|*head*|*\|*grep*|*\|*tee*|*\|*awk*|*\|*sed*|*\|*wc*)
                        echo "$file:$lineno: gate invocation piped into a filter: $trimmed"
                        ;;
                esac
                ;;
        esac
    done < "$file"
}

# Gate 1: every gate wrapper that does real shell work sets the hardened
# options (pipefail included). Pure `exec` dispatchers (a single `exec
# cargo run …` line) are exempt: exec replaces the shell, so the Rust
# binary's own exit status IS the script's exit status — nothing to mask.
for script in "$CI_DIR"/*.sh; do
    [ "$script" = "$SCRIPT_DIR/$(basename "$0")" ] && continue
    if grep -Ev '^\s*(#|$)' "$script" | grep -qv '^exec '; then
        if ! grep -q 'set -.*pipefail' "$script"; then
            note_failure "$script does not 'set -euo pipefail'"
        fi
    fi
done

# Gate 2: no bare piped gate invocations.
for script in "$CI_DIR"/*.sh; do
    [ "$script" = "$SCRIPT_DIR/$(basename "$0")" ] && continue
    while IFS= read -r violation; do
        [ -n "$violation" ] || continue
        note_failure "$violation"
    done < <(scan_gate_lines "$script")
done

# Gate 3: self-test — prove the checks bite and the enforced pattern works.
selftest_dir="$(mktemp -d)"
trap 'rm -rf "$selftest_dir"' EXIT

cat > "$selftest_dir/violating.sh" <<'EOF'
set -euo pipefail
cargo test --workspace --all-targets --all-features | tail -60
EOF

cat > "$selftest_dir/clean.sh" <<'EOF'
set -euo pipefail
out="$(cargo test --workspace --all-targets --all-features 2>&1)" || {
    echo "gate failed"; exit 1;
}
printf '%s\n' "$out" | tail -60
EOF

violating_hits="$(scan_gate_lines "$selftest_dir/violating.sh")"
if [ -z "$violating_hits" ]; then
    note_failure "self-test: scan_gate_lines did not reject a bare piped gate line"
fi

clean_hits="$(scan_gate_lines "$selftest_dir/clean.sh")"
if [ -n "$clean_hits" ]; then
    note_failure "self-test: scan_gate_lines rejected a compliant capture line: $clean_hits"
fi

# Masked-pipeline demonstration: in a default (no-pipefail) pipeline the
# shell reports the LAST command's status, so the real gate exit vanishes.
set +o pipefail
sh -c 'echo test result: ok. 100 passed; exit 3' | tail -1
masked_rc=$?
set -o pipefail
if [ "$masked_rc" -ne 0 ]; then
    note_failure "self-test premise broken: pipeline unexpectedly reported nonzero ($masked_rc)"
fi
echo "demonstrated: piped gate reported tail's exit ($masked_rc) despite gate exit 3"

# Enforced pattern: capture first, check the tool's own exit separately.
captured_rc=0
captured_out="$(sh -c 'echo test result: ok. 100 passed; exit 3' 2>&1)" || captured_rc=$?
if [ "$captured_rc" -ne 3 ]; then
    note_failure "self-test: capture pattern lost the real exit code (got $captured_rc, want 3)"
fi
echo "enforced pattern: captured real gate exit ($captured_rc) from the same command"

if [ "$failures" -ne 0 ]; then
    echo "gate_exit_code_gates: FAILED ($failures failure(s))" >&2
    exit 1
fi
echo "gate_exit_code_gates: PASSED"
