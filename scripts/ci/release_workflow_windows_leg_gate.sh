#!/usr/bin/env bash
# release_workflow_windows_leg_gate.sh — Q1 static gate.
#
# Q1 (P0): a `v*.*.*` tag could never produce a release. release.yml's build
# matrix built `-p rustynet-cli` on the windows-2022 leg, but rustynet-cli is
# Unix-only by design (unconditional `std::os::unix` imports and the `nix`
# dependency). That leg failed, `manifest` (`needs: build`) was skipped, and
# no signed manifest or GitHub Release was ever produced.
#
# The fix is a per-platform artifact set: the Windows leg ships only the
# Windows-buildable binaries (rustynetd + rustynet-relay, per
# documents/operations/PlatformSupportMatrix.md and the PKGS list in
# .github/workflows/cross-platform-ci.yml), while every other leg keeps
# building rustynet-cli (shipped as `rustynet`).
#
# This gate statically holds that shape in place. It is a structural guard,
# not a semantic proof; it asserts:
#
#   G1  The "Build shipping binaries" step builds `-p rustynetd` and
#       `-p rustynet-relay --features daemon` OUTSIDE any Windows guard
#       (they must be built on every leg, including Windows).
#   G2  The `-p rustynet-cli` build line is inside a guard that EXCLUDES the
#       Windows family (`matrix.family != "windows"`), so the Unix-only crate
#       is never compiled on Windows.
#   G3  The "Stage binaries" step copies rustynetd and rustynet-relay
#       unconditionally, and stages the rustynet-cli artifact only inside the
#       same Windows-excluding guard.
#   G4  The build matrix still declares a `family: windows` row, so the guard
#       is actually exercised (a matrix with no Windows leg would make the
#       guard vacuous).
#   G5  Every runner label the workflow references (each matrix `os:` value
#       and every literal `runs-on:` value) is in an explicit allowlist of
#       LIVE GitHub-hosted labels. GitHub retired `macos-13` in 2025 and
#       retires `macos-14` on 2026-11-02 (brownout failures live since
#       2026-07); a dead label means the leg never starts, `build` never
#       succeeds, and `manifest` is skipped — the same objective Q1
#       protects. An unknown label fails here, at review time, instead of
#       silently eating a leg. The check FAILS CLOSED on every `os:` /
#       `runs-on:` value it cannot positively classify: the value must be a
#       bare token drawn only from [A-Za-z0-9._-] (or a flow-map value
#       starting with such a token on a `{ ... }` line), or exactly the
#       `runs-on: ${{ matrix.os }}` indirection whose effective values are
#       the harvested matrix `os:` rows. EVERY other spelling is rejected
#       outright — a quoted or flow-form value, a space before the colon, a
#       block-list `runs-on:`, a quoted or single-quoted KEY (`"os": x`),
#       an EXPLICIT YAML key (`? runs-on` with its value on the next line,
#       or the flow form `{? os : x}` — neither line carries the colon
#       shape, and via a matrix include row it rides the one allowed
#       `matrix.os` indirection), a YAML scalar alias (`*x`, which the
#       runner's parser resolves to the anchored label), a YAML anchor
#       (`&x`), a `${{ }}` expression other than that one `matrix.os`
#       shape (e.g. `env.X` or `vars.X` indirection), or any value
#       containing a character outside [A-Za-z0-9._-]. None of those is
#       silently skipped: there is no known spelling that passes this
#       check without its effective label having been allowlist-verified.
#
#   S   Self-test battery: the PRE-FIX step bodies (rustynet-cli built and
#       staged unguarded on the Windows leg) must be REJECTED by the same
#       checker run against the real target, an INVERTED guard
#       (`family == "windows"` builds the CLI) must also be rejected, the
#       RETIRED runner labels (`macos-13`, and `macos-14` for its
#       2026-11-02 retirement) must be rejected by G5, a replica using the
#       live Intel label (`macos-15-intel`) must pass, and every
#       non-classifiable `os:`/`runs-on:` spelling must be REJECTED, never
#       silently skipped: quoted value, flow sequence, space before the
#       colon, block-list `runs-on:`, scalar alias (`*x`), anchored value
#       (`&x`), a `${{ env.X }}` runs-on, a `${{ vars.X }}` matrix `os:`, a
#       space-separated multi-token value, a quoted KEY (`"runs-on": x`),
#       an EXPLICIT KEY (`? runs-on` / `: macos-13`, and the flow form
#       `{? os : macos-13, ...}`, including as a matrix include row),
#       and a `runs-on: ${{ matrix.os }}`
#       positive control proving the one allowed indirection still passes.
#       A gate that cannot fail is not a gate.
#
# Usage:
#   scripts/ci/release_workflow_windows_leg_gate.sh [workflow-path]
#     Default target: .github/workflows/release.yml

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TARGET="${1:-${ROOT}/.github/workflows/release.yml}"

BUILD_STEP_NAME="Build shipping binaries"
STAGE_STEP_NAME="Stage binaries as <name>-<target>[.exe]"

failures=0
gate_fail() { printf 'FAIL %s\n' "$1"; failures=$((failures + 1)); }
gate_pass() { printf 'PASS %s\n' "$1"; }

# Extract a `- name: <exact>` step block (name line plus its body) from a
# workflow file. Literal (index) matching so regex metacharacters in the step
# name (e.g. `[.exe]`) cannot misfire.
extract_step() {
    awk -v pat="$2" '
        {
            if (!f && index($0, "- name: " pat) > 0) { f = 1; print; next }
            if (f) {
                if ($0 ~ /^      - name: /) { exit }
                print
            }
        }
    ' "$1"
}

# Print "<guard_line> <fi_line>" for the first `if [ ... family ... windows ...
# != ... ]` guard in the block, or "0 0" when there is none.
guard_region() {
    awk '
        { l[NR] = $0 }
        END {
            g = 0
            for (i = 1; i <= NR; i++) {
                if (l[i] ~ /if \[/ && l[i] ~ /family/ && l[i] ~ /windows/ && l[i] ~ /!=/) {
                    g = i; break
                }
            }
            if (g == 0) { print "0 0"; exit }
            f = 0
            for (i = g + 1; i <= NR; i++) {
                if (l[i] ~ /^[[:space:]]*fi[[:space:]]*$/) { f = i; break }
            }
            print g, f
        }
    ' "$1"
}

# Print the 1-based line number of the first line containing literal needle
# $2, or 0 when absent.
line_of() {
    awk -v needle="$2" '
        { if (index($0, needle) > 0) { print NR; found = 1; exit } }
        END { if (!found) print 0 }
    ' "$1"
}

# Live GitHub-hosted runner labels (standard, free-for-public-repos tier) at
# the time of writing (2026-10). Deliberately explicit: a label that is not
# listed is rejected, so a GitHub retirement (macos-13, windows-2019,
# ubuntu-20.04 are gone; macos-14 is unsupported from 2026-11-02 with
# brownout failures already live) cannot silently kill a release leg. Paid
# large-runner labels (macos-15-large, macos-14-large, macos-13-large, ...)
# are excluded on purpose: they are not available on free plans and would
# fail the same way. When GitHub announces a retirement, move the label out
# of the workflow AND this list in the same change.
RUNNER_LABEL_ALLOWLIST="ubuntu-latest ubuntu-24.04 ubuntu-22.04 ubuntu-24.04-arm ubuntu-22.04-arm macos-latest macos-15 macos-15-intel windows-latest windows-2025 windows-2022"

# Print every runner label the workflow references, one per line, unique:
# each matrix `os:` value (this also covers `runs-on: ${{ matrix.os }}`) plus
# every literal `runs-on:` value. `runs-on:` lines carrying a `${{ ... }}`
# expression are skipped, but that skip is SAFE only because
# exotic_label_lines (run as part of the same G5 check) hard-rejects every
# expression spelling except exactly `runs-on: ${{ matrix.os }}` — the one
# indirection whose effective values are the matrix `os:` rows harvested
# here. Bare tokens only: the collector is deliberately form-sensitive and
# pairs with exotic_label_lines, so a value either classifies as a bare
# [A-Za-z0-9._-]+ label (checked against the allowlist below) or the whole
# G5 check fails. Keys are anchored to a non-label character (a
# `cross_os:`-style suffix key is not a runner label and is not harvested).
runner_labels() {
    awk '
        {
            if ($0 ~ /^[[:space:]]*#/) next
            line = $0
            while (match(line, /(^|[^A-Za-z0-9_-])os:[[:space:]]*[A-Za-z0-9._-]+/)) {
                s = substr(line, RSTART, RLENGTH)
                sub(/^.*os:[[:space:]]*/, "", s)
                print s
                line = substr(line, RSTART + RLENGTH)
            }
            line = $0
            if (line ~ /runs-on:[[:space:]]*\$\{\{/) next
            if (match(line, /(^|[^A-Za-z0-9_-])runs-on:[[:space:]]*[A-Za-z0-9._-]+/)) {
                s = substr(line, RSTART, RLENGTH)
                sub(/^.*runs-on:[[:space:]]*/, "", s)
                print s
            }
        }
    ' "$1" | sort -u
}

# Print every `os:` / `runs-on:` line whose value the gate cannot
# POSITIVELY classify, prefixed with its 1-based line number. The contract
# (fail closed): a value is accepted only when
#   (a) it is a bare token drawn solely from [A-Za-z0-9._-] (optionally
#       followed by a ` #` comment) — the collector reads exactly that
#       token and the allowlist judges it; or
#   (b) it starts with such a token and continues with `,` or `}` on a
#       flow-mapping line (`{ ...` seen earlier on the line) — flow plain
#       scalars end at those delimiters, so the collector's token IS the
#       whole YAML value; or
#   (c) the key is `runs-on` and the value is exactly `${{ matrix.os }}`
#       (internal whitespace tolerated) — the one indirection whose
#       effective values are the matrix `os:` rows the collector harvests.
# Everything else is a hard failure, never a silent skip: an empty value
# (block-list `runs-on:`), a quoted or flow-form value, a space before the
# colon, a quoted or single-quoted KEY (`"os": x` — the quote breaks the
# key:colon shape below, so it is caught by an explicit pre-check), an
# EXPLICIT YAML key (`? runs-on` / `: macos-13`, or flow `{? os : x}` —
# caught by explicit pre-checks; a matrix include row spelled this way
# rides the allowed ${{ matrix.os }} indirection), a YAML
# scalar alias (`*x` — the runner's parser resolves it to the
# anchored label, which this textual gate cannot verify), an anchored value
# (`&x`), a YAML tag (`!...`), a `${{ }}` expression other than shape (c)
# (`env.X`/`vars.X`/`inputs.X` indirection makes the label invisible here),
# or any value containing a character outside [A-Za-z0-9._-] (e.g. a
# space-separated multi-token scalar, which GitHub would treat as one
# unusable label). Pure awk (match/RSTART/substr), so it behaves identically
# on BSD and GNU awk.
exotic_label_lines() {
    awk '
        /^[[:space:]]*#/ { next }
        {
            # A quoted or single-quoted KEY ("os": x / 'runs-on': y) is valid
            # YAML that GitHub executes, but the bare-key matcher below never
            # sees it (the quote breaks the key:colon shape), so it would be
            # invisible to both the collector and the value classifier.
            # Fail closed on the spelling itself.
            if ($0 ~ /(^|[^A-Za-z0-9_-])["'\''][[:space:]]*(os|runs-on)[[:space:]]*["'\''][[:space:]]*:/) { print FNR ": " $0; next }
            # An EXPLICIT YAML key ("? runs-on" with the value on the next
            # ": v" line, or the flow form "{? os : macos-13, ...}") is
            # valid YAML that the runner parses, but NEITHER spelling gives
            # any line the `os:`/`runs-on:` colon shape the collector and
            # the classifier below key on — and via a matrix include row it
            # rides the one allowed ${{ matrix.os }} indirection. No
            # legitimate workflow spells a key this way: fail closed on the
            # indicator itself wherever a KEY can start — line-initial
            # (optionally after `- `), after `{`, or after `,` in a flow
            # map — with the key name `os`/`runs-on` ending at `,` `:` `}`
            # or end of line.
            if ($0 ~ /(^|[[:space:]{,])\?[[:space:]]*(os|runs-on)([[:space:]]*[,:}]|[[:space:]]*$)/) { print FNR ": " $0; next }
            # ...and one whose name is quoted, anchored, tagged, or a
            # collection (`? "runs-on"`, `? &k runs-on`, `? !!str os`,
            # `? [...]`): exotic key spellings no legitimate workflow uses.
            if ($0 ~ /(^|[[:space:]{,])\?[[:space:]]*[&!"'\''\[{]/) { print FNR ": " $0; next }
            line = $0; consumed = ""; shown = 0
            while (match(line, /(^|[^A-Za-z0-9_-])(os|runs-on)[[:space:]]*:/)) {
                ks = RSTART; kl = RLENGTH
                keystr = substr(line, ks, kl)
                before = consumed substr(line, 1, ks - 1)
                rest = substr(line, ks + kl)
                sub(/^[^A-Za-z0-9_-]/, "", keystr)
                spaced = (keystr ~ /[[:space:]]/)
                sub(/[[:space:]]*:$/, "", keystr)
                bad = 0
                if (spaced) {
                    bad = 1
                } else {
                    val = rest
                    if (match(val, /[[:space:]]#/)) val = substr(val, 1, RSTART - 1)
                    sub(/^[[:space:]]+/, "", val)
                    sub(/[[:space:]]+$/, "", val)
                    if (val == "") {
                        bad = 1
                    } else if (substr(val, 1, 1) == "$") {
                        if (keystr != "runs-on" || val !~ /^\$\{\{[[:space:]]*matrix\.os[[:space:]]*\}\}$/) bad = 1
                    } else if (val ~ /^[*&!]/) {
                        bad = 1
                    } else if (val ~ /^[A-Za-z0-9._-]+$/) {
                        bad = 0
                    } else if (val ~ /^[A-Za-z0-9._-]+,/ && before ~ /\{/) {
                        bad = 0
                    } else if (val ~ /^[A-Za-z0-9._-]+\}/ && before ~ /\{/) {
                        bad = 0
                    } else {
                        bad = 1
                    }
                }
                if (bad && !shown) { print FNR ": " $0; shown = 1 }
                consumed = consumed substr(line, 1, ks + kl - 1)
                line = substr(line, ks + kl)
            }
        }
    ' "$1"
}

# Verify one workflow file. Emits PASS/FAIL and returns non-zero if any check
# failed. A leading label namespaces the output for the self-test replicas.
check_workflow() {
    local file="$1"
    local label="$2"
    local ok=1

    local build_block stage_block
    build_block="$(mktemp)"
    stage_block="$(mktemp)"
    extract_step "$file" "$BUILD_STEP_NAME" > "$build_block"
    extract_step "$file" "$STAGE_STEP_NAME" > "$stage_block"

    if [ ! -s "$build_block" ]; then
        gate_fail "${label} G1: step '${BUILD_STEP_NAME}' not found in ${file}"
        rm -f "$build_block" "$stage_block"
        return 1
    fi

    read -r g f < <(guard_region "$build_block")
    local daemon_line relay_line cli_line
    daemon_line="$(line_of "$build_block" "-p rustynetd")"
    relay_line="$(line_of "$build_block" "-p rustynet-relay --features daemon")"
    cli_line="$(line_of "$build_block" "-p rustynet-cli")"

    # G1: daemon + relay built unconditionally (not inside the Windows guard).
    local unconditional=1
    if [ "$daemon_line" -eq 0 ]; then unconditional=0; fi
    if [ "$relay_line" -eq 0 ]; then unconditional=0; fi
    if [ "$g" -gt 0 ] && [ "$f" -gt "$g" ]; then
        if [ "$daemon_line" -gt "$g" ] && [ "$daemon_line" -lt "$f" ]; then unconditional=0; fi
        if [ "$relay_line" -gt "$g" ] && [ "$relay_line" -lt "$f" ]; then unconditional=0; fi
    fi
    if [ "$unconditional" -eq 1 ]; then
        gate_pass "${label} G1: rustynetd + rustynet-relay built on every leg"
    else
        gate_fail "${label} G1: rustynetd (line ${daemon_line}) and rustynet-relay (line ${relay_line}) must be built OUTSIDE the Windows guard"
        ok=0
    fi

    # G2: rustynet-cli built only inside a Windows-EXCLUDING guard.
    if [ "$cli_line" -eq 0 ]; then
        gate_fail "${label} G2: no '-p rustynet-cli' build found (the Unix legs must still build it)"
        ok=0
    elif [ "$g" -eq 0 ] || [ "$f" -eq 0 ]; then
        gate_fail "${label} G2: '-p rustynet-cli' build is not guarded by a 'matrix.family != \"windows\"' condition"
        ok=0
    elif [ "$cli_line" -gt "$g" ] && [ "$cli_line" -lt "$f" ]; then
        gate_pass "${label} G2: rustynet-cli build guarded off the Windows leg"
    else
        gate_fail "${label} G2: '-p rustynet-cli' build (line ${cli_line}) is outside the Windows-excluding guard [${g},${f}]"
        ok=0
    fi

    # G3: staging — daemon + relay copied unconditionally, CLI only in the guard.
    local stage_ok=1
    if [ -z "$stage_block" ] || [ ! -s "$stage_block" ]; then
        gate_fail "${label} G3: step '${STAGE_STEP_NAME}' not found in ${file}"
        rm -f "$build_block" "$stage_block"
        return 1
    fi
    local s_daemon s_relay s_cli sg sf
    s_daemon="$(line_of "$stage_block" 'dist/rustynetd-$T$X')"
    s_relay="$(line_of "$stage_block" 'dist/rustynet-relay-$T$X')"
    s_cli="$(line_of "$stage_block" '"$BIN/rustynet-cli$X"')"
    read -r sg sf < <(guard_region "$stage_block")
    if [ "$s_daemon" -eq 0 ]; then stage_ok=0; fi
    if [ "$s_relay" -eq 0 ]; then stage_ok=0; fi
    if [ "$s_cli" -eq 0 ]; then stage_ok=0; fi
    if [ "$sg" -eq 0 ] || [ "$sf" -eq 0 ] || [ "$s_cli" -le "$sg" ] || [ "$s_cli" -ge "$sf" ]; then stage_ok=0; fi
    if [ "$sg" -gt 0 ] && [ "$sf" -gt "$sg" ]; then
        if [ "$s_daemon" -gt "$sg" ] && [ "$s_daemon" -lt "$sf" ]; then stage_ok=0; fi
        if [ "$s_relay" -gt "$sg" ] && [ "$s_relay" -lt "$sf" ]; then stage_ok=0; fi
    fi
    if [ "$stage_ok" -eq 1 ]; then
        gate_pass "${label} G3: stages rustynetd + rustynet-relay always, rustynet only off Windows"
    else
        gate_fail "${label} G3: staging must copy rustynetd/rustynet-relay unconditionally and the rustynet-cli artifact inside the Windows-excluding guard"
        ok=0
    fi

    # G4: the guard must be exercised — the matrix still has a Windows leg.
    if grep -Eq 'family: *windows' "$file"; then
        gate_pass "${label} G4: build matrix declares a Windows leg"
    else
        gate_fail "${label} G4: no 'family: windows' matrix row — the Windows guard would be vacuous"
        ok=0
    fi

    # G5: every runner label must be a LIVE GitHub-hosted label (allowlist).
    # Fail-closed classification first: every os:/runs-on: value must be a
    # bare [A-Za-z0-9._-]+ token (flow-map `,`/`}` continuations allowed on
    # `{ ... }` lines) or exactly `runs-on: ${{ matrix.os }}`; anything else
    # (quoted/flow values, space before the colon, block-list runs-on, YAML
    # alias `*x` or anchor `&x`, any other `${{ }}` expression, or a value
    # with characters outside the label class) is a hard failure. Silently
    # skipping any of those would let a one-character edit (a quote, an
    # alias, an env indirection) disarm the allowlist below.
    local exotic
    exotic="$(exotic_label_lines "$file")"
    local g5_ok=1 n_labels=0 bad_labels="" lbl want allowed
    while IFS= read -r lbl; do
        if [ -z "$lbl" ]; then continue; fi
        n_labels=$((n_labels + 1))
        allowed=0
        # shellcheck disable=SC2086  # allowlist is a controlled literal
        for want in $RUNNER_LABEL_ALLOWLIST; do
            if [ "$lbl" = "$want" ]; then allowed=1; break; fi
        done
        if [ "$allowed" -eq 0 ]; then
            bad_labels="${bad_labels} '${lbl}'"
            g5_ok=0
        fi
    done <<< "$(runner_labels "$file")"
    if [ -n "$exotic" ]; then
        gate_fail "${label} G5: runner-label value the gate cannot positively classify (quoted or flow-form value, space before the colon, block-list runs-on, a YAML alias *x or anchor &x, a \${{ }} expression other than exactly runs-on: \${{ matrix.os }}, or any value containing a character outside [A-Za-z0-9._-]) at:
${exotic}"
        ok=0
    elif [ "$n_labels" -eq 0 ]; then
        gate_fail "${label} G5: no runner labels found — no matrix os: rows and no literal runs-on"
        ok=0
    elif [ "$g5_ok" -eq 1 ]; then
        gate_pass "${label} G5: all ${n_labels} runner label(s) in the live-label allowlist"
    else
        gate_fail "${label} G5: unknown/retired runner label(s):${bad_labels} — not in the live-label allowlist"
        ok=0
    fi

    rm -f "$build_block" "$stage_block"
    [ "$ok" -eq 1 ]
}

echo "== Q1 release-workflow Windows-leg gate =="
echo "target: ${TARGET}"

if [ ! -f "$TARGET" ]; then
    echo "FAIL target missing: ${TARGET}" >&2
    exit 1
fi

if check_workflow "$TARGET" "target"; then
    echo "PASS target: release workflow ships the right per-platform artifact set"
else
    echo "FAIL target: release workflow structural checks failed" >&2
    exit 1
fi

# --- self-test battery: the gate must REJECT the pre-fix shapes -------------
#
# A replica workflow carrying the PRE-FIX steps (rustynet-cli built and staged
# unguarded on the Windows leg).
tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

make_replica() {
    local out="$1" build_body="$2" stage_body="$3" os="${4:-windows-2022}"
    {
        printf 'name: replica\non: push\njobs:\n'
        printf '  build:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        include:\n'
        printf '          - { os: %s, target: x86_64-pc-windows-msvc, family: windows }\n' "$os"
        printf '    steps:\n'
        printf '      - name: %s\n' "$BUILD_STEP_NAME"
        printf '        run: |\n'
        printf '%s\n' "$build_body" | sed 's/^/          /'
        printf '      - name: %s\n' "$STAGE_STEP_NAME"
        printf '        run: |\n'
        printf '%s\n' "$stage_body" | sed 's/^/          /'
    } > "$out"
}

# Replace the FIRST occurrence of literal $2 with literal $3 in file $1.
# Pure awk (index/substr), so it behaves identically on BSD and GNU — no
# `sed -i` dialect differences.
mutate_first() {
    awk -v old="$2" -v new="$3" '
        { i = index($0, old); if (i > 0 && !did) { $0 = substr($0, 1, i - 1) new substr($0, i + length(old)); did = 1 } print }
    ' "$1" > "$1.mut" && mv "$1.mut" "$1"
}

PREFIX_BUILD='cargo build --release --locked --target "$T" -p rustynetd
cargo build --release --locked --target "$T" -p rustynet-cli --bin rustynet-cli
cargo build --release --locked --target "$T" -p rustynet-relay --features daemon'

PREFIX_STAGE='cp "$BIN/rustynetd$X" "dist/rustynetd-$T$X"
cp "$BIN/rustynet-cli$X" "dist/rustynet-$T$X"
cp "$BIN/rustynet-relay$X" "dist/rustynet-relay-$T$X"'

make_replica "${tmpdir}/prefix.yml" "$PREFIX_BUILD" "$PREFIX_STAGE"
if prefix_out="$(check_workflow "${tmpdir}/prefix.yml" "prefix-replica" 2>&1)"; then
    gate_fail "selftest T1: pre-fix replica PASSED the checker (gate is fail-open): ${prefix_out}"
else
    if printf '%s\n' "$prefix_out" | grep -q 'FAIL prefix-replica G2'; then
        gate_pass "selftest T1: pre-fix unguarded rustynet-cli build rejected end-to-end (G2)"
    else
        gate_fail "selftest T1: pre-fix replica rejected but not via G2: ${prefix_out}"
    fi
fi

# T2: an INVERTED guard (`family == "windows"` builds the CLI) must also be
# rejected — otherwise the gate would accept a guard that runs the Unix-only
# crate exactly on Windows.
INVERTED_BUILD='cargo build --release --locked --target "$T" -p rustynetd
cargo build --release --locked --target "$T" -p rustynet-relay --features daemon
if [ "${{ matrix.family }}" = "windows" ]; then
  cargo build --release --locked --target "$T" -p rustynet-cli --bin rustynet-cli
fi'
INVERTED_STAGE='cp "$BIN/rustynetd$X" "dist/rustynetd-$T$X"
cp "$BIN/rustynet-relay$X" "dist/rustynet-relay-$T$X"
if [ "${{ matrix.family }}" = "windows" ]; then
  cp "$BIN/rustynet-cli$X" "dist/rustynet-$T$X"
fi'
make_replica "${tmpdir}/inverted.yml" "$INVERTED_BUILD" "$INVERTED_STAGE"
if inverted_out="$(check_workflow "${tmpdir}/inverted.yml" "inverted-replica" 2>&1)"; then
    gate_fail "selftest T2: inverted guard PASSED the checker (gate accepts building rustynet-cli ON Windows): ${inverted_out}"
else
    if printf '%s\n' "$inverted_out" | grep -q 'FAIL inverted-replica G2'; then
        gate_pass "selftest T2: inverted (Windows-only) guard rejected end-to-end (G2)"
    else
        gate_fail "selftest T2: inverted replica rejected but not via G2: ${inverted_out}"
    fi
fi

# T3: the FIXED shape must pass the same checker (positive control), proving
# the gate is not trivially rejecting everything.
FIXED_BUILD='cargo build --release --locked --target "$T" -p rustynetd
cargo build --release --locked --target "$T" -p rustynet-relay --features daemon
if [ "${{ matrix.family }}" != "windows" ]; then
  cargo build --release --locked --target "$T" -p rustynet-cli --bin rustynet-cli
else
  echo "windows leg: skipping rustynet-cli"
fi'
FIXED_STAGE='cp "$BIN/rustynetd$X" "dist/rustynetd-$T$X"
cp "$BIN/rustynet-relay$X" "dist/rustynet-relay-$T$X"
if [ "${{ matrix.family }}" != "windows" ]; then
  cp "$BIN/rustynet-cli$X" "dist/rustynet-$T$X"
fi'
make_replica "${tmpdir}/fixed.yml" "$FIXED_BUILD" "$FIXED_STAGE"
if fixed_out="$(check_workflow "${tmpdir}/fixed.yml" "fixed-replica" 2>&1)"; then
    gate_pass "selftest T3: fixed-shape replica accepted (positive control)"
else
    gate_fail "selftest T3: fixed-shape replica REJECTED by the checker: ${fixed_out}"
fi

# T4: a RETIRED runner label must be rejected by G5. The bodies are the FIXED
# ones so the ONLY possible failure is the label check — a G5 rejection here
# is attributable to G5 alone. macos-13 was retired by GitHub in 2025; a
# workflow carrying it never starts that leg, so the gate must refuse it.
make_replica "${tmpdir}/retired-label.yml" "$FIXED_BUILD" "$FIXED_STAGE" "macos-13"
if retired_out="$(check_workflow "${tmpdir}/retired-label.yml" "retired-replica" 2>&1)"; then
    gate_fail "selftest T4: retired runner label macos-13 PASSED the checker (G5 is fail-open): ${retired_out}"
else
    if printf '%s\n' "$retired_out" | grep -q 'FAIL retired-replica G5'; then
        gate_pass "selftest T4: retired runner label macos-13 rejected end-to-end (G5)"
    else
        gate_fail "selftest T4: retired-label replica rejected but not via G5: ${retired_out}"
    fi
fi

# T4b: macos-14 must ALSO be rejected now — GitHub retires it on 2026-11-02
# (actions/runner-images issue #13518; brownout failures live since 2026-07)
# and the allowlist no longer carries it. Same silent-leg-loss failure mode
# as T4, on the sibling arm64 leg.
make_replica "${tmpdir}/retired-label-14.yml" "$FIXED_BUILD" "$FIXED_STAGE" "macos-14"
if retired14_out="$(check_workflow "${tmpdir}/retired-label-14.yml" "retired14-replica" 2>&1)"; then
    gate_fail "selftest T4b: dying runner label macos-14 PASSED the checker (allowlist still admits it): ${retired14_out}"
else
    if printf '%s\n' "$retired14_out" | grep -q 'FAIL retired14-replica G5'; then
        gate_pass "selftest T4b: dying runner label macos-14 rejected end-to-end (G5)"
    else
        gate_fail "selftest T4b: macos-14 replica rejected but not via G5: ${retired14_out}"
    fi
fi

# T5: the live Intel label this workflow now uses must pass the full checker
# (positive control for G5 — proves the allowlist admits the intended label
# and that T4's rejection is about the label, not the replica shape).
make_replica "${tmpdir}/intel-label.yml" "$FIXED_BUILD" "$FIXED_STAGE" "macos-15-intel"
if intel_out="$(check_workflow "${tmpdir}/intel-label.yml" "intel-replica" 2>&1)"; then
    gate_pass "selftest T5: live runner label macos-15-intel accepted (G5 positive control)"
else
    gate_fail "selftest T5: live runner label macos-15-intel REJECTED by the checker: ${intel_out}"
fi

# T6-T9: the collector reads bare unquoted labels only, so every OTHER
# valid-YAML spelling must be REJECTED outright, never silently skipped.
# Each of these four replicas passed the pre-fix checker green (the review's
# P1/P2/P3/P4 bypasses): a quoted value, a flow sequence, a space before the
# colon and a block-list `runs-on:` were all invisible to the collector and
# sailed through G5. The label in T6-T8 is the LIVE macos-15-intel, so a
# rejection there is attributable to the spelling alone.
make_replica "${tmpdir}/quoted-label.yml" "$FIXED_BUILD" "$FIXED_STAGE" "macos-15-intel"
mutate_first "${tmpdir}/quoted-label.yml" 'os: macos-15-intel' 'os: "macos-15-intel"'
if quoted_out="$(check_workflow "${tmpdir}/quoted-label.yml" "quoted-replica" 2>&1)"; then
    gate_fail "selftest T6: quoted os value PASSED the checker (quoted labels are invisible to the collector): ${quoted_out}"
else
    if printf '%s\n' "$quoted_out" | grep -q 'FAIL quoted-replica G5'; then
        gate_pass "selftest T6: quoted os value rejected end-to-end (G5 spelling hardening)"
    else
        gate_fail "selftest T6: quoted-label replica rejected but not via G5: ${quoted_out}"
    fi
fi

make_replica "${tmpdir}/flow-label.yml" "$FIXED_BUILD" "$FIXED_STAGE" "macos-15-intel"
mutate_first "${tmpdir}/flow-label.yml" 'os: macos-15-intel' 'os: [macos-15-intel]'
if flow_out="$(check_workflow "${tmpdir}/flow-label.yml" "flow-replica" 2>&1)"; then
    gate_fail "selftest T7: flow-sequence os value PASSED the checker (flow labels are invisible to the collector): ${flow_out}"
else
    if printf '%s\n' "$flow_out" | grep -q 'FAIL flow-replica G5'; then
        gate_pass "selftest T7: flow-sequence os value rejected end-to-end (G5 spelling hardening)"
    else
        gate_fail "selftest T7: flow-label replica rejected but not via G5: ${flow_out}"
    fi
fi

make_replica "${tmpdir}/spaced-label.yml" "$FIXED_BUILD" "$FIXED_STAGE" "macos-15-intel"
mutate_first "${tmpdir}/spaced-label.yml" 'os: macos-15-intel' 'os : macos-15-intel'
if spaced_out="$(check_workflow "${tmpdir}/spaced-label.yml" "spaced-replica" 2>&1)"; then
    gate_fail "selftest T8: space-before-colon os key PASSED the checker (spaced keys are invisible to the collector): ${spaced_out}"
else
    if printf '%s\n' "$spaced_out" | grep -q 'FAIL spaced-replica G5'; then
        gate_pass "selftest T8: space-before-colon os key rejected end-to-end (G5 spelling hardening)"
    else
        gate_fail "selftest T8: spaced-label replica rejected but not via G5: ${spaced_out}"
    fi
fi

make_replica "${tmpdir}/blocklist-label.yml" "$FIXED_BUILD" "$FIXED_STAGE" "macos-15-intel"
cat >> "${tmpdir}/blocklist-label.yml" <<'EOF'
  monitor:
    runs-on:
      - ubuntu-latest
    steps:
      - run: 'true'
EOF
if block_out="$(check_workflow "${tmpdir}/blocklist-label.yml" "blocklist-replica" 2>&1)"; then
    gate_fail "selftest T9: block-list runs-on PASSED the checker (block-list labels are invisible to the collector): ${block_out}"
else
    if printf '%s\n' "$block_out" | grep -q 'FAIL blocklist-replica G5'; then
        gate_pass "selftest T9: block-list runs-on rejected end-to-end (G5 spelling hardening)"
    else
        gate_fail "selftest T9: blocklist-label replica rejected but not via G5: ${block_out}"
    fi
fi

# T10: a YAML SCALAR ALIAS must be rejected. `os: *rl` is valid YAML that
# the Actions runner's parser resolves to the anchored value (here the
# retired macos-13), but no bare token is present for the collector and the
# alias dereference is not verifiable by a textual gate — so the spelling
# itself must fail closed, whatever the anchor holds.
make_replica "${tmpdir}/alias-label.yml" "$FIXED_BUILD" "$FIXED_STAGE" "windows-2022"
{ printf 'x-anchor: &rl macos-13\n'; cat "${tmpdir}/alias-label.yml"; } > "${tmpdir}/alias-label.yml.new" \
    && mv "${tmpdir}/alias-label.yml.new" "${tmpdir}/alias-label.yml"
mutate_first "${tmpdir}/alias-label.yml" 'os: windows-2022' 'os: *rl'
if alias_out="$(check_workflow "${tmpdir}/alias-label.yml" "alias-replica" 2>&1)"; then
    gate_fail "selftest T10: scalar alias os value PASSED the checker (alias *rl dereferences to the anchored label): ${alias_out}"
else
    if printf '%s\n' "$alias_out" | grep -q 'FAIL alias-replica G5'; then
        gate_pass "selftest T10: scalar alias os: *rl rejected end-to-end (G5 fail-closed classification)"
    else
        gate_fail "selftest T10: alias-label replica rejected but not via G5: ${alias_out}"
    fi
fi

# T11: an anchored os value must be rejected, even with a LIVE label: the
# value the runner sees is the anchor's target, which this textual gate
# cannot bind to the `&a` declaration with certainty.
make_replica "${tmpdir}/anchor-label.yml" "$FIXED_BUILD" "$FIXED_STAGE" "windows-2022"
mutate_first "${tmpdir}/anchor-label.yml" 'os: windows-2022' 'os: &a macos-15-intel'
if anchor_out="$(check_workflow "${tmpdir}/anchor-label.yml" "anchor-replica" 2>&1)"; then
    gate_fail "selftest T11: anchored os value PASSED the checker (anchor &a hides the effective value): ${anchor_out}"
else
    if printf '%s\n' "$anchor_out" | grep -q 'FAIL anchor-replica G5'; then
        gate_pass "selftest T11: anchored os: &a rejected end-to-end (G5 fail-closed classification)"
    else
        gate_fail "selftest T11: anchor-label replica rejected but not via G5: ${anchor_out}"
    fi
fi

# T12: a `${{ env.X }}` indirection on runs-on must be rejected. This
# spelling passed the pre-hardening checker: the collector skipped every
# runs-on ${{ line assuming it was the matrix.os indirection, but the env
# context is documented available in runs-on and env.RUNNER is invisible to
# any textual scan of this file.
make_replica "${tmpdir}/envexpr-label.yml" "$FIXED_BUILD" "$FIXED_STAGE" "windows-2022"
cat >> "${tmpdir}/envexpr-label.yml" <<'EOF'
  monitor:
    env: { RUNNER: macos-13 }
    runs-on: ${{ env.RUNNER }}
    steps:
      - run: 'true'
EOF
if envexpr_out="$(check_workflow "${tmpdir}/envexpr-label.yml" "envexpr-replica" 2>&1)"; then
    gate_fail "selftest T12: runs-on \${{ env.X }} PASSED the checker (env indirection is invisible to the collector): ${envexpr_out}"
else
    if printf '%s\n' "$envexpr_out" | grep -q 'FAIL envexpr-replica G5'; then
        gate_pass "selftest T12: runs-on \${{ env.RUNNER }} rejected end-to-end (G5 fail-closed classification)"
    else
        gate_fail "selftest T12: envexpr-label replica rejected but not via G5: ${envexpr_out}"
    fi
fi

# T13: a `${{ vars.X }}` matrix os value must be rejected (block form, the
# only valid YAML shape for it). The repo variable RUNNER never appears in
# the file, so the effective label is unverifiable here.
make_replica "${tmpdir}/varsexpr-label.yml" "$FIXED_BUILD" "$FIXED_STAGE" "windows-2022"
cat >> "${tmpdir}/varsexpr-label.yml" <<'EOF'
  alt:
    strategy:
      matrix:
        include:
          - os: ${{ vars.RUNNER }}
    runs-on: ubuntu-latest
    steps:
      - run: 'true'
EOF
if varsexpr_out="$(check_workflow "${tmpdir}/varsexpr-label.yml" "varsexpr-replica" 2>&1)"; then
    gate_fail "selftest T13: matrix os \${{ vars.X }} PASSED the checker (vars indirection is invisible to the collector): ${varsexpr_out}"
else
    if printf '%s\n' "$varsexpr_out" | grep -q 'FAIL varsexpr-replica G5'; then
        gate_pass "selftest T13: matrix os: \${{ vars.RUNNER }} rejected end-to-end (G5 fail-closed classification)"
    else
        gate_fail "selftest T13: varsexpr-label replica rejected but not via G5: ${varsexpr_out}"
    fi
fi

# T14: a value that starts with a live label but carries any other token
# must be rejected: `os: macos-15-intel ubuntu-latest` is ONE YAML scalar
# that GitHub would look up verbatim (no such runner), yet the old
# collector harvested only the leading token and the allowlist admitted it.
# Both tokens are LIVE labels, so the rejection here is attributable to the
# classification rule alone, never to the allowlist.
make_replica "${tmpdir}/multitoken-label.yml" "$FIXED_BUILD" "$FIXED_STAGE" "windows-2022"
mutate_first "${tmpdir}/multitoken-label.yml" 'os: windows-2022' 'os: macos-15-intel ubuntu-latest'
if multitoken_out="$(check_workflow "${tmpdir}/multitoken-label.yml" "multitoken-replica" 2>&1)"; then
    gate_fail "selftest T14: multi-token os value PASSED the checker (only the leading token was harvested): ${multitoken_out}"
else
    if printf '%s\n' "$multitoken_out" | grep -q 'FAIL multitoken-replica G5'; then
        gate_pass "selftest T14: multi-token os value rejected end-to-end (G5 fail-closed classification)"
    else
        gate_fail "selftest T14: multitoken-label replica rejected but not via G5: ${multitoken_out}"
    fi
fi

# T15: POSITIVE control for the one allowed indirection: a replica whose
# build job runs via `runs-on: ${{ matrix.os }}` (the shape the target
# release.yml uses) must still pass — proving the fail-closed classifier
# did not over-reject the expression form whose values the collector reads.
make_replica "${tmpdir}/matrixos-label.yml" "$FIXED_BUILD" "$FIXED_STAGE" "windows-2022"
mutate_first "${tmpdir}/matrixos-label.yml" 'runs-on: ubuntu-latest' 'runs-on: ${{ matrix.os }}'
if matrixos_out="$(check_workflow "${tmpdir}/matrixos-label.yml" "matrixos-replica" 2>&1)"; then
    gate_pass "selftest T15: runs-on \${{ matrix.os }} indirection accepted (G5 positive control)"
else
    gate_fail "selftest T15: runs-on \${{ matrix.os }} indirection REJECTED by the checker: ${matrixos_out}"
fi

# T16: a quoted KEY ("runs-on": macos-13) must be rejected. Valid YAML that
# GitHub executes, but invisible to both the bare-key collector and the
# value classifier (the quote breaks the key:colon shape), so the spelling
# itself fails closed regardless of the value.
make_replica "${tmpdir}/quotedkey-label.yml" "$FIXED_BUILD" "$FIXED_STAGE" "windows-2022"
cat >> "${tmpdir}/quotedkey-label.yml" <<'EOF'
  sneaky:
    "runs-on": macos-13
    steps:
      - run: 'true'
EOF
if quotedkey_out="$(check_workflow "${tmpdir}/quotedkey-label.yml" "quotedkey-replica" 2>&1)"; then
    gate_fail "selftest T16: quoted-key runs-on PASSED the checker (quoted keys are invisible to the classifier): ${quotedkey_out}"
else
    if printf '%s\n' "$quotedkey_out" | grep -q 'FAIL quotedkey-replica G5'; then
        gate_pass "selftest T16: quoted-key \"runs-on\": rejected end-to-end (G5 fail-closed classification)"
    else
        gate_fail "selftest T16: quotedkey-label replica rejected but not via G5: ${quotedkey_out}"
    fi
fi

# T17: an EXPLICIT YAML key (? runs-on with the value on the next ": v"
# line) must be rejected. Valid YAML the runner parses, but NEITHER line
# carries the `runs-on:` colon shape, so the collector and the value
# classifier are both blind to it and the job would run on the anchored
# label. The other replica labels are LIVE, so the rejection here is
# attributable to the spelling alone.
make_replica "${tmpdir}/explicitkey-label.yml" "$FIXED_BUILD" "$FIXED_STAGE" "windows-2022"
cat >> "${tmpdir}/explicitkey-label.yml" <<'EOF'
  sneaky:
    ? runs-on
    : macos-13
    steps:
      - run: 'true'
EOF
if explicitkey_out="$(check_workflow "${tmpdir}/explicitkey-label.yml" "explicitkey-replica" 2>&1)"; then
    gate_fail "selftest T17: explicit-key runs-on PASSED the checker (explicit keys are invisible to the classifier): ${explicitkey_out}"
else
    if printf '%s\n' "$explicitkey_out" | grep -q 'FAIL explicitkey-replica G5'; then
        gate_pass "selftest T17: explicit-key \"? runs-on:\" rejected end-to-end (G5 fail-closed classification)"
    else
        gate_fail "selftest T17: explicitkey-label replica rejected but not via G5: ${explicitkey_out}"
    fi
fi

# T17b: the SAME explicit-key spelling as a matrix include row is the worst
# shape: the job's `runs-on: ${{ matrix.os }}` is the one ALLOWED
# indirection, so every other row is harvested and allowlisted while the
# effective label is the anchored macos-13. Must fail closed like T17.
make_replica "${tmpdir}/explicitkey-matrix.yml" "$FIXED_BUILD" "$FIXED_STAGE" "windows-2022"
mutate_first "${tmpdir}/explicitkey-matrix.yml" \
    '          - { os: windows-2022, target: x86_64-pc-windows-msvc, family: windows }' \
    '          - ? os\n            : macos-13\n            target: x86_64-pc-windows-msvc\n            family: windows'
if explicitkeym_out="$(check_workflow "${tmpdir}/explicitkey-matrix.yml" "explicitkeym-replica" 2>&1)"; then
    gate_fail "selftest T17b: explicit-key matrix os row PASSED the checker (it rides the allowed matrix.os indirection): ${explicitkeym_out}"
else
    if printf '%s\n' "$explicitkeym_out" | grep -q 'FAIL explicitkeym-replica G5'; then
        gate_pass "selftest T17b: explicit-key matrix \"- ? os\" rejected end-to-end (G5 fail-closed classification)"
    else
        gate_fail "selftest T17b: explicitkey-matrix replica rejected but not via G5: ${explicitkeym_out}"
    fi
fi

# T17c: the FLOW form of the explicit key ({? os : macos-13, ...}) must be
# rejected the same way: valid YAML, same blindness, same ride on
# matrix.os.
make_replica "${tmpdir}/explicitkey-flow.yml" "$FIXED_BUILD" "$FIXED_STAGE" "windows-2022"
mutate_first "${tmpdir}/explicitkey-flow.yml" \
    '          - { os: windows-2022, target: x86_64-pc-windows-msvc, family: windows }' \
    '          - {? os : macos-13, target: x86_64-pc-windows-msvc, family: windows }'
if explicitkeyf_out="$(check_workflow "${tmpdir}/explicitkey-flow.yml" "explicitkeyf-replica" 2>&1)"; then
    gate_fail "selftest T17c: flow explicit-key os PASSED the checker (flow explicit keys are invisible to the classifier): ${explicitkeyf_out}"
else
    if printf '%s\n' "$explicitkeyf_out" | grep -q 'FAIL explicitkeyf-replica G5'; then
        gate_pass "selftest T17c: flow explicit-key \"{? os :}\" rejected end-to-end (G5 fail-closed classification)"
    else
        gate_fail "selftest T17c: explicitkey-flow replica rejected but not via G5: ${explicitkeyf_out}"
    fi
fi

# T17d: the same explicit key as a LATER entry of a flow map, with its
# value on the NEXT line (`{ ubuntu-latest, ? os
# : macos-13 }`): valid YAML, and neither line carries the colon shape, so
# only the indicator pre-check can see it.
make_replica "${tmpdir}/explicitkey-flow2.yml" "$FIXED_BUILD" "$FIXED_STAGE" "windows-2022"
mutate_first "${tmpdir}/explicitkey-flow2.yml" \
    '          - { os: windows-2022, target: x86_64-pc-windows-msvc, family: windows }' \
    '          - { os: windows-2022, ? os\n: macos-13, target: x86_64-pc-windows-msvc, family: windows }'
if explicitkeyf2_out="$(check_workflow "${tmpdir}/explicitkey-flow2.yml" "explicitkeyf2-replica" 2>&1)"; then
    gate_fail "selftest T17d: flow explicit-key os after a comma PASSED the checker: ${explicitkeyf2_out}"
else
    if printf '%s\n' "$explicitkeyf2_out" | grep -q 'FAIL explicitkeyf2-replica G5'; then
        gate_pass "selftest T17d: flow explicit-key \", ? os\" (value next line) rejected end-to-end (G5 fail-closed classification)"
    else
        gate_fail "selftest T17d: explicitkey-flow2 replica rejected but not via G5: ${explicitkeyf2_out}"
    fi
fi

# T17e: a QUOTED explicit key (? "runs-on" / : macos-13) must be rejected:
# valid YAML the runner parses, invisible to the colon-shape checks.
make_replica "${tmpdir}/explicitkey-quoted.yml" "$FIXED_BUILD" "$FIXED_STAGE" "windows-2022"
cat >> "${tmpdir}/explicitkey-quoted.yml" <<'EOF'
  sneaky:
    ? "runs-on"
    : macos-13
    steps:
      - run: 'true'
EOF
if explicitkeyq_out="$(check_workflow "${tmpdir}/explicitkey-quoted.yml" "explicitkeyq-replica" 2>&1)"; then
    gate_fail "selftest T17e: quoted explicit-key runs-on PASSED the checker: ${explicitkeyq_out}"
else
    if printf '%s\n' "$explicitkeyq_out" | grep -q 'FAIL explicitkeyq-replica G5'; then
        gate_pass "selftest T17e: quoted explicit-key \"? \\\"runs-on\\\"\" rejected end-to-end (G5 fail-closed classification)"
    else
        gate_fail "selftest T17e: explicitkey-quoted replica rejected but not via G5: ${explicitkeyq_out}"
    fi
fi

# T17f: an ANCHORED explicit key (? &k runs-on / : macos-13) must be
# rejected: valid YAML the runner parses, invisible to the colon-shape
# checks.
make_replica "${tmpdir}/explicitkey-anchored.yml" "$FIXED_BUILD" "$FIXED_STAGE" "windows-2022"
cat >> "${tmpdir}/explicitkey-anchored.yml" <<'EOF'
  sneaky:
    ? &k runs-on
    : macos-13
    steps:
      - run: 'true'
EOF
if explicitkeya_out="$(check_workflow "${tmpdir}/explicitkey-anchored.yml" "explicitkeya-replica" 2>&1)"; then
    gate_fail "selftest T17f: anchored explicit-key runs-on PASSED the checker: ${explicitkeya_out}"
else
    if printf '%s\n' "$explicitkeya_out" | grep -q 'FAIL explicitkeya-replica G5'; then
        gate_pass "selftest T17f: anchored explicit-key \"? &k runs-on\" rejected end-to-end (G5 fail-closed classification)"
    else
        gate_fail "selftest T17f: explicitkey-anchored replica rejected but not via G5: ${explicitkeya_out}"
    fi
fi

if [ "${failures}" -eq 0 ]; then
    echo "release-workflow Windows-leg gate: ALL GATES PASS"
    exit 0
fi
echo "release-workflow Windows-leg gate: ${failures} FAILURE(S)" >&2
exit 1
