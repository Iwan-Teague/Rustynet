#!/usr/bin/env bash
# Witness for the self-exec deleted-binary defect (AQ lane
# rustynet-b25-self-exec-deleted-binary).
#
# Defect: the CI gate flows re-execute this binary for nested ops
# (`run_self_command_allow_failure` in
# crates/rustynet-cli/src/ops_ci_release_perf.rs used to exec
# `std::env::current_exe()` directly). On Linux the flow's own `cargo test`
# stages relink `target/debug/rustynet-cli` mid-run, so /proc/self/exe
# resolves to "<path> (deleted)" and every nested self-op fails with
# ENOENT: "failed to execute [\"ops\", \"sign-release-artifact\"]: No such
# file or directory".
#
# Reproduction: launch `ops run-supply-chain-integrity-gates`, then replace
# target/debug/rustynet-cli on disk while it runs (mv over the file, the
# same rename `cargo` performs), and require the flow to still PASS with a
# byte-identical pinned copy (rustynet-self-exec-<pid>-* under $TMPDIR).
# Before the fix this fails (ENOENT on Linux); after the fix it passes on
# Linux and macOS alike.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

fail() {
    echo "WITNESS: FAIL: $*" >&2
    exit 1
}

command -v cargo >/dev/null 2>&1 || fail "cargo not on PATH"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

echo "WITNESS: building rustynet-cli in $REPO_DIR"
( cd "$REPO_DIR" && cargo build --quiet -p rustynet-cli ) || fail "cargo build -p rustynet-cli"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_DIR/target}"
case "$TARGET_DIR" in
    /*) ;;
    *) TARGET_DIR="$REPO_DIR/$TARGET_DIR" ;;
esac
BIN="$TARGET_DIR/debug/rustynet-cli"
[ -x "$BIN" ] || fail "missing $BIN"
PRE_SHA="$(sha256_of "$BIN")"
echo "WITNESS: pre-replacement sha256 $PRE_SHA"

ARTIFACT="$SCRATCH/artifact.bin"
SBOM="$SCRATCH/sbom.json"
SBOM_SHA="$SCRATCH/sbom.sha256"
PROVENANCE="$SCRATCH/provenance.json"
printf 'rustynet self-exec witness artifact\n' > "$ARTIFACT"
printf '{"witness":"supply-chain-input"}\n' > "$SBOM"
sha256_of "$SBOM" > "$SBOM_SHA"
export RUSTYNET_RELEASE_ARTIFACT_PATH="$ARTIFACT"
export RUSTYNET_RELEASE_SBOM_PATH="$SBOM"
export RUSTYNET_RELEASE_SBOM_SHA256_PATH="$SBOM_SHA"
export RUSTYNET_RELEASE_PROVENANCE_PATH="$PROVENANCE"
export RUSTYNET_RELEASE_PROVENANCE_SIGNING_KEY_PATH="$SCRATCH/signing.key"
export RUSTYNET_RELEASE_PROVENANCE_VERIFIER_KEY_PATH="$SCRATCH/verifier.key"

FLOW_LOG="$SCRATCH/flow.log"
echo "WITNESS: launching ops run-supply-chain-integrity-gates (pid follows)"
"$BIN" ops run-supply-chain-integrity-gates >"$FLOW_LOG" 2>&1 &
FLOW=$!

# Wait for the flow's first child process (or early exit), then replace the
# on-disk binary exactly the way `cargo` does: rename a new file over it.
seen_child=0
for _ in $(seq 1 6000); do
    if ! kill -0 "$FLOW" 2>/dev/null; then
        break
    fi
    if pgrep -P "$FLOW" >/dev/null 2>&1; then
        seen_child=1
        break
    fi
    sleep 0.05
done
echo "WITNESS: saw first child=$seen_child; checking the pinned copy"

# The pin runs at flow entry, before any child process, so by the time the
# flow has children the private copy must already exist and match the
# pre-replacement binary byte for byte (the flow removes it at exit, hence
# the check here rather than after the wait).
PINNED_DIR="${TMPDIR:-/tmp}"
PINNED=""
for candidate in "$PINNED_DIR"/rustynet-self-exec-"$FLOW"-*/rustynet-cli; do
    if [ -f "$candidate" ] && [ "$(sha256_of "$candidate")" = "$PRE_SHA" ]; then
        PINNED="$candidate"
        break
    fi
done
[ -n "$PINNED" ] || fail "no byte-identical pinned copy rustynet-self-exec-$FLOW-* found in $PINNED_DIR"
echo "WITNESS: pinned copy $PINNED is byte-identical to the pre-replacement binary"

echo "WITNESS: replacing $BIN mid-run"
DECOY="$SCRATCH/decoy"
printf '#!/bin/sh\nexit 3\n' > "$DECOY"
chmod +x "$DECOY"
cp "$DECOY" "$DECOY.replacement"
mv -f "$DECOY.replacement" "$BIN"

wait "$FLOW"
RC=$?
echo "WITNESS: flow exited rc=$RC"

if [ "$RC" -ne 0 ]; then
    echo "WITNESS: --- flow log tail ---" >&2
    tail -n 25 "$FLOW_LOG" >&2
    fail "run-supply-chain-integrity-gates exited $RC after the on-disk binary was replaced"
fi
grep -q "Supply-chain integrity gates: PASS" "$FLOW_LOG" \
    || fail "flow passed but did not print the supply-chain PASS line"

echo "WITNESS: PASS"
exit 0
