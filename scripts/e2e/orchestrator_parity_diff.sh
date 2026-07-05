#!/usr/bin/env bash
#
# orchestrator_parity_diff.sh — Bucket-7 run-both-and-diff post-processor.
#
# Given two already-completed live-lab report directories — one produced by the
# bash orchestrator and one by the Rust `--node` orchestrator on the SAME
# topology — reconstruct a parity_input.json for each via the engine-agnostic
# converter (`ops vm-lab-emit-parity-input`) and run the functional-parity diff
# (`ops vm-lab-diff-orchestrator-parity --mode functional`), which is the
# redefined W5.6 flip gate.
#
# Both sides are rebuilt through the SAME converter (from state/stages.tsv +
# state/nodes.tsv) so the comparison is apples-to-apples: any drift the diff
# reports is a real difference in what the two engines DID, not a difference in
# how the report was constructed.
#
# This script does NOT run either orchestrator — it only post-processes their
# evidence, so it is deterministic given two report directories. Drive the two
# live runs first (e.g. exit + single-client so both go green), then point this
# at their report dirs.
#
# Usage:
#   scripts/e2e/orchestrator_parity_diff.sh <bash_report_dir> <rust_report_dir> <output_diff.json>
#
# Exits 0 iff overall_functional_parity_pass=true; non-zero otherwise.

set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <bash_report_dir> <rust_report_dir> <output_diff.json>" >&2
  exit 2
fi

BASH_REPORT_DIR="$1"
RUST_REPORT_DIR="$2"
OUTPUT_DIFF="$3"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUSTYNET_BIN="${RUSTYNET_BIN:-"$REPO_ROOT/target/debug/rustynet-cli"}"

if [ ! -x "$RUSTYNET_BIN" ]; then
  echo "error: rustynet-cli binary not found or not executable: $RUSTYNET_BIN" >&2
  echo "       build it (cargo build -p rustynet-cli) or set RUSTYNET_BIN" >&2
  exit 2
fi

for d in "$BASH_REPORT_DIR" "$RUST_REPORT_DIR"; do
  if [ ! -f "$d/state/stages.tsv" ]; then
    echo "error: '$d' is not a completed report dir (no state/stages.tsv)" >&2
    exit 2
  fi
done

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rustynet-parity.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

BASH_PARITY="$WORK_DIR/bash_parity_input.json"
RUST_PARITY="$WORK_DIR/rust_parity_input.json"

echo "== emitting bash parity_input from $BASH_REPORT_DIR" >&2
"$RUSTYNET_BIN" ops vm-lab-emit-parity-input \
  --report-dir "$BASH_REPORT_DIR" --output "$BASH_PARITY" >&2

echo "== emitting rust parity_input from $RUST_REPORT_DIR" >&2
"$RUSTYNET_BIN" ops vm-lab-emit-parity-input \
  --report-dir "$RUST_REPORT_DIR" --output "$RUST_PARITY" >&2

echo "== functional parity diff (bash=left, rust=right)" >&2
# The diff subcommand exits non-zero on drift; `set -e` propagates that.
"$RUSTYNET_BIN" ops vm-lab-diff-orchestrator-parity \
  --left "$BASH_PARITY" --right "$RUST_PARITY" \
  --output "$OUTPUT_DIFF" --mode functional
