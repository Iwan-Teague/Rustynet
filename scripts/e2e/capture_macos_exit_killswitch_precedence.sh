#!/usr/bin/env bash
set -euo pipefail

# Capture macOS exit killswitch precedence proof on the macOS host.
# This is destructive inside the RustyNet pf anchor only: rustynetd
# snapshots the active anchor, flushes it, verifies the assertion
# fails closed, then reloads the captured rules before exit.

OUTPUT=""
PF_ANCHOR=""

usage() {
    cat <<'USAGE'
usage: capture_macos_exit_killswitch_precedence.sh --output <path> [--pf-anchor <name>]

  --output <path>       Absolute output JSON path.
  --pf-anchor <name>    Optional RustyNet pf anchor. Omit to auto-select latest
                        com.apple/rustynet_g<N> anchor.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)    OUTPUT="${2:-}"; shift 2 ;;
        --pf-anchor) PF_ANCHOR="${2:-}"; shift 2 ;;
        -h|--help)   usage; exit 0 ;;
        *)           echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$OUTPUT" ]]; then
    echo "--output is required" >&2
    usage >&2
    exit 2
fi

case "$OUTPUT" in
    /*) ;;
    *) echo "--output must be absolute" >&2; exit 2 ;;
esac

args=(macos-exit-killswitch-precedence-check --output "$OUTPUT")
if [[ -n "$PF_ANCHOR" ]]; then
    args+=(--pf-anchor "$PF_ANCHOR")
fi

rustynetd "${args[@]}"
