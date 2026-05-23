#!/usr/bin/env bash
# Capture macOS active-exit DNS fail-closed evidence artifacts.
#
# Run on the macOS host while it is serving as the active Rustynet exit.
# The daemon-side producer writes the complete dns_leak_proof/ artifact
# set consumed by validate_macos_exit_dns_failclosed.

set -euo pipefail
umask 077

OUTPUT=""
LAN_IFACE="en0"
MESH_HOSTNAME="exit-1.rustynet"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output) OUTPUT="$2"; shift 2 ;;
        --lan-iface) LAN_IFACE="$2"; shift 2 ;;
        --mesh-hostname) MESH_HOSTNAME="$2"; shift 2 ;;
        *)
            printf 'unknown argument: %s\n' "$1" >&2
            exit 1
            ;;
    esac
done

if [[ -z "$OUTPUT" ]]; then
    printf 'output directory is required (--output)\n' >&2
    exit 1
fi
if [[ "${OUTPUT:0:1}" != "/" ]]; then
    printf 'output directory must be absolute\n' >&2
    exit 1
fi
if ! command -v rustynetd >/dev/null 2>&1; then
    printf 'rustynetd not found on PATH; install it before capturing\n' >&2
    exit 1
fi

rustynetd macos-exit-dns-failclosed-capture \
    --output "$OUTPUT" \
    --lan-iface "$LAN_IFACE" \
    --mesh-hostname "$MESH_HOSTNAME"

printf '[capture] wrote macOS DNS fail-closed artefacts under: %s\n' "$OUTPUT"
