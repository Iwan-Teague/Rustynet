#!/usr/bin/env bash
# Adversarial Linux IPv6 tunnel-leak capture for the
# `validate_linux_ipv6_leak` orchestrator stage.
#
# Run on a Linux node WHILE it is in a protected routing mode (tunnel +
# killswitch up). The capture drives a real outbound IPv6 probe to a global
# address while tcpdump watches the egress interface (link-local + multicast
# excluded by the BPF filter), and records the host's IPv6 containment posture
# (disable_ipv6 sysctl + nft killswitch ruleset). The orchestrator-side
# validator `evaluate_linux_ipv6_leak_artifact` then fails closed if any
# global-scope IPv6 datagram leaked, if the probe reached its target, or if
# no IPv6 containment control is present at all.
#
# This proves SecurityMinimumBar.md §8 (tunnel fail-close in protected-routing
# modes) holds for IPv6 — not just IPv4. An IPv4-only killswitch that lets
# native IPv6 egress in the clear is the exact bug this catches.

set -euo pipefail
umask 077

OUTPUT=""
EGRESS_IFACE=""
PROBE_TARGET="2606:4700:4700::1111"
KILLSWITCH_TABLE="rustynet_g1"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)           OUTPUT="$2"; shift 2 ;;
        --egress-iface)     EGRESS_IFACE="$2"; shift 2 ;;
        --probe-target)     PROBE_TARGET="$2"; shift 2 ;;
        --killswitch-table) KILLSWITCH_TABLE="$2"; shift 2 ;;
        *)
            printf 'unknown argument: %s\n' "$1" >&2
            exit 1
            ;;
    esac
done

if [[ -z "$OUTPUT" ]]; then
    printf 'output path is required (--output)\n' >&2
    exit 1
fi
if [[ "${OUTPUT:0:1}" != "/" ]]; then
    printf 'output path must be absolute\n' >&2
    exit 1
fi

if ! command -v rustynetd >/dev/null 2>&1; then
    printf 'rustynetd not found on PATH; install it before capturing\n' >&2
    exit 1
fi
if ! command -v tcpdump >/dev/null 2>&1; then
    printf 'tcpdump not found on PATH; IPv6 leak capture requires tcpdump\n' >&2
    exit 1
fi

# Auto-detect the default egress interface when not pinned explicitly.
if [[ -z "$EGRESS_IFACE" ]]; then
    if command -v ip >/dev/null 2>&1; then
        EGRESS_IFACE="$(ip route show default 2>/dev/null | awk '/default/ {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
    fi
fi
if [[ -z "$EGRESS_IFACE" ]]; then
    printf 'could not determine egress interface; pass --egress-iface <name>\n' >&2
    exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"

printf '[capture] IPv6 leak probe on egress %s (target %s, killswitch table %s)\n' \
    "$EGRESS_IFACE" "$PROBE_TARGET" "$KILLSWITCH_TABLE"

# The daemon subcommand performs the privileged capture (argv-only): posture
# read of /proc + `nft list ruleset`, a background tcpdump on the egress
# interface, and a real outbound IPv6 ping probe. It emits the snapshot JSON
# the validator consumes.
rustynetd linux-ipv6-leak-capture \
    --egress-iface "$EGRESS_IFACE" \
    --probe-target "$PROBE_TARGET" \
    --killswitch-table "$KILLSWITCH_TABLE" > "$OUTPUT"

printf '[capture] wrote IPv6 leak artefact: %s\n' "$OUTPUT"
