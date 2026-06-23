#!/usr/bin/env bash
# Adversarial macOS IPv6 tunnel-leak capture for the
# `validate_macos_ipv6_leak` orchestrator stage (pf parity of the Linux
# `capture_linux_ipv6_leak.sh`).
#
# Run on a macOS node WHILE it is in a protected routing mode (tunnel +
# pf killswitch up). Drives a real outbound IPv6 probe while tcpdump watches
# the physical egress interface (link-local + multicast excluded by the BPF
# filter), and records the pf v6-containment posture. The validator
# `evaluate_macos_ipv6_leak_artifact` fails closed if any global-scope IPv6
# datagram leaked, the probe reached its target, or no pf v6 block is present
# (a `block drop ... all`/`inet6` rule; an inet-only pf block does NOT count).
#
# Proves SecurityMinimumBar.md §8 (tunnel fail-close in protected modes) holds
# for IPv6 on macOS, not just IPv4.

set -euo pipefail
umask 077

OUTPUT=""
EGRESS_IFACE=""
PROBE_TARGET="2606:4700:4700::1111"
PF_ANCHOR="com.apple/rustynet_g1"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)        OUTPUT="$2"; shift 2 ;;
        --egress-iface)  EGRESS_IFACE="$2"; shift 2 ;;
        --probe-target)  PROBE_TARGET="$2"; shift 2 ;;
        --pf-anchor)     PF_ANCHOR="$2"; shift 2 ;;
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
if ! command -v /usr/sbin/tcpdump >/dev/null 2>&1; then
    printf 'tcpdump not found at /usr/sbin/tcpdump; macOS IPv6 leak capture requires it\n' >&2
    exit 1
fi

# Auto-detect the default IPv4 egress interface when not pinned explicitly.
if [[ -z "$EGRESS_IFACE" ]]; then
    EGRESS_IFACE="$(route -n get default 2>/dev/null | awk '/interface:/ {print $2; exit}')"
fi
if [[ -z "$EGRESS_IFACE" ]]; then
    printf 'could not determine egress interface; pass --egress-iface <name>\n' >&2
    exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"

printf '[capture] macOS IPv6 leak probe on egress %s (target %s, pf anchor %s)\n' \
    "$EGRESS_IFACE" "$PROBE_TARGET" "$PF_ANCHOR"

# The daemon subcommand performs the privileged capture (argv-only): pf anchor
# rule read, a background tcpdump on the egress interface, and a real outbound
# IPv6 ping6 probe. It emits the snapshot JSON the validator consumes.
rustynetd macos-ipv6-leak-capture \
    --egress-iface "$EGRESS_IFACE" \
    --probe-target "$PROBE_TARGET" \
    --pf-anchor "$PF_ANCHOR" > "$OUTPUT"

printf '[capture] wrote macOS IPv6 leak artefact: %s\n' "$OUTPUT"
