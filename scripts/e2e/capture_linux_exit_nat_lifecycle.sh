#!/usr/bin/env bash
# Destructive two-phase Linux exit-mode NAT lifecycle capture for the
# `validate_linux_exit_nat_lifecycle` orchestrator stage.
#
# Run on the Linux host while it is actively serving exit traffic:
# capture nftables NAT + forwarding state, stop rustynetd, capture the
# after-stop state, restart rustynetd, then merge into the validator's
# two-phase JSON shape.

set -euo pipefail
umask 077

MESH_CIDR=""
OUTPUT=""
NAT_TABLE="rustynet_nat_g1"
SERVICE_NAME="rustynetd.service"
SETTLE_SECS=4

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mesh-cidr)     MESH_CIDR="$2"; shift 2 ;;
        --output)        OUTPUT="$2"; shift 2 ;;
        --nat-table)     NAT_TABLE="$2"; shift 2 ;;
        --service-name)  SERVICE_NAME="$2"; shift 2 ;;
        --settle-secs)   SETTLE_SECS="$2"; shift 2 ;;
        *)
            printf 'unknown argument: %s\n' "$1" >&2
            exit 1
            ;;
    esac
done

if [[ -z "$MESH_CIDR" ]]; then
    printf 'mesh CIDR is required (--mesh-cidr)\n' >&2
    exit 1
fi
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
if ! command -v systemctl >/dev/null 2>&1; then
    printf 'systemctl not found on PATH; Linux service lifecycle capture requires systemd\n' >&2
    exit 1
fi

snapshot_dir="$(mktemp -d -t rustynet-linux-exit-nat-lifecycle.XXXXXX)"
during_path="$snapshot_dir/during.json"
after_path="$snapshot_dir/after.json"
trap 'rm -rf "$snapshot_dir"' EXIT

printf '[capture] during_run snapshot (daemon expected exit-mode)\n'
rustynetd linux-exit-nat-lifecycle-snapshot \
    --mesh-cidr "$MESH_CIDR" \
    --nat-table "$NAT_TABLE" > "$during_path"

printf '[capture] stopping systemd service %s\n' "$SERVICE_NAME"
systemctl stop "$SERVICE_NAME"
sleep "$SETTLE_SECS"

printf '[capture] after_stop snapshot (daemon expected stopped)\n'
rustynetd linux-exit-nat-lifecycle-snapshot \
    --mesh-cidr "$MESH_CIDR" \
    --nat-table "$NAT_TABLE" > "$after_path"

printf '[capture] restarting systemd service %s\n' "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"
sleep "$SETTLE_SECS"

mkdir -p "$(dirname "$OUTPUT")"
python3 - "$during_path" "$after_path" "$OUTPUT" <<'PY'
import json, sys
during_path, after_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(during_path) as f:
    during = json.load(f)
with open(after_path) as f:
    after = json.load(f)

after_tunnel = (after.get("tunnel_forwarding") or "Disabled").lower()
after_egress = (after.get("egress_forwarding") or "Disabled").lower()
forwarding_restored = after_tunnel == "disabled" and after_egress == "disabled"

after_v6_tunnel = (after.get("ipv6_tunnel_forwarding") or "Disabled").lower()
after_v6_egress = (after.get("ipv6_egress_forwarding") or "Disabled").lower()
ipv6_forwarding_restored = after_v6_tunnel == "disabled" and after_v6_egress == "disabled"

merged = {
    "schema_version": 1,
    "mesh_cidr": during.get("mesh_cidr", ""),
    "nat_table": during.get("nat_table", ""),
    "during_run": {
        "nat_table_present": bool(during.get("nat_table_present", False)),
        "internal_prefix": during.get("internal_prefix", ""),
        "tunnel_forwarding": during.get("tunnel_forwarding", "Disabled"),
        "egress_forwarding": during.get("egress_forwarding", "Disabled"),
        "ipv6_tunnel_forwarding": during.get("ipv6_tunnel_forwarding", "Disabled"),
        "ipv6_egress_forwarding": during.get("ipv6_egress_forwarding", "Disabled"),
    },
    "after_stop": {
        "nat_table_present": bool(after.get("nat_table_present", False)),
        "forwarding_restored": forwarding_restored,
        "ipv6_forwarding_restored": ipv6_forwarding_restored,
    },
}

with open(out_path, "w") as f:
    json.dump(merged, f, indent=2)
PY

printf '[capture] wrote merged artefact: %s\n' "$OUTPUT"
