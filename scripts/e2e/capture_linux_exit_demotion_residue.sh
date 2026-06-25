#!/usr/bin/env bash
# Adversarial Linux exit→client DEMOTION NAT-residue capture for the
# `validate_linux_exit_demotion_residue` orchestrator stage (SecurityMinimumBar
# §6.D.7: exit-serving NAT + forwarding MUST be torn down before serves_exit is
# removed; residue after demotion = release-blocking open relay).
#
# Run on a Linux node WHILE it is actively serving exit traffic. This is NOT the
# daemon-stop lifecycle test — the daemon stays RUNNING throughout; we demote it
# through the PUBLIC role surface (`rustynet role set client`) and assert the NAT
# table is gone + ip_forward restored while the daemon is still alive.
#
# Reuses the read-only `rustynetd linux-exit-nat-lifecycle-snapshot` producer for
# both phases; only the two-phase merge keyed on `after_demote` is new.

set -euo pipefail
umask 077

MESH_CIDR=""
OUTPUT=""
NAT_TABLE="rustynet_nat_g1"
SERVICE_NAME="rustynetd.service"
ROLE_CLI="rustynet"
SETTLE_SECS=4

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mesh-cidr)    MESH_CIDR="$2"; shift 2 ;;
        --output)       OUTPUT="$2"; shift 2 ;;
        --nat-table)    NAT_TABLE="$2"; shift 2 ;;
        --service-name) SERVICE_NAME="$2"; shift 2 ;;
        --role-cli)     ROLE_CLI="$2"; shift 2 ;;
        --settle-secs)  SETTLE_SECS="$2"; shift 2 ;;
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
if [[ -z "$OUTPUT" || "${OUTPUT:0:1}" != "/" ]]; then
    printf 'absolute output path is required (--output)\n' >&2
    exit 1
fi
if ! command -v rustynetd >/dev/null 2>&1; then
    printf 'rustynetd not found on PATH\n' >&2
    exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
    printf 'systemctl not found on PATH\n' >&2
    exit 1
fi

snapshot_dir="$(mktemp -d -t rustynet-linux-exit-demotion.XXXXXX)"
during_path="$snapshot_dir/during.json"
after_path="$snapshot_dir/after.json"
trap 'rm -rf "$snapshot_dir"' EXIT

printf '[capture] during_run snapshot (daemon expected exit-serving)\n'
rustynetd linux-exit-nat-lifecycle-snapshot \
    --mesh-cidr "$MESH_CIDR" --nat-table "$NAT_TABLE" > "$during_path"

# Demote exit→client through the PUBLIC role surface (no daemon stop).
printf '[capture] demoting role exit→client via %s\n' "$ROLE_CLI"
demotion_exit_code=0
"$ROLE_CLI" role set client || demotion_exit_code=$?
sleep "$SETTLE_SECS"

# Prove the daemon is still running (this stage must NOT be the daemon-stop test).
daemon_still_running=false
if systemctl is-active --quiet "$SERVICE_NAME"; then
    daemon_still_running=true
fi

printf '[capture] after_demote snapshot (daemon expected running, NAT gone)\n'
rustynetd linux-exit-nat-lifecycle-snapshot \
    --mesh-cidr "$MESH_CIDR" --nat-table "$NAT_TABLE" > "$after_path"

mkdir -p "$(dirname "$OUTPUT")"
DEMO_EXIT="$demotion_exit_code" DAEMON_RUN="$daemon_still_running" \
python3 - "$during_path" "$after_path" "$OUTPUT" <<'PY'
import json, os, sys
during_path, after_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(during_path) as f:
    during = json.load(f)
with open(after_path) as f:
    after = json.load(f)

# Fail-closed merge (RSA-0031 / F0.3), mirroring the Rust producer
# `rustynetd::linux_exit_nat_lifecycle::merge_linux_exit_nat_lifecycle_artifact`
# and the already-fixed `capture_macos_exit_nat_lifecycle.sh`. A MISSING/empty/
# null forwarding field must NOT default to "Disabled" (fail-open); default to
# "Unknown" so `forwarding_restored` stays false unless the field is the
# explicit literal "Disabled".
after_tunnel = str(after.get("tunnel_forwarding") or "Unknown").lower()
after_egress = str(after.get("egress_forwarding") or "Unknown").lower()
forwarding_restored = after_tunnel == "disabled" and after_egress == "disabled"
after_v6_t = str(after.get("ipv6_tunnel_forwarding") or "Unknown").lower()
after_v6_e = str(after.get("ipv6_egress_forwarding") or "Unknown").lower()
ipv6_forwarding_restored = after_v6_t == "disabled" and after_v6_e == "disabled"

merged = {
    "schema_version": 1,
    "mesh_cidr": during.get("mesh_cidr", ""),
    "nat_table": during.get("nat_table", ""),
    "demotion_exit_code": int(os.environ.get("DEMO_EXIT", "1")),
    "daemon_still_running": os.environ.get("DAEMON_RUN", "false") == "true",
    "during_run": {
        # During run we must positively prove the node was actually serving exit:
        # a missing NAT field defaults to False so the validator's anti-vacuous
        # guard fails rather than silently passing. `internal_prefix` (F0.10) is
        # emitted here so the validator can assert internal_prefix == mesh_cidr,
        # matching the lifecycle artifact's during-run guard.
        "nat_table_present": bool(during.get("nat_table_present", False)),
        "internal_prefix": during.get("internal_prefix", ""),
        "tunnel_forwarding": during.get("tunnel_forwarding") or "Unknown",
        "egress_forwarding": during.get("egress_forwarding") or "Unknown",
    },
    "after_demote": {
        # After demotion the validator FAILS if the NAT table is still present; a
        # missing field must default to True (still-present) so an unverifiable
        # teardown cannot be read as a clean one (residue = open relay).
        "nat_table_present": bool(after.get("nat_table_present", True)),
        "forwarding_restored": forwarding_restored,
        "ipv6_forwarding_restored": ipv6_forwarding_restored,
    },
}
with open(out_path, "w") as f:
    json.dump(merged, f, indent=2)
PY

printf '[capture] wrote merged exit demotion residue artefact: %s\n' "$OUTPUT"
