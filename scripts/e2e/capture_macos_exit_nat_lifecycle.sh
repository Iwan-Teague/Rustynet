#!/usr/bin/env bash
# Track B Step 2 follow-up — destructive two-phase macOS exit-mode NAT
# lifecycle capture for the `validate_macos_exit_nat_lifecycle`
# orchestrator stage.
#
# Mirrors the destructive capture portion of the Windows
# `scm_context_nat_lifecycle.json` producer (embedded PowerShell in
# `crates/rustynet-cli/src/vm_lab/mod.rs`): snapshot pf anchor + sysctl
# forwarding while the daemon is in exit mode, stop the daemon,
# snapshot again, restart the daemon, then merge the two snapshots
# into the validator's two-phase JSON shape.
#
# Run ON the macOS host (orchestrator can SSH-invoke this script). The
# operator passes the mesh CIDR explicitly; the producer reads pf +
# sysctl state directly.
#
# Required environment / args:
#   --mesh-cidr <cidr>       Mesh CIDR (e.g. 100.64.0.0/16)
#   --output <path>          Where to write the merged artefact JSON
#   [--pf-anchor <name>]     Override the reviewed default
#                            (`com.rustynet/nat`)
#   [--service-label <l>]    Override the reviewed launchd label
#                            (`com.rustynet.daemon`)
#   [--service-plist <p>]    Override the reviewed plist path
#                            (`/Library/LaunchDaemons/com.rustynet.daemon.plist`)
#   [--settle-secs <n>]      Seconds to wait after stop before
#                            capturing the after-stop snapshot
#                            (default: 4)

set -euo pipefail
umask 077

MESH_CIDR=""
OUTPUT=""
PF_ANCHOR="com.rustynet/nat"
SERVICE_LABEL="com.rustynet.daemon"
SERVICE_PLIST="/Library/LaunchDaemons/com.rustynet.daemon.plist"
SETTLE_SECS=4
# The admin->exit role transition's launchd restarts can briefly leave the daemon
# fail-closed (membership reconcile racing the snapshot write -> restrict_recoverable
# -> NAT anchor torn down) before it self-heals into a stable exit-mode. Poll the
# during_run snapshot up to MAX_ATTEMPTS x RETRY_SECS so we capture the SETTLED
# exit-mode, not a transient restriction window. The assertion is unchanged.
DURING_RUN_MAX_ATTEMPTS=20
DURING_RUN_RETRY_SECS=3

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mesh-cidr)        MESH_CIDR="$2"; shift 2 ;;
        --output)           OUTPUT="$2"; shift 2 ;;
        --pf-anchor)        PF_ANCHOR="$2"; shift 2 ;;
        --service-label)    SERVICE_LABEL="$2"; shift 2 ;;
        --service-plist)    SERVICE_PLIST="$2"; shift 2 ;;
        --settle-secs)      SETTLE_SECS="$2"; shift 2 ;;
        --during-run-max-attempts) DURING_RUN_MAX_ATTEMPTS="$2"; shift 2 ;;
        --during-run-retry-secs)   DURING_RUN_RETRY_SECS="$2"; shift 2 ;;
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

snapshot_dir="$(mktemp -d -t rustynet-macos-exit-nat-lifecycle.XXXXXX)"
during_path="$snapshot_dir/during.json"
after_path="$snapshot_dir/after.json"
trap 'rm -rf "$snapshot_dir"' EXIT

printf '[capture] during_run snapshot (daemon expected exit-mode)\n'
# Poll until the daemon has settled into exit-mode (pf NAT anchor loaded). The
# admin->exit transition's launchd restarts can briefly leave the daemon
# fail-closed (reconcile racing the snapshot write -> restricted -> NAT torn
# down) and a single-shot snapshot can land in that ~seconds-long window and read
# no anchor. We retry the SAME assertion (the snapshot subcommand still requires
# the anchor) until exit-mode is live or the bounded window elapses -- this waits
# out a fail-CLOSED transient, it does not weaken the proof.
during_ok=0
during_err="$snapshot_dir/during.err"
for _attempt in $(seq 1 "$DURING_RUN_MAX_ATTEMPTS"); do
    if rustynetd macos-exit-nat-lifecycle-snapshot \
        --mesh-cidr "$MESH_CIDR" \
        --pf-anchor "$PF_ANCHOR" > "$during_path" 2>"$during_err"; then
        during_ok=1
        break
    fi
    sleep "$DURING_RUN_RETRY_SECS"
done
if [[ "$during_ok" != 1 ]]; then
    printf '[capture] during_run snapshot never observed exit-mode after %s attempts (~%ss):\n' \
        "$DURING_RUN_MAX_ATTEMPTS" "$((DURING_RUN_MAX_ATTEMPTS * DURING_RUN_RETRY_SECS))" >&2
    cat "$during_err" >&2 2>/dev/null || true
    exit 1
fi

printf '[capture] stopping launchd service %s\n' "$SERVICE_LABEL"
launchctl bootout "system/${SERVICE_LABEL}" >/dev/null 2>&1 || true
sleep "$SETTLE_SECS"

printf '[capture] after_stop snapshot (daemon expected stopped)\n'
rustynetd macos-exit-nat-lifecycle-snapshot \
    --mesh-cidr "$MESH_CIDR" \
    --pf-anchor "$PF_ANCHOR" > "$after_path"

printf '[capture] restarting launchd service %s\n' "$SERVICE_LABEL"
launchctl bootstrap system "$SERVICE_PLIST"
sleep "$SETTLE_SECS"

# Merge during + after snapshots into the validator's shape using a
# tiny Python heredoc. Python is on macOS by default; jq is not always
# available so we avoid it. The merge logic mirrors
# `rustynetd::macos_exit_nat_lifecycle::merge_macos_exit_nat_lifecycle_artifact`.
mkdir -p "$(dirname "$OUTPUT")"
python3 - "$during_path" "$after_path" "$OUTPUT" <<'PY'
import json, sys
during_path, after_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(during_path) as f:
    during = json.load(f)
with open(after_path) as f:
    after = json.load(f)

# Fail-closed merge (RSA-0031), mirroring the Rust producer
# `rustynetd::macos_exit_nat_lifecycle::merge_macos_exit_nat_lifecycle_artifact`
# and its capture layer (a failed sysctl read yields "Unknown", never
# "Disabled"). A MISSING/empty/null forwarding field must NOT default to
# "Disabled" — that would let a truncated or older snapshot read as restored
# (fail-open). Default to "Unknown" so `forwarding_restored` stays false unless
# both interfaces are the explicit literal "Disabled".
after_tunnel = str(after.get("tunnel_forwarding") or "Unknown").lower()
after_egress = str(after.get("egress_forwarding") or "Unknown").lower()
forwarding_restored = after_tunnel == "disabled" and after_egress == "disabled"

merged = {
    "schema_version": 1,
    "mesh_cidr": during.get("mesh_cidr", ""),
    "pf_anchor": during.get("pf_anchor", ""),
    "during_run": {
        # During run we must positively prove the anchor was present; a missing
        # field defaults to False (not-serving) so the validator's anti-vacuous
        # guard fails rather than silently passing.
        "pf_anchor_present": bool(during.get("pf_anchor_present", False)),
        "internal_prefix": during.get("internal_prefix", ""),
        "tunnel_forwarding": during.get("tunnel_forwarding") or "Unknown",
        "egress_forwarding": during.get("egress_forwarding") or "Unknown",
    },
    "after_stop": {
        # After stop the validator FAILS if the anchor is still present; a
        # missing field must default to True (still-present) so an unverifiable
        # teardown cannot be read as a clean one.
        "pf_anchor_present": bool(after.get("pf_anchor_present", True)),
        "forwarding_restored": forwarding_restored,
    },
}

with open(out_path, "w") as f:
    json.dump(merged, f, indent=2)
PY

printf '[capture] wrote merged artefact: %s\n' "$OUTPUT"
