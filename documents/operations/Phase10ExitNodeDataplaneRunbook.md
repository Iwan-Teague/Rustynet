# Phase 10 Exit-Node Dataplane Runbook

## 1) Purpose
This runbook defines deployment, validation, rollback, and incident procedures for Rustynet Phase 10 Linux dataplane enablement (exit-node full tunnel + LAN-toggle controls + DNS/tunnel fail-close behavior).

## 2) Preconditions
- Linux host with required privileges for route/firewall/NAT operations.
- `rustynetd` and `rustynet` binaries built from current workspace.
- `scripts/ci/phase10_gates.sh` completed and artifacts present in `artifacts/phase10/`.
- Trust state and signed control data validation path healthy.

## 3) Deployment Procedure
1. Run `./scripts/ci/phase10_gates.sh` and verify PASS.
2. Start daemon:
- `cargo run -p rustynetd -- daemon --socket /tmp/rustynetd.sock --state /tmp/rustynetd.state`
3. Validate baseline daemon status:
- `cargo run -p rustynet-cli -- status`
4. Select exit node:
- `cargo run -p rustynet-cli -- exit-node select <node-id>`
5. Toggle LAN access only when required:
- `cargo run -p rustynet-cli -- lan-access on`
6. Validate DNS policy state:
- `cargo run -p rustynet-cli -- dns inspect`

## 4) Rollback Procedure
1. Disable exit mode:
- `cargo run -p rustynet-cli -- exit-node off`
2. Disable LAN access:
- `cargo run -p rustynet-cli -- lan-access off`
3. Restart daemon in restricted-safe mode if trust or state integrity is suspect.
4. Revert to last-known-safe build and rerun `./scripts/ci/phase10_gates.sh`.
5. Preserve `artifacts/phase10/state_transition_audit.log` for post-incident analysis.

## 5) Incident Response Checklist
- Confirm whether daemon entered `FailClosed` state via `status` output.
- Check for trust-state failures (signed-data freshness, signature validation, clock skew).
- Check latest `state_transition_audit.log` for transition reason.
- If DNS leak protection fault is detected, keep fail-closed posture and do not bypass protection.
- If route/firewall apply failed, enforce rollback and block egress until trusted state recovers.

## 6) Verification Commands
- `cargo run -p rustynet-cli -- status`
- `cargo run -p rustynet-cli -- netcheck`
- `cargo run -p rustynet-cli -- dns inspect`
- `cargo run -p rustynet-cli -- route advertise 192.168.1.0/24`
- `cargo run -p rustynetd -- --emit-phase10-evidence artifacts/phase10`

## 7) Required Evidence for Sign-Off
- `artifacts/phase10/netns_e2e_report.json`
- `artifacts/phase10/leak_test_report.json`
- `artifacts/phase10/perf_budget_report.json`
- `artifacts/phase10/direct_relay_failover_report.json`
- `artifacts/phase10/state_transition_audit.log`

## 8) Security Invariants
- Default-deny policy remains active.
- Tunnel/DNS fail-close behavior is never bypassed.
- Mutating daemon IPC commands require peer credential authorization.
- WireGuard implementation remains behind `TunnelBackend` and replaceable.
- No custom crypto/protocol behavior is introduced.
