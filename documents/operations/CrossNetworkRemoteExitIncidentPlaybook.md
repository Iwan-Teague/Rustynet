# Cross-Network Remote Exit Incident Playbook

## Purpose
This playbook defines fail-closed incident response for cross-network remote exit operations when networks, relay paths, or signed control artifacts become unavailable or untrusted.

This is an operations complement to `Phase10ExitNodeDataplaneRunbook.md` and `CrossNetworkRemoteExitNodePlan_2026-03-16.md`.

## Security Invariants (Never Relax)
- Do not bypass signed trust, assignment, traversal, or DNS verification.
- Do not disable kill-switch or DNS fail-closed controls to restore connectivity.
- Do not introduce ad-hoc SSH tunnels as replacement control-plane mutation paths.
- Do not mutate endpoints or routes from unsigned/unverified observations.
- Keep one hardened path: fix the trusted path or stay in restricted/fail-closed mode.

## Trigger Conditions
Start this playbook immediately when any of the following occurs:
- Client or relay status enters `FailClosed` / restricted-safe mode.
- `rustynet netcheck` reports traversal stale/replay/future-dated rejections rising.
- Cross-network report checks fail: `remote_exit_no_underlay_leak`, `relay_to_direct_failback_success`, or DNS fail-closed checks.
- Remote exit path stops forwarding while signed state appears outdated or missing.
- Controller/orchestrator network changes and nodes no longer accept trusted state updates.

## Immediate Containment
1. Freeze policy/control mutations until signed-state validity is confirmed.
2. Capture current runtime state before restarts:
   - `rustynet status`
   - `rustynet netcheck`
   - `rustynet dns inspect`
3. Preserve forensic evidence:
   - `artifacts/phase10/state_transition_audit.log`
   - latest cross-network report JSON/log artifacts
   - `journalctl -u rustynetd --no-pager -n 300`
4. Confirm no plaintext secret material exists:
   - `/var/lib/rustynet/keys/wireguard.passphrase` must be absent
   - `/etc/rustynet/wireguard.passphrase` must be absent

## Incident A: Controller Network Switched / Signed-State Refresh Degraded
Symptoms:
- periodic refresh services fail
- assignment/traversal freshness alarms rise
- nodes remain healthy only on stale local state

Response:
1. Verify trust refresh pipeline:
   - `systemctl status rustynetd-trust-refresh.timer`
   - `journalctl -u rustynetd-trust-refresh.service --no-pager -n 100`
2. Verify assignment refresh pipeline:
   - `systemctl status rustynetd-assignment-refresh.timer`
   - `journalctl -u rustynetd-assignment-refresh.service --no-pager -n 100`
3. Validate signed artifacts locally before apply:
   - `rustynet trust verify ...`
   - `rustynet assignment verify ...`
   - `rustynet traversal verify ...`
4. If verification fails, keep runtime fail-closed and do not force endpoint/route mutation.
5. Restore trusted signer/verifier inputs and rerun refresh services.
6. Re-check `status`/`netcheck` for alarm-state recovery.

Exit criteria:
- signed-state verification succeeds,
- refresh timers/services healthy,
- traversal alarm not `critical/error`,
- no leak/bypass checks regressed.

## Incident B: Node Underlay Network Switch Mid-Session
Symptoms:
- endpoint fingerprint changes
- relay/direct flapping or path loss
- temporary drop during roam/failback

Response:
1. Confirm endpoint-change and traversal refresh counters increase in status output.
2. Revalidate path state via:
   - `rustynet netcheck` (remaining TTL, alarm state, probe mode)
   - `rustynet status` (exit active, selected exit, restricted mode)
3. Ensure signed traversal bundle is refreshed and accepted (no replay/stale/future-dated errors).
4. If direct path cannot be re-established safely, remain on trusted relay path; do not accept unsigned endpoint hints.
5. If neither trusted direct nor relay path is available, keep fail-closed and escalate to network remediation.

Exit criteria:
- client route remains tunnelled (`dev rustynet0`) once recovered,
- selected exit remains policy-valid,
- underlay leak checks pass.

## Incident C: Relay Path Degradation / Failback Instability
Symptoms:
- relay path used longer than expected
- failback to direct never converges
- repeated probe failures

Response:
1. Validate relay host health and service reachability.
2. Validate relay and client signed traversal artifacts and freshness windows.
3. Run targeted failback/roaming validator for measured evidence:
   - `scripts/e2e/live_linux_cross_network_failback_roaming_test.sh ...`
4. If failback SLO misses persist but security checks pass, keep relay as active trusted path and open reliability incident.
5. If security checks fail (leak/bypass/control-surface), halt rollout and keep strict fail-closed posture.

Exit criteria:
- failback report checks pass or relay-only operation is explicitly accepted as temporary reliability mode with security intact.

## Incident D: DNS Fail-Closed Triggered
Symptoms:
- managed name resolution fails,
- stale zone bundle rejects,
- DNS checks fail in cross-network DNS report

Response:
1. Validate signed DNS zone bundle and watermark:
   - `rustynet dns zone verify ...`
2. Verify resolver service state:
   - `systemctl status rustynetd-managed-dns.service`
   - `rustynet dns inspect`
3. Do not reroute DNS to untrusted system resolvers.
4. Restore valid signed zone and rerun DNS validator:
   - `scripts/e2e/live_linux_cross_network_remote_exit_dns_test.sh ...`

Exit criteria:
- managed DNS resolution succeeds,
- stale bundle remains fail-closed,
- no underlay DNS leak.

## Post-Incident Verification Gates
After remediation, run:
- `scripts/ci/phase10_cross_network_exit_gates.sh`
- `scripts/ci/phase10_gates.sh`
- `scripts/ci/membership_gates.sh`

Collect and retain:
- updated report artifacts under `artifacts/phase10/`
- gate logs
- affected service journal snippets

## Escalation
Escalate to security+platform owners if any apply:
- repeated replay/rollback rejection spikes without clear root cause,
- inability to verify trust/assignment/traversal signatures,
- any indication of plaintext secret exposure,
- control-surface exposure checks failing.

