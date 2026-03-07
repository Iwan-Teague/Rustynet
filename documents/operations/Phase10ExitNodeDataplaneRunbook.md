# Phase 10 Exit-Node Dataplane Runbook

Status correction (verified 2026-03-05):
- Legacy `/etc/rustynet/wireguard.*` path assumptions are stale for current Linux runtime.
- Current Linux hardened runtime uses encrypted key material under `/var/lib/rustynet/keys/` and encrypted systemd credential blob `/etc/rustynet/credentials/wg_key_passphrase.cred`.
- Security risk truth: relying on legacy plaintext passphrase-file assumptions weakens key-custody posture and can cause unsafe operator workflows.

## 1) Purpose
This runbook defines deployment, validation, rollback, and incident procedures for Rustynet Phase 10 Linux dataplane enablement (exit-node full tunnel + LAN-toggle controls + direct/relay traversal path control + DNS/tunnel fail-close behavior).

## 2) Preconditions
- Linux host with required privileges for route/firewall/NAT operations.
- `rustynetd` and `rustynet` binaries built from current workspace.
- `scripts/ci/phase10_gates.sh` completed and artifacts present in `artifacts/phase10/`.
- Trust state and signed control data validation path healthy.
- WireGuard encrypted key present at `/var/lib/rustynet/keys/wireguard.key.enc` with mode `0600`.
- `/etc/rustynet` directory present with mode `0750` (`root:<daemon-group>`).
- `/etc/rustynet/credentials` directory present with mode `0700` (`root:root`).
- Encrypted passphrase credential blob present at `/etc/rustynet/credentials/wg_key_passphrase.cred` with mode `0600`.
- Encrypted signing-passphrase credential blob present at `/etc/rustynet/credentials/signing_key_passphrase.cred` with mode `0600`.
- Persistent plaintext passphrase file is absent at `/var/lib/rustynet/keys/wireguard.passphrase`.
- Runtime decrypted key at `/run/rustynet/wireguard.key` with mode `0600` (managed by `rustynetd`).
- Trust evidence file present at `/var/lib/rustynet/rustynetd.trust`.
- Trust verifier key present at `/etc/rustynet/trust-evidence.pub`.
- If unattended trust auto-refresh is enabled: encrypted signer key present at `/etc/rustynet/trust-evidence.key` (`0600`) and passphrase injected via systemd credential (`%d/signing_key_passphrase`).
- Phase10 provenance signing seed file present at absolute path configured by `RUSTYNET_PHASE10_PROVENANCE_SIGNING_KEY_PATH` (owner-only mode `<=0600`, 32-byte hex seed).
- Matching phase10 provenance verifier key file present at absolute path configured by `RUSTYNET_PHASE10_PROVENANCE_VERIFIER_KEY_PATH` (owner-only mode `<=0600`, 32-byte hex key).
- `RUSTYNET_PHASE10_PROVENANCE_HOST_ID` configured and stable for the host/environment.
- Host clock synchronization healthy (for freshness-bound signed traversal endpoint-hint checks).

## 3) Deployment Procedure
1. Run `./scripts/ci/phase10_gates.sh` and verify PASS.
2. Recommended: run `./start.sh` and complete first-run wizard bootstrap.
3. Install and start hardened systemd service:
- `sudo ./scripts/systemd/install_rustynetd_service.sh`
4. Confirm detected daemon environment:
- `cat /etc/default/rustynetd`
5. If `RUSTYNET_TRUST_AUTO_REFRESH=true`, verify timer:
- `sudo systemctl --no-pager --full status rustynetd-trust-refresh.timer`
- `sudo systemctl start rustynetd-trust-refresh.service`
6. Validate baseline daemon status:
- `RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock cargo run -p rustynet-cli -- status`
7. Validate traversal/path diagnostics baseline:
- `RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock cargo run -p rustynet-cli -- netcheck`
8. Select exit node:
- `RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock cargo run -p rustynet-cli -- exit-node select <node-id>`
9. Toggle LAN access only when required:
- `RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock cargo run -p rustynet-cli -- lan-access on`
10. Validate DNS policy state:
- `RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock cargo run -p rustynet-cli -- dns inspect`

## 4) Rollback Procedure
1. Disable exit mode:
- `RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock cargo run -p rustynet-cli -- exit-node off`
2. Disable LAN access:
- `RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock cargo run -p rustynet-cli -- lan-access off`
3. Restart daemon in restricted-safe mode if trust or state integrity is suspect.
4. Revert to last-known-safe build and rerun `./scripts/ci/phase10_gates.sh`.
5. Preserve `artifacts/phase10/state_transition_audit.log` for post-incident analysis.
6. If auto-refresh signer key is compromised or missing, disable refresh timer until key custody is restored:
- `sudo systemctl disable --now rustynetd-trust-refresh.timer`

## 5) Incident Response Checklist
- Confirm whether daemon entered `FailClosed` state via `status` output.
- Check for trust-state failures (signed-data freshness, signature validation, clock skew).
- Check latest `state_transition_audit.log` for transition reason.
- If stale trust evidence is reported during unattended runtime, verify `rustynetd-trust-refresh.timer` and `rustynetd-trust-refresh.service` journal output before any bypass actions.
- If DNS leak protection fault is detected, keep fail-closed posture and do not bypass protection.
- If route/firewall apply failed, enforce rollback and block egress until trusted state recovers.

## 6) Verification Commands
- `RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock cargo run -p rustynet-cli -- status`
- `RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock cargo run -p rustynet-cli -- netcheck`
- `RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock cargo run -p rustynet-cli -- dns inspect`
- `RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock cargo run -p rustynet-cli -- route advertise 192.168.1.0/24`
- `RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock cargo run -p rustynet-cli -- key rotate`
- `RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock cargo run -p rustynet-cli -- key revoke`
- `sudo systemctl list-timers --all | grep rustynetd-trust-refresh`
- `sudo journalctl -u rustynetd-trust-refresh.service -n 50 --no-pager`
- `sudo systemd-creds decrypt --name=signing_key_passphrase /etc/rustynet/credentials/signing_key_passphrase.cred /tmp/signing_key_passphrase.test && sudo rm -f /tmp/signing_key_passphrase.test`
- `RUSTYNET_PHASE10_PROVENANCE_VERIFIER_KEY_PATH=<absolute-path> RUSTYNET_PHASE10_PROVENANCE_HOST_ID=<host-id> cargo run --quiet -p rustynet-cli -- ops verify-phase10-provenance`
- `./scripts/ci/phase10_gates.sh` (validates pre-generated measured artifacts in `artifacts/phase10`)

## 7) Required Evidence for Sign-Off
- `artifacts/phase10/netns_e2e_report.json`
- `artifacts/phase10/leak_test_report.json`
- `artifacts/phase10/perf_budget_report.json`
- `artifacts/phase10/direct_relay_failover_report.json`
- `artifacts/phase10/traversal_path_selection_report.json` (when traversal gate coverage is enabled)
- `artifacts/phase10/state_transition_audit.log`
- `artifacts/phase10/phase10_provenance.attestation.json`
- Limitation note: current failover artifact demonstrates path-mode transition/audit evidence; full relay transport failover integration remains open code work.

## 8) Security Invariants
- Default-deny policy remains active.
- Tunnel/DNS fail-close behavior is never bypassed.
- Mutating daemon IPC commands require peer credential authorization.
- WireGuard implementation remains behind `TunnelBackend` and replaceable.
- No custom crypto/protocol behavior is introduced.
- Direct/relay path transitions require signed, fresh traversal endpoint data; invalid traversal state must fail closed.
- Dataplane firewall/NAT ownership is generation-tagged and must only clean up Rustynet-owned tables.
