# Rustynet

## Quick Start Wizard

Run the interactive setup/menu wizard:

```bash
./start.sh
```

The wizard handles:
- role selection (`admin`, `client`, or `blind_exit`) during setup, with role-specific console permissions
- guided in-menu role switching (`client` <-> `admin`) with local signed assignment refresh support on Linux
- host OS detection on startup with strict host-profile enforcement (`linux` dataplane vs `macos` compatibility)
- first-run bootstrap (dependencies, keys, trust material, systemd wiring)
- optional signer-backed trust-evidence auto-refresh timer on Linux to keep trust freshness valid during unattended runtime
- daemon/service lifecycle
- centrally signed auto-tunnel defaults with fail-closed enforcement
- break-glass manual peer connection helpers (explicit acknowledgement + audit logging)
- encrypted key custody at rest + runtime key management
- Linux runtime passphrase handling is credential-only: `rustynetd` requires a systemd
  encrypted credential (`/etc/rustynet/credentials/wg_key_passphrase.cred`) and
  rejects direct plaintext passphrase-file fallback at daemon runtime
- local key rotation/revocation and peer rotation-bundle apply flow
- membership bootstrap with persisted owner signing key (default Linux path: `/etc/rustynet/membership.owner.key`)
- exit-node and LAN-access toggles, including one-hop and two-hop chain selection in `start.sh` (re-selecting the active chain disconnects/clears selection)
- route advertisement and status checks

Host-profile behavior:
- Linux host: full runtime/dataplane provisioning.
- macOS host: full client/runtime dataplane provisioning using userspace WireGuard (`wireguard-go`) with privileged-helper mediated system operations.
- macOS service lifecycle hardening: daemon and privileged helper are managed through `launchd` (`launchctl bootstrap`/`kickstart`) rather than ad-hoc background processes.
- macOS dependency hardening: privileged networking tools (`wg`, `wireguard-go`) must be installed with admin privileges in root-owned paths; non-admin local fallback is intentionally blocked.
- macOS key custody hardening: WireGuard passphrase custody is Keychain-backed (`rustynet.wg_passphrase` service); persistent plaintext passphrase files are rejected by startup preflight.
- macOS path policy: Linux runtime roots (`/etc/rustynet`, `/var/lib/rustynet`, `/run/rustynet`, `/var/log/rustynet`) are not used; user-space paths are enforced instead.
- macOS PF safety: stale Rustynet PF anchors (`com.apple/rustynet_g*`) are pruned on dataplane generation apply to prevent residual fail-closed anchors after crashes/restarts.

Current implementation support/security matrix:
- [`documents/operations/PlatformSupportMatrix.md`](./documents/operations/PlatformSupportMatrix.md)

After first setup, run `./start.sh` again anytime to open the terminal control menu.

Role model:
- `admin`: full operational console (policy/trust/key/exit-node administration, with break-glass controls).
- `client`: limited console for joining/using the network (status, connect/disconnect from exit nodes, LAN toggle), with admin-only actions blocked at daemon runtime.
- `blind_exit`: least-knowledge exit-serving role intended as a final hop. It is immutable after setup (factory reset + fresh key provisioning required to change role), blocks local control-plane mutation commands, auto-enforces exit-serving posture, and sanitizes client-only assignment fields (selected exit/LAN flags) instead of fail-closing on role conversion.

Two-hop chain notes:
- Client chain selection supports `1-hop` (`client -> exit`) and `2-hop` (`client -> entry relay -> final exit`) in `start.sh` under `SELECT EXIT NODE`.
- For secure two-hop operation, the entry relay must be configured to use its upstream exit and advertise `0.0.0.0/0` (exit-serving) so it can relay downstream client traffic while tunneling upstream.
- `blind_exit` remains final-hop oriented: it can serve exit but cannot be configured to select an upstream exit.

Linux trust-refresh behavior:
- When admin setup has signer-key access (`AUTO_REFRESH_TRUST=1`), install flow enables `rustynetd-trust-refresh.timer` and performs periodic signed trust evidence refreshes.
- Guided role switching no longer force-disables `AUTO_REFRESH_TRUST` for `client` mode when a local signer key is available; this prevents avoidable trust-staleness fail-closed transitions during long-running client operation.
- If a node is switched to `client` mode without signer-key access, `AUTO_REFRESH_TRUST` is disabled with an explicit warning.
- Trust refresh jobs write trust evidence as `root:<daemon-group>` with `0640` mode so `rustynetd` can validate trust state without exposing signer key material.

Linux assignment-refresh behavior:
- Auto-tunnel enforcement remains fail-closed: stale/invalid signed assignment bundles are rejected.
- For unattended runtime, enable signer-backed assignment refresh with:
  - `RUSTYNET_ASSIGNMENT_AUTO_REFRESH=true` in `/etc/default/rustynetd`
  - `/etc/rustynet/assignment-refresh.env` containing:
    - `RUSTYNET_ASSIGNMENT_TARGET_NODE_ID`
    - `RUSTYNET_ASSIGNMENT_NODES`
    - `RUSTYNET_ASSIGNMENT_ALLOW`
    - optional `RUSTYNET_ASSIGNMENT_EXIT_NODE_ID`
    - `RUSTYNET_ASSIGNMENT_SIGNING_SECRET` (default `/etc/rustynet/assignment.signing.secret`, `0600 root:root`)
    - `RUSTYNET_ASSIGNMENT_TTL_SECS` and `RUSTYNET_ASSIGNMENT_MIN_REMAINING_SECS`
- Installer enables `rustynetd-assignment-refresh.timer` when assignment auto-refresh is enabled.
- Refresh jobs rewrite assignment artifacts with strict custody:
  - bundle: `/var/lib/rustynet/rustynetd.assignment` (`0640 root:<daemon-group>`)
  - verifier key: `/etc/rustynet/assignment.pub` (`0644 root:root`)

Signed auto-tunnel assignment issuance:
- Issue centrally signed per-node assignment bundles with explicit allow rules:
```bash
rustynet assignment issue \
  --target-node-id client-40 \
  --nodes "client-40|192.168.18.40:51820|<client_pubkey_hex>;exit-37|192.168.18.37:51820|<exit_pubkey_hex>" \
  --allow "client-40|exit-37" \
  --signing-secret /etc/rustynet/assignment.signing.secret \
  --output /tmp/client-40.assignment \
  --verifier-key-output /tmp/assignment.pub \
  --exit-node-id exit-37 \
  --ttl-secs 300
```
- `--nodes` format: `node_id|endpoint|public_key_hex[|owner|hostname|os|tags_csv]` entries separated by `;`.
- `--allow` format: `source_node_id|destination_node_id` entries separated by `;` (default-deny unless explicitly allowed).
- Endpoint stability: set a fixed WireGuard listen port on each node (`RUSTYNET_WG_LISTEN_PORT`, default `51820`) so signed assignment endpoints remain valid across daemon restarts.
- Exit-serving mode under enforced auto-tunnel: advertise `0.0.0.0/0` on the serving node (`rustynet route advertise 0.0.0.0/0`). This is the only route mutation allowed while auto-tunnel enforcement is enabled.
- When `0.0.0.0/0` is advertised and the node is not itself using an exit node, `rustynetd` applies forwarding+NAT for secure exit serving during reconcile.
- Keep assignment TTL aligned to `RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS` (default max-age is 300s). If TTL exceeds max-age, max-age still enforces fail-closed expiration.

## Automated Debian Pair Clean Install + Tunnel Validation

To repeat a full two-node Debian 13 clean install and secure tunnel validation from one operator machine:

```bash
umask 077 && printf 'tempo\n' > /tmp/rustynet_sudo.pass
./scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh \
  --exit-host 192.168.18.37 \
  --client-host 192.168.18.40 \
  --ssh-user debian \
  --sudo-password-file /tmp/rustynet_sudo.pass \
  --ssh-allow-cidrs 192.168.18.2/32 \
  --skip-apt
```

What this script does:
- pushes the selected local git ref (`HEAD` by default) to both hosts as a clean source archive
- performs clean Rustynet runtime reset on each host (service stop + Rustynet-owned dataplane cleanup)
- builds and installs `rustynetd` + `rustynet`
- initializes encrypted key custody using `systemd-creds` credential blob (no persistent plaintext passphrase files)
- initializes trust + membership state, issues signed assignment bundles, and enables auto-tunnel enforcement
- configures exit-node routing and validates tunnel/dataplane/security invariants
- writes a validation report to `artifacts/phase10/debian_two_node_remote_validation.md`

Important:
- `--ssh-allow-cidrs` is required and should be your management CIDR(s), not `0.0.0.0/0`.
- SSH control-master sessions are used; password-based SSH is supported interactively.
- When SSH user is non-root, provide `--sudo-password-file` (mode `0600`); this keeps sudo secrets out of command arguments.

## Release Readiness Evidence (Fail-Closed)

Rustynet no longer accepts static/pass-through readiness JSON artifacts.

Before Phase 6/9/10 gates can pass, generate measured evidence artifacts from real inputs:

```bash
# Phase 6 probe collection + parity evidence
./scripts/release/collect_platform_parity_bundle.sh

# Phase 6 platform parity evidence
RUSTYNET_PHASE6_PARITY_ENVIRONMENT=lab \
./scripts/release/generate_platform_parity_report.sh

# Phase 9 raw evidence collection from logs/probes
./scripts/operations/collect_phase9_raw_evidence.sh

# Phase 9 operational evidence
RUSTYNET_PHASE9_EVIDENCE_ENVIRONMENT=prod-lab \
./scripts/operations/generate_phase9_artifacts.sh

# Phase 10 operational evidence
RUSTYNET_PHASE10_EVIDENCE_ENVIRONMENT=prod-lab \
./scripts/operations/generate_phase10_artifacts.sh
```

Raw measured inputs must exist first:
- `artifacts/release/raw/platform_parity_linux.json`
- `artifacts/release/raw/platform_parity_macos.json`
- `artifacts/release/raw/platform_parity_windows.json`
- `artifacts/operations/source/*.ndjson|*.json` phase9 source logs/config:
  - `compatibility_policy.json`
  - `crypto_deprecation_schedule.json`
  - `slo_windows.ndjson`
  - `performance_samples.ndjson`
  - `incident_drills.ndjson`
  - `dr_drills.ndjson`
  - `backend_security_review.json`
- `artifacts/phase10/source/*.json|*.log` phase10 source evidence:
  - `netns_e2e_report.json`
  - `leak_test_report.json`
  - `perf_budget_report.json`
  - `direct_relay_failover_report.json`
  - `state_transition_audit.log`

Then run gates:

```bash
./scripts/ci/phase6_gates.sh
./scripts/ci/phase9_gates.sh
./scripts/ci/phase10_gates.sh
./scripts/ci/membership_gates.sh
```

## Phase 1 Measured Baseline Inputs

Phase 1 baseline gates require measured runtime inputs (`RUSTYNET_PHASE1_*` vars).  
Generate them from measured evidence sources (fail-closed, no synthetic fallback):

```bash
./scripts/perf/collect_phase1_measured_env.sh
./scripts/perf/run_phase1_baseline.sh
```

`run_phase1_baseline.sh` will auto-run the collector when env vars are missing.
If present, the collector can use `artifacts/operations/performance_budget_report.json`
as measured Phase1 input source.
The repo also seeds `artifacts/perf/phase1/source/performance_samples.ndjson`
for first-run CI/bootstrap resolution; refresh this with current measured samples
for release evidence.
