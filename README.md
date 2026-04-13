# Rustynet

## Current Focus

- finish an honest production transport-owning backend for traversal and relay on the real peer-traffic path
- refresh commit-bound live evidence for traversal, relay, failback, and fresh-install gates
- keep repository guidance current in ledgers, runbooks, and indexes rather than standalone prompt files

## Read First

If you are implementing or reviewing work in this repository, start here:

- [AGENTS.md](./AGENTS.md)
- [CLAUDE.md](./CLAUDE.md)
- [documents/README.md](./documents/README.md)
- [documents/Requirements.md](./documents/Requirements.md)
- [documents/SecurityMinimumBar.md](./documents/SecurityMinimumBar.md)

Primary execution ledgers:

- [documents/operations/active/MasterWorkPlan_2026-03-22.md](./documents/operations/active/MasterWorkPlan_2026-03-22.md)
- [documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md](./documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md)

Operational indexes and runbook maps:

- [documents/operations/README.md](./documents/operations/README.md)
- [documents/operations/active/README.md](./documents/operations/active/README.md)

Repository guidance rule:

- standalone prompt documents are not part of the long-term source of truth; use the active ledgers, runbooks, and index files above

## Quick Start Wizard

Run the interactive setup/menu wizard:

```bash
./start.sh
```

Optional Rust-native operator menu (baseline UX path):

```bash
rustynet operator menu
```

If you are starting from local UTM VMs and want the fastest first-pass inventory,
use the compact discovery summary first:

```bash
cargo run --quiet -p rustynet-cli -- ops vm-lab-discover-local-utm-summary --inventory documents/operations/active/vm_lab_inventory.json
```

Use the full JSON discovery report when you need the raw bundle, IP, SSH, and
readiness details:

```bash
cargo run --quiet -p rustynet-cli -- ops vm-lab-discover-local-utm --inventory documents/operations/active/vm_lab_inventory.json
```

Add `--update-inventory-live-ips` when you want a fully ready discovery pass to
refresh `documents/operations/active/vm_lab_inventory.json` without first
forcing a restart. Add `--report-dir <path>` when you want the JSON report and
summary written as artifacts.

## Live Lab Workflow

Use this four-step path when you want to exercise the local UTM lab end to end:

1. Discover
   - `ops vm-lab-discover-local-utm-summary`
   - Finds the local UTM bundles, live IPs, SSH readiness, and the fastest
     “can I use this lab?” summary.
   - Use `ops vm-lab-discover-local-utm` when you need the full JSON evidence.
   - If discovery shows live IPs but `readiness.execution_ready=false`,
     restart the local UTM fleet and wait for SSH auth readiness before you
     proceed:
     `ops vm-lab-restart --all --wait-ready --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 --known-hosts-file ~/.ssh/known_hosts`
   - A successful `ops vm-lab-restart --wait-ready` run also refreshes the
     local UTM inventory IP tracking in
     `documents/operations/active/vm_lab_inventory.json` so `ssh_target` and
     `last_known_ip` match the authoritative live IPs that actually came back.
   - Add `--json` when you want a machine-readable restart result, and
     `--report-dir <path>` when you want restart artifacts written to disk.
2. Setup
   - `ops vm-lab-setup-live-lab`
   - Generates or validates the live-lab profile, runs preflight plus the
     setup-only stages, writes the report directory, and supports
     `--resume-from` or `--rerun-stage` for deterministic reruns.
   - The setup wrapper now writes provenance-bound `state/setup_manifest.json`
     and `state/report_state.json` before execution. A reused setup report
     directory is accepted only when the current commit, dirty/clean tree
     state, profile, inventory identity, wrapper version/source, and setup
     flags match the recorded setup provenance.
3. Link and Test
   - `ops vm-lab-run-live-lab`
   - Runs the full live-lab suite and validates the report contract instead of
     trusting the shell exit code alone.
   - If the report directory already contains only completed setup stages from
     `ops vm-lab-setup-live-lab`, it continues with the test stages without
     rerunning setup, but only when the existing report directory passes the
     full provenance check. Any commit, dirty-tree, profile, inventory, or
     wrapper mismatch fails closed instead of attempting best-effort reuse.
4. Diagnose
   - `ops vm-lab-diagnose-live-lab-failure`
   - Collects the first failed stage and packages stage-aware failure context
     for triage.

This is the recommended operator path for live-lab work:
discover, set up, link and test, then diagnose if something fails.

Live-lab automation security expectations:

- SSH host trust must be pinned with `--ssh-known-hosts-file` or a pre-populated `~/.ssh/known_hosts`
- SSH TOFU (`accept-new`) is not part of the active wrapper path
- automation targets are expected to satisfy `sudo -n`
- unattended runtime secret custody remains credential-only; plaintext passphrase files are not an acceptable substitute

If you want the CLI to make the discovery-versus-restart decision for you and
then run the standard workflow in one shot, use:

- `ops vm-lab-orchestrate-live-lab`
- It discovers the selected local UTM VMs, restarts only the aliases that are
  not `readiness.execution_ready`, reruns discovery, then proceeds through
  setup, full live-lab execution, and diagnose-on-failure using the same report
  directory.
- The orchestration wrapper requires a fresh report directory and refuses to
  write into a populated one.
- Add `--stop-after-ready` when you want it to stop after proving VM
  reachability and inventory freshness, without starting setup.

If report-directory reuse is rejected, do one of these:

- use a new empty `--report-dir`, or
- rerun the original setup/report flow from the exact same commit and inputs on
  the original directory

Supporting wrappers remain available when you need tighter control over one part
of the flow:
- `ops vm-lab-write-live-lab-profile`
- `ops vm-lab-validate-live-lab-profile`
- `ops vm-lab-bootstrap-phase --phase all`

## Release Readiness

Use this final sign-off command when you want the repo-level release-readiness
guardrail:

```bash
./scripts/ci/release_readiness_gates.sh
```

That wrapper keeps the Phase 5 release-doc/provenance path and the Phase 10
fresh-install/cross-network evidence path on one fail-closed command. Reduced
helper evidence is useful for narrowing defects, but it is not treated as a
substitute for full release-gate evidence.

Authoritative release-gate reporting is generated during gate execution:

- `artifacts/release/phase5_gate_report.json`
- `artifacts/release/phase5_readiness_bundle.json`

Those files must come from the current gate run. They record
`executed_passed`, `executed_failed`, and `not_executed` states; pre-existing
files are not accepted as proof.

Current sign-off references:

- [documents/operations/ReleaseReadinessGuardrails.md](./documents/operations/ReleaseReadinessGuardrails.md)
- [documents/operations/active/Phase5ReleaseReadinessSummary_2026-04-12.md](./documents/operations/active/Phase5ReleaseReadinessSummary_2026-04-12.md)

The wizard handles:
- role selection (`admin`, `client`, or `blind_exit`) during setup, with role-specific console permissions
- guided in-menu role switching (`client` <-> `admin`) with local signed assignment refresh support on Linux
- host OS detection on startup with strict host-profile enforcement (`linux` dataplane vs `macos` compatibility)
- first-run bootstrap (dependencies, keys, trust material, systemd wiring)
- optional signer-backed trust-evidence auto-refresh timer on Linux to keep trust freshness valid during unattended runtime
- daemon/service lifecycle
- centrally signed auto-tunnel defaults with fail-closed enforcement
- manual peer break-glass mutation paths removed; signed assignment workflows are the only supported peer/routing mutation path
- encrypted key custody at rest + runtime key management
- Rust-backed WireGuard custody bootstrap (`rustynet ops bootstrap-wireguard-custody`) is mandatory in setup paths; unsupported/failed ops invocation is fail-closed (no shell fallback)
- sensitive bootstrap/migration artifacts (legacy key files and temporary passphrase files) are scrubbed before removal
- startup config integrity is strict for security-critical fields: invalid persisted role/chain/backend/interface/port values are fail-closed errors (no silent coercion)
- macOS canonical storage paths are enforced (`.../trust`, `.../assignment`, `.../keys`, `.../membership`); non-canonical legacy path values are fail-closed
- dependency bootstrap is single-route hardening: `start.sh` installs `rustup` from the approved host package manager and then installs the pinned workspace toolchain from `rust-toolchain.toml`; ambient distro `cargo`/`rustc` fallback and remote installer scripts are disabled
- Linux runtime passphrase handling is credential-only: `rustynetd` requires a systemd
  encrypted credential (`/etc/rustynet/credentials/wg_key_passphrase.cred`) and
  rejects direct plaintext passphrase-file fallback at daemon runtime
- Linux signing-key passphrase handling is also credential-only for unattended jobs:
  `/etc/rustynet/credentials/signing_key_passphrase.cred` is loaded into refresh
  services via `LoadCredentialEncrypted` (no persistent plaintext passphrase files)
- signing credential decrypt flows pin embedded credential name for cross-distro
  systemd compatibility: `systemd-creds decrypt --name=signing_key_passphrase ...`
- signing passphrase materialization is Rust-backed and fail-closed: the CLI decrypts
  into a fresh secure temp path and atomically publishes the requested output, rather
  than writing credential material through ad hoc direct-to-existing-file flows
- local key rotation/revocation through signed control-plane workflows
- membership bootstrap with encrypted persisted owner signing key (default Linux path: `/etc/rustynet/membership.owner.key`)
- exit-node and LAN-access toggles, including one-hop and two-hop chain selection in `start.sh` (re-selecting the active chain disconnects/clears selection)
- main menu quick actions keep VPN connect-state explicit: option `1` toggles between `CONNECT TO VPN` and `DISCONNECT FROM NETWORK`; option `2` is `SELECT EXIT NODE` for `admin`/`client`
- `SELECT EXIT NODE` performs a per-candidate readiness probe (`membership + tunnel`) and prints `membership`, `tunnel`, and `readiness`; current selection is marked with `*`
- connectivity architecture is staged toward direct-UDP-first with signed traversal endpoint hints and ciphertext-only relay for hard NAT paths; current runtime validates signed traversal bundles and signed coordination records, requires traversal-authoritative peer coverage for all managed peers in enforced auto-tunnel mode, collects bounded backend handshake evidence via `wg show ... latest-handshakes`, and only promotes `direct_active` or `relay_active` from fresh live proof rather than programmed state; relay-backed sessions are periodically reprobed on reconcile, and direct-active peers now use live backend handshake evidence to avoid stale cached path decisions before failing back from relay when direct becomes healthy again; traversal probe fanout, freshness, and reprobe cadence are explicit daemon policy (`--traversal-probe-max-candidates`, `--traversal-probe-max-pairs`, `--traversal-probe-rounds`, `--traversal-probe-round-spacing-ms`, `--traversal-probe-relay-switch-after-failures`, `--traversal-probe-handshake-freshness-secs`, `--traversal-probe-reprobe-interval-secs`) instead of implicit runtime defaults; the daemon now consumes an explicit backend-owned authoritative shared-transport contract for STUN round trips, relay hello/refresh, keepalive, and transport-identity diagnostics when a backend provides it, but current production WireGuard backends still explicitly block those workflows on separate daemon-owned sockets because they remain command-only adapters over OS-managed peer sockets and do not yet expose authoritative packet I/O or a backend-owned datagram multiplexer; the explicit non-default mode names `linux-wireguard-userspace-shared` and `macos-wireguard-userspace-shared` are now wired through daemon/start parsing and host-profile enforcement, but both still fail closed with that precise blocker, so plug-and-play cross-network completion remains blocked on a production backend mode that can satisfy the shared-transport contract plus fresh commit-bound live direct/relay/failback evidence
- `rustynet netcheck` now reports structured traversal diagnostics (`path_mode`, `path_reason`, traversal artifact freshness, candidate counts by type, and validation error state) and uses runtime-authored path states (`direct_active`, `relay_active`, `fail_closed`) instead of a static transport string
- traversal artifact custody and probe policy are configurable end-to-end (`--traversal-bundle`, `--traversal-verifier-key`, `--traversal-watermark`, `--traversal-max-age-secs`, `--traversal-probe-*`), and Linux systemd install wiring now propagates `RUSTYNET_TRAVERSAL_*` into `rustynetd.service`
- Magic DNS is now a signed control-plane path only: `rustynetd` loads a signed DNS-zone bundle from pinned custody paths, cross-checks every managed record against signed assignment state, answers the managed zone from a loopback-only authoritative resolver (`--dns-zone-*`, `--dns-resolver-bind-addr`), returns `SERVFAIL` for managed-name queries when signed DNS state is missing/invalid/stale, and refuses non-managed names rather than falling back to ad hoc local overrides or `/etc/hosts`; the supported Linux host-integration path is a dedicated `systemd-resolved` unit (`rustynetd-managed-dns.service`) that routes the private zone through the Rustynet interface only, with no `/etc/hosts` or raw resolver fallback
- route advertisement and status checks

Host-profile behavior:
- Linux host: full runtime/dataplane provisioning.
- macOS host: full client/runtime dataplane provisioning using userspace WireGuard (`wireguard-go`) with privileged-helper mediated system operations.
- macOS service lifecycle hardening: daemon and privileged helper are managed through `launchd` (`launchctl bootstrap`/`kickstart`) rather than ad-hoc background processes.
- macOS dependency hardening: privileged networking tools (`wg`, `wireguard-go`) must be installed with admin privileges in root-owned paths; non-admin local fallback is intentionally blocked.
- macOS key custody hardening: WireGuard passphrase custody is Keychain-backed (`rustynet.wg_passphrase` service); persistent plaintext passphrase files are rejected by startup preflight.
- macOS passphrase-file runtime fallback is removed; daemon runtime requires keychain-backed passphrase custody (`RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT` + keychain item).
- macOS path policy: Linux runtime roots (`/etc/rustynet`, `/var/lib/rustynet`, `/run/rustynet`, `/var/log/rustynet`) are not used; user-space paths are enforced instead.
- macOS dependency hardening: Homebrew must already be installed via approved operator workflow; automated remote-script install fallback is blocked.
- macOS PF safety: stale Rustynet PF anchors (`com.apple/rustynet_g*`) are pruned on dataplane generation apply to prevent residual fail-closed anchors after crashes/restarts.

Current implementation support/security matrix:
- [`documents/operations/PlatformSupportMatrix.md`](./documents/operations/PlatformSupportMatrix.md)
- Fresh-install OS matrix release gate (Debian/Ubuntu/Fedora/Mint/macOS):
  [`documents/operations/FreshInstallOSMatrixReleaseGate.md`](./documents/operations/FreshInstallOSMatrixReleaseGate.md)
- Traversal architecture and rollout plan:
  [`documents/operations/active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md`](./documents/operations/active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md)
- Traversal implementation blueprint (file-level security implementation):
  [`documents/operations/active/UdpHolePunchingImplementationBlueprint_2026-03-07.md`](./documents/operations/active/UdpHolePunchingImplementationBlueprint_2026-03-07.md)

After first setup, run `./start.sh` again anytime to open the terminal control menu.

Role model:
- `admin`: full operational console (policy/trust/key/exit-node administration) with signed control-plane enforcement.
- `client`: limited console for joining/using the network (status, connect/disconnect from exit nodes, LAN toggle), with admin-only actions blocked at daemon runtime.
- `blind_exit`: least-knowledge exit-serving role intended as a final hop. It is immutable after setup (factory reset + fresh key provisioning required to change role), blocks local control-plane mutation commands, auto-enforces exit-serving posture, and sanitizes client-only assignment fields (selected exit/LAN flags) instead of fail-closing on role conversion.

Two-hop chain notes:
- Client chain selection supports `1-hop` (`client -> exit`) and `2-hop` (`client -> entry relay -> final exit`) in `start.sh` under `SELECT EXIT NODE`.
- For secure two-hop operation, the entry relay must be configured to use its upstream exit and advertise `0.0.0.0/0` (exit-serving) so it can relay downstream client traffic while tunneling upstream.
- In relay-with-upstream mode, Linux dataplane enforcement now explicitly allows `rustynet0 -> rustynet0` forwarding and applies scoped tunnel-to-tunnel NAT (`iif rustynet0`, `oif rustynet0`) on the entry relay so return traffic from the final hop stays fail-closed and routable.
- `blind_exit` remains final-hop oriented: it can serve exit but cannot be configured to select an upstream exit.

Linux trust-refresh behavior:
- When admin setup has signer-key access (`AUTO_REFRESH_TRUST=1`), install flow enables `rustynetd-trust-refresh.timer` and performs periodic signed trust evidence refreshes.
- Linux trust refresh service path is Rust-only: `rustynetd-trust-refresh.service` executes `rustynet ops refresh-trust` directly (no shell wrapper in the active path), then enforces daemon-side signed state revalidation via `rustynet state refresh`.
- systemd refresh units pin `/usr/local/bin/rustynet` and run `ops verify-runtime-binary-custody` as `ExecStartPre`, enforcing root-owned/non-group-writable binary custody before refresh execution.
- `start.sh` manual trust refresh path is Rust-backed via `rustynet ops refresh-signed-trust` (typed passphrase materialization + scrubbed temp cleanup) with fail-closed behavior (no shell fallback).
- Guided role switching no longer force-disables `AUTO_REFRESH_TRUST` for `client` mode when a local signer key is available; this prevents avoidable trust-staleness fail-closed transitions during long-running client operation.
- If a node is switched to `client` mode without signer-key access, `AUTO_REFRESH_TRUST` is disabled with an explicit warning.
- Trust refresh jobs write trust evidence as `root:<daemon-group>` with `0640` mode so `rustynetd` can validate trust state without exposing signer key material.
- Trust signer keys are encrypted-at-rest and are signed/refreshed with explicit passphrase-file input (credential-injected under systemd).

Linux assignment-refresh behavior:
- Auto-tunnel enforcement remains fail-closed: stale/invalid signed assignment bundles are rejected.
- Trust and auto-tunnel watermark parsers are strict: only digest-bound `version=2` watermark files are accepted (legacy `version=1` is rejected fail-closed).
- Linux assignment refresh service path is Rust-only: `rustynetd-assignment-refresh.service` executes `rustynet ops refresh-assignment` directly (no shell wrapper in the active path), then enforces daemon-side signed state revalidation via `rustynet state refresh`.
- Linux service installer path is Rust-backed: `scripts/systemd/install_rustynetd_service.sh` is a thin wrapper to `rustynet ops install-systemd` (with `RUSTYNET_INSTALL_SOURCE_ROOT` pinned by the wrapper).
- Linux `start.sh` exit-node selection/disable flows now require local signed assignment refresh support; if assignment refresh is unavailable, interactive exit-node mutation fails closed instead of falling back to raw direct CLI mutation.
- Legacy Linux WireGuard key paths are no longer implicitly migrated in custody bootstrap/install flows; canonical paths must be present, or operators must perform explicit key re-enrollment/rotation.
- Linux signing artifact custody expects `/etc/rustynet` parent directory mode
  `0750` (`root:<daemon-group>`) with encrypted key files remaining `0600`.
- For unattended runtime, enable signer-backed assignment refresh with:
  - `RUSTYNET_ASSIGNMENT_AUTO_REFRESH=true` in `/etc/default/rustynetd`
  - `/etc/rustynet/assignment-refresh.env` containing:
    - `RUSTYNET_ASSIGNMENT_TARGET_NODE_ID`
    - `RUSTYNET_ASSIGNMENT_NODES`
    - `RUSTYNET_ASSIGNMENT_ALLOW`
    - optional `RUSTYNET_ASSIGNMENT_EXIT_NODE_ID`
    - `RUSTYNET_ASSIGNMENT_SIGNING_SECRET` (default `/etc/rustynet/assignment.signing.secret`, `0600 root:root`)
    - `RUSTYNET_ASSIGNMENT_SIGNING_SECRET_PASSPHRASE_FILE` (default credential path injected by `rustynetd-assignment-refresh.service`)
    - `RUSTYNET_ASSIGNMENT_TTL_SECS` and `RUSTYNET_ASSIGNMENT_MIN_REMAINING_SECS`
  - assignment refresh env files are written in quoted `EnvironmentFile` format; structured values such as `RUSTYNET_ASSIGNMENT_NODES` and `RUSTYNET_ASSIGNMENT_ALLOW` must not be emitted as raw unquoted shell text
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
  --signing-secret-passphrase-file /run/credentials/rustynetd-assignment-refresh.service/signing_key_passphrase \
  --output /tmp/client-40.assignment \
  --verifier-key-output /tmp/assignment.pub \
  --exit-node-id exit-37 \
  --ttl-secs 300
```
- Initialize an encrypted assignment signing secret:
```bash
rustynet assignment init-signing-secret \
  --output /etc/rustynet/assignment.signing.secret \
  --signing-secret-passphrase-file /run/credentials/rustynetd-assignment-refresh.service/signing_key_passphrase \
  --force
```
- `--nodes` format: `node_id|endpoint|public_key_hex[|owner|hostname|os|tags_csv]` entries separated by `;`.
- `--allow` format: `source_node_id|destination_node_id` entries separated by `;` (default-deny unless explicitly allowed).
- Endpoint stability: set a fixed WireGuard listen port on each node (`RUSTYNET_WG_LISTEN_PORT`, default `51820`) so signed assignment endpoints remain valid across daemon restarts.
- Optional internet reachability assist for Linux exit-serving nodes: setup now exposes opt-in NAT-PMP auto port-forward (`AUTO_PORT_FORWARD_EXIT=1`, default `0`; lease via `AUTO_PORT_FORWARD_LEASE_SECS`, default `1200`). This path is intentionally best-effort and fail-safe: unsupported routers/backends keep normal tunnel operation but leave external mapping unavailable.
- NAT-PMP/PCP/UPnP-style mapping is an optimization only and is not the primary connectivity architecture.
- Exit-serving mode under enforced auto-tunnel: advertise `0.0.0.0/0` on the serving node (`rustynet route advertise 0.0.0.0/0`). This is the only route mutation allowed while auto-tunnel enforcement is enabled.
- When `0.0.0.0/0` is advertised and the node is not itself using an exit node, `rustynetd` applies forwarding+NAT for secure exit serving during reconcile.
- Linux fail-closed management and peer-endpoint bypass routes resolve interface per destination (`ip route get`) before installing table `51820` host/CIDR routes. This prevents dual-NIC lockouts when management and internet egress interfaces differ.
- Linux service egress hardening now derives `RUSTYNET_EGRESS_INTERFACE` from the selected exit endpoint route when a client exit is selected (assignment-backed); explicit env overrides that do not match the route-derived interface are rejected fail-closed.
- `rustynetd` no longer ships with a stale `eth0` assumption: daemon default `egress_interface` is `auto`, and service startup resolves the actual default-route interface before dataplane preflight.
- Keep assignment TTL aligned to `RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS` (default max-age is 300s). If TTL exceeds max-age, max-age still enforces fail-closed expiration.

Signed Magic DNS zone issuance and verification:
- Issue a signed managed-zone bundle from the same control-plane signing root used for other signed artifacts:
```bash
rustynet dns zone issue \
  --signing-secret /etc/rustynet/membership.owner.key \
  --signing-secret-passphrase-file /run/credentials/rustynetd-trust-refresh.service/membership_owner_signing_key_passphrase \
  --subject-node-id client-40 \
  --nodes "client-40|192.168.18.40:51820|<client_pubkey_hex>;exit-37|192.168.18.37:51820|<exit_pubkey_hex>" \
  --allow "client-40|exit-37" \
  --records-manifest /tmp/dns-zone-records.manifest \
  --output /tmp/client-40.dns-zone \
  --verifier-key-output /tmp/dns-zone.pub \
  --zone-name rustynet \
  --ttl-secs 300
```
- Verify a signed managed-zone bundle before deployment:
```bash
rustynet dns zone verify \
  --bundle /tmp/client-40.dns-zone \
  --verifier-key /tmp/dns-zone.pub \
  --expected-zone-name rustynet \
  --expected-subject-node-id client-40
```
- `--records-manifest` must be canonical UTF-8 `key=value` text:
  - required top-level fields: `version=1`, `record_count=<n>`
  - required per-record fields: `record.<i>.label`, `record.<i>.target_node_id`, `record.<i>.ttl_secs`, `record.<i>.alias_count`
  - aliases are indexed as `record.<i>.alias.<j>=<label>`
  - unknown fields, sparse indices, duplicate fields, and whitespace-padded fields are rejected fail-closed
- `rustynetd` authoritative DNS defaults:
  - zone bundle: `/var/lib/rustynet/rustynetd.dns-zone`
  - verifier key: `/etc/rustynet/dns-zone.pub`
  - watermark: `/var/lib/rustynet/rustynetd.dns-zone.watermark`
  - max age: `300s`
  - managed zone: `rustynet`
  - loopback bind: `127.0.0.1:53535`
- The authoritative resolver is loopback-only; non-loopback bind addresses are rejected fail-closed.
- Linux systemd install now also wires a dedicated managed-DNS routing unit:
  - unit: `rustynetd-managed-dns.service`
  - resolver integration: `systemd-resolved` via `resolvectl`
  - routing scope: the Rustynet interface only (`RUSTYNET_WG_INTERFACE`)
  - Linux managed-DNS routing currently requires an IPv4 loopback resolver bind such as `127.0.0.1:53535`

## Automated Debian Pair Clean Install + Tunnel Validation

To repeat a full two-node Debian 13 clean install and secure tunnel validation from one operator machine:

```bash
umask 077 && printf 'tempo\n' > /tmp/rustynet_sudo.pass
./scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh \
  --exit-host 192.168.18.37 \
  --client-host 192.168.18.40 \
  --ssh-user debian \
  --ssh-known-hosts-file ~/.ssh/known_hosts \
  --sudo-password-file /tmp/rustynet_sudo.pass \
  --ssh-allow-cidrs 192.168.18.2/32 \
  --skip-apt
```

What this script does:
- pushes the selected local git ref (`HEAD` by default) to both hosts as a clean source archive
- performs clean Rustynet runtime reset on each host (service stop + Rustynet-owned dataplane cleanup)
- builds and installs `rustynetd` + `rustynet`
- initializes encrypted key custody using `systemd-creds` credential blob (no persistent plaintext passphrase files)
- decrypts signing credential blobs with explicit embedded-name pinning
  (`systemd-creds decrypt --name=signing_key_passphrase`) for distro portability
- initializes trust + membership state, issues signed assignment bundles, and enables auto-tunnel enforcement
- configures exit-node routing and validates tunnel/dataplane/security invariants
- writes a validation report to `artifacts/phase10/debian_two_node_remote_validation.md`

Important:
- `--ssh-allow-cidrs` is required and should be your management CIDR(s), not `0.0.0.0/0`.
- SSH host trust is pinned: provide `--ssh-known-hosts-file` or pre-populate `~/.ssh/known_hosts` with the target host keys. TOFU (`accept-new`) is intentionally disabled.
- SSH control-master sessions are used; password-based SSH is supported interactively.
- When SSH user is non-root, provide `--sudo-password-file` (mode `0600`); this keeps sudo secrets out of command arguments.

## Active-Network Adversarial Security Tests

Run hardened, active-network adversarial tests against real hosts:

```bash
./scripts/e2e/real_wireguard_signed_state_tamper_e2e.sh \
  --exit-host 192.168.18.49 \
  --client-host 192.168.18.50 \
  --ssh-user root \
  --ssh-known-hosts-file ~/.ssh/known_hosts \
  --ssh-allow-cidrs 192.168.18.2/32 \
  --skip-apt

./scripts/e2e/real_wireguard_rogue_path_hijack_e2e.sh \
  --exit-host 192.168.18.49 \
  --client-host 192.168.18.50 \
  --ssh-user root \
  --ssh-known-hosts-file ~/.ssh/known_hosts \
  --ssh-allow-cidrs 192.168.18.2/32 \
  --rogue-endpoint-ip 203.0.113.250 \
  --skip-apt
```

Security intent:
- signed-state tamper test mutates the active assignment bundle and requires daemon fail-closed behavior (`state=FailClosed`, `restricted_safe_mode=true`) until valid signed state is restored.
- rogue-path hijack test forges assignment endpoints to a rogue IP (with invalid signature) and requires explicit rejection, no rogue endpoint adoption in `wg show`, and secure recovery after restoration.

Optional combined gate wrapper:

```bash
RUSTYNET_ACTIVE_NET_EXIT_HOST=192.168.18.49 \
RUSTYNET_ACTIVE_NET_CLIENT_HOST=192.168.18.50 \
RUSTYNET_ACTIVE_NET_SSH_USER=root \
RUSTYNET_ACTIVE_NET_SSH_KNOWN_HOSTS_FILE=~/.ssh/known_hosts \
RUSTYNET_ACTIVE_NET_SSH_ALLOW_CIDRS=192.168.18.2/32 \
RUSTYNET_ACTIVE_NET_ROGUE_ENDPOINT_IP=203.0.113.250 \
RUSTYNET_ACTIVE_NET_SKIP_APT=1 \
./scripts/ci/active_network_security_gates.sh
```

To include these tests in security regression gates:
- set `RUSTYNET_SECURITY_RUN_ACTIVE_NETWORK_GATES=1`.
- set `RUSTYNET_SECURITY_REQUIRE_ACTIVE_NETWORK_GATES=1` to fail closed when active-network gates are not run.

Additional live Linux regression scenarios on the active VM lab:

```bash
umask 077 && printf 'tempo\n' > /tmp/rustynet_lab.pass

./scripts/e2e/live_linux_two_hop_test.sh \
  --ssh-known-hosts-file ~/.ssh/known_hosts \
  --ssh-password-file /tmp/rustynet_lab.pass \
  --sudo-password-file /tmp/rustynet_lab.pass

./scripts/e2e/live_linux_exit_handoff_test.sh \
  --ssh-known-hosts-file ~/.ssh/known_hosts \
  --ssh-password-file /tmp/rustynet_lab.pass \
  --sudo-password-file /tmp/rustynet_lab.pass

./scripts/e2e/live_linux_lan_toggle_test.sh \
  --ssh-known-hosts-file ~/.ssh/known_hosts \
  --ssh-password-file /tmp/rustynet_lab.pass \
  --sudo-password-file /tmp/rustynet_lab.pass
```

These scripts are measured live-network regressions for:
- two-hop client -> entry relay -> final exit routing
- exit handoff under load without route leak or restricted-safe regressions
- LAN-access toggle enforcement, including blind-exit deny behavior

Security properties asserted by the live harness:
- assignment issuance uses the Rust signing/passphrase path (`rustynet ops materialize-signing-passphrase`)
- remote sudo password material is securely scrubbed on cleanup (`rustynet ops secure-remove`)
- plaintext passphrase-file residue checks are enforced on the tested hosts
- reports are bound to the current git commit and written under `artifacts/phase10/`

## Release Readiness Evidence (Fail-Closed)

Rustynet no longer accepts static/pass-through readiness JSON artifacts.

Before Phase 6/9/10 gates can pass, generate measured evidence artifacts from real inputs:

```bash
# Phase 6 probe collection + parity evidence
./scripts/release/collect_platform_parity_bundle.sh

# Phase 6 platform parity evidence
RUSTYNET_PHASE6_PARITY_ENVIRONMENT=lab \
./scripts/release/generate_platform_parity_report.sh
cargo run --quiet -p rustynet-cli -- ops verify-phase6-parity-evidence

# Phase 9 raw evidence collection from logs/probes
./scripts/operations/collect_phase9_raw_evidence.sh

# Phase 9 operational evidence
RUSTYNET_PHASE9_EVIDENCE_ENVIRONMENT=prod-lab \
./scripts/operations/generate_phase9_artifacts.sh
cargo run --quiet -p rustynet-cli -- ops verify-phase9-evidence

# Phase 10 operational evidence
RUSTYNET_PHASE10_EVIDENCE_ENVIRONMENT=prod-lab \
./scripts/operations/generate_phase10_artifacts.sh
```

Phase10 provenance defaults:
- if `RUSTYNET_PHASE10_PROVENANCE_SIGNING_KEY_PATH` / `RUSTYNET_PHASE10_PROVENANCE_VERIFIER_KEY_PATH` are unset, Rustynet uses `artifacts/phase10/provenance/signing_seed.hex` and `artifacts/phase10/provenance/verifier_key.hex`.
- when both default key files are absent, Rustynet generates a matching Ed25519 keypair through the Rust command path and writes owner-only files (`0600`) under an owner-only directory (`0700`).
- if `RUSTYNET_PHASE10_PROVENANCE_HOST_ID` is unset, Rustynet uses `ci-localhost`.
- for production, set all three provenance env vars explicitly to stable host-specific values under controlled key paths.

Phase 6 release scripts are thin wrappers to Rust-only ops commands:
- `rustynet ops collect-platform-probe`
- `rustynet ops generate-platform-parity-report`
- `rustynet ops collect-platform-parity-bundle`
- `rustynet ops verify-phase6-parity-evidence`

Phase 9/10 operations scripts are also thin wrappers to Rust-only ops commands:
- `rustynet ops collect-phase9-raw-evidence`
- `rustynet ops generate-phase9-artifacts`
- `rustynet ops verify-phase9-evidence`
- `rustynet ops generate-phase10-artifacts`
- `rustynet ops verify-phase10-provenance`
- `rustynet ops sign-release-artifact`
- `rustynet ops verify-release-artifact`

Signed evidence attestations:
- Phase 6 parity report attestation: `artifacts/release/platform_parity_report.attestation.json`
- Phase 9 operational evidence attestation: `artifacts/operations/phase9_evidence.attestation.json`
- both attestations are fail-closed verified, signed with release provenance keys, and bound to the current git commit.

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
  - `traversal_path_selection_report.json`
  - `traversal_probe_security_report.json`
  - `managed_dns_report.json`
  - `state_transition_audit.log`
- `artifacts/phase10/fresh_install_os_matrix_report.json` cross-platform fresh-install release evidence:
  - must include Debian/Ubuntu/Fedora/Mint/macOS clean-install checks
  - must include one-hop + two-hop enforcement checks per OS
  - must include role-switch validation checks per OS
  - must bind evidence to current `HEAD` commit SHA
  - for Linux-only validation runs, set `RUSTYNET_FRESH_INSTALL_OS_MATRIX_PROFILE=linux` (requires Debian/Ubuntu/Fedora/Mint scenarios; default remains `cross_platform`)

Then run gates:

```bash
./scripts/ci/phase6_gates.sh
./scripts/ci/phase9_gates.sh
./scripts/ci/phase10_gates.sh
./scripts/ci/security_regression_gates.sh
./scripts/ci/supply_chain_integrity_gates.sh
./scripts/ci/active_network_security_gates.sh
./scripts/ci/role_auth_matrix_gates.sh
./scripts/ci/traversal_adversarial_gates.sh
./scripts/ci/fresh_install_os_matrix_release_gate.sh
./scripts/ci/secrets_hygiene_gates.sh
./scripts/ci/membership_gates.sh
```

High-assurance no-leak dataplane gate (root Linux netns + underlay packet capture):

```bash
sudo -E ./scripts/ci/no_leak_dataplane_gate.sh
```

Security gate toolchain note:
- phase gate scripts require the pinned Rust security toolchain (`RUSTYNET_SECURITY_TOOLCHAIN`, default `1.88.0-<host-triple>`) to be installed; ambient cargo toolchain fallback is disabled.
- interactive/operator bootstrap now follows the same provenance rule: install `rustup` from the host package manager, then install/use the pinned workspace toolchain declared in [`rust-toolchain.toml`](/Users/iwanteague/Desktop/Rustynet/rust-toolchain.toml).

## Phase 1 Measured Baseline Inputs

Phase 1 baseline gates require measured source evidence from
`RUSTYNET_PHASE1_PERF_SAMPLES_PATH` (no source-fallback chain).

Canonical flow:

```bash
./scripts/perf/collect_phase1_measured_env.sh
./scripts/perf/run_phase1_baseline.sh
```

Both scripts resolve `RUSTYNET_PHASE1_PERF_SAMPLES_PATH` to:
- default `artifacts/perf/phase1/source/performance_samples.ndjson`, or
- an explicit operator override.

If the source file is missing, both scripts fail closed.

The collector writes structured measured input JSON
(`artifacts/perf/phase1/measured_input.json` by default) and no longer emits shell
`export` scripts.

`run_phase1_baseline.sh` exports the validated source path into the Rust command path
and runs baseline generation directly (no shell `source`, no legacy fallback chain).

Optional output override:
- `RUSTYNET_PHASE1_MEASURED_INPUT_OUT` for collector output path.
- collector source files and output directories fail closed when group/world writable.

The repo also seeds `artifacts/perf/phase1/source/performance_samples.ndjson`
for first-run CI/bootstrap; refresh this with current measured samples before release evidence sign-off.
