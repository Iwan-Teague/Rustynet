# Cross-Network Live Lab Prerequisites Checklist

## Purpose
This checklist defines the minimum external prerequisites required to run reproducible, security-valid cross-network Rustynet remote-exit validation.

Scope: direct remote exit, relay remote exit, failback/roaming, traversal adversarial, DNS fail-closed, and soak suites.

## 1) Host and Topology Prerequisites
- Distinct hosts for role separation:
  - `client_host`
  - `exit_host`
  - `relay_host` (required for relay/failback suites)
  - `probe_host` (required for traversal adversarial control-surface checks)
- Distinct underlay networks:
  - `client_network_id != exit_network_id`
  - relay network distinct when relay suite is used
- Linux hosts only for Phase10 dataplane validation.
- Stable hostnames and pinned SSH host keys for every target.

## 2) Access and Identity Prerequisites
- SSH private key file available locally with owner-only permissions (`0400` or `0600`).
- Pinned known-hosts file present and not group/world writable.
- Passwordless sudo available on each target for automation (`sudo -n` must succeed).
- No SSH TOFU acceptance in automation runs (strict host key checking only).

## 3) Runtime and Binary Prerequisites
- Current repository source synchronized to test runner and target hosts.
- `rustynet` and `rustynetd` binaries installed on each target.
- Active daemon socket on each target:
  - `/run/rustynet/rustynetd.sock`
- systemd units available:
  - `rustynetd.service`
  - `rustynetd-managed-dns.service`
  - `rustynetd-trust-refresh.timer`/service
  - `rustynetd-assignment-refresh.timer`/service

## 4) Signed-State and Key-Custody Prerequisites
- Trust evidence and verifier key installed:
  - `/var/lib/rustynet/rustynetd.trust`
  - `/etc/rustynet/trust-evidence.pub`
- Assignment verifier key path available:
  - `/etc/rustynet/assignment.pub`
- Traversal verifier key path available:
  - `/etc/rustynet/traversal.pub`
- DNS zone verifier key path available:
  - `/etc/rustynet/dns-zone.pub`
- Assignment/traversal refresh environment files hardened:
  - `/etc/rustynet/assignment-refresh.env` mode `0600`
- No plaintext passphrase files at rest:
  - `/var/lib/rustynet/keys/wireguard.passphrase` absent
  - `/etc/rustynet/wireguard.passphrase` absent

## 5) Network and Security-Control Prerequisites
- nftables support and policy routing available on each target.
- Exit forwarding/NAT prerequisites present for exit host.
- Control-plane SSH allow CIDRs explicitly defined (narrow scope only).
- Host clocks synchronized (freshness/replay windows must be respected).
- Underlay default routes healthy on all participating hosts.

## 6) Tooling Prerequisites on Runner
- `cargo`
- `bash`
- `ssh`, `scp`, `ssh-keygen`
- `awk`, `sed`, `openssl`, `xxd`, `mktemp`, `chmod`
- repository scripts executable:
  - `scripts/ci/phase10_cross_network_exit_gates.sh`
  - `scripts/ci/phase10_gates.sh`
  - cross-network e2e scripts under `scripts/e2e/`

## 7) Required Inputs Per Suite
- Direct remote exit:
  - client/exit targets, node ids, distinct network ids
- Relay remote exit:
  - + relay target/node id/network id
- Failback/roaming:
  - + relay target and endpoint roam-capable underlay
- Traversal adversarial:
  - + probe target, rogue endpoint IP input
- DNS:
  - managed zone name and resolver bind/interface parameters
- Soak:
  - soak duration, sample interval, failure thresholds

## 8) Reproducibility Controls
- Use explicit NAT profile labels (`--cross-network-nat-profiles`).
- **The label vocabulary below is CLOSED, and the flags enforce it (CN-4, 2026-08-27).**
  `--cross-network-nat-profiles` and `--cross-network-required-nat-profiles` parse onto
  `substrate::NatProfileId`, so a name outside the five is a **parse-time error listing
  the whole vocabulary** — it no longer travels as a free string to a substrate that can
  only object much later, on a guest. Owner-approved in
  `active/OwnerDecisionDigest_2026-08-27.md` §16. This intentionally rejects free-form
  labels that parsed before; correct any saved invocation that used one.
- Defined NAT profile labels (dataplane plan D5.1; the semantics of record are
  `scripts/vm_lab/apply_nat_profile.sh`, which records the active profile in
  `/run/rustynet_nat_profile` for pre-run verification, and are implemented in Rust by
  `CrossNetworkSubstrateProvider::apply_nat_profile`):
  - `baseline_lan` — plain routing, no NAT (legacy same-subnet baseline; cross-network
    suites must NOT claim cross-network results under this label).
  - `port_restricted_cone` — plain conntrack masquerade: endpoint-independent mapping,
    endpoint-dependent filtering. Default cross-network profile; exposes the
    cold-contact gap (plan §4.1.1).
  - `full_cone` — masquerade plus DMZ-style DNAT of the WireGuard/relay UDP port range
    to the LAN host: endpoint-independent mapping and filtering.
  - `symmetric` — masquerade with randomised source ports per flow (endpoint-dependent
    mapping).
  - `double_nat_cgnat` — nested-namespace double NAT with an RFC 6598 (100.64.0.0/10)
    inner segment and a randomised outer hop; no uPnP at the outer hop (plan §4.1.3).
  - Modifier `upnp_available` — a uPnP/NAT-PMP responder answering on the router's LAN
    side (inner hop only under `double_nat_cgnat`). In Rust this is
    `NatModifiers::with_upnp()`, wired on the **vxlan** substrate only.
  - Modifier `v6_native` — an IPv6 prefix routed natively, no NAT66. In Rust this is
    `NatModifiers::with_ipv6_prefix(<ULA>/<len>)`, also vxlan-only; the prefix must be a
    unique-local (`fc00::/7`) network address, and the two site addresses are assigned
    statically rather than advertised by radvd (see the CN-4 deviation note in
    `active/CrossNetworkSubstrateIntegrationSpec_2026-06-21.md` §0.4).
  - **Which substrate realises which label** — ask the code, not this list:
    `CrossNetworkSubstrateProvider::supports()` / `supports_with_modifiers()` answer per
    substrate, and an unrealisable combination is a typed, reasoned refusal rather than
    a silent no-op. As of CN-4: **netns** realises `port_restricted_cone`, `full_cone`,
    `symmetric`, `double_nat_cgnat` (no modifiers); **vxlan** realises `baseline_lan`,
    `port_restricted_cone`, `full_cone`, `symmetric` (modifiers on the three shaping
    profiles); **slirp** realises none — UTM `Shared Network` NAT is not selectable.
- Use explicit impairment profile labels for each run.
- Stamp reports with commit-bound evidence (`git_commit`).
- Store outputs in canonical artifact directory (`artifacts/phase10`).
- Require suite-local SSH trust summary artifacts for authoritative reports:
  - pinned host-key proof for every participating target
  - `sudo -n` proof for every participating target
- Require path evidence to prove authoritative backend-owned shared transport for authoritative pass claims.
- Require schema and NAT-matrix validation pass before accepting results.

## 9) Pre-Run Go/No-Go Checklist
- [ ] All required hosts reachable with pinned-key SSH.
- [ ] `sudo -n` succeeds on every target.
- [ ] Daemon socket exists on every required host.
- [ ] Trust/assignment/traversal verifier files present.
- [ ] No plaintext passphrase files detected.
- [ ] Distinct client/exit network IDs confirmed.
- [ ] Required scripts and binaries present on runner.
- [ ] Artifact output directory writable.
- [ ] Network profile selected and verified: `rustynet ops vm-lab-network-preflight
      --profile <id>` passes (or the run's derived profile record exists) —
      see [LiveLabVmConnectivityRulebook.md](./LiveLabVmConnectivityRulebook.md) §10.
- [ ] No reverse-SOCKS bootstrap tunnel active (`set_vm_internet_access`
      disabled for every alias); SOCKS presence blocks evidence stages.
- [ ] Ordinary simulated transit is inside `198.18.0.0/15` (the netns
      simulator default); `100.64.0.0/24` transit only under the explicit
      `cgnat_collision_v1` profile.

If any item fails, stop and remediate before running cross-network validators.
