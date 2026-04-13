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

If any item fails, stop and remediate before running cross-network validators.
