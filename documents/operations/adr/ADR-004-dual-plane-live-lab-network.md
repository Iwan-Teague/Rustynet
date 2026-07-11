# ADR-004: Dual-plane live-lab VM network architecture

- Status: Accepted
- Date: 2026-07-10

## Context

The UTM lab's VM attachments had drifted into an unmanaged mix: some guests on
UTM Shared (host-NAT), some Bridged to the host's everyday LAN (`en0`), some
Bridged with no pinned interface at all. Run meaning depended on the selected
VM, the current physical LAN, host VPN state, and prior MCP actions. The
deterministic netns simulator's transit (`100.64.0.0/24`) overlapped the
Rustynet mesh overlay (`100.64.0.0/10`), so daemon-path evidence from it was
unacceptable. MCP tooling could silently re-bridge a VM onto `en0` with no
profile, transaction, rollback, or evidence contract.

A network security product needs selectable NAT, routing, DNS, firewall,
roaming, loss, MTU, address-family, hostile-LAN, and relay conditions — and
observation without handing the product a hidden management route it can use
as an egress bypass. Full analysis and policy:
[LiveLabVmConnectivityRulebook.md](../LiveLabVmConnectivityRulebook.md).

## Decision

1. **Four-plane model.** Management plane, scenario underlay, Rustynet
   overlay, and egress plane are distinct and never conflated
   (`management_ip` / `scenario_ip` / `mesh_ip` / `observed_egress_ip`).
   Management reachability is never dataplane proof.
2. **Dual-NIC target.** Each lab VM gets NIC 0 as a narrow
   management/recovery plane (Shared or Host Only; no Rustynet endpoint
   advertisement; no default internet route in security-evidence stages) and
   NIC 1 as the controlled scenario plane carrying all Rustynet product
   traffic, with a unique scenario IP on a lab-owned subnet.
3. **Evidence ladder.** Tier 0 pure Rust tests → Tier 1 `crossnet_netns_v1`
   (deterministic netns NAT/security regression) → Tier 2
   `isolated_multivm_v1` (dual-plane multi-VM; long-term routine default) →
   Tier 3 `dedicated_physical_lab_v1` → Tier 4 `remote_wild_v1` (mandatory
   for any "works in the wild"/release claim). No lower tier can be promoted
   into a higher tier's claim.
4. **Mutation boundary.** VM network attachments change ONLY through the
   typed Rust prepare/restore transaction
   (`rustynet ops vm-lab-network-prepare` / `vm-lab-network-restore`):
   explicit `--approve-reconfigure` authorization, atomic overlap-refusing
   lease, stopped-VM-only configuration writes, full-config rollback
   snapshots (owner-only, outside committed evidence), verified rollback, and
   no partial continuation. MCP run functions verify profiles; they never
   silently mutate networking, and direct MCP plist/AppleScript network
   mutation is removed.
5. **Address plan.** Rustynet mesh overlay: `100.64.0.0/10`. Scenario sites:
   `172.20.0.0/16` (one subnet per site). Ordinary simulated
   internet/transit: `198.18.0.0/15` (IANA benchmarking). `100.64.0.0/10`
   underlay use is reserved for the explicit `cgnat_collision_v1` adversarial
   profile with its own dedicated oracle. Never bridge automatically to
   `en0`; a bridged profile must name a dedicated allowlisted interface.
6. **Profiles are the unit of network truth.** Reviewed, versioned,
   secret-free TOML manifests under `profiles/vm_lab/network/` with a
   canonical digest over the validated representation; every run records
   profile ID + digest immutably at launch; drift after launch fails closed;
   status vocabulary is `pass`/`fail`/`not_run`/`not_supported`/
   `expected_fail` (`skipped` is internal-only and missing substrate is
   `not_run`, never pass).

## Rejected alternatives

- **Shared-only for everything.** Hides or couples behavior to host NAT,
  host VPN/proxy state, and UTM implementation details; no selectable NAT
  boundary; convenient for builds, invalid as canonical network evidence.
- **Bridged-to-ordinary-LAN as default.** Realistic DHCP addresses but weak
  reproducibility, exposes guests to ambient traffic, leaves all peers on one
  L2 segment with no controlled NAT boundary, and couples every run to the
  operator's current physical network. Retained only as an explicit,
  environment-bound physical test cell behind an allowlisted interface.

## Consequences

- Runs carry network-profile provenance (ID, digest, management mode,
  substrate, address family, internet mode, evidence path) in the run matrix;
  legacy rows stay blank.
- The mixed-attachment fleet is now a detected, reported condition
  (`vm-lab-network-audit`), not silent ambient state; migrating it is an
  explicit approval-gated transaction.
- The netns simulator's ordinary transit moved to `198.18.0.0/15`
  (Tier 1 re-proven live 2026-07-10); the CGNAT overlap became a deliberate
  adversarial profile instead of an accident.
- Higher tiers (dedicated physical lab, remote wild) stay honestly `not_run`
  until the rulebook §15.9 owner infrastructure decisions close.

## Implementation

- `crates/rustynet-cli/src/vm_lab/network_profile.rs` — typed profiles,
  digests, capability matrix, per-run record.
- `crates/rustynet-cli/src/vm_lab/network_audit.rs` — read-only audit /
  preflight, redacted evidence writer.
- `crates/rustynet-cli/src/vm_lab/network_prepare.rs` — the mutation
  transaction (lease, rollback, fault-injected).
- `profiles/vm_lab/network/*.toml` — reviewed manifests.
- Execution ledger:
  [LiveLabVmConnectivityImplementation_2026-07-10.md](../active/LiveLabVmConnectivityImplementation_2026-07-10.md).

## Related

- [LiveLabVmConnectivityRulebook.md](../LiveLabVmConnectivityRulebook.md) —
  owning policy document (§15 implementation contract).
- [CrossNetworkSimulationRunbook.md](../CrossNetworkSimulationRunbook.md) —
  deterministic substrates on the new address plan.
- ADR-001 (no-secret-leakage) — the evidence writer's redaction obligations.
