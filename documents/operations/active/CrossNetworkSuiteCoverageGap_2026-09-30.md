# Cross-network scenario stages have never run (2026-09-30)

**Status.** DRAFT FOR OWNER DECISION. The finding is confirmed by an independent review. The proposed fix changes the network configuration of the lab host katana, which needs the owner's approval before anyone does it.

## Finding

Eight cross-network scenario stages have a `skip` row in every run recorded in `live_lab_node_stage_results.csv` (903 rows each) and have never passed or failed:
- `cross_network_direct_remote_exit`
- `cross_network_node_network_switch`
- `cross_network_relay_remote_exit`
- `cross_network_failback_roaming`
- `cross_network_controller_switch`
- `cross_network_traversal_adversarial`
- `cross_network_remote_exit_dns`
- `cross_network_remote_exit_soak`

`cross_network_nat_matrix` ran in one lost run (5 `fail` rows from 2026-08-28, commit no longer reachable) and has skipped since.

The stages are planned in every run. Each one skips on a precondition that no lab fleet has met:

1. **Substrate.** They need `--cross-network-substrate vxlan` (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/cross_network.rs` ~621). `cross_network_nat_classification` needs the netns substrate instead, so the two halves never run in the same launch. This split is by design.
2. **Roles.** They need client, exit, and entry or aux (~1096).
3. **Distinct underlay networks.** The client's and the exit's management (SSH) addresses must be in different /24 networks (~1119). The vxlan substrate groups nodes by the same address and builds no overlay when every node shares one /24. The local UTM fleet (192.168.64.0/24) and katana (192.168.122.0/24) each put every guest on one /24, so this gate can never pass on either.

The lenovo runs u9 and u10 used vxlan. u9 lacked an entry or aux role. u10 had all four roles, but all of them were on one /24. katana-u24 had no substrate flag.

What does run today: `cross_network_preflight` is a real gate. `cross_network_nat_classification` does real work (netns NAT profiles on the exit guest). `cross_network_substrate_setup` and `_teardown` are provenance no-ops when no overlay is built. Their witness wrongly claimed `provisioned=true` in that case; that is being fixed separately (fleet lane b62).

## Why not change the gate instead

The only other address field is the inventory's `dataplane_endpoint`. Using it would weaken the proof:
- The substrate binds vxlan to the SSH address, so a gate keyed on another field would pass while the substrate grouped nodes differently.
- A substrate overlay and a `dataplane_endpoint` on the same node are refused, fail-closed.
- Owner-lab dataplane endpoints are tailnet addresses, so every node would trivially be "its own /24".

The local inventory overlay cannot move katana-exit-1 either: it refuses a duplicate alias.

## Proposed fix (owner decision)

Enable the scenario suite on katana only, through the lab tooling (`~/rustysuite-fleet/lab/katana-prep*.sh`, outside the repo). Nothing in the repo changes:

1. Define a second libvirt NAT network, crossnet2, on 192.168.123.0/24, and give katana-exit-1 a second NIC on it, with a static guest address (for example 192.168.123.2/24) and no gateway. DHCP would add a second default route on the exit.
2. Add persisted FORWARD accepts between virbr0 and virbr1. libvirt's per-bridge rules otherwise reject new flows between the two networks, and the underlay traffic would never pass.
3. Pin the new exit address in katana's `~/.ssh/known_hosts` (`ssh-keyscan`), because the orchestrator enforces StrictHostKeyChecking.
4. In the lab snapshot's inventory, move katana-exit-1's `ssh_target` and `last_known_ip`, plus its network labels, to the new address. The killswitch SSH allowlist is derived from `last_known_ip` first.
5. Run `--cross-network-substrate vxlan` with `katana-client-1:client katana-exit-1:exit katana-entry-1:entry katana-aux-1:aux`.

katana's llama-server (a host process) is not affected. Risk: the exit guest becomes dual-homed, so stages that are LAN-scoped on the exit need watching in the first run. The change is reversible: detach the NIC, undefine the network, and remove the FORWARD rules.

## Evidence

- Investigation: fleet lane rustynet-b61-cross-network-never-runs.
- Independent review: charter/reviews/REVIEW-cross-network-coverage-gap-2026-09-30.md (CONFIRMED WITH CORRECTIONS; it corrected the nat_matrix history, added the firewall, static-address, host-key and inventory steps, and found the witness defect).
