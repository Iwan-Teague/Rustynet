# Azure cloud VM as a Rustynet live-lab node (2026-09-29)

**Status.** Owner-approved. Direction (2026-09-29): "can we add this as a rustynet VM that can be used for testing? Can we use it as a node in our live labs", then "just compile it on this machine and ship the binary to the cloud VM", then yes to the access and firewall changes listed below. This record says how, why, and what is still open. Nothing here changes the product. The VM's addresses are deliberately not written in this public repository.

## The machine

- `student-vm`: Ubuntu 24.04 LTS, x86_64, 2 vCPU, about 900 MB RAM, 61 GB disk, glibc 2.39, on the owner's university "Azure for Students" subscription (region restricted by university policy to a few EU regions). It has a dynamic public IPv4 address.
- It runs nothing else of note. The only non-system processes belong to the Azure Linux Agent (`walinuxagent`), which Azure needs for provisioning and run-command, and which must be left running.

## Why it is worth adding

Every existing lab host puts all its guests on one private network: katana on its libvirt NAT network, lenovo-bot on one bridged LAN, the Mac on the UTM vmnets. So:
- **Cross-network stages lack a real second network.** 9 of the 13 `cross_network_*` stages have never passed on any host; the other four pass only as single-host netns-simulator plumbing (`LiveLabCoverageGapAudit_2026-09-27.md` row 27, re-counted from `live_lab_node_stage_results.csv`). A node on the public internet, behind a different NAT from the lab hosts, is a genuine second network.
- **HP-3 needs a globally addressable relay.** In `HP3RelayForwardProvisioning_2026-09-28.md`, gap B3 is that the daemon rejects relay candidates on private or CGNAT addresses. A relay on this VM's public address satisfies that check honestly, instead of the proposed 198.18.0.0/15 benchmarking-range workaround, which cannot prove global reachability.

This is lab infrastructure, not the product's runtime or trust path, so ADR-027 (charter `decision-log.md`: no cloud or third-party service in the runtime or trust path) is not engaged. That is recorded here so the question does not come back. Precedent caution: AQ-09 held third-party CI tooling to an explicit owner look even though ADR-027 covers runtime only. The owner gave that look for Azure and for the tailnet on 2026-09-29.

## Access and firewall: decided and done (2026-09-29)

- **Management over the tailnet.** The owner approved the VM on the lab tailnet. The Mac and katana both reach it there, and katana reaches it peer to peer. katana's lab SSH key is authorized for the admin user. Login is key-only.
- **Public SSH closed.** The security-group rule that allowed TCP 22 from one address was deleted, and TCP 22 no longer answers from the internet. The fallback is Azure run-command, usable only while the node is NOT running with the rustynet killswitch applied (see the 2026-09-30 findings: the killswitch drops the wireserver path run-command needs).
- **Dataplane.** A security-group rule allows UDP 51820 (WireGuard), 3478 (STUN), 4500 (relay) and 40000-49999 (relay data) from katana's home public IPv4 only. katana's libvirt guests egress from that same address, and a UDP probe from a katana guest to the VM's WireGuard port was received. If that home address changes, the rule must be re-pointed; that is a cloud firewall change, and it is the owner's.
- **Access cleanup.** A client-side SSH hook that re-pointed the firewall rule at the Mac's current address was tried and removed; it is not needed with tailnet management. Tooling must not edit cloud firewall rules automatically.

## How binaries get there

The VM is too small to compile Rustynet; the lab normally builds on each guest. The orchestrator already covers this with `--source-mode host-cross-binary` (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/host_cross_build.rs`, design `CrossCompileThenCloneDesign_2026-09-04.md`). It cross-builds `rustynetd`, `rustynet-cli` (feature `vm-lab`) and `rustynet-relay` (feature `daemon`) on the orchestrator host with `cargo zigbuild`, under one glibc 2.31 floor for every Linux target (hardcoded today in `orchestrator/native.rs`). A 2.31-capped binary runs on this VM's glibc 2.39 and on katana's 2.41. The Linux bootstrap then installs the shipped binaries and skips the guest build (`RN_PREBUILT_BINARIES=1`, `scripts/bootstrap/linux/rn_bootstrap.sh`). As a first step the owner had the binaries built on the Mac, which needs `cargo-zigbuild` and `zig` there, and shipped by hand. They ran on the VM with no missing libraries.

## Inventory, without publishing addresses

- The VM is a **node**, not a lab host: a controller-less `entries[]` node (legal; `debian-lan-11` is a precedent), driven by `--node <alias>:<role>`. It cannot be its own host, because `LabHostKind` accepts only `local_utm` and `libvirt`.
- Its entry lives in an **untracked overlay file** at the suite root, under `lab-local/` (gitignored). The overlay is merged over the tracked inventory at load time. It sets `ssh_target` to the tailnet address and a new `dataplane_endpoint` field to the public address, so SSH uses the tailnet while peers dial the public IP.
- Both harness changes, the overlay loader and the endpoint field, are being built in fleet lane b52, with review and gates before use. The same change must keep overlay addresses out of committed ledgers and must never write overlay entries back into the tracked inventory.
- **Readiness gate.** Discovery only knows UTM and libvirt guests. A controller-less cloud alias it does not report is marked unready (`not-reported-by-discovery`); without `--trust-inventory-ready` the restart stage then fails loudly (a controller-less alias has no start controller), and with it the restart is skipped and bootstrap/live SSH decides. So the first runs need `--trust-inventory-ready`. The alias must also declare `platform: linux` (or an inferable OS).
- Do not apply the host-onboarding runbook's passwordless-sudo convention to an internet-facing node. The VM's admin user already has passwordless sudo, as Azure provisioned it; with public SSH closed, it is reachable only over the tailnet.

## Plan

1. Land b52 after review and gates.
2. First run: a two-node cross-network run, one katana guest plus the VM, launched on katana with `--source-mode host-cross-binary` and `--trust-inventory-ready`.
3. Then the `cross_network_*` stages, then HP-3 with the relay on the VM once HP-3's other gaps are closed.
4. Record findings in the node ledgers like any other run.

## Risks

- **Credit and quota.** The subscription runs on student credit, and a deallocated VM ends a run badly. Stop the VM between runs only if the owner wants to save credit. A deallocated VM can lose its dynamic public address, which silently breaks the dataplane endpoint in the overlay until it is updated. The tailnet address survives.
- **Exposure.** The public address answers only on the Rustynet UDP ports, and only to katana's address. Lab keys placed on the VM are lab-only material.
- **Terms.** It is a university subscription; use it within its terms. Testing one's own software is the intended use.

## Update 2026-09-30 (state and host changes)

- **VM running again.** `az vm start` succeeded on 2026-09-30 (~12:40Z; the 2026-09-29 `ZonalAllocationFailed` was transient). Tailnet address unchanged (100.109.160.10); reachable from the Mac and from katana with the katana-lab key. The public IP (<public IP, overlay-only>, static, zone 2) is unchanged, so the overlay `dataplane_endpoint` stays valid.
- **Tailscale netfilter off (owner decision, 2026-09-30).** The VM's `ts-input` chain dropped `100.64.0.0/10` arriving on any non-`tailscale0` interface, which is exactly the Rustynet mesh range. Applied `tailscale set --netfilter-mode=off` on the VM (reversible with `--netfilter-mode=on`); the `ts-input`/`ts-forward` chains are gone and management SSH is unaffected. The VM's only inbound exposure remains the NSG (UDP from katana, no public SSH).
- **Binaries.** katana's glibc (2.41) is newer than the VM's (2.39), so a katana-native build may not load on the VM. Owner chose (2026-09-30) to cross-build on the Mac (zig + zigbuild present) rather than install zig on katana, so the first run waits for Mac AC power (owner battery rule).
- **Landed since the record was written:** the overlay loader and `dataplane_endpoint` (b52r1, commit 900f82d59).

## Findings from the first live runs (2026-09-30, katana-u28..u30)

1. **Orchestrator gates, now fixed in the harness.** The readiness gate aborted on a controller-less alias (above). The cross-bridge preflight hard-failed because it probes guest-to-guest TCP/22 across derived /24s and a cloud node is by definition not on the management L2; nodes declaring `dataplane_endpoint` are now excluded from that probe (with a Pass-with-note only when `mesh_status_validation` and `traffic_test_matrix` are planned). `--ssh-allow-cidrs` is now mandatory when a dataplane-endpoint node is selected, because the auto-derived /24 of a tailnet address (100.109.160.0/24) excludes the orchestrator's tailnet address and would strand SSH once the killswitch is applied.
2. **Product bug found: off-link endpoint bypass routes had no next hop.** `rustynetd` installed peer-endpoint and management bypass routes in table 51820 as `dev <iface>` on-link (it ran `ip route get` but discarded `via <gw>`), so every off-link endpoint black-holed (ARP on the local bridge: neighbour FAILED). Invisible in earlier same-subnet labs. Fixed in `phase10.rs` (next hop parsed, installed, and verified; helper allowlist extended strictly).
3. **The killswitch drops tailscaled's outer transport for new flows** (boot table `rustynet_boot`: only UDP 51820, ssh-CIDR tcp/22 and STUN pinholes leave the NIC). The orchestrator's own SSH survives because the katana-to-VM direct path is katana-initiated and Azure only sends replies on tracked flows; anything needing an Azure-initiated new flow (DERP, the Mac, waagent, IMDS) dies until cleanup. Consequences: **Azure run-command is NOT a fallback while the node is killswitched** (it needs the wireserver, which is dropped too); a reboot reinstalls the boot killswitch. Harness safety net added: a direct-path precondition before enforce, a node-side dead-man timer (`rn-deadman-cleanup`, disarmed at teardown), and scrubbed node diagnostics captured post-enforce and at failure time.
4. **Still unproven:** the WireGuard handshake between a NAT'd katana guest (client) and the cloud exit, and Azure's peer endpoint for the client (the orchestrator seeds the client's private host candidate; WireGuard roaming should correct it once the client's authenticated handshake arrives; `--lab-stun-servers` or a reflexive candidate is the fallback).
5. **Public address hygiene.** The VM's public address lives only in the untracked overlay (`lab-local/`); it must not appear in tracked files, ledgers or committed report artifacts (this record briefly carried it and was redacted; before any push, decide whether the history commit that introduced it needs rewriting).
