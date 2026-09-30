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
- **Public SSH closed.** The security-group rule that allowed TCP 22 from one address was deleted, and TCP 22 no longer answers from the internet. The fallback is Azure run-command.
- **Dataplane.** A security-group rule allows UDP 51820 (WireGuard), 3478 (STUN), 4500 (relay) and 40000-49999 (relay data) from katana's home public IPv4 only. katana's libvirt guests egress from that same address, and a UDP probe from a katana guest to the VM's WireGuard port was received. If that home address changes, the rule must be re-pointed; that is a cloud firewall change, and it is the owner's.
- **Access cleanup.** A client-side SSH hook that re-pointed the firewall rule at the Mac's current address was tried and removed; it is not needed with tailnet management. Tooling must not edit cloud firewall rules automatically.

## How binaries get there

The VM is too small to compile Rustynet; the lab normally builds on each guest. The orchestrator already covers this with `--source-mode host-cross-binary` (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/host_cross_build.rs`, design `CrossCompileThenCloneDesign_2026-09-04.md`). It cross-builds `rustynetd`, `rustynet-cli` (feature `vm-lab`) and `rustynet-relay` (feature `daemon`) on the orchestrator host with `cargo zigbuild`, under one glibc 2.31 floor for every Linux target (hardcoded today in `orchestrator/native.rs`). A 2.31-capped binary runs on this VM's glibc 2.39 and on katana's 2.41. The Linux bootstrap then installs the shipped binaries and skips the guest build (`RN_PREBUILT_BINARIES=1`, `scripts/bootstrap/linux/rn_bootstrap.sh`). As a first step the owner had the binaries built on the Mac, which needs `cargo-zigbuild` and `zig` there, and shipped by hand. They ran on the VM with no missing libraries.

## Inventory, without publishing addresses

- The VM is a **node**, not a lab host: a controller-less `entries[]` node (legal; `debian-lan-11` is a precedent), driven by `--node <alias>:<role>`. It cannot be its own host, because `LabHostKind` accepts only `local_utm` and `libvirt`.
- Its entry lives in an **untracked overlay file** at the suite root, under `lab-local/` (gitignored). The overlay is merged over the tracked inventory at load time. It sets `ssh_target` to the tailnet address and a new `dataplane_endpoint` field to the public address, so SSH uses the tailnet while peers dial the public IP.
- Both harness changes, the overlay loader and the endpoint field, are being built in fleet lane b52, with review and gates before use. The same change must keep overlay addresses out of committed ledgers and must never write overlay entries back into the tracked inventory.
- **Readiness gate.** Discovery only knows UTM and libvirt guests, and the pre-run readiness gate fails closed on any alias it cannot match. So the first runs need `--trust-inventory-ready`, or new discovery code for cloud nodes.
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

- **VM running again.** `az vm start` succeeded on 2026-09-30 (~12:40Z; the 2026-09-29 `ZonalAllocationFailed` was transient). Tailnet address unchanged (100.109.160.10); reachable from the Mac and from katana with the katana-lab key. The public IP (68.221.26.30, static, zone 2) is unchanged, so the overlay `dataplane_endpoint` stays valid.
- **Tailscale netfilter off (owner decision, 2026-09-30).** The VM's `ts-input` chain dropped `100.64.0.0/10` arriving on any non-`tailscale0` interface, which is exactly the Rustynet mesh range. Applied `tailscale set --netfilter-mode=off` on the VM (reversible with `--netfilter-mode=on`); the `ts-input`/`ts-forward` chains are gone and management SSH is unaffected. The VM's only inbound exposure remains the NSG (UDP from katana, no public SSH).
- **Binaries.** katana's glibc (2.41) is newer than the VM's (2.39), so a katana-native build may not load on the VM. Owner chose (2026-09-30) to cross-build on the Mac (zig + zigbuild present) rather than install zig on katana, so the first run waits for Mac AC power (owner battery rule).
- **Landed since the record was written:** the overlay loader and `dataplane_endpoint` (b52r1, commit 900f82d59).
