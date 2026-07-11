# VM-Lab Network Standard & Onboarding

The one standard for how lab VMs get on the network, get a stable unique
address, and reach the internet — and how to onboard a new VM in a couple of
minutes without hand-fixing each machine. This operationalizes
[LiveLabVmConnectivityRulebook.md](./LiveLabVmConnectivityRulebook.md) (policy)
and [ADR-004](./adr/ADR-004-dual-plane-live-lab-network.md) (the locked
decision) for the single-Mac UTM lab.

## The standard (what every VM uses)

| Concern | Standard | Why |
| --- | --- | --- |
| Attachment | **UTM Shared** (vmnet-shared) | One internal subnet on the Mac, independent of whatever Wi-Fi/LAN/hotspot the Mac is on — not bridged to your everyday `en0` (rulebook §5 rejects that default; it was the source of the churn). |
| Address | **vmnet's per-MAC DHCP** — no in-guest config | vmnet's DHCP hands each MAC the **same address on every boot** (verified: each VM kept its exact IP across repeated reboots). That is the rulebook §15.3 "address bound to the preserved NIC MAC", delivered with zero per-guest work — the stable IP is a property of the MAC, and the MAC is stable. |
| Internet | **Host NAT** (automatic with Shared) | Internet follows the Mac's uplink; the VMs' identity and inter-VM LAN do not. Change Wi-Fi → the lab keeps working; only internet reachability follows the host. |
| Host route | **Self-healing connected route** to the vmnet bridge (launchd) | Fixes the intermittent host→guest loss — the real cause of "loses connection, fix it differently each time" (see Gotcha 1). This is the load-bearing permanent fix. |

Two vmnet subnets exist because the macOS guest uses Apple's virtualization
backend on its own bridge:

- `192.168.64.0/24` — QEMU-backend guests (Linux/Windows), host/gateway `.1`.
- `192.168.65.0/24` — Apple-backend macOS guest, host/gateway `.1`.

Reachable through the host, but not the same broadcast domain. For the
Linux/Windows mesh this is one clean LAN; the macOS guest joins over the host
route. (True single-L2 across QEMU+Apple needs the dedicated-hardware profile —
rulebook Tier 3.)

### Current stable addresses (vmnet-assigned, per-MAC)

| VM | Subnet | Address |
| --- | --- | --- |
| debian-headless-2 | 64 | 192.168.64.4 |
| debian-headless-4 | 64 | 192.168.64.10 |
| windows-utm-1 | 64 | 192.168.64.14 |
| fedora-utm-1 | 64 | 192.168.64.20 |
| rocky-utm-1 | 64 | 192.168.64.22 |
| macos-utm-1 | 65 | 192.168.65.2 |

The inventory (`vm_lab_inventory.json`) is the source of truth; refresh it with
`rustynet ops vm-lab-discover-local-utm-summary --update-inventory-live-ips`
(never hand-edit live IPs). The orchestrator resolves each node's live IP by
MAC at run time, so tooling never breaks even if an address ever moves.

## One-time host setup (operator, needs sudo)

The only privileged step, and the one that makes the lab actually stable:
**install the self-healing route keeper** so host→guest never silently breaks.

```sh
sudo mkdir -p /usr/local/lib/rustynet
sudo install -m 0755 scripts/vm_lab/ensure_vmnet_route.sh \
    /usr/local/lib/rustynet/ensure_vmnet_route.sh
sudo install -m 0644 scripts/launchd/com.rustynet.vmnet-route.plist \
    /Library/LaunchDaemons/com.rustynet.vmnet-route.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.rustynet.vmnet-route.plist
```

To fix it once, right now, without the daemon:
`sudo route -n add -net 192.168.64.0/24 -interface bridge100`
(`scripts/vm_lab/ensure_vmnet_route.sh --dry-run` reports the state without
changing anything, and discovers the `.65` bridge too when the macOS VM runs).

## Onboarding a new VM (the easy path)

1. **Create the VM in UTM** with **Shared** networking. Leave the guest on
   **DHCP** (the default). Do not touch the guest's network config.
2. **Boot it.** vmnet hands it a stable per-MAC address on `192.168.64.0/24`
   (or `.65` for an Apple-backend macOS guest).
3. **Add it to the inventory** with its `controller` bundle path, `alias`,
   `ssh_user`, and role; then
   `rustynet ops vm-lab-discover-local-utm-summary --update-inventory-live-ips`
   records its address.
4. Done — stable, unique, on the LAN, internet via host NAT. No in-guest
   network config, no per-OS steps.

Verify the whole fleet any time (read-only, mutates nothing):
`rustynet ops vm-lab-network-audit` — flags duplicate MAC/IP, drift, and stale
labels.

## Gotchas (why the lab used to "lose connection")

**Gotcha 1 — host loses the vmnet route (the big one).** After Shared
migrations or power-cycles, the connected route `192.168.64.0/24 → bridge100`
can drop, so `route get 192.168.64.x` falls through to the corporate default
(`en0`) and host→guest silently breaks (working only briefly via a transient
ARP-cloned /32). The route keeper above prevents this permanently.

**Gotcha 2 — raw TCP reachability probes false-negative on macOS.** A raw TCP
`connect()` from a tool process to a LAN IP is silently blocked by macOS Local
Network Privacy (CLAUDE.md §12.3.1); the `ssh` binary works. All lab
reachability checks shell out to `ssh` — never trust a bare TCP/`nc`
"connection refused/timeout".

**Gotcha 3 — plist edits vs a running UTM.** UTM holds the VM config in memory;
a raw `config.plist` edit while UTM runs can leave the file out of step with the
running attachment (rulebook §14). `rustynet ops vm-lab-network-prepare` is the
sanctioned attachment-change path.

## Dead ends (verified 2026-07-11 — do not re-attempt)

- **`/etc/bootptab` DHCP reservations are ignored by UTM's vmnet.** `bootpd`
  runs, but vmnet's shared-mode DHCP does not honor `/etc/bootptab`; a rebooted
  guest keeps its vmnet-assigned address, not the reserved one. (This is fine —
  vmnet's own per-MAC assignment is already stable; see the standard above.)
- **Forcing an in-guest static IP is fragile and not worth it.** On the Debian
  guests `dhcpcd` re-DHCPs the interface on every boot regardless of
  `/etc/network/interfaces` or `/etc/dhcpcd.conf` static blocks, so a static IP
  did not persist across reboots; other guests use different stacks
  (systemd-networkd / NetworkManager / netsh / networksetup). Per-guest static
  is exactly the "fix each VM differently" churn to avoid. Rely on vmnet's
  stable per-MAC DHCP instead. (If one specific VM ever needs a
  guaranteed-unchanging address, pin it in that guest's own network stack — but
  that is a per-VM exception, not the standard.)

## Where this sits vs the full rulebook

This is the rulebook's **management/Shared plane used as the stable working
LAN** — the right, plan-consistent standard for a single Mac and the everyday
"stable unique devices simulating a LAN with internet" goal. The stricter
dual-plane `isolated_multivm_v1` (a dedicated scenario NIC on a fully isolated
fabric) and the physical/remote tiers remain later upgrades, gated on the
rulebook §15.9 owner decisions and hardware — see the
[implementation ledger](./active/LiveLabVmConnectivityImplementation_2026-07-10.md).
