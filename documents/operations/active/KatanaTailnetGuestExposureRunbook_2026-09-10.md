# Katana Tailnet Guest Exposure Runbook (2026-09-10)

**Status:** TODO / DEFERRED (owner, 2026-09-10: "mark katana as todo and come back to it another time") — nothing in §1–§5 has been applied; katana keeps running host-launched 2-node runs meanwhile. Owner-executed host change (every `sudo` line is the owner's; the manager runs the verify lines). Written 2026-09-10 for the D4 decision ("cross-network on lenovo-bot/katana = restart", `ManagerHandover_2026-09-08.md` §D4) and for the two-LAN cross-network live proof the QH-83 CrossNetwork / Chaos / NegativeControl rows still owe (`QualityHardeningTodo_2026-07-25.md` QH-83).

**What this is for.** katana's two guests (`katana-client-1` 192.168.122.45, `katana-exit-1` 192.168.122.222) sit on libvirt's NAT network `virbr0` (192.168.122.0/24). Today they are reachable only from katana itself, which is why every katana run is launched ON the host (`launch_live_lab_on_host`). For a lenovo-bot ↔ katana cross-network run the guests must be reachable across LANs. The tailnet already joins the three hosts (Mac, lenovo-bot, katana `100.122.143.29`); this runbook makes katana a **Tailscale subnet router** for 192.168.122.0/24 and opens libvirt's forwarding chain so tailnet traffic reaches the guests.

**Not this runbook.** No Mac host-networking change (CP-1 stays closed), no change to katana's Wi-Fi uplink, no bridging over Wi-Fi (impossible on most Wi-Fi drivers — that is why the guests are NAT'd in the first place).

**Facts this rests on** (inventory `vm_lab_inventory.json` host `katana`; verified 2026-09-09 while the box was up): Debian 13, Wi-Fi-only uplink `wlo1` 192.168.18.44/24, libvirt `default` network NAT on `virbr0` 192.168.122.0/24, tailnet name `debian`, tailnet IP 100.122.143.29, user `debian` with NOPASSWD sudo. **Not re-verified today:** katana did not answer SSH on either address at the time of writing (present in ARP at 192.168.18.44, so asleep or Wi-Fi power-save — see §0), and the Mac's Tailscale client was stopped.

---

## 0) Preconditions (both sides)

1. **katana awake.** From the Mac on the 192.168.18.0/24 LAN:
   ```sh
   nc -z -G3 192.168.18.44 22 && echo ssh-open
   ```
   If ARP knows the MAC (`arp -a | grep 192.168.18.44`) but TCP/22 times out, the laptop is asleep. Owner: open the lid / disable sleep on lid close and on AC:
   ```sh
   sudo sed -i 's/^#\?HandleLidSwitch=.*/HandleLidSwitch=ignore/; s/^#\?HandleLidSwitchExternalPower=.*/HandleLidSwitchExternalPower=ignore/' /etc/systemd/logind.conf
   sudo systemctl restart systemd-logind
   sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
   ```
   Verify: `systemctl status sleep.target | grep -q masked && echo sleep-masked`.
   Wi-Fi power save can also drop the link on an idle laptop: `sudo iw dev wlo1 set power_save off` (runtime) and, to persist, a NetworkManager connection setting `sudo nmcli connection modify "<ssid>" 802-11-wireless.powersave 2`. Verify: `iw dev wlo1 get power_save` prints `off`.
2. **Mac Tailscale running** (the lab-state MCP and `sync_host` use the LAN address first and fall back to `alt_ssh_endpoints` = the tailnet):
   ```sh
   /Applications/Tailscale.app/Contents/MacOS/Tailscale up
   /Applications/Tailscale.app/Contents/MacOS/Tailscale status --self | head -1
   ```
3. **lenovo-bot on the tailnet** (`ssh ubuntu@192.168.0.29 'tailscale ip -4'` prints a 100.x address). It was, as of 2026-09-09.

---

## 1) katana: advertise the guest subnet (owner, sudo)

```sh
# 1.1 forwarding — libvirt normally already sets this; make it explicit and persistent
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/99-rustynet-lab.conf
# 1.2 advertise the libvirt NAT subnet as a tailnet route
sudo tailscale up --advertise-routes=192.168.122.0/24 --accept-routes
```
`--accept-routes` is included so katana (and therefore its guests, via katana's default route) can reach a subnet lenovo-bot advertises in §4. `tailscale up` prints "Some peers are advertising routes but --accept-routes is false" only if you omit it; if it prints a re-auth URL, open it as the tailnet admin. **If `tailscale up` complains about changing flags**, re-run with the full current flag set it prints.

Verify on katana:
```sh
tailscale debug prefs | grep -E 'AdvertiseRoutes|RouteAll'   # AdvertiseRoutes contains 192.168.122.0/24, RouteAll true
```

## 2) Tailnet admin: approve the route (owner, browser)

Tailscale does not activate an advertised subnet until an admin approves it: **admin console → Machines → `debian` → Edit route settings → enable 192.168.122.0/24**. (If the tailnet uses autoApprovers in the ACL policy instead, add `"autoApprovers": {"routes": {"192.168.122.0/24": ["<owner login>"]}}`.)

Verify from the Mac:
```sh
/Applications/Tailscale.app/Contents/MacOS/Tailscale status | grep debian     # route not shown as "offers" any more
netstat -rn | grep '^192.168.122'                                            # a route via utun* (the Tailscale interface)
```
The macOS client accepts subnet routes by default ("Use Tailscale subnets" in the menu — confirm it is ticked). lenovo-bot is Linux and does NOT accept routes by default:
```sh
ssh ubuntu@192.168.0.29 'sudo tailscale set --accept-routes && ip route | grep 192.168.122'
```

## 3) katana: let tailnet traffic through libvirt's forwarding chain (owner, sudo)

libvirt's NAT network installs FORWARD rules that accept traffic **from** `virbr0` and only RELATED/ESTABLISHED traffic **to** it; a new SSH connection arriving from `tailscale0` destined to 192.168.122.x is otherwise REJECTED. Add the two accepts in front of libvirt's rules:

```sh
sudo iptables -I FORWARD 1 -i tailscale0 -o virbr0 -d 192.168.122.0/24 -j ACCEPT
sudo iptables -I FORWARD 1 -i virbr0 -o tailscale0 -s 192.168.122.0/24 -j ACCEPT
```
(Debian 13 uses iptables-nft; `iptables` here writes into the same nft tables libvirt uses. If `iptables` is missing: `sudo apt-get install -y iptables`.)

Make them survive a libvirt network restart (libvirt re-inserts its own rules and would otherwise leave yours below the REJECT) with the libvirt network hook:
```sh
sudo install -d /etc/libvirt/hooks
sudo tee /etc/libvirt/hooks/network >/dev/null <<'H'
#!/bin/sh
# Rustynet lab: keep tailnet -> virbr0 forwarding open (KatanaTailnetGuestExposureRunbook_2026-09-10.md §3)
[ "$1" = "default" ] || exit 0
case "$2" in
  started|updated)
    iptables -C FORWARD -i tailscale0 -o virbr0 -d 192.168.122.0/24 -j ACCEPT 2>/dev/null || \
      iptables -I FORWARD 1 -i tailscale0 -o virbr0 -d 192.168.122.0/24 -j ACCEPT
    iptables -C FORWARD -i virbr0 -o tailscale0 -s 192.168.122.0/24 -j ACCEPT 2>/dev/null || \
      iptables -I FORWARD 1 -i virbr0 -o tailscale0 -s 192.168.122.0/24 -j ACCEPT
    ;;
esac
exit 0
H
sudo chmod 755 /etc/libvirt/hooks/network
sudo systemctl restart libvirtd     # the hook only fires on network start; the running guests keep their tap devices
```
Verify on katana:
```sh
sudo iptables -S FORWARD | head -3        # the two ACCEPT lines come first
sudo virsh net-list                       # default still active
```

## 4) Reachability proof (manager runs; nothing to install)

From the Mac (Tailscale up, route approved):
```sh
nc -z -G5 192.168.122.45 22 && nc -z -G5 192.168.122.222 22 && echo guests-reachable-over-tailnet
ssh -i ~/.ssh/rustynet_lab_ed25519 debian@192.168.122.45 'hostname; ip -4 -br addr show eth0'
```
From lenovo-bot (after §2's `--accept-routes`):
```sh
ssh ubuntu@192.168.0.29 'nc -z -w5 192.168.122.45 22 && echo lenovo-reaches-katana-guest'
```
Then the MCP: `check_vm_reachable` on `katana-client-1` / `katana-exit-1` must read `reachable: true`, and `validate_inventory` must stop reporting the katana pair as host-only. **Nothing in the inventory changes** — the guests keep their 192.168.122.x addresses; only the path to them changed.

## 5) For the two-LAN cross-network run: the reverse direction

§1–§4 expose katana's guests to the tailnet. The vxlan substrate and the traversal scenarios also need katana's guests to reach **lenovo's** guests (192.168.0.30/.31, bridged on lenovo's LAN) and lenovo's guests to reply. Two more owner steps:

1. **lenovo-bot advertises its LAN** (or just the two guests as /32s):
   ```sh
   ssh ubuntu@192.168.0.29 'sudo sysctl -w net.ipv4.ip_forward=1 && sudo tailscale up --advertise-routes=192.168.0.30/32,192.168.0.31/32 --accept-routes'
   ```
   approve in the admin console as in §2. lenovo-bot's guests are bridged, so **they** need a route back to the tailnet through lenovo-bot (their default route is the LAN router, which knows nothing about 100.64.0.0/10 or 192.168.122.0/24):
   ```sh
   ssh debian@192.168.0.30 'sudo ip route add 192.168.122.0/24 via 192.168.0.29 && sudo ip route add 100.64.0.0/10 via 192.168.0.29'
   ssh debian@192.168.0.31 'sudo ip route add 192.168.122.0/24 via 192.168.0.29 && sudo ip route add 100.64.0.0/10 via 192.168.0.29'
   ```
   Persist them the way the TwoLanFleetSetupRunbook §1 persists guest routes (a `/etc/network/interfaces.d/` `post-up` line or a systemd-networkd `[Route]`). katana's guests need nothing: their default route is katana, which now accepts lenovo's routes.
2. **Know what the NAT looks like.** Tailscale subnet routers source-NAT forwarded traffic by default (`--snat-subnet-routes=true`), so a packet from katana-client-1 arrives at a lenovo guest with source 100.122.143.29, and the reply follows the guest's new 100.64.0.0/10 route back through lenovo-bot. That is a symmetric-NAT-shaped path — exactly the kind the cross-network NAT classification and traversal scenarios are designed to measure, so expect `cross_network_nat_classification` to report it rather than "open". If a scenario needs the raw addresses, `--snat-subnet-routes=false` on katana plus a `192.168.122.0/24 via <lenovo-bot tailnet IP>`-style route is the alternative; decide that per scenario, not up front.

Verify (manager): `ssh debian@192.168.0.30 'ping -c2 192.168.122.45'` and the reverse, then the CN-3 proof invocation in `TwoLanFleetSetupRunbook_2026-08-28.md` §Phase 3 with `--node katana-client-1:client --node katana-exit-1:exit --node lenovo-client-1:entry --node lenovo-exit-1:aux` (plus an admin node) and `--cross-network-substrate vxlan`. Take every verdict from the stage's own report artifact, never the CSV column.

## 6) Rollback

```sh
# katana
sudo tailscale up --advertise-routes= --accept-routes=false          # (re-supply any other flags it prints)
sudo iptables -D FORWARD -i tailscale0 -o virbr0 -d 192.168.122.0/24 -j ACCEPT
sudo iptables -D FORWARD -i virbr0 -o tailscale0 -s 192.168.122.0/24 -j ACCEPT
sudo rm /etc/libvirt/hooks/network && sudo systemctl restart libvirtd
# lenovo-bot / guests: tailscale up without --advertise-routes; ip route del the two routes on each guest
```
Disable the routes in the admin console as well; an approved-but-unadvertised route is harmless but confusing.

## 7) Security note

Advertising 192.168.122.0/24 exposes the two lab guests to every tailnet member. The tailnet is the owner's private one and the guests hold lab keys only (the lab password rotation owed in `lab_password_committed_in_source` still stands). Do not widen the route beyond the /24, and do not advertise katana's Wi-Fi LAN (192.168.18.0/24) — the Mac is on it and that would route the Mac's LAN traffic through a laptop.
