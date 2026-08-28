# Two-LAN Fleet Setup Runbook — 2026-08-28

**Status: turnkey operator runbook (doc-only; no code change).**
**Purpose:** convert the lab from a single-routable-LAN fleet into a genuinely two-LAN fleet so the cross-network validators (CN-3 `cross_network_substrate_setup` with the vxlan substrate, and the NAT-matrix scenarios that follow it) can be exercised for real instead of skipping.

This runbook exists because of the CN-PROOF run `livelab-1787908428-6d9224cfd954` (2026-08-28, recorded in `LiveValidation_2026-08-28.md` §12): with the `--cross-network-substrate vxlan` flag on the five-guest UTM topology, the substrate provisioned nothing and every scenario skipped, for three independently verified reasons. §0.6 of `CrossNetworkSubstrateIntegrationSpec_2026-06-21.md` put the fix decision to the owner; the owner approved **option (a): make the lab a genuinely 2-LAN fleet**. This document is the execution path for that decision.

Read this document top to bottom before touching anything. Phase 0 is a cheap, ~15-minute, fully reversible probe that decides between the cheap path and the expensive path — do it before committing to either.

---

## 1) Target state — exactly what CN-3 needs

### 1.1 The three gates, in code

A CN-3 vxlan proof run needs all three of the following to hold at once. Each was verified in the CN-PROOF triage; the file:line refs are the enforcement points.

| # | Gate | Enforcement point | What it requires |
| --- | --- | --- | --- |
| G1 | Two underlay /24 groups | `crates/rustynetd/src/.../stage/cross_network/substrate.rs:754-756` — `plan_overlay` returns `Ok(None)` below two underlay /24 groups; `substrate.rs:1529-1532` — `VxlanSubstrateProvider::setup` then short-circuits to an empty handle with `provisioned: false` | At least two participating guests whose management addresses sit in **different /24s**. With one group, `cross_network_substrate_setup` "passes" as an honest no-op and no `rustynet-vx0` device is ever created. |
| G2 | `entry` and `aux` roles present | `cross_network.rs:929-932` — `CrossNetworkTopology::resolve` fills the relay participant from `["entry","aux"]` and the probe participant from `["aux","entry"]`, never from the `relay` role | The `--node` list must contain at least one node tagged `entry` and one tagged `aux`, in addition to `client`/`exit`. Without them the scenarios fail with `TopologyError::MissingRole` and the run records skip reason `cross-network topology requires a role that no node in this topology is assigned`. |
| G3 | client and exit on distinct /24s, judged on the **management** plane | `cross_network.rs:514-520` — the distinct check in `prepare_scenario_stage`; `cross_network.rs:944-949` and `:1085-1105` — `distinct_underlay_prefixes` reads each role's address from `ssh_params_for_role` ← `adapter.ssh_connection_params()`, i.e. the address the orchestrator SSHes to | The SSH-management address of the `client` node and of the `exit` node must be in different /24s. This is about which address the orchestrator reaches the node on, not about the tunnel addresses. |

Consequence worth stating plainly: **G1 and G3 are satisfied by the same condition** — a fleet in which the participating guests' management addresses span two distinct /24s. One physical change serves both gates.

### 1.2 What "routable between them" means

The vxlan overlay carries guest-to-guest frames over the underlay. For the overlay to come up, the two /24s must be able to reach each other in **both directions** at IP level, from the guests themselves:

- 192.168.64.0/24 → 192.168.0.0/24: **already works today** (measured in the CN-PROOF probes: UTM guest → lenovo-client-1 ping 0% loss, TCP/22 open; UTM's Shared network NATs out through the Mac host).
- 192.168.0.0/24 → 192.168.64.0/24: **broken today** (measured: lenovo-client-1 → 192.168.64.10 ping 100% loss, TCP refused). The 192.168.64.0/24 exists behind the Mac host's UTM shared-network interface; nothing on the real LAN has a route to it.

Reverse path is the whole gap. It must work bidirectionally before any CN-3 run is attempted — a one-directional reachability will produce a scenario that half-comes-up and then fails in a confusing way rather than a clean gate.

### 1.3 Target fleet shape

The participants for the proof run — all Linux (Phase 10 dataplane constraint: macOS/Windows guests are out of scope for the cross-network scenarios):

| Node | Role | Management LAN after this runbook |
| --- | --- | --- |
| `ubuntu-utm-1` | `client` | 192.168.64.0/24 (UTM Shared, unchanged) |
| `debian-headless-4` | `aux` | 192.168.64.0/24 (UTM Shared, unchanged) |
| `lenovo-client-1` | `exit` | 192.168.0.0/24 (real LAN, already there) |
| `lenovo-exit-1` | `entry` | 192.168.0.0/24 (real LAN, already there) |
| `rocky-utm-1` | `admin` | 192.168.64.0/24 (non-participant; unchanged) |

This assignment satisfies G1 (two /24 groups present), G2 (`entry` = `lenovo-exit-1`, `aux` = `debian-headless-4`), and G3 (client SSH addr 192.168.64.x vs exit SSH addr 192.168.0.30 — distinct) **with zero UTM network reconfiguration**. The only physical change required is the reverse-path route (§4, Phase 1).

### 1.4 What is explicitly NOT required

- No macOS or Windows guest participates. Do not move `macos-utm-1` or `windows-utm-1` for this work.
- No change to the UTM Shared networking of the guests that stay on 192.168.64.x.
- No second router purchase and no VLAN work **unless the cheap path fails its Phase 0 probe** (§4).
- No inventory hand-editing, ever. IP refreshes go through `ops vm-lab-discover-local-utm-summary --update-inventory-live-ips` only.

---

## 2) Current state and the gap

### 2.1 Where every node sits today

From `documents/operations/active/vm_lab_inventory.json` plus the QH-41 verified host measurements (`QualityHardeningTodo_2026-07-25.md`, QH-41, corrected 2026-08-12):

| Node(s) | Backend | Segment | Notes |
| --- | --- | --- | --- |
| `debian-headless-2`, `debian-headless-4`, `ubuntu-utm-1`, `rocky-utm-1`, `fedora-utm-1`, `windows-utm-1` | UTM, QEMU, `Mode="Shared"` | 192.168.64.0/24 (host `bridge100`, members `vmenet0`+`vmenet1`) | The default lab LAN. |
| `macos-utm-1` | UTM, **Apple**, `Mode="Shared"` | 192.168.65.0/24 (host `bridge101`, member `vmenet2`, PRIVATE) | QH-41: "Shared" names **two different L2 segments** depending on backend. This split is a backend property; no mode change or boot order merges the bridges. This island is why every mixed-OS traffic matrix fails, and it is NOT this runbook's problem. |
| `lenovo-client-1`, `lenovo-exit-1` | libvirt on `lenovo-bot` (192.168.0.29), bridged via `br0` | 192.168.0.0/24 (the real LAN) | `lenovo-client-1` = 192.168.0.30. |
| `debian-lan-11` | — | 192.168.0.0/24 | Real LAN. |
| `linux-x86-client-1`, `linux-x86-exit-1`, `windows-x86-1`, `fedora-x86-1` | libvirt on `ubuntu-kvm-1` | 192.168.121.0/24 | Unreachable from both the UTM island and the real LAN (CN-PROOF probes: 100% loss from both sides). Out of scope. |

### 2.2 Why CN-3 skipped on this fleet (the gap, precisely)

1. **Single routable /24.** Every UTM Linux guest's management address is 192.168.64.x → one underlay group → G1 fails → substrate no-ops.
2. **No `entry`/`aux` in the CN-PROOF topology.** The run assigned `ubuntu-utm-1:client, rocky-utm-1:admin, debian-headless-4:exit, fedora-utm-1:relay, debian-headless-2:anchor` → G2 fails → scenarios skip on `MissingRole`.
3. **One-directional reachability.** Even with a second /24 (the lenovo pair), the reverse path real-LAN → 192.168.64.x is 100% loss. A substrate that half-works is worse than one that refuses cleanly.

The CN-PROOF run's own numbers, for the record (§12 of `LiveValidation_2026-08-28.md`): commit `6d9224cfd954`, one-flag delta `--cross-network-substrate vxlan` over the standard five-node run; result 43 pass / 1 fail / 17 skip, `first_failed_stage=cross_network_nat_matrix` (the CN-PROOF-D1 ordering defect — the gate ran while its feeding suites were skipped — is already fixed on `work/cnproof-d1-gate` via the shared `resolve_dispatchable_topology`; that fix is separate from this runbook). CN-PROOF-D2 stands: the vxlan flag on the *current* fleet is strictly worse than the default (it loses the netns `nat_classification` data and adds nothing). This runbook is what makes the flag worth passing.

---

## 3) Options considered, with trades

Three ways to get two mutually routable /24s. The owner approved (a); (b) and (c) are recorded as fallbacks, not as parallel work.

### Option (a) — use the two LANs that already exist (RECOMMENDED)

The fleet already spans two /24s: 192.168.64.0/24 (UTM Shared) and 192.168.0.0/24 (real LAN, via the lenovo pair). Forward reachability 64→0 is already proven. The only missing piece is the reverse route. **No UTM reconfiguration of any kind is needed** — which also means the management-SSH-plane risk that dominates the other options mostly does not apply.

Two variants:

- **(a-minimal) Route via the Mac host.** Add `192.168.64.0/24` routes on the lenovo guests pointing at the Mac's real-LAN address, enable IP forwarding on the Mac, and allow the forwarded traffic in PF. One hop. Cheapest; the single unknown is whether macOS forwards into the vmnet interface cleanly (Phase 0 answers this in ~15 minutes, fully reversible).
- **(a-bridge) Bridge two UTM Linux guests onto the real LAN** so the second /24 needs no host routing. Rejected as the default because it is the high-risk variant: a UTM Shared→Bridged per-VM change moves those guests off 192.168.64.x onto real-router DHCP, which shifts the orchestrator's SSH plane, the inventory `live_ips`, `known_hosts` pins, and the `network_group` labels all at once. QH-41 adds a trap: UTM "Bridged" on the QEMU backend attaches a tap to a chosen host interface, and bridging over Wi-Fi (`en0`) is unreliable — the repo's own ops path already refuses `en0` as a bridge target by policy (`LiveLabVmConnectivityRulebook` §11.3; the `apply_vm_bridged_network` mutation tool is DEPRECATED). Keep this variant only as a last resort, and only over a wired interface, and only one guest at a time with SSH verified after each (§6.2).

Warning, stated as its own sentence because it is the mistake this option invites: **do not bridge ALL participants onto the real LAN** — that collapses the fleet back to one /24 and re-fails G1 and G3. The two groups must remain distinct /24s.

### Option (b) — a second router segment on the lenovo-bot side

`lenovo-bot` already bridges libvirt guests onto the real LAN via `br0`; give it a second segment: a USB-Ethernet NIC (or a travel router) serving its own /24 (say 192.168.65.0/24, or any range the real LAN does not use) with two libvirt guests on it, and let `lenovo-bot` route/NAT between the two segments. Then the CN participants would be the lenovo-bot pair (one per segment) plus `ubuntu-utm-1` — but note the UTM side still reaches the real LAN only one-directionally unless the Mac route is ALSO fixed, so this option alone does not close the reverse path for a UTM-hosted participant. Clean variant: keep ALL CN participants on the lenovo-bot side (two per segment), leaving UTM out of the CN scenarios entirely.

- Trades: buys deterministic, fully Linux-controlled routing; costs a hardware trip, new guests (provisioning + toolchain + bootstrap time), and inventory additions. Use it only if Phase 0 proves the Mac cannot forward into vmnet AND all-CN-on-lenovo is acceptable.

### Option (c) — VLAN the existing switch

Requires a managed switch and a router that does inter-VLAN routing: define VLAN 2 (say 192.168.65.0/24), trunk or access-port the Mac onto both, put the lenovo pair (or newly bridged UTM guests) on VLAN 2, let the router route between VLANs.

- Trades: cleanest long-term topology and no host-forwarding dependency; costs switch/router admin work and the same UTM-bridging management-plane risk as (a-bridge) for any guest moved. Only worth it if the owner wants the 2-LAN lab to become the permanent shape.

### Decision

**(a-minimal), contingent on the Phase 0 probe.** If the probe fails, fall back to (b) with all CN participants on the lenovo-bot side. (a-bridge) and (c) are recorded for completeness.

---

## 4) Execution — option (a-minimal), step by step

Every step has a **Verify** command and an **If it fails** remedy. Run everything from the Mac (`mac-utm-1`), in a normal shell (not through the MCP wrapper — the `bin/rustynet-mcp-lab-state` binary rots silently; see `LiveValidation` §12.9 for why this run family is shell-launched).

### Phase 0 — prove the Mac can route into vmnet (~15 min, fully reversible)

This is the decision point for the whole runbook. It enables host routing temporarily and tests it, then you can turn it straight back off.

**Step 0.1 — find the Mac's real-LAN address and the UTM shared-net host address.**

```sh
ifconfig en0 | grep "inet "        # Mac on the real LAN (expect 192.168.0.x)
ifconfig bridge100 | grep "inet "  # UTM shared-net host side (expect 192.168.64.1)
```

**Verify:** both `inet` lines print. Note the en0 address (used as `<MAC-LAN-IP>` below).
**If it fails:** the Mac is on a different range than expected — stop and re-derive the plan's addresses before proceeding; do not guess.

**Step 0.2 — temporarily enable IP forwarding.**

```sh
sudo sysctl -w net.inet.ip.forwarding=1
sysctl net.inet.ip.forwarding      # Verify: prints = 1
```

**If it fails:** macOS refuses the write — check you are an admin; `sudo` prompted on your terminal.

**Step 0.3 — from a lenovo guest, probe ACROSS the Mac into the UTM island.**

```sh
ssh ubuntu@192.168.0.29   # onto lenovo-bot, then from the bot or a guest:
ping -c 3 192.168.64.10 && nc -zv -w 3 192.168.64.10 22
```

(Use the live 192.168.64.x address of any UTM guest from the inventory; refresh it first with `ops vm-lab-discover-local-utm-summary --update-inventory-live-ips` if unsure.)

**Verify:** ping 0% loss and `succeeded` on the TCP probe.

**If it fails (100% loss):** three suspects, in order:
1. **PF blocks forwarded traffic.** Check and, if needed, add a pass rule:
   ```sh
   sudo pfctl -s rules | head
   # add to /etc/pf.anchors/<your anchor> or a temp ruleset, then:
   #   pass on bridge100
   #   pass on en0
   sudo pfctl -f /etc/pf.conf
   ```
   Re-run the probe. (If the macOS application firewall is on, System Settings → Network → Firewall may also need the specific traffic allowed — verify in your macOS version's UI; the concept is "stateful host firewall independently filtering forwarded packets".)
2. **vmnet drops host-forwarded frames.** If PF is clean and the loss persists, the UTM vmnet shared interface is not accepting host-routed traffic — this is the known-unknown Phase 0 exists to catch. Decision: **stop here, revert (Step 0.4), and take option (b)** — do not burn hours trying to force vmnet.
3. **Wrong route targets.** Confirm from the lenovo side that `traceroute 192.168.64.10` first hop is the Mac.

**Step 0.4 — revert the temporary forwarding state.**

```sh
sudo sysctl -w net.inet.ip.forwarding=0
```

**Verify:** `sysctl net.inet.ip.forwarding` prints 0. (Phase 1 turns it back on permanently.)

### Phase 1 — make the reverse path permanent (~10 min)

**Step 1.1 — make forwarding persistent on the Mac** so a reboot doesn't silently undo the fleet's routing:

```sh
echo 'net.inet.ip.forwarding=1' | sudo tee -a /etc/sysctl.conf   # if your macOS honors it
```

**Verify in your macOS version:** after a reboot, `sysctl net.inet.ip.forwarding` = 1. Some macOS builds ignore `/etc/sysctl.conf`; if so, use a LaunchDaemon that runs the `sysctl -w` at boot (concept: "restore the sysctl at boot"; verify by rebooting once and re-reading the sysctl).
**If it fails:** worst case is re-running the `-w` after each reboot — acceptable but must be written into the run log so a future "routing suddenly broken" triage doesn't start from zero.

**Step 1.2 — PF rule.** Ensure the pass rules from Phase 0 are in the *persistent* pf config (an anchor loaded by `/etc/pf.conf`), not a temp ruleset.

**Verify:** `sudo pfctl -s rules | grep bridge100` shows the rule; then re-run the Step 0.3 probe from the lenovo side.

**If it fails:** probe again; if the rule loads but traffic dies, re-walk Phase 0's failure list.

**Step 1.3 — add the route on the lenovo guests** (both `lenovo-client-1` and `lenovo-exit-1`; on Debian-style guests):

```sh
sudo ip route add 192.168.64.0/24 via <MAC-LAN-IP>    # <MAC-LAN-IP> from Step 0.1
ip route get 192.168.64.10                             # Verify: "via <MAC-LAN-IP>"
```

Persist per your guest OS (netplan / NetworkManager / systemd-networkd — verify the correct mechanism in your guest image; the concept is "a static route surviving reboot").
**If it fails:** `RTNETLINK answers: File exists` means a route already exists — inspect `ip route show` and correct rather than stack duplicates. If the gateway is unreachable, the Mac's en0 address is wrong or the LAN blocks inter-host traffic — fix Step 0.1 first.

**Step 1.4 — bidirectional proof (the gate this runbook exists for).**

From a UTM guest (e.g. `debian-headless-4`):
```sh
ping -c 3 192.168.0.30 && nc -zv -w 3 192.168.0.30 22          # 64 → 0: expected to already pass
```
From `lenovo-client-1`:
```sh
ping -c 3 192.168.64.10 && nc -zv -w 3 192.168.64.10 22        # 0 → 64: the new capability
ip route get 192.168.64.10                                     # shows the Mac as gateway
```

**Verify:** all four commands succeed, both directions. This pair of probes IS the "two mutually routable /24s" precondition for CN-3. Record both directions' output in the run notes.

**If it fails:** you are back in Phase 0's failure list; the fleet is not ready for a CN-3 run, and running one anyway will produce a half-up overlay.

### Phase 2 — refresh the management plane (~5 min)

No guest moved, so this should be a no-op — but run it anyway so the orchestrator's view is provably current before the run.

```sh
cargo run -q -p rustynet-cli --features vm-lab -- ops vm-lab-discover-local-utm-summary --update-inventory-live-ips
```

**Verify:** the command exits 0; `documents/operations/active/vm_lab_inventory.json` still shows the lenovo pair on 192.168.0.x and the UTM guests on 192.168.64.x (no drift).
**If it fails or shows drift:** a guest moved networks when you weren't looking — re-check that guest's UTM/`virsh` attachment before proceeding. Never hand-edit the inventory.

### Phase 3 — the CN-3 proof run (~20-45 min)

The invocation, adapted from the CN-PROOF reproduction (`LiveValidation_2026-08-28.md` §12.9) with the role assignment from §1.3 of this runbook (entry/aux added per gate G2, client/exit split across the two LANs per gates G1/G3):

```sh
cargo run -q -p rustynet-cli --features vm-lab -- ops vm-lab-orchestrate-live-lab \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 \
  --known-hosts-file ~/.ssh/known_hosts \
  --report-dir state/live-lab-cn3-twolan-20260828 \
  --cross-network-substrate vxlan \
  --node ubuntu-utm-1:client --node debian-headless-4:aux --node lenovo-client-1:exit \
  --node lenovo-exit-1:entry --node rocky-utm-1:admin
```

**Verify, in this order:**
1. A row appends to `documents/operations/live_lab_node_run_matrix.csv` (the `--node` ledger — verify it exists and names this commit; remember a row is NOT proof a stage passed).
2. In the report dir, `cross_network_substrate_setup` no longer reads as an honest no-op: the substrate report should show a created overlay (`rustynet-vx0`) and `provisioned: true` — the direct opposite of the CN-PROOF `provisioned: false` short-circuit at `substrate.rs:1529-1532`.
3. The scenario stages that previously skipped on `MissingRole` now RUN, and their pass/fail is a real dataplane verdict.
4. Take every pass/fail claim from the stage's own report artifact (status + data block), never from the CSV column.

**If it fails:** read `first_failed_stage`, then `ops vm-lab-explain-stage <stage>` and the stage log in the report dir. New failure modes to expect on a first-ever two-LAN run: MTU mismatch across the routed path (vxlan adds overhead on top of a routed hop), asymmetric latency tripping timeouts, or PF dropping the encapsulated traffic — each is a fleet issue to fix in §4, not an orchestrator bug. Record every fix in the stage-triage ledger before the next run so the chain stays readable.

---

## 5) Rollback — back to today's single-LAN lab

The recommended path changes exactly three persistent things: the Mac's forwarding sysctl, a PF rule, and two guest routes. Roll each back:

```sh
# On the Mac:
sudo sysctl -w net.inet.ip.forwarding=0
sudo pfctl -d                      # only if you enabled pf solely for this; otherwise remove the anchor lines and reload
# remove the persistence you added in Step 1.1 (edit /etc/sysctl.conf / the LaunchDaemon)

# On each lenovo guest:
sudo ip route del 192.168.64.0/24
ip route get 192.168.64.10         # Verify: no longer via the Mac
```

**Verify rollback:** the Step 1.4 probes now fail in the reverse direction only (0→64 100% loss), i.e. the fleet is exactly as it was before this runbook.

**If the management plane breaks at any point during this work** (a guest stops answering SSH after you touched networking — not expected on (a-minimal), the standard hazard if you ever resort to (a-bridge)):
1. `scripts/vm_lab/probe_and_recover_local_utm.sh` — a stale nft killswitch can lock SSH out after a network reconfig; this is the sanctioned recovery (runbook: `UTMVirtualMachineInventory_2026-03-31.md`).
2. If a UTM guest's network mode was actually changed (only possible on the (a-bridge) path): revert the per-VM network setting to Shared in the UTM UI — verify the exact menu path in your UTM version; the concept is per-VM network mode Shared/Bridged in the VM's network device settings — then power-cycle it and re-run probe-and-recover.
3. Last resort: restore the lab's canonical profile state with a dry-run plan first — `ops vm-lab-network-prepare --profile mgmt_shared_smoke_v1` (no approval flag prints the plan only) — and only re-apply with explicit owner approval, since `approve_reconfigure` is a stop-and-restart of every affected VM.
4. If a guest's IP changed permanently: refresh with `--update-inventory-live-ips` and re-pin `known_hosts` — never hand-edit the inventory.

---

## 6) Evidence and cross-references

- CN-PROOF run + failure analysis + reproduction invocation: `LiveValidation_2026-08-28.md` §12 (run `livelab-1787908428-6d9224cfd954`, commit `6d9224cfd954`).
- Decision record: `CrossNetworkSubstrateIntegrationSpec_2026-06-21.md` §0.6.
- Gate enforcement points: `substrate.rs:754-756`, `substrate.rs:1529-1532` (G1); `cross_network.rs:929-932` (G2); `cross_network.rs:514-520`, `cross_network.rs:944-949`, `cross_network.rs:1085-1105` (G3).
- Two-bridge host topology and the vmnet backend split: QH-41 in `QualityHardeningTodo_2026-07-25.md` (verified bidirectionally 2026-08-11; plutil backend correction 2026-08-12).
- Probe-and-recover runbook: `UTMVirtualMachineInventory_2026-03-31.md` + `scripts/vm_lab/probe_and_recover_local_utm.sh`.
- Network-mutation policy: `prepare_lab_network` is the only sanctioned VM network mutation; `en0` is denied as a bridge target (`LiveLabVmConnectivityRulebook` §11.3).
- CN-2 status (for context: what the netns substrate already proves): `livelab-1787906534-877a0226693c`, 3 of 5 NAT profiles live-proven; `double_nat_cgnat` unproven.
