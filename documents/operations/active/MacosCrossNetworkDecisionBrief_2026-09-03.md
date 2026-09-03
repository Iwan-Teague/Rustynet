# macOS Cross-Network Traffic — Owner Decision Brief (2026-09-03)

**Scope:** docs-only. Turns the three fix directions in `MacosCrossNetworkTrafficBlocker_2026-09-03.md` §6 into an executable owner decision. No code executed or changed. **UNTRUSTED** — every step and citation below must be re-verified by the owner/manager before acting; where this brief CORRECTS the blocker doc, the correction is flagged in place.

**The failure being decided on:** run `livelab-1788433705-bf4b1b1187c8` (2026-09-03, 3 nodes: `macos-utm-1` client + `debian-headless-4` exit + `debian-headless-2`), `traffic_test_matrix` = 100% ICMP loss on every cross-vmnet pair, both directions. Cause: the three harvest guests sit on **two isolated UTM vmnet shared networks** (`macos-utm-1` on `192.168.64.0/24`; both debians on `192.168.65.0/24`), the run launched **without a cross-network substrate**, so every cross-vmnet WireGuard peer endpoint in the assignment bundle is an underlay address on the *other* vmnet's private prefix — unroutable, no handshake possible (`MacosCrossNetworkTrafficBlocker_2026-09-03.md` §3, live-measured 2026-09-03).

---

## 0) Decision in one line

**RECOMMENDATION: Option 1 — re-pin the whole UTM fleet onto the single `192.168.64.0/24` shared network.** It is the only option whose critical path ends in a macOS `traffic_test_matrix` verdict: Option 2 structurally excludes macOS (the vxlan substrate fails closed on any non-Linux participant, `substrate.rs:2082-2099`), and Option 3 does not touch the failing path at all (the traffic matrix proves *direct* full-mesh pings over the endpoints in `NODES_SPEC`, `distribute_assignments.rs:60-87`; a relay on one vmnet is exactly as unroutable from the other vmnet as a peer is). Option 1 is also zero-code and restores the historical single-L2 lab shape every prior pass assumed. Owner hands-on: the UTM network re-attachment of four guests. Manager/CLI: inventory refresh, label fix, re-prove run.

---

## 1) The facts the choice rests on (all verified 2026-09-03 on this tree)

1. **Endpoint seam is substrate-only.** `collect_pubkeys` overrides a node's recorded endpoint only when the requested substrate answers on the `Overlay` plane (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/collect_pubkeys.rs:112-141`); otherwise the endpoint is the raw discovered underlay address + `:51820` (`adapter/macos.rs:320-326`, `adapter/linux.rs:307-313`). `distribute_assignments` feeds those verbatim into `NODES_SPEC` (`node_id|endpoint|pubkey|caps`, `distribute_assignments.rs:60-87`) with a **full-mesh** `ALLOW_SPEC` (`:89-107`) — every peer pair is expected to dial directly.
2. **The two vmnets are isolated, and the host does not forward between them.** Live-measured (blocker §3.2): guest→guest across vmnets is 100% loss every protocol, both directions, **with the host already at `net.inet.ip.forwarding=1` and no pf rules** — the debian route is correct (`192.168.64.18 via 192.168.65.1`) and the packet dies at the host bridge. macOS vmnet "Shared" segments drop host-forwarded frames. This **refutes the cheap variant** "just route between the two vmnets on the host": that experiment is effectively already done and it failed. It also means the accidental 64/65 split **cannot serve as the vxlan underlay** — see Option 2.
3. **The drift is wider than the blocker doc's three nodes.** Current live inventory (`documents/operations/active/vm_lab_inventory.json`, `ssh_target` = live SSH address): on `192.168.65.0/24` sit `debian-headless-2` (.4), `debian-headless-4` (.5), `fedora-utm-1` (.10), `ubuntu-utm-1` (.9); on `192.168.64.0/24` sit `macos-utm-1` (.18), `windows-utm-1` (.25), `rocky-utm-1` (.105). The blocker's §3.3 "swapped subnets" observation is correct, and two more QEMU guests (fedora, ubuntu) drifted with the debians.
4. **vxlan fails closed on macOS.** With ≥2 underlay /24 groups and any non-Linux participant, `CrossNetworkSubstrateSetupStage` returns `Failed("the vxlan topology substrate supports only Linux guests today; '<alias>' is …")` (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/cross_network/substrate.rs:2082-2099`, the "cannot be silently excluded" comment at `:2078-2081`). **This corrects blocker §6.2**, which suggested the vxlan substrate would make `collect_pubkeys` record overlay endpoints for this harvest — with the mac in the topology the setup stage fails *before* `collect_pubkeys` ever runs.
5. **Below two /24 groups the vxlan substrate is an honest no-op** (`plan_overlay` → `Ok(None)` at `substrate.rs:753-756`; `VxlanSubstrateProvider::setup` short-circuits to `provisioned: false` around `:1514`) — so after a successful Option 1 re-pin, the substrate machinery stays dormant and harmless.
6. **CN-3 scenario topology needs `entry`+`aux`.** `CrossNetworkTopology::resolve` fills its relay participant from `["entry","aux"]` and its probe participant from `["aux","entry"]`, never from the `relay` node role (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/cross_network.rs:963-965`; recorded as `cross_network.rs:929-932` in `TwoLanFleetSetupRunbook_2026-08-28.md` §1.1 — line numbers drifted on this tree, logic unchanged). `NodeRole::Entry`/`NodeRole::Aux` exist (`orchestrator/role.rs:19-20`). A 3-node client/exit/+1 topology has **no** `entry` or `aux`, so the scenario stages would skip on `MissingRole`.
7. **No usable relay exists in the UTM fleet.** The only `relay_capable: true` inventory entry is `fedora-x86-1` — on the `192.168.121.0/24` libvirt net, measured unreachable from both the UTM island and the real LAN (`TwoLanFleetSetupRunbook_2026-08-28.md` §2.1). All UTM guests are `relay_capable: false`. Relay role is platform-supported on Linux today, pending on macOS (`role.rs:38-39`, `:54`).
8. **`--update-inventory-live-ips` fixes `live_ips` only.** `write_inventory_live_ips` (`crates/rustynet-cli/src/vm_lab/mod.rs:30433`, rewrite at `:30503-30512`) touches the `live_ips` array and nothing else — the stale `network_group` labels are NOT repaired by the sanctioned refresh and need a separate, reviewed correction (Option 1 step 4).

---

## 2) OPTION 1 — Re-pin single-L2 on `192.168.64.0/24` (RECOMMENDED)

**Goal:** every UTM guest back on ONE vmnet shared network, so raw underlay endpoints are mutually reachable again — the shape `CrossNetworkSubstrateIntegrationSpec_2026-06-21.md` §7 assumed and the shape in which `traffic_test_matrix` passes with **no substrate, no relay, no code change**.

### 2.1 Owner steps (hands on the UTM app; not scriptable from the repo)

1. **Confirm which shared network yields 64.x today.** In UTM, inspect `macos-utm-1`, `windows-utm-1`, `rocky-utm-1` (the three guests currently on 192.168.64.x): VM Settings → Network → note each network device's mode/network. Sanity-check the backend field of `macos-utm-1` while there (QH-41, `QualityHardeningTodo_2026-07-25.md`, previously observed Apple-backend vs QEMU-backend "Shared" as two different L2s — the current drift shows mac+QEMU guests co-resident on 64.x, so either the backend split no longer binds or UTM renumbered; record what you see either way).
2. **Move the four 65.x guests onto the 64.x shared network**: `debian-headless-2`, `debian-headless-4`, `fedora-utm-1`, `ubuntu-utm-1`. Per VM: Settings → Network → set the device to the **same** shared network the mac sits on → Apply → power-cycle the VM (Shared-network membership is applied before boot). The harvest only needs the two debians, but move all four — a half-pinned fleet re-creates this blocker the next time the harvest topology changes.
3. **Sanctioned-path check first (manager can run, owner approves):** `ops vm-lab-network-prepare --profile mgmt_shared_smoke_v1` **without** the approval flag prints a dry-run plan (current vs target attachment per VM) and changes nothing. The profile declares `attachment = "shared"` management-plane only (`profiles/vm_lab/network/mgmt_shared_smoke_v1.toml` — "NO network-fidelity claim") and does not pin a *specific* vmnet, so expect the plan to be a no-op (guests are already "Shared"); the *which-shared-network* fix is the UTM-app action in step 2. `prepare` with `approve_reconfigure` is a stop-and-restart of every affected VM — explicit owner authorization only.
4. **If SSH locks out after a reconfig:** `scripts/vm_lab/probe_and_recover_local_utm.sh` (stale nft killswitch recovery; runbook `UTMVirtualMachineInventory_2026-03-31.md`).

### 2.2 Manager steps (CLI/MCP; no UTM access needed)

5. **Verify guest↔guest underlay BEFORE the run** (cheap; proves the re-pin took):
   ```sh
   ssh debian@192.168.65.4 ping -c2 192.168.64.18      # expect 0% loss (or the guest's NEW 64.x address after the move)
   ssh mac@192.168.64.18 ping -c2 <debian new addr>    # expect 0% loss
   ```
   Guests get fresh 64.x DHCP leases — re-read addresses from the next step before probing.
6. **Refresh live IPs** (never hand-edit; this is the only sanctioned IP update — §10.9):
   ```sh
   cargo run -q -p rustynet-cli --features vm-lab -- ops vm-lab-discover-local-utm-summary --update-inventory-live-ips
   ```
   Verify in `documents/operations/active/vm_lab_inventory.json`: `debian-headless-2`/`debian-headless-4`/`fedora-utm-1`/`ubuntu-utm-1` now show `live_ips` on 192.168.64.x; `macos-utm-1` stays 192.168.64.18.
7. **Fix the stale `network_group` labels + stale known-IP entries** (blocker §3.3). The refresh does NOT touch these (fact 8):
   - `debian-headless-2`: `network_group: "utm-shared-192.168.64.0/24"` — becomes CORRECT again after the move; its stale pre-drift `live_ips` entries (`192.168.64.4`, `192.168.64.201`) are replaced by step 6's refresh.
   - `debian-headless-4`: same (`network_group` becomes correct; `live_ips` refreshed).
   - `macos-utm-1`: `network_group: "utm-shared-192.168.65.0/24"` → must be corrected to `"utm-shared-192.168.64.0/24"` by a **reviewed, committed inventory edit** (it is a static label, not discovered state; the "never hand-edit the inventory" rule covers discovered addresses). `live_ips` refreshed by step 6.
   - Also re-check `windows-utm-1`/`rocky-utm-1` labels (both currently say 64.x and the guests are on 64.x — likely correct already).
8. **Verify SSH reachability per guest** (`check_vm_reachable` lab-state tool or `nc -z <ip> 22`); if a guest's IP changed and `known_hosts` pins now mismatch, re-pin the host key before the run (the orchestrator requires pinned keys; do not disable checking).

### 2.3 The re-prove run

Same 3-node shape as the failed harvest, bare orchestrate (no substrate — fact 5: it would no-op anyway):

```sh
cargo run -q -p rustynet-cli --features vm-lab -- ops vm-lab-orchestrate-live-lab \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 \
  --known-hosts-file ~/.ssh/known_hosts \
  --report-dir state/live-lab-macos-traffic-reprove-20260903 \
  --node macos-utm-1:client --node debian-headless-4:exit --node debian-headless-2:client
```

(Or, manager-via-MCP: `ai_lab_run` / `start_live_lab_run` with `nodes=["macos-utm-1:client","debian-headless-4:exit","debian-headless-2:client"]`. Match the harvest's original `debian-headless-2` role from its `state/nodes.tsv` if it differed.)

**Verify pass (per §12.3 — the CSV column is NOT proof):**
1. A row appends to `documents/operations/live_lab_node_run_matrix.csv` naming this commit.
2. In the report dir, `state/stages.tsv`: `traffic_test_matrix  pass`, and `logs/traffic_test_matrix.log` shows no failed pairs (the log only lists failures, `traffic_test_matrix.rs:101-162`).
3. The fail-closed negative-test line ("default-deny INCONCLUSIVE …") is gone — with peers reachable, the negative test can attribute the block to policy.
4. `cross_os_peer_visibility` (recorded `fail` on the failed run's row) flips with the stage (blocker §6.4).

### 2.4 Risks / what could still fail

- **Guests re-land on 65.x after the move** (if the two "Shared" definitions are backend-bound per QH-41): the post-move lease check (step 5/6) catches it immediately. If QEMU guests persistently re-land on 65.x while the mac stays on 64.x, **single-L2 is structurally unachievable** on this UTM build — stop, record the measurement in the blocker doc, and fall back to Option 2's program for the CN track; for the macOS traffic proof specifically there is then NO same-fleet fix (host-routing between vmnets is refuted, fact 2) short of changing the mac guest's backend/network definition in UTM — an owner decision this brief does not prescribe.
- **DHCP renumbering on the mac side** if UTM re-assigns bridges during the churn: step 6's refresh + step 8's reachability check catch drift; re-pin `known_hosts` if needed.
- **Killswitch lockout during reconfig**: probe-and-recover (step 4).
- **fedora/ubuntu guests** may lack current bootstrap/toolchain state if they were idle through the drift — irrelevant to the 3-node re-prove; they re-enter later harvests via the normal bootstrap path.

---

## 3) OPTION 2 — vxlan two-LAN substrate (record the honest scope: NOT a macOS fix)

**What the flag does.** `--cross-network-substrate vxlan` makes `CrossNetworkSubstrateSetupStage` (ordered after `bootstrap_hosts`, before `collect_pubkeys`) provision a vxlan overlay: `plan_overlay` groups participants by underlay /24, assigns `172.20.<10*g>.0/24` per group (`substrate.rs:740-775`), creates `rustynet-vx0` on each Linux participant, and `collect_pubkeys` then records the overlay address as the WireGuard endpoint (fact 1). Teardown is `always_run` and residue-fail-closed (`substrate.rs:2120+`).

**Why it cannot close THIS blocker, in three hard gates:**
1. **macOS is excluded by code.** The mac in the topology → `cross_network_substrate_setup` FAILS closed (fact 4). The mac out of the topology → there is no macOS node to prove `traffic_test_matrix` on. Either way the current blocker is untouched.
2. **The accidental 64/65 split is not a usable underlay.** The vxlan tunnels ride the underlay; the two vmnets must be mutually routable (runbook §1.2) — measured 100% loss both directions with host forwarding already on (fact 2). A half-up overlay is worse than a clean refusal (runbook §1.2 explicitly).
3. **The scenario roles are missing.** A 3-node client/exit/+1 topology has no `entry`/`aux` → `MissingRole` skips (fact 6). Fix: assign `--node <alias>:entry` and `--node <alias>:aux` explicitly (e.g. `fedora-utm-1:entry`, `debian-headless-2:aux`), plus the `client`/`exit` split across the two /24s (G3, `cross_network.rs:514-520`, `944-949` — satisfied by any 64.x-vs-65.x split, but see gate 2).

**Known gaps to expect (spec §0.6 + §0.5 status rows):** the vxlan provider and the eight CN-3 validators are **unit-tested against `MockLeafRunner`/`RecordingHost` but not live-proven**; `TwoLanFleetSetupRunbook_2026-08-28.md` is the operator program for this direction, and its real two-LAN shape is **UTM 64.x + real-LAN lenovo pair** (option (a-minimal): 64→0 proven, 0→64 pending its Phase 0 Mac-forwarding probe) — not the accidental vmnet split.

**If the owner still wants a first vxlan shakedown on the current split anyway** (cheap diagnostic, expect the underlay gate to fail it):
```sh
cargo run -q -p rustynet-cli --features vm-lab -- ops vm-lab-orchestrate-live-lab \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 --known-hosts-file ~/.ssh/known_hosts \
  --cross-network-substrate vxlan \
  --node ubuntu-utm-1:client --node debian-headless-4:exit \
  --node debian-headless-2:aux --node fedora-utm-1:entry --node rocky-utm-1:admin \
  --report-dir state/live-lab-cn3-vxlan-shakedown-20260903
```
Expected shakedown order: substrate setup provisions `rustynet-vx0` (`provisioned: true` in the substrate report — the opposite of the CN-PROOF `provisioned: false` no-op), then scenarios run (no `MissingRole` skips), then the dataplane verdict is where the unroutable underlay shows up. New failure modes per runbook §4: MTU (vxlan overhead), asymmetric latency, encapsulated frames dropped. Record every fix in the stage-triage ledger (`stage_triage_history`).

**Verdict:** pursue as its own program (runbook option (a)) AFTER Option 1 lands, if the owner wants CN-3/Tier-B live proof. It is not a candidate fix for the macOS traffic blocker.

---

## 4) OPTION 3 — Elect a relay into the topology (does NOT fix the cross-vmnet path)

**What electing a relay requires:** a node assigned the `relay` node role (`--node <alias>:relay`; `NodeRole::Relay` at `role.rs:16`), Linux platform (supported live-evidenced; macOS pending, `role.rs:38-39`, `:54`) — then `deploy_relay_service` + `relay_validation` stages run (on the failed run both were *skipped*: "no node in this topology is assigned the relay role"). The inventory `relay_capable` label is not consulted by role election (only by the relay-forward-test cell, `mod.rs:13719-13731`, which demands `relay_capable == Some(true)` — and the only such node, `fedora-x86-1`, is unreachable, fact 7).

**Why it does not fix this blocker:** `traffic_test_matrix` proves *direct* mesh pings over `NODES_SPEC` endpoints, and `NODES_SPEC` is a **full mesh of direct endpoints** (`distribute_assignments.rs:60-87` + full-mesh `ALLOW_SPEC` `:89-107`). The relay is not consulted by the traffic matrix and — decisively — a relay guest lives on ONE vmnet, so its underlay endpoint is exactly as unroutable from the other vmnet as any peer's (fact 2: no host forwarding between vmnets, measured). The relay fallback path would need to reach the relay first. There is no dual-homed or third-plane UTM guest to elect.

**Verdict: REJECT for this blocker.** Revisit relay election when the dataplane relay-lifecycle cells need a live relay participant on a properly routed fleet.

---

## 5) Parallel follow-through (cheap, any option)

- **Failure-time evidence capture** (blocker §6.3): wire `collect_wireguard_tunnels` (`adapter/macos_traffic.rs:413-417`, `adapter/linux_traffic.rs:474-497`) into `traffic_test_matrix`'s failure path per `LiveLabInfoAccuracyDesign_2026-09-03.md` — today the run destroys its own evidence at cleanup. Code change; separate scope.
- **Inventory label hygiene** is the residual regression-class risk (blocker §5): Option 1 step 7 closes it for the re-pinned fleet; add a periodic `network_group` vs live-subnet consistency check to the lab preflight if drift recurs.

## 6) Post-decision verification (whichever option)

1. Row appended to `documents/operations/live_lab_node_run_matrix.csv`, attributed to this commit (quote-aware parse — QH-07).
2. Pass/fail taken from the stage's own report artifact (status + data block), never the CSV column (§12.3).
3. For Option 1 success, explicitly record: macOS `traffic_test_matrix` = pass — there is **no prior row** in the `--node` ledger where a macOS node ever passed it (blocker §3.3).
