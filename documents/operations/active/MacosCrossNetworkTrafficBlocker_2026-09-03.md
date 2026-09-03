# macOS Cross-Network Traffic Blocker — grounded diagnosis (2026-09-03)

**Scope:** docs-only investigation. No production code touched. UNTRUSTED — every citation below should be re-verified by a human before acting.

**Problem:** after the macOS `DnsFailclosed` blocker closed, the rank-1 harvest advanced to `traffic_test_matrix` and failed with 100% ICMP loss between `macos-utm-1` (mesh IP `100.64.181.171`) and the debian nodes `debian-headless-4` (`100.124.191.164`) / `debian-headless-2` (`100.80.169.183`) — both directions.

**Verdict up front:** **(c) substrate-wiring gap — a silent fleet topology drift, not a rustynetd regression and not a NAT-traversal defect.** The three lab guests now sit on **two separate UTM vmnet shared networks** (`192.168.64.0/24` bridge100 for `macos-utm-1`; `192.168.65.0/24` bridge101 for both debian guests), the harvest run was launched **without any cross-network substrate** and **without a relay/anchor node**, so every cross-vmnet WireGuard peer endpoint distributed in the assignment bundle is an **underlay address on the other vmnet's private prefix — unroutable**. This is the exact failure mode already documented as the "NEW, upstream gap" in `CrossNetworkSubstrateIntegrationSpec_2026-06-21.md` §0.5 (live-proven then in `livelab-1787790884-c9ccf1a4d1cc`); the code seam that fixes it (`collect_pubkeys` + `SubstrateHandle::endpoint()`) exists but only activates when a substrate is requested, and this run requested none.

---

## 1) The failing run, stage by stage

Evidence base: `state/deepseek-lab-labrun-1788432982031-99063-0/` (run `livelab-1788433705-bf4b1b1187c8`, commit `bf4b1b1187c8`, `main`, clean; 3 nodes, 65 stages; passed=23 failed=1 skipped=41). The earlier dir named in the ticket, `deepseek-lab-labrun-1788431870-*`, does not exist; the nearest neighbours are `deepseek-lab-labrun-1788431081990-83468-0` (the run that failed `dns_failclosed_validation` **and** `traffic_test_matrix` — same cross-pair symptom behind the DNS blocker) and `deepseek-lab-labrun-1788432883380-98335-0` (aborted: only `state/report_state.json`, no stages).

- `state/stages.tsv`: `traffic_test_matrix  hard  fail  1` at `2026-09-03T11:05:40Z→11:08:14Z`. Everything after is cascade-skipped (`role_switch_matrix`, `exit_handoff`, `active_exit`, all `cross_network_*` stages, all mac/win role cells).
- `logs/traffic_test_matrix.log` (whole file is 18 lines): all four **cross-vmnet** pairs fail at 100% loss:
  - `debian-headless-4 → macos-utm-1 (100.64.181.171)` — `3 packets transmitted, 0 received, 100% packet loss`
  - `debian-headless-2 → macos-utm-1` — `3 packets transmitted, 0 received, 100% packet loss`
  - `macos-utm-1 → debian-headless-4 (100.124.191.164)` — `3 packets transmitted, 0 packets received, 100.0% packet loss`
  - `macos-utm-1 → debian-headless-2 (100.80.169.183)` — `3 packets transmitted, 0 packets received, 100.0% packet loss`
  - plus the fail-closed negative-test note: `macos-utm-1: default-deny INCONCLUSIVE — 198.51.100.1 was unreachable but the node reached no mesh peer, so the block cannot be attributed to policy (failing closed)`
- **The same-substrate debian↔debian pings are NOT in the error list** — `traffic_test_matrix.rs:101-162` pings every ordered pair and only failures are reported, so `debian-headless-2 ↔ debian-headless-4` (both on `192.168.65.0/24`, one L2) **passed**. The failure is precisely and only the cross-vmnet boundary.
- `mesh_status_validation` **passed** (11:05:31) seconds before the traffic failure. Not contradictory: it validates the daemon-reported mesh status (control-plane peer visibility — "expected peer IDs present, within max-age bounds", `crates/rustynet-cli/src/vm_lab/orchestrator/stage/mesh_status_validation.rs:12`), not the data path.
- `gossip_convergence_validation` skipped — `logs/gossip_convergence_validation.log`: "no node executed this validation; 1 node(s) reported a runtime skip" (the macOS node).
- `deploy_relay_service` / `relay_validation` skipped — "no node in this topology is assigned the relay role"; `anchor_validation`, `admin_issue`, `blind_exit` likewise skipped. **There is no relay or anchor in this topology to fall back to.**
- `exit_handoff` / `active_exit` never ran (`traffic_test_matrix` is their dependency, per `state/stages.tsv` order), so debian-headless-4's exit role (bootstrap role `exit`, `state/nodes.tsv`) was **not yet active** at traffic-test time. Hypothesis (d) "mac full-tunnel routes via the exit" is **ruled out for this run**: there was no active exit, and the daemons were freshly bootstrapped this run (`cleanup_hosts` 10:56:47, `bootstrap_hosts` 10:56:51→11:04:44).

## 2) Q1 — Was there a WireGuard handshake / usable route? Not captured, and post-hoc state is destroyed

The run's artifacts contain **no `wg show` / peer / handshake capture at failure time**:

- `diagnostics/rust-native-failure/summary.json`: all three nodes report `"daemon_reason": "no daemon failure marker found"`, `"artifact": null` — the rust-native failure collector found nothing to collect, and nothing in `traffic_test_matrix.rs` (whole file: mesh-IP re-collection `:29-79`, per-pair ping-with-retry `:101-162`, default-deny negative `:164-203`) captures tunnel state.
- The adapters **have** the capture primitives — `collect_wireguard_tunnels` runs `wg show 2>/dev/null || echo 'wg-not-installed'` (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_traffic.rs:413-417`) and the linux analogue collects `wg show all latest-handshakes` (`adapter/linux_traffic.rs:474-497`) — but neither is invoked by `traffic_test_matrix` nor by the failure collector. This is exactly the "capture the evidence, not just the verdict" gap the active `LiveLabInfoAccuracyDesign_2026-09-03.md` describes; a failure-time evidence bundle would have answered Q1 from the run itself.
- Post-run live check (2026-09-03, after `cleanup`): `macos-utm-1` daemon socket gone (`/run/rustynet/rustynetd.sock: No such file or directory`, `latest_handshakes` empty — `rustynet ops vm-lab-status` via lab-state MCP), `debian-headless-2` `rustynetd` inactive, no nft ruleset, no mesh interface or route (`utmctl exec` network info). The cleanup stage destroys the mesh before anyone can inspect it, so **the run's own artifacts are the only evidence channel, and they don't capture handshakes today.**

## 3) Q2 — Mechanism: the underlay endpoints are unroutable, live-proven right now

### 3.1 What endpoints the daemons were given

- `collect_pubkeys` records each node's endpoint; **without a requested substrate the endpoint is the raw discovered underlay address** — the seam comment at `crates/rustynet-cli/src/vm_lab/orchestrator/stage/collect_pubkeys.rs:112-123` says it outright: "the raw discovered underlay IP sits on another LAN's private prefix and is unroutable cross-LAN (spec §0.5, 2026-08-27)". `SubstrateHandle::endpoint()` overrides only on the Overlay plane.
- With no substrate, `adapter.endpoint()` returns the SSH host + `:51820`: `format!("{host}:51820")` (`adapter/macos.rs:320-327`, `adapter/linux.rs:307-314`) → `192.168.64.18:51820` for the mac, `192.168.65.4:51820` / `192.168.65.5:51820` for the debians.
- `distribute_assignments` feeds those verbatim into `NODES_SPEC` (`stage/distribute_assignments.rs:60-85`): every peer entry is `node_id|endpoint|pubkey|caps`. So macos-utm-1's daemon holds debian peer endpoints `192.168.65.4:51820`/`192.168.65.5:51820`, and the debians hold `192.168.64.18:51820`.
- The substrate setup stage passed as an **honest no-op**: `cross_network_substrate_setup` → `pass` in `state/stages.tsv`, and `stage/cross_network/substrate.rs:2060-2072` returns `Passed` untouched when `topology_level_seam` says `NoOverlay` (`substrate.rs:1852-1864`) — which is the case because the run command was bare `vm-lab-orchestrate-live-lab` (no `--cross-network-substrate`; `state/live_lab_run_matrix_row.csv`, `run_command` column).

### 3.2 The underlay really is split — measured live during this investigation (2026-09-03, ~12:xx, host + guests)

- Host route table: `192.168.64` → `bridge100` (macos-utm-1 `192.168.64.18`, windows, fedora's old lease), `192.168.65` → `bridge101` (debian-headless-2 `192.168.65.4`, debian-headless-4 `192.168.65.5`); host owns `192.168.64.1` and `192.168.65.1`; `net.inet.ip.forwarding: 1`; pf emits no rules.
- Host → every guest: ICMP OK (all three).
- **Guest → guest across vmnets: 100% loss, every protocol, both directions, with no mesh involved:**
  - `macos-utm-1` (`ssh mac@192.168.64.18`): `ping -c2 192.168.65.4` → `2 packets transmitted, 0 packets received, 100.0% packet loss`; `nc -z 192.168.65.4 22` → rc=1; `nc -z 192.168.65.1 53` → rc=1.
  - `debian-headless-2` (`ssh debian@192.168.65.4`): `ping -c2 192.168.64.18` → `2 packets transmitted, 0 received, 100% packet loss`; route is correct (`192.168.64.18 via 192.168.65.1 dev enp0s1`) — the packet reaches the host bridge and dies there. macOS vmnet "Shared" networks are isolated NAT segments; the host does not forward between two vmnet instances even with `forwarding=1`.

So the WireGuard layer never had a chance: **no peer endpoint is reachable, so no handshake can start, so every cross-pair ping times out.** This is not (a) NAT hole-punch failing mid-traversal — the bundle-endpoint dial is the only path engaged and there is no relay/anchor fallback deployed; not (b) relay mis-selection — `deploy_relay_service` was skipped ("no node in this topology is assigned the relay role"); not (d) full-tunnel-via-exit — `exit_handoff`/`active_exit` never ran. It is (c).

### 3.3 The drift that caused it

`documents/operations/active/vm_lab_inventory.json` is **self-contradictory and stale** for both sides:

- `debian-headless-2`: `ssh_target 192.168.65.4`, but `network_group: "utm-shared-192.168.64.0/24"` and known IPs `192.168.64.4`, `192.168.64.201`.
- `debian-headless-4`: `ssh_target 192.168.65.5` vs `network_group: "utm-shared-192.168.64.0/24"`, known IPs `192.168.64.10`, `192.168.64.6`.
- `macos-utm-1`: `ssh_target 192.168.64.18`, but `network_group: "utm-shared-192.168.65.0/24"`, known IPs `192.168.65.101`, `192.168.65.2`.

The two fleets have effectively **swapped subnets**: historically all UTM shared guests lived on one `192.168.64.0/24` L2 (the substrate spec's §7 assumption, `CrossNetworkSubstrateIntegrationSpec_2026-06-21.md:358` "every UTM guest is `192.168.64.x`"), where raw underlay endpoints WERE mutually reachable and `traffic_test_matrix` passed without any substrate. UTM has since split/re-assigned the shared networks into two vmnet instances; nobody re-pinned or re-labeled the fleet; the rank-1 harvest mixed guests across the new boundary. The ledger confirms this has never passed before on this engine: every `--node` run that ever recorded a `traffic_test_matrix` pass (e.g. `livelab-1785307884`, `livelab-1785313039`, `livelab-1788175066`, all 2026-07/08) was a **debian-only 2-node topology** — `topology_summary` names only the two debian guests, `macos_present=not_run`. There is **no row in `documents/operations/live_lab_node_run_matrix.csv` where a macOS node ever passed `traffic_test_matrix`**; the "cross-network proven 2026-07-29" memory (2 Mac UTM + 2 Ubuntu KVM, 12/12 mesh ping, hole-punch both NATs) is not a `--node`-ledger traffic pass and predates the subnet drift — it was proven across real, router-routed LANs, not across two host-local vmnet NATs. So: **a harvest-topology/config gap that a substrate-wiring drift exposed — not a code regression.** (The regression-class concern that remains is the inventory `network_group` staleness, §5.)

## 4) Q3 — Is `traffic_test_matrix` the right expectation here?

Yes — the stage's contract is legitimate and must not be weakened: it proves "the mesh pings, every pair" (`live_lab_stage_registry.rs:949-991`, incl. the QH-07 comment that it is the pure mesh-ping stage). Full all-pairs guest↔guest reachability is the correct baseline for any fleet that is one L2, or that has been given an overlay substrate / a relay. What is wrong is the **launch configuration of this harvest topology**, in two stacked ways:

1. The fleet is now (silently) two /24s, and the documented rule is that a split underlay **requires** the overlay seam: `collect_pubkeys.rs:112-123` (endpoint = `SubstrateHandle::endpoint()`, overlay only). With no substrate requested, the stage correctly measures a broken underlay and fails.
2. The vxlan substrate was previously blocked because the fleet had only ONE /24 group (`substrate.rs:754-756`: `plan_overlay` returns `Ok(None)` below two underlay /24 groups; §0.6 blocker 1 of the spec). **The drift ironically created the two-/24 precondition** (`192.168.64.0/24` + `192.168.65.0/24`, both host-connected) that `plan_overlay` needs — but also note spec §0.6 blocker 3: the cross-network scenario stages additionally require client and exit on **distinct /24s judged on the management plane** (`cross_network.rs:514-520`, `944-949`) — which this 3-node topology now satisfies (mac client 64.x, debian-4 exit 65.x).

So the right expectation for this topology is: `traffic_test_matrix` passes **either** with all guests pinned back onto one vmnet shared network (the historical single-L2 shape), **or** with a requested cross-network substrate providing overlay endpoints, **or** with a relay node elected into the topology. It should keep failing loudly otherwise — that is the fail-closed behaviour working as designed.

## 5) Next diagnostic step (capture on a live run, before cleanup)

Re-run the same 3-node harvest (bare `vm-lab-orchestrate-live-lab`) **without cleanup hold-off**, and at the moment `traffic_test_matrix` fails grab, over SSH (identity already primed by the orchestrator; users: `mac@192.168.64.18`, `debian@192.168.65.4`, `debian@192.168.65.5`):

On `macos-utm-1` (192.168.64.18):
```sh
sudo wg show                                  # peers, endpoints, latest handshakes (expect: endpoints = 192.168.65.x:51820, no handshake)
ifconfig | grep -A2 utun                      # mesh interface + mesh IP 100.64.181.171 present?
netstat -rn -f inet | grep 100.64             # route to peer mesh IPs via utun?
log show --last 15m --predicate 'process == "rustynetd"' --style compact | tail -80   # handshake/dial errors
ping -c2 192.168.65.4                         # underlay reachability of the peer endpoint itself (expected: 100% loss, proven above)
```
On each debian guest:
```sh
sudo wg show; sudo wg show rustynet0 endpoints  # expect endpoints 192.168.64.18:51820 etc., latest-handshake empty
ip route get 192.168.64.18                      # via 192.168.65.1 (proven correct already)
ping -c2 192.168.64.18                          # underlay probe (expected: 100% loss)
sudo nft list ruleset | head -40                # confirm no stale killswitch masking the probe
```
Decision rule: if `wg show` shows the cross-LAN endpoints and zero latest-handshakes while the debian↔debian peers handshake fine, the mechanism in §3 is confirmed end-to-end; then apply the fix below and re-run.

## 6) Fix direction (owner to choose; do NOT weaken the stage)

1. **Restore the single-L2 lab shape (recommended first):** pin all UTM guests back onto ONE vmnet shared network (`192.168.64.0/24`) in UTM so raw underlay endpoints are mutually reachable again — the shape every historical pass used and the substrate spec's §7 assumption. Then refresh live IPs (`ops vm-lab-discover-local-utm-summary --update-inventory-live-ips`) and **fix the stale `network_group` labels / known IPs** that §3.3 documents. Lowest risk; no new substrate machinery on the harvest's critical path.
2. **Embrace the two-LAN fleet deliberately:** relaunch the harvest with `--cross-network-substrate vxlan` so `CrossNetworkSubstrateSetupStage` provisions the overlay and `collect_pubkeys` records overlay endpoints (the seam built for exactly this, `substrate.rs:2192+`; two-/24 precondition now met). NOTE: spec §0.6 records the vxlan provider as **unit-tested but not live-proven**, and the CN-3 scenario gates additionally want `entry`+`aux` roles (`cross_network.rs:929-932`) — expect shakedown. `TwoLanFleetSetupRunbook_2026-08-28.md` is the operator runbook for the two-LAN direction (its premise — second LAN = lenovo `192.168.0.x` — is now complemented by the accidental 64/65 split; if option 2 is chosen, the runbook's Phase 0 "does macOS forward into vmnet" probe is still the right first measurement).
3. **Info-accuracy follow-through (orthogonal, cheap):** wire a failure-time tunnel capture into `traffic_test_matrix`'s failure path (reuse `collect_wireguard_tunnels` on `macos_traffic.rs:413` / `linux_traffic.rs:474`) or the `evidence_bundle()` contract from `LiveLabInfoAccuracyDesign_2026-09-03.md` — today the run answers Q1 with nothing, and cleanup destroys the state.
4. Whichever option is chosen, re-verify the appended row in `documents/operations/live_lab_node_run_matrix.csv` per §10.9, and expect `cross_os_peer_visibility` (currently `fail` on this run's row) to flip with the stage.
