# Cross-Network Simulation Runbook (single-host VM lab)

## Purpose

How to exercise Rustynet's cross-network data path (NAT traversal, STUN reflexive discovery, ICE pair
race, relay fallback, gossip, enrollment, anchor renumber) **without** real separate physical networks —
using only the existing single-host UTM VM lab. This is the battle-testing substrate used to wring out
defects before any move to real hardware.

It complements, and does not replace:
- [LiveLabVmConnectivityRulebook.md](./LiveLabVmConnectivityRulebook.md) — the canonical VM attachment,
  management-plane, and internet-connectivity policy.
- [CrossNetworkLiveLabPrerequisitesChecklist.md](./CrossNetworkLiveLabPrerequisitesChecklist.md) — the
  go/no-go prerequisites and the NAT-profile vocabulary.
- [active/RustynetDataplaneExecutionPlan_2026-05-18.md](./active/RustynetDataplaneExecutionPlan_2026-05-18.md)
  §4.1 (residual traversal gaps) and §D5.1 (substrate architecture, full roadmap, pass criteria).
- [LiveLinuxLabOrchestrator.md](./LiveLinuxLabOrchestrator.md) — the orchestrator the substrates plug into.

## Why a simulation substrate is needed

The original Tier-B layout put its participating QEMU VMs on one bridged L2
segment (`192.168.0.0/24`), so every VM-to-VM path was same-LAN: there was no
NAT boundary to traverse, and a "cross-network" claim against that wiring was
false. The current fleet has mixed Shared and Bridged attachments; the
connectivity rulebook owns that state and the migration target. In either
case, ordinary UTM attachment alone does not provide the selectable,
deterministic NAT matrix required here. Two hard UTM constraints (established
2026-06-11) shape the options:

1. Editing a VM's `config.plist` while UTM is running is silently clobbered from UTM's in-memory model, so
   any VM network reconfiguration requires stop → quit UTM → rewrite → relaunch → start (a full-lab
   restart per switch).
2. UTM cannot place two VMs alone on a shared isolated L2 segment, so a "client alone behind its own router
   VM" topology is not directly buildable in UTM.

The substrate is therefore four tiers (see plan §D5.1 for the authoritative description):

| Tier | Substrate | What it tests | Status |
|---|---|---|---|
| A | netns "internet simulator" in one Debian guest | Deterministic §4.1 NAT-profile matrix; CI gate | **Topology + mapping classifier built** (2026-06-11); filtering verifier added; lifecycle integration in progress |
| B | VXLAN overlay across Debian VMs (over the flat bridge) | Separate-kernel / separate-WireGuard fidelity with controllable NAT | Setup driver added; live run pending |
| C | slirp `Shared` mode for Windows/macOS guests | Coarse cross-OS traversal + relay fallback (NAT type not selectable) | Designed; not built |
| D | chaos / soak / adversarial on A + B | Churn, rebinding, renumber, replay/forged-bundle/downgrade | Designed; not built |

Real separate-network hardware remains the post-lab fidelity ceiling (plan Definition of Done §10).

## Tier A — netns internet simulator

`scripts/vm_lab/netns_internet_sim.sh` builds a complete cross-NAT "internet in a box" from Linux network
namespaces inside a single Debian guest. The NAT, routing, conntrack and (once layered on) WireGuard are
the real kernel code paths; only the wires are virtual. It is fully reproducible.

Topology (default 2 sites; `--site` adds more):

```
     ns:ep-A (10.10.0.2)                         ns:ep-B (10.20.0.2)
          | veth lan                                   | veth lan
     ns:rtr-A --+ NAT(profile)            NAT(profile) +-- ns:rtr-B
     198.18.0.11|                                      |198.18.0.12
                +------------  br:rnsim-wan  -----------+
                        (198.18.0.0/24  =  "the internet")
                                  |
                          ns:svc (198.18.0.254)
                       STUN responder + rustynet-relay
```

Each endpoint reaches the wan only through its own NAT, so the reflexive address it learns from the `svc`
STUN responder is the router's translated `(ip:port)` — exactly as on a real home network. Endpoints
cannot reach each other unsolicited; the routers' filtering rules enforce the NAT type.

**Address plan (migrated 2026-07-10):** the ordinary simulated transit now
defaults to `198.18.0.0/24` inside the canonical IANA benchmarking range
`198.18.0.0/15`; the legacy `100.64.0.0/24` WAN overlapped Rustynet's
`100.64.0.0/10` mesh range and is only valid when deliberately re-created via
`--wan-cidr 100.64.0.0/24` under the explicit `cgnat_collision_v1` adversarial
network profile (`profiles/vm_lab/network/cgnat_collision_v1.toml`), which
requires its own dedicated oracle. `rustynet ops vm-lab-network-audit` flags
any simulator source drift back to a mesh-overlapping transit. See
[LiveLabVmConnectivityRulebook.md](./LiveLabVmConnectivityRulebook.md) §15.3.

### Prerequisites on the guest

Confirmed present on `debian-headless-1` (2026-06-11): kernel modules `veth`, `vxlan`, `dummy`, `bridge`,
`sch_netem`, `nf_conntrack`; `nft` 1.1.3 (in `/usr/sbin`, available under `sudo`); kernel WireGuard
(`ip link add … type wireguard` succeeds); prebuilt `rustynetd` / `rustynet-cli` under
`/home/debian/Rustynet/target/release/`. Passwordless `sudo -n` works.

### Commands

Run on the guest as root (the script execs `nft`/`ip`, which need root; drive over SSH with `sudo -n`):

```
# build the default 2-site port-restricted-cone topology
sudo bash netns_internet_sim.sh build

# custom matrix: per site NAME:PROFILE[:IMPAIR]
sudo bash netns_internet_sim.sh build \
    --site A:port_restricted_cone:latency_50ms_loss_1pct \
    --site B:symmetric \
    --site C:full_cone

# inspect
sudo bash netns_internet_sim.sh status

# run a command inside a namespace (svc | rtr-<NAME> | ep-<NAME>)
sudo bash netns_internet_sim.sh exec ep-A -- ping -c2 198.18.0.254

# remove everything (idempotent; sweeps only rnsim-* namespaces + the rnsim-wan bridge)
sudo bash netns_internet_sim.sh teardown
```

Profiles use the same vocabulary as `apply_nat_profile.sh`: `port_restricted_cone` (plain masquerade),
`full_cone` (masquerade + DNAT of the WG/relay UDP range to the endpoint), and `symmetric` (masquerade with
randomised source ports). `double_nat_cgnat` is recognized but currently refused because the required
chained two-router site is not implemented. Impairment labels
(`latency_50ms_loss_1pct`, `latency_120ms_loss_3pct`, `loss_5pct`) attach netem to the endpoint uplink.

### What is validated today

On `debian-headless-1`, 2026-06-11:
- Build/teardown idempotent; 5 namespaces + wan bridge created and removed cleanly.
- Real SNAT translation confirmed via `/proc/net/nf_conntrack` on a router (private `10.x` →
  router wan IP).
- Endpoint isolation holds (an endpoint cannot reach another site's private address).
- Concurrent multi-site reachability to the shared `svc` node from distinct translated wan IPs.
- **NAT-reflexive (srflx) discovery** end-to-end: with `scripts/vm_lab/stun_responder.py` running in `svc`,
  an endpoint behind its NAT learns its translated public mapping (ep-A → `<rtr-A wan>:<mapped>`, ep-B →
  `<rtr-B wan>:<mapped>`; validated on the legacy transit range pre-migration). The responder speaks the exact wire format `crates/rustynetd/src/stun_client.rs`
  parses (RFC 5389 binding request/response, XOR-MAPPED-ADDRESS), so the real client consumes it unchanged.
  It is lab tooling standing in for the public STUN servers — not a Rustynet component.
- **NAT mapping-behaviour classification** (`netns_nat_classify.sh` + `nat_probe.py`): each
  `apply_nat_profile` profile produces its intended NAT type, verified by probing a single socket against two
  distinct STUN server addresses and comparing the reflexive ports (RFC 5780-style). Result on
  debian-headless-5: `port_restricted_cone` and `full_cone` are endpoint-INDEPENDENT (hole-punchable),
  `symmetric` is endpoint-DEPENDENT (relay-forced) — all as intended. This is the foundation the §4.1 matrix
  rests on: if a "cone" profile had behaved symmetrically, the traversal tests would be exercising the wrong
  NAT semantics. Pure netns + UDP, no rustynetd, so it runs safely alongside a VM's live mesh daemon.
- **NAT filtering-behaviour verification** (`netns_nat_filter.sh` + `nat_filter_probe.py`): each profile is
  checked against the three §4.1.1 cold-contact cases the mapping classifier cannot prove by itself:
  `RETURN_EXACT` (the exact STUN responder return path reaches every profile),
  `UNSOLICITED_DIFF_PORT` (full cone admits packets from a different svc IP:port, while
  port-restricted cone and symmetric block), and `COLD_INBOUND` (full cone admits a cold packet to the
  mapped WireGuard/relay port, while port-restricted cone and symmetric block). The wrapper rebuilds a clean
  topology per profile/scenario so conntrack state cannot hide the cold-inbound result. It adds
  `100.64.0.253/24` to `rnsim-svc-w` for the secondary svc sender and uses only UDP probe packets; no
  Rustynet daemon is started or stopped. **VALIDATED on debian-headless-5 2026-06-11**: all 9 cells
  (3 profiles × 3 scenarios) produce the expected matrix — `full_cone` receives in all three scenarios;
  `port_restricted_cone` and `symmetric` receive only `RETURN_EXACT` and block `UNSOLICITED_DIFF_PORT`
  and `COLD_INBOUND`.

Run the filtering verifier on the Debian sim guest:

```
sudo bash netns_nat_filter.sh
```

Expected matrix:

| Profile | RETURN_EXACT | UNSOLICITED_DIFF_PORT | COLD_INBOUND |
|---|---:|---:|---:|
| `full_cone` | receive | receive | receive |
| `port_restricted_cone` | receive | block | block |
| `symmetric` | receive | block | block |

## Tier B — VXLAN-overlay multi-VM cross-NAT

`scripts/vm_lab/vxlan_tier_b.sh` builds the separate-kernel Tier B topology without UTM network
reconfiguration, using unicast VXLAN links over whatever management underlay the five guests
share. **Underlay hosts are required inputs** (generalized 2026-07-10; the script no longer
assumes the retired `192.168.0.200-204` fleet) and the overlay follows the canonical
address plan (`LiveLabVmConnectivityRulebook` §15.3: sites from `172.20.0.0/16`,
overlay transit from `198.18.0.0/15`):

| Role | Underlay | Overlay |
|---|---:|---:|
| client A (`NODE_A_HOST`) | operator-supplied management IP | `vxlan100` `172.20.10.2/24`, gateway `172.20.10.1` |
| client B (`NODE_B_HOST`) | operator-supplied management IP | `vxlan200` `172.20.20.2/24`, gateway `172.20.20.1` |
| svc / STUN / relay (`SVC_HOST`) | operator-supplied management IP | `vxlan1` `198.18.1.254/24` |
| router (`ROUTER_HOST`) | operator-supplied management IP | `vxlan100` `172.20.10.1/24`, `vxlan200` `172.20.20.1/24`, `vxlan1` `198.18.1.11/24` |
| sim work host (`WORK_HOST`) | operator-supplied management IP | reserved for driving/capturing sim work |

Commands from the Mac host (all five host variables are mandatory):

```
NODE_A_HOST=<ip> NODE_B_HOST=<ip> SVC_HOST=<ip> ROUTER_HOST=<ip> WORK_HOST=<ip> \
  scripts/vm_lab/vxlan_tier_b.sh setup
...same env... scripts/vm_lab/vxlan_tier_b.sh status
...same env... scripts/vm_lab/vxlan_tier_b.sh run-daemon-test
...same env... scripts/vm_lab/vxlan_tier_b.sh teardown
```

The driver invokes `apply_nat_profile.sh` for both router LANs (`vxlan100/vxlan1` and
`vxlan200/vxlan1`) and then installs a combined two-LAN nftables table because the helper is currently a
single-LAN/table-reset tool. The active defaults are `PROFILE_A=port_restricted_cone` and
`PROFILE_B=port_restricted_cone`; override via `--profile-a`/`--profile-b` flags or
`PROFILE_A`/`PROFILE_B` env vars. `UDP_PORTS_A` and `UDP_PORTS_B` control the DNAT port ranges for
`full_cone` profiles.

`run-daemon-test` delegates the full two-node lifecycle to `rustynet ops run-debian-two-node-e2e`,
which handles source archive, bootstrap, membership init and add, assignment issuance, WG handshake
verification, and tunnel ping — exactly the same path the live-lab orchestrator uses. It does not
hand-mint bundles. The script runs from the Mac host; the Rust CLI drives both VMs over SSH.
Simulator processes (STUN responder on the svc node) are stopped only by recorded PID files, and
the script does not `pkill -f rustynetd`.

## Tier A pending work

Layering the rest of the real lifecycle into the topology: `rustynetd` (kernel WireGuard) in each endpoint
namespace pointed at the in-sim STUN responder via the legitimate `--traversal-stun-servers` flag, then the
full enrollment cold-contact → gossip → ICE pair race → direct-punch flow with forced relay fallback
(`rustynet-relay` in `svc`), `tcpdump` on the wan as the direct-vs-relay path oracle, and the expanded
`full_cone` / `symmetric` / double-NAT / impairment matrix. (STUN reflexive discovery — the prerequisite —
is done; see above.)

Validated frontier (2026-06-11): a real `rustynetd` started in an endpoint namespace passes config
validation, runtime-ACL checks, key-material preparation and the hardened passphrase-credential check
(`RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH`), then correctly fail-closes at the signed-trust-evidence
gate — the security bar enforcing itself inside the simulator. Bringing a node fully up therefore reuses
the operator provisioning path the live-lab orchestrator already uses
(`rustynet ops e2e-bootstrap-host` → `e2e-membership-add` → `refresh-signed-trust`) rather than
hand-minting bundles; that node-bringup helper is the next build step. The simulator drives the daemon
exactly as a human/operator would — no test-only daemon flags. Tracked in plan
§D5.1 and the §4.1 gap stages (`cross_network_cold_enroll`, `cross_network_anchor_renumber`,
`cross_network_double_nat_anchor`).

## Building-block: apply_nat_profile.sh

`scripts/vm_lab/apply_nat_profile.sh` turns a two-interface Linux host (a router netns, or a real router
VM under Tier B) into a deterministic NAT boundary for one chosen profile. It takes interface names
(`--wan-if` / `--lan-if`), so it works unchanged in a namespace or on a real NIC. Every invocation tears
down prior state before rebuilding, and records the active profile in `/run/rustynet_nat_profile`. See its
header for the full option list (profiles, `--enable-upnp` via `miniupnpd`, `--enable-v6 <prefix>` via
`radvd`, `--reset`).

## Orchestrator integration (planned)

A `--cross-network-substrate={netns,vxlan,slirp}` selector chooses the tier; the three §4.1 stages plus the
existing four cross-network stages run on whichever substrate is selected, against the requested
NAT-profile matrix, appending rows to `live_lab_run_matrix.csv` per the standard wrappers. Until that lands,
drive Tier A directly with the commands above and capture artifacts manually under
`artifacts/cross_network/<commit>/`.

## Cross-references

- [active/RustynetDataplaneExecutionPlan_2026-05-18.md](./active/RustynetDataplaneExecutionPlan_2026-05-18.md)
  — §4.1 gaps, §D5.1 substrate architecture and pass criteria, D14 coverage levers.
- [CrossNetworkLiveLabPrerequisitesChecklist.md](./CrossNetworkLiveLabPrerequisitesChecklist.md) — NAT
  profile vocabulary, go/no-go checklist.
- [LiveLinuxLabOrchestrator.md](./LiveLinuxLabOrchestrator.md), [LiveLabRunMatrix.md](./LiveLabRunMatrix.md)
  — orchestrator and evidence ledger.
- `scripts/vm_lab/netns_internet_sim.sh`, `scripts/vm_lab/apply_nat_profile.sh`,
  `scripts/vm_lab/stun_responder.py`, `scripts/vm_lab/nat_probe.py`,
  `scripts/vm_lab/netns_nat_classify.sh`, `scripts/vm_lab/nat_filter_probe.py`,
  `scripts/vm_lab/netns_nat_filter.sh`, `scripts/vm_lab/vxlan_tier_b.sh` — the substrate +
  NAT-behaviour tooling and Tier B driver.
