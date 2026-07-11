# Live-Lab VM Connectivity Rulebook

## Purpose

Define the long-term network architecture for Rustynet VM testing. The lab must
be reproducible, hostile enough to expose security defects, observable during
failure, and honest about what each topology proves.

This document owns VM attachment policy and the network contract used by the
Rust orchestrator and MCP functions. It complements:

- [RustynetUnifiedTodoLedger_2026-07-10.md](./active/RustynetUnifiedTodoLedger_2026-07-10.md)
  — repository-wide implementation and verification roll-up.
- [LiveLinuxLabOrchestrator.md](./LiveLinuxLabOrchestrator.md) — execution.
- [CrossNetworkSimulationRunbook.md](./CrossNetworkSimulationRunbook.md) —
  deterministic NAT substrates.
- [CrossNetworkLiveLabPrerequisitesChecklist.md](./CrossNetworkLiveLabPrerequisitesChecklist.md)
  — cross-network go/no-go gates.
- [LiveLabRunMatrix.md](./LiveLabRunMatrix.md) — evidence recording.

## 1. Executive decision

### 1.1 Best long-term design

**Neither Shared-only nor Bridged-to-the-host's everyday LAN is the correct
default for Rustynet.**

The long-term default is a **dual-plane lab**:

1. A narrow, stable **management plane** for SSH, artifact transfer, monitoring,
   and recovery.
2. A separate, controlled **scenario plane** carrying Rustynet underlay,
   traversal, relay, exit, DNS, and adversarial traffic.

Each VM should have its own scenario-plane IP. Those addresses should live on
dedicated lab subnets controlled by the harness, not on the user's home,
office, hotel, or Wi-Fi LAN.

Shared remains useful for management/bootstrap. Bridged remains useful for
explicit physical-router tests. Neither is sufficient alone.

### 1.2 Why

- Shared hides or couples behavior to host NAT, host VPN, backend-specific
  bridges, and UTM implementation details.
- Bridging every guest onto the everyday physical LAN gives realistic DHCP
  addresses but weak reproducibility, exposes guests to ambient traffic, and
  leaves every peer on one L2 segment with no controlled NAT boundary.
- A network security product needs selectable NAT, routing, DNS, firewall,
  roaming, loss, MTU, IPv4/IPv6, hostile-LAN, and relay conditions.
- Security testing needs observation without giving the product a hidden
  management route it can use as an egress bypass.

NIST SP 800-125B identifies segmentation, firewall traffic control, and VM
traffic monitoring as core secure virtual-network concerns. The lab architecture
adopts those controls. See [NIST SP 800-125B](https://csrc.nist.gov/pubs/sp/800/125/b/final).

## 2. “Own local IP” is not the deciding factor

Shared guests already receive private IPs. Bridged guests receive DHCP leases
from the physical router. Neither fact proves useful Rustynet fidelity.

What matters:

- who controls the subnet and gateway;
- whether peers are intentionally same-LAN or cross-NAT;
- whether NAT/filter behavior is selectable and verified;
- whether management traffic is separated from product traffic;
- whether packet capture can prove direct, relay, exit, DNS, and leak behavior;
- whether the topology survives host roaming and restart without changing its
  meaning.

Therefore: **yes, give every VM a unique scenario IP; no, do not make the
everyday physical LAN the canonical scenario network.**

## 3. Four separate network planes

Never use “the VM network” as if it were one thing.

1. **Management plane** — host-to-guest SSH/SCP, guest-agent execution,
   monitoring, and recovery.
2. **Scenario underlay** — same-LAN, NAT, CGNAT, roaming, loss, hostile DNS,
   IPv4/IPv6, and router conditions under test.
3. **Rustynet overlay** — encrypted tunnel addresses and routes.
4. **Egress plane** — deterministic simulated internet or controlled public
   internet reached directly or through an exit.

Management reachability is not dataplane proof. Internet access is not
cross-network proof. A mesh ping is not proof of the intended direct/relay/exit
path.

Use distinct fields everywhere:

- `management_ip`
- `scenario_ip`
- `mesh_ip`
- `observed_egress_ip`
- `management_network_id`
- `scenario_site_id`
- `scenario_network_id`

The current overloaded `ssh_target`/`network_group` model cannot express this
safely.

## 4. Target VM architecture

### 4.1 NIC 0: management

Purpose: orchestration only.

Preferred attachment:

- QEMU Linux/Windows: UTM Host Only when stable automation and addressing are
  proven; Shared is the migration fallback.
- Apple macOS guest: Shared, because UTM's Apple backend currently exposes
  Shared and Bridged but not Host Only.

Policy:

- no Rustynet endpoint advertisement from this NIC;
- no Rustynet tunnel bind unless a test explicitly targets it;
- no default internet route for security-evidence stages;
- host-to-guest SSH only, restricted to the operator host address and pinned
  host keys;
- deny VM-to-VM management traffic unless a management test explicitly needs
  it;
- capture management traffic and fail on DNS, application, tunnel, relay, or
  exit traffic using this plane;
- stable MAC; runtime IP discovered, never assumed;
- management exceptions are lab-only and must be visible in evidence.

Shared traffic is routed through the host. Host VPN/proxy state can therefore
change effective guest egress and must be recorded. UTM calls Shared the
recommended general-purpose mode, not a network-fidelity guarantee. See the
official [QEMU network settings](https://docs.getutm.app/settings-qemu/devices/network/network/)
and [Apple network settings](https://docs.getutm.app/settings-apple/devices/network/).

### 4.2 NIC 1: scenario

Purpose: all Rustynet product traffic.

Policy:

- unique IP from the selected scenario subnet;
- gateway, DNS, NTP, MTU, impairment, and address family owned by the lab;
- no route to management subnets except an explicitly modeled test route;
- packet capture at endpoint and router boundaries;
- Rustynet endpoint discovery/programming must select this NIC;
- every stage asserts that no protected traffic escaped over NIC 0.

Scenario attachment depends on the profile:

- isolated same-LAN fabric;
- VXLAN site overlay;
- Linux `netns` endpoint/router topology;
- dedicated physical lab interface/VLAN;
- real remote network.

Apple's Virtualization framework supports multiple virtual NICs and both NAT
and physical-interface bridge attachments; UTM support and the selected host
interfaces still require preflight validation. See Apple's
[VZNetworkDevice](https://developer.apple.com/documentation/virtualization/vznetworkdevice)
and [VZBridgedNetworkDeviceAttachment](https://developer.apple.com/documentation/virtualization/vzbridgednetworkdeviceattachment).

### 4.3 Security-evidence mode

A management NIC can mask leaks if it remains a usable alternate default route.
Release-grade leak tests therefore use one of these modes:

1. **Out-of-band management:** QEMU guest agent/serial/hypervisor control; no
   in-band management NIC.
2. **Quarantined management:** management NIC has only a host /32 route and SSH
   allow rule; no gateway or DNS; capture proves only control traffic used it.
3. **Link-down phase:** prepare through management, bring management NIC down,
   run/capture the security stage, then recover out-of-band.

Evidence must name which mode was used. Routine dual-NIC evidence cannot be
promoted silently into stronger single-homed leak proof.

## 5. UTM attachment policy

| Mode | Canonical use | Not valid proof of |
| --- | --- | --- |
| Shared | management, builds, coarse smoke | real LAN, selected NAT, physical router |
| Host Only | QEMU management, offline tests | internet egress |
| Emulated VLAN | exceptional single-VM QEMU isolation | multi-site cross-NAT |
| Bridged to everyday `en0` | temporary physical-LAN integration | deterministic default lab |
| Bridged to dedicated lab interface | high-fidelity scenario fabric | independent remote internet |
| `netns` | deterministic NAT/security regression | separate-host/cross-OS fidelity |
| VXLAN | separate-kernel multi-VM sites | real physical-network independence |
| remote physical/cloud/cellular | final wild-deployment proof | deterministic fast CI |

Rules:

- No automatic Shared↔Bridged fallback.
- Never bridge automatically to `en0`.
- Bridged profiles must name a dedicated approved host interface.
- Physical-LAN mode is opt-in, environment-bound evidence.
- No direct `config.plist` mutation by MCP code.
- UTM changes go through a typed Rust transaction and UTM's supported
  configuration interface while the VM is stopped.
- Preserve MAC addresses unless explicit regeneration is part of the test.
- A partial multi-VM reconfiguration rolls back; it never continues.

## 6. Canonical test ladder

No one topology proves Rustynet.

### Tier 0 — pure Rust/model tests

Policy, routing decisions, signed-state validation, parsers, transition logic,
and failure-state invariants. Fastest gate. No networking claim.

### Tier 1 — `crossnet_netns_v1`

Deterministic Linux kernel NAT, firewall, conntrack, loss, and path-selection
gate. Preferred per-commit traversal/security regression profile.

Required profiles:

- port-restricted cone;
- full cone;
- symmetric NAT;
- double NAT/CGNAT once implemented;
- v4-only and native IPv6;
- loss/latency/reordering/MTU variants.

### Tier 2 — `isolated_multivm_v1`

Long-term default integration profile.

- dual-plane VMs;
- unique scenario IP per VM;
- separate endpoint kernels;
- isolated same-LAN or VXLAN-backed sites;
- router VM(s) between sites and transit network;
- deterministic DHCP/DNS/NTP/STUN/relay services;
- no dependency on the host's current Wi-Fi subnet.

This is the best routine proof for Rustynet as a network project.

### Tier 3 — `dedicated_physical_lab_v1`

VM scenario NICs bridge to a dedicated lab interface/network, never the host's
ordinary LAN by default. A controlled router/switch or Linux/OpenWrt appliance
provides site segments and public egress.

Validates:

- real L2/DHCP/router behavior;
- real NIC/driver/offload behavior;
- UPnP/NAT-PMP/PCP;
- broadcast/multicast;
- router reboot and link events.

### Tier 4 — `remote_wild_v1`

At least two endpoint sites on genuinely distinct networks plus a relay/STUN
service on a third network. Include cloud, separate home ISP, mobile hotspot or
cellular, CGNAT, IPv6, roaming, and hostile/public access conditions.

This is mandatory for “works in the wild” or release claims. A single Mac,
however sophisticated its simulation, cannot replace it.

## 7. Which profile to use

| Goal | Profile |
| --- | --- |
| Build/install/role iteration | management Shared/Host Only; no network claim |
| Same-LAN mesh and role parity | `isolated_multivm_v1` same-site variant |
| NAT/traversal regression | `crossnet_netns_v1` |
| Separate-kernel cross-NAT | `isolated_multivm_v1` VXLAN variant |
| Cross-OS coarse smoke now | Shared management + explicitly limited smoke |
| Exit/DNS/leak security proof | isolated multi-VM + quarantined/link-down management |
| Real router/UPnP/L2 | `dedicated_physical_lab_v1` |
| Release/wild claim | `remote_wild_v1` |

Shared-only is a convenience profile. It is not the long-term default evidence
profile. Bridged-to-home-LAN is a useful test cell. It is not the long-term
default topology.

## 8. Required scenario coverage

The long-term matrix must include:

- same-LAN direct path;
- distinct routed sites without NAT;
- port-restricted/full-cone/symmetric NAT;
- double NAT and CGNAT;
- relay forced, relay loss, direct failback;
- IPv4-only, IPv6-only where supported, and dual stack;
- DNS success, poisoning, outage, and leak attempts;
- hostile LAN: rogue DHCP/DNS, ARP/NDP spoof attempts, unsolicited inbound;
- MTU/fragmentation, loss, jitter, reorder, duplication, bandwidth pressure;
- address change, Wi-Fi/LAN change, sleep/reboot, router reboot;
- exit promotion/demotion, NAT residue, DNS residue;
- management-plane bypass attempts;
- host VPN/proxy on/off as an explicitly named environmental profile;
- public-internet smoke and long soak on remote networks.

Each cell must state expected direct/relay/fail-closed behavior before running.

## 9. Internet policy

Internet is not one boolean.

### Deterministic internet-in-a-box

Default for security and regression gates. Provide lab-owned:

- DNS;
- HTTP/TLS endpoint;
- STUN;
- relay;
- NTP/time-skew source;
- packet capture;
- hostile/malformed responders.

This stays repeatable, private, and failure-injectable.

### Controlled public egress

Use when testing package access, public STUN, real TLS, exit-node public egress,
or long-running internet behavior. Route through a declared lab router, not a
hidden host SOCKS proxy or host VPN unless that is the named scenario.

Record route, DNS, TCP/TLS, UDP, public egress address, host VPN/proxy state,
and packet-capture path.

### SOCKS bootstrap exception

The MCP `set_vm_internet_access` reverse SOCKS tunnel may bootstrap packages or
caches. It cannot count as Rustynet egress, exit, traversal, DNS, or leak
evidence. It must be disabled before test execution and recorded as absent.

## 10. Preflight and evidence contract

Every run selects one versioned network profile before VM readiness checks.

Preflight verifies:

- UTM version/backend and adapter count;
- mode, MAC, isolation, and bridged host interface per NIC;
- profile compatibility with QEMU/Apple backends;
- host routes, VPN, proxy, and approved lab interfaces;
- management and scenario IPs, gateways, route metrics, DNS, MTU;
- Rustynet endpoint interface selection;
- positive and negative reachability matrices;
- scenario substrate/NAT status;
- DNS/TCP/TLS and optional UDP/STUN probes;
- capture points active before mutation;
- no unapproved default route on management NIC;
- no bootstrap SOCKS tunnel during evidence stages.

Any mismatch stops before deployment or signed-state mutation.

Every run emits `state/vm_network_evidence.json` with:

- profile ID, schema version, and profile digest;
- git commit and dirty-tree state;
- UTM version;
- per-VM backend and redacted per-NIC configuration;
- management/scenario/mesh addresses as separate fields;
- host route/VPN/proxy summary;
- site, NAT, impairment, address-family, and internet mode;
- reachability matrices and internet probes;
- capture paths and leak verdicts;
- network changes/recovery actions during the run;
- final pass/fail/not-run reason.

Release evidence signs or provenance-binds this artifact. Secrets, passwords,
tokens, private keys, raw environments, and sensitive public addresses are
forbidden.

## 11. MCP integration review

### 11.1 Current answer: MCP does not enforce this architecture

Current `rustynet-mcp-lab-state` and DeepSeek MCP functions are not yet aligned:

- `start_live_lab_run` exposes no `network_profile`, NAT-profile, impairment,
  or `cross_network_substrate` argument.
- `deepseek_lab_run` builds commands with unconditional
  `--skip-cross-network`, so autonomous runs do not test traversal substrates.
- `preflight_check` checks tools, inventory, disk, power, and TCP; it does not
  validate VM adapter intent or scenario topology.
- `ensure_lab_ready` discovers/restarts/rechecks but does not select or verify a
  network profile.
- `diagnose_vm_lan_presence` treats “on physical LAN” as good and tells callers
  to bridge anything else.
- `apply_vm_bridged_network` directly changes a VM to Bridged on `en0`, restarts
  it, and refreshes inventory. It has no named profile, profile digest,
  multi-VM transaction, rollback, or evidence contract. This conflicts with
  this rulebook.
- `set_vm_internet_access` can create a SOCKS bootstrap path that would
  contaminate network evidence if left active.
- `reset_vm_network` flushes the guest nftables ruleset and stops Rustynet
  services. Any run using it must invalidate prior network/security evidence
  and re-preflight.
- MCP descriptions in `mcp/mcp.json` still advertise physical-LAN bridging as
  the repair path.

Therefore current MCP runs may use whatever attachment state happens to exist.
They do not set up the approved long-term topology.

### 11.2 Required MCP behavior

MCP should orchestrate policy, not implement a second network configurator.

Add these tools backed by typed Rust CLI operations:

```text
audit_lab_network(profile, aliases?)             # read-only
prepare_lab_network(profile, aliases?, approve_reconfigure) # explicit mutation
restore_lab_network(transaction_id)              # verified rollback
start_live_lab_run(network_profile, ...)          # verify-only; never silently mutate
```

Rules:

- `start_live_lab_run` requires or deterministically derives a profile from the
  selected test cell.
- Run launch defaults to `network_policy=verify`; drift fails closed.
- Only `prepare_lab_network` may mutate attachments.
- Autonomous loops may choose a profile but may not reconfigure VMs unless the
  caller explicitly allowed network reconfiguration for that loop.
- MCP calls the Rust CLI. Remove direct AppleScript/plist network mutation from
  MCP code.
- `ensure_lab_ready(profile)` preserves the profile; it does not “repair”
  Shared into Bridged.
- `preflight_check(profile)` returns the network evidence path and digest.
- `deepseek_lab_run` passes `--cross-network-substrate`, NAT profiles, and
  impairment when the selected target requires them; it stops unconditionally
  skipping cross-network coverage.
- `deepseek_next_live_lab_target` and the autonomous loop include required
  network profile/readiness in target selection.
- Network recovery marks the current run invalid and forces fresh preflight.
- Tool descriptions state evidence limitations explicitly.

### 11.3 Existing MCP function disposition

| Current function | Required disposition |
| --- | --- |
| `diagnose_vm_lan_presence` | replace with profile-aware read-only audit |
| `apply_vm_bridged_network` | deprecate; route explicit physical profile through Rust transaction |
| `set_vm_internet_access` | retain as bootstrap-only; prohibit during evidence |
| `diagnose_host_lab_network` | retain, but evaluate expected profile routes |
| `apply_host_route_fix` | retain as explicit recovery; invalidate/re-preflight run |
| `reset_vm_network` | retain recovery; invalidate/re-preflight run |
| `ensure_lab_ready` | require profile and verify it before/after restart |
| `preflight_check` | add full read-only network audit/evidence |
| `start_live_lab_run` | require/derive profile and pass all substrate controls |
| `deepseek_lab_run` | remove unconditional cross-network skip |

## 12. Repository changes required

### Rust CLI and profile model

- Add `crates/rustynet-cli/src/vm_lab/network_profile.rs`.
- Add typed `NetworkProfileId`, `AttachmentMode`, `ManagementPolicy`,
  `ScenarioSubstrate`, `InternetMode`, and `EvidenceTier`.
- Add reviewed manifests under `profiles/vm_lab/network/*.toml`.
- Add Rust commands:
  - `vm-lab-network-audit`
  - `vm-lab-network-preflight`
  - `vm-lab-network-prepare`
  - `vm-lab-network-restore`
- Add atomic evidence/rollback writers and negative tests.
- Make `vm-lab-orchestrate-live-lab` require/derive `--network-profile`.

### Orchestrator

- Split connection data in `orchestrator/context.rs` into management and
  scenario endpoints.
- Make `stage/preflight.rs` validate the profile digest and reachability
  matrices.
- Make `stage/cross_network.rs` consume scenario addresses, not SSH hosts.
- Bind endpoint issuance, exit egress, DNS, and captures to the scenario NIC.
- Add management-plane leak assertions to traffic and exit stages.
- Fail if a stage is skipped because its substrate was never prepared.

### Inventory and topology

- Migrate `vm_lab_inventory.json` through a Rust command, never by hand.
- Replace ambiguous `network_group` usage with separate management/scenario
  fields and site IDs.
- Keep runtime IPs as observations with timestamps, not declared intent.
- Update `vm_lab/topology.rs` and topology profiles.

### MCP

- Update `crates/rustynet-mcp/src/bin/lab_state.rs`.
- Update `crates/rustynet-mcp/src/bin/deepseek.rs` and its CLI-arg tests.
- Update `mcp/mcp.json`, `scripts/mcp/install.sh`, and MCP operator prompts.
- Add tests proving MCP cannot bridge, downgrade, or mutate without an explicit
  prepare call and approved profile.

### Substrates and evidence

- Generalize `scripts/vm_lab/vxlan_tier_b.sh` away from fixed
  `192.168.0.200-204` assumptions.
- Finish real chained `double_nat_cgnat` in the selected substrate.
- Update `LiveLabRunMatrix` code/schema with profile ID/digest, management mode,
  scenario substrate, and evidence path.
- Update the lab monitor to show profile, site, management/scenario IPs, and
  drift status.
- Sync `CrossNetworkSimulationRunbook`, prerequisites, UTM inventory runbook,
  active substrate plan, and operations indexes.

### Dedicated lab infrastructure

Long-term high-fidelity hardware target:

- dedicated host network interface, not ordinary `en0`;
- controlled router/firewall appliance or router VM;
- managed switch/VLANs where supported;
- separate endpoint sites plus transit/service segment;
- capture/mirror point;
- declared public-egress path;
- separate remote/cloud/cellular release nodes.

## 13. Change transaction and rollback

Network mutation is a security-sensitive transaction:

1. Validate profile and backend support.
2. Produce a redacted plan and current config digest.
3. Require explicit mutation authorization.
4. Stop every affected VM and prove stopped.
5. Apply all NIC changes through supported UTM configuration APIs.
6. Preserve MACs and storage.
7. Start, rediscover, configure guest routes/firewalls, and audit.
8. Write transaction/evidence artifacts.
9. If any VM fails, stop all affected VMs, restore all prior configs, restart,
   and verify rollback.

No partial continuation. No silent fallback. No automatic bridge to a physical
interface.

## 14. Current lab audit (observed 2026-07-10; non-normative)

UTM 4.6.5 currently has mixed attachments:

| VM | Backend | Attachment | Observed address |
| --- | --- | --- | --- |
| `debian-headless-2` | QEMU | Shared | `192.168.64.4` |
| `rocky_10` | QEMU | Shared | `192.168.64.22` |
| `macOS` | Apple | Shared | `192.168.65.2` |
| `debian-headless-4` | QEMU | Bridged, interface unpinned in plist | `10.230.76.58` |
| `Windows` | QEMU | Bridged, interface unpinned in plist | `10.230.76.57` |
| `Fedora` | QEMU | Bridged to `en0` | `10.230.76.59` |
| `ubuntu` | QEMU | Bridged to `en0` | stopped |

Additional findings:

- QEMU Shared and Apple Shared currently occupy separate host bridges/subnets.
- The host has multiple IPv4 addresses on `en0` and full-tunnel-style routes
  through `utun9`.
- Some inventory network labels describe older prefixes.
- MCP can currently push Shared VMs onto physical `en0`.
- Run meaning therefore depends on selected VM, current LAN, host VPN state,
  and prior MCP actions.

Do not bulk-change attachments yet. First build the read-only Rust audit,
profile manifests, MCP fail-closed checks, and rollback transaction.

## 15. Implementation handoff contract

Before migration, this contract is mandatory. Do not ask
one agent to implement every tier in one patch. Complete and verify each slice
before enabling mutation in the next slice.

### 15.1 Trust model

Trusted for local-lab evidence:

- operator host and pinned Rustynet source revision;
- UTM/hypervisor control API;
- reviewed network profile manifests;
- Rust profile validator and evidence writer;
- lab-owned router/service images after digest verification.

Potentially hostile or faulty:

- every guest workload and guest network stack;
- peer, relay, STUN, DNS, DHCP, NTP, and HTTP responses;
- physical LAN peers and routers;
- public internet paths;
- stale inventory, DHCP, ARP/NDP, routes, VPN state, captures, and prior lab
  residue;
- interrupted MCP/server/orchestrator processes.

Required invariant: a compromised guest or hostile scenario service cannot
mutate the host, another plane, another run, the profile definition, or evidence
outside its owned run directory. A single-host tier does not prove resistance
to hypervisor compromise or common-host failure; only remote tiers reduce that
common-mode risk.

### 15.2 Profile manifest minimum schema

Profiles are reviewed, versioned, secret-free TOML. Unknown fields, duplicate
IDs, unsupported enum values, unsafe paths, and incompatible backend requests
fail closed.

Minimum shape:

```toml
schema_version = 1
id = "isolated_multivm_v1"
evidence_tier = "multi_vm"

[management]
attachment = "host_only_or_shared"
internet = false
peer_to_peer = false
security_mode = "quarantined"

[scenario]
substrate = "vxlan"
address_family = "dual_stack"
internet_mode = "simulated"
require_unique_site_subnets = true

[evidence]
require_endpoint_capture = true
require_router_capture = true
require_negative_reachability = true
forbid_socks_proxy = true
```

Profiles reference inventory aliases/site roles; they never contain passwords,
private keys, tokens, or mutable runtime IPs. The parser computes a canonical
digest over the validated representation, not raw TOML formatting.

### 15.3 Canonical address plan

Address ownership must be explicit and overlap-free.

| Purpose | Canonical range |
| --- | --- |
| Rustynet mesh overlay | `100.64.0.0/10` |
| Scenario site networks | `172.20.0.0/16`, one /24 per site |
| Simulated internet/transit/services | `198.18.0.0/15` ([IANA benchmarking range](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)) |
| Documentation-only public examples | RFC 5737 ranges |
| Simulated IPv6 | stable per-run ULA; `2001:db8::/32` only for isolated documentation/test traffic |
| Management | UTM-assigned/discovered; never reused as scenario intent |

Important: the existing netns simulator uses `100.64.0.0/24` for its WAN while
Rustynet uses `100.64.0.0/10` for mesh addresses. The deterministic default
transit must move to `198.18.0.0/15` before daemon-path evidence is accepted.

`100.64.0.0/10` remains valid only in an explicit CGNAT collision/adversarial
profile. That profile must prove routing remains fail-closed despite the
real-world underlay/overlay overlap; it cannot reuse the ordinary NAT oracle.

Preflight rejects overlap among management, scenario, mesh, host routes, VPN
routes, and configured tunnel routes unless the selected adversarial profile
explicitly requires the overlap and supplies a dedicated oracle.

Address assignment rules:

- deterministic site/subnet allocation from validated profile data;
- DHCP reservation or static assignment bound to the preserved NIC MAC;
- duplicate MAC/IP detection before VM start;
- IPv4/IPv6 route and DNS ownership recorded separately;
- no stale inventory address accepted without live observation.

### 15.4 Profile resolution

- Evidence-producing runs must carry an explicit profile ID.
- A stage registry may select the profile for an autonomous target only when
  the mapping is unique, versioned, and emitted in the launch plan.
- Operator overrides must be compatible with the stage's minimum evidence tier.
- No generic fallback profile.
- A missing, ambiguous, unavailable, or incompatible profile is `not_run`, not
  pass and not skip-as-success.
- Profile ID and digest become immutable after the first stage starts.

### 15.5 Status vocabulary

- `pass`: all required positive and negative oracles executed and passed.
- `fail`: an executed required oracle failed or topology drifted.
- `not_run`: prerequisites/profile/substrate unavailable; no evidence claim.
- `not_supported`: backend capability is explicitly unavailable.
- `expected_fail`: adversarial behavior failed in the exact fail-closed manner
  declared before execution; requires its own positive diagnosis oracle.

`skipped` is internal scheduling state only. It must resolve to one of the
external states above before the run matrix is written.

### 15.6 Resource ownership, locking, and cleanup

- Acquire an atomic network lease before prepare or run.
- Lease records run ID, profile digest, VM aliases, UTM interfaces, namespaces,
  VXLAN IDs, router resources, capture handles, and owner PID/job identity.
- Concurrent runs are allowed only when every VM and network resource is
  disjoint. “Different report directory” is insufficient.
- Stale-lock recovery verifies process/job identity and observed resources
  before release; PID reuse alone is never proof.
- Every created resource has a run-scoped name/prefix and ownership marker.
- Cleanup removes only owned resources; no broad `pkill`, global nft flush, or
  wildcard deletion.
- Teardown verifies absence of owned namespaces, VXLAN devices, routes, nft
  tables, DHCP/DNS/STUN/relay processes, SOCKS tunnels, captures, and temp
  credentials.
- Cleanup failure makes the run fail and blocks the next overlapping run.

Full rollback material may contain complete UTM configuration. Store it under
an owner-only transaction directory (`0700` directory, `0600` files), outside
committed artifacts. Evidence contains only redacted fields and digests.

### 15.7 Test oracles

Daemon status is supporting evidence, not the sole path oracle.

Required where applicable:

- packet capture on endpoint management and scenario NICs;
- capture on every scenario router/transit boundary;
- fresh WireGuard/backend handshake evidence;
- route/rule/firewall snapshots before, during, and after mutation;
- direct-versus-relay destination/port oracle;
- exit public/simulated egress identity;
- DNS resolver and upstream path oracle;
- zero cleartext mesh payload/tunnel-CIDR leak;
- management-plane traffic allowlist assertion;
- residue check after role transition and teardown.

Captures are sensitive artifacts. Minimize payload, bound size/time, restrict
permissions, redact metadata in summaries, and apply the repository retention
policy.

### 15.8 Implementation slices and acceptance gates

#### Slice A — read-only profile/audit foundation

Scope:

- typed profile model and strict parser;
- UTM QEMU/Apple fixture parsers;
- host/guest observation model;
- overlap, duplicate-address, backend-capability, and drift validation;
- atomic redacted evidence writer;
- `vm-lab-network-audit` and `vm-lab-network-preflight` only.

Acceptance:

- zero VM/UTM/inventory/network mutation in tests and live audit;
- correctly identifies every currently mixed VM attachment;
- detects stale inventory and the `100.64.0.0/10` collision;
- malformed/unknown/unsafe profiles fail closed;
- unit tests cover QEMU Shared/Host Only/Bridged and Apple Shared/Bridged;
- evidence schema validates and contains no secrets;
- scoped fmt/check/clippy/tests pass.

Do not implement prepare/apply before Slice A is accepted.

#### Slice B — prepare/restore transaction

Scope:

- dry-run plan;
- explicit authorization boundary;
- atomic lease;
- stopped-VM UTM apply;
- guest route/firewall configuration;
- verified rollback and owned-resource cleanup.

Acceptance:

- fault injection after every transaction step restores the full prior state;
- interruption/restart recovery is idempotent;
- `en0` is rejected unless an explicit allowlisted physical profile names it;
- partial multi-VM application never continues;
- concurrent overlapping transactions are refused;
- full configs remain owner-only and outside committed evidence.

#### Slice C — orchestrator integration

Scope:

- explicit profile in context/report;
- management/scenario endpoint split;
- stage-to-profile compatibility;
- capture/oracle lifecycle;
- run-matrix schema update.

Acceptance:

- every stage reports the external status vocabulary;
- no substrate absence becomes pass;
- profile drift mid-run fails immediately;
- management-plane bypass test fails when deliberate test traffic uses NIC 0;
- netns default transit no longer overlaps the mesh;
- Tier 1 live evidence passes on a clean current commit.

#### Slice D — MCP integration

Scope:

- profile-aware audit/prepare/restore/run tools;
- remove direct MCP AppleScript/plist mutation;
- DeepSeek target/profile selection;
- cross-network argument propagation;
- descriptions/tests/install sync.

Acceptance:

- ordinary run tools cannot mutate network configuration;
- autonomous loops cannot prepare without explicit caller authorization;
- `deepseek_lab_run` no longer unconditionally skips cross-network stages;
- legacy `apply_vm_bridged_network` refuses or delegates only to an explicitly
  authorized physical profile;
- SOCKS presence blocks evidence stages;
- MCP reload/crash preserves transaction and lease truth.

#### Slice E — multi-VM and release tiers

Scope:

- generalized VXLAN/isolated multi-VM profile;
- cross-OS dual-plane proof;
- dedicated physical lab profile;
- remote-wild topology.

Acceptance:

- Tier 2 same-site and cross-NAT evidence pass across Linux/macOS/Windows;
- physical profile proves router/L2 behaviors without ordinary-LAN fallback;
- remote tier uses genuinely distinct networks and third-network relay/STUN;
- all evidence is current-commit-bound and indexed in the run matrix.

### 15.9 Owner decisions and ADR

This document proposes a durable architecture, not a disposable run tweak.
After owner approval, record the decision in
`documents/operations/adr/ADR-004-dual-plane-live-lab-network.md`. The ADR
should lock the four-plane model, dual-NIC target, evidence ladder, mutation
boundary, and why Shared-only/ordinary-LAN Bridged were rejected. Future
changes supersede the ADR instead of silently changing this runbook.

Owner decisions:

1. Approve the dual-plane architecture and evidence tiers.
2. Approve `198.18.0.0/15` as ordinary simulated transit and reserve
   `100.64.0.0/10` underlay use for CGNAT collision tests.
3. Approve which host interfaces may ever appear in physical profiles; ordinary
   `en0` remains denied by default.
4. Choose the long-term QEMU management attachment after a live capability
   probe: Host Only preferred, Shared fallback.
5. Confirm UTM Apple-backend multi-NIC behavior live before enabling the macOS
   dual-plane profile.
6. Approve dedicated lab-router/switch/interface acquisition when Slice E is
   scheduled.
7. Approve remote/cloud/cellular cost, provider, data-retention, and public-IP
   disclosure policy before `remote_wild_v1`.

Slice A is not blocked by hardware decisions: unsupported or unproven
capabilities remain explicit observations. Slice B cannot mutate a platform
until its management/scenario NIC capability is live-proven. Slice E cannot
claim physical/remote readiness until the infrastructure decisions are closed.

## 16. Migration order

1. Land this rulebook as policy.
2. Add read-only Rust profile/audit/evidence types.
3. Add profile-aware CLI and MCP preflight; block drift.
4. Deprecate direct MCP bridging and prohibit SOCKS during evidence.
5. Generalize VXLAN and separate management/scenario addressing.
6. Add NIC 1 scenario adapters in a controlled migration window.
7. Enforce management quarantine and packet-capture leak assertions.
8. Build dedicated physical lab network.
9. Add remote/cloud/cellular release topology.
10. Only then call the lab representative of in-the-wild deployment.
