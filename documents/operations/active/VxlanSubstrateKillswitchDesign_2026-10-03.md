# Vxlan cross-network substrate versus the node killswitch (2026-10-03)

**Status.** OWNER ANSWERS RECEIVED 2026-10-03 (chat), CONDITIONAL ON AN INDEPENDENT SECURITY REVIEW BEFORE IMPLEMENTATION. The owner answered the four questions below: (1) approve the two default-empty `substrate_transit` daemon config fields: yes; (2) approve the egress-anchoring rule that ignores Rustynet-owned overlay interfaces, with its charter re-review: yes; (3) keep `baseline_lan` flat: yes (keep); (4) authorise the interim fail-loud preflight in the lab tool: yes. The owner's standing conditions for the work: the project must stay secure (fail-closed, no weakening of the killswitch), and it must stay easy to use with a good user experience (secure by default, never expert-only to set up, no new manual steps for users). Nothing is implemented yet: the design goes through an independent security and usability review first (record: charter/reviews/REVIEW-vxlan-substrate-transit-design-2026-10-03.md when it exists), and the implementation lands only if that review confirms the approvals are the best way to meet the conditions, or lists what must change.

Written by fleet lane b93 from the live lab runs lenovo-u38, u38b and u38c. Where it fits: the eight `cross_network_*` stages (see CrossNetworkSuiteCoverageGap_2026-09-30.md) need the vxlan substrate. The lenovo-bot lab provides client and exit management addresses in different /24s, and the substrate provisions (`provisioned=true`, three overlay nodes), but the mesh stages fail because of the conflict described below. Two related daemon defects were fixed separately: the unbounded killswitch rule growth (landed in d98b8a8c2) and, here, the QH-60 refusal.

---

# Lane rustynet-b93-vxlan-substrate-vs-killswitch-design — DECISION

Date: 2026-10-03. Repo `wt/submodule-migration` @ 91451f6a8 (rustynet submodule same sha). Design lane: no code changed.

## Question

Why does `--cross-network-substrate vxlan` + `baseline_lan` wedge lab mesh stages (u38/u38b/u38c on lenovo-bot), and which coexistence design should land: (a) router-namespace placement for baseline_lan, (b) orchestrator-installed narrow UDP 4789 allowance via existing daemon knobs, (c) daemon-side lab exemption?

## Root cause (one paragraph)

`DaemonConfig.egress_interface` is a single field serving four incompatible roles: (i) WG listen-port allowances (`wg_listen_port_allow_tokens`, phase10.rs ~2460, emitted ~3303–3340, hardbound to the field), (ii) management-bypass anchoring + QH-60 (`ensure_management_bypass_anchored` ~1834, "management must never be pinned to another link"), (iii) traversal bootstrap pinholes (`traversal_bootstrap_allow_rule_args` ~3085, oifname-bound), (iv) forward tunnel→egress tokens + fail-closed scope. The vxlan substrate makes the WG dataplane ride a rustynet-owned overlay link (`rustynet-vx0` flat / `rustynet-vxl` router-ns) while management + underlay live on `eth0`, so (i)≠(ii,iii,iv) **by construction**. The installer then pins the overlay link as egress (`ops_install_systemd.rs:1797` via `ip route get <endpoint>`; substrate.rs:1775–1783 even documents that "the overlay is what causes it to be written wrong" and only reverts the pin at teardown, substrate.rs:1789). Observed on u38c (run ff30f27499): egress=`rustynet-vx0` → STUN pinhole misanchored to vx0 (192.168.0.1 is on eth0), WG 51820 allows on vx0, **no UDP 4789 allowance anywhere** (encapsulation out eth0 dropped, fail-closed drop counter 1079 pkts), and QH-60 refuses full-tunnel engage ("no management CIDR overlaps a connected prefix on rustynet-vx0") → node stuck `restrict_recoverable` → mesh_status_validation FAIL, traffic_test_matrix FAIL 100%.

## Candidate dispositions

- **(b) as stated — REFUTED.** No existing daemon knob emits a UDP 4789 allowance. The only endpoint-scoped pinhole knob (`traversal_bootstrap_allow_endpoints`, phase10.rs:1426/1527) renders `oifname <egress_interface>` rules: with egress=vx0 it can never match the eth0 underlay; with egress=eth0 the same oifname binding then misplaces the hardbound WG 51820 allow (mesh dies differently) and QH-60 still refuses under egress=vx0. No harness-only config satisfies roles (i)+(ii) simultaneously; the CIDR-quorum dodge (adding the overlay prefix to `fail_closed_ssh_allow_cidrs`) is worse: unanchored real-mgmt CIDRs get on-link `dev vx0 table 51820` bypass routes → SSH replies policy-routed into the vxlan → management black hole (the exact wrong-link failure QH-60 exists to prevent).
- **(a) — REJECTED as primary fix.** Moving vx0 into `rustynet-vxr` for baseline_lan does fix the 4789-drop class-wide (nftables is netns-scoped; encapsulation leaves the killswitch's namespace) and would make baseline uniform with the NAT profiles. But it breaks the CN-4 contract text ("baseline_lan builds no router namespace" — substrate.rs:1436 refusal reason; substrate.rs:1396–1397 documents baseline as "exactly what setup builds: a flat, routable overlay"), changes guest L2 overlay semantics to L3 site-LAN addressing, and **still requires the same daemon change**: egress becomes `rustynet-vxl`, which carries no management connected prefix → QH-60 refuses identically, and the WG listen allow anchoring problem is unchanged.
- **(c) — REJECTED.** A lab exemption weakens the fail-closed posture (AGENTS.md §3, SecurityMinimumBar). Non-negotiable per b91: a management CIDR that reaches nothing must still refuse.

## DECISION — orchestrator-attested substrate transit allowances (refined (b))

Adopt the intent of (b), acknowledging existing knobs cannot express it; it needs **two narrowly-scoped, default-empty daemon config fields** plus the b91 Defect-B anchoring rule — all installed by the orchestrator, which is the only component that knows the topology it built:

1. **`substrate_transit` (new optional daemon config, default = absent → zero behavior change).** The orchestrator (rustynet-cli) attests, at substrate provisioning time: `underlay_interface` (the physical iface carrying the route to peer underlay IPs, excluding rustynet-owned links — here eth0), `underlay_port` (4789), `overlay_interface` (rustynet-vx0 flat / rustynet-vxl router-ns), `dataplane_port` (the WG listen port). The daemon renders ONLY: `udp dport/sport 4789` allowances on `underlay_interface`, the existing WG listen-port allowance re-anchored to `overlay_interface`, peer-endpoint /32 pins (table 51820) following `overlay_interface`, and a forward accept `iifname <tunnel> oifname <overlay_interface>` — every rule exact-iface, exact-port, comment-tagged `rustynet_substrate_transit`. No state-machine change, no exemption, no posture relaxation.
2. **Egress anchoring rule (b91 Defect-B option 2, unchanged):** egress-interface selection/derivation for management anchoring excludes rustynet-owned overlay interfaces and falls back to the underlay iface holding the main-table default route. QH-60 semantics untouched; with egress=eth0 the STUN pinholes and forward→egress tokens anchor correctly, and management anchoring succeeds.

This satisfies all four roles simultaneously: (i) WG allow on vx0/vxl where the dataplane actually rides, (ii) QH-60 on eth0, (iii) pinholes on eth0, (iv) forward tokens to both eth0 (underlay) and the overlay link (transit).

## Implementation status in this lane

**None.** The decision is not local+safe: it is a rustynetd firewall-emitter + config-surface change (security-adjacent, requires Linux gates, charter review of the anchoring rule, and a live-lab proof with guests ON — currently shut off per lane constraints). A rustynet-cli-only partial fix is proven impossible (above). Optional interim hardening (rustynet-cli-only, fail-loud): a provisioning-time refusal when the substrate would pin a rustynet-owned iface as egress under an enforcing daemon — deferred to an owner decision below because it would also refuse the NAT profiles whose behavior under the killswitch is unproven.

## Falsifiers for this decision

- A lab run with the transit-attestation knobs installed where the mesh still shows handshake `none` while `nft list ruleset` contains the exact `rustynet_substrate_transit` rules → the allowance model is wrong (e.g. additional chain/hook drops encapsulation).
- Evidence that a NAT-profile run (`port_restricted_cone` etc.) passes mesh stages today with the killswitch engaged → the wedge is baseline-specific and (a) alone might suffice, weakening the case for new daemon fields.
- A harness-only env/config combination (no daemon change) under which all four roles anchor correctly on u38c's topology → refutes the four-role impossibility claim.

## Owner decisions requested

1. Approve the `substrate_transit` daemon config surface (two new default-empty fields) as a charter-compliant alternative to a lab exemption?
2. Approve the b91 Defect-B anchoring rule (exclude rustynet-owned ifaces from egress derivation) for implementation together with (1), including the charter re-review it implies?
3. Should `baseline_lan` keep its CN-4 flat contract (recommended), leaving router-namespace placement to the NAT profiles only?
4. Authorize the interim rustynet-cli fail-loud preflight (refuse substrate provisioning that pins a rustynet-owned egress under an enforcing daemon) before the daemon change lands — accepting it will also block NAT-profile runs until (1) lands?
