# macOS dataplane parity — every software route is blocked — plan — 2026-08-13

**Status: PLAN, unreviewed.** Supersedes the remedy sections of
`VmnetSplitTrafficMatrixPlan_2026-08-13.md` (whose diagnosis stands). Every claim below is a
code citation or a live measurement taken 2026-08-13.

## 0. Conclusion first

**In this lab, macOS dataplane parity cannot be reached in software.** Three routes were
proposed across two review cycles; each is independently blocked, and two of the three are
blocked by deliberate fail-closed rules that should NOT be relaxed.

The remaining routes are **dedicated hardware** or **an explicit ADR-004 amendment**. Both are
operator decisions. This plan exists so the next person does not spend another cycle
re-deriving the three dead ends.

## 1. The underlying fact

`macos-utm-1` runs on UTM's **Apple Virtualization** backend on host `bridge101`
(192.168.65.0/24). Every other guest runs on the **QEMU** backend on `bridge100`
(192.168.64.0/24). The host isolates the two: `debian-headless-2` cannot reach even the host's
own `192.168.65.1`, and `traceroute` dies at hop 1 with no reply, while
`net.inet.ip.forwarding` is already `1`.

A macOS guest cannot run under QEMU on Apple Silicon, so it cannot join the QEMU vmnet. The
split is permanent for as long as a macOS guest is in the fleet.

## 2. Route A — relay between the planes. BLOCKED (fail-closed security rule)

A relay candidate on an RFC1918 address is rejected at traversal-bundle **parse** time:

```rust
// rustynetd/src/daemon.rs:14699-14705
if matches!(candidate_type, TraversalCandidateType::Relay)
    && (v4.is_private() || is_shared_carrier_grade_nat_ipv4(v4))
{ return Err(InvalidFormat("relay candidate index {index} must not use private transport address")) }
```

Called with `?` inside the per-candidate decode loop (`:14402`), so it aborts the **entire
bundle**, not just that candidate. Every address available here is private
(192.168.8/64/65/121.x), so minting one would be worse than doing nothing: it would invalidate
the traversal bundle and break the Debian↔Debian paths that currently work.

Independently, the lab cannot express a relay candidate at all: `RELAY_SPEC` has zero hits
repo-wide and the issuer emits `relay_id: None` (`ops_e2e.rs:3728`), pinned by a test
(`ops_e2e.rs:7694`).

**Do not relax the private-address rule.** It is a §10.4 default-deny control.

## 3. Route B — dual-plane scenario NIC (`isolated_multivm_v1`). BLOCKED (capability)

ADR-004's Tier 2 profile puts product traffic on a second, lab-owned scenario NIC. The
transaction machinery for this already exists and is complete — journal, rollback snapshots,
overlap-refusing lease, verified apply (`network_prepare.rs`, 2713 lines). It does not help,
for **two independent reasons**:

1. **Host Only is not supported on the Apple backend.**
   `backend_attachment_support` (`network_profile.rs:202-210`) returns `Supported` for Apple on
   `Shared | Bridged` and `NotSupported` for everything else; `utm_mode_str`
   (`network_prepare.rs:190-196`) maps `HostOnly` only for QEMU. `derive_target_nics` derives
   the `Vxlan | IsolatedLan` scenario adapter as **Host Only** (`:730`). So the profile's
   scenario NIC cannot exist on macOS. This is a capability fact, not a proof gap — UTM's Apple
   backend offers Shared and Bridged only.
2. **Multi-NIC on Apple is `Unproven` and fails closed**
   (`backend_multi_nic_support`, `:215-220`; the guard at `network_prepare.rs:723-728`).

Reason 1 is fatal on its own: **live-proving multi-NIC would not unblock this route**, because
the mode the scenario NIC needs is unsupported regardless. An earlier reading of this plan's
predecessor treated the multi-NIC guard as *the* blocker; that was wrong and is corrected here.

Using `Shared` as the scenario mode instead is not a workaround — Apple `Shared` **is** the
isolated 192.168.65.0/24 vmnet that causes the problem.

## 4. Route C — bridge `macos-utm-1` to `en0`. BLOCKED (ADR-004, and it re-creates a solved problem)

ADR-004 (**Accepted**, 2026-07-10) §5: *"Never bridge automatically to `en0`; a bridged profile
must name a dedicated allowlisted interface."* §4 additionally confines all NIC mutation to the
typed `vm-lab-network-prepare` / `-restore` transaction with `--approve-reconfigure`; direct
plist/AppleScript mutation was deliberately removed.

The rationale is recorded and still applies. `VmLabNetworkStandard.md:14` chose Shared for
*"one internal subnet on the Mac, independent of whatever Wi-Fi/LAN/hotspot the Mac is on — not
bridged to your everyday `en0` … it was the source of the churn"*. The rulebook §1.2 adds that
bridging onto the everyday LAN gives *"weak reproducibility, exposes guests to ambient traffic,
and leaves every peer on one L2 segment with no controlled NAT boundary"*.

The code enforces the ADR rather than merely documenting it: `ScenarioSubstrate::PhysicalInterface`
bridges only to `allowed_host_interfaces.first()` and never `en0`.

## 5. What remains

### R1 — dedicated physical interface (ADR-compliant, needs hardware)

`ScenarioSubstrate::PhysicalInterface` is already implemented and is the ADR's sanctioned way to
bridge. It requires a NIC that is not `en0`, named in a profile's `allowed_host_interfaces`.

Measured: this host exposes `en1`–`en6` (Thunderbolt 1 and three "Ethernet Adapter" ports) and
**all six are `status: inactive` with no address** — nothing is plugged in. So R1 needs a USB/TB
ethernet adapter plus a switch, then a new reviewed profile naming that interface.

Cost: hardware + one profile + one prepare transaction. It is the only route that satisfies
ADR-004 unchanged.

### R2 — amend ADR-004 (operator decision)

If macOS parity matters more than the properties ADR-004 protects, the ADR can be amended to
allow a named `en0` bridge for the Apple-backend guest specifically. That is a real trade, and
the costs are the recorded ones: the guest's address becomes the home router's DHCP lease, the
lab breaks when the Mac changes network, and a lab guest is exposed to ambient LAN traffic.
**An amendment must be written into the ADR** — not applied as an undocumented exception,
which is precisely the "unmanaged mix" ADR-004 was written to end.

### R3 — accept the split and re-scope the macOS claim

macOS control-plane parity is already demonstrated (four local-posture validations pass live).
Dataplane parity would be tracked as blocked-on-hardware rather than unproven-by-neglect, and
the parity matrix would say so explicitly instead of showing a red stage with no explanation.

## 6. Recommendation

**R1 if the hardware is available or cheap to obtain; otherwise R3 with R2 held open.**

R1 is the only route that leaves every fail-closed control intact. R2 buys one green stage by
permanently degrading lab reproducibility. R3 is honest and costs nothing, but does not advance
the release-blocking parity mandate.

Not recommended under any circumstance: relaxing the relay private-address rule (§2), or
applying an undocumented ADR exception (§4).

## 7. Corrections this plan carries

- The predecessor plan proposed Route A as *"proposed"*; it is blocked. Already corrected there.
- The predecessor's Revision 2 proposed bridging one guest (Route C); that is ADR-forbidden.
  This plan supersedes that recommendation.
- Treating the Apple multi-NIC guard as the blocker for Route B was wrong: Host Only being
  unsupported on Apple is fatal first, and live-proving multi-NIC would not unblock it.

## 8. Definition of done

Either R1 lands (hardware present, profile reviewed, transaction applied, `traffic_test_matrix`
green with macOS in the topology and the mechanism confirmed by a path-evidence read outside
that stage), or R3 is recorded in the parity matrix with this document cited as the reason.
