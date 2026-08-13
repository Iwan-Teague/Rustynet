# `network_group` is hand-maintained and silently stale — plan — 2026-08-13

> **REVISION 2 — adversarially reviewed; C1 IMPLEMENTED, C2 re-scoped and still open.**
> The diagnosis survived. Four factual claims did not, and three of the four were wrong in this
> plan's own disfavour — they made the defect look smaller than it is:
>
> 1. **"The field is read only by the audit" was false.** `ensure_inventory_entries_share_network`
>    (`vm_lab/mod.rs:33747`) and `ensure_role_targets_share_network` (`:33770`) compare the label
>    and return `Err` before any stage runs, reached from five `--require-same-network` call
>    sites. `build_vm_lab_topology` (`:39064`) copies it into `network_id`. C1 was therefore a
>    stage-behaviour change, not a cosmetic one.
> 2. **"Nothing has consumed the report" was inverted.**
>    `ensure_orchestration_network_profile_record` (`orchestrator/native.rs:1043-1071`) reads
>    `overall_status` from the evidence file and aborts before deployment whenever the profile is
>    `enforced` — i.e. any explicit `--network-profile <id>`.
> 3. **"Correcting three labels does not change the modal outcome" was false.** It was a 4-4 tie
>    broken by string compare; C1 makes `192.168.64.0/24` win 6-4 outright and the
>    `off_fleet_subnet` set inverts. QH-42 said so first.
> 4. **Prior art existed and went uncited:** `QH41CrossBackendL2SplitPlan_2026-08-11.md` §C4
>    already proposed C1 and already predicted that the refresh path does not touch this field;
>    `UTMVirtualMachineInventory_2026-03-31.md:85-86` already documents the bridge100/bridge101
>    split, so the 2026-08-13 measurement is a re-confirmation.

**Status: C1 LANDED and verified. C2 OPEN, re-scoped.** Written against `HEAD = a892121c` + the
macOS teardown fix.

## 0. The defect, quantified

`network_group` labels which L2 a lab node sits on. Three of twelve entries named a subnet that
did not contain the node's own address:

| alias | `last_known_ip` | old `network_group` | new |
| --- | --- | --- | --- |
| `debian-headless-4` | 192.168.64.10 | `lan-192.168.0.0/24` | `utm-shared-192.168.64.0/24` |
| `fedora-utm-1` | 192.168.64.103 | `lan-10.230.76.0/24` | `utm-shared-192.168.64.0/24` |
| `macos-utm-1` | 192.168.65.101 | `lan-192.168.0.0/24` | `utm-shared-192.168.65.0/24` |

**Why it drifts:** nothing writes the field. `--update-inventory-live-ips` — the remedy CLAUDE.md
§12.3 names — writes `ssh_target`, `last_known_ip` and `live_ips` only (`mod.rs:32672-32697`). A
rule cannot govern a field its own named remedy cannot touch, which is why C1 was a legitimate
scoped data correction rather than a rule-bend.

**What consumed the stale labels:** a `--network-profile <id>` launch aborts before deployment on
a failed audit (`native.rs:1043-1071`). `rebaseline-20260813c`'s evidence recorded
`overall_status: "fail"` with the three `stale_network_group` entries as its only error findings.

## 1. Why this matters for `traffic_test_matrix`

`macos-utm-1` is on **192.168.65.0/24** (host `bridge101`, Apple Virtualization vmnet); every
Linux guest is on **192.168.64.0/24** (`bridge100`, QEMU vmnet). Re-measured 2026-08-13:
`debian-headless-2` cannot reach `192.168.65.1` — the host's *own* address on the other bridge —
and `traceroute` dies at hop 1 with no reply. Host `net.inet.ip.forwarding` is already `1`, so
this is filtering/vmnet isolation, not a routing gap.

Correct labels are the precondition for stage selection ever routing the macOS cell through
traversal/relay. **C1 does not make `traffic_test_matrix` pass**, and nothing in this plan does.

## 2. The change

### C1 — correct the three labels — **LANDED**

`last_known_network` moved with `network_group` on each entry so the two cannot disagree.
`macos-utm-1` got a *new* group deliberately: the tempting alternative — giving it the Linux
label — turns the audit green by asserting a same-L2 membership measurement disproves.

**Verified before/after:**

| check | before | after |
| --- | --- | --- |
| `--require-same-network`, `debian-headless-2 + debian-headless-4` | rejected | accepted |
| `--require-same-network`, `debian-headless-4 + macos-utm-1` | accepted | rejected |
| audit `stale_network_group` | 3 | 0 |
| audit `off_fleet_subnet` | 5 (all false) | 1 (`macos-utm-1`, true) |
| audit total errors | 8 | 1 |

The gate was inverted in **both** directions, which is why the regression test asserts both — a
single-direction test looks healthy either way.

### C2 — make the label computable — **OPEN, re-scoped**

Not address-derived. The audit's own doc comment (`network_audit.rs:846-849`) names the failure
address-only derivation would mask: a vmnet "Shared" NIC taking a real-LAN lease. Under
address-only the updater would write `last_known_ip` and `network_group` from the same wrong
address in one pass, `stale_network_group` would report clean, and the fault would be relabelled
as the truth. Backend-only is also wrong — one backend can hold several planes.

**Derive from the observed L2 segment, gated on `ProbeState::Ok`.** The input is already computed
and discarded: `extract_ip_for_mac_from_arp_output` (`mod.rs:33129`) parses
`? (192.168.65.101) at .. on bridge101` and drops the interface;
`parse_libvirt_domifaddr_candidates` (`:33174`) parses `192.168.121.100/24` and strips the
prefix. Keep them. Gate on `ProbeState::Ok` so a label is never stamped from an address that was
echoed back from the inventory (`mod.rs:7830-7835` → `:7877`) rather than observed.

Measured constraint: `macos-utm-1` lists four `live_ips` and only `192.168.65.101` is live — the
other three, including a `192.168.64.18` on the *Linux* plane, are dead. A derivation reading the
stored array would have a one-in-four chance of relabelling the mac onto a plane it cannot reach.

### C3 — keep a CIDR in every group name

`network_group_cidr` (`network_audit.rs:772-775`) takes the last `-`-delimited token and requires
a parseable CIDR; on `None` it downgrades to a *warning* and `continue`s, so `stale_network_group`
can never fire for that entry. Renaming groups to backend flavours (`apple-vmnet`, …) would make
the audit greener while making the rot undetectable. Move provenance to a separate
`network_backend` field instead, and add a test asserting every group's trailing token parses.

Note the two consumers disagree about what a group is: the audit dedupes by parsed CIDR
(`:861-870`), `ensure_inventory_entries_share_network` compares the whole string (`:33758`). No
two current labels share a CIDR, so the divergence is latent — a second reason provenance must
not live in the name.

## 3. Blast radius (corrected)

- **Stage behaviour changed**, in both directions, as tabulated in C1. Any runbook or habit that
  relied on `--require-same-network` accepting a mac+Linux pair now fails — correctly.
- **The audit's finding set inverted**, exactly as QH-42 (`QualityHardeningTodo_2026-07-25.md:1997-2003`)
  predicted. Five false `off_fleet_subnet` errors cleared; one true one remains.
- **A profile-enforced launch is still blocked**, by that one true finding. C1 replaced eight
  false errors with one real one; it did not turn the gate green, and must not be reported as
  having done so.
- Historical run rows are unaffected — this is inventory state, not evidence.

## 4. Tests

1. Real-inventory topology guard — **landed** (`mod.rs`, `real_inventory_network_groups_match_the_measured_l2_topology`).
   Asserts both directions. Verified to fail before C1 and pass after, which is the only evidence
   that it discriminates.
2. *(C2)* refreshing an entry whose L2 moved rewrites the label. *Mutation:* drop the recompute → fails.
3. *(C2)* derivation never widens a group to contain an address it does not hold. *Mutation:*
   derive from the modal plane → the mac gets the Linux label → fails.
4. *(C3)* every group's trailing token parses as a CIDR. *Mutation:* rename one to `apple-vmnet` → fails.

Dropped from Revision 1: a `last_known_network`/`network_group` agreement test. Five current
entries disagree by string equality and none is in C1's set, and `last_known_network` is read
only as a fallback when `network_group` is absent (`mod.rs:39064-39067`) — which C1/C2 guarantee
never happens. It would pin a field no live path reads.

## 5. Prior art

- `QH41CrossBackendL2SplitPlan_2026-08-11.md` §C4 — proposed C1; predicted the refresh-path gap.
- QH-42 in `QualityHardeningTodo_2026-07-25.md:1997-2003` — the modal-plane heuristic and the
  inversion. Already filed; do not file again.
- `UTMVirtualMachineInventory_2026-03-31.md:85-86` — the bridge100/bridge101 split.

## 6. Definition of done

C1: done and verified. C2/C3 remain: the updater maintains the label from the observed L2, every
test above is mutation-proven, §7 gates pass, and the surviving true `off_fleet_subnet` finding
is tracked as the macOS cross-network work rather than treated as a label bug.
