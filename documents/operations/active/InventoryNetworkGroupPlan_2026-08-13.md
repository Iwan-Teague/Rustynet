# `network_group` is hand-maintained and silently stale — plan — 2026-08-13

**Status: PLAN, unreviewed.** Written against `HEAD = a892121c` + the macOS teardown fix, clean
tree. Every value below was read from the live inventory, the live guests, or the audit run at
that commit.

## 0. The defect, quantified

`network_group` labels which L2 a lab node sits on. Three of the twelve entries name a subnet
that does not contain the node's own recorded address:

| alias | `last_known_ip` | `network_group` | contains the IP? |
| --- | --- | --- | --- |
| `debian-headless-4` | 192.168.64.10 | `lan-192.168.0.0/24` | **no** |
| `fedora-utm-1` | 192.168.64.103 | `lan-10.230.76.0/24` | **no** |
| `macos-utm-1` | 192.168.65.101 | `lan-192.168.0.0/24` | **no** |

The audit already reports all three as `stale_network_group` errors. It has been reporting them
and nothing has consumed the report.

**Why it is stale rather than wrong-once:** nothing writes the field. `network_group` is parsed
at `vm_lab/mod.rs:34003` and read by `network_audit.rs` (62 references, all reads or test
fixtures). `--update-inventory-live-ips` — the sanctioned updater, and the reason CLAUDE.md
§12.3 forbids hand-editing the inventory — refreshes `live_ips` and `last_known_ip` and does
**not** touch `network_group`. So every time a guest's address moves, the updater silently
widens the gap between the two fields it maintains and the one it does not.

This is the repo's recurring failure shape: a hand-maintained mirror of a computable fact
(QH-07's `logical` alias, the `oracle_cross_os_column` table, the gate filters that matched zero
tests). The label is not merely cosmetic — see §1.

## 1. Why this blocks `traffic_test_matrix`

`macos-utm-1` is on **192.168.65.0/24**, served by host `bridge101` (Apple Virtualization
vmnet). Every Linux guest is on **192.168.64.0/24**, served by `bridge100` (QEMU vmnet). Measured
2026-08-13: `debian-headless-2` cannot reach `192.168.65.1` — the host's *own* address on the
other bridge — and `traceroute` dies at hop 1 with no reply. The two vmnet networks are isolated
by the host.

So mac↔Linux is, factually, a **cross-network** pair. The orchestrator cannot know that, because
the field that would tell it says `lan-192.168.0.0/24` for the mac and the same label for a node
that is actually on `192.168.64.0/24`. A correct label is the precondition for stage selection
ever routing the macOS cell through traversal/relay instead of asserting same-LAN pings that
cannot succeed.

Fixing the labels does **not** by itself make `traffic_test_matrix` pass. It makes the topology
legible so the follow-up (macOS proven cross-network) is possible. Do not conflate the two.

## 2. The change

### C1 — correct the three labels

| alias | new `network_group` | rationale |
| --- | --- | --- |
| `debian-headless-4` | `utm-shared-192.168.64.0/24` | matches its address and the four other QEMU guests |
| `fedora-utm-1` | `utm-shared-192.168.64.0/24` | same |
| `macos-utm-1` | `utm-shared-192.168.65.0/24` | **a new group** — the Apple-backend vmnet is a distinct L2 |

The macOS entry is the load-bearing one. Giving it the *same* label as the Linux guests would be
the tempting "make the audit green" move and would be a lie: it would assert same-L2 membership
for a node measured to have no path to them.

`last_known_network` carries the same stale strings on the same entries and must move with
`network_group`, or the inventory contradicts itself in a second field.

### C2 — make the label computable, so it cannot rot again

Correcting three strings fixes today and guarantees nothing. Add derivation to the sanctioned
updater: when `--update-inventory-live-ips` refreshes an entry's address, recompute
`network_group` from the observed address against the set of known lab planes, and write it in
the same pass.

Open question for review: derive the label purely from the address (`/24` containing it), or
from the address **plus the backend** (`apple` vs `qemu`)? The measured isolation is a property
of the vmnet backend, not of the CIDR — two QEMU guests on different `/24`s might still route,
while an Apple guest never joins the QEMU vmnet. §5 asks the reviewer to settle this.

### C3 — the hand-edit question

CLAUDE.md §12.3 says never hand-edit `vm_lab_inventory.json`, use `--update-inventory-live-ips`.
That rule exists for the *address* fields, and the updater cannot write `network_group` at all
today, so a literal reading leaves the field uncorrectable. Two orderings:

- **(a) C2 first**, then run the updater and let it write the labels. No hand-edit ever occurs.
  Slower, but the fix and its enforcement land together.
- **(b) C1 by hand now**, C2 after. Faster, unblocks the macOS topology work, but performs
  exactly the edit the rule forbids and sets the precedent that the rule bends.

This plan proposes **(a)**, and asks review to challenge it: (b) is defensible if the derivation
turns out to need the observed-vs-recorded distinction that only a live discovery pass provides.

## 3. Blast radius

- The audit's `off_fleet_subnet` findings are **not** addressed here and will remain. Its
  "fleet management plane" is the modal `network_group` CIDR (`network_audit.rs:850`), and with
  four libvirt nodes on `192.168.121.0/24` outvoting the local UTM guests it elects that plane
  and calls every local guest off-fleet — including the two Debians that reach each other fine.
  Correcting three labels does not change the modal outcome. Flagged, deliberately out of scope,
  and it means a green audit is **not** the acceptance signal for this change.
- No stage behaviour changes today. Nothing branches on `network_group` yet; the field is
  read only by the audit.
- Historical run rows are unaffected. This is inventory state, not evidence.

## 4. Tests, each with the mutation that proves it discriminates

1. An entry whose address falls outside its `network_group` is reported `stale_network_group`.
   *Already exists* (`network_audit.rs:2584-2604`) — cite it, do not duplicate it.
2. After C2, refreshing an entry whose address moved between planes rewrites `network_group`.
   *Mutation:* drop the recompute → the label keeps its old value and the test fails.
3. C2 never widens a group to contain an address it does not hold. *Mutation:* derive the label
   from the modal plane instead of the entry's own address → the macOS entry gets the Linux
   label and the test fails. This is the assertion that stops "make the audit green".
4. `last_known_network` and `network_group` never disagree after an update. *Mutation:* update
   one and not the other → fails.

## 5. Questions for review

1. C2's derivation input: address alone, or address + backend? Argue from the measured vmnet
   isolation, not from tidiness.
2. Ordering (a) vs (b) in C3 — is deferring the label correction behind a code change the right
   call when the macOS topology work is waiting on it?
3. Is a *new* group name for the Apple vmnet right, or should the schema express "backend" as a
   first-class field and let the group be purely a CIDR? The current label mixes both concerns
   (`utm-shared-…`, `lan-…`, `libvirt-…` are provenance, not topology).
4. Should the audit's modal-plane heuristic (§3) be filed as its own defect? It currently
   produces five false `off_fleet_subnet` errors on a lab that is behaving as designed.

## 6. Definition of done

Labels agree with measured addresses; the updater maintains them; every test above is
mutation-proven; §7 gates pass; and the §3 caveat is recorded so nobody reads a still-red audit
as a failed change.
