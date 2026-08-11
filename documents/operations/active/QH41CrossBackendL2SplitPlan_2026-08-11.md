# QH-41 — wire the existing network preflight into the run path — plan — 2026-08-11

**Status: PLAN (REVISION 2), pre-review.** Written against `HEAD = 5fa191f1`, clean tree.
Every claim below was produced by running the tool or reading the code at that commit; the
exact command is given so a reviewer re-runs rather than trusts.

## 0. Revision 1 was wrong, and wrong in an instructive way

Revision 1 proposed **building** a preflight that groups elected nodes by backend and fails
on a cross-backend L2 split. Before review it was discovered that this already exists — not
approximately, but exactly, and twice over:

| already shipped | what it does |
| --- | --- |
| `ops vm-lab-network-audit` | resolves each VM's backend and NIC mode, compares live addresses against the fleet plane, emits typed findings |
| `ops vm-lab-network-preflight --profile <p>` | the **read-only fail-closed gate** over the same engine — its own doc says "a run must stop before deployment or signed-state mutation"; exits non-zero |
| `--require-same-network` + `ensure_inventory_entries_share_network` (`vm_lab/mod.rs:33747`) | refuses when selected VMs span `network_group`s |

**This was the fourth consecutive time in this session that a plan proposed building
something the repository already had.** The pattern is now the finding: diagnosis has been
reliable, and the reach for new code before searching for existing code has not. Recorded
here because it is the transferable part.

The audit already states Revision 1's central conclusion, as its own repair text:

> "the attachment mode is already correct, so a mode rewrite (`vm-lab-network-prepare`)
> alone will not move it onto the fleet plane"

**So the entire remaining gap is one thing: nothing runs the gate.** Verified — no reference
to `network_preflight` exists anywhere under `vm_lab/orchestrator/`, and none in the
orchestrate path in `vm_lab/mod.rs`. The only preflight stage in the plan is
`CrossNetworkPreflight`, which is the NAT/STUN cross-network probe, a different thing.

## 1. What the gate says about this lab right now

```
rustynet ops vm-lab-network-preflight \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --profile mgmt_shared_smoke_v1
```

Exits **1**, `overall_status=fail`, 8 error findings, and correctly resolves
`macos-utm-1 backend=apple` against every other guest `backend=qemu`. Two kinds:

- **5 × `off_fleet_subnet`** — every local UTM guest, including both Debians, is off "the
  fleet management plane 192.168.121.0/24 (shared by 4 inventory nodes)".
- **3 × `stale_network_group`** — `macos-utm-1`, `debian-headless-4` and `fedora-utm-1`
  carry labels that do not contain their own recorded addresses.

**The stale labels matter beyond tidiness: they disarm the same-network gate that does
exist.** `debian-headless-4` (192.168.64.10) and `macos-utm-1` (192.168.65.101) both carry
`lan-192.168.0.0/24`, so `--require-same-network` would *affirmatively certify* two guests on
different bridges as same-network — while failing the two Debians that genuinely share a
bridge, because `debian-headless-2` carries a different label. Enabling that flag against
today's metadata is worse than leaving it off.

## 2. The problem this plan has to solve, not dodge

**Wiring the gate as-is blocks every run on this host, today.** All five local UTM guests are
`off_fleet_subnet`, so a hard gate refuses even an all-Debian run — and the two Debians
demonstrably *can* reach each other (both on `192.168.64.x`; the 2026-08-11 run bootstrapped,
distributed bundles and passed 15 stages across them).

It would also have refused run `percontrol-rebaseline-20260811` at preflight — the run that
produced the **first-ever population of 16 per-control security columns**, which had gone
unrecorded across the previous 106 runs. A gate that would have destroyed the only new
evidence in months is not obviously an improvement, and this plan must not pretend otherwise.

The resolution is **scope**, not severity. The gate currently judges the whole inventory; a
run only needs the nodes it elects to be able to reach each other.

## 3. The change

### C1 — run the gate over the ELECTED nodes only

Invoke the existing engine from `preflight`, restricted to the aliases this run elects.
`debian-2 + debian-4` → both on `192.168.64.x` → PASS. `debian-2 + debian-4 + macos-utm-1` →
spans two vmnet L2s → FAIL, before a single guest is touched.

The "fleet management plane" is derived by majority across the inventory, which the four
remote KVM guests dominate. Scoping to elected nodes removes that dependence entirely: the
question becomes "can these nodes reach each other", which is the question the run actually
depends on.

### C2 — per-finding disposition, not one verdict

- **`off_fleet_subnet` among elected nodes, spanning more than one L2** → **FAIL**. This is
  QH-41 exactly, and it is fatal to the run.
- **`off_fleet_subnet` where all elected nodes are on ONE segment** (even if that segment is
  not the inventory-majority plane) → **PASS with a recorded note**. They can reach each
  other; that is what matters.
- **`stale_network_group`** → **WARN, never fail.** It is a metadata defect. Failing a run
  because a label is stale would block work for a reason that has no bearing on whether the
  nodes can talk — and the label is exactly what should not be trusted.
- **findings about non-elected VMs** → ignored for gating, recorded in the artifact.

### C3 — fail-closed on undetermined, with one bounded exception

If an elected node's segment cannot be determined, **fail**. The exception, which must be
explicit rather than incidental: a node with **no local UTM bundle** (a remote KVM guest
reached over libvirt) has no local config to read, and failing those would block every
mixed-host run. Those are **not gated** and are named in the artifact as ungated. That
exception is a known hole, and stating it is the point.

### C4 — fix the three stale labels

Correct them from the observed addresses so `--require-same-network` stops being actively
misleading. The inventory must not be hand-edited (§12.3), so this goes through the
supported refresh path; if that path does not update `network_group` — it appears not to —
say so and treat it as a separate defect rather than hand-editing.

## 4. What this does NOT do

- **No VM is mutated.** No backend switch, no NIC re-creation, no MAC regeneration. Those are
  the audit's own repair instructions and they are the operator's call — with a real risk of
  losing SSH to a guest.
- **It does not make mixed-OS runs work.** After this, a mixed-OS run fails in ~30 seconds
  with the reason instead of ~20 minutes with a misleading dataplane symptom. That is the
  whole claim.
- **No new detection logic.** Every finding used here already exists.
- **No override flag.** An operator who wants to run anyway elects a single-segment topology.

## 5. Tests, each with the mutation that proves it discriminates

1. Two elected nodes on one segment → PASS. *Mutation:* gate on the inventory-majority plane
   instead of the elected set → fails (both Debians are off that plane).
2. Elected nodes spanning two segments → FAIL, message naming both nodes and both segments.
   *Mutation:* compare `network_group` labels instead of observed addresses → passes, because
   the two stale labels match.
3. `stale_network_group` alone → PASS with the warning recorded. *Mutation:* treat every
   error finding as fatal → fails.
4. One elected node → PASS. *Mutation:* fail on any run whose nodes are off the majority
   plane → fails.
5. An elected node with no determinable segment and a local bundle → FAIL. *Mutation:*
   default unknown to "same segment" → fails.
6. An elected remote (non-UTM) node → not gated, named ungated in the artifact. *Mutation:*
   gate it → fails.

## 6. Definition of done

All §7 gates green; every test mutation-proven; QH-41 corrected to say the detection exists
and only the wiring was missing; and the two commands in §0/§1 re-runnable by a reviewer to
reproduce the measurements this plan rests on.
