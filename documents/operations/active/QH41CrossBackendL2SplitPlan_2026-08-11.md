# QH-41 — the cross-backend vmnet L2 split — plan — 2026-08-11

**Status: PLAN, pre-review.** Written against `HEAD = 401a93d6`, clean tree. Every claim was
verified by reading config or measuring the host at that commit; the method is named inline
so a reviewer can re-run it rather than trust it.

## 0. What QH-41 said, and what is actually true

QH-41 as filed describes `macos-utm-1` sitting on an isolated vmnet bridge and calls it
**lab drift** — "the inventory's own `live_ips` record shows the guest used to be on the
shared network", implying someone changed a setting and it can be changed back.

**That is wrong, and it is the load-bearing error in the entry.** Measured on the host:

| VM | `Backend` | `Mode` | lands on |
| --- | --- | --- | --- |
| `macOS` (macos-utm-1) | **`Apple`** | `Shared` | `bridge101` — sole member `vmenet2`, flags `PRIVATE,VIRTIO` |
| `debian-headless-2` | `QEMU` | `Shared` | `bridge100` |
| `debian-headless-4` | `QEMU` | `Shared` | `bridge100` |
| `Fedora`, and four more | `QEMU` | `Shared` | `bridge100` (7 vmenet members total) |

**Both sides are already set to `Shared`.** The split is not a misconfiguration to revert:
UTM's Apple-Virtualization backend and its QEMU backend each get their **own** vmnet shared
network, so "Shared" names two different L2 segments depending on backend. Verified by
reading `config.plist` for each VM (`plutil -p …/config.plist`) and by `ifconfig` bridge
membership.

The repo already knows this distinction exists — `network_profile.rs:138-151` parses
attachment modes per `UtmBackend`, `:205` gates `(Apple, Shared|Bridged)`, and
`backend_multi_nic_support` (`:215-220`) records Apple multi-NIC as **`Unproven`**. What is
missing is anything that *checks* the resulting topology before a run spends 20 minutes on it.

**Therefore: changing the network mode cannot fix this, and no amount of boot-order care
fixes it either.** Boot order decides which bridge claims `192.168.64.x` versus
`192.168.65.x`; it does not merge them. The earlier handover's "boot the Debians first"
advice addresses the *addressing* symptom, not the partition.

Corroborating measurement from the implementation review of the previous item, re-stated
because it rules out the obvious workaround: host-level routing between the two bridges does
**not** work — `ping -S 192.168.64.1 192.168.65.101` is 100% loss with forwarding enabled,
because vmnet drops foreign-source packets.

## 1. What this costs today

Run `percontrol-rebaseline-20260811` spent ~10 minutes reaching `traffic_test_matrix`, failed
it, and skip-cascaded the remainder. The failure surfaced as a mesh/dataplane symptom, which
is why it was initially attributed to Rustynet rather than to the lab. Every mixed-OS run on
this host will do the same until the topology changes.

## 2. The honest split: what is an operator decision, and what is code

**The lab remedy is an operator decision with real trade-offs, and this plan does not take
it.** The options, with the reason each is not obviously right:

- **(a) Bridge the whole fleet to the physical LAN.** Puts every guest on one L2. But the
  fleet was *deliberately* migrated Bridged→Shared (192.168.64.x) by the VM connectivity
  program, and `network_prepare.rs` denies `en0` as a bridge target, so this reverses a
  considered decision and touches every guest.
- **(b) Move the Linux guests to the Apple backend** so they join `bridge101`. Linux does run
  under Apple Virtualization, but changing a VM's backend is not a setting flip — disk and
  boot configuration differ — and `backend_multi_nic_support` already records Apple
  multi-NIC as `Unproven`, which the dual-plane rulebook depends on.
- **(c) Accept that macOS cannot share L2 with QEMU guests on this host**, and prove
  mixed-OS dataplane parity on the second host (`ubuntu-kvm-1`) instead, where guests are
  KVM and share one bridge.
- **(d) Run the macOS guest bridged while the rest stay Shared.** Does not help — it would be
  on the physical LAN, still partitioned from `192.168.64.x`.

**A macOS guest cannot be moved to QEMU at all** on Apple Silicon; macOS guests require Apple
Virtualization. So (b) and (c) are the only options that keep a macOS node in a mixed-OS
mesh, and both are the operator's call.

**What IS code, and what this plan implements:** the lab currently discovers the partition
the expensive way — by failing a dataplane stage twenty minutes in, with a symptom that
misattributes the cause. That is a tooling defect independent of which remedy the operator
picks, and fixing it is worthwhile under every option above.

## 3. The change

### C1 — a preflight that fails loudly on a cross-backend L2 split

Add a check that runs in `preflight`, before any guest work, that:

1. Resolves each elected node's UTM backend from its `config.plist` (`Backend` key —
   `Apple` / `QEMU`), reusing `UtmBackend` and the parsing already in `network_profile.rs`
   rather than adding a second vocabulary.
2. Groups the elected nodes by (backend, attachment mode).
3. **Fails closed** when a run elects nodes in more than one group AND the run requires
   inter-node reachability — naming the partition, both groups, and the remedy options from
   §2 rather than a bare error.

**Fail-closed rule:** if a node's backend cannot be determined, that is a FAILURE, not a
pass. An undetermined backend is exactly the case where the check is most needed.

**Why preflight and not a dataplane stage:** the information is available before a single
guest is touched, and the whole cost of this defect is that it is currently discovered late.

### C2 — do not fail a run that does not need it

A single-platform run (all QEMU) must be unaffected, as must a run that elects one node.
`--skip-linux-live-suite` mac/win cells still need the mesh, so they are NOT exempt. The
check keys on "more than one group among the ELECTED nodes", not on the fleet.

**Deliberate:** there is no override flag. An operator who wants to run anyway can elect a
single-backend topology. A skip flag here would be a way to re-acquire exactly the silent
false-attribution this removes.

### C3 — correct QH-41's own text

The entry calls this "lab drift … the guest used to be on the shared network". It is a
backend property, not drift. The `live_ips` history it cites (`192.168.64.18`,
`192.168.0.210`) is evidence the guest has been on other networks in other configurations,
not that a setting was changed under the current one. Correct it in the same change.

## 4. What this explicitly does NOT do

- **It does not mutate any VM.** No backend switch, no mode change, no adapter edit. Those
  are §2's operator decisions and carry a real risk of losing SSH access to a guest.
- **It does not claim to fix mixed-OS coverage.** After this change, mixed-OS runs on this
  host still cannot pass a dataplane stage — they will simply say so in 30 seconds instead of
  20 minutes, and say why. That is the entire claim.
- **It does not touch `network_prepare.rs` or the dual-plane rulebook.**

## 5. Tests

1. Two elected nodes, one `Apple` and one `QEMU` → preflight FAILS, message names both
   groups. *Mutation:* make the grouping compare mode only, ignoring backend → passes → test
   fails.
2. Two elected nodes, both `QEMU` `Shared` → preflight PASSES. *Mutation:* fail on any
   multi-node run → test fails.
3. One elected node, `Apple` → PASSES (nothing to partition). *Mutation:* fail on any Apple
   node → test fails.
4. A node whose backend cannot be determined → FAILS closed. *Mutation:* default the unknown
   backend to `QEMU` → test fails.
5. The failure message names at least one concrete remedy from §2. *Mutation:* reduce it to a
   bare "topology mismatch" → test fails.

## 6. Definition of done

All §7 gates green; each test mutation-proven; QH-41 corrected in the same change; and the
plan's own central claim — that both VMs are set to `Shared` and differ only by backend —
re-verifiable by the two commands named in §0.
