# macOS Exit Membership Role Fix — Design (2026-08-31)

**DESIGN ONLY — trust-state change, requires human security review + owner sign-off before implementation.**
This document proposes no code change. Every claim cites file:line from the tree at
HEAD `690fc35b` (the same tree the investigation
`MacosExitDnsFailclosedRoleSplitInvestigation_2026-08-31.md` was written against).
Parent investigation: `MacosExitDnsFailclosedRoleSplitInvestigation_2026-08-31.md`
(henceforth "the Investigation"). Related: `MacosDnsFailclosedEnforcementGap_2026-08-28.md`,
`MacosDnsFailclosedAdversarialReview_2026-08-31.md`,
`CrossPlatformRoleParityRefresh_2026-07-23.md` ("the Refresh").

## 0) Decision summary

The macOS exit node's OWN signed membership entry must carry exactly
`{blind_exit, exit_server}` — the product capability grant for a macOS exit
(`crates/rustynet-cli/src/vm_lab/orchestrator/role.rs:186-189`) and the daemon's
required set for the `blind_exit` role
(`crates/rustynetd/src/daemon.rs:2164-2165`) — instead of the anchor genesis set
it inherits today (`crates/rustynetd/src/main.rs:4469-4479`).

**Chosen layer: post-genesis, owner-signed capability rewrite at the orchestrator
membership adapter, using the EXISTING hardened signed-update op
`ops e2e-membership-set-capabilities` (`crates/rustynet-cli/src/ops_e2e.rs:2596-2700`).**
No product signed-membership semantics change; no daemon change; no genesis
change. Rationale in §1.3, adversarial review in §3, rejected alternative in §4.

## 1) The fix precisely

### 1.1 The provisioning chain today (verified, file:line)

1. **Lab role mapping (platform-split).** `NodeRole::daemon_node_role_for_platform`
   maps lab `Exit` → daemon `admin` on Linux/Windows
   (`crates/rustynet-cli/src/vm_lab/orchestrator/role.rs:136`) but → `blind_exit`
   on macOS (`role.rs:159-160`), with the macOS product capability grant
   `{BlindExit, ExitServer}` (`role.rs:186-189`) and the Linux exit grant
   `{Client, Anchor, ExitServer, RelayHost, AnchorEnrollmentEndpoint}`
   (`role.rs:202-218`).
2. **Genesis membership is anchor-carrying on every platform.**
   `rustynetd membership init` hard-wires the genesis node's own entry to the
   full anchor set + sub-caps + `Client/ExitServer/RelayHost`, epoch 1
   (`crates/rustynetd/src/main.rs:4459-4492`; capability list at :4469-4479;
   deliberate role-agnostic bootstrap rationale in the comment at :4448-4458:
   "the daemon can start with any role mapping before the orchestrator
   distributes the real multi-node membership"). The `membership init` argv
   surface has **no** role or capability flag
   (`main.rs:4242-4330` — only `--snapshot/--log/--watermark/--owner-signing-key/
   --owner-signing-key-passphrase-file/--node-id/--network-id/--force` plus the
   D4 gossip-secret pair).
3. **`ops init-membership` does not forward the role either.**
   `execute_ops_init_membership` (`crates/rustynet-cli/src/main.rs:13781-13909`)
   validates `RUSTYNET_NODE_ROLE` ∈ {admin, client, blind_exit} (:13787-13792)
   and gates blind_exit to Linux/macOS hosts (:13793-13800), but the spawned
   `rustynetd membership init` command carries only
   snapshot/log/watermark/owner-key/passphrase/node-id/network-id/force
   (:13867-13886). The role value is used solely for
   `maybe_remove_blind_exit_owner_signing_key` (:13897-13901). So a blind_exit
   node provisioned through this path mints an **anchor-carrying** genesis —
   the exact mismatch.
4. **Both membership adapters skip the exit's own entry.**
   `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_membership.rs:248-251`
   and `adapter/linux_membership.rs:75-78` (`if peer.role == NodeRole::Exit {
   continue; }`). The Linux skip is *correct*: the Linux exit maps to daemon
   `admin` (`role.rs:136`) whose required capability is `Anchor`
   (`daemon.rs:2161`) — genesis aligns by construction. The macOS skip is the
   defect.
5. **The platform grant is computed but never applied to the exit's record.**
   `stage/membership_init.rs:108-111` computes
   `product_capabilities_for_platform` per peer into `NodeMembershipPeer`
   (:131-138), but the macOS adapter consumes `peer.capabilities` only for
   non-exit peers (`macos_membership.rs:269`).
6. **The daemon enforces the mismatch, fail-closed.**
   `validate_node_role_membership_alignment` (`daemon.rs:2262`): missing
   required caps on a blind_exit node warn-and-continue (:2277-2290); a
   blind_exit node whose membership *carries* `Anchor` hard-rejects with
   `blind_exit role cannot use membership carrying anchor capability`
   (:2302-2304), called from membership bootstrap replay at :5308. The daemon
   sits in restricted safe mode; `apply_dns_protection`
   (`crates/rustynetd/src/phase10.rs:4557`, invoked from the bootstrap apply at
   `daemon.rs:8767-8793`) never runs; the baseline `DnsFailclosed` probe then
   observes the unpinned resolver posture and fails
   (Investigation §b, §c step 5).

### 1.2 The change

In `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_membership.rs`
`init_membership_snapshot` (:232-...), after the genesis `ops init-membership`
call (:241-245) and **before** the per-peer adds (:248-...) and the snapshot
read-back (`membership_snapshot_readback_script`, :221-230), the adapter issues
one additional remote command for the exit peer:

```
sudo -n env RUSTYNET_SIGNING_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT='trust-passphrase-<exit_node_id>' \
     '<MACOS_RUSTYNET_PATH>' ops e2e-membership-set-capabilities \
         --node-id '<exit_node_id>' \
         --capabilities 'blind_exit,exit_server' \
         --owner-approver-id '<exit_node_id>-owner'
```

Concretely:

- Add a `exit_capability_rewrite_script(exit_node_id) -> Result<String, AdapterError>`
  builder next to `peer_add_script` (:180-205), reusing the same
  `shell_safe_arg` and MAC-D11 keychain-account env plumbing
  (:191-196, :198) that the peer-add path already uses.
- Call it from `init_membership_snapshot` for the exit peer (the same peer the
  loop currently `continue`s past at :249-251). The capabilities string MUST be
  derived from `NodeRole::Exit.product_capabilities_for_platform(&VmGuestPlatform::Macos)`
  (`role.rs:186-189`) via the existing `role_capability_csv` helper — never a
  hand-typed CSV at the call site — so the provisioning grant and the product
  grant cannot drift.
- `linux_membership.rs` is NOT touched: its exit legitimately keeps the anchor
  genesis set (§1.1 step 4).

`ops e2e-membership-set-capabilities` already implements the entire
trust ceremony and is root-gated
(`crates/rustynet-cli/src/main.rs:5669-5673` argv; `ops_e2e.rs:2596-2700`
execution): it stages membership-state permissions (:2622, restore :2680-2683),
runs `membership propose-set-capabilities` (:2624-2642), `membership
sign-update` with the owner approver key and passphrase file (:2643-2661), and
`membership apply-update` (:2662-2676), then emits a capability audit entry
(:2677, `emit_anchor_bundle_pull_capability_audit` :2702-...). The signature
chain — record built from the current snapshot, signed by the owner key,
applied with epoch/replay checks — is the canonical signed-mutation pipeline
this repo already trusts for e2e provisioning.

**Idempotency (required).** `init_membership_snapshot` runs on re-used guests
and is documented idempotent (`linux_membership.rs:52` "idempotent if already
done"; the CLI short-circuits when files are present,
`main.rs:13846-13857`). The rewrite must therefore read the snapshot first and
skip the rewrite when the exit's canonical capability set already equals
`{blind_exit, exit_server}`; re-running `apply-update` with an unchanged state
root is not a replay (`crates/rustynet-control/src/membership.rs:1556-1557`)
but a needless epoch bump. The read-back helper
(`membership_snapshot_readback_script`, :221-230) already returns the
base64'd snapshot; reuse it (or read the genesis snapshot once, decide, then
read back again after the rewrite).

**CORRECTION 2026-09-05 (found by the implementation's in-process test, missed
by both reviews):** "needless epoch bump" understates it. The membership
reducer REFUSES any `SetNodeCapabilities` whose target node already carries
`blind_exit` — `reduce_membership_state`
(`crates/rustynet-control/src/membership.rs`, SetNodeCapabilities arm: "blind_exit
is immutable; factory reset and fresh enrollment are required to change
capabilities", the RT-2 / SecMinBar §6.D.2 immutability gate). So on a re-used
guest whose record is already canonical, re-issuing the rewrite would not bump
the epoch — it would HARD-FAIL `membership_init` at propose time. The
read-and-skip guard is therefore a correctness requirement, not an
optimisation. Two further consequences: (1) the rewrite is one-way at the
membership layer — once the exit's record carries `blind_exit`, no signed
`SetNodeCapabilities` can ever change it again (only `RemoveNode` +
`AddNode` under a fresh identity, i.e. factory reset), which is exactly the
§2.4 one-way-door property, now confirmed to hold at the trust boundary and
not only in the CLI planner; (2) the §3c/QH-65 exploit is reachable only by
ENTERING blind_exit with an over-wide set (an `AddNode` carrying
`{blind_exit, exit_server, relay_host}`, or one `SetNodeCapabilities` from a
non-blind record straight to that set) — not by widening an existing
blind_exit record. Pinned by
`owner_signed_set_capabilities_narrows_anchor_genesis_to_blind_exit_pair_at_epoch_two`
in `membership.rs`.

### 1.3 Why THIS layer (and not the alternatives)

Three candidate layers were weighed (Investigation §e sketches two of them):

**A. Adapter-level post-genesis rewrite (CHOSEN).**
- Zero product-code change: every touched line sits in the `vm-lab`-gated lab
  orchestrator (RNQ-17 — the shipped release binary carries none of it).
- It does NOT bypass signed-membership semantics; it *uses* the existing
  owner-signed, epoch-bumped, replay-checked update pipeline
  (`ops_e2e.rs:2624-2676`). The exit's entry is never mutated outside a signed,
  owner-approved update — exactly the control `SecurityMinimumBar.md` §6.C
  demands ("an anchor cannot self-promote — capability changes require an
  owner-signed membership bundle").
- The genesis contract stays intact. The genesis anchor set is deliberate:
  role-agnostic bootstrap so the daemon can start under any role mapping before
  the real membership distributes (`rustynetd main.rs:4448-4458`). Narrowing
  genesis would couple the guest's first boot to one role.

**B. Thread a capability override through `ops init-membership` → `rustynetd
membership init` (e.g. a `--genesis-capabilities` flag, or deriving genesis
caps from `RUSTYNET_NODE_ROLE`).** Rejected for this fix, recorded as follow-up:
- It changes what the FIRST signed snapshot contains — a product
  signed-membership provisioning semantic change that needs its own
  design+review cycle (the Investigation classifies this path as "product
  security-sensitive", Investigation §e).
- It weakens the role-agnostic bootstrap property the genesis comment
  documents (`main.rs:4448-4458`): a blind_exit-genesis node could no longer
  boot once as `admin`/`anchor` on a re-election, because `admin` hard-requires
  the `Anchor` capability (`daemon.rs:2161`, enforced at :2291-2295) while
  blind_exit missing-caps only warns (:2283-2290). The asymmetry is
  load-bearing for the lab's re-provision cycle.
- **However**, there is a real product-level inconsistency hiding here that
  this design surfaces rather than fixes: `ops init-membership` ACCEPTS
  `blind_exit` today (`main.rs:13788-13800`) yet mints anchor genesis caps
  (:13867-13886 forwards no role), so a non-lab operator provisioning a
  blind_exit node gets the same fail-closed daemon the lab hit. A follow-up
  product design (role-aware genesis, or init-membership refusing blind_exit
  until genesis is role-aware) should be scheduled separately. This design
  does not smuggle that change in.

**C. Change the genesis default (drop anchor from `main.rs:4469-4479`).**
Rejected outright: it breaks every non-exit node's documented reliance on the
bootstrap set (comment :4450-4454 — "Without Client capability here, every
non-exit node fails its `validate_node_role_membership_alignment` preflight at
first boot (exit 65)") and breaks live_anchor's reliance on the genesis
sub-caps (:4455-4458). Largest blast radius, no offsetting benefit.

### 1.3.1 Independent review correction (2026-09-05) — §1.3's rationale is wrong in two places, and the mechanism has an undisclosed dependency

An independent security review (Fable 5.1, grounded against the tree at
`a272b896`) found that §1.3-B's rejection rationale rests on two claims that do
not hold on this tree, and that the CHOSEN mechanism (§1.3-A) has a real,
previously undisclosed dependency. **Approved as an INTERIM fix with the
corrections below; the review's Option D (§1.3.2) is the ledgered target.**

**Correction 1 — the "role-agnostic bootstrap" property §1.3-B invokes to
reject genesis changes is already false.** `main.rs:4498-4501`'s own comment
says genesis grants the anchor set "so the daemon can start with any role
mapping" — but `daemon.rs:2397-2398` hard-rejects `blind_exit` on exactly that
genesis. **The bug this design fixes IS that property failing for
`blind_exit`.** §1.3-B's rejection of a genesis-aware alternative because it
would "weaken" this property is circular: the property is already broken for
the one role this design is about.

**Correction 2 — §1.3-B calls the admin/blind_exit missing-caps asymmetry
"load-bearing."** The project has already adjudicated the analogous
warn-and-continue exception the opposite way: `daemon.rs:2410-2412` states
plainly that exception "is not precedent." §1.3-B's rationale leans on a
pattern the codebase's own comments flag for eventual removal (see §3c's
revision below).

**Undisclosed dependency (F1) — the fix only works because the adapter lies
about the node's role during provisioning, and that lie has a real security
consequence.** `macos_membership.rs` passes `RUSTYNET_NODE_ROLE=admin` to
`ops init-membership` for this node (a node that will actually run daemon role
`blind_exit`). This is necessary: `ops init-membership` deletes the owner
signing key from any node correctly declared `blind_exit` at provisioning time
(`maybe_remove_blind_exit_owner_signing_key`, `main.rs:13941-13962`, called at
`:13851`/`:13901`), and the capability-rewrite mechanism in §1.2 REQUIRES that
key still be present on disk to sign its own follow-up update
(`ops_e2e.rs:2672, 2708-2711` sign with `paths.owner_signing_key`) — as do the
existing per-peer `e2e-membership-add` calls. Declaring `admin` instead of
`blind_exit` at provisioning time is what keeps the key from being deleted.

**Consequence, stated plainly:** after this fix runs, the macOS exit's SIGNED
RECORD correctly says `{blind_exit, exit_server}` with no anchor authority —
but the node's disk still holds the one signing key that can mint ANY
capability for ANY node in this mesh (genesis makes this node the sole
approver, `quorum_threshold: 1`, `main.rs:4533-4540`). **§2.3's "strictly
narrowing" claim is true of the signed record and false of the node's actual
capability** — a compromised exit host under this scheme retains the physical
ability to re-mint itself (or any node) full anchor authority, which is
exactly the class of escalation `blind_exit` exists to make structurally
impossible. This must be treated as a known, disclosed limitation of the
INTERIM fix, not silently accepted as "strictly narrowing" without
qualification — see §2.3's revision below.

**Also found, present-tense not future-tense (revises §3c):** the blind_exit
exact-set validator gap §3c defers as a hypothetical future risk is
exploitable TODAY — `{blind_exit, exit_server, relay_host}` (or `+ client`)
passes both the membership-format layer (`membership.rs:2668-2757` has no
blind_exit⊕relay_host or ⊕client rule) and the daemon
(`daemon.rs:2372-2399` rejects only `Anchor`) right now, with no future
capability addition required. See §3c's revision.

**Also found (revises §4):** the lab's macOS `Exit` role does not test the
product's actual macOS exit preset. The product's `Exit` preset uses
`primary: PrimaryRole::Admin` (`role_presets.rs:321-323`) and has its own
installer path (`ops_install_macos_exit.rs`); the lab maps macOS `Exit` to
daemon role `blind_exit` instead (`role.rs:160`). `Requirements.md` treats
`exit` and `blind_exit` as distinct roles and states no OS may be limited in
which role it can take. A green Refresh exit-row cell on `blind_exit` evidence
does not validate the admin-posture macOS exit preset at all. See §4's
revision.

### 1.3.2 Ledgered target fix (Option D) — not implemented this round

The review identifies a cleaner foundational alternative the original design
never considered: **the mesh's membership owner must never be a `blind_exit`
node.** Mint genesis on a different (non-blind) node in the topology, and add
the macOS exit as an ordinary NON-OWNER peer via the same
`e2e-membership-add --capabilities blind_exit,exit_server` path the Linux
`blind_exit` lab role already uses (`macos_membership.rs:297-304`,
`membership_init.rs:108-111`). This eliminates the F1 dependency entirely — no
identity lie at provisioning time, the owner signing key never touches a
blind_exit host, and blind_exit provisioning becomes one hardened path across
every OS instead of a macOS-specific second signed update.

**Why this is the target, not this round's fix:** `membership_init.rs`
currently hard-wires the membership owner to be the topology's `Exit` alias
(`:21, :28-35`), and the macOS-exit lab topology as currently constructed has
no separate anchor/admin node to serve as owner instead — making Option D an
orchestrator-topology change, not a drop-in replacement for §1.2's rewrite.
**Tracked as a follow-up with no committed date yet** — ledger entry to be
added to `QualityHardeningTodo_2026-07-25.md` alongside the §3c reclassification
below when this fix lands.

The related product-level gap §1.3-B's Alternative B already surfaced
(`ops init-membership` accepts `blind_exit` today but mints anchor genesis
caps regardless, producing a dead-on-arrival node for any real non-lab
operator) is NOT fixed by either this round's rewrite or by Option D on its
own — Option D only fixes the LAB's provisioning path. The honest product fix,
per the review, is likely that `ops init-membership` should REFUSE `blind_exit`
outright (a blind-exit node can never be a mesh founder) rather than making
genesis role-aware for it. This is recorded here as a known open product gap,
not scheduled by this design.

### 1.4 Ordering constraints

- Rewrite runs **before** `DistributeMembership` distributes the snapshot, so
  every peer receives the final (epoch ≥ 2) state and no peer ever replays the
  anchor-carrying genesis entry for the macOS exit.
- Rewrite runs **before** the stage's read-back so
  `ctx.membership_snapshot` (`stage/membership_init.rs:70`) holds the final
  state the daemon will validate against.
- The rewrite is a single node's capability record; the per-peer
  `e2e-membership-add` calls (:248-...) are unaffected and keep their existing
  ordering and key-identity branching (:260-268).

## 2) Trust-state impact

### 2.1 What is signed, when, and by whom

- **Before the fix:** the macOS exit's capability set exists only inside the
  genesis snapshot signed at `membership init` time by the node's owner
  approver key (`main.rs:4483-4492` approver set; attestation minted at
  :4494-4499). The anchor set rides on the exit's signed record indefinitely.
- **After the fix:** a second signed update record is added during
  `membership_init`: `propose` builds the record from the current snapshot,
  `sign-update` signs it with the SAME owner approver identity
  (`<exit>-owner`, the convention both adapters derive —
  `macos_membership.rs:187-190`, `linux_membership.rs:72-74`), `apply-update`
  verifies and mutates. Authorship does not change; the number of signed
  artifacts grows by exactly one; the update is signed at provisioning time by
  the same authority that signed genesis.
- The membership format validator independently rejects the dangerous
  combinations at propose/apply time regardless of this fix:
  `validate_membership_node_capabilities`
  (`crates/rustynet-control/src/membership.rs:2668`) forbids `blind_exit`
  without `exit_server` (:2677-2684), `blind_exit` + `Anchor`/any anchor
  sub-capability (:2693-2705), and `blind_exit` + service-hosting caps
  (:2735-2746). The target set `{blind_exit, exit_server}` is legal
  (`blind_exit` requires `exit_server` — satisfied).

### 2.2 Replay / rollback / epoch

All handled by the existing apply path, not by this design:
- `apply_signed_update` verifies the signature against the record, then
  observes `record.update_id` + `record.epoch_new` in the replay cache
  (`membership.rs:1032-1073`).
- The epoch watermark alone blocks rollback replays (`membership.rs:721`);
  watermark classification is at :1559 (`membership_watermark_is_replay`);
  same-root re-verification is explicitly not a replay (:1556-1557).
- Genesis is epoch 1 (`main.rs:4462`); the rewrite bumps it (to 2) before any
  distribution. No watermark file or epoch constant is touched by this design.

### 2.3 Direction of the change

The rewrite REMOVES capabilities from the signed record (`Anchor`, the five
anchor sub-caps, `Client`, `RelayHost`) and ADDS `BlindExit`. This is
strictly narrowing **of the signed record.** The reverse edit (adding anchor
onto a blind_exit node's record) remains forbidden at two independent layers
(§3c).

**Qualification, required by §1.3.1's F1 finding:** the record narrows; the
node's ACTUAL capability does not. Because provisioning declared this node
`admin` rather than `blind_exit` (§1.3.1) to prevent the owner signing key's
deletion, the node's disk retains that key — the sole mesh-wide signing
authority (`quorum_threshold: 1`) — for the life of the interim fix. A
compromised exit host under this scheme could still re-sign its own (or any
node's) membership record with full anchor capabilities, because it physically
holds the key that can do so, regardless of what its current signed record
says. **This is a disclosed limitation of the interim fix, not a property that
holds.** It is closed only by the Option D target (§1.3.2), which never
places the owner key on a blind_exit host in the first place. Also note:
`blind_exit` is an irreversible role marker once assigned
(`role_presets.rs` taxonomy; §2.4 below) — installing it here via a signed
update is a one-way door for this node, same as installing it at genesis
would be.

### 2.4 Interaction with blind_exit irreversibility (AGENTS.md §10.7,
SecurityMinimumBar §6.D.2)

- §6.D.2: "A node currently in role `blind_exit` MUST refuse every other-role
  transition without an explicit factory-reset operator step" (typed
  confirmation required when *entering or leaving* `blind_exit`).
- This fix performs **no role transition**. Provisioning a node directly as
  blind_exit-capable at genesis/first-distribution is INITIAL STATE, not a
  transition: the role-preset transition matrix
  (`crates/rustynet-control/src/role_presets.rs`, §6.D.1) governs *leaving*
  roles; the wizard's typed-confirmation gate governs the operator `role set`
  surface. Neither is invoked by a provisioning-time capability record that
  matches the role the node is being installed with. The one-way door is
  simply installed in the closed-and-locked position from the first signed
  snapshot the node distributes.
- Nothing in this fix creates a path by which a blind_exit node could reach
  another role: `role_cli.rs` transition gates are untouched, the daemon's
  `admin`-vs-`blind_exit` membership exclusivity (`daemon.rs:2299-2301`,
  :2302-2304) is untouched, and the membership-format layer
  (`membership.rs:2693-2705`) would reject any signed record attempting to
  carry both.

## 3) Adversarial self-review

Each attack/failure below was actively attempted against the design in §1.
Verdicts are stated with the mechanism that holds or the change required.

**(a) Does `{blind_exit, exit_server}` open anything it should not, or remove
something the macOS exit legitimately needs?**

Opens: nothing beyond what the daemon's own required set for the role already
demands (`daemon.rs:2164-2165`), and `blind_exit`'s posture is strictly
narrower than what it replaces — IPC drops from full operator surface to
read-only status/netcheck/state-refresh/dnsinspect (`daemon.rs`
`allows_command`, BlindExit arm :2200-2203 vs Admin arm :2169-2170), and the
pf blind-exit anchor (tunnel-only local-origin egress, mesh-CIDR-only
forwarded egress; Refresh §intended-divergences; `macos_blind_exit.rs`
machinery per `CrossPlatformRoleParityRoadmap_2026-06-22.md` §BLIND_EXIT) is
the enforced runtime. Removals, checked one by one:

- `Client`: the Linux exit keeps it ONLY because the Linux exit runs the
  `client` daemon role and validates its auto-tunnel bundle against that role
  (`role.rs:190-201`, required-cap enforcement for `NodeRole::Client` at
  `daemon.rs:2162`). The macOS exit runs `blind_exit`, which requires
  `{blind_exit, exit_server}` only; the membership_init stage is what assigns
  the daemon role env, and the macOS blind_exit election (Refresh §3 blind_exit
  row: FIRST ELECTION + PASS 2026-08-31, `livelab-1788172934687-17194-11`)
  already exercised a macOS node holding exactly this pair. No auto-tunnel
  client-bundle path is lost.
- `Anchor` + sub-caps: forbidden on a blind_exit node at BOTH layers
  (`daemon.rs:2302-2304`; `membership.rs:2693-2705`). Keeping them is the bug.
- `RelayHost`: the blind-exit posture is a terminal hop, not a relay
  co-host; the product grant excludes it (`role.rs:188`), and the capability
  preset table never produces blind_exit+relay_host. No macOS exit stage
  consumes relay_host from the exit's own record.
- `AnchorEnrollmentEndpoint` (implicitly lost with the anchor set): this is a
  REAL functional delta and is recorded as a known limitation — the Linux exit
  advertises it because it is the membership owner AND the node live
  enrollment stages redeem tokens on (`role.rs:209-217`, D-3 comment). A macOS
  exit under blind_exit posture CANNOT serve enrollment redemption (anchor
  sub-capability + blind_exit is format-forbidden, `membership.rs:2693-2705`).
  No current macOS-exit lab stage exercises enrollment redemption, so nothing
  breaks today; if the program ever requires it, that is a new posture design,
  not a capability tweak. **This limitation must be surfaced to the owner at
  sign-off.**

Verdict: withstood. The set is exactly the daemon-required pair, nothing more,
nothing less.

**(b) Cross-OS mesh inconsistency (Linux exit = admin+anchor; macOS exit =
blind_exit+exit_server in one mesh)?**

- Signed membership is a per-node record set; there is no rule that same-lab-role
  nodes carry identical capabilities, and the mesh already mixes sets today
  (clients `{client}`, entries six caps, relays two — `role.rs:239-307`).
- Each daemon validates ITS OWN entry against ITS OWN local role
  (`validate_node_role_membership_alignment` takes `local_node_id` +
  `node_role`, `daemon.rs:2262-2266`; called at :5308 during bootstrap replay).
  A peer never validates another node's record against its own role table.
- Cross-node serviceability is capability-driven, not role-name-driven: the
  client's assignment names its exit provider, and the daemon requires the
  NAMED provider to hold `exit_server` in signed membership
  (`validate_exit_provider_membership`, `daemon.rs:1589`; cited from
  `role.rs:250-254`). The macOS exit holds `exit_server`. Satisfied.
- The Refresh already classifies the Linux-nft vs macOS-pf exit mechanism
  split as an intended per-OS divergence whose egress PROOF is not waived
  (Refresh §intended-divergences, "macOS exit — `pf` NAT *mechanism*
  divergence"). Capability-set divergence is the same shape: intended, and
  provable per-OS.
- Residual watch-item (verification, not design change): in a macOS-exit
  topology the membership OWNER (genesis node) is the macOS exit itself, now
  holding blind_exit caps rather than anchor. No code path requires the owner
  node to hold `Anchor` (issuance is owner-KEY-driven, not
  owner-capability-driven: `ops_e2e.rs:2643-2661` signs with the owner
  signing key; genesis approver set is key-based, `main.rs:4483-4492`), and
  the pre-fix run already passed `membership_init`/`distribute_membership`/
  `distribute_assignments` (Refresh §3 exit row), but the live proof in §5
  explicitly watches those three stages plus anchor-bundle-pull absence.

Verdict: withstood; one explicit live-verification watch-item added.

**(c) Could the fix be gamed to weaken `daemon.rs:2302-2304` by accident?**

- The design does not touch `daemon.rs` at all; the Investigation's
  prohibition (Investigation §e: "Do **not** weaken daemon.rs:2302-2304") is
  restated as an implementation invariant in §5.
- Gamed via the new rewrite path? The rewrite can only set what it is given;
  the design mandates deriving the CSV from
  `product_capabilities_for_platform` (`role.rs:186-189`) at the call site. A
  hypothetical future edit passing `anchor,blind_exit` would be rejected by
  the membership format layer at propose/apply (`membership.rs:2693-2705`,
  "cannot combine anchor and blind_exit capabilities") — the game cannot even
  produce signed state.
- Gamed by replacing the blind_exit caps with a plain anchor set (making the
  record anchor-only while the daemon role stays blind_exit)? Signed-valid at
  the format layer, but the daemon then hard-rejects at bootstrap replay
  (`daemon.rs:2302-2304`) — fail-closed, and the stage-level negative test
  (§5.2) catches it at provisioning time first.
- Gamed by DROPPING `exit_server` (degrading the node)? blind_exit
  missing-caps warn-and-continue (`daemon.rs:2283-2290`) means the daemon
  still boots — but with the pf blind-exit posture enforced by the reconcile
  apply block regardless of membership contents (comment :2279-2282), so the
  degradation is a posture warning, not a privilege gain; and the stage-level
  exact-set assertion fails the run before it matters.
- **Structural note — RECLASSIFIED 2026-09-05, no longer "out of scope."**
  blind_exit's validator uses a forbidden-values pattern while blind_relay
  uses an exact canonical-set compare (`daemon.rs:2305-2332`, whose own
  comment explains the reject-future anti-pattern, F5, and states the
  warn-and-continue exception "is not precedent"). Independent review found
  this is exploitable TODAY, not merely a future risk: `{blind_exit,
  exit_server, relay_host}` (or `+ client`) is accepted right now by both the
  membership-format layer (`membership.rs:2668-2757` has no blind_exit⊕
  relay_host or ⊕client rule) and the daemon (`daemon.rs:2372-2399` rejects
  only `Anchor`). This design's stage-level exact-set assertion (§5.2) pins
  *this fix's own* provisioning correctness, but does nothing for any other
  path that could sign a blind_exit+relay_host record.
  **Tracked as a fail-closed/default-deny violation (AGENTS.md/CLAUDE.md §3),
  not a deferred nice-to-have** — ledger entry to be added to
  `QualityHardeningTodo_2026-07-25.md` with this fix's landing commit, to be
  closed by migrating blind_exit's validator to the exact-set form (removing
  the warn-and-continue exception in the same change) immediately after this
  fix lands, not on an open-ended "someday."

Verdict: the mechanism withstands the game scenarios tested; the structural
gap identified above is real and present-tense, now tracked rather than
deferred — see the ledger note above.

**(d) Existing deployed macOS exit whose signed membership already carries
anchor — migration or re-provisioning?**

- Today such a node is ALREADY broken: the daemon fail-closes at bootstrap
  replay (`daemon.rs:5308` → :2302-2304), sitting in restricted safe mode
  (Investigation §a, §c step 5). There is no working state to preserve.
- In the lab, guests are re-provisioned with fresh identity each run
  (`CrossPlatformRoleParityRoadmap_2026-06-22.md` §BLIND_EXIT: "the next
  run's bootstrap re-provisions a fresh identity"), so the normal path is
  fresh genesis + rewrite.
- For a persisted guest (snapshot present, `init-membership` short-circuits,
  `main.rs:13846-13857`): the adapter's idempotent read-and-skip (§1.2)
  detects the anchor-carrying entry and issues the rewrite — which is exactly
  the sanctioned mechanism for changing ALREADY-SIGNED state: an owner-signed
  update with epoch bump and replay-cache observation (§2.2). **No separate
  migration tool and no manual epoch bump are needed; the signed-update path
  IS the migration mechanism.** The stage then reads back and asserts.
- What is NOT required and would be wrong: a factory reset. §6.D.2 gates role
  TRANSITIONS; a capability alignment on a node whose role was already
  blind_exit from birth is not a transition (§2.4). Requiring factory reset
  here would add an irreversible destruction step to fix a provisioning bug —
  the opposite of the fail-closed direction.

Verdict: withstood; re-provisioning plus one signed update covers every case,
with no epoch surgery and no factory reset.

## 4) The rejected alternative: mapping macOS exits back to daemon `admin`

### 4.1 The decision record for the blind_exit posture

- **Origin commit:** `e3f55b7e` (2026-05-22, "dataplane: D11.a + macOS
  userspace backend split + daemon lifecycle hardening") introduced
  `VmGuestPlatform::Macos => NodeRole::Exit => Ok("blind_exit")` in
  `daemon_node_role_for_platform` (verified via `git log -S` and the commit
  diff; the arm and a pinning test were both added there).
- **Formalization:** `dbb41c87` ("feat(orchestrator): Admin + BlindExit as
  first-class --node roles (Bucket 1.5)") extended the macOS arm to
  `Exit | BlindExit` and added the product capability grant `{BlindExit,
  ExitServer}` (`role.rs:159-160`, :186-189).
- **Documented posture:** the Refresh records the macOS exit mechanism as an
  intended divergence — "macOS Exit maps to enforce-time `pf` NAT (anchor
  hard-locked)" with the egress proof NOT waived (Refresh §intended-divergences);
  the Roadmap describes the macOS runtime as the blind-exit machinery
  (`macos_blind_exit.rs`: pf anchor, local-origin egress tunnel-only,
  forwarded egress mesh-CIDR-only) and records macOS blind_exit live-proven
  2026-06-29 and macOS exit live-proven 2026-07-03 under the legacy bash
  engine (`CrossPlatformRoleParityRoadmap_2026-06-22.md` §BLIND_EXIT and §5).
  The mechanism rationale is structural: macOS has no kernel WireGuard / nft
  NAT path; the pf-based blind-exit machinery is the macOS egress enforcement
  substrate, so the lab exit rides the `blind_exit` daemon posture that
  machinery implements.
- **Honest finding (surface, do not bury):** the ORIGIN commit carries no
  inline rationale comment for the mapping, and no dedicated decision document
  records "macOS exit ⇒ blind_exit" in so many words. The record above is
  reconstructed from the commits' content/dates plus the Refresh/Roadmap
  posture text — all consistent, none explicit. The Investigation's phrase
  "the deliberate macOS exit→blind_exit posture decision recorded at
  role.rs:159-160" (Investigation §e) overstates the paper trail: role.rs
  records the DECISION but not its REASONING. Recommendation: when the fix
  lands, add the missing rationale comment at `role.rs:159-160` citing this
  section, so the next investigator does not re-derive it.

### 4.2 Why reversing the mapping is worse than fixing the membership

1. **It trades a provisioning bug for a privilege upgrade.** `admin` is the
   highest-authority daemon posture: full IPC operator surface
   (`daemon.rs:2169-2170` `allows_command` Admin arm) and a hard `Anchor`
   membership requirement (`daemon.rs:2161`, enforced :2291-2295). Making the
   lab exit an admin to satisfy an adapter skip inverts the fail-closed
   direction: the defect gets "fixed" by granting the exit the control-plane
   authority blind_exit deliberately withholds (read-only IPC, :2200-2203).
2. **It is not mechanically free on macOS.** The admin posture's exit-NAT path
   is what macOS cannot express the Linux way — the Refresh states the macOS
   exit maps to enforce-time pf NAT with anchor "hard-locked"; reverting the
   mapping means re-designing and re-proving NAT lifecycle + DNS enforcement
   under the admin posture on macOS, i.e. re-opening the very cell this fix
   unblocks, with no evidence the posture is even achievable (the
   EnforcementGap/AdversarialReview pair documents how narrow the macOS DNS
   enforcement surface already is).
3. **It contradicts the recorded evidence base.** macOS blind_exit is
   live-proven (2026-06-29), the macOS blind_exit `--node` election passed
   first-time 2026-08-31 (Refresh §3 blind_exit row), and the daemon-side
   alignment acceptance of `{blind_exit, exit_server}` is unit-pinned
   (`daemon.rs:20049-20067`,
   `node_role_membership_alignment_requires_signed_capability`). The blind_exit
   posture is the one macOS exit posture with standing proof.
4. **The Investigation already classified it as requiring a posture review**
   (Investigation §e: do not remap "without a posture review"). This section is
   that review's conclusion: the mapping stands; the membership was wrong.

### 4.3 Where the decree lives, and what it does NOT prove — CORRECTED 2026-09-05

§4.2 concludes macOS `Exit` stays `blind_exit` in the lab. Independent review
found this conclusion right but the RECORDING plan (§5.1 step 6, a code
comment at `role.rs:159-160`) insufficient: this decree effectively assigns
macOS a DIFFERENT daemon role than Linux/Windows for the same lab `Exit`
role, and `Requirements.md` treats `exit` and `blind_exit` as distinct roles,
stating no OS may be limited in which role it can take. A source comment does
not surface that divergence to anyone reading the parity ledgers.

**Required, in addition to §5.1 step 6's comment:**
- Record the divergence explicitly in `CrossPlatformRoleParityRefresh_2026-07-23.md`
  and `CrossPlatformRoleParityPlan_2026-06-21.md` as an intended per-OS
  divergence (same treatment already given to the macOS pf-vs-Linux-nft NAT
  mechanism split) — not silently implied by a passing test.
- **The Refresh's macOS `exit` cell must NOT be marked green on `blind_exit`
  evidence alone.** `blind_exit` evidence does not exercise the product's
  actual macOS `Exit` preset, which runs `PrimaryRole::Admin`
  (`role_presets.rs:321-323`) with its own installer
  (`ops_install_macos_exit.rs`). Mark the admin-posture macOS exit cell
  explicitly `N/A-by-decree` or `open` — whichever the owner prefers — rather
  than inheriting a green from this fix's `blind_exit` proof. This fix
  unblocks the LAB's `blind_exit`-mapped exit cell; it says nothing about
  whether the admin-posture macOS exit preset works.

## 5) Implementation plan + mandatory negative test

### 5.1 Ordered checklist for the eventual code task

1. `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_membership.rs`:
   add `exit_capability_rewrite_script(exit_node_id: &str) -> Result<String,
   AdapterError>` beside `peer_add_script` (:180-205): argv-only remote script,
   `shell_safe_arg` on every interpolated value, MAC-D11 keychain env prefix
   (:198), `ops e2e-membership-set-capabilities --node-id <exit>
   --capabilities <csv-from-product-grant> --owner-approver-id <exit>-owner`.
1a. **REQUIRED (§1.3.1 F1):** at the existing genesis-init call site that
    passes `RUSTYNET_NODE_ROLE=admin` for this node (the site the review found
    at `:174`), add an explicit comment stating WHY `admin` is declared
    instead of the node's real eventual role `blind_exit`: declaring
    `blind_exit` here would trigger `maybe_remove_blind_exit_owner_signing_key`
    (`main.rs:13941-13962`) and delete the owner signing key this very
    provisioning flow needs on disk to sign its own follow-up capability
    rewrite (step 2) and the per-peer adds. State plainly that this is a
    disclosed interim workaround (§1.3.1/§2.3), closed only by the Option D
    target (§1.3.2) — so a future reader does not "fix" this call site to say
    `blind_exit` and silently break the rewrite this design depends on.
2. Same file, `init_membership_snapshot` (:232-...): after the genesis init
   (:241-245), resolve the exit peer (today skipped at :249-251), derive the
   capability CSV via
   `NodeRole::Exit.product_capabilities_for_platform(&VmGuestPlatform::Macos)`
   + `role_capability_csv` (the grant lives at `role.rs:186-189`; do NOT
   hard-type the CSV), read back the snapshot, and if the exit's canonical
   caps ≠ the target set, run the rewrite script via `ssh::run_remote` with
   `MEDIUM_TIMEOUT`. Keep the per-peer loop and final read-back unchanged.
3. Same file, `mod tests` (:488-...): add tests pinning the rewrite script's
   exact shape (see §5.2) in the style of the existing `peer_add_script_*`
   tests (:731, :835, :854). **REQUIRED additions (review item 5):**
   idempotency-branch tests — a fresh anchor-carrying genesis triggers the
   rewrite (plan contains the set-capabilities command); an already-canonical
   `{blind_exit, exit_server}` snapshot does NOT re-trigger it (plan omits the
   command, no needless epoch bump); and an assertion that a fresh genesis
   ends at exactly `epoch == 2` after the rewrite (epoch 1 genesis + one
   signed update), to catch a future double-apply regression.
4. `crates/rustynet-cli/src/vm_lab/orchestrator/stage/membership_init.rs`: after
   `ctx.membership_snapshot` is set (:70), add a fail-loud assertion: when the
   membership-owner peer is `NodeRole::Exit` on `VmGuestPlatform::Macos`, the
   snapshot's entry for that node MUST canonically equal
   `{blind_exit, exit_server}` (canonicalize via the rustynet-control
   canonicalization used at `membership.rs:2670`); any other content fails the
   stage. FAIL-LOUD per the Roadmap's live-stage spec — no skip-as-pass.
5. Do NOT touch: `crates/rustynetd/src/daemon.rs` (esp. :2298-2304),
   `crates/rustynetd/src/main.rs` genesis (:4448-4492),
   `adapter/linux_membership.rs` (:75-78 skip stays — Linux exit legitimately
   keeps anchor genesis), `crates/rustynet-control/src/membership.rs`.
6. Docs at implementation time (same change): add the missing rationale
   comment at `role.rs:159-160` (§4.1 finding); update the Refresh §3 exit row
   **as an explicit intended per-OS divergence, marking the admin-posture
   macOS exit cell N/A-by-decree/open rather than inheriting green from
   blind_exit evidence (§4.3, REQUIRED)**; update the Investigation doc's
   status line; add the index entry to `documents/operations/active/README.md`
   (this design doc is itself missing from the index today — add it in the
   same change); add the QH-ledger entries for the §3c reclassification and
   the §1.3.2 Option D follow-up.
7. Gates: `cargo fmt --all -- --check`; scoped
   `cargo check -p rustynet-cli --all-targets --all-features` /
   `cargo test -p rustynet-cli --all-targets --all-features` (the flags are
   mandatory — the orchestrator lives behind the `vm-lab` feature, RNQ-17, so
   the bare scoped form under-tests); full §7 list before landing.

### 5.2 The mandatory negative test

Requirement (Investigation §e): pin **"macOS exit membership carries exactly
{blind_exit, exit_server}, never anchor"** at BOTH layers:

- **Unit (provisioning command layer)** —
  `macos_membership.rs::tests`:
  - `exit_capability_rewrite_script_carries_exact_blind_exit_set`: the script
    contains `ops e2e-membership-set-capabilities`, `--capabilities
    'blind_exit,exit_server'` (exact canonical CSV, order-insensitive compare
    on the parsed set but exact-length-2), `--owner-approver-id
    '<exit>-owner'`, the keychain env prefix, and NO other
    capability-affecting verb; the string `anchor` appears nowhere in the
    script.
  - **Mutation that proves it bites:** re-introduce the pre-fix behavior —
    make `init_membership_snapshot` skip the exit peer (restore `continue` at
    :249-251 and delete the rewrite invocation). To catch that at unit level,
    structure the command construction as a pure ordered plan
    (`init_membership_commands(exit_node_id, peers) -> Vec<String>`,
    executed by a thin loop) so a test can assert the plan for a macOS exit
    peer list CONTAINS the set-capabilities command between the init command
    and the peer adds. The mutation removes the plan entry → the ordering/
    presence test fails. **The pure-plan refactor is MANDATORY, not optional
    (review item 5 correction — the original text's "if judged too invasive,
    the stage assertion is the backstop" escape hatch is removed):** without
    it, the mutation is only lab-visible, and this design's own §1.3.1/§2.3
    disclosure of the F1 owner-key dependency means the provisioning path
    deserves the tighter, unit-level guarantee.
- **Stage (live provisioning layer)** — the `membership_init` fail-loud
  assertion of §5.1 step 4: with the mutation applied, the read-back snapshot
  still carries the anchor genesis set on the macOS exit → the stage fails
  with an error naming the offending capability set. This is the direct
  live analogue of the daemon's own rejection, one stage earlier.
- **Daemon-side (already exists, cited for completeness)** —
  `daemon.rs:20049-20067` proves the pair passes alignment, and
  `daemon.rs:2302-2304` + its consumers reject the anchor-carrying variant;
  these stay untouched and are the last-resort backstop.

### 5.3 Live-lab proof

- Target cell: macOS exit election on `macos-utm-1` (the exact topology of the
  failing run: macos=exit, debian entry, debian client — Investigation §a,
  run `deepseek-lab-labrun-1788164004680-17194-2`).
- PASS criterion: `membership_init` passes WITH the new stage assertion, and
  `validate_baseline_runtime` passes all six per-node ops on macos-utm-1
  (`RuntimeAcls, ServiceHardening, KeyCustody, Authenticode, MeshStatus,
  DnsFailclosed` — Investigation §a) — i.e. the run gets PAST the current
  failure point, whose root cause line
  (`blind_exit role cannot use membership carrying anchor capability`,
  `daemon.rs:2303`) must be ABSENT from the run's daemon failure markers.
- Watch-items (§3b): `distribute_membership` + `distribute_assignments` pass
  with a blind_exit-capped membership owner, and anchor-bundle-pull stages
  skip as expected in an anchorless exit topology.
- Expected next blocker, pre-declared: if the exit cell then enters protected
  DNS mode, `DnsFailclosed` may surface the SEPARATE, already-documented
  enforcement question — the M1 apply path pins loopback via
  `networksetup`/`resolv.conf` (`phase10.rs:4557-4683`; Investigation §c) but
  `MacosDnsFailclosedEnforcementGap_2026-08-28.md` (dispositioned
  design-only/owner-gated, `1278af04`) and
  `MacosDnsFailclosedAdversarialReview_2026-08-31.md` record that the
  enforcement posture must be verified against what the OS actually consults
  (`scutil --dns`). A post-fix `DnsFailclosed` failure with daemon failure
  markers CLEAN is that distinct, already-dispositioned gap — not a regression
  of this fix. Distinguish by the daemon marker's absence.
- Evidence recording: verify the appended row in
  `documents/operations/live_lab_node_run_matrix.csv` and take the pass/fail
  claim from the stage's own report artifact, never the column alone
  (AGENTS.md §12.3).
- **REQUIRED (§1.3.1 F1) — owner-signing-key presence on the exit host is
  recorded as an explicit fact, never inferred from a green stage.** The
  `membership_init` stage must probe, AFTER the genesis init + capability
  rewrite + peer adds have completed, whether `MACOS_OWNER_SIGNING_KEY_PATH`
  (`/usr/local/etc/rustynet/membership.owner.key`) exists on the macOS exit
  host, and must write the result as a named line into its own stage log
  (`logs/membership_init.log` in the run's report directory) in the form
  `owner_signing_key_present=<true|false> path=<path> node_id=<exit node id>`
  — the same file the report artifact's data block is read from, so the
  fact travels with the stage verdict. Under the INTERIM fix the expected
  and disclosed value is `true`: that is F1 itself, made visible. A run
  whose `membership_init` log does not carry this line does NOT satisfy
  this design's proof criteria, regardless of stage status, because the
  disclosed limitation would then be invisible in evidence — exactly the
  "swept under a green checkmark" outcome the review forbade. A value of
  `false` on the interim fix is itself a defect signal (the rewrite could
  not have signed its own update without the key; something deleted it
  after signing) and must be investigated, not celebrated. When the
  Option D target (§1.3.2) lands, the expected value flips to `false` and
  this same line becomes the closure evidence for F1; the probe is
  therefore permanent, not a temporary diagnostic.
- Sign-off evidence must quote the actual `owner_signing_key_present=`
  line from the proving run alongside the stage status — quoting only the
  status is incomplete.

## 6) Sign-off checklist (for the human reviewer)

Updated 2026-09-05 to reflect the independent review's corrections
(§1.3.1, §1.3.2, §2.3, §3c, §4.3, §5.1–§5.3). The owner approved the
review's MODIFIED recommendation — interim fix WITH F1 disclosed, mandatory
corrections applied, Option D ledgered as the target — not the original
"approve all as-is". Items marked ★ are the review's mandatory additions.

- [x] §1.2 layer decision (adapter-level signed rewrite; product code
      untouched) approved — **as an INTERIM fix only** (§1.3.1), with the
      Option D target (§1.3.2) ledgered as the committed follow-up.
- [x] ★ §1.3.1 F1 accepted as a DISCLOSED KNOWN LIMITATION of the interim
      fix: the exit host keeps the sole mesh owner signing key
      (`quorum_threshold: 1`) for the life of the interim fix. Accepted on
      the explicit condition that it is recorded in evidence on every
      proving run (§5.3 `owner_signing_key_present=` line) and closed by
      Option D, not by a later "we forgot" default.
- [x] §2.3 privilege-narrowing direction accepted **with the F1
      qualification**: narrowing holds for the signed record only, not for
      the node's physical capability. §3a enrollment-endpoint limitation on
      macOS exits accepted as a known posture consequence.
- [x] ★ §3c reclassified: the blind_exit forbidden-values validator gap is
      a PRESENT-TENSE default-deny violation (`{blind_exit, exit_server,
      relay_host}` / `+ client` accepted today at both layers), tracked in
      `QualityHardeningTodo_2026-07-25.md` as a §3 violation to be closed
      by migrating to the exact-set form immediately after this fix lands —
      NOT "out-of-scope follow-up".
- [x] §4 posture review conclusion accepted: macOS lab exit stays
      `blind_exit`; the mapping's missing written rationale is acknowledged
      and will be added at implementation (§5.1 step 6).
- [x] ★ §4.3 decree-vs-proof accepted: the divergence is recorded
      explicitly in the Refresh and the ParityPlan as an intended per-OS
      divergence, and the admin-posture macOS `Exit` preset
      (`PrimaryRole::Admin`, `ops_install_macos_exit.rs`) is marked
      N/A-by-decree/open — it does NOT inherit green from blind_exit
      evidence.
- [x] ★ §5.1 step 1a: the `RUSTYNET_NODE_ROLE=admin` call site carries an
      explanatory comment naming F1 and Option D, so nobody "fixes" it to
      `blind_exit` and silently breaks the rewrite.
- [x] ★ §5.2 pure-plan refactor (`init_membership_commands`) is MANDATORY;
      the former "stage assertion is the backstop" escape hatch is removed.
      Idempotency-branch tests + the `epoch == 2` assertion are required.
- [x] ★ §5.3 live proof must record `owner_signing_key_present=` as an
      explicit evidence line; sign-off quotes it next to the stage status.
- [ ] Implementation landed on `main` with the §5.1 checklist complete,
      gates green, and an adversarial review of the ACTUAL diff (not the
      design) recorded before landing.
- [ ] §5.3 live proof run recorded: run-matrix row attributed to the
      landing commit, `membership_init` artifact status quoted, and the
      `owner_signing_key_present=true` line quoted from the run's
      `membership_init` log.
