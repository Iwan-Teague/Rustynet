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
anchor sub-caps, `Client`, `RelayHost`) and ADDS `BlindExit`. Net effect on
the node's authority is strictly narrowing: it loses control-plane anchor
surface and gains the hardened minimal-surface final-hop posture. This is the
fail-closed direction; the reverse edit (adding anchor onto a blind_exit node)
remains forbidden at two independent layers (§3c).

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
- Structural note (recorded, out of scope): blind_exit's validator uses a
  forbidden-values pattern while blind_relay uses an exact canonical-set
  compare (`daemon.rs:2305-2332`, whose own comment explains the
  reject-future anti-pattern, F5). A future capability added to the schema
  could ride along on a blind_exit record. Migrating blind_exit to the exact-set
  form is a daemon trust-invariant change requiring its own review; this
  design's stage-level EXACT-set assertion pins provisioning correctness
  without it.

Verdict: withstood; two independent format/daemon layers plus the stage
assertion remain intact, and the known structural gap is recorded rather than
expanded.

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

## 5) Implementation plan + mandatory negative test

### 5.1 Ordered checklist for the eventual code task

1. `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_membership.rs`:
   add `exit_capability_rewrite_script(exit_node_id: &str) -> Result<String,
   AdapterError>` beside `peer_add_script` (:180-205): argv-only remote script,
   `shell_safe_arg` on every interpolated value, MAC-D11 keychain env prefix
   (:198), `ops e2e-membership-set-capabilities --node-id <exit>
   --capabilities <csv-from-product-grant> --owner-approver-id <exit>-owner`.
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
   tests (:731, :835, :854).
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
   and the Investigation doc's status line; add the index entry to
   `documents/operations/active/README.md`.
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
    presence test fails. (If the pure-plan refactor is judged too invasive,
    the stage assertion below is the backstop and the unit test above still
    pins the script content; the plan fn is preferred because it makes the
    mutation unit-visible rather than lab-visible.)
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

## 6) Sign-off checklist (for the human reviewer)

- [ ] §1.2 layer decision (adapter-level signed rewrite; product code
      untouched) approved.
- [ ] §2.3 privilege-narrowing direction accepted; §3a enrollment-endpoint
      limitation on macOS exits accepted as a known posture consequence.
- [ ] §3c structural blind_exit exact-set gap acknowledged as out-of-scope
      follow-up.
- [ ] §4 posture review conclusion accepted: macOS exit stays `blind_exit`;
      the mapping's missing written rationale is acknowledged and will be
      added at implementation (§5.1 step 6).
- [ ] §5.2 negative tests + §5.3 live proof plan accepted as the completion
      evidence.
