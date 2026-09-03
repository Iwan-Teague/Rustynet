# macOS Membership-Capability Rewrite — does one owner sign-off unblock BOTH stuck cells? (2026-09-03)

**DOC ONLY.** Read-only gap check against the owner-gated design package. Proposes no
code change and modifies no other document. Every claim cites file:line; where a
citation is quoted from a companion document rather than read directly on this tree
(worktree of the delegated-edit job `edit-1788440047855-17043-0`, which may sit a few
commits from the Design's HEAD `690fc35b`), that is marked **[via companion]**. This
document does not modify the owner-gated Design or its Adversarial Review; it records
the sign-off scope question the owner must answer.

## VERDICT

**BOTH — but only if the sign-off is given against the Adversarial Review's
superseding checklist, not against the Design §6 checklist alone.**

- The Design (`MacosExitMembershipRoleFixDesign_2026-08-31.md`) **as written unblocks
  the EXIT cell only**: its implementation plan (§5.1) provisions and asserts exactly
  one entry — the macOS exit node's own membership entry rewritten to
  `{blind_exit, exit_server}` — and never mentions anchor nodes,
  `anchor.port_mapping_authoritative`, or the anchor cell.
- The **anchor-cell gap is already covered by the package's companion document**
  (`MacosExitMembershipRoleFixAdversarialReview_2026-08-31.md`), whose PART A folds
  the `anchor.port_mapping_authoritative` grant into the SAME
  signed-capability-rewrite mechanism, and whose **"Updated sign-off checklist
  (supersedes Design §6; owner checks BOTH)"** (:362-402) adds six NEW items covering
  the anchor extension. Its verdict: **READY-pending-owner-signoff** (:404-415).
- So one owner sign-off unblocks BOTH cells **provided the signature is against the
  superseding checklist**. A sign-off against Design §6 alone is exit-only.

This matches the repo's own index reading: `documents/operations/active/README.md:188`
describes the Adversarial Review as "adversarial review + port-mapping-authority scope
extension … verdict READY-pending-owner-signoff with 8 implementation sign-off items;
the anchor-cell `anchor.port_mapping_authoritative` grant folds into the same
per-elected-role signed-capability-rewrite mechanism."

## Evidence chain

### 1. What the Design's chosen rewrite grants (exit cell)

Chosen shape (Design §0, `MacosExitMembershipRoleFixDesign_2026-08-31.md:14-25`): the
macOS exit node's OWN signed membership entry must carry EXACTLY
`{blind_exit, exit_server}` (product grant `role.rs:186-189`; daemon required set
`daemon.rs:2164-2165`). Mechanism: a post-genesis, owner-signed capability rewrite at
the orchestrator membership adapter using the existing hardened signed-update op
`ops e2e-membership-set-capabilities` (`ops_e2e.rs:2596-2700`) — no product, daemon,
or genesis change.

Implementation site (Design §1.2, :83-136): in
`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_membership.rs`
`init_membership_snapshot`, after genesis `ops init-membership` and before per-peer
adds + read-back, one extra remote command for the EXIT peer:
`ops e2e-membership-set-capabilities --node-id <exit> --capabilities
'blind_exit,exit_server' --owner-approver-id <exit>-owner`. The CSV must derive from
`NodeRole::Exit.product_capabilities_for_platform(&VmGuestPlatform::Macos)` via
`role_capability_csv` — never hand-typed. §5.2's negative test pins that the string
`anchor` appears NOWHERE in the rewrite script. **The Design only provisions and
asserts the EXIT peer's entry; it contains no anchor-cell provision.**

### 2. What the macOS ANCHOR validator requires

The live stage `validate_macos_anchor_port_mapping_authority` fails when the macOS
anchor's OWN persisted membership entry lacks
`RoleCapability::AnchorPortMappingAuthoritative` (rendered
`anchor.port_mapping_authoritative`): orchestrator-side evaluator
`vm_lab/mod.rs:15294-15300` — `"macOS anchor {alias} … does not hold
anchor.port_mapping_authoritative in its membership entry; current election
authority=…"` (comment :15287-15293: the stage asserts the GRANT reached persisted
state, not that the node wins the Pin-then-Seniority election); daemon-side status
check `rustynetd/src/anchor_port_mapping_status.rs:91-96`. The capability enum variant
is at `rustynet-control/src/role_presets.rs:259`/:285 and `roles.rs:56`/:84-85.

The anchor-role advertisement validator additionally word-boundary-asserts ALL seven
`REQUIRED_ANCHOR_CAPS` on the anchor's own row (`orchestrator/role_validation/
anchor.rs:59-67`, `anchor.port_mapping_authoritative` at :66):
`anchor, relay_host, anchor.gossip_seed, anchor.bundle_pull,
anchor.enrollment_endpoint, anchor.relay_colocation, anchor.port_mapping_authoritative`.

Is that set in the Design's granted set? **No — and it cannot be.** The two target
sets are mutually exclusive in signed state: combining `blind_exit` with `Anchor` or
ANY `anchor.*` sub-capability is a hard format rejection — `"cannot combine anchor and
blind_exit capabilities"` (`rustynet-control/src/membership.rs:2692-2702`) **[via
companion, Adversarial Review :133-137]**. No single CSV can serve both cells.

### 3. How the anchor cell is covered — the Adversarial Review's PART A

`MacosExitMembershipRoleFixAdversarialReview_2026-08-31.md` (companion, explicitly
"Scope extension folded in per review instruction", :12-19) establishes:

- **Root cause of the anchor failure is NOT a missing grant in the live product path.**
  The live `--node` path already grants the full canonical anchor set to an
  `Anchor`-role peer: `role.rs:295-303` returns
  `[Anchor, RelayHost, AnchorGossipSeed, AnchorBundlePull, AnchorEnrollmentEndpoint,
  AnchorRelayColocation, AnchorPortMappingAuthoritative]` (:302), explicitly
  platform-independent (comment :284-294), equal to
  `anchor_role_capabilities()` (`roles.rs:119-133`, cap at :124). (Verified directly
  on this tree: `role.rs:295-303`.) The defect is assignment-shape: when the macOS
  node's `--node` assignment role at `membership_init` time is not `Anchor`, no
  later stage ever upgrades its entry, while the OR-shaped
  `--anchor-platform macos` election alone still elects the three validator stages
  (`native.rs:1019-1036`) — a "validator-elected but capability-less macOS anchor"
  (Adversarial Review §A.1, :74-102). The bash-era post-join amendment
  `macos_membership_capabilities` (`vm_lab/mod.rs:10738-10746`) that used to grant
  `"client,anchor.bundle_pull,anchor.port_mapping_authoritative"` is quarantined
  `#[allow(dead_code)]` since W5.7 (verified directly: `mod.rs:10764`) and
  unreachable under the Rust `--node` engine.
- **Required mitigation (already specified, not newly proposed here)**: parameterize
  the Design's single signed-capability rewrite by the node's ELECTED role —
  `rewrite_script(node_id, elected_role, platform)` — and add a stage-level read-back
  assertion that the elected anchor's entry canonically equals
  `anchor_role_capabilities()` (§A.1 :96-102; §A.3 :152-164). The anchor cell's
  rewrite targets a JOINED node's entry (same op, different `--node-id`), executed as
  a read-back-then-decide REPAIR only when the snapshot's canonical set ≠ the product
  grant (§A.3 item 2). The legacy bash-era two-cap CSV is explicitly REJECTED as a
  target set — it under-grants (no `anchor` marker, no `relay_host`, no
  `gossip_seed`/`enrollment_endpoint`/`relay_colocation`) (§B.a :193-198).
- **Adversarial status of the extension**: Part B confirms both cells safe on
  over-grant (§B.a), cross-OS mesh consistency (§B.b, incl. the normal-two-holders
  election being single-winner by construction, §B.d), signed-state ordering
  verify→freshness→apply (§B.c), and blind_exit irreversibility with a new stated
  invariant — the generalized rewrite derives per-role and never crosses the
  anchor/blind_exit boundary (§B.f). The one acknowledged direction change: the
  anchor rewrite is privilege-ADDING (unlike the exit cell's strictly narrowing
  rewrite), mitigated by derived-CSV + format validator + owner key +
  provisioning-time scope, with a required BIDIRECTIONAL exact-set assertion
  (under-grant AND over-grant both fail loudly) (§B.e :298-330).

### 4. Genesis context (why the exit rewrite is even possible)

Bootstrap `membership init` grants the founding node the full anchor set including
`AnchorPortMappingAuthoritative` (verified directly on this tree:
`rustynetd/src/main.rs:4519-4529`, cap at :4525; the Design's tree cites :4469-4479
with the cap at :4475) — this is why the genesis/senior Linux exit currently wins the
port-mapping election, and why the exit-cell rewrite (dropping all anchor caps from
the macOS exit) is safe: an ineligible node simply drops out of the election scan
(`gossip_runtime.rs:941-945` **[via companion]**).

## Sign-off scope conclusion for the owner

One signature CAN unblock both cells, and the package is structured for exactly that:
the Adversarial Review's checklist (:362-402) explicitly "supersedes Design §6; owner
checks BOTH" and folds the anchor extension in as six NEW items (scope extension
approval; legacy-CSV rejection; enumeration-drift unit test; anchor-topology live
proof watch; bidirectional exact-set assertion; per-role/no-crossing invariant) on top
of the unchanged Design §6 items. The residual open item is verification, not design:
confirm from the failing macOS anchor run's snapshot artifact (run
`labrun-1788266019601-1574-3`, commit `451f9730`) exactly which CSV the macOS anchor's
entry carried — expected: no anchor-bearing caps, per the §A.1 assignment-shape
analysis (Adversarial Review :397-402). That confirmation does not gate the design.

If the owner intends to sign only the Design document itself (§6), then the answer to
"does this unblock both?" is **no — exit only**, and the anchor cell remains blocked
until the Part A extension is approved. There is no third mechanism to design: PART A
already specifies the exact delta (per-elected-role parameterization of the same
`ops e2e-membership-set-capabilities` op, target CSV derived from
`NodeRole::Anchor.product_capabilities_for_platform` = `anchor_role_capabilities()`,
repair-only after read-back, bidirectional exact-set stage assertion).

## Sources read directly on this tree vs via companion

- Direct: `MacosExitMembershipRoleFixDesign_2026-08-31.md` (full);
  `role.rs:280-339`, `:600-669` (anchor + blind_exit capability arms, tests);
  `rustynetd/src/main.rs:4440-4573` (genesis init + capability vec);
  `vm_lab/mod.rs:15280-15339` (port-mapping validator), `:10760-10804` +
  `:38090-38129` (quarantined bash-era grant + its test); `macos_membership.rs`
  (full, `init_membership_snapshot` :265-322, exit-peer skip :278-280);
  `role_validation/anchor.rs:1-200` (`REQUIRED_ANCHOR_CAPS` :59-67);
  `MacosExitMembershipRoleFixAdversarialReview_2026-08-31.md` (full).
- Via companion (quoted from the Adversarial Review's own citations, re-verifiable at
  the Design's HEAD `690fc35b`): `roles.rs:119-133` (`anchor_role_capabilities`),
  `membership.rs:2692-2702` (anchor⊕blind_exit rejection), `gossip_runtime.rs:931-953`
  (election), `native.rs:1019-1036` (OR-shaped stage election), `ops_e2e.rs:2596-2700`
  (signed-update op), `daemon.rs:2161-2165`/:2299-2304 (required sets).
