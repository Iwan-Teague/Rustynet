# macOS Exit Membership Role Fix — Adversarial Review + Port-Mapping-Authority Scope Extension (2026-08-31)

**DOC ONLY.** This is the companion adversarial review + scope extension for
`MacosExitMembershipRoleFixDesign_2026-08-31.md` ("the Design"). It proposes no
code change and modifies no other document. Every claim cites file:line from the
tree at the Design's HEAD `690fc35b` unless a function is named without a line
(and then verified by reading it on this tree). This document was produced by
independent adversarial review, not by the Design's author; where it confirms
the Design it says so, and where it extends the Design the extension is
explicitly marked.

**Scope extension folded in per review instruction:** the same-family live
defect surfaced by the 2026-08-31 macOS anchor run —
`validate_macos_anchor_port_mapping_authority` failing because the macOS
ANCHOR's signed membership lacks `anchor.port_mapping_authoritative` — is
analyzed in Part A and folded into the Design's single signed-capability-rewrite
mechanism. See Refresh §1 anchor row
(`CrossPlatformRoleParityRefresh_2026-07-23.md` line 100, MAC-D1 rerun) for the
run context.

---

## PART A — Scope extension: `anchor.port_mapping_authoritative`

### A.1 What a macOS ANCHOR needs to hold vs. to WIN the election

**Holding (what the live stage asserts).** The stage
`validate_macos_anchor_port_mapping_authority`
(`stage/macos_anchor_port_mapping_authority_validation.rs:22`, wired to
`exercise_macos_anchor_port_mapping_authority_live` at :78) drives
`rustynetd anchor-port-mapping-status-check` and its evaluator fails exactly
when the macOS anchor's OWN persisted membership entry does not contain
`RoleCapability::AnchorPortMappingAuthoritative`:
`"macOS anchor {alias} ... does not hold anchor.port_mapping_authoritative in
its membership entry"` (`vm_lab/mod.rs:14995-15001`, report field
`self_holds_capability`, `rustynetd/src/anchor_port_mapping_status.rs:70-78`,
:91-96). The evaluator deliberately does NOT assert that this node WINS the
global election (`mod.rs:14988-14994`; the rationale is written out in
`anchor_port_mapping_status.rs:13-25`): the genesis/founding node is
unconditionally granted every `anchor.*` sub-capability at
`membership init` (`rustynetd/src/main.rs:4469-4479`; the
`AnchorPortMappingAuthoritative` grant is at `main.rs:4475`), and being the most
senior member it always wins Pin-then-Seniority over a later-joined node unless
pinned. **So the macOS anchor's requirement is: hold the capability in its own
signed entry. Winning is neither required nor achievable against a senior
genesis cap-holder.**

**Winning (how the election actually resolves).** The election is
`select_port_mapping_authority_node_id` (`rustynetd/src/gossip_runtime.rs:938-953`),
a pure function over the signed membership snapshot only — every node evaluates
it independently against the same state and gets the same answer, with zero
coordination (`gossip_runtime.rs:931-937`). Mechanics:

1. Eligibility filter: node `status == Active` AND its own entry contains
   `AnchorPortMappingAuthoritative` (`gossip_runtime.rs:941-945`). A node
   without the capability — including a macOS exit holding only
   `{blind_exit, exit_server}` — simply drops out of the scan.
2. Winner: `min_by_key((!pinned, joined_at_unix, node_id))`
   (`gossip_runtime.rs:946-951`) — pinned nodes first
   (`AnchorPortMappingPinned`), then longest membership (earliest
   `joined_at_unix`), then lexicographically smallest node id as the final
   deterministic tie-break. Pin fallback is not a separate branch: a pinned node
   that fails the eligibility filters drops out and lands on the same seniority
   winner every other node computes (`gossip_runtime.rs:933-937`).
3. Consumption: `anchor_runtime_view_from_membership`
   (`gossip_runtime.rs:805-808`, field `:158`) feeds
   `port_mapping_bring_up_skip_reason`
   (`rustynetd/src/daemon.rs:11462-11478`) — the uPnP/PCP/NAT-PMP lease
   bring-up proceeds only when SELF is the elected authority, and the
   `anchor-port-mapping-status-check` subcommand reports both the winner and
   self-holds (`main.rs:1924-1925`,
   `anchor_port_mapping_status.rs:58-108`).

**What went wrong in the live run.** The macOS anchor's entry lacked the
capability entirely, so the evaluator failed before seniority ever mattered.
The grant paths for a non-owner node's entry are: (i) the membership-owner's
peer-add, whose capability CSV is
`role_capability_csv(&peer.capabilities)`
(`adapter/macos_membership.rs:269`, script builder `:180-205`) where
`NodeMembershipPeer.capabilities` is computed per peer by
`NodeRole::product_capabilities_for_platform`
(`stage/membership_init.rs:108-138` per Design §1.1 step 5); and (ii) the
bash-era post-join amendment `macos_membership_capabilities`
(`vm_lab/mod.rs:10738-10746`), which granted the elected anchor exactly
`"client,anchor.bundle_pull,anchor.port_mapping_authoritative"` — but that
function is `#[allow(dead_code)]` quarantined (W5.7 bash retirement,
`mod.rs:10717`, :10737) and unreachable under the Rust `--node` engine. The
`deploy_macos_anchor_profile` stage performs **no membership amendment at all**
(`mod.rs:15082-15173` — plist derivation + token seed + verify-before-serve
only). Consequently, when the macOS node's `--node` assignment role at
`membership_init` time is not `Anchor`, no later stage ever upgrades its entry,
and the port-mapping stage fail-closes. The election flag is OR-shaped:
`--anchor-platform macos` alone elects the three validator stages
(`native.rs:1019-1036`, `:267-277`, `:397`) even when the node's assignment
role is not `Anchor`, which is exactly the shape that produces a
validator-elected but capability-less macOS anchor. **Required mitigation
(folded into the Design's §5.1 checklist below): parameterize the Design's
single signed-capability rewrite by the node's ELECTED role, and add a
stage-level read-back assertion that the elected anchor's entry canonically
equals `anchor_role_capabilities()`.** The exact CSV the failing run's entry
carried must be confirmed from that run's snapshot artifact; the code-level gap
above is verified regardless.

### A.2 Does granting it fit the anchor capability model?

Yes — it is not a new grant, it is the existing canonical grant:

- `NodeRole::Admin | NodeRole::Anchor =>
  product_capabilities_for_platform` returns the anchor marker + `RelayHost` +
  all five anchor sub-capabilities including
  `AnchorPortMappingAuthoritative`, and the arm is explicitly
  platform-independent ("the same set is advertised on every OS",
  `role.rs:295-303`, comment `:284-294`).
- That set is exactly `anchor_role_capabilities()`
  (`rustynet-control/src/roles.rs:119-133`: `ANCHOR_CAPABILITIES`
  `:119-125` includes `AnchorPortMappingAuthoritative` at `:124`; the function
  prepends `Anchor` + `RelayHost` and canonicalizes).
- The membership format validator accepts it:
  `validate_membership_node_capabilities`
  (`rustynet-control/src/membership.rs:2668`) imposes
  `anchor.relay_colocation` ⇒ `relay_host` (`:2703-2710`) — satisfied — and
  `anchor.port_mapping_pinned` ⇒ `anchor.port_mapping_authoritative`
  (`:2711-2718`) — satisfied, and not triggered unless a pin is added.
- Nothing in the anchor set conflicts with any role the macOS anchor runs: the
  lab anchor maps to daemon `admin` on every platform
  (`role.rs:146`, `:162`), whose required capability is `Anchor`
  (`daemon.rs:2161`) — genesis/peer alignment holds by construction, exactly
  like the Linux exit (Design §1.1 step 4).

### A.3 Anchor cell vs exit cell: two per-role grants, one mechanism

The two cells need **different** capability sets and they are **mutually
exclusive in signed state** — `blind_exit` combined with `Anchor` or ANY
`anchor.*` sub-capability (which includes
`anchor.port_mapping_authoritative`, `roles.rs:98-108` at `:105`) is a hard
format rejection: `"cannot combine anchor and blind_exit capabilities"`
(`membership.rs:2692-2702`). Therefore no single CSV can serve both cells:

| Cell | Node | Target set | Source of truth |
|---|---|---|---|
| exit | macOS exit (lab `NodeRole::Exit`, macOS) | `{blind_exit, exit_server}` | `role.rs:186-189` |
| anchor | macOS anchor (lab `NodeRole::Anchor`, any OS) | `{anchor, relay_host, anchor.gossip_seed, anchor.bundle_pull, anchor.enrollment_endpoint, anchor.relay_colocation, anchor.port_mapping_authoritative}` | `role.rs:295-303` = `roles.rs:119-133` |

The Design's mechanism already parameterizes cleanly: one owner-signed op
(`ops e2e-membership-set-capabilities`, `ops_e2e.rs:2596-2700`) whose
`--capabilities` CSV **must** be derived at the call site from
`NodeRole::<elected>.product_capabilities_for_platform(<platform>)` via
`role_capability_csv` — never hand-typed (Design §1.2 already mandates this for
the exit cell; this review extends the mandate to the anchor cell). Two
concrete generalizations the implementation must carry:

1. **Derive from the ELECTED role, not a fixed role.** The Design's §1.2
   hard-codes the exit peer; the general form is
   `rewrite_script(node_id, elected_role, platform)` where `elected_role` is
   the node's `--node` assignment role. The exit cell's rewrite targets the
   membership OWNER's own entry; the anchor cell's rewrite targets a JOINED
   node's entry issued on the Linux authority — same op, different `--node-id`.
2. **Read-back-then-decide, per node.** For the anchor cell the peer-add path
   may already have written the correct set (§A.1 path (i)); the rewrite is a
   **repair**, executed only when the read-back snapshot's canonical set for
   that node ≠ the product grant (Design §1.2 idempotency rule, generalized).
   `validate_macos_anchor_port_mapping_authority` then remains the
   daemon-side live assertion, and a new stage-level exact-set assertion (§5.1
   step 4 analogue) becomes the provisioning-time backstop.

---

## PART B — Adversarial review of the extended design

Each attack was attempted against the Design (§1-§5) as extended by Part A.
Verdicts: **CONFIRMED-safe** (mechanism cited) or **RISK** (failure + required
mitigation). Under-claiming is preferred: "CONFIRMED-safe" means the cited code
closes the attack, not that no future change could reopen it.

### (a) Over-grant vs minimal?

**CONFIRMED-safe for the exit cell** (Design §3a already argued this; this
review confirms against the capability tables): `{blind_exit, exit_server}` is
exactly the daemon's required set for the role (`daemon.rs:2164-2165`), the
format layer forbids anything anchor-bearing alongside it
(`membership.rs:2692-2702`) and service-hosting alongside it
(`membership.rs:2719-2732`), and the canonicalizer plus
`decode`-side hard-reject of a missing capabilities field
(`membership.rs:2761-2769`, ENR-05) leave no room to ride extra grants.

**CONFIRMED-safe for the anchor cell, with one explicit boundary**: the target
set is the full canonical seven-capability anchor grant
(`role.rs:295-303` = `roles.rs:119-133`). That is *not* over-grant, because it
is the smallest set that satisfies the product model and the live validators —
`validate_anchor_capabilities` word-boundary-asserts ALL of
`REQUIRED_ANCHOR_CAPS` (`role_validation/anchor.rs:59-67`, `:197-213`),
`anchor.relay_colocation` cannot be signed without `relay_host`
(`membership.rs:2703-2710`), and the legacy bash-era elected-anchor CSV
`"client,anchor.bundle_pull,anchor.port_mapping_authoritative"`
(`mod.rs:10742`) is **not** an acceptable target (it under-grants: no
`anchor` marker, no `relay_host`, no `gossip_seed`/`enrollment_endpoint`/
`relay_colocation` — `anchor_validation` and gossip re-broadcast targeting
would fail, `role_validation/anchor.rs:231-263`). The boundary that must be
stated: `anchor.port_mapping_authoritative` lets the node *request and hold*
the router port-mapping lease **only when it wins the election**
(`daemon.rs:11462-11478`) — on the standard topology the senior Linux genesis
wins, so the macOS anchor holds an inert-unless-elected capability. That is
capability surface, honestly accounted: it is one of the five anchor
sub-caps the control plane already defines as the anchor role
(`AnchorNodeRoleDesign_2026-05-21.md` §cap-table; `NodeRoleTaxonomy_2026-05-21.md`
line 96), not a novel privilege invented for this fix.

**RISK (enumeration drift, low)**: a future eighth anchor sub-capability added
to `role.rs:295-303` would automatically flow into the derived rewrite CSV —
correct by derivation, but a sub-cap added ONLY to `roles.rs:119-133` (or vice
versa) would silently diverge the two "identical" sets. The role.rs comment
already claims exact equivalence (`:284-287`). **Required mitigation:** the
implementation should add a unit test asserting
`product_capabilities_for_platform(Anchor) == anchor_role_capabilities()` for
every platform, so drift fails a gate instead of a live run.

### (b) Cross-OS mesh consistency — does capability divergence break cross-node validation / gossip / authority election in one mesh?

**CONFIRMED-safe.** Four independent mechanisms, each cited:

1. **Self-validation only.** Each daemon validates ITS OWN entry against ITS
   OWN local role (`validate_node_role_membership_alignment` takes
   `local_node_id` + `node_role`, `daemon.rs:2262-2266`; called at `:5308`
   during bootstrap replay). No code path validates another node's record
   against one's own role table. Design §3b already established this; the
   anchor cell adds a third distinct set to the mesh (Linux exit
   `{client, anchor, exit_server, relay_host, anchor.enrollment_endpoint}` +
   genesis sub-caps, `role.rs:202-218` + `main.rs:4469-4479`; macOS exit
   `{blind_exit, exit_server}`; macOS anchor = the canonical anchor set) and
   the mechanism is unchanged.
2. **Mutual exclusion is per-node, not per-mesh.** The
   anchor⊕blind_exit format rejection (`membership.rs:2692-2702`) constrains
   each node's own record; a mesh containing an anchor-bearing Linux exit, a
   blind_exit macOS exit, and an anchor-bearing macOS anchor is legal because
   no single record mixes them.
3. **Serviceability is capability-driven.** The daemon requires the NAMED exit
   provider to hold `exit_server` in signed membership
   (`validate_exit_provider_membership`, `daemon.rs:1589`); the macOS exit
   holds it. Gossip seed targeting reads `anchor.gossip_seed` advertisements
   from the shared view (`role_validation/anchor.rs:226-230`,
   `validate_anchor_gossip_seed` requires the PRIMARY anchor to hold it,
   `:248-252`) — the macOS anchor holds it once Part A lands.
4. **The election is convergence-guaranteed, not coordination-based.** The
   pure function over shared signed state yields the same single winner on
   every node (`gossip_runtime.rs:931-937`, `:946-951`); heterogeneous
   eligibility sets across OSes change *who is in the candidate pool*, never
   *whether every node computes the same winner*.

**Residual watch-item (verification, not design change)**: with a
blind_exit-capped macOS exit as membership owner AND an anchor-bearing macOS
anchor as a peer, the mesh has two non-Linux-grant shapes simultaneously. The
live proof plan (Design §5.3) should explicitly watch
`distribute_membership`/`distribute_assignments` on the anchor topology the
same way §3b watches them for the exit topology.

### (c) Owner-key re-sign, epoch bump, anti-replay through verify-before-apply?

**CONFIRMED-safe.** The mechanism is the Design's §1.2/§2.2, unchanged by the
extension: `ops e2e-membership-set-capabilities` proposes from the current
snapshot, signs with the owner approver key, applies with epoch/replay checks
(`ops_e2e.rs:2624-2642` propose, `:2643-2661` sign,
`:2662-2676` apply; permission staging `:2622`, restore `:2680-2683`; audit
`:2677`). The apply path verifies the signature against the record, then
observes `update_id` + `epoch_new` in the replay cache
(`membership.rs:1032-1073`); the epoch watermark blocks rollback replays
(`membership.rs:721`), classification at `:1559`, same-root re-verification is
explicitly not a replay (`:1556-1557`). This is exactly the
SecurityMinimumBar signed-state ordering (verify → freshness → apply); the
Design performs the rewrite at provisioning time by the same authority that
signed genesis, before any distribution (Design §1.4), so no peer ever holds
the pre-rewrite state to be fooled by. Format-level rejection of illegal
target sets happens at propose/apply *before* signature is even the question
(`membership.rs:2668-2757`), so the rewrite cannot mint signed-invalid state.

### (d) Two authoritative nodes — single-winner conflict resolution?

**CONFIRMED-safe.** "Two nodes hold `anchor.port_mapping_authoritative`" is
the NORMAL state (genesis always holds it, `main.rs:4475`; an elected macOS
anchor holds it after Part A). The election is single-winner by construction:
`min_by_key` over `(!pinned, joined_at_unix, node_id)` is a total order with a
deterministic lex tie-break (`gossip_runtime.rs:946-951`), so duplicates never
split the mesh — every node computes the identical winner. Tie/duplicate
resolution hierarchy: (1) pinned beats unpinned, (2) earlier
`joined_at_unix` beats later, (3) lex-min node id. The operator pin
(`rustynet role pin-port-mapping-authority`) mints a `SetNodeCapabilities`
proposal through the normal sign/apply path, refuses targets lacking the
authoritative cap (`main.rs:19361-19397`), and the format layer refuses a pin
without the cap (`membership.rs:2711-2718`). A revoked/pinned-but-ineligible
node silently drops back to seniority (`gossip_runtime.rs:933-937`;
regression-tested at `:2113-2172`). The one behavioral note: bringing the
macOS anchor's cap online does NOT change who holds the lease on the standard
topology (senior Linux genesis still wins) — the uPnP lease holder only
changes if the macOS node is pinned or outlives/succeeds the genesis node
(`AnchorNodeRoleDesign_2026-05-21.md` line 228 handover semantics).

### (e) Migration of an existing deployed node lacking the caps?

**CONFIRMED-safe for the lab; RISK (direction-of-change) for the anchor cell —
mitigated.**

- *Exit cell*: the target node is already fail-closed dead
  (Design §3d), the signed update IS the migration, no factory reset needed
  (Design §2.4, §3d). Unchanged by this review.
- *Anchor cell*: the node is NOT dead today — it runs as a
  capability-less anchor peer whose port-mapping stage skips/fails. The same
  signed-update path migrates it (read-back → compare to product grant →
  rewrite → re-read). Epoch bump + replay cache handle an in-service node
  identically to a dead one (`membership.rs:1032-1073`).
- **RISK**: unlike the exit cell's strictly narrowing rewrite (Design §2.3),
  the anchor cell's rewrite is **privilege-ADDING** (it grants anchor-bearing
  capabilities onto an existing record). The fail-closed direction argument in
  Design §2.3 does not transfer. Mitigations, all already in the mechanism:
  (i) the CSV is derived from the reviewed product grant, never hand-typed
  (§A.3); (ii) the format validator rejects any illegal combination at
  propose/apply (`membership.rs:2668-2757`) — e.g. the rewrite cannot smuggle
  `blind_exit` onto an anchor node or vice versa; (iii) the signing authority
  is the same owner key that authorized genesis (§c); (iv) the change is
  provisioning-time, inside the lab orchestrator's `vm-lab`-gated surface
  (RNQ-17), not an operator-facing privilege-escalation verb. **Required
  mitigation to ADD**: the stage-level exact-set assertion must be
  bidirectional — assert the entry canonically EQUALS the product grant, so a
  rewrite that over-grants (or a peer-add that under-grants) both fail loudly
  (Design §5.1 step 4 asserts equality for the exit cell; replicate for the
  anchor cell against `anchor_role_capabilities()`).
- *Downgrade-rollback*: intentional non-feature. Once epoch N+1 is applied the
  watermark forbids re-applying epoch N (`membership.rs:721`) — a node cannot
  be rolled back to its pre-rewrite (weaker-or-stronger) set by replay. If an
  operator genuinely wants to REVOKE the anchor caps later, that is a new
  forward signed update (epoch N+2), not a rollback — which is the correct
  anti-rollback posture (SecurityMinimumBar §anti-replay).

### (f) blind_exit irreversibility (AGENTS.md §10.7) vs provisioning blind_exit-capable at/after genesis?

**CONFIRMED-safe, with one new invariant the extension must state.**

- The Design's §2.4 argument stands: provisioning a node blind_exit-capable is
  INITIAL STATE, not a role transition; §6.D.2's factory-reset gate governs
  *leaving* `blind_exit`, and no transition machinery is invoked
  (`role_presets.rs` transition matrix untouched; `role_cli.rs` gates
  untouched; daemon admin⊕blind_exit exclusivity `daemon.rs:2299-2304`
  untouched).
- The extension does not weaken this: the anchor cell's target set contains
  `Anchor`/anchor sub-caps, and the format layer would hard-reject any signed
  record that attempted to carry them onto a blind_exit node
  (`membership.rs:2692-2702`) — so the rewrite mechanism, even generalized and
  even if misdirected at a blind_exit node, cannot produce the forbidden state.
  Two independent layers hold (format + daemon), plus the Design's §5.2
  stage-level exact-set assertion as the third.
- **New invariant to state explicitly (adopted as part of this review's
  sign-off conditions): the generalized rewrite must derive its target set
  from the node's OWN elected role and must never be invoked to move a node
  ACROSS the anchor/blind_exit boundary.** Crossing that boundary in either
  direction is either format-rejected (blind_exit→anchor-bearing:
  `membership.rs:2692-2702`) or a §6.D.2 role transition requiring the typed
  confirmation / factory-reset semantics (anchor→blind_exit enters the
  irreversible posture). The one-way door is installed locked and the rewrite
  has no key: derive-per-role + format-reject + daemon-reject. A blind_exit
  node's only exit remains the factory reset, exactly as §10.7 demands.

---

## Updated sign-off checklist (supersedes Design §6; owner checks BOTH)

- [ ] Design §1.2 layer decision (adapter-level owner-signed rewrite; product
      code untouched) approved — unchanged.
- [ ] Design §2.3 narrowing direction accepted for the EXIT cell; §3a
      enrollment-endpoint limitation on macOS exits accepted — unchanged.
- [ ] **NEW (Part A)**: scope extension approved — the SAME signed-rewrite
      mechanism is parameterized per ELECTED role; the anchor cell's target
      set is the canonical `anchor_role_capabilities()` grant
      (`role.rs:295-303` = `roles.rs:119-133`), granting
      `anchor.port_mapping_authoritative` to the elected macOS anchor.
- [ ] **NEW (Part A)**: the legacy bash-era elected-anchor CSV
      (`client,anchor.bundle_pull,anchor.port_mapping_authoritative`,
      `mod.rs:10742`, quarantined) is explicitly REJECTED as a target set
      (under-grants vs `REQUIRED_ANCHOR_CAPS`, `role_validation/anchor.rs:59-67`).
- [ ] **NEW (Part B.a)**: the enumeration-drift unit test
      (`product_capabilities_for_platform(Anchor) == anchor_role_capabilities()`
      per platform) is required at implementation.
- [ ] **NEW (Part B.b)**: anchor-topology live proof explicitly watches
      `distribute_membership`/`distribute_assignments` with BOTH divergence
      shapes in one mesh (blind_exit owner + anchor peer).
- [ ] **NEW (Part B.e)**: the stage-level exact-set assertion is
      bidirectional equality (under-grant AND over-grant both fail loudly);
      the anchor cell's rewrite is acknowledged as privilege-ADDING, mitigated
      by derived-CSV + format validator + owner key + provisioning-time scope.
- [ ] **NEW (Part B.f)**: invariant adopted — the rewrite derives per-role and
      never crosses the anchor/blind_exit boundary; blind_exit's only exit
      remains factory reset.
- [ ] Design §3c structural blind_exit exact-set gap acknowledged as
      out-of-scope follow-up — unchanged.
- [ ] Design §4 posture review conclusion accepted (macOS exit stays
      `blind_exit`; rationale comment to be added at implementation) —
      unchanged.
- [ ] Design §5.2 negative tests + §5.3 live proof plan accepted, extended by
      the anchor-cell stage assertion above — unchanged otherwise.
- [ ] **Open verification item (before implementation)**: confirm from the
      failing macOS anchor run's snapshot artifact exactly which CSV the macOS
      anchor's entry carried (expected: no anchor-bearing caps; per §A.1 the
      OR-shaped `--anchor-platform macos` election without an `:anchor` node
      assignment is the suspected trigger). This confirms root cause; it does
      not gate the design.

## Verdict

**READY-pending-owner-signoff.**

No design change is REQUIRED: the extension folds into the Design's single
mechanism by parameterizing the capability CSV per elected role (derived from
`product_capabilities_for_platform`, never hand-typed) and by generalizing the
read-back-decide-rewrite flow from exit-only to any elected role. The eight
new sign-off items above are conditions of implementation, not blockers to the
design itself. The gate remains the owner's signature on the checklist, per
the QH-60/blind_relay convention for trust-state changes (Design header;
`SecurityMinimumBar.md` §6.C/§6.D.2).
