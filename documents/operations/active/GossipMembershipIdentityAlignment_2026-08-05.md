# Gossip identity alignment — design for publishing the real verifying key in signed membership

**DESIGN ONLY. NOT APPROVED. NO CODE WRITTEN.** Revision 3, after two adversarial
reviews. Each refuted a headline claim of the revision before it — including, both
times, a claim the author had labelled `[verified]`. §0.2 and §0.4 record what was
retracted and why, because a deleted error is one a later reader re-derives from
scratch.

A caution for whoever reads this next: the pattern across three revisions is that
**the sweeping conclusion was wrong while its narrow supporting fact was right**. Zero
`membership` occurrences in `live_linux.rs` was true; "the product path never runs
genesis" was false. `MembershipNode` deriving no serde was true; "only one type embeds
it" was false. Treat every generalisation below as the weakest link.

Follows on from `GossipProvisioningPhase1_2026-08-04.md` §7, which refuted the
scope split and left the migrate-vs-measure choice open, and §10.2, which lists
what Phase 1 did not close.

## Scope

**In scope.** Making the provisioning paths publish each node's real gossip Ed25519
verifying key into membership's `node_pubkey_hex`; the primitive that makes that
possible; and the migration path for nodes already provisioned.

**Explicitly out of scope**, and nothing below proposes touching them:

- the gossip **wire format** — unchanged; this changes what value a field carries,
  not how bundles are encoded or signed;
- what **`derive_gossip_signing_key` computes** — unchanged. §5.1 *calls* it. The
  design's whole point is that the daemon's existing derivation is authoritative and
  everything else must match it, never the reverse;
- **`crates/rustynet-backend-wireguard/`** — untouched. Another agent has work in
  flight there. Worth stating plainly because the WireGuard public key appears
  throughout as the *wrong* value being published; that is a fact about producers in
  `rustynet-cli`, not a reason to touch the backend;
- the three-valued `gossip_identity_mismatch` surface, which is correct as built and
  is the measurement this work depends on.

## 0. Provenance of every claim

- `[verified]` — I read the cited line myself and the claim is what the code says.
- `[computed]` — established by running an independent calculation, not by reading.
- `[reported]` — asserted by a review or an existing document, not re-read by me.
- `[open]` — could not be established; recorded as a question, not an answer.

### 0.1 The five questions, and an honest note about them

The task brief asked for five numbered questions answered with file:line evidence.
**The brief's verbatim list was not recoverable** from the session transcript — only
a paraphrase survived — so rather than fabricate a quote, the five below are
reconstructed from what the design must settle. If the intended five differed,
§1–§4 should still cover the ground.

| # | Reconstructed question | Answered in |
| --- | --- | --- |
| Q1 | Where does a node's real gossip verifying key come from, and can anything obtain it today? | §1, §4, §5.1 |
| Q2 | Which paths publish `node_pubkey_hex`, and is the enumeration complete? | §3.3 |
| Q3 | What reads the field, and does changing its meaning break a consumer? | §3.2 |
| Q4 | What is the migration path for already-provisioned nodes, and what does it cost? | §5.3, §6 |
| Q5 | How would the change be proven, and what would stay unproven? | §7 |

### 0.2 What the adversarial review changed — including a retraction

Revision 1 was reviewed by an independent agent instructed that endorsement is a
failed review. I then re-read every load-bearing line myself rather than taking its
word; two of its claims needed correcting in turn.

**Retracted — revision 1's fail-open revocation claim was wrong.** Revision 1
asserted that alignment would create a fail-open path: a revoked-then-rotated node
signing under a new key while membership listed the old one. That path **fails
closed**, three times over. Registration is Active-only
(`crates/rustynetd/src/gossip_runtime.rs:846`, `if member.status !=
MembershipNodeStatus::Active { continue; }`); inbound rejects an unknown source
*before* the revoked check is reached
(`crates/rustynetd/src/peer_gossip.rs:602-604`, `known_peers.get(&bundle.source_node_id)
.ok_or(GossipError::UnknownSource)?`); and revoked ids are additionally
unregistered, not merely blocklisted (`crates/rustynetd/src/daemon.rs:5552-5555`).
All `[verified]`. §6's D3 rested on this and has been rewritten.

**Corrected — the reader labelling in §3.2.** Revision 1 called five files
"test-fixture constructors". Three are **production audit binaries**: their
`#[cfg(test)]` blocks begin at `membership_signature_audit.rs:562`,
`membership_revoke_audit.rs:396` and `blind_exit_reversal_audit.rs:228`, all *after*
the fixture lines 139/109/79, and all three are dispatched as real verbs
(`crates/rustynetd/src/main.rs:240`, `:243`, `:249`) `[verified]`. The substantive
conclusion survives — see §3.2 — but the mislabel understated §5.4's blast radius.

**Downgraded — the review's own BLOCKER on §5.4.** The review argued a
canonical-point tripwire could break those three shipped audits, but said it could
not check whether their fixtures are curve points because it was barred from running
code. I settled it independently (§5.4): `[9u8;32]` and `[10u8;32]` **are** valid
Ed25519 points, so those three audits are unaffected. Two *other* fixtures are not
points and would break. Labelling error, not a build-breaker.

**Accepted in full**: the missed producer family (§3.3), the platform blocker (§4.3),
the epoch-skew migration window (§5.3), the second registration authority (§3.4),
the owner-gating asymmetry (§6 D5), and a set of citation off-by-ones now fixed.

### 0.3 A second, independent pass — and what it did not get to

Separately from the review above, six independent investigations were run against the
code, one per load-bearing question, each intended to be attacked by its own skeptic.
**The six investigations completed; five of the six skeptics and the adjudicator all
died on server-side `API Error: 529 Overloaded` after retries.** A resume replayed the
six completed investigations from cache and re-ran the skeptics, which failed the same
way. So the findings below carry the six investigations' evidence but **were not
adversarially attacked** — I re-read every load-bearing line myself instead, and that
is the only reason they appear here rather than as `[open]`.

What that second pass added, all since verified by me:

- **§3.5, the largest single correction** — the product installer never runs membership
  genesis, so enrollment is the production path.
- **§3.3 P10** — a fourth flag spelling and a renamed field that made `RotateNodeKey`
  invisible to every previous enumeration, including the review's.
- **§3.2's structural completeness argument** — no serde, no `Deref`, one embedding,
  therefore literal-grep is exhaustive *for reads*.
- Independent corroboration of two conclusions reached above by different routes: the
  revocation claim is refuted, and no consumer treats the field as a WireGuard key.
  Two independent agreements on the second point is the strongest evidence in this
  document.
- A citation fix: `revoked_peer_ids_from_membership` is defined at
  `gossip_runtime.rs:782`; `:792` is a line inside its body `[verified]`.

One fact worth keeping in view: the gossip verifying key is **not secret**. It is the
`source_node_id` of every bundle a node mints (`peer_gossip.rs:480`) `[reported]`, so
it already crosses the wire by design. §5.1 is about exposing it *locally to the
operator*, not about revealing something confidential.

### 0.4 What revision 3 retracted

A second adversarial review attacked revision 2's new material. I verified each claim
against the code before accepting it. Retracted or corrected:

- **§3.5's headline, retracted.** "The product path never runs genesis" is false:
  `ops init-membership` is an ungated verb in the shipped binary that shells
  `rustynetd membership init --force` (`main.rs:1412`, `:14009-14011`, `:20459`)
  `[verified]`. The consequence inverts — genesis is product work, and on macOS it is
  *worse* than revision 2 thought (§3.5, §4.3).
- **§4.1's "no test names `decrypt_private_key`", retracted.** One does, and it is
  worse than absence: `build_gossip_node_derives_gossip_only_subkey_from_encrypted_secret`
  (`daemon.rs:20158`) is the pin §4 asks for, but its fixture is 32 bytes ending `0x0a`,
  so it silently exercises the vacuous case while its comment claims otherwise
  `[verified]`.
- **§3.2's structural premise, corrected.** Two types embed `MembershipNode`, not one
  (`membership.rs:189`) `[verified]`. Conclusion survives; argument repaired.
- **§3.3's spelling count, corrected.** Five spellings, not four — `--pubkey`
  (`main.rs:6515`, `:6535`) was cited in §5.2 and omitted from the count `[verified]`.
- **§5.4's statistic, corrected.** The valid fraction is exactly `8ℓ/2^256` = 50%
  `[computed]`; revision 2's "50.1% measured (4000 samples)" over-claimed precision on
  a quantity available in closed form.
- **§3.4's severity, bounded.** The accept is real but ages out after two further epoch
  bumps (`peer_gossip.rs:637-641`) `[reported]`; revision 2 implied it was permanent.

Added: the small-order fixture `"00".repeat(32)` (`main.rs:22250`) `[computed]`; the
absence of any platform/capability filter on peer registration (§4.3); and the
admit-vs-consume validation asymmetry (§7).

Not retracted, and now confirmed by two independent reviews plus my own reading: no
consumer treats the field as a WireGuard key (§3.2), and the `enrollment_consume`
bypass reaches an accept (§3.4).

## 1. The root cause is a missing primitive, not a set of buggy producers

Every provisioning path publishes a wrong value into `node_pubkey_hex`. It is
tempting to read that as N independent bugs. It is not.

`rustynetd key` supports exactly `init`, `init-gossip`, `migrate`,
`store-passphrase` (`crates/rustynetd/src/main.rs:460`, dispatch `:464-469`)
`[verified]`. **No verb prints the gossip verifying key.** In-process it exists only
as `GossipNode::local_node_id`, defined `crates/rustynetd/src/gossip_runtime.rs:201`
and set at `:276` from `signing_key.verifying_key().to_bytes()` `[verified]`.

So no producer is *able* to publish the right value; each publishes whatever key it
does have. Fixing producers without first adding an export primitive is not
possible. That reframing matters: it converts a long list of independent bugs into
one prerequisite plus mechanical follow-through.

One qualification, so the claim is not overstated: the value is not perfectly
sealed. `short_id` emits the first 8 bytes — 16 hex chars — into gossip logs
(`gossip_runtime.rs:468`, `:476`, `:542`) `[reported, not re-read]`. That is not a
usable programmatic surface and does not remove the need for §5.1, but it does hand
§7 a free cross-check.

## 2. The code already states the contract it does not honour

`crates/rustynetd/src/gossip_runtime.rs:819-824` `[verified]`:

> The peer id AND the verifying key are the member's 32-byte `node_pubkey_hex` from
> signed membership. That value is the contract: membership publishes each node's
> GOSSIP verifying key (the `derive_gossip_signing_key` sub-key, I1a) …

And the implementation at `gossip_runtime.rs:852-868` decodes `node_pubkey_hex` once
into `peer_node_id`, then builds `VerifyingKey::from_bytes(&peer_node_id)` from those
same bytes, with both failure branches a silent `continue` `[verified]`.

This document therefore proposes **no contract change**. It proposes making the
producers meet the contract that already exists.

## 3. Enumeration by type and symbol

The brief required enumerating by type/symbol rather than one grep pattern. That
was the right instruction and revision 1 still under-counted: a name-grep misses
every producer that passes the value as a **CLI flag to a subprocess**, and there
are more of those than revision 1 found.

### 3.1 Two distinct types own a field of this name

| Type | Location | Role |
| --- | --- | --- |
| `MembershipNode` | `crates/rustynet-control/src/membership.rs:166` | the signed membership record |
| `EnrolleeAdmitContext` | `crates/rustynet-control/src/enrollment.rs:65` | enrollment input; its doc already claims "Ed25519 verifying key" |

Both `[verified]`. A name-grep conflates them; they are different flows.

### 3.2 Readers — and the feasibility argument, which survives

| # | Symbol | Location |
| --- | --- | --- |
| R1 | `gossip_peer_registrations_from_membership` | `gossip_runtime.rs:838`, field read `:852` |
| R2 | `revoked_peer_ids_from_membership` | defined `gossip_runtime.rs:782`, field read `:792` |
| R3 | `anchor_gossip_seed_peer_ids_from_membership` | `gossip_runtime.rs:772` |
| R4 | `gossip_identity_mismatch_state` + warn latch | `daemon.rs:5712`, `:5573` |

All `[verified]`. (Revision 1 named R1 `desired_gossip_peer_registrations`; **that
symbol does not exist** — the cited line was right, the name was invented from
surrounding prose. Corrected.)

**No reader anywhere treats the field as a WireGuard key**, so publishing the gossip
key breaks no consumer. This is the design's load-bearing feasibility claim, and it
is the one claim the adversarial review tried hardest to break and could not: it
independently enumerated field *reads* (rather than constructor forms) and found the
same five production sites, confirming the only `VerifyingKey` construction from the
field is `gossip_runtime.rs:858`, with everything else being length validation
(`membership.rs:240`, `:1948`, `:2012`), canonical-payload serialisation (`:333`,
`:551`), or the reducer assignment (`:2018`) `[reported]`. It further checked the two
plausible cross-contamination sites and found them clean — `resolve_peer_identity`
(`service_exposure.rs:234-245`) keys on overlay IP → node_id, and
`MembershipDirectory` carries only status and selector members `[reported]`.

**The reader enumeration is structurally provable, not merely grepped** — which is
the right standard given the brief's warning, and it is worth recording because it
converts "I searched and found nothing" into "nothing else can exist".
`MembershipNode` derives only `Debug, Clone, PartialEq, Eq` — **no serde, no
`Deref`** (`membership.rs:163`) `[verified]`, with no manual `Serialize` impl in the
crate `[reported]`. With no derived serialisation and no deref coercion, every direct
read of the field must contain the literal `node_pubkey_hex`, so enumerating that
literal *is* exhaustive for reads. A second review searched specifically for the holes
— `let MembershipNode { .. }` destructuring, `..` struct-update in production,
`PartialEq`/`Debug` reads, macro-generated access — and found none outside `#[cfg(test)]`
fixtures `[reported]`.

**Correction to revision 2, which overstated the premise.** It claimed "the only type
embedding it is `MembershipOperation::AddNode`". **Two** types embed it: `AddNode`
(`:403`) and `MembershipState.nodes: Vec<MembershipNode>` (`:189`) `[verified]` — the
latter twenty-six lines after the line revision 2 cited. The conclusion survives the
correction, but a paragraph arguing "structurally provable, not merely grepped" cannot
rest on a mis-stated premise, so it is fixed here rather than quietly kept.

Two limits on the argument's scope. First, the asymmetry that caught every pass: it
holds for **reads** but not **writes**, because `RotateNodeKey` writes the field from a
differently named source (§3.3 P10). Second, it holds for reads *of the struct field*,
not reads of the value destined for it — `op.new_pubkey_hex` is validated, serialised
and parsed at `membership.rs:585`, `:587` and `:2205` with no occurrence of
`node_pubkey_hex` `[reported]`. That is the same definitional narrowing this document
blames for P10 hiding, so the claim is "exhaustive for direct field reads", nothing
wider.

Independently confirmed disjoint: the real WireGuard peer-key path never touches
membership — keys enter via the `--nodes` spec (`rustynet-cli/src/main.rs:16449`) into
`AssignmentNodeSpec.public_key` → `NodeMetadata.public_key` → `AutoTunnelPeer.public_key`
→ the signed auto-tunnel bundle's `peer.{i}.public_key_hex`, decoded at
`daemon.rs:13338`; and `rustynet node info` reads the WireGuard pubkey from the key
file, not membership `[reported]`. A search across `.sh/.py/.json/.yaml/.service/.txt/.conf`
for `node_pubkey` returns nothing, so there are no non-Rust readers `[reported]`.

The apparent overloading is a **producer-side** phenomenon: one collected value is
handed to two different sinks (§3.3).

Correction carried from §0.2: three of the files revision 1 dismissed as fixtures
are production audit binaries. They do not read the field — they *construct*
`MembershipNode` values in production code — so the feasibility claim is unaffected,
but they are in scope for §5.4.

### 3.3 Producers — the enumeration revision 1 got wrong

| # | Path | Value published | Location |
| --- | --- | --- | --- |
| P1 | membership genesis | raw CSPRNG bytes | `rustynetd/src/main.rs:4129` |
| P1b | genesis via PowerShell bootstrap | same, invoked remotely | `scripts/bootstrap/windows/Install-RustyNetWindowsAnchorService.ps1:182` `[reported]` |
| P2 | `rustynetd membership add-peer --node-pubkey-hex` | operator-supplied | `rustynetd/src/main.rs:3774` |
| P3 | `rustynet membership propose-add --node-pubkey` | operator-supplied | `rustynet-cli/src/main.rs:5940`, `:6115` |
| P3b | `membership propose --operation rotate-node-key`, and a second route `propose-rotate-key` | operator-supplied | `rustynet-cli/src/main.rs:6181`, `:6002` `[reported]` |
| P4 | `rustynet enrollment admit --pubkey <b64>` | whatever the enrollee presents | `rustynet-cli/src/main.rs:8415` → `:8458` → `enrollment.rs:175` |
| P5 | orchestrator peer-builder | **typed `WireguardPublicKey`** | `vm_lab/orchestrator/context.rs:40`, `stage/membership_init.rs:88` |
| P5a | linux membership adapter | `--client-pubkey-hex` | `orchestrator/adapter/linux_membership.rs:86` |
| P5b | macos membership adapter | `--client-pubkey-hex` | `orchestrator/adapter/macos_membership.rs:78` |
| P5c | windows membership adapter | `--node-pubkey-hex` | `orchestrator/adapter/windows_membership.rs:308` |
| P6 | `ops e2e` membership-add | WireGuard pub, b64→hex | `ops_e2e.rs:4053` → `:4066`, `:4157`; pass-through at `:1953` |
| P7 | vm_lab macOS / Windows paths | WireGuard pub from disk | `vm_lab/mod.rs:13847`, `:24609` `[reported]` |
| P8 | shell orchestrator | `--client-pubkey-hex` | `scripts/e2e/live_linux_lab_orchestrator.sh:3584` `[reported]` |
| P9 | netns harness | `rand_hex_32` | `scripts/vm_lab/netns_daemon_path.sh:218` |
| **P10** | `RotateNodeKey`'s own write — field `new_pubkey_hex`, flag `--new-pubkey` | operator-supplied | `membership.rs:2008-2018`; `rustynet-cli/src/main.rs:6004`, `:6183` |

P1–P6, P9 and P10 `[verified]`; the four marked `[reported]` come from the review and
I have not re-read them.

**P10 is the one every earlier pass missed**, including revision 1 and the
adversarial review. `MembershipOperation::RotateNodeKey` carries its pubkey in a
field named **`new_pubkey_hex`**, not `node_pubkey_hex`, and reaches it through its own
flag spelling, `--new-pubkey` (`main.rs:6004` and `:6183`) `[verified]`.
It is therefore invisible to a `node_pubkey_hex` grep *and* to greps for all three
other flag spellings, while writing the very field under discussion
(`membership.rs:2018`). It is also the mechanism §5.3 proposes to migrate with — so
the migration verb is itself an unaligned producer.

**Two lessons worth keeping.** First, revision 1 found six producers and there are
roughly fifteen — the gap is entirely paths that pass the value as a subprocess flag
or under a renamed field, across **five** spellings: `--node-pubkey`,
`--node-pubkey-hex`, `--client-pubkey-hex`, `--new-pubkey`, and `--pubkey`
(`main.rs:6515`, `:6535` — the flag on P4, the very producer this document calls the
production surface) `[verified]`. Revision 2 said four, having cited the `--pubkey`
sites in §5.2 while omitting them from its own count. Two binaries, two scripting
languages.

For completeness, the operation enumeration is now closed: `MembershipOperation` has
eight variants, of which three carry a pubkey — `AddNode`, `RotateNodeKey` and
`RotateApprover` — and only the first two write `node_pubkey_hex` (`RotateApprover`
writes `approver_pubkey_hex`, `membership.rs:178`). `rustynetd membership` itself
exposes only `init` and `add-peer` `[reported]`. So there is no sixth spelling and no
further operation that writes this field.

Second, and worse for effort estimation: at P5 the source
variable is **typed** `BTreeMap<String, WireguardPublicKey>` (`context.rs:40`)
`[verified]` and the *same* value simultaneously feeds the real WireGuard peer
configuration. So those sites are not a value swap — they are **splitting one
collected value into two distinct values**, materially larger than revision 1's
"P5/P6 are lab paths" implied.

### 3.4 Two findings stronger than Phase 1 §7's framing

**Genesis publishes a public key with no private counterpart in existence.**
`node_key_bytes` appears at exactly four lines — allocated `main.rs:4119`, filled
from the CSPRNG `:4121`, hex-encoded into `node_pubkey_hex` `:4129`, zeroized
`:4232` — and is consumed only at `:4161`. It is never persisted and never signs
`[verified]`. Contrast `approver_key_bytes`, whose published value correctly goes
through `.verifying_key()` (`:4128`) and whose private half is persisted (`:4132`).
So the genesis record is not a mis-derived key; it is a public key for which no
private key exists anywhere. **No migration can recover it — genesis must change
under every option in §6.**

**There are two independent gossip peer-registration authorities, and revocation
only reaches one.** Revision 1's four-reader model treated membership as the sole
authority. It is not: `crates/rustynetd/src/enrollment_consume.rs:219-220` calls
`gossip_node.register_peer(enrollee_node_id, enrollee_pubkey, enrollee_push_addr)`
with the enrollee-supplied key, reached in production from `daemon.rs:8615`
`[verified]`. The module doc is explicit that this key "is taken at face value" and
that the remedy for misbehaviour is to "rotate them out via the membership-revoke
path" (`enrollment_consume.rs:30-33`) `[verified]`.

That remedy only works if the registered id equals membership's `node_pubkey_hex`,
because revocation is computed from membership (`daemon.rs:5552`). **Today those two
values need not agree**, so a peer registered via enrollment can survive membership
revocation.

The mechanism is worth stating exactly, because §0.2's retraction shows how easy it
is to get this direction wrong. Inbound order is: unknown-source rejection
(`peer_gossip.rs:602-604`), then `verify_signature` (`:605`), then candidate scope,
freshness and epoch skew `[verified]`; the revoked-set check runs *after* signature
verification, as `gossip_revoked_readmit_audit.rs` documents (it "checks it on every
inbound bundle, after signature verification and before any state mutation")
`[verified]`. So an enrollment-registered peer **is** present in `known_peers` — it
therefore clears the unknown-source gate that closes the §0.2 case — and its
signature verifies under its own real key. The revoked check then consults ids
derived from membership, misses because the registered id differs, and the bundle
proceeds. **This one reaches an accept.** It is the fail-open revision 1 thought it
had found, in a different place and for a different reason. Two independent reviews
traced this path and both confirmed the accept `[reported]`, and both confirmed the
obvious mitigation does *not* apply: nothing prunes a peer merely absent from
membership — `sync_gossip_data_plane` unregisters only ids in the revoked set
(`daemon.rs:5552-5556`) `[verified]`, and `register_peer` is a plain additive insert
(`gossip_runtime.rs:308-321`) `[reported]`.

**It is bounded in time, though, and revision 2 presented it as permanent.** The epoch
arm is documented as exactly the mechanism that ages this class out
(`peer_gossip.rs:637-641`): a peer cut off from membership updates has its truthful
epoch frozen while the mesh advances, so once the local epoch runs more than
`GOSSIP_EPOCH_SKEW_WINDOW = 2` (`:147`) ahead, its bundles are rejected on skew
regardless of the revoked set `[reported]`. The revoking update supplies one bump, so
the window closes after two *further* membership updates — unbounded only while
membership is quiescent. That is a mitigation, not a fix, and it is timing-dependent
rather than structural.

(The pivot sentence above — that the registered id and membership's `node_pubkey_hex`
need not agree — is an inference from the two write paths, not a line I read. Marking
it `[inferred]` rather than leaving it bare, since the whole finding turns on it.)

Note the direction carefully: the review framed this as a hazard *created by*
alignment; it is the opposite. Alignment makes the two authorities agree and
therefore **closes** it — provided both paths are updated together. That requirement
is now explicit in §5.2.

A related structural defect, independent of alignment: `register_peer` is additive
(`gossip_runtime.rs:308-321`) and `unregister_peer` has one production caller, for
revoked ids only (`daemon.rs:5555`) `[reported]`. Nothing prunes a peer that merely
*changed* key, so a rotation leaves the old key registered for the process lifetime
on peers that already synced. This weakens `RotateNodeKey` as a response to key
compromise and is recorded in §8 rather than fixed here.

### 3.5 Which paths actually genesis a node (revision 2's answer here was wrong)

This reorders the whole design and no earlier pass had it.

**Lab path**: the mint runs *before* genesis, in the same process, same closure, same
machine — `key init-gossip` at `ops_e2e.rs:467-480` and `membership init` at
`:574-597`, both inside one closure of `execute_ops_e2e_bootstrap_host` (`:206`)
`[reported]`. So on the lab path the secret already exists on disk when genesis writes
`node_pubkey_hex`, and genesis *could* publish the real key today.

**Product path**: `rustynet install` **never runs membership genesis at all**. The
string `membership` does not appear anywhere in
`crates/rustynet-cli/src/install/live_linux.rs` — zero occurrences `[verified]` — and
the install terminates at `awaiting_enrollment_message` (`live_linux.rs:305-310`)
`[verified]`:

> service installed and enabled; the daemon is awaiting enrollment — it activates once
> trust material is delivered (run `rustynet enrollment consume <token>`). This is the
> correct fail-closed terminal state for a fresh node.

**But "the product path never runs genesis" is FALSE, and revision 2 asserted it.**
A second adversarial review refuted it and I confirmed the refutation. Genesis is
reachable from the **shipped product binary** via `rustynet ops init-membership`,
which is not feature-gated at any wiring point:

- the enum variant `InitMembership` sits at `rustynet-cli/src/main.rs:1412`, between
  two ungated neighbours, with **no** `#[cfg(feature = "vm-lab")]` — whereas
  `E2eBootstrapMacos` twenty lines earlier *is* gated (`:1359-1360`) `[verified]`;
- its body shells `rustynetd membership init … --force` (`main.rs:14009-14011`)
  `[verified]` — that is P1;
- it is advertised in the product `--help` (`:20459`) `[verified]`.

The `vm-lab` feature is default-off precisely so the shipped binary carries none of
the lab surface, and the lab bootstrap verbs *are* gated while this one is not — so
the contrast is deliberate, not an oversight in the gating.

Revision 2 should have caught this from its own evidence: the P1b row in §3.3 already
records genesis being invoked from a **product** PowerShell bootstrap
(`Install-RustyNetWindowsAnchorService.ps1:182`). §3.5 asserted a conclusion its own
producer table contradicted. The narrow fact — zero `membership` occurrences in
`live_linux.rs` — is true and remains useful; the sweeping conclusion drawn from it
was not.

**What survives, and what inverts.**

1. **P4 + `enrollment_consume` are still the surface a fresh node arrives through.**
   All three installers terminate awaiting enrollment `[verified for Linux]`, so the
   requirement that P4 and `enrollment_consume` change *together* (§3.4) stands as
   the core of the product-path fix.
2. **Genesis is NOT merely a lab and founder concern** — inverted. It is reachable on
   Linux and macOS product nodes, so it must be aligned as product work, and D2 is a
   real decision again rather than a lab-only one.
3. **D4 gets worse, not narrower.** On Linux, `install` mints the gossip secret
   (`live_linux.rs:175`, `:180`) before any later `ops init-membership`, so ordering
   there is benign. On **macOS**, `install` never mints (§4.3), so
   `ops init-membership` publishes CSPRNG bytes for a node that has no gossip secret
   at all and cannot acquire one through its installer.

Also established: Linux `rustynet install` supports only `--role node`, rejecting
relay/exit/anchor (`live_linux.rs:45-52`) `[reported]`. Whether operators actually run
`ops init-membership` in the field is `[open]` — its only in-repo callers are the
vm-lab adapters, and no runbook was found instructing it `[reported]`. That does not
rescue §3.5's original claim: the verb ships in the product binary and in its help.

## 4. The 33-byte HKDF input constrains the implementation

The daemon's gossip path loads through `decrypt_private_key`
(`crates/rustynetd/src/daemon.rs:4056`) and then derives at `:4059`
(`let signing_key = derive_gossip_signing_key(signing_secret);`) `[verified]`.
`decrypt_private_key` appends a trailing newline if absent
(`crates/rustynetd/src/key_material.rs:538-539`) `[verified]`, and
`derive_gossip_signing_key` HKDFs over exactly the bytes handed to it
(`crates/rustynet-control/src/lib.rs:3565-3578`) `[verified]`. So the daemon derives
from `<32 minted bytes> || b"\n"`, and an independent deriver fed the 32 minted bytes
gets a different key. Already documented at the constant, `main.rs:478-488`.

**Design consequence.** The §5.1 primitive must obtain its bytes by calling
`decrypt_private_key` and `derive_gossip_signing_key`, so the normalisation is
reproduced *by construction*. It must not re-implement the load and must not
"helpfully" strip the newline. A test pinning export output against a hand-computed
HKDF would re-implement the trap and pass while being wrong; the pin must be against
the daemon's own derivation. That pin is exact and cheap, since `GossipNode::new`
sets `local_node_id = signing_key.verifying_key().to_bytes()`
(`gossip_runtime.rs:276`) `[verified]` — so the assertion is literally
"export output == hex of `GossipNode::new(derive_gossip_signing_key(loaded)).local_node_id`",
with no independent crypto in the test.

**The append is conditional, which makes a naive test vacuous.** Minted material is
32 raw CSPRNG bytes, so with probability 1/256 the last byte is already `0x0a`, no
newline is appended, and that node's HKDF input is 32 bytes. A mutation test for
"export strips the newline" therefore passes vacuously against any fixture secret
ending in `0x0a`. The test must assert its fixture does not end in `0x0a`.

### 4.1 The 33-byte behaviour has a test that looks like a pin and is not

Newline handling exists at exactly two sites in the tree: `key_material.rs:538-539`
(the gossip-relevant one) and `:870-871`, which is inside
`generate_wireguard_keypair` and merely normalises `wg genkey` output `[verified]`.
The encrypt side appends nothing, so the stored blob is exactly the 32 minted bytes.

Revision 2 claimed "**no test anywhere names `decrypt_private_key`**" and labelled it
`[verified]`. **That was wrong**, and the truth is a sharper finding than the error.

A test does exercise the full production load path:
`build_gossip_node_derives_gossip_only_subkey_from_encrypted_secret`
(`crates/rustynetd/src/daemon.rs:20158`), which encrypts a secret, calls the real
`build_gossip_node`, and asserts `node.local_node_id` equals
`derive_gossip_signing_key(plaintext).verifying_key().to_bytes()` (`:20191-20195`)
`[verified]`. That is, almost exactly, the pin §4 asks for — already built, minus the
export verb.

**But it is the vacuous case, and its own comment says the opposite.** The comment at
`:20162-20164` states the fixture pins the newline "to make the exact derivation input
explicit". The fixture is `b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"` (`:20165`) — I
counted it: **31 `'A'` plus `\n` = exactly 32 bytes, final byte `0x0a`** `[computed]`.
So `decrypt_private_key`'s conditional append is a **no-op** for this fixture, and the
test pins the 32-byte path while claiming to pin the 33-byte one. Deleting
`key_material.rs:538-539` leaves it green.

The other derivation test, `derive_gossip_signing_key_is_domain_separated`
(`rustynet-control/src/lib.rs:8011`), also uses a 32-byte secret, deliberately
(`:8012-8014`) `[verified]`.

**Consequence — unchanged in substance, corrected in remedy.** Someone tidying
`key_material.rs:538-539` would silently change the gossip identity of every
provisioned node and **no test would fail**. Once membership publishes derived keys,
that tidy-up invalidates every published record at once.

But the fix is *not* "write a pin that does not exist". It is **repair a test that
looks like the pin and is not** — which is strictly worse than absence, because a
reviewer reading the test's name and comment would conclude the behaviour is covered.
Note too that it is gated `#[cfg(all(unix, not(target_os = "macos")))]` (`:20156`)
`[verified]`, so it does not run on macOS either.

### 4.2 The export verb inherits a Windows precondition

`decrypt_private_key` calls `verify_dpapi_startup_self_test()` before opening the
custody manager (`key_material.rs:529`), with separate Windows and non-Windows
definitions (`:402`, `:437`) `[verified]`. A verb that correctly reuses the load path
inherits a DPAPI self-test on Windows and can fail for reasons unrelated to the
gossip secret. That is right — it fails closed — but the error reporting must
distinguish it, or an operator reads DPAPI failure as "gossip not minted".

Passphrase resolution is a constraint, not a parameter: the e2e bootstrap records
that `resolve_passphrase_source` is process-global and "refuses to fall back to a
per-secret path, so a secret sealed under a different passphrase would be
permanently unloadable" (`ops_e2e.rs:462-466`) `[verified]`, which is why both mint
callers deliberately reuse the WireGuard passphrase file. The verb cannot take a
per-secret passphrase path. It must also run as the daemon uid or root and be told
where the secret lives, since the paths exist only in the unit environment
`[reported]`.

Test-coverage risk is the mirror image: gossip status tests are predominantly
`#[cfg(unix)]` — 63 occurrences of that gate in `daemon.rs` `[verified]` — so a test
written to match its neighbours would leave the Windows path unproven.

### 4.3 BLOCKER — two of three platforms cannot satisfy the design as stated

This is the review's most valuable finding and it is confirmed.

- **Windows cannot have a gossip identity at all.** `daemon.rs:11539-11547` rejects
  any configured gossip secret under `#[cfg(not(unix))]` with "gossip signing secret
  is not supported on this platform: the gossip transport is unix-only" `[verified]`.
- **macOS never mints one.** `init-gossip` appears **zero** times in both
  `crates/rustynet-cli/src/install/live_macos.rs` and `install/live_windows.rs`
  `[verified]`; the mint exists only in `install/live_linux.rs:173-179` and
  `ops_e2e.rs:468-479` `[verified]`.

Yet P5b and P5c are producers that must publish *something* for macOS and Windows
nodes. So §5.1's verb returns "not minted" on macOS and can never succeed on
Windows, and §5.2 is unimplementable for those platforms. Revision 1 did not
address this at all. It becomes decision **D4**; it is not resolvable by design
alone, because "what a Windows node publishes" is a policy question about a node
that cannot participate in gossip.

Note this also bounds §5.4's claim that `gossip_identity_mismatch` is "the real
gate": on a node with no gossip node it returns `"unknown"`
(`daemon.rs:5699-5701`) `[reported]`, so on macOS and Windows the gate measures
nothing.

**And nothing excludes them from the peer set, so D4 is a real problem rather than a
narrow one.** The obvious hope is that macOS and Windows members are filtered out
before registration by some capability, role or platform predicate. They are not:
`gossip_peer_registrations_from_membership` (`gossip_runtime.rs:838-870`) filters only
on Active status, not-self, hex-decodability, `VerifyingKey::from_bytes` success, and
presence of an overlay address `[reported]` — there is no platform or capability term.
So macOS and Windows membership entries **do** become candidate gossip peers on every
Linux node, and whatever they publish in `node_pubkey_hex` is consumed as a verifying
key by peers that can never receive a valid signature from them. D4 must therefore
answer what those nodes publish; "they are not gossip participants anyway" is not
available as an answer.

## 5. The design

### 5.1 Step 1 — add the missing export primitive (prerequisite for all else)

A new `rustynetd key` verb that loads the gossip secret through the existing custody
path and prints the derived verifying key as lowercase hex. Sibling of
`init-gossip`, dispatched alongside it at `main.rs:466` `[verified]`.

Requirements: reuse `decrypt_private_key` + `derive_gossip_signing_key` unmodified;
never print or log the secret; and return **distinguishable** errors for
not-minted, cannot-read, and (per §4.2) Windows DPAPI self-test failure — an
operator must be able to tell them apart. Per §4.3 it must also fail intelligibly on
platforms that cannot hold a gossip secret at all.

### 5.2 Step 2 — make producers publish that value

P1/P1b (genesis) must change under every option (§3.4). P4 (enrollment) is the
natural production hook: the enrollee already presents an opaque 32-byte key.

**The enrollment hook is blocked on §5.1, not merely improved by it.** `--pubkey` is
operator-supplied on both `enrollment consume` (`rustynet-cli/src/main.rs:6514`) and
`enrollment admit` (`:6534`), and no script or helper in the repo computes that value
— I searched `scripts/**` and the Rust tree and found only test callers `[verified]`.
Today an operator has no way to obtain the correct value to type.

**P4 and the enrollment-consume registration must be changed together.** Per §3.4,
`enrollment_consume` registers a gossip peer under the enrollee-supplied key
independently of membership. If only one of the two paths is aligned, the two
authorities disagree and membership revocation stops reaching enrollment-registered
peers. Aligning both is what closes that gap; aligning one re-opens it.

P5/P5a-c/P6/P7/P8 are orchestrator and lab paths, and per §3.3 each requires
splitting a `WireguardPublicKey`-typed value into two. They should change with the
product paths, or the lab goes green while product stays broken — the exact failure
Phase 1 §0 records twice.

### 5.3 Step 3 — migration reuses machinery that already exists, with an epoch budget

No new membership operation is needed. `MembershipOperation::RotateNodeKey {
node_id, new_pubkey_hex }` exists and assigns the field
(`membership.rs:2011-2019`) `[verified]`, reachable as `membership propose
--operation rotate-node-key|rotate-key` (`rustynet-cli/src/main.rs:6181`) plus a
second route at `:6002` `[reported]`.

**But the migration verb is itself an unaligned producer.** Per §3.3 P10,
`RotateNodeKey` takes its value from `--new-pubkey` and writes it through a field named
`new_pubkey_hex` (`main.rs:6004`, `:6183`; `membership.rs:2018`) `[verified]`. Nothing
constrains what an operator passes there, so the migration mechanism can just as
easily install another wrong key. Whatever validation §5.4 adds must cover this path,
or the migration becomes a second way to create the problem it exists to fix.

This matters because the field sits **inside the signed canonical payload** — written
as `node.{index}.node_pubkey_hex=` (`membership.rs:333`), parsed back at `:2070`, and
also `op.node_pubkey_hex` at `:551` `[verified]`. The value cannot be edited in place;
it must go through a signed, approver-authorised update. Migration is therefore a
sequencing and authorisation problem, not a new-mechanism problem.

**But there is an epoch budget revision 1 missed.** The accept window is ±2:
`GOSSIP_EPOCH_SKEW_WINDOW = 2` (`peer_gossip.rs:147`) and
`GOSSIP_EPOCH_FUTURE_TOLERANCE = 2` (`:162`) `[verified]`, with local epoch taken
from the verified snapshot (`daemon.rs:5528`) `[reported]`. Migrating N nodes as N
separate `RotateNodeKey` updates advances the epoch by N, so any node whose snapshot
lags more than 2 epochs has inbound bundles rejected and its own rejected by updated
peers. For N > 2 with staggered distribution, gossip stops mesh-wide until snapshots
land. The degradation is transient and symmetric, so this is an **outage window, not
a brick** — but the migration must either batch rotations into few epoch bumps or
sequence distribution to keep skew inside 2. Whether a real migration distributes
per-rotation or once at the end is `[open]`; no migration sequencing exists to read.

### 5.4 Validation cannot fully separate the two key kinds

Both X25519 and Ed25519 public keys are 32 bytes, and validation is
`decode_hex_to_fixed::<32>` (`membership.rs:240`, `:1948`, reducer `:2012`)
`[verified]`. Length can never separate them, which is why the bug is silent.

A canonical-Ed25519-point check is a worthwhile cheap tripwire but is **not** a
correctness gate: it cannot detect a WireGuard key that happens to decompress. The
discrimination is **exactly one half**: every curve point has exactly one compressed
encoding, so the valid fraction is `8ℓ / 2^256` = `0.50000000000000000000`
`[computed]`. Revision 2 said "50.1% … (4000 samples)" and called that measured; with
n = 4000 the standard error is ≈ 0.79 pp, so the third digit was unsupported. The
closed form supersedes the sample — this was the one quantity in the document that
never needed estimating.

**The tripwire must specify which rule it applies, or it will disagree with the
runtime.** `ed25519_dalek::VerifyingKey::from_bytes` (pinned 2.2.0) performs
decompression and nothing else — no small-order rejection, no canonical-`y`
enforcement, and the decoder masks bit 255 without rejecting `y ≥ p` `[reported]`.
Small-order rejection happens later, at `verify_strict` (`peer_gossip.rs:515`)
`[reported]`. So a tripwire written from the spec ("canonical point") would be
*stricter* than the runtime that consumes the value.

This matters for one more fixture revision 2 missed: `"00".repeat(32)`
(`rustynet-cli/src/main.rs:22250`) **decompresses but is small order** — I confirmed
`8·P` is the identity `[computed]`. It therefore passes a decompression tripwire and
fails any `verify_strict`-grade strengthening. None of the other "yes" fixtures in the
table is small order `[reported]`.

**What the tripwire would break, precisely.** I computed validity for the fixture
byte-strings in the affected files `[computed]`:

| Fixture | Site | Canonical point? |
| --- | --- | --- |
| `[9u8;32]` | `membership_signature_audit.rs:139` | **yes** |
| `[10u8;32]` | `blind_exit_reversal_audit.rs:113` | **yes** |
| `[11u8;32]`, `0xaa`, `0xbb`, `0xcc`, `0x0a` ×32 | `daemon.rs`, `service_exposure.rs:627` | yes |
| `[1u8;32]` | `enrollment.rs:372` | yes |
| `[7u8;32]` | `membership.rs:2867` | **NO** |
| `[2u8;32]` | `enrollment.rs:559` | **NO** |

So the three shipped audit binaries are unaffected — which is what downgrades the
review's BLOCKER — and exactly two in-crate test fixtures would need new bytes.

The real gate is `gossip_identity_mismatch`, which compares against the node's own
derived key (`daemon.rs:5712`) — exact, and already three-valued with a documented
rationale (`:5687-5697`) `[verified]`, reporting `unknown` rather than `false` when
either input is absent. Per §4.3 it measures nothing on macOS or Windows.

## 6. Decisions for the operator — deliberately not chosen here

**D1 — migrate the existing fleet, or enforce for new nodes only?** Phase 1 §7
recommends measuring first via `gossip_identity_mismatch` `[reported]`. That
recommendation predates §3.4's finding that genesis publishes a key with no private
counterpart, which weakens "new nodes only": that policy still leaves every existing
node's record unusable, and genesis must change regardless. The measure-first
argument still holds for *sequencing*; it no longer implies migration is optional.

**D2 — genesis ordering** (smaller than revision 1 thought, per §3.5). On the **lab**
path the ordering is already correct: the mint precedes genesis in the same closure
`[reported]`, so genesis can publish the real key with no reordering. On the
**product** path there is no genesis to order — `rustynet install` never runs it and
ends awaiting enrollment (`live_linux.rs:305-310`) `[verified]`. So D2 is not a
fleet-wide sequencing decision; it is a question about the lab and founder paths
only, and the answer there may simply be "publish it, the secret already exists".
What remains genuinely open is whether any non-Linux or anchor/founder install path
genesises a node, since Linux `install` accepts only `--role node` `[reported]`.

**D3 — rotation safety** (rewritten; revision 1's fail-open premise was retracted in
§0.2). The live issue is not revocation bypass but **silent identity rotation**:
`--force` is unconditional at both mint callers (`install/live_linux.rs:180`,
`ops_e2e.rs:476`) `[verified]`, so a re-run rotates the gossip identity while
membership still publishes the old key. Post-alignment that is a self-inflicted
`gossip_identity_mismatch=true` and a node dropped from the epidemic — loud, not
silent, which is an improvement, but still an outage. Options: make the gossip mint
refuse to overwrite an existing secret, or require a membership rotation to
accompany any re-mint. A decision because the first changes installer behaviour.

**D4 — what do macOS and Windows nodes publish?** Forced by §4.3: Windows cannot
hold a gossip secret and macOS never mints one, yet both have membership producers.
Options: (a) leave their `node_pubkey_hex` as-is and accept that the field means
different things per platform — which defeats the point of a contract; (b) publish a
documented sentinel so the mismatch surface can distinguish "wrong key" from "no
gossip on this platform"; (c) extend the mint to macOS, leaving only Windows
special. This is policy, not design.

**D5 — should rotating the gossip trust anchor be owner-gated?**
`requires_owner_signer` matches only `RotateApprover` and `SetQuorum`
(`membership.rs:441-446`) `[verified]`, so `RotateNodeKey` needs quorum but not the
owner. Once `node_pubkey_hex` *is* the gossip trust anchor, rotating it is arguably
as sensitive as rotating an approver. Raising the bar is a policy change with
operational cost.

## 7. How the implementation would be proven

Mutation-verified per the standing rule: commit first, then break it, confirm the
*specific* test fails, restore.

| Mutation | Test that must fail |
| --- | --- |
| Export verb strips the trailing newline before deriving | export-vs-`local_node_id` equality test — **whose fixture must be asserted not to end in `0x0a`** (§4), else vacuous |
| Export verb re-implements HKDF instead of calling `derive_gossip_signing_key` | same test |
| The newline append at `key_material.rs:538-539` is deleted | **repair `build_gossip_node_derives_gossip_only_subkey_from_encrypted_secret` (`daemon.rs:20158`) first** — it looks like this pin but its fixture is 32 bytes ending `0x0a`, so the mutation is green today (§4.1). Give it a fixture that does *not* end `0x0a`, and drop the macOS cfg-gate |
| A migration passes a WireGuard key to `--new-pubkey` | validation on the `RotateNodeKey` path (§3.3 P10, §5.3) — the migration verb is itself an unaligned producer |
| Genesis reverts to `encode_hex(&node_key_bytes)` | genesis-publishes-a-derivable-key test |
| Enrollment **admit** accepts a non-canonical point | the §5.4 tripwire test — **admit-side only**: `enrollment consume` already rejects a non-point via `VerifyingKey::from_bytes` (`daemon.rs:8610-8611`), while `admit` checks base64 and length only (`rustynet-cli/src/main.rs:8417-8423`) `[verified]`. The two halves of the enrollment flow already disagree on validation |
| Only `enrollment admit` is aligned, not `enrollment_consume` | a test that revocation reaches an enrollment-registered peer (§3.4/§5.2) |
| A migration bumps the epoch past the skew window | an epoch-budget test (§5.3) |

**The revocation row has an existing home.** `gossip_revoked_readmit_audit.rs` is an
adversarial self-audit that already drives the real shipped `GossipNode` in-process
with synthetic Ed25519 keys, asserting that a Revoked peer's bundle is rejected with
`GossipError::RevokedSource` **and** that the same scenario with an Active peer is
accepted — an explicit non-vacuity check `[verified]`. It is dispatched as
`rustynetd gossip-revoked-readmit-audit` (`main.rs:252`) and fails loud. Extending it
with the §3.4 case — a peer registered through `enrollment_consume` under a key that
differs from membership's — is far cheaper than a new harness, and because it uses
proper Ed25519 keys it is unaffected by the §5.4 tripwire.

The `RotateNodeKey` re-signing path is likely already covered: signatures are
enforced by `verify_membership_signatures` (`membership.rs:1789-1829`) with quorum
threshold, active-approver lookup and `verify_strict` `[reported]`, and
`membership-revoke-audit` exists as a shipped verb whose failure message names
exactly this property — "RSA-0009's delayed-apply fix regressed or state-root
integrity weakened" (`main.rs:2114-2126`) `[verified]`. That resolves revision 1's
`[open]` row in the affirmative for the delayed-apply case. The signature-enforcement
lines themselves are still `[reported]` and should be read before the proof plan
leans on them.

## 8. Recorded, not fixed

- **Stale-peer entries on rotation.** `register_peer` is additive and nothing prunes
  a peer that changed key (§3.4) `[reported]`. Any rotation leaves the old key
  registered for the process lifetime on already-synced peers, so `RotateNodeKey` is
  a weak response to key compromise. Not fixed here because it is a gossip-runtime
  lifecycle defect independent of this alignment.
- **Drifted line references in `GossipProvisioningPhase1_2026-08-04.md` §7**: genesis
  cited as `main.rs:4002-4012` but at `:4119-4129`; the e2e producer as
  `ops_e2e.rs:1926-1927` but at `:1953` — and `:1953` is itself a pass-through
  (`execute_ops_e2e_membership_add` receives the value as a parameter), with the real
  WireGuard source at `:4053`. `[verified]`
- **§7's producer table omits every operator-facing CLI path and the whole
  orchestrator family**, which biases a reader toward believing the problem is
  lab-only.
- **Phase 1 §10.2 items 1–5 remain open** and are not addressed here `[reported]`.
- **`revoked-peer-denied-audit` is not relevant to this design after all.** I read it
  rather than leaving it as an open guess: it drives
  `revoked_peer_denied_audit::run_revoked_peer_denied_audit` and guards
  "DD-03/RSA-0007's membership-aware **ACL** fix" (`main.rs:2144-2154`) `[verified]` —
  the dataplane access path, not gossip peer registration. So
  `gossip-revoked-readmit-audit` remains the only existing gossip-side proof surface,
  as §7 says.
