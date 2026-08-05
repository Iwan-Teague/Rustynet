# Adversarial Security Remediation — starting notes — 2026-07-29

Status: **starting notes, mostly unapplied.** Everything below §2 still matches
its original description: unapplied, undesigned, unprototyped, uncosted.

**Applied so far (2026-07-30) — the five grouped changes in §2, all five now
landed, gated, and mutation-verified:**

| Group | Closes | Commit(s) |
|---|---|---|
| **S1** bound `ManagementCidr::from_str` | PF-02, WIN-05, Linux nft twin | `464e3b79` |
| **S2** assert precedence, not presence | IPV-03, PF-05, RN-27, WIN-03 | `b8eb044d` (core), `f2e084d9`, `8417edf1`, `7af2f0e0`, `c047358f`, `d40323e8` |
| **S3** single-line guard on node ids | node-id vector of CTL-01, issuance half of RLY-03 | landed |
| **S4** cap `node_id` length at parse | RLY-05, AUDIT-031 | landed |
| **S5** fail closed on non-unix key custody | CRY-05 / AUDIT-027 | `0968c44d` |

Read §2 for what each group does. Three things about S2 specifically, because it
turned out larger than the "M" the table guessed:

- It is built on a **new shared primitive**,
  `crates/rustynetd/src/killswitch_precedence.rs` — an ordered-rule walk plus
  per-backend classifiers, so the four sites share one precedence model and one
  set of adversarial tests. The review's framing was right: this is the item that
  converts silent failures into loud ones.
- It found a **fifth site of the same class** the review did not name:
  `macos_blind_exit.rs`'s own terminal-block check was also presence-only
  (`7af2f0e0`).
- It is deliberately the **narrow** fix, exactly as §2 said. It does **not**
  close PF-01/PF-02/IPV-01. The wide-open `oifname "<underlay>" accept` the
  daemon installs when NAT is active is passed as *acknowledged*: it can no
  longer mask rules beneath it, but its own disposition stays with the owning
  finding rather than being decided by a verifier change that would fail every
  exit node closed.

**Where the 103 findings stand (recounted from the §3 dictionary rows, 2026-07-30).**
Every §3 row now carries its own status, so the row view and this summary agree —
they did not before, and a reader scanning rows would have re-done closed work:

| | count |
|---|---|
| closed | **38** |
| partially closed (one half landed, the other named) | 4 |
| parked — DECISION / GATED / DO-NOT-FIX | 20 |
| genuinely open | **41** |

Open, for planning: `CRY-03 CTL-02 CTL-04 CTL-05 CTL-07 ENR-04 ENR-06
ENR-07 ENR-10…ENR-12 ENR-14 ENR-15 IPV-01 IPV-04…IPV-09 IPV-11 IPV-13 IPV-14 PF-06
PF-07 PF-11 PF-12 PF-15 POL-11 POL-13 RLY-06 RLY-08 RLY-09 RLY-13 RLY-14 WIN-01
WIN-02 WIN-04 WIN-06 WIN-09 WIN-10`. The ENR block is still the largest single
cluster (7 of the 41).

**How to count this list, because two readers have now got it wrong.** The open
list uses RANGE notation — `ENR-10…ENR-12` is three ids written as two tokens,
`IPV-04…IPV-09` is six written as two. Counting visible tokens gives **36** and is
wrong; expanding the ranges gives **41**, which is what the table says. A recount
on 2026-08-05 confirmed the table: 111 dictionary row tokens, 8 ids appearing in
both §1 (the do-not-apply warnings) and §3 (the status dictionary), so **103
unique findings**, and **41 unique open ids** after expansion. The duplicate ids
are deliberate structure, not drift — §1 and §3 serve different purposes — so do
not "deduplicate" them.

The prose above previously said "8 of the 42", which was an off-by-one against its
own table.

**Corrections applied 2026-07-30, second pass.** Two of them, both of which a
reader would otherwise have acted on:

- The previous revision called the ENR block "19 of the 48". Counting the ids in
  the open list itself gives **13**, not 19 — 19 is the running total through
  CRY + CTL + ENR. ENR was the largest cluster either way, so the conclusion
  held while the number did not.
- **RLY-15 was listed as open while its fix had already landed** (`7c262858`),
  which is the exact drift the recount above exists to prevent. Its row is now
  stamped. **ENR-02** was in the same state: closed by S3 at `4333d473`, since
  `NodeRegistry::upsert` validates at entry, but never marked.

Closed in this pass: **ENR-01**, **ENR-03** (`436b23b7`), **ENR-13**
(`fa67f646`), **ENR-05** (`c61c1e92`), plus the two stamp-only corrections above.

**ENR-05's decode-side twin is now closed too** (`93dbd421`), as a separate
change after an explicit decision to accept the compatibility break.
`parse_node_capabilities` carried the same mapping for its legacy
roles→capabilities fallback, drifted differently again — it handled the
`anchor.*` tokens the bridge dropped, still dropped `serves_nas`, `serves_llm`
and `anchor.port_mapping_pinned`, and granted `Anchor` from the same four tokens
the canonical parser rejects.

It was **deleted rather than made stricter**, because strictness was the wrong
axis. Capabilities are the *authorization* field; in a snapshot with no
`capabilities` line what the approvers signed is a `roles` string — a *label*.
The shim read that label and derived authority from it, mapping `tag:servers` to
`Anchor`. The quorum's signature covered the label and never covered the grant,
so the shim converted a **signed label into an unsigned privilege** — the POL-05
shape, and the exact inversion §10.4's default-deny rule exists to prevent.

Four things were measured before deleting, not assumed:
`MEMBERSHIP_SCHEMA_VERSION` has never been bumped (`git log -S` returns only the
initial commit), which is *why* the shim existed; `canonical_payload` always
writes the field; **no test reached the fallback**, proven by making the branch
`panic!` and running the crate suite green; and no archived artifact contained
such a snapshot.

The schema version is deliberately **not** bumped — bumping refuses strictly
more, including good snapshots that *do* carry capabilities, for no extra
security. The versioning debt is recorded instead: `version=1` now means
slightly stricter than it did. Accepted residual risk: a genuine
pre-capabilities snapshot no longer loads and its node fails closed. Only
*absence* is refused — an explicit empty `capabilities=` still decodes, so
clearing a node's capabilities stays expressible.

One caution on that table. A "closed" row means a fix landed with a commit and,
where behaviour changed, a mutation-verified test — it does **not** mean the
finding's whole subject area is sound; several rows closed one named vector and
say so.

A note that used to sit here said `RLY-15` read open because its fix was
implemented but not yet committed. That is no longer true — it is committed at
`7c262858` and its row is stamped.

**Individual findings closed after S1–S5 (2026-07-30).** All mode-verified and,
where a behaviour change was involved, mutation-verified:

| Finding | What changed |
|---|---|
| **POL-01** (High) | `selector_requires_membership` failed OPEN on a prefix miss, so `NODE:revoked-node`, `nodes:revoked-node`, `" node:revoked-node"` and the bare `revoked-node` all skipped the revocation check entirely. Replaced with a closed `SelectorKind` parser — anything unparseable denies. The review's whole confirmed exploit table is now a test. |
| **POL-14** (Medium) | The `ensure_lan_route_allowed` half: the `Result` was discarded, so a DENIED grant enabled LAN access anyway. Now consumed, with every failure path reverting the mutations it made. |
| **POL-06** (Medium) | `is_populated`'s doc comment still advertised a governance-disabled bypass that `8cca1458` had removed — a stale doc describing a fail-open is an invitation to restore it, and this one had already been cited as current behaviour in a security review. Corrected, and the actual deny-on-empty behaviour pinned. |
| **POL-07** (Low) | `validate_policy_safety` required `Protocol::Any`, so three rules enumerating Tcp/Udp/Icmp staged successfully while being equivalent to allow-all. Any `*` → `*` Allow is now refused regardless of protocol. |
| **POL-08** (Low) | `stage_revision` did a bare `insert`, so re-staging an id silently redefined what rolling back to it meant. Duplicate ids are refused. |
| **POL-09** (Low) | `rollback_to` checked only `contains_key`, so a staged-but-never-promoted revision could be activated by a method whose name reads as a safety action. It must now have been promoted at least once. |
| **POL-12** (Low) | `scope_for`'s doc claimed a specificity tiering the code does not have — precedence comes entirely from the caller's selector order. Doc corrected and the real contract pinned by a test that reverses the caller order and shows the BROADER scope winning. |
| **CRY-07** (Low) | The unix key-custody validator checked modes but not ownership, so an ATTACKER-owned directory and file with perfect `0700`/`0600` validated. Added a `Uid::effective()` check, matching the peer store's audited-PASS sibling. |
| **IPV-10** (Medium) | `evaluate_linux_blind_exit_ruleset` was thorough and not on the daemon assert path — its only production caller was the evidence-report command, so a blind_exit node's posture was checked when someone asked for a report and never during operation. Wired into `assert_exit_serving`, closing a platform asymmetry (macOS already did this). |
| **WIN-08** (Low) | The self-check pipe leaf was an unbounded prefix match and the charset allowlist permits `\` and `.`, so `…check-\..\..\evil` validated. Suffix bounded to 1–10 ASCII digits with no separator after the prefix. |
| **PF-09 / PF-08** (Low) | `push_list` could emit an over-cap token for a single over-cap element. Documented rather than changed, because the current behaviour is the safest available — the decoder rejects the whole spec, whereas dropping the element would silently narrow the rendered `pf` ruleset. `debug_assert` makes it loud in test builds, and the new budget test covers PF-08's ask so a future peer-cap raise fails there rather than at the helper. |
| **PF-16** (Medium) | The blind_exit pf evaluator's terminal-block check was presence-only — a fifth site of the PF-05 class the review did not name. |
| **RLY-12** (Low) | **Already closed** — verified, not fixed. The review cited an unescaped `node_id` interpolated into a relay log line at `transport.rs:429-431`; that interpolation is no longer in the tree. Every remaining `eprintln!` in the relay crate interpolates a `SocketAddr`, a `Debug` enum, or an error — no peer-supplied string. S3's single-line guard on `is_valid_node_id_text` closes the upstream half independently. |

**Still open on POL-06, and it is a decision.** The doc comment is fixed but the
*inertness* is not: `set_membership_directory` / `with_membership_directory` have
**zero** production callers, so `is_populated()` is always false in a shipped
binary and the RSA-0008 issuance gate never runs. Closing it means either giving
the three CLI issuance commands (`execute_assignment`,
`execute_dns_zone_issue`, `execute_traversal_issue`) a way to supply a membership
snapshot — a CLI contract change across three commands — or making
`ControlPlaneCore` refuse to issue without one, which breaks all three until the
first is done. Order matters and the contract question is the operator's.

**One new finding surfaced while doing S2, filed in the review as IPV-15:** with
NAT active *and* `dns_protected`, the killswitch chain orders the wide-open
egress accept **above** the `udp/tcp dport 53 oifname != <tunnel> drop` rules, so
plaintext DNS out the underlay is accepted before the fail-closed drop is
reached. Same class as IPV-03 but a different traffic class, so the S2 walk (which
decides the *general* egress terminator) does not catch it. Needs its own entry.
Companion to: `documents/operations/active/AdversarialSecurityReview_2026-07-29.md` (the findings doc). Every finding ID there has exactly one entry here, so this works as a lookup: problem → where to start.
Coverage: 103 finding IDs across Parts I–VIII (POL, CRY, PF, RLY, CTL, WIN, IPV, ENR).

## What this document is for

**It exists to save the next agent the orientation time**, not to hand it a
solution. For each finding it gives a few facts worth knowing before touching the
code, and a possible direction where one is obvious. That is all.

## What work actually went into it — read this before trusting a row

Being explicit, because the format of a table invites more confidence than it has
earned:

- Every entry was written **by reading the finding and the surrounding code**. None
  was prototyped, compiled, or tested. No fix here has been shown to work.
- Roughly a quarter of the findings carried an explicit "proposed enforcement" note
  in the review; those entries restate it. **The remaining ~three quarters had no
  such note, and their direction was written here for the first time** — those are
  first-pass suggestions from reading, and some will turn out to be wrong.
- **Size is a sort order, not an estimate.** It reflects how large the change looked
  while reading, not an attempt at the change. "one line" means the edit looked like
  one line; it says nothing about the test, the review, or the live-lab proof.
- The genuinely load-bearing content is **§1 (do not apply as written)** and
  **§2 (one change closes several findings)**. Those came out of adversarial
  verification and are the parts most likely to save real time. The per-row
  directions are the weakest content in the document.

So: treat a row as a starting point for reasoning, and expect to discard some.
Always read the finding itself first — the entries here omit the evidence, the
worked example, and the reachability caveats that decide whether a fix is worth
doing at all.

Size column (rough, unvalidated): **XS** looked like one line · **S** small and
local · **M** touches several sites or needs a fixture · **L** needs a design
decision before any code.

Before-you-start column: **—** nothing special noticed · **test first** the
negative test is the harder half, and per `SecurityMinimumBar.md` a
security-sensitive fix needs both an enforcement point and a negative test ·
**GATED** unresolved prerequisite, see §1 · **DECISION** someone has to choose;
this is not an engineering ticket · **DO-NOT-FIX** current behaviour is deliberate
and correct.

---

## 0. Status — twelve entries are DONE

**Round 2 (2026-07-30):** CRY-06, CRY-10, CRY-11, CRY-12, POL-03 and ENR-08 landed
in `73ae5cc9`, with review corrections in `de9a6afb` and a scaffold repair in
`acb5ef15`. Three lessons from that round, all of which generalise:

1. **A fix can introduce a worse defect than it closes.** ENR-08's size cap was
   enforced on read but not on write, and the ledger is grow-only (RN-26 no-op), so
   at ~31,775 tokens the daemon would have written a file it then refused to load —
   an unrecoverable enrollment outage whose only recovery reopens replay. Caught by
   review, fixed by capping the write side too.
2. **`cargo check --workspace` does not run binaries.** CRY-06 broke
   `rustynet-control`'s startup, and fmt, clippy, a workspace check and ~2,400
   passing tests were all green. Run the workspace's binaries after touching a
   shared constructor or validator.
3. **Tests derived from a constant follow it when mutated.** This bit both rounds.
   Where the constant *is* the control, pin it with a literal.

**Round 1:** RLY-01, RLY-02, RLY-04, RLY-05, RLY-10 and RLY-11 landed in `62837ed0`.

**RLY-01, RLY-02, RLY-04, RLY-05, RLY-10, RLY-11** were implemented in commit
`62837ed0` and are no longer starting notes. Their rows below are marked **DONE**.

Two lessons from doing them, which apply to the rest of this document:

1. **A "possible direction" here can be wrong in a way that matters.** RLY-10's
   direction — lower the skew ceiling — was insufficient: skew is applied twice on
   independent axes, so the real bound is `ttl + 2*skew`, and implementing the
   suggested fix would have shipped a compile-time assertion of an invariant the
   code did not hold. The correct fix was on the retention side. Treat every row
   here as a hypothesis to test, exactly as §"What work actually went into it" says.
2. **Your test suite is a real check on these fixes.** A pre-existing test
   (`nonce_at_exact_retention_age_is_pruned_by_cleanup`) rejected the first RLY-10
   attempt, with a comment saying it exists to catch precisely that loosening. Run
   the suite before assuming a direction here is safe.

Fix efficacy for the six was verified by mutation rather than by green tests: six of
seven mutations are caught, and RLY-04's is not (an fsync is not observable from a
unit test), which is recorded in the code.

---

## 1. Fixes that must NOT be applied as written — read this first

A remediation doc invites someone to implement an entry without reading the caveats. These are the entries where that would cause harm. This section exists because the repo already has a precedent for it: **RSA-0003** was assessed "keep as-is" because the obvious fix would have introduced a fail-open.

| ID | Why not |
|---|---|
| **PF-03** | The proposed reorder (load-then-flush) rests on pf sub-anchor evaluation ordering that **PF-07 marks explicitly unverified**. If PF-07's inference holds, during the overlap the *old* anchor's `block drop out quick all` preempts every pass in the new anchor — a **full egress blackout on every reconcile**, made persistent because the flush discards its result. Run the on-box ordering experiment first. |
| **CRY-08** | **DO-NOT-FIX.** The inverted `with_exceptions` guard is currently *protective* — it denies all compatibility exceptions, the strictest-secure outcome. "Repairing" it makes it fail-open. This is RSA-0003, already assessed keep-as-is. The only safe change is a comment. |
| **CTL-03** | The code being criticised carries an explicit instruction: *"Do NOT add a `payload_field_matches` gate here without a coordinated wire-format change."* The missing re-canonicalization is a recorded compatibility decision. Fixing it requires the wire-format migration, not a local edit. |
| **CRY-04** | Deliberately **DEFERRED 2026-06-24** (RSA-0001): the safe fix needs an on-disk framing migration whose upgrade path cannot be validated without a lab. Do not "just fix the discriminator" — that strands legacy v0 blobs. Land the regression test only. |
| **PF-06** | Adopting `is_interface_name` verbatim also drops `.` from the accepted charset, silently rejecting dotted interface names. Port the length bound (15), not the whole predicate. |
| **IPV-02** | Do **not** flip `ipv6_parity_supported` to true. The `ip6` sibling table it depends on does not exist, and its only checker is recorded as unwired. Flipping it removes the one working IPv6 control. |
| **ENR-06** | The `BlindExit` immutability guard is correct and deliberate (RT-2 / SecMinBar §6.D.2). Do not relax it. The fix is a confirmation prompt at the *enrollment* boundary, not a change to the reducer. |
| **POL-05** | `None` scope = unrestricted grant is **documented intended design**. Changing it is a product decision about whether an unscoped grant should exist, not a bug fix. |

---

## 2. Changes that would close several findings at once

Worth reading before the dictionary. Each looks like a single change that resolves several findings, and three of them would convert currently-silent failures into detectable ones. These groupings came out of the adversarial passes rather than from reading one finding in isolation, so they are the most reliable content here — but they are still unbuilt.

### S1 — Bound `ManagementCidr::from_str` · **RECLASSIFIED: DECISION, not a safe fix** · closes **PF-02, WIN-05**, and the Linux nft twin

> **Corrected 2026-07-30.** This entry previously read "test first" and asserted a
> width floor "false-rejects nothing real". That is **wrong**, and it was checked
> before implementing rather than after. `phase10.rs:1205-1213` documents allowing
> SSH from anywhere (`0.0.0.0/0`) as *"reachable in production"* — a
> route-assertion bug was fixed specifically to make that configuration work — and
> `ipc.rs:473` asserts `validate_cidr("0.0.0.0/0")` is valid. Rejecting prefix 0
> would break a configuration this repo deliberately accommodates, and prefix 0 is
> the whole finding, so the two cannot be reconciled by choosing a gentler floor.
> **An owner must decide** whether unrestricted management SSH remains supported.
> Everything below is the original text, kept for the reasoning.

One unbounded validator produces the same unrestricted TCP/22 egress hole on **three** backends (macOS pf, Linux nftables, Windows netsh). Add a width floor or private/CGNAT/ULA containment, mirroring `macos_pf_mesh_cidr::validate_mesh_egress_source_cidr` — whose doc comment already spells out the reasoning verbatim. Fixing at `from_str` is the only placement that cannot drift between platforms. Management CIDRs are bounded operator networks by definition, so this false-rejects nothing real.

Separately and independently: move the SSH block inside the `strict_fail_closed` guard, or document why it must fire in the strictest posture.

### S2 — Assert precedence, not presence · closes **PF-05, WIN-03, IPV-03**, and **RN-27** · looked **M** · test first

Four sites make the same error: they check that a block rule *exists*, not that it is *reachable*. Because pf and nftables are first-match-wins, a permissive rule ordered earlier defeats a block that is still literally present — which is exactly why **PF-01, PF-02 and IPV-01 are silent**.

The fix is to model the rendered ruleset as an ordered list and assert that no rule preceding the terminator matches broader than an allowlisted shape. For WFP, read the filter back and assert `action`, condition count, and that the condition LUID is the tunnel — not merely that the GUIDs exist. **This is the highest-leverage item in the document**: it does not fix PF-01/PF-02/IPV-01, but it makes them, and any future instance of the class, impossible to introduce silently.

### S3 — Apply the single-line guard that already exists · closes the node-id vector of **CTL-01** and the issuance half of **RLY-03**; partially **ENR-01, ENR-03** · looked **S**

`is_single_line_payload_value` already exists in `rustynet-control/src/lib.rs` and already rejects `\n`, `\r`, `=`. It is applied to relay-fleet fields and **not** to node ids. Apply it inside `is_valid_node_id_text`, at `NodeRegistry::upsert`, and at `EnrolleeAdmitContext` construction.

Scope honestly: this does **not** close CTL-02 (verifier soundness), CTL-03 (`|`-delimited payload plus unsigned timestamp), or the `os`-field vector in CTL-03. Real node ids in this tree are hostname slugs, so the guard strands no existing fleet.

### S4 — Cap `node_id` length at parse · closes **RLY-05**, finishes NO-SHIP item **AUDIT-031** · looked **XS**

`parse_relay_hello` reads a bare `u16` length with no maximum, and the pre-auth limiter stores the unverified value as a map key — 1015 MiB retained pre-authentication. RSA-0037 capped entry *count*; this caps *bytes*. **AUDIT-031 is on the before-release list and is currently only half-closed.**

### S5 — Fail closed where a platform check is unimplemented · closes **CRY-05 / AUDIT-027** · looked **XS**

`validate_key_custody_permissions`'s `#[cfg(not(unix))]` arm returns `Ok(())`. Return `Err(CryptoError::PermissionValidationUnavailable)` — the variant already exists and is already constructed elsewhere in the same file. **This is on the repo's own NO-SHIP before-release list.**

---

## 3. The dictionary — per-finding starting notes

### Part I — `rustynet-policy` (POL)

| ID | Problem | Possible direction | Size? | Before you start |
|---|---|---|---|---|
| POL-01 | Selector prefix allowlist fails open on its miss branch; unrecognised/mis-cased prefixes skip revocation | Invert the default: parse every selector into a recognised, canonicalised kind and **deny anything unparseable**; treat a non-conforming selector as a policy *load* error, not a runtime allow | M | **DONE** `09193c60` |
| POL-02 | Raw CIDR dst plus `user:local` resolving only to the local node means two route paths validate no remote peer | Give literal destinations a selector kind that resolves to the owning node's membership status; stop using one `user:local` constant as `src` for decisions whose subject is a remote peer | M | DECISION |
| POL-03 | Empty string is a valid, ungated, `*`-matching identity | Reject empty selectors at construction in both rules and requests | XS | **DONE** `73ae5cc9` + `de9a6afb` |
| POL-04 | The gate never binds a selector to the *requesting* peer | Pass the requester's verified identity into evaluation and require the matched selector to be one the peer holds | L | DECISION |
| POL-05 | Scope absence = maximum privilege, reached silently by three paths | Make absence deny: `ScopeTable::Loaded \| Unavailable` where `Unavailable` denies; fail closed on read error; reject malformed numerics instead of `.ok()` | M | **DECISION** — see §1 |
| POL-06 | Issuance membership gate is unconditionally inert (directory never installed) | Install the directory at the three `ControlPlaneCore::new` sites, or make `ControlPlaneCore` refuse to issue without one | S | **PARTIAL** `09193c60` — doc corrected + deny-on-empty pinned; the INERTNESS half (zero production callers of `set_membership_directory`) needs a CLI contract decision |
| POL-07 | `validate_policy_safety` evadable and context-blind | Flag any `*`→`*` Allow regardless of protocol; consider a protocol-spanning set; make the check context-aware | S | **DONE** `09193c60` |
| POL-08 | Rollback target is mutable and not content-addressed | Reject duplicate revision ids, or content-address revisions by digest and bind the id to the signed bytes | S | **DONE** `09193c60` |
| POL-09 | `rollback_to` activates never-promoted revisions | Require the target to have been promoted at least once; emit an audit event with actor and timestamp | S | **DONE** `09193c60` |
| POL-10 | `PolicyRolloutController` is decorative — no accessor returns the active policy | **DECISION:** wire it (immutable revisions, accessor, real canary evaluation, audit events) or delete it and the runbook that describes it. Half-present is what makes POL-07/08/09 latent traps | L | DECISION |
| POL-11 | Scope key format mismatch: policy emits `node:<id>`, gateway looks up bare `<id>` | Converge on one key form; add a round-trip test across writer and parser | S | test first |
| POL-12 | `scope_for` doc claims specificity tiering the code lacks | Either implement prefix-based tiering, or correct the doc and rename so the caller's ordering obligation is explicit; intersect scopes rather than first-match | S | **DONE** `09193c60` |
| POL-13 | No fuzz target covers the policy engine | Add a differential target: a canonical selector and any whitespace/case/prefix mutation must not differ in `Decision`. Would have caught POL-01/02/03 mechanically | S | — |
| POL-14 | Two daemon ACL results discarded with `let _ =` | Consume both `Result`s and fail closed; `set_exit_node` half is AUDIT-044 | XS | **DONE** `3d135c0b` (the discarded-Result half; `set_exit_node` half was AUDIT-044, already closed) |

### Part II — `rustynet-crypto` (CRY)

| ID | Problem | Possible direction | Size? | Before you start |
|---|---|---|---|---|
| CRY-01 | `RequireOsSecureStore` is load-side only; the key file is written unconditionally | Gate the disk write on the returned `KeyCustodyBackend`, or make the intent explicit in the type (`materialize_disk_backup: bool`) rather than implied by a comment | S | DECISION |
| CRY-02 | Linux has no strict-policy arm, and its OS store fails to `OsStoreUnavailable` in the ordinary headless case | Decide Linux's tier explicitly rather than by omission; surface the returned backend so a silent downgrade is observable | S | DECISION |
| CRY-03 | 16-char passphrase floor with no entropy requirement; Argon2 params not stored in the blob | Store `(algorithm, version, m, t, p)` in the envelope so cost can be raised migration-safely; raise the passphrase floor given this string bounds at-rest security | M | test first |
| CRY-04 | v0/v1 framing ambiguity renders ~99.6% of legacy blobs undecodable | **Land the regression test only** (hand-build a v0 blob, assert it decodes). The framing fix is deferred by decision | S | **GATED** — see §1 |
| CRY-05 | Windows permission validation is an `Ok(())` no-op, both directions | **See S5.** Also apply a DACL at write time on non-unix rather than inheriting | XS | **PARTIAL** `0968c44d` (S5) — stamped 2026-07-30. Verified: the `#[cfg(not(unix))]` arm of `validate_key_custody_permissions` now returns `PermissionValidationUnavailable` instead of `Ok(())`, so the READ-side no-op is closed. The WRITE-side half is **not** done — `write_encrypted_key_file` applies permissions only under `#[cfg(unix)]`, so a non-unix key file still inherits its DACL, and `rustynet-windows-native` exposes only `inspect_*_sddl` readers with no setter to call. Sizing the remainder as XS is optimistic: it needs a new native primitive |
| CRY-06 | `NodeKeyPair::from_raw` never verifies pub/priv correspondence | Delete it (dead public API), or make it take a seed and derive the public key, as `from_seed` already does | XS | **DONE** `73ae5cc9` — also fixed a scaffold it broke (`acb5ef15`) |
| CRY-07 | Unix permission validator checks modes but not ownership | Add a uid check, matching the pattern `ops_peer_store.rs` is audited PASS for; optionally `O_NOFOLLOW` + `fstat` for the TOCTOU | S | **DONE** `306575df` |
| CRY-08 | `with_exceptions` rejects all non-empty lists, making the denylist loop dead | **Comment only** — state that exceptions are administratively disabled by design, so nobody "repairs" the guard into a fail-open | XS | **DO-NOT-FIX** |
| CRY-09 | Three security controls unwired; `release_manifest.rs` builds what the strict default forbids | Wire `validate_signing_provider_policy` into `release_manifest.rs` and accept a documented exception, or delete all three controls | M | DECISION |
| CRY-10 | `aead_seal` doc claims OS-secure custody; production reads a raw key from a plain file | Correct the doc comment to describe the actual key sources | XS | **DONE** `73ae5cc9` |
| CRY-11 | `from_seed` never zeroizes its by-value seed parameter | Zeroize the parameter copy after `SigningKey::from_bytes` | XS | **DONE** `73ae5cc9` — source-pinned; a stack wipe is not behaviourally testable |
| CRY-12 | Blob length arithmetic unchecked — debug panic on 32-bit | `checked_add` / `saturating_add` before the equality compare; fold into whatever work first attempts the armv7 cross-build | XS | **DONE** `73ae5cc9` — test does not discriminate on 64-bit; see the code comment |

### Part III — macOS `pf` privileged boundary (PF)

| ID | Problem | Possible direction | Size? | Before you start |
|---|---|---|---|---|
| PF-01 | `allow_egress_interface=true` is a one-boolean full-IPv4 killswitch off-switch, and it passes the assertion | Make the exit posture a distinct spec *kind* the helper can reason about, or require a helper-visible attestation of the signed exit capability. **S2 is the prerequisite** that makes this detectable | L | DECISION |
| PF-02 | `ssh_cidr=0.0.0.0/0` opens unrestricted off-tunnel TCP/22, even under strict, not interface-scoped | **See S1.** Also consider deleting the outbound half — the inbound rule is `keep state`, so it already covers sshd replies | S | **DONE** `464e3b79` (S1) |
| PF-03 | Anchor flush precedes the load, so a failed load leaves egress open | Reorder to load-then-flush, **or** fold the flush into the builtin so the helper flushes only after its own load succeeds | S | **GATED** — see §1 |
| PF-04 | The `-F all` flush arm lets the daemon empty the live killswitch anchor | Have the helper own generation state, or move flush inside the atomic builtin (also resolves PF-03), or drop the boundary flush arm | M | DECISION |
| PF-05 | Killswitch assertions check presence, not precedence | **See S2** | M | **DONE** `8417edf1` (S2) |
| PF-06 | Specs that pass decode but that `pfctl` rejects (iface length/keywords, `/+N`) | Port the length bound of 15 **only** — adopting `is_interface_name` wholesale drops `.` from the charset and silently rejects dotted interface names. Also reject pf keywords and pure-digit names; adopt parse-to-typed-then-re-render for the three raw-string CIDR sites | S | **see §1** |
| PF-07 | `generation` is an unbounded daemon-chosen `u64` | Reject a generation the helper has not seen monotonically advance, or cap the live anchor count. **Also run the sub-anchor ordering experiment PF-03 depends on** | S | — |
| PF-08 | Module list caps exceed what the 16 KiB wire can frame | Reconcile `MAX_MANAGED_PEER_ENDPOINTS` with the frame budget and add a test asserting the budget, so a future peer-cap raise fails loudly | XS | **DONE** `09e49b13` (budget test) |
| PF-09 | `push_list` does not bound a single over-cap element | Add an assert that one element fits `MAX_ARG_BYTES - key.len() - 1` | XS | **DONE** `09e49b13` (documented + `debug_assert`; see the row note) |
| PF-10 | Root `pfctl -f` on a predictable `$TMPDIR` file in the precedence validator | Convert `write_restore_file` to the `write_root_owned_pf_temp` pattern, or route the restore through the builtin (closes SR-020) | S | **DONE** `29a9666d` |
| PF-11 | `contains_forbidden_route_primitive` evadable but unreachable | Tighten the matcher for tidiness only; note the test at `:635` blesses the paren gap and must be updated with it | XS | — |
| PF-12 | This production privilege-boundary file has no ledger row — and 11 unrowed production files exist | Add rows for all 11, cross-linking the parity-log review and this document. Root cause: they postdate the ledger's snapshot, so add a step that catches new production files | S | — |
| PF-13 | Three round-trip tests pin render equality, not spec equality | Assert `decoded == original` in the blind-exit and exit-NAT round-trips; sweep `strict` and `generation` in the cartesian test | S | **DONE** `02333009` |
| PF-14 | `reject_nonempty` is a content guard with a presence-guard name | Rename, or add a presence check so the guard matches its name | XS | **DONE** `02333009` |
| PF-15 | **`block_all_egress` does not block all egress** — `FailClosed` leaves up to 320 UDP passes rendered | Have `force_fail_closed` clear the three lists (or have `apply_pf_rules(true)` ignore them). Replace the two "minimal" tests with fixtures that **populate** all four lists, so the assertion cannot pass vacuously | S | test first |

### Part IV — `rustynet-relay` (RLY)

| ID | Problem | Possible direction | Size? | Before you start |
|---|---|---|---|---|
| RLY-01 | No lower bound on `issued_at_unix`; a future-dated token replays forever | Reject `issued_at_unix > now + skew` in `validate_hello`. One check, restores the retention invariant the comment already claims | XS | **DONE** `62837ed0` |
| RLY-02 | One unauthenticated datagram forces O(N) work under both global locks (~4900× amplification) | Match on the error variant and prune only for reclamation-worthy cases — `UnauthorizedSourceTuple` means the session is *healthy*. The keepalive path already does this correctly. Safe: prune is also driven by the periodic cleanup and the accept path | XS | **DONE** `62837ed0` |
| RLY-03 | Signed-payload field boundaries not bound by the signature | Reject `\n`/`\r`/`=` in `node_id`/`peer_node_id` at parse time, **or** length-prefix the signed payload, **or** port the text parser's re-canonicalization check to the binary parser. **S3** covers the issuance half | S | **PARTIAL** `4333d473` (S3) — issuance half only |
| RLY-04 | Replay store never parent-dir fsync'd, and a doc asserts it is | Add the parent-directory fsync after rename, using the existing pattern from `rustynet-crypto` / `write_ledger`; correct `Arm32BitEmbeddedSupportReference:919` | XS | **DONE** `62837ed0` |
| RLY-05 | Pre-auth limiter bounds entry count but not key size (~1015 MiB) | **See S4** | XS | **DONE** `62837ed0` |
| RLY-06 | Pre-auth ed25519 verify keyed on attacker `node_id`, under the transport mutex | Key the pre-auth limiter on the source IP rather than the claimed identity; move the verify out from under the transport mutex | M | — |
| RLY-07 | Rate limiting per-`node_id` only; no aggregate or per-destination cap | Add a global token bucket and a per-destination cap, **or** amend the module header's "bounded resources" claim to match reality | S | DECISION |
| RLY-08 | Reject-path log writes are the unbudgeted twin of the budgeted notice path | Route the ten `eprintln!` sites through `PreAuthNoticeBudget` | S | — |
| RLY-09 | Bind mutation precedes the rate-limit check; IP-only TOFU bind lets a spoofer lock out the real peer | Consult the limiter **before** mutating the bind (free win). Consider a rebind path or full-tuple bind — note the "intentional NAT concession" rationale does **not** exist, so nothing recorded blocks tightening it | S | — |
| RLY-10 | Replay window whenever `ttl + 2*skew >= retention` — **61 s at the daemon's default skew**, for any `ttl >= 60` (originally recorded as a one-second window at `skew == 120`, which undercounted: skew applies twice) | Size retention from the true acceptance window: `NONCE_RETENTION_SECS = ttl + 2*skew_ceiling + 1`, and fix **both** const guards. Do **not** clamp the skew below 60 — that rejects the honest 60–90 s drift the tolerance exists for | S | **DONE** `62837ed0` — see §0; the originally-suggested skew-ceiling fix was insufficient |
| RLY-11 | No self-pair rejection — the relay echoes to the sender | Assert `node_id != peer_node_id` in `validate_hello` as defence in depth; the control plane already refuses to mint one | XS | **DONE** `62837ed0` |
| RLY-12 | `node_id` written unescaped into log lines | Escape or reject control characters before logging; the correct upstream guard is `is_valid_node_id_text` (**S3**), not `NodeId::new` | XS | **ALREADY CLOSED** — verified 2026-07-30: the cited interpolation is gone; every relay `eprintln!` now takes a `SocketAddr`, a `Debug` enum, or an error |
| RLY-13 | Unreachable size guard; invisible tuple rejections; data-path skew inconsistency; O(n) persist per hello | Restate the `rate_limit.rs` ledger row (the "caller caps len" justification is vacuous); add a counter for `UnauthorizedSourceTuple`; apply skew consistently on the data path or document why not; batch the nonce persist | S | — |
| RLY-14 | Ledger maintenance | Mark AUDIT-031 stale (superseded by applied RSA-0037 — but see S4, the byte half is open); promote RSA-0086/0087/0088 off "needs confirmation"; add a row for `hello_limiter_audit.rs`; name the authoritative port range | S | — |
| RLY-15 | `now_unix()` → `0` on a pre-1970 clock makes every token unexpired in both `is_expired` and the data path | **The sentinel half of this direction is UNSAFE — do not take it (analysed 2026-07-30).** Substituting `u64::MAX` does fix expiry (`MAX > expires_at + skew` ⇒ every token expired) but breaks anti-replay: `NonceStore::prune` computes `now - retention`, so with `now = u64::MAX` **every nonce is evicted** and the replay set empties on each prune. Today's `0` is the mirror image — it retains nonces (fail-closed for replay) while disabling expiry. Neither sentinel is uniformly fail-closed, because the two consumers want opposite directions from the same value. Only the `Result` half works: make the failure explicit and dispose per call site — reject the hello, treat a session as expired on the forward paths, and **skip** the prune so nonces are retained. Original direction, for the record: return `Result` and fail closed at the call sites, or substitute a sentinel that makes tokens **expired** rather than unexpired, so a broken clock denies instead of admitting. Matters because the repo targets RTC-less Pi Zero-class relay hardware | S | **DONE** `7c262858` — took the `Option` half, disposing per call site; stamped 2026-07-30, the fix having landed earlier without the row being marked |
| RLY-16 | The replay store's **file-side** permission check is skipped on any non-`NotFound` stat error | Either treat a non-`NotFound` stat error as fail-closed, or keep the documented skip and narrow the surrounding claim so nobody relies on "fails closed" for the file. The existing rationale is defensible — decide, do not just tighten | S | **DECISION** |

### Part V — `rustynet-control`, trust issuer (CTL)

| ID | Problem | Possible direction | Size? | Before you start |
|---|---|---|---|---|
| CTL-01 | `is_valid_node_id_text` is non-blank only, so node-id-bearing signed payloads are delimiter-injectable | **See S3.** Note the reachable path is `NodeRegistry::upsert` via three CLI verbs, not the test-only enroll path | S | **PARTIAL** `4333d473` (S3) — node-id vector closed; CTL-02/CTL-03 vectors remain |
| CTL-02 | `verify_signed_endpoint_hint_bundle` is the only bundle verifier with no re-canonicalization | Add the `expected_payload != bundle.payload` comparison both siblings already have; same for `verify_signed_auto_tunnel_bundle` | S | test first |
| CTL-03 | `SignedPeerMap` leaves `generated_at_unix` outside the signature and validates nothing | Include a version line and the timestamp in the signed payload; reject `\|`, `\n`, `\r` in all six interpolated fields; reject duplicate `node_id` records | M | **GATED** — see §1 |
| CTL-04 | Enrollment evaluates credential expiry against a caller-supplied clock | Inject a clock or use `unix_now()`; treat `request.now_unix` as an untrusted hint bounded to ±skew. Confirmed *not* to affect the production path | S | — |
| CTL-05 | No bundle verifier checks expiry — all four accept decades-expired artifacts | Add a `now_unix` parameter and reject `now > expires_at` and `generated_at > now + skew`; **or** rename to `verify_*_signature` and add a distinct freshness wrapper so callers cannot mistake one for the other | M | test first |
| CTL-06 | No signed artifact carries a generation, so there is no anti-rollback | Add a monotonic `generation` to each signed bundle; have consumers persist and enforce a highest-seen floor. Bounded today by TTL except for `SignedPeerMap` | L | DECISION |
| CTL-07 | RSA-0010 and RSA-0017 are applied but their ledger rows read open | Update both rows; name the remediation plan authoritative for the 2026-06-24 batch; `sign_at` remains `pub` and un-gated (RSA-0010's second half) | XS | — |

### Part VI — Windows privileged/at-rest surface (WIN)

| ID | Problem | Possible direction | Size? | Before you start |
|---|---|---|---|---|
| WIN-01 | The DPAPI custody ACL gate is a three-alias substring denylist, not default-deny | Port the `windows_ipc.rs` pattern: enumerate allow-ACE principals, require a subset of `{SY, BA, service SID}`, pin owner, reject any unparsable or non-`A` ACE. Confirm against the 13 live `windows_dpapi_key_custody` runs | M | test first |
| WIN-02 | Pipe name unowned between messages; client never authenticates the server | Hold one persistent listening instance (or pre-create before the loop); use `CreateFileW` with `SECURITY_SQOS_PRESENT \| SECURITY_ANONYMOUS` plus a `GetNamedPipeServerProcessId` token check; add bounded backoff on the serve-error path | M | test first |
| WIN-03 | WFP installs only a max-weight PERMIT with `CLEAR_ACTION_RIGHT`; the assertion checks existence not scope | Read the filter back and assert `action == PERMIT`, exactly one condition, `fieldKey == IP_LOCAL_INTERFACE`, and the LUID equals the tunnel alias; reject an alias resolving to `egress_interface`. **Part of S2** | M | **DONE** `d40323e8` (S2) |
| WIN-04 | System32 check is a substring test — UNC and user-writable prefixes pass | Resolve `%SystemRoot%` via `GetSystemDirectoryW` and require a canonicalized **prefix** match; reject UNC unconditionally; verify Authenticode before first exec | S | test first |
| WIN-05 | PF-02 generalizes to the Windows backend | **See S1** | S | **DONE** `464e3b79` (S1) |
| WIN-06 | `validate_windows_dpapi_file` accepts an inherited DACL | Require `D:P` on the file as well as the root; set an explicit DACL in `write_windows_dpapi_blob` | S | — |
| WIN-07 | The pipe security policy type has zero production callers; a hardcoded check does the real work | Pass the policy into `named_pipe_client_authorized`, or delete the type so the tests stop implying it governs the boundary | S | DECISION |
| WIN-08 | Self-check pipe leaf is an unbounded prefix match | Bound the suffix to `[0-9]{1,10}` and forbid `\` after the prefix | XS | **DONE** `09e49b13` |
| WIN-09 | All three SDDL evaluators are blind to conditional (`XA`) ACEs | Treat any ACE type other than `A` as a rejection rather than a skip | XS | — |
| WIN-10 | AUDIT-028/029/030 confirmations, plus a doc correction | Supply `pOptionalEntropy` and bind the blob description to its key id (AUDIT-028); zeroize the DPAPI plaintext before `LocalFree` (AUDIT-029); reject interior NULs in `to_wide` (AUDIT-030) | S | — |

### Part VII — IPv6 leak prevention + blind exit (IPV)

| ID | Problem | Possible direction | Size? | Before you start |
|---|---|---|---|---|
| IPV-01 | The Linux exit own-egress accept is family-agnostic, so an `inet` killswitch does not contain IPv6 — and the assertion *requires* that rule | Qualify as `oifname <egress> ip accept`; add `meta nfproto ipv6 oifname != <tunnel> drop` at the top of the chain; assert **both** in `assert_firewall_ruleset`. Also correct RN-07's premise sentence, and retarget "bring Windows to Linux parity" at macOS's rendering discipline | M | test first |
| IPV-02 | Flipping `ipv6_parity_supported` removes the only working control | Gate the flag on the `ip6` sibling table existing, and refuse to promote it while `linux_runtime_nftables` is unwired | S | **GATED** — see §1 |
| IPV-03 | `nft_ruleset_has_v6_drop` credits chain `policy drop` while ignoring accepts above it | Require `policy drop` **and** no `accept` preceding the drop in the same chain, or replace the heuristic with a positive `meta nfproto ipv6 … drop` requirement. Update the fixture that pins the blind spot. **Part of S2** | M | **DONE** `f2e084d9` (S2) |
| IPV-04 | `rule_is_v6_drop` credits RA suppression, single-address, DNS-only, input-hook, unhooked and foreign-table drops | Require the drop to be unqualified (`meta nfproto ipv6`, no daddr/dport/icmpv6-type narrowing), in the killswitch table, on an egress hook, with no preceding accept. Evaluate the table/hook gate **before** crediting | M | test first |
| IPV-05 | `probe_attempted` only proves the ping binary exists; a failed pcap capture reads as zero leaks | Require a **positive control** (the probe must reach a global v6 target with the killswitch down before the run counts); make an unreadable or absent pcap `leaked = unknown → fail`. Withdraw the "exemplar template" credit in the two live-lab honesty docs | M | test first |
| IPV-06 | The sole production IPv6 control is an unasserted, allowlist-revocable sysctl; Linux has no drift loop | Re-read `disable_ipv6` in `assert_firewall_ruleset` and fail closed on drift, as `assert_nat_forwarding` already does for `ip_forward`; add a periodic reconcile matching macOS's poller | M | test first |
| IPV-07 | `prior_ipv6_disabled` re-captured on every apply, clobbering the true baseline | Copy the `is_none()` guard from the IPv4 path verbatim | XS | — |
| IPV-08 | Blind-exit drift checks are exact-string equality; blind to supersets and `policy accept` | Require `policy drop` on the forward chain; replace equality-based absence checks with a positive whitelist ("the forward chain contains exactly these N rules") — the only shape that catches a superset | M | test first |
| IPV-09 | The blind-exit mesh allow is credited from any table and any chain | Parse to `(family, table, chain)` and require the rule inside `inet <killswitch_table>` chain `forward` with `hook forward` | S | — |
| IPV-10 | The blind-exit evaluator is not on the daemon assert path, contradicting its own doc | Call `evaluate_linux_blind_exit_ruleset` from `assert_exit_serving` when `blind_exit_config.is_some()`; correct the module doc either way | S | **DONE** `09e49b13` |
| IPV-11 | The blind-exit re-author is three `nft` invocations, not one transaction | Emit one `nft -f -` transaction so flush+adds are atomic, and pin `policy drop` in the same transaction | S | — |
| IPV-12 | The WireGuard port allows are family-agnostic | Decide whether v6 peer endpoints require it; if not, qualify with `ip`. Correct `SecurityReview_2026-05-24:518`, which cites this as the narrow model | S | DECISION |
| IPV-13 | macOS `pf_rules_have_v6_block` ignores direction, interface and anchor reachability | Require an `out`-direction, unscoped v6 block with no preceding `pass`; verify the anchor is referenced by the main ruleset | S | test first |
| IPV-14 | Orchestrator passes no `--killswitch-table`, so the nft branch evaluates a stale generation | Pass the live table name through from the run context | XS | — |

### Part VIII — Enrollment (ENR)

| ID | Problem | Possible direction | Size? | Before you start |
|---|---|---|---|---|
| ENR-01 | `admit --node-id` with a newline permanently corrupts the persisted membership snapshot | Validate charset and length in `MembershipState::validate` **and** at `EnrolleeAdmitContext` construction (**S3**); add a negative test for each of the three observed corruption shapes | S | **DONE** `436b23b7` — guard placed in `validate` (the chokepoint inside both `canonical_payload` and `decode_membership_state`) and widened to all six free-form fields, not just node id; CLI checks it before the token is consumed, which partially mitigates **ENR-04** |
| ENR-02 | `NodeRegistry::upsert` has zero validation and three production callers | Validate inside `upsert` itself so every caller inherits it (**S3**) | XS | **DONE** `4333d473` (S3) — stamped 2026-07-30; the fix landed with S3 but the row was never marked |
| ENR-03 | A `\r` silently mutates an identifier across encode/decode, producing state-root drift | Rejecting `\r` (**S3**) closes it; add a round-trip test asserting `decode(encode(x)) == x` for identifier edge cases | S | **DONE** `436b23b7` — reading the decoder found three more mutation shapes the review did not name: `split_csv` does `split(',') → trim → drop-empty`, so a role with an embedded comma, surrounding whitespace, or an empty entry also fails the round trip; and `metadata_hash: Some("")` decoded back as `None`. All refused |
| ENR-04 | `admit` burns the single-use token before validating the collision or loading the signing key | Move the duplicate-`node_id` check, the signing-key load, and an output-path writability probe **ahead** of the consume — or make the consume the last durable step | S | — |
| ENR-05 | Role bridge drops 8/14 tokens to Client **and** grants `Anchor` from 4 tokens the canonical parser rejects | Delegate to `RoleCapability::parse` and return a typed error on any unrecognised token. **Also re-rate RSA-0015** — its "can only drop privilege" rationale is wrong in both directions | S | **DONE** `c61c1e92` — the second table is deleted, not corrected; the five invented aliases (`exit`, `relay`, `entry`, `tag:members`, `tag:clients`) go with it. Tests derive their expectation FROM the canonical parser, so a new capability extends them automatically rather than needing a third hand-copy. Decode-side twin closed separately at `93dbd421`. **STILL OWED: the RSA-0015 re-rate**, which lives in another ledger and was not touched here |
| ENR-06 | A `--roles blind_exit` typo at admit is irreversible | Require an explicit `--confirm-irreversible` flag when the admit role set maps to `BlindExit`. **Do not** touch the reducer guard | S | **see §1** |
| ENR-07 | On non-Unix the `<ledger>.lock` file wedges enrollment permanently after a crash | Use a real Windows file lock (`LockFileEx`), or stamp the lock with the owning PID and treat a dead owner as stale | S | test first |
| ENR-08 | `load_ledger` lacks the permission gate and size cap that `load_secret` has | Apply the same group/world rejection and size cap | XS | **DONE** `73ae5cc9` + `de9a6afb` — needed a write-side cap too; see §0 |
| ENR-09 | The persisted single-use ledger has no MAC, generation, or anti-rollback | MAC the ledger with the enrollment secret and add a monotonic counter; deleting the file should not silently reset single-use state | M | DECISION |
| ENR-10 | No rate limit or attempt counter on the consume path | Add an attempt budget; check the token HMAC **before** taking the exclusive ledger lock and reading the whole ledger | S | — |
| ENR-11 | `purge_expired_against` is a genuine no-op | Implement the purge (RN-26); the ledger is currently grow-only | S | — |
| ENR-12 | The daemon never provisions the enrollment secret, contradicting the module doc | Either provision it at bring-up as documented, or correct the doc and add the operator provisioning step to the runbook | S | — |
| ENR-13 | `enrollment mint --output` writes the bearer token under the default umask | Write 0o600, matching `write_secret` / `write_ledger` (AUDIT-011) | XS | **DONE** `fa67f646` — temp-at-0o600 then rename, so there is no window at the wider mode and an existing destination's permissions are replaced rather than inherited; non-unix fails closed per **S5** |
| ENR-14 | Two per-file ledger rows read `open` for an applied RSA-0023 | Update both rows | XS | — |
| ENR-15 | A stale ledger reachability claim — `build_gossip_node` is a second production setter | Correct the claim; the IPC `enrollment consume` verb is config-gated live, not dead | XS | — |

---

## 4. A suggested order (opinion, not a schedule)

1. **S5 (CRY-05)** — already on the NO-SHIP list, one line.
2. **S4 (RLY-05)** — one line, and finishes the half-closed NO-SHIP item AUDIT-031.
3. **S1 (PF-02/WIN-05)** — one validator, three platforms.
4. **RLY-02** — one-line variant match, largest measured remote impact in the document.
5. **S3 (CTL-01/ENR-01/ENR-02/ENR-03)** — apply the guard that already exists.
6. **S2 (PF-05/WIN-03/IPV-03/RN-27)** — the biggest job, and the one that converts silent failures into loud ones. Everything in §1's GATED list becomes safer once assertions can actually detect a permissive rule.
7. **IPV-04, IPV-05** — the verifier that certifies leaks and the probe that passes with no IPv6 upstream. False assurance hides everything else.
8. **PF-15, IPV-01, IPV-06** — fail-closed guarantees that do not currently hold.
9. Everything marked **DECISION** — route to an owner; these are choices, not tickets.
10. Everything marked **GATED** — do not start until the prerequisite in §1 is resolved.

## 5. Open questions that gate other work

| Prerequisite | Blocks | Why |
|---|---|---|
| On-box pf sub-anchor ordering experiment | PF-03, PF-04, PF-07 | Determines whether load-then-flush is safe or causes an egress blackout |
| Confirm whether peer-advertised endpoints are validated | PF-15 severity | If a remote peer can advertise an arbitrary endpoint, PF-15 becomes High |
| Decide whether D13 service hosting is meant to be live | POL-05, POL-11, POL-12 | The whole path is currently unreachable in a shipped daemon |
| Decide `PolicyRolloutController`'s fate | POL-07, POL-08, POL-09 | All three are latent traps only because the controller is half-present |
| Confirm the 13 live Windows runs | WIN-01 … WIN-10 | Every Win32 runtime claim is INFERRED; these runs are where to check them |
| On-disk framing migration plan | CRY-04 | The framing fix is deferred pending it |
| Wire-format migration plan | CTL-03 | The code explicitly forbids a local fix |

## 6. Untriaged leads — discovered but NOT reviewed, so deliberately not given finding IDs

These surfaced as side-observations during the reviews. None has been verified, none
is a finding, and none should be treated as one — they are recorded so they are not
lost, and so nobody mistakes the 103-entry dictionary for a complete account of
everything the reviews touched.

| Lead | Where it came from | Why it is not a finding | Suggested next step |
|---|---|---|---|
| `linux_exit_nat_lifecycle.rs` appears to carry the **same `unwrap_or_default()` fail-open** that IPV-05 found in the IPv6 leak modules — and `LiveLabCoverageAndHonestyAudit_2026-06-25.md` items #1/#2 already record it there at **CRIT**, apparently unfixed | Part VII, as context for IPV-05 | That file was never in any part's scope and was not read | Review the file; if the twin is confirmed, it is a pre-existing CRIT that IPV-05's fix should be applied to at the same time |
| `managed_peer_egress_endpoints` may accept **peer-advertised** endpoints without the guard `validate_runtime_relay_candidate_endpoint` applies to relay candidates | Part III, PF-15 | Explicitly labelled INFERRED; the managed-peer path was not traced | Trace it. If a remote peer can mint a pass, **PF-15 becomes High** |
| pf `anchor "com.apple/*"` sub-anchor **evaluation order** (lexicographic vs numeric) | Part III, PF-07 | Needs an on-box experiment that was not run | Run it — it gates PF-03, PF-04 and PF-07 (see §5) |
| The `Skip`-on-absent-artifact behaviour in the IPv6 leak orchestrator stage | Part VII | Documented intent, honest message — raised as an observation only | Leave unless the skip is masking real absences |

## 7. Honesty notes

- **Nothing here is verified.** These are proposals derived from a review that changed no code. Each needs an enforcement point plus a negative test before it counts as closed.
- **The findings doc had a 12-error rate** when adversarially audited, including two mis-rated Highs in both directions. Where a fix here looks disproportionate to its finding, re-read the finding first — the severity may be the thing that is wrong.
- **Effort estimates are structural, not scheduled.** "XS" means the code change is one line, not that the test, review and live-lab proof are free.
- **This dictionary was built by mapping finding IDs to fixes, which means it can only
  ever be as complete as the ID list.** Two real defects (**RLY-15**, **RLY-16**) were
  originally written as prose corrections inside a *defence* list rather than as
  numbered findings, and were therefore invisible to this mapping until a
  completeness check found them. The rule that follows: **withdrawing a credited
  defence must create a finding**, because a defence that does not hold usually means
  a defect does. §6 exists for the same reason — to hold what is deliberately *not*
  in the dictionary.
- **Several entries fix a *document*, not code** (PF-12, CTL-07, RLY-14, ENR-14, ENR-15, IPV-05's credit withdrawal, CRY-10, IPV-01's RN-07 correction). Those are cheap and worth doing early, because stale docs are what produced several findings in the first place.
