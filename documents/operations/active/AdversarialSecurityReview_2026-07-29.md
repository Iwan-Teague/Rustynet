# Adversarial Security Review — 2026-07-29

Status: review only — **no code changed**, no enforcement applied; findings await owner triage
Audit baseline: repository at commit **`22847b12`** ("refactor(live-lab): call the key-custody report writer in-process"), on `main`. Parts V and VI were verified as the tree advanced under concurrent workers (`fe634559`, then `c5018acb`); those parts note their own drift and their line refs should be treated as approximate.
Method: rolling adversarial review, one focused area per part. Each part names its own crate baseline, scope, and reachability conclusions.

| Part | Area | Findings | Status |
|---|---|---|---|
| **I** | `rustynet-policy` — ACL / policy evaluation engine | POL-01 … POL-14 | complete |
| **II** | `rustynet-crypto` — key custody, key envelopes, signing | CRY-01 … CRY-12 | complete |
| **III** | macOS `pf` privileged-helper boundary — killswitch rule regeneration | PF-01 … PF-15 | complete |
| **IV** | `rustynet-relay` — remote/unauthenticated input path | RLY-01 … RLY-16 | complete |
| **V** | `rustynet-control` — the trust issuer (signed-artifact issuance) | CTL-01 … CTL-07 | complete |
| **VI** | Windows privileged + at-rest surface (named pipe, DPAPI, WFP) | WIN-01 … WIN-10 | complete |
| **VII** | IPv6 leak prevention + blind-exit dataplane (Linux, macOS) | IPV-01 … IPV-14 | complete |
| **VIII** | Enrollment — token, ledger, admit path | ENR-01 … ENR-15 | complete |

This is a single rolling document by intent: the areas share the same baseline
commit and the same fail-closed/default-deny constraints, and several findings
cross-reference each other (Part I's membership gate depends on Part II's signed
key custody). Splitting them would hide those links.

## 0. Meta-review — this document was audited against the code, and corrected

An adversarial review of *this document* was run on 2026-07-29 and found 12
factual errors plus several overstatements. All are corrected in place and marked
`Corrected 2026-07-29 (meta-review)` so the record shows what changed rather than
quietly reading as though it were right all along. The material ones:

| Was | Now |
|---|---|
| Part VI §24: these Windows paths have "never run outside a unit test" | **False.** The authoritative `live_lab_run_matrix.csv` shows 13 live passes each for `windows_named_pipe_acl` and `windows_dpapi_key_custody`. The earlier claim generalized from the *node* matrix — an error this repo had already caught and recorded once (`LiveLabFindings_2026-07-03.md:364-368`) |
| CTL-01: High, "single highest-leverage fix in the whole document" | **Medium-latent.** Enrollment has zero production callers, so the injection precondition is unreachable in a shipped binary — the same discount CTL-04, POL-10, CRY-09 and WIN-07 already applied to themselves. Class also already tracked as AUDIT-042 |
| CRY-05: Medium, mapped to RSA-0002 | **High**, also mapped to **AUDIT-027** — an existing High NO-SHIP item describing the identical lines |
| §14 item 14: "DNS ordering is correct" | **Withdrawn as a general defence.** Under `strict_fail_closed` the DNS blocks are skipped while the endpoint passes still render — a *candidate missing finding*, not a defence |
| §19 item 15: `now_unix` "fails closed to 0" | Fails closed against a *panic*, but **fails open on freshness** — `now = 0` disables expiry in both `is_expired` and the data path |
| PF-03: reorder to load-then-flush, "strictly safer" | **Gated.** That asserted as fact the pf sub-anchor ordering PF-07 marks unverified; if PF-07's inference holds the reorder causes an egress blackout every reconcile |
| POL-06: six issuance callers named | Two were mislabelled, and the wording contradicted CTL-03. `signed_peer_map` and `signed_relay_fleet_bundle` call the gate **not at all** |
| §12: "two were production daemon code" lack ledger rows | **Eleven** do — making PF-12 a systematic gap |
| RSA-0077 listed open | **Applied** (`6e0d0f0`); the repo-wide plain-`verify` grep is zero |
| RLY-08: ~200,000 log lines/s | **~409,600** — the earlier figure conflated the hello rate with the line rate |
| PF-06/RLY-09/RLY-12: three supporting citations | Each pointed at a comment or type that says something other than claimed; conclusions survive under corrected citations |

Also confirmed by the meta-review, and worth recording because it was the claim
most at risk: Part II §9's credit to `rustynet-crypto` for a full
`temp → fsync → rename → fsync parent` sequence is **accurate**, so RLY-04's
cross-crate contrast holds. Every quantitative claim in the document was
independently checked and found sound except RLY-08 above. Findings marked
**New** were re-checked against the ledger; the four with prior coverage are now
attributed (POL-05, POL-14, PF-05, CTL-01).

**Process lesson, recorded because it caused a real gap.** This meta-review
withdrew or narrowed **three** credited defences (the DNS-ordering credit,
`now_unix`, and the replay-store path check). Only the first was promoted to a
numbered finding at the time. The other two were left as prose corrections inside a
defence list — and because the companion remediation document is built by mapping
*finding IDs* to fixes, both fell out of it entirely and went unplanned until a
completeness check caught them. They are now **RLY-15** and **RLY-16**.
The rule this implies: **withdrawing a credited defence should always create a
finding**, because a defence that does not hold usually means a defect does.

**Follow-up completed 2026-07-29.** The two loose ends this meta-review left have
since been closed by a dedicated re-verification pass, which corrected the
meta-review itself in three places:

- The withdrawn "DNS ordering" defence is now resolved as **PF-15** — and the real
  defect is not the mode inversion but that `block_all_egress` leaves up to 320 UDP
  passes rendered in the state named `FailClosed`, reachable in honest operation.
- The render function is **byte-identical to the baseline**, so PF-15 was an error
  in the original credit rather than drift. The meta-review's "needs re-verification
  at HEAD because the renderer moved" caveat was chasing a shift that never touched
  this code.
- Part III's corrected anchor table was itself wrong twice: PF-04's flush arm is at
  `:2210` (not `:2193`), and only `c5018acb` touched `phase10.rs` — its +43 lines are
  entirely in `LinuxCommandSystem`, and the traversal/managed-peer render loops
  predate the baseline. A complete per-file shift mapping is now in Part III's header.

Every remaining Part III reference either sits in an unmodified file or shifts by a
pure constant; **nothing needed re-review for material code change.**

**Companion document:** `documents/operations/active/AdversarialSecurityRemediation_2026-07-29.md`
mirrors this one entry-for-entry — every finding ID below has one entry there. It is
**starting notes, not a plan**: no fix in it has been prototyped or tested, and about
three quarters of its directions were written from reading rather than restating a
verified enforcement note. **Eight of those fixes must not be applied as
written** (one would blackhole a live fleet, one would convert a protective guard
into a fail-open); that document's §1 lists them. Read a finding here before
implementing its fix there.

Out of scope throughout: WireGuard backends, live-lab evidence, and the GUI.
(Earlier revisions of this header also excluded relay framing; Part IV now covers
the relay's untrusted-input path, so that exclusion no longer applies.)

---

# Part I — `rustynet-policy` (ACL / policy evaluation engine)

Crate baseline: `crates/rustynet-policy/src/lib.rs`, 1132 lines, zero external dependencies, `#![forbid(unsafe_code)]`; `cargo test -p rustynet-policy` **21/21 green** at this commit
Scope: selector and identity handling, the membership/revocation gate, context matching, `PolicyRolloutController` + `validate_policy_safety`, and `LlmAccessScope`/`LlmScopePolicy`; plus the production call sites in `rustynetd`, `rustynet-control`, and `rustynet-llm-gateway` that determine whether each defect is reachable
Out of scope for this part: crypto primitives and signing/verification (covered in Part II)

## 1. Purpose and security rule

This document records an adversarial re-review of the policy engine. It is a
findings backlog, not live-lab evidence and not a remediation record.

**Nothing below authorizes weakening fail-closed behavior, default-deny policy,
or signed-state provenance.** Every "proposed enforcement" is review-only and
deliberately unapplied. Per `documents/SecurityMinimumBar.md`, a
security-sensitive fix requires both an enforcement point and a negative
verification test; none of the proposals here have either yet.

Because the crate's own suite is 21/21 green at this baseline, **every finding
below is a coverage gap, not a regression.** The existing tests pin only
canonical inputs, so none of them fail in the presence of these defects.

### 1.1 Relationship to existing tracked findings — read this first

Four of the findings restate or extend items already in
`documents/operations/active/SecurityAuditLedger_2026-06-18.md` and
`documents/operations/active/DocCodeDiscrepancyAudit_2026-07-18.md`. They are
**not** presented as new discoveries. The table separates new material from
confirmation so triage is not misled:

| This review | Existing entry | Relationship |
|---|---|---|
| POL-06 | **RSA-0005** (Low, open, corrected 2026-07-27) | Confirms; **argues the severity premise is still understated** — see POL-06 |
| POL-07 | **RSA-0006** (Low, open) | Confirms the protocol-enumerated evasion; **extends** with a service-context blind spot |
| POL-10 | **DA-37** (`DocCodeDiscrepancyAudit_2026-07-18.md:30,112`) | Confirms the runbook/code divergence; **adds** the structural reason (no accessor exists) |
| POL-02 | `SecurityAnalysis_2026-06-12.md:76` documents the intent | Confirms behaviour is **by design**; reframes what that design leaves uncovered |
| POL-01, POL-03, POL-04, POL-05, POL-08, POL-09, POL-11, POL-12, POL-13, POL-14 | none found | **New.** Searched `documents/` for selector-normalization, whitespace, case, and unknown-prefix handling — the only hit is an unrelated parser note (`PlatformImprovementBacklog_2026-05-14.md:177`) |

`RSA-0007` (revocation-blind `evaluate` in `phase10.rs`) is **applied/fixed**;
verified at this baseline that `phase10.rs:5431` and `:5507` both call
`evaluate_with_membership`. This review does not reopen it.

### 1.2 How these findings were verified

Claims labelled **CONFIRMED** were executed, not reasoned about. The crate has
zero dependencies, so `lib.rs` was copied verbatim into a scratch location
**outside the repository** with its own `#[cfg(test)]` module stripped, an
adversarial `main` appended, and compiled with `rustc --edition 2021`. Every
`Allow`/`Deny` quoted below is the engine's actual output. The repository was
never written to; `cargo test -p rustynet-policy` was run with a scratch
`CARGO_TARGET_DIR` so as not to contend with other workers' builds.

Findings labelled **INFERENCE** are reasoned conclusions from confirmed
individual links, and are marked as such inline.

## 2. Findings, ranked by recommended execution priority

| ID | Finding | Severity | Reachable today? |
|---|---|---|---|
| POL-01 | `selector_requires_membership` is an allowlist whose **miss branch fails open** — any non-canonical prefix skips revocation entirely | High | Operator/control-plane-authored input only |
| POL-02 | Raw CIDR destinations skip the gate, and `user:local` resolves only to the **local** node — so two shipped daemon paths validate no remote peer | Medium | **Yes**, shipped default policy |
| POL-03 | The empty string is a valid, ungated, `*`-matching identity | Medium | Latent (no call site emits it) |
| POL-04 | The gate never binds a selector to the **requesting** peer — it trusts the selector string wholesale | Medium | Latent (call sites use constants/`node:`) |
| POL-05 | `LlmAccessScope` absence = maximum privilege, and three separate paths reach absence silently (the `None`-is-unrestricted *design* is documented in `ServiceHostingRolesDeltaPlan_2026-06-11.md:77`; the swallowed-read-failure and malformed-parse paths are new) | Medium | Inert (see POL-13) |
| POL-06 | `is_populated()` doc advertises a removed fail-open; its live caller is **unconditionally inert in production** | Medium (re-rate) | **Yes**, issuance layer |
| POL-07 | `validate_policy_safety` is evadable and context-blind | Low | Inert (controller unwired) |
| POL-08 | `stage_revision` silently overwrites a revision — the rollback target is mutable and not content-addressed | Low (High as design) | Inert |
| POL-09 | `rollback_to` activates never-promoted revisions, bypassing canary review | Low | Inert |
| POL-10 | `PolicyRolloutController` is decorative — no accessor returns the active policy | Low (doc divergence) | Inert |
| POL-11 | Scope key format mismatch: policy emits `node:<id>`, gateway looks up bare `<id>` | Low (latent) | Inert |
| POL-12 | `scope_for` doc claims specificity tiering the code does not implement | Low | Inert |
| POL-13 | No fuzz target covers the policy engine | Low (process) | n/a |
| POL-14 | Adjacent: two daemon ACL results discarded with `let _ =` (`set_exit_node` half is **AUDIT-044**; `ensure_lan_route_allowed` half is new) | Medium | **Yes** |

---

### POL-01 — `selector_requires_membership` fails open on its miss branch (High, CONFIRMED)

File: `crates/rustynet-policy/src/lib.rs:435-440`, consumed at `:412-429`

`selector_requires_membership` is a case-sensitive `starts_with` allowlist over
`node:` / `user:` / `group:` / `tag:`. On a miss it returns `false`, and
`selector_membership_allowed` then returns `true` at `:416-418` — the revocation
check does not run at all. `selector_matches` (`:383`) then admits the string
against any `*` rule.

The direction of the failure is the defect: an unrecognized identity is
reclassified as "not an identity, therefore nothing to check," rather than as
unresolvable trust state. That inverts the mandated posture in `CLAUDE.md:318-330`
(§10.4: "empty/missing/malformed → deny").

Worked example against the daemon's **shipped default policy**, verbatim from
`crates/rustynetd/src/daemon.rs:4016-4024` (`src: "user:local"`, `dst: "*"`,
`Protocol::Any`, Allow, contexts Mesh+SharedExit), with `revoked-node` marked
`Revoked` in the directory:

| Request `dst` | Decision |
|---|---|
| `node:revoked-node` | `Deny` — correct |
| `NODE:revoked-node`, `Node:revoked-node` | **`Allow`** |
| `nodes:revoked-node`, `svc:revoked-node` | **`Allow`** |
| ` node:revoked-node` (leading space) | **`Allow`** |
| `revoked-node` (bare id, no prefix) | **`Allow`** |
| `nodе:revoked-node` (Cyrillic `е` homoglyph) | **`Allow`** |

The case variants are the sharpest edge: `NODE:` and `Node:` are the *same
prefix* to a human reader and a different prefix to the gate.

Reachability is bounded and should be stated honestly: production builds
selectors itself with `format!("node:{…}")` (`service_exposure.rs:266-267`,
`daemon.rs:4378`, `:4415`), so a hostile *node id* cannot inject a prefix —
`node:{garbage}` still fails closed. The live surface is the
operator/control-plane-authored side: one mis-cased or typo'd prefix in a policy
file or directory entry silently disables revocation for that identity, with no
error and no warning. Nothing in the repository validates selector prefixes.

Note the revealing asymmetry, both confirmed: `"node:revoked-node "` (trailing
space) **denies** — the prefix still matches, so the gate runs and the unknown id
resolves `Unknown` — while `" node:revoked-node"` (leading space) **allows**.
Only mangling that breaks the prefix is dangerous. There is no canonicalization
step anywhere.

Proposed enforcement (review-only — do NOT apply): invert the default. Parse
every selector into a recognized, canonicalized kind and **deny anything
unparseable**, rather than extending the allowlist. Reject or normalize
surrounding whitespace and non-ASCII, and treat a non-conforming selector as a
policy *load* error rather than a silent runtime allow.

Verification method: a table-driven negative test asserting `Deny` for each
mutation above; a policy-load validator rejecting non-conforming selectors.

---

### POL-02 — raw CIDR dst plus local-only `user:local` leaves two shipped paths validating no remote peer (Medium, CONFIRMED)

Files: `crates/rustynetd/src/daemon.rs:4397-4405`, `crates/rustynetd/src/phase10.rs:5507-5513`, gated by `crates/rustynet-policy/src/lib.rs:435-440`; directory construction at `daemon.rs:15453-15469`

Two production `evaluate_with_membership` sites pass a raw CIDR as `dst`:
`route.destination_cidr` (`daemon.rs:4399`) and `request.cidr`
(`phase10.rs:5509`). `selector_requires_membership` returns `false` for
`"192.168.1.0/24"`, so the destination contributes **no** revocation check.

This much is **by design and documented** — `SecurityAnalysis_2026-06-12.md:76`
states "Literal route destinations such as CIDRs are not treated as membership
selectors," and the behaviour is pinned by
`literal_route_destinations_do_not_require_membership_resolution` (`lib.rs:810-834`).
A destination network is not an identity, and requiring it to resolve to a member
would be wrong. The finding is not that this is a bug in isolation.

The finding is what it leaves uncovered once combined with the `src` side.
Confirmed at `daemon.rs:15467`: `membership_directory_from_state` does
`directory.set_selector_members(DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT, [local_node_id])`
— so `"user:local"` resolves to exactly one member, **the local node itself**.
Every daemon-side request uses `src: "user:local"`. Therefore on those two
route paths, the `src` check proves only that *this* node is Active and the
`dst` check proves nothing at all: **neither side validates the remote peer.**

Containment exists and should be credited: the peer *is* checked by the sibling
evaluations that pass `dst: node:<id>` (`daemon.rs:4375` for `bundle.peers`,
`:4412` for `route.via_node`) and by explicit `node_status(...) != Active`
pre-checks at `daemon.rs:7916` / `:7951`. So this is a defence-in-depth gap, not
a demonstrated end-to-end bypass. But the membership gate is precisely the layer
meant to catch a stale or compromised control plane emitting a route toward a
revoked peer's overlay address, and on these two paths it cannot fire.

Proposed enforcement (review-only — do NOT apply): give literal destinations an
explicit selector kind that resolves to the owning node's membership status where
the overlay address is known to the directory, so a revoked peer's `/32` is
deniable; and stop using a single `user:local` constant as `src` for decisions
whose real subject is a remote peer.

Verification method: a negative test asserting a route toward a revoked node's
overlay `/32` is denied.

---

### POL-03 — the empty string is a valid, ungated, wildcard-matching identity (Medium, CONFIRMED)

File: `crates/rustynet-policy/src/lib.rs:435-440` and `:383`

`selector_requires_membership("")` is `false` (no prefix matches) → gate skipped
at `:416-418`. `selector_matches("*", "")` is `true`. Confirmed results:

- rule `*`/`*`/`Any`/Allow + request `src: ""` → **`Allow`**
- the same, against a **completely empty** `MembershipDirectory` → **`Allow`**

So a missing, unresolved, or defaulted identity is classified as a harmless
literal instead of absent trust state — a direct inversion of `AGENTS.md:60`
("Fail closed when trust/security state is missing, invalid, stale, or
unavailable"). Note also that `selector_matches("", "")` is `true`, so a rule
with an accidentally-empty `src`/`dst` field matches an empty request field.

No current call site emits an empty selector, so this is latent rather than live.
It is nonetheless a fail-open default in the primitive that every caller depends
on. Contrast `"node:"` (empty id **after** a valid prefix), which correctly
**denies** because `node_status("")` returns `Unknown`.

Proposed enforcement (review-only — do NOT apply): reject empty selectors at
construction/parse time in both rules and requests.

---

### POL-04 — the gate never binds a selector to the requesting peer (Medium, CONFIRMED)

File: `crates/rustynet-policy/src/lib.rs:412-429`

`selector_membership_allowed("group:family")` asserts only that the group's
members are all `Active`. It never checks that the *requesting* peer is in that
group — the engine has no concept of "this peer's selectors." Confirmed:
directory has `group:family → [a]` with `a` Active; a request with
`src: "group:family"` returns **`Allow`** regardless of who is actually asking.

Not exploitable at today's call sites, which pass constants or `node:` forms.
But this is the structural reason POL-01 and POL-03 are dangerous rather than
cosmetic: the engine trusts the selector string wholesale, so any path that lets
an untrusted party influence that string converts directly into an authorization
bypass.

Also confirmed at `:419-427`, and worth crediting: both the unset case
(`selector_members` → `None`) and the explicit-empty case (`!members.is_empty()`)
correctly **deny**. A second, non-security consequence of
`all(status == Active)`: revoking one laptop silently denies every `group:family`
rule mesh-wide, with no signal distinguishing "you are revoked" from "someone in
your group is."

Proposed enforcement (review-only — do NOT apply): pass the requesting peer's
verified identity into evaluation and require the matched selector to be one the
peer actually holds.

---

### POL-05 — scope absence means maximum privilege, reached silently by three paths (Medium, CONFIRMED)

Files: `crates/rustynet-policy/src/lib.rs:268-290`, `:307-318`; `crates/rustynet-llm-gateway/src/enforce.rs:82-86`, `:172`; `crates/rustynet-llm-gateway/src/main.rs:244`, `:265-267`; `crates/rustynetd/src/service_access_state.rs:116`

`None` is both the `Default` and the deserialized-absent state, and
`permits_model` returns `true` for it (`:284-289`). `scope_for` returns `None`
for a missing peer (`:317`). Downstream, `admit_request` short-circuits to
`Ok(())` on a `None` scope (`enforce.rs:82-86`). Absent scope = unlimited
models, unlimited tokens, unlimited request rate.

To be fair to the authors, the quota and rate limiters **are** real, implemented
code: `enforce.rs:97-104` (rate → `RateLimited`), `:111-118` (token pre-check),
`:138-146` (mid-stream, severs the stream), wired at `main.rs:434` and `:475`.
The framing in `lib.rs:260-267` — "scopes only narrow, never authorise" — is
also true in the direction meant: a scope cannot manufacture an `Allow`.

The objection is that this framing is used to treat scope *loss* as benign, and
that does not follow. Once the grant exists, the scope is the only control
confining which model, how many tokens, and at what rate — materially different
privilege levels. Three confirmed paths reach absence with no error:

1. **Production always emits empty scopes.** `ServiceAccessSnapshot.scopes` is
   hardcoded `Vec::new()` (`service_access_state.rs:116`, documented at `:56-61`),
   so `scopes.v1` is always empty and every granted peer is unrestricted.
2. **Read failure is swallowed.** `main.rs:244` reads scopes under
   `if let Ok(body)`. A permission-denied, truncated, or corrupt `scopes.v1`
   yields an empty map with no error — while `grants.v1` correctly fails closed
   (empty grants → deny-all, `:286-290`). The asymmetry is backwards:
   authorization state fails closed, restriction state fails open.
3. **Malformed input fails open.** `quota.parse().ok()` / `rate.parse().ok()`
   (`:265-267`) turn `quota=abc` or an overflow into `None` = no quota. Unknown
   keys are ignored (`:255-269`), so `model=small` (missing `s`) yields an
   all-`None` scope. Note `models=` with an empty value *does* correctly yield
   `Some([])` = deny-all.

Proposed enforcement (review-only — do NOT apply): make absence deny — a
`ScopeTable::Loaded | Unavailable` enum where `Unavailable` denies, or a required
`Scope` with restrictive defaults, so "admin chose unrestricted" is
distinguishable from "state is missing."

---

### POL-06 — `is_populated()` doc advertises a removed fail-open, and its live caller is inert in production (Medium — recommend re-rating **RSA-0005**, CONFIRMED)

Files: `crates/rustynet-policy/src/lib.rs:112-118`; caller `crates/rustynet-control/src/lib.rs:3423-3443`, `:2288`

This confirms **RSA-0005** (Low, open, corrected 2026-07-27). One fact is added
that the ledger does not currently state, and it bears on severity.

The doc comment at `:112-118` still claims that on an empty directory the gate
"treats nodes as pre-membership and **skips the check**." The policy crate does
not do this — `selector_membership_allowed` never consults `is_populated`, and
`:714-735` pins `Deny`. Confirmed: empty directory + `node:` selector → `Deny`.
Provenance is unambiguous; commit `8cca1458` states "RN-11: empty membership
directory denies peer provisioning (**removed the `is_populated()`
governance-disabled bypass**)" and deleted the *twin* comment in `phase10.rs`
while leaving this one as untouched context.

The ledger's 2026-07-27 correction already records that the shape returned at
`rustynet-control/src/lib.rs:3432-3437`, and bounds the blast radius on the
grounds that the daemon re-checks membership. **The added fact:** that caller is
not merely permissive on empty directories — it is *unconditionally* inert in
production. `set_membership_directory` / `with_membership_directory`
(`control/lib.rs:2309`, `:2315`) have **zero production callers** — verified,
all five call sites are tests (`:7605`, `:7625`, `:7647`, `:7673`, `:7692`).
`ControlPlaneCore::new` initializes `membership_directory: MembershipDirectory::default()`
(`:2288`), and the three real constructions (`rustynet-cli/src/main.rs:6889`,
`:6996`, `:7087`) never install one. So `is_populated()` is **always** false in
a shipped binary, the RSA-0008 issuance gate **never runs**, and
`policy_allows_node_pair` (`:3423-3455`) reduces to the revocation-blind
`PolicySet::evaluate` on every issuance path that calls it. **Corrected
2026-07-29 (meta-review):** an earlier revision mislabelled two of the six
callers. The line numbers were right, the names were not — `:2609` and `:2642`
are both inside `signed_auto_tunnel_bundle` (peers and exit node), `:2748` is
`signed_dns_zone_bundle`, `:2840` `signed_endpoint_hint_bundle`, `:3028`
`issue_relay_session_token`, `:3116` `signed_traversal_coordination_record`.
`signed_peer_map` and `signed_relay_fleet_bundle` call it **not at all**, which
is the stronger statement CTL-03 makes; the earlier wording contradicted CTL-03.

This does not create an end-to-end bypass; the RSA-0008 containment argument
still holds (the daemon's `check_peer_membership_active` drops a revoked peer).
But RSA-0005's Low rests on "dead API / not currently reachable as a weakening,"
and RSA-0008's Medium rests on a gate that is in fact never active. Both premises
are false at this baseline. Severity re-rating is an owner decision; this review
records that the premises no longer hold.

Proposed enforcement (review-only — do NOT apply): rewrite or delete the
`is_populated()` doc comment; make the empty-directory fallback explicit and
fail-closed at each caller; and either install the directory in the three CLI
construction sites or make `ControlPlaneCore` refuse to issue without one.

Verification method: a test asserting a production-shaped `ControlPlaneCore`
refuses to name a revoked node in a generated bundle.

---

### POL-07 — `validate_policy_safety` is evadable and context-blind (Low, CONFIRMED)

File: `crates/rustynet-policy/src/lib.rs:369-380`, sole caller `:340`

Confirms **RSA-0006** (Low, open), whose protocol-enumerated evasion reproduces
exactly: three rules `*`/`*`/`{Tcp,Udp,Icmp}`/Allow stage successfully
(`stage_revision` → `Ok(())`) and are operationally equivalent to allow-all.

Two extensions beyond the existing entry, both confirmed:

- **Context-blind.** The check never reads `contexts`, so it cannot distinguish
  a dataplane allow-all from a *service-context* allow-all. The smuggled set
  above returns `Allow` for `NasService` and `LlmService` — the precise blast
  radius the D13 `context_matches` hardening exists to prevent. Relatedly, the
  runbook's stated safety requirement, "Protocol filters must not widen in shared
  subnet-router/shared-exit contexts" (`PolicyRolloutRunbook.md:23`), has **zero**
  code enforcement anywhere.
- **Individually-narrow, jointly-total passes** — and already ships.
  `{src: "user:local", dst: "*", Any, Allow}` passes because `src != "*"`. That
  is verbatim the daemon's live policy (`daemon.rs:4016-4024`).

Two attack ideas were tested and **refuted**: ignoring `contexts` does not widen
what passes (the literal tuple is rejected regardless of contexts), and there is
no "effectively-wildcard selector" — `selector_matches` has no globbing, so no
string other than `"*"` is universal.

Also: `validate_policy_safety` is private with one caller, so no policy reaching
an evaluator by any other route is validated at all; `PolicySet` has no safety
gate whatsoever; and nothing checks that a terminal default-deny exists or
detects `Deny` rules made unreachable by first-match ordering.

---

### POL-08 — the rollback target is mutable and not content-addressed (Low today; High as a design defect, CONFIRMED)

File: `crates/rustynet-policy/src/lib.rs:341`

`stage_revision` does a bare `insert` — no occupancy check, no content hash, no
`RolloutError` variant for a duplicate id. Confirmed sequence: stage `rev-1`
(Tcp) → promote → re-stage `rev-1` (Udp) → `rollback_to("rev-1")` → `Ok`, active
`rev-1`, **content silently replaced**. Line `:342` also silently makes the
re-staged id the canary again.

An operator following the runbook ("Select previous known-good revision ID",
`PolicyRolloutRunbook.md:15-17`) restores the *id* and gets whatever content was
last written under it. Revision ids are not content-addressed: no digest, no
signature binding id→bytes, no immutability, no overwrite audit event.
`ContextualPolicySet` does not even derive `PartialEq`, so no caller could diff
old against new. The safety mechanism's target is writable by anyone who can
stage — per the ledger's own threat framing, a careless or compromised policy
author, i.e. exactly whom the tripwire is for.

Proposed enforcement (review-only — do NOT apply): make revisions immutable —
reject a duplicate id, or content-address revisions by digest and bind the id to
the signed bytes.

---

### POL-09 — `rollback_to` activates never-promoted revisions (Low, CONFIRMED)

File: `crates/rustynet-policy/src/lib.rs:355-362`

The method checks only `contains_key`. It does not require the target to have
ever been active, or ever been a canary. So `stage_revision("rev-evil", …)`
followed directly by `rollback_to("rev-evil")` activates it, bypassing runbook
steps 3-4 ("Promote staged revision to canary. Observe canary metrics and audit
events") entirely — under a method name that reads as a safety action.

Also confirmed: `rollback_to` (`:360`) and `stage_revision` (`:342`) both
silently discard an in-flight canary with no error or signal; neither method
takes an actor or timestamp nor emits an event, against
`PolicyRolloutRunbook.md:24` ("Rollout and rollback actions must be audited with
actor identity and timestamp").

One concern was **refuted**: `active_revision` can never name an absent revision
— `promote_canary` only copies `canary_revision`, whose sole writer always
`insert`s the same id, and `rollback_to` gate-checks membership. Worth noting
this is an *emergent* invariant, unpinned by any test, that would break silently
the moment an eviction/GC method is added (which `revisions`, growing unbounded,
eventually needs). `promote_canary` with no canary correctly errors (`:347-349`),
though the variant is misnamed `UnknownRevision` rather than a `NoCanary`.

---

### POL-10 — `PolicyRolloutController` is decorative (Low, doc divergence, CONFIRMED)

File: `crates/rustynet-policy/src/lib.rs:328-367`

Confirms **DA-37**, adding the structural reason. All three fields are private
(`:329-331`) and the only accessor is `active_revision() -> Option<&str>`
(`:364-366`) — the *id string*. There is no `active_policy()`, no `revisions()`,
no canary getter, no `Deref`, no public field. The stored `ContextualPolicySet`
values are **write-only**: once inserted at `:341` no code, in-crate or out, can
ever read them back.

Verified zero references to `PolicyRolloutController` / `stage_revision` /
`promote_canary` / `rollback_to` outside this crate's own tests and prose docs.
The daemon's enforcement policy is a hardcoded literal (`daemon.rs:4016-4024`)
never sourced from a revision. So `promote_canary` and `rollback_to` mutate a
`String` no evaluator consults, and no traffic splitting exists — "observe canary
metrics" is unimplementable against this type.

Practical consequence: POL-07, POL-08, and POL-09 are unexploitable in
production today and are latent traps that fire the moment anyone wires this up.

---

### POL-11 — scope key format mismatch (Low, latent, CONFIRMED)

Policy-side selectors are prefixed — `node:laptop-1`, `group:family`
(`lib.rs:292-296`; `service_exposure.rs:266-267` builds `node:{id}`) — but the
gateway keys scopes by the **bare** node id (`llm-gateway/src/main.rs:291`,
`scopes.get(node_id)`, ids written bare at `service_access_state.rs:132`).
Separately, the gateway parses `models=` / `quota=` / `rate=` (`main.rs:256`,
`:264`, `:266`) while the CLI's operator record emits `peer=node:<id>` with keys
`max_tokens_per_window=` / `max_requests_per_minute=` (`llm_cli.rs:96-107`).
Neither the selector prefix nor the key names line up, and no code converts
between the forms.

Dormant only because production never populates scopes (POL-05.1). The moment
scope distribution is implemented per the documented format, every scope line
silently fails to match → `None` → unrestricted. **INFERENCE** on the
consequence; each individual link is confirmed by reading.

---

### POL-12 — `scope_for` doc claims specificity tiering the code lacks (Low, CONFIRMED)

File: `crates/rustynet-policy/src/lib.rs:292-296` vs `:307-318`

The struct doc claims "an exact peer selector (e.g. `node:laptop-1`) wins over a
group selector." The code iterates **caller-supplied** order and returns the
first entry match. There is no prefix parsing, ranking, or tier concept
anywhere. Confirmed with the crate's own fixtures — same table, same peer:

- `scope_for(["node:laptop-1", "group:family"])` → node scope, `permits("big") == false`
- `scope_for(["group:family", "node:laptop-1"])` → group scope, `permits("big") == **true**`

Wider privilege chosen purely by argument order. The hazard is not exotic: a
`BTreeSet` or sorted `Vec` of selectors produces the escalating order **by
default**, since `"group:" < "node:"` lexicographically.

The inline doc at `:304-306` ("in decreasing specificity") is accurate — the
struct-level comment is the overstatement. The test at `:1067-1099` does not
catch this despite its name: it varies `policy.entries` order, never
`peer_selectors` order, which is the thing that actually decides. Aggravating:
`scope_for` has zero callers outside its own tests; the real consumer does a flat
`BTreeMap` lookup with no tiering, so `group:`-scoped restrictions could never
apply even if scopes were populated. The first-match design also never
*intersects* scopes, which is what a narrowing-only control should do.

---

### POL-13 — no fuzz coverage for the policy engine (Low, process)

`fuzz/fuzz_targets/` contains `ipc_parse_command.rs`,
`membership_decode_signed_update.rs`, `membership_decode_state.rs`. None
exercise `selector_matches`, `selector_membership_allowed`, or any `evaluate*`
path.

A property target asserting **"a canonical selector and any whitespace/case/
prefix mutation of it must not differ in `Decision`"** would have caught POL-01,
POL-02, and POL-03 mechanically. This is the highest-leverage process fix here,
because the whole POL-01 class is exactly what a differential fuzzer finds and
example-based tests miss.

---

### POL-14 — adjacent: two daemon ACL results discarded (Medium, CONFIRMED)

Outside the reviewed crate but directly downstream of it, two
`Phase10Controller` ACL results are dropped:

- `crates/rustynetd/src/daemon.rs:7554` — `let _ = self.controller.set_exit_node(node_id, "user:local", Protocol::Any);` (bootstrap exit restore)
- `crates/rustynetd/src/daemon.rs:7964` — `let _ = self.controller.ensure_lan_route_allowed(RouteGrantRequest { … });` (`IpcCommand::LanAccessOn`)

The RSA-0007 fix that routed `phase10.rs:5431`/`:5507` through
`evaluate_with_membership` is therefore load-bearing only where the `Result` is
consumed — e.g. `daemon.rs:7925` (`ExitNodeSelect`), which does match on it and
additionally pre-checks `node_status == Active` at `:7916`. Flagged for the
owner of `rustynetd`; not triaged here.

## 3. Defences that hold — verified, for the record

Adversarial review is only credible if it also reports what resisted attack.
Each of these was probed and held:

1. **Service-context isolation is correct and is the strongest code in the file.**
   `context_matches` (`:386-397`) returns `!candidate.is_service_context()` for
   the empty-`contexts` legacy form, so a pre-D13 wildcard-context rule can never
   grant `NasService`/`LlmService`. Probed a `*`/`*`/`Any`/Allow/`contexts: []`
   rule against both service contexts: `Deny`. No path to a service context
   without a rule naming it. This is **required** by
   `SecurityMinimumBar.md:560-566` (E2) and is not a prohibited legacy branch —
   it is a deny-widening compatibility rule with no weaker fallback.
2. **Default-deny holds in all four `evaluate*` paths** (`:149`, `:181`, `:221`, `:256`).
3. **The membership gate runs before rule matching** (`:157-159`, `:229-231`), so
   a revoked node loses even under a wildcard `Allow`.
4. **Unresolvable non-`node:` selectors fail closed** (`:419-427`) — both unset
   and explicitly-empty member lists deny.
5. **Trailing whitespace fails closed** (see POL-01) — the prefix still matches,
   so the gate runs and the unknown id denies.
6. **`"node:"` with an empty id denies** — `node_status("")` is `Unknown`.
   (Minor caveat, Low: `set_node_status` (`:90-92`) does not validate ids, so
   registering `("", Active)` would make `node:` resolve Active. Requires write
   access to the directory.)
7. **`promote_canary` with no canary errors** rather than promoting nothing (`:347-349`).
8. **Zero external dependencies**, `#![forbid(unsafe_code)]`, no backend leakage —
   the crate honours its transport-agnostic boundary rule.

## 4. Notable observation — the D13 service path is unreachable in a shipped daemon

Recorded because it materially affects how POL-05, POL-11, and POL-12 should be
prioritized. The daemon's production `ContextualPolicySet` is hardcoded
(`daemon.rs:4016-4024`) to a single rule whose `contexts` are `[Mesh, SharedExit]`,
and the same object is passed to `Phase10Controller::new` (`:4053`) and
`derive_service_access_snapshot` (`:4527`). Because that rule names no service
context, and `context_matches` correctly refuses to let a non-naming rule match
one, `evaluate_service_access` returns `Deny` for every peer, so `grants.v1` is
always empty and the NAS/LLM gateways are unconditionally deny-all.

This direction is **fail-closed, so it is not a vulnerability.** But it means the
entire D13 service-authorization path — including the scope enforcement and quota
limiters in `enforce.rs` — is unreachable in a shipped daemon. Any triage that
treats POL-05 as urgent should first confirm whether D13 is intended to be live.
**INFERENCE** on "always empty in production"; every individual link is confirmed
by reading.

## 5. Suggested triage order

1. **POL-13** — add the differential selector fuzz target. Cheapest, and
   mechanically covers the POL-01/02/03 class rather than one instance of it.
2. **POL-01** — invert the selector default to parse-and-deny. Highest-severity
   new finding; the fix is contained within this crate.
3. **POL-06** — correct the doc comment and re-examine the RSA-0005 / RSA-0008
   severity premises, both of which are false at this baseline.
4. **POL-14 / POL-02** — owner of `rustynetd`: stop discarding the two ACL
   `Result`s; reconsider `user:local` as the `src` for remote-peer decisions.
5. **POL-05 / POL-11 / POL-12** — gate behind a decision on whether D13 is meant
   to be live (§4). If it is, the scope table must fail closed before it is
   populated, not after.
6. **POL-07 / POL-08 / POL-09 / POL-10** — resolve together, as one decision:
   either wire `PolicyRolloutController` up properly (immutable content-addressed
   revisions, an accessor, real canary evaluation, audit events) or delete it and
   the runbook that describes it. Leaving it half-present is what makes the other
   three latent traps.

## 6. Reproduction

```bash
git -C ~/Desktop/rustynet rev-parse --short HEAD   # expect 22847b12
cargo test -p rustynet-policy                       # expect 21/21 green
```

The probe used for every CONFIRMED result: copy
`crates/rustynet-policy/src/lib.rs` to a scratch path **outside** the repo,
strip its `#[cfg(test)]` module, append a `main` exercising the tables above, and
build with `rustc --edition 2021`. The crate's zero-dependency design makes this
a two-command reproduction and is worth preserving for exactly this reason.

---

# Part II — `rustynet-crypto` (key custody, key envelopes, signing)

Crate baseline: `crates/rustynet-crypto/src/lib.rs`, 2708 lines; deps are vetted primitives only (argon2, chacha20poly1305, ed25519-dalek, sha2, subtle, zeroize) plus platform keystores; `cargo test -p rustynet-crypto` **38/38 green** at this commit
Scope: `KeyCustodyManager` + `OsStoreFallbackPolicy`, the Argon2id/XChaCha20-Poly1305 key envelope and its on-disk framing, `aead_seal`/`aead_open`, `AlgorithmPolicy`/`CompatibilityException`, `SigningProviderPolicy` + provider attestation, `SecretKey`/`NodeKeyPair` hygiene, and `validate_key_custody_permissions`; plus the production call sites in `rustynetd/src/key_material.rs`, `rustynet-cli`, `rustynet-nas`, and `rustynet-windows-trust-cli`
Out of scope for this part: the vendored boringtun Noise implementation, and the macOS `security` CLI argv exposure already tracked as RSA-0004

> ## ✅ CRY-06, CRY-10, CRY-11 and CRY-12 are FIXED — `49a5652a`, corrections in `0742cb0c`
>
> Mutation-verified: CRY-06 (full-key compare, plus the all-zeros branch's one
> decisive case) and CRY-11 (source-pinned) are caught. **CRY-12's test does not
> discriminate on a 64-bit host** — `ciphertext_len` comes from a `u32`, so the
> addition cannot overflow a 64-bit `usize`; the overflow is reachable only where
> `usize` is 32-bit, and the test's own doc comment says so.
>
> CRY-06 also **broke a production binary** on landing — see the correction in the
> finding below. Still open here: CRY-01, CRY-02, CRY-03, CRY-04, CRY-05, CRY-07,
> CRY-08, CRY-09.

## 7. Prior coverage — this crate is already well audited

**Read this before treating anything below as new.** Unlike Part I's area, this
crate has an existing audit row (`SecurityAuditLedger_2026-06-18.md:209`) with
four findings, and I checked them *before* writing:

| This review | Existing entry | Relationship |
|---|---|---|
| CRY-04 | **RSA-0001** (open, **DEFERRED 2026-06-24**) | Confirms exactly; adds line-drift correction. **Not new** |
| CRY-05 | **RSA-0002** (Medium, open) | Confirms; adds the unused-error-variant and write-path details |
| CRY-08 | **RSA-0003** (**ASSESSED 2026-06-24, keep as-is**) | Confirms the repo's decision is correct; adds only a readability note |
| — | RSA-0004 (macOS `-A` keychain, open) | Not re-reviewed; out of scope |
| CRY-01, CRY-02, CRY-03, CRY-06, CRY-07, CRY-09, CRY-10, CRY-11 | none found | **New** |

Searched `documents/` for `OsStoreFallbackPolicy`, `AllowEncryptedFileFallback`,
`fallback_passphrase`, Argon2 parameters, `temp_path_for`, `provider_attestation`,
and pub/priv correspondence in `from_raw`. Only `OsStoreFallbackPolicy` had a hit
(inside RSA-0002's reachability note), and the `from_raw` hits are unrelated
(`from_raw_fd` / `from_raw_parts` in other crates).

Two honest calibrations found during that check, both of which stopped me
overstating a finding:

- RSA-0002's note already records that the daemon's primary WG-key path uses
  `RequireOsSecureStore` + DPAPI, so "the fallback policy defaults to permissive"
  is **not** by itself a live defect on macOS/Windows. CRY-01 and CRY-02 are
  narrowed accordingly.
- RSA-0001 is not an oversight but a **recorded deliberate deferral**: "high-blast-radius
  key-load change; the safe fix needs an on-disk-framing migration + the upgrade
  path can't be validated without a lab, so deferred rather than risk a fleet
  key-load regression — AEAD preserves confidentiality meanwhile"
  (`SecurityRemediationPlan_2026-06-19.md:92`). CRY-04 does not re-argue it.

As in Part I, the crate's suite is green (38/38), so every finding is a coverage
gap rather than a regression.

## 8. Findings

| ID | Finding | Severity | New? |
|---|---|---|---|
| CRY-01 | `RequireOsSecureStore` is a **load-side-only** guarantee — the encrypted key file is written unconditionally on every platform | High | **New** |
| CRY-02 | Linux has no strict-policy arm, and Linux's OS store fails to `OsStoreUnavailable` in exactly the headless case — so the file fallback is the *normal* path, silently | Medium-High | **New** |
| CRY-03 | Passphrase floor is 16 chars with no entropy requirement; Argon2 params are not stored in the blob | Medium | **New** |
| CRY-04 | v0/v1 framing ambiguity makes ~99.6% of legacy v0 blobs undecodable | Medium (availability) | RSA-0001 |
| CRY-05 | Windows permission validation is an `Ok(())` no-op, on both read and write | Medium | RSA-0002 |
| CRY-06 | `NodeKeyPair::from_raw` never checks that the public key corresponds to the private key | Medium-if-used | **New** |
| CRY-07 | Unix permission validator checks modes but never ownership (uid); plus a narrow TOCTOU | Low | **New** |
| CRY-08 | `with_exceptions` rejects all non-empty lists, making the denylist loop dead code | Low (quality) | RSA-0003 |
| CRY-09 | Three security controls are entirely unwired — and `release_manifest.rs` builds exactly the provider config the default policy forbids | Medium | **New** |
| CRY-10 | `aead_seal` doc claims OS-secure key custody; production reads a raw key from a plain file | Low (doc) | **New** |
| CRY-11 | `Ed25519SigningProvider::from_seed` never zeroizes its by-value seed parameter | Info | **New** |
| CRY-12 | Blob length arithmetic is unchecked — a debug-build panic if the planned armv7 target lands | Low | **New** |

---

### CRY-01 — `RequireOsSecureStore` protects only the load path; the key file is written unconditionally (High, CONFIRMED)

Files: `crates/rustynetd/src/key_material.rs:562-580`, `:596-599`; `crates/rustynet-crypto/src/lib.rs:399-447`

`encrypt_private_key_with_passphrase` stores the key through the custody manager
and then, with **no `cfg` and no branch on the returned backend**, also writes a
passphrase-encrypted copy to disk (`key_material.rs:572-579`). Verified by
reading; the code even explains itself:

> `// Keep the configured encrypted-key path materialized on disk for service prechecks and`
> `// deterministic bootstrap across hosts, even when the custody backend also stores by key-id.`

So this is **deliberate, not an oversight**, and the finding is not "someone
forgot a branch." The finding is that the guarantee is narrower than its name
conveys: `OsStoreFallbackPolicy::RequireOsSecureStore` removes the file from the
*load* path only (`lib.rs:430-436`). It is a "don't read from disk" guarantee,
never a "no key on disk" guarantee. On macOS and Windows — the two platforms that
*do* set the strict policy (`key_material.rs:596-599`) — a passphrase-encrypted
copy of the WireGuard private key is on disk regardless.

Why that matters is CRY-03: the at-rest strength of that copy is
Argon2id-with-default-parameters over an operator string whose only enforced
property is length ≥ 16. So the effective at-rest protection of the WG private
key is not the OS keystore — it is the weaker of the two, and the file copy is
the weaker one. Reached in production from `rustynetd/src/daemon.rs:2998`, `:3910`,
`:3959`, `:9451`, `:10830`, `:19805`, `:19985`, plus
`key_material.rs:1020`/`:1077`.

Proposed enforcement (review-only — do NOT apply): if the on-disk copy is
genuinely required for service prechecks and bootstrap, say so in the type — e.g.
rename the policy to reflect load-side semantics, or add an explicit
`materialize_disk_backup: bool` so the decision is visible at the call site
rather than implied by a comment. If it is not required when the OS store
succeeded, gate it on the returned `KeyCustodyBackend`.

Verification method: a test asserting that under `RequireOsSecureStore` with a
healthy OS store, no key file is created (or, if it must be, that its existence
is an explicit documented decision with a strength floor attached).

---

### CRY-02 — on Linux the encrypted-file fallback is the normal path, silently (Medium-High, CONFIRMED)

Files: `crates/rustynetd/src/key_material.rs:596-599`, `:564`; `crates/rustynet-crypto/src/lib.rs:905-949`, `:406`, `:430`

`key_custody_manager` has a `#[cfg(target_os = "macos")]` arm and a
`#[cfg(target_os = "windows")]` arm applying `RequireOsSecureStore`. **There is no
Linux arm**, so Linux keeps `OsStoreFallbackPolicy::default()` —
`AllowEncryptedFileFallback` (`lib.rs:357-362`).

That default matters more on Linux than anywhere else, because Linux's "OS secure
store" is `secret-tool` shelling out (`lib.rs:905-949`), and **every** failure
mode — binary absent, no D-Bus session, locked collection, nonzero exit — maps to
`CryptoError::OsStoreUnavailable` (`:915`, `:916`, `:921`, `:923`, `:927`, `:937`),
which is precisely the variant that triggers the file fallback (`:406`, `:430`).
A headless `rustynetd` has no Secret Service session, so the **ordinary** Linux
path is the encrypted-file fallback.

It is also silent: `let _backend = manager.store_private_key(...)`
(`key_material.rs:564`) discards the `KeyCustodyBackend` discriminator, so nothing
logs or surfaces which custody tier was actually used. An operator cannot tell
from the outside whether their key is in a keystore or in a file.

Proposed enforcement (review-only — do NOT apply): decide Linux's intended tier
explicitly rather than by omission; and surface the returned
`KeyCustodyBackend` (log at minimum, ideally a health/precheck field) so a
silent downgrade is observable.

---

### CRY-03 — passphrase floor is 16 characters with no entropy requirement, and Argon2 parameters are not stored (Medium, CONFIRMED)

Files: `crates/rustynetd/src/key_material.rs:191-214`; `crates/rustynet-crypto/src/lib.rs:1324`, `:1362`

`parse_passphrase_bytes` enforces exactly one strength property (`:207`):
`if trimmed.len() < 16 { return Err("passphrase must be at least 16 characters") }`.
No entropy estimate, no charset requirement, no dictionary rejection. Verified by
reading: `"aaaaaaaaaaaaaaaa"` is accepted. Combined with CRY-01 (the file always
exists), this string is the effective at-rest security boundary for the WG
private key.

Both encrypt and decrypt use `Argon2::default()` (`lib.rs:1324`, `:1362`).
Verified against the vendored `argon2-0.5.3` source, those defaults are
**Argon2id, version 0x13, m_cost = 19 × 1024 KiB (19 MiB), t_cost = 2,
p_cost = 1**, 32-byte output (`params.rs:42`, `:52`, `:61`, `:76`). To be fair to
the authors: that is exactly the OWASP-recommended Argon2id minimum, so the
choice is defensible and is **not** itself a vulnerability — it is on the low end
for wrapping an at-rest key (19 MiB / 2 passes is the interactive-login bar,
where a key-wrapping KDF can usually afford more), but it clears the bar.

The actual defect is that the **KDF parameters are not recorded in the blob** —
`EncryptedKeyBlob` (`lib.rs:272-278`) carries only `version`, `salt`, `nonce`,
`ciphertext`. Two consequences:

1. There is no way to raise the KDF cost for new blobs without breaking old ones,
   because a reader cannot know which parameters produced a given blob.
2. If the `argon2` crate ever changes its defaults (a minor-version bump could;
   they have moved historically), every existing blob silently becomes
   undecryptable — the same class of failure as CRY-04, arriving through a
   dependency bump rather than a framing bug. Worse, the failure is
   indistinguishable from a wrong passphrase: both surface as
   `DecryptionFailed`, with no diagnostic separating "bad passphrase" from
   "parameters drifted."

This is the opposite of the standard PHC-string approach, where `m`/`t`/`p` travel
with the hash. The `version` byte is a migration lever, but as written both
encrypt and decrypt are pinned to the *ambient crate default* rather than an
explicitly recorded, version-bound parameter set.

Credit where due, and this is a real defence: the passphrase *sources* refuse
insecure defaults. macOS file custody is explicitly disabled in favour of the
System keychain (`key_material.rs:730`), and Linux requires an explicit
`RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH` or systemd `CREDENTIALS_DIRECTORY`,
deliberately refusing to fall back to the configured default path (`:760-765`).
So the passphrase is operator-supplied and never hardcoded or generated — the gap
is only its strength floor.

Proposed enforcement (review-only — do NOT apply): store the Argon2 parameters
(m, t, p, algorithm, version) in the envelope so cost can be raised
migration-safely; and raise the passphrase floor (length plus a minimum-entropy or
generated-passphrase requirement) given that this string, not the OS keystore,
bounds at-rest security.

---

### CRY-04 — v0/v1 framing ambiguity renders legacy blobs undecodable (Medium, availability; confirms **RSA-0001**)

File: `crates/rustynet-crypto/src/lib.rs:1604-1611`, with `:1613-1663`, framing at `:1585-1602`

Confirms RSA-0001 with no new argument. `decode_encrypted_blob` dispatches on
`bytes.len() >= 45 && bytes[0] != 0`. A v0 blob is `[salt:16][nonce:24][len:4][ct]`,
so `bytes[0]` is `salt[0]` — a CSPRNG byte, nonzero 255/256 of the time — and a
32-byte key yields 44+48 = 92 bytes. So a genuine v0 blob is routed to
`decode_encrypted_blob_v1`, which reads its length from `bytes[41..45]` (garbage)
and returns `InvalidLength` (`:1653`).

The direction is worth stating precisely, because it determines the severity:
this **fails closed**. The misparse cannot yield a wrong-key decryption — for a
real v0 blob of length `44+N`, the v1 check requires `44+N == 45+G` where `G` is
the big-endian u32 at `bytes[41..45]`, which in a v0 blob is
`[len[1], len[2], len[3], ct[0]]`, giving `G = ((N & 0xFFFFFF) << 8) | ct[0] >= 256`
for any `N >= 1` — always vastly larger than the required `N-1`. Confirmed by
execution: a brute force over `N ∈ [1, 100000]` × every `ct[0] ∈ [0, 255]` found
**zero** accepting combinations. So the outcome is a daemon that cannot load its
key and fail-closes — an availability and upgrade-compatibility failure, not a
confidentiality bypass. That matches the ledger's own assessment.

One nuance the existing entry does not record, and it sharpens the operator
impact: **the failure is nondeterministic per key file.** The 1/256 of v0 blobs
whose `salt[0]` happens to be `0x00` route to the v0 parser and decode perfectly.
So the symptom is not "all legacy nodes fail after upgrade" but "≈99.6% of legacy
nodes fail, apparently at random" — which is materially harder to diagnose in the
field than a uniform failure, and easy to misattribute to a bad passphrase.

The reverse direction is also fail-closed, verified by execution: flipping
`bytes[0]` to `0` on a v1 blob routes it to the v0 parser, which then reads its
length from `bytes[40..44]` = `[nonce[23], len[0], len[1], len[2]]` — garbage
(1728053248 vs a real 49 in the demo) → `InvalidLength`. Even had the structure
matched, salt and nonce would be shifted by one byte and the empty-AAD path would
face a tag computed over the v1 AAD → `DecryptionFailed`. The crate's own test at
`:1980-1992` already pins that empty-AAD relabelling fails the tag check.

Two contributions only:

- **Line drift for the ledger.** RSA-0001 cites `decode_encrypted_blob` at
  `:1601-1608` and `encode_encrypted_blob` at `:1582-1599`; at this baseline they
  are `:1604-1611` and `:1585-1602`. RSA-0002 cites the non-unix branch at
  `:1712-1717`; it is now `:1715-1720`. Worth refreshing so the entries stay
  greppable.
- **The regression test RSA-0001 asked for still does not exist.** Confirmed
  against the 38 passing tests: there is no test that hand-builds a v0
  `[salt][nonce][len][ct]` blob and asserts it decodes. Given the fix is
  deliberately deferred, adding *only* the failing-or-ignored regression test
  would at least pin the contract without touching the key-load path.

`encode_encrypted_blob`'s v0 branch (`:1586-1592`) is confirmed dead for writes:
`encrypt_private_key_envelope` hardcodes `KEY_ENVELOPE_VERSION = 1` (`:1315`,
`:1346`), and the encoder is private with one caller. So v0 is read-only legacy.

---

### CRY-05 — Windows permission validation is a no-op on both directions (**re-rated High**; confirms **RSA-0002** and **AUDIT-027**)

**Re-rated 2026-07-29 (meta-review).** This was originally mapped only to RSA-0002 (Medium) and rated Medium. The identical defect at the identical location is also **AUDIT-027**, which the repo rates **High** and names in its NO-SHIP list: `SecurityAndQualityAudit_2026-06-10.md:65` ("Windows encrypted-key custody ACL check is a no-op `Ok(())` (RN-33 escalated) | High | Open"), with `:32` listing "wire/fail-close the Windows key-custody ACL (AUDIT-027)" as a before-release item and `:331` recommending *verbatim* what this finding proposes. Rating it Medium while an existing High ship-blocker describes the same lines was an under-call; it is aligned to High here rather than arguing the repo's own rating down.

File: `crates/rustynet-crypto/src/lib.rs:1715-1720`, plus `:1498-1511`, `:1519`, `:1532-1536`

Confirms RSA-0002. The `#[cfg(not(unix))]` branch returns `Ok(())` with
`// Windows ACL validation not yet implemented; defer to OS enforcement.` Two
details to add to the existing entry:

1. **The write side is unprotected too, not just the check.**
   `write_encrypted_key_file`'s permission-tightening block is `#[cfg(unix)]`
   (`:1498-1511`) and `write_atomic_encrypted_key_file` applies `options.mode(_mode)`
   only under `#[cfg(unix)]` (`:1532-1536`), so on Windows the key file is created
   with inherited directory ACLs, never restricted *and* never validated.
2. **The error variant the fix needs already exists, and is not used *here*.**
   `CryptoError::PermissionValidationUnavailable` (`:84`, "permission validation
   unavailable on this platform") is never constructed by
   `validate_key_custody_permissions` — which is exactly what RSA-0002's proposed
   enforcement calls for (`SecurityAuditLedger_2026-06-18.md:869`). The one-line
   fail-closed change is already expressible in the existing type.
   **Corrected in Part VI (WIN-10):** an earlier revision of this finding said the
   variant was "defined but never constructed" anywhere. That was wrong — it *is*
   constructed on the Windows DPAPI path at `:1016` and `:1033`. The claim is
   narrowed to this function; CRY-05's substance is unaffected.

Reachable in production from `rustynet-cli/src/bin/rustynet-windows-trust-cli.rs:325`
and `:375`, whose policy helper is a bare default (`:385-387`) — and per RSA-0002's
own note, the most sensitive instance is the **trust signing key**.

---

### CRY-06 — `NodeKeyPair::from_raw` never verifies pub/priv correspondence (Medium-if-used, CONFIRMED by the crate's own test)

File: `crates/rustynet-crypto/src/lib.rs:137-154`

`from_raw` validates only `is_all_zeros` on each half. The public key is never
derived from, or compared against, the private key, so the struct can hold an
inconsistent pair. The crate's own passing test demonstrates it:
`accepts_nonzero_key_material` (`:1860-1864`) constructs
`from_raw([7; 32], [9; 32])` and succeeds — `[7u8; 32]` is certainly not the
ed25519 public key for seed `[9u8; 32]`.

Consequence if wired: publishing `public_key` while signing with `private_key`
produces signatures nobody can verify (availability), or binds an identity to a
key the holder does not control. The all-zeros check is largely security theatre
— it rejects one degenerate encoding while other small-order and non-canonical
encodings pass, and for a dalek seed any nonzero 32 bytes is "valid."

Severity was originally held at *Medium-if-used* on the grounds that there is "no
non-test consumer" of `from_raw`. **That was wrong — corrected 2026-07-30.**
`rustynet-control/src/main.rs:37` is a production caller, and it passed a
*non-corresponding* pair, so when the fix landed the binary failed at startup with
`weak key material` (repaired in `e3adf9c1` by deriving the public key). The lesson
is procedural: a finding that rests on "no production caller" must have that grep
re-run at fix time, because every other gate missed it — fmt, clippy, a workspace
check and ~2,400 tests were all green while a shipped binary was broken.
`cargo check` compiles a binary but never runs it. The correct shape already exists in the same
file: `Ed25519SigningProvider::from_seed` (`:1128-1142`) takes only the seed and
derives the verifying key, making mismatch structurally impossible.

Proposed enforcement (review-only — do NOT apply): either delete `NodeKeyPair::from_raw`,
or make it accept a seed and derive the public key, following `from_seed`.

---

### CRY-07 — unix permission validator checks modes but not ownership (Low, CONFIRMED)

File: `crates/rustynet-crypto/src/lib.rs:1685-1713`

The unix path is genuinely strict about *modes* — it rejects symlinks and wrong
types on both directory and file via `symlink_metadata` (`:1689-1697`) and
requires exact `0o700` / `0o600` (`:1702-1709`). But it never compares the owning
`uid` against the effective user, so an **attacker-owned** directory and file with
correct modes validate successfully.

This matters only where an attacker can influence `fallback_directory`, which
in-crate callers do not — hence Low. It is worth recording because the repo
already applies the stronger pattern elsewhere: `ops_peer_store.rs` is audited as
PASS specifically for having a "uid check" alongside 0700/0600
(`SecurityAuditLedger_2026-06-18.md:490`). This validator is the weaker of two
sibling implementations.

Also present and correctly rated as theoretical: a TOCTOU window between
`symlink_metadata`, the later `metadata` calls (`:1699-1700`), and the actual
`std::fs::read` in `read_encrypted_key_file` (`:1579-1580`). Exploiting it needs
write access inside a directory the same function requires to be `0700`, i.e. the
attacker is already the owner or root. Hardening would be an `O_NOFOLLOW` open
plus `fstat` on the handle.

---

### CRY-08 — `with_exceptions` rejects every non-empty list, making the denylist loop dead code (Low, quality; confirms **RSA-0003**)

File: `crates/rustynet-crypto/src/lib.rs:188-199`

Line `:189` returns `Err(CryptoError::InvalidException)` for any non-empty
exception list, so the per-exception denylist loop at `:192-196` is unreachable.

**The repo's existing decision is correct and this review does not challenge it.**
RSA-0003 was ASSESSED 2026-06-24 as *keep as-is*, on the grounds that the
inverted guard is currently protective — it denies all exceptions, the
strictest-secure outcome — and that "repairing" it would make it fail-open
(`SecurityRemediationPlan_2026-06-19.md:92`). Independently verified here: the
exception path in `validate` (`:211-219`) would otherwise be the one route by
which a *denylisted* algorithm (Md5, Sha1, Rc4, Des, TripleDes, BlowfishCbc,
WeakDh) could return `Ok(())`, and it is unreachable because `exceptions` is
private and no non-empty list can be constructed.

The only residual point is readability: a dead validation loop plus a live
`CompatibilityException` type reads as a working feature, which invites a future
contributor to "fix" the guard and reintroduce the downgrade path. A comment
stating that exceptions are administratively disabled by design would prevent
that, at zero security cost.

---

### CRY-09 — three security controls are entirely unwired, and one production path builds exactly what the default policy forbids (Medium, CONFIRMED)

Files: `crates/rustynet-crypto/src/lib.rs:183-233`, `:1088-1194`, `:1195-1236`; `crates/rustynet-cli/src/release_manifest.rs:114`

Three separate controls in this crate have **zero production callers**:

1. `AlgorithmPolicy` / `CompatibilityException` / `validate` — every call site is
   a test (`lib.rs:1868`-`:1911`; `rustynet-control/src/lib.rs:4697`, `:4703-4704`,
   inside that crate's `#[cfg(test)]` module). `validate_now` (`:228`) has **no
   callers at all**, test or otherwise. So the algorithm allowlist/denylist —
   which is correct and complete (§9.1) — governs nothing at runtime.
2. `SigningProviderPolicy` / `validate_signing_provider_policy` — only
   `lib.rs:2216` (test).
3. `create_provider_attestation` / `verify_provider_attestation` — only tests
   (`lib.rs:2236`-`:2264`).

The sharpest part is the interaction. `SigningProviderPolicy::default()` is
strict — `require_hardware_backed_primary: true`, `allow_local_fallback: false`
(`:1096-1097`) — and the one production consumer of the provider abstraction
constructs precisely what that default forbids, without calling the validator
(`release_manifest.rs:114`):

```rust
let provider =
    Ed25519SigningProvider::from_seed(SigningProviderKind::LocalEncryptedFile, key_id, seed);
```

It also signs via `SigningProvider::sign_attestation` directly, bypassing
`create_provider_attestation` and therefore the provider-kind and key-id binding
checks at `:1221-1226`. So the policy that would reject a local-file signing key
for release manifests exists, defaults to rejecting it, and is never consulted.

Proposed enforcement (review-only — do NOT apply): either wire
`validate_signing_provider_policy` into `release_manifest.rs` and accept an
explicit documented exception for local-file signing, or delete the three unwired
controls. Leaving a strict-by-default policy unconsulted is the failure mode Part I
records as POL-10 — a control that reads as protection and provides none.

---

### CRY-10 — `aead_seal` doc claims OS-secure key custody; production reads a raw key from a plain file (Low, doc, CONFIRMED)

Files: `crates/rustynet-crypto/src/lib.rs:1413-1414`; `crates/rustynet-nas/src/main.rs:98`, `:198-243`

The doc comment states the 32-byte key "comes from OS-secure custody (keychain /
DPAPI / `LoadCredentialEncrypted`), NOT from a passphrase KDF." The actual
production path is `load_at_rest_key`, which reads a raw 32-byte key from
`--at-rest-key-file` (validated as a regular file, `mode & 0o077 == 0`, exactly 32
bytes) or `--at-rest-key-credential`. Only the systemd-credential variant
plausibly involves `LoadCredentialEncrypted`; the file variant is a plain 0600
file with no keychain or DPAPI involvement on any platform.

The AEAD construction itself is sound and is credited in §9. This is a doc
accuracy issue: a reader auditing NAS at-rest encryption would conclude the key is
hardware/OS-protected when it need not be.

---

### CRY-11 — `from_seed` does not zeroize its by-value seed parameter (Info, CONFIRMED)

File: `crates/rustynet-crypto/src/lib.rs:1129-1142`

`Ed25519SigningProvider::from_seed` takes `seed: [u8; 32]` by value and never
zeroizes that parameter copy after `SigningKey::from_bytes` copies out of it, so a
transient stack copy of the signing seed survives the call. The resulting
`SigningKey` *is* zeroized on drop (ed25519-dalek 2.x `ZeroizeOnDrop`, `zeroize`
being a default feature — confirmed in the vendored manifest), so this is the
parameter copy only. Recorded for completeness rather than as a practical risk.

### CRY-12 — blob length arithmetic is unchecked, which becomes a debug-build panic if 32-bit ARM lands (Low, forward-looking, CONFIRMED)

File: `crates/rustynet-crypto/src/lib.rs:1624-1625`, `:1652-1653`

Both parsers do `u32::from_be_bytes(...) as usize` and then compare
`bytes.len() != 44 + ciphertext_len` / `!= 45 + ciphertext_len`.

On every currently-shipping target this is a non-issue: `usize` is 64-bit, so
`45 + u32::MAX ≈ 4.29e9` cannot overflow and the equality against the real
(small) buffer length simply fails → `InvalidLength`. Verified.

On a **32-bit** target it is not benign. With an attacker-declared
`ciphertext_len` near `u32::MAX`, `44 + ciphertext_len` overflows `usize`: a
**debug build panics** ("attempt to add with overflow") while merely *parsing a
malformed key file*, and a release build wraps (e.g. `45 + 0xFFFFFFF5 ≡ 34 mod 2^32`,
executed) — though the wrapped sum then mismatches the real length, so no
malformed blob passes. There is no allocation hazard in either case: the parsers
slice the real buffer (`bytes[44..]` / `bytes[45..]`) and only after the exact-length
equality passes, so no capacity is ever reserved from the declared length.

This is recorded because 32-bit ARM is an explicit product direction, not
speculation: `documents/Requirements.md:141-143` names
`armv7-unknown-linux-gnueabihf` for "low-power relay and exit/blind_exit nodes
(e.g. Raspberry Pi Zero 2 W class hardware)", and that same entry states its
blockers are UNVERIFIED and should be re-derived. If armv7 is attempted, this is
one more thing to fix, and it is a two-character fix now (`checked_add` /
`saturating_add`) versus a debug-build DoS later. Exploitation requires write
access to the key file, which already implies serious compromise — hence Low.

## 9. Defences that hold — verified, for the record

This crate resisted most of what was aimed at it. Each item below was probed and
held:

1. **Algorithm coverage is complete with a terminal deny.** `CryptoAlgorithm` has
   18 variants; the allowlist (`:234-249`) covers 11 and the denylist (`:251-262`)
   covers 7 — no variant is in neither. More robustly, `validate` ends in an
   unconditional `Err(CryptoError::DeniedAlgorithm)` (`:225`), so even a *future*
   variant added to neither list is denied. **No default-allow defect.** Ordering
   is also right: the allowlist is checked first, and an exception is consulted
   only inside the denylisted branch, so an exception can never bless a
   neither-listed algorithm.
2. **Clock failure fails closed.** `unix_now` (`:264-270`) maps errors to
   `InvalidClock`, and `validate_now` (`:228-231`) propagates with `?` — the
   expiry check is never skipped. The only other `SystemTime` use
   (`temp_path_for`, `:1563-1571`) does `unwrap_or(0)` but feeds a temp-file name
   suffix, where a collision hits `create_new(true)` (`:1531`) and fails.
3. **`SecretKey` hygiene is correct.** `Drop` (`:61-68`) really zeroizes; `Debug`
   (`:55-59`) prints `SecretKey(REDACTED)`; the type has **no derives at all**
   (`:43`) so it is not `Clone`, not `Copy`, and `==` on it will not compile;
   `ct_eq` (`:50-52`) delegates to `subtle::ConstantTimeEq`. No `==` on secret
   bytes anywhere in the crate.
4. **Attestation verification is real, not field theatre.**
   `verify_provider_attestation` (`:1216-1235`) ends in
   `provider.verify_attestation`, which for Ed25519 is `verify_strict`
   (`:1173-1175`) — strict RFC-8032/ZIP-215, rejecting non-canonical S and
   small-order components — and the crate has an executed regression for malleable
   signatures. A forged attestation cannot pass without the signing key. (Trust
   root is the caller-supplied provider's verifying key; there is no chain, which
   is a contract observation, not a defect.)
5. **CSPRNG handling fails closed, and is enforced by a test.**
   `try_generate_key_custody_material` (`:1288-1299`) refuses to degrade to
   `ThreadRng`, with a comment explaining why. The panicking legacy variant
   (`:1264-1274`) has **zero production callers** — all three are in `#[cfg(test)]`
   — and there is a source-scanning regression test (`:1831-1851`) that keeps
   `write_encrypted_key_file` on the fallible path.
6. **AEAD associated data genuinely binds location.** All eight `aead_seal`/`aead_open`
   sites in `rustynet-nas/src/store.rs` pass an AAD that fully determines the
   blob's location: objects use `nas:object:{peer_id}:{hash}` (`:375`, `:397`),
   snapshots `nas:snapshot:{peer_id}:{snapshot_id}`, quotas `nas:quota:{peer_id}`,
   each matching its real path granularity. Object reads are additionally
   hash-checked after open (`:399-405`). The one constant AAD (`nas:keycheck`) is
   correct by design — a single fixed sentinel file with no per-location
   component.
7. **`hex_decode` is correct for its use** (`:1245-1262`): rejects empty and
   odd-length input, rejects non-hex per nibble, accepts both cases. Not
   constant-time, but it decodes a *signature* — public material — so timing
   reveals nothing useful.
8. **Passphrase sources refuse insecure defaults** — see CRY-03: macOS file
   custody disabled in favour of the System keychain; Linux requires an explicit
   credential path and refuses the default.
9. **Dependencies are vetted primitives only**, no custom crypto, matching the
   `#3` architecture constraint and the existing PASS on
   `rustynet-crypto/Cargo.toml`.
10. **No salt or nonce reuse on any write path.** `write_encrypted_key_file`
    mints fresh material via `try_generate_key_custody_material()` (`:1481`) on
    every call and passes it straight into the envelope;
    `write_atomic_encrypted_key_file` touches no crypto state, only already-encoded
    bytes. There is no stored-salt/stored-nonce path, so a re-encryption always
    draws a new 192-bit nonce — the specific catastrophic failure mode for
    XChaCha20-Poly1305 is structurally absent. Nonce reuse is only reachable by
    calling the lower-level `encrypt_private_key_envelope` directly with a fixed
    nonce, which the file API never does.
11. **The atomic write is properly hardened on unix.** The temp file is opened
    `create_new(true)` (O_CREAT|O_EXCL) with `.mode(policy.required_file_mode)`
    applied **at creation** (`:1531-1536`), so 0o600 is set atomically and there is
    no world-readable window (and it is umask-safe, since umask only clears bits).
    O_EXCL means a predictable temp name (`:1569`) is at worst a squatting DoS,
    never a symlink-follow write. Durability ordering is correct: `sync_all()` on
    the file before rename (`:1543`), then the parent directory is opened and
    `sync_all()`'d after rename (`:1557-1558`). The temp file is removed on the
    write, sync, and rename error paths (`:1540`, `:1544`, `:1548`). Only residual:
    a crash between create and rename leaves an empty 0o600 temp with no GC.
12. **`read_encrypted_key_file` validates before reading.** Permission validation
    (`:1579`) runs *before* `std::fs::read` (`:1580`) and before decode/decrypt —
    check-before-read, not check-after-read. (The residual path-based TOCTOU is
    CRY-07.)
13. **The v1 version byte is effectively authenticated.** The v1 AAD is built from
    `blob.version` rather than a literal `1` (`:1382`), but that arm is reached only
    through `match blob.version { 1 => ... }` (`:1375`), so the value is provably
    `1` there — functionally identical. Versions `2..=255` hit
    `_ => DeniedAlgorithm` (`:1392-1395`). An attacker rewriting byte 0 achieves
    only denial of service, and the crate pins both outcomes with tests
    (`:1968-1978` for the deny, `:1980-1992` for the tag failure). No
    version-confusion or AAD-substitution attack exists.

## 10. Suggested triage order for Part II

1. **CRY-01 + CRY-03 together** — they compose into the one finding that changes
   the threat model: the WG private key is always on disk, protected by a
   possibly-trivial passphrase under unrecorded KDF parameters. Either the disk
   copy or the passphrase floor has to change; deciding requires knowing whether
   the "service prechecks and deterministic bootstrap" requirement is real.
2. **CRY-02** — cheap and self-contained: give Linux an explicit policy arm and
   stop discarding the `KeyCustodyBackend`.
3. **CRY-09** — decide wire-or-delete for the three unwired controls; at minimum
   stop `release_manifest.rs` from silently contradicting the strict default.
4. **CRY-04** — the fix stays deferred per the recorded 2026-06-24 decision, but
   the regression test it asked for can land independently and should.
5. **CRY-05** — one-line fail-closed change using the already-defined
   `PermissionValidationUnavailable`, per RSA-0002's own proposal.
6. **CRY-06** — derive-or-delete `from_raw` while it is still dead API and the
   change is free.
7. **CRY-07, CRY-08, CRY-10, CRY-11** — low-cost hygiene; CRY-08 is a comment, not
   a code change.
8. **CRY-12** — fold into whatever work first attempts the armv7 cross-build that
   `Requirements.md:141-143` calls for; it is a `checked_add` today and a
   debug-build DoS after that target lands.

## 11. Reproduction (Part II)

```bash
git -C ~/Desktop/rustynet rev-parse --short HEAD   # expect 22847b12
cargo test -p rustynet-crypto                      # expect 38/38 green
```

Unlike Part I, this crate has real dependencies, so the standalone-`rustc` probe
does not apply to the whole crate. The blob framing functions
(`encode_encrypted_blob` / `decode_encrypted_blob*`) are pure byte manipulation
and **can** be copied out and compiled standalone, which is how CRY-04's
arithmetic was checked. Crate-level runs used a `CARGO_TARGET_DIR` outside the
repository to avoid contending with concurrent workers' builds.

---

# Part III — macOS `pf` privileged-helper boundary (killswitch rule regeneration)

Crate baseline: `crates/rustynetd/src/macos_pf_load_spec.rs`, 1061 lines, added by `fd1b50d1` ("macos pf: close the pfctl -f privileged boundary via rule regeneration")
Scope: the `macos-pf-load` privileged builtin end to end — `MacosPfLoadSpec` encode/decode across the daemon→root boundary, anchor derivation, the three rule renderers it drives (`render_macos_killswitch_pf_rules`, `build_macos_blind_exit_pf_rules`, `build_macos_exit_nat_pf_rules`), the `assert_rule_invariants` guard, and the surrounding apply/assert ordering in `phase10.rs` and `privileged_helper.rs`
Out of scope for this part: Linux nftables killswitch paths except where they share a validator, and Windows WFP (Part VI now covers the latter)

> **Line-reference drift (meta-review 2026-07-29; corrected again after a
> dedicated re-verification pass).** References into `phase10.rs` after ~`:1864`
> are uniformly **+43 lines** at HEAD. Two claims in the first version of this note
> were wrong: only **`c5018acb`** touched `phase10.rs` (not `fe634559`/`5bbf2062`),
> and its +43 lines are entirely inside `LinuxCommandSystem` (an nft `udp sport`
> allow) — the traversal/managed-peer fields and render loops **predate the
> baseline entirely**, which is why PF-15 is a baseline-era defect and not drift.
> The corrected PF-04 anchor below was also itself wrong (`:2193`; the flush arm is
> at **`:2210`**). Substance was re-checked and holds in every case
> examined, but the refs below are as-of `22847b12`. Key corrected anchors:
> PF-01's `allow_egress_interface` pass `:2653-2662` → **`:2700-2705`** (guard
> opens `:2674`, closes **`:2706`**); PF-02's SSH block `:2663-2677` →
> **`:2707-2720`**; the terminator `:2699` → **`:2742`**; the DNS blocks
> `:2644-2651` → **`:2688-2694`**; PF-03's `apply_pf_rules` `:2940-2998` →
> **`:2983-3041`** with the flush `:2944-2948` → **`:2988-2991`** and the load
> `:2971` → **`:3012-3015`**; `block_all_egress` `:3585-3588` → **`:3628-3631`**;
> PF-05's `assert_killswitch` `:3515` → **`:3544`** with the substring test at
> **`:3558`**; PF-04's flush arm `:2169` → **`:2210`** (`privileged_helper.rs`
> shifts +15 in 1330-1803, +41 in 1900-3206, +75 above 3211).
> `macos_pf_load_spec.rs` is
> **unmodified** since the baseline, so all refs into it are exact. Anything in
> this part that depends on render *ordering* — notably §14 item 14 — needs
> re-verification at HEAD, not a renumber.

## 12. Why this area, and what was already known

Part I and Part II covered an in-process authorization engine and at-rest key
custody. This part covers a **privilege boundary**: a possibly-compromised daemon
talking to a root helper that programs the macOS `pf` firewall. The killswitch is
what prevents traffic leaving outside the tunnel, so a defect here is a **traffic
leak**, which is a different and more severe failure class than either earlier
part.

Target selection was evidence-driven rather than by intuition. Of the 594 file
rows in `SecurityAuditLedger_2026-06-18.md`, none are pending — the ledger is
thorough — so the gap is code that postdates it. Enumerating tracked `.rs` files
with **no ledger row** showed most are lab/test tooling (`vm_lab/`,
`lab-monitor`, `live_lab_*`), which the charter places outside the production
trust path. **Corrected 2026-07-29 (meta-review):** an earlier revision said "two
were production daemon code." The real figure is **11** of the 19 unrowed files in
`crates/rustynetd/src/` (the other 8 are `*_audit.rs` report harnesses):
`anchor_port_mapping_status.rs`, `keepalive.rs`, `linux_blind_exit.rs`,
`linux_blind_exit_dataplane.rs`, `linux_ipv6_leak.rs`, `macos_exit_nat.rs`,
`macos_ipv6_leak.rs`, `macos_pf_load_spec.rs`, `macos_pf_mesh_cidr.rs`,
`path_mtu.rs`, `peer_traversal_prior.rs`. Several are killswitch and
IPv6-leak-prevention code — the same severity class as the file this part
selected. That makes **PF-12 a systematic coverage gap rather than one missing
row**, and it means target selection here was less exhaustive than claimed.

**This boundary is not unreviewed, and that must be stated plainly.**
`AutonomousSecurityParityPassLog_2026-06-24.md:119-129` records a prior 4-lens
workflow review of exactly this landed boundary, which found one HIGH — a
compromised daemon sending `mesh_cidr=0.0.0.0/0` renders
`pass out quick on en0 inet from 0.0.0.0/0 to any`, passing all local-origin
egress before the terminal block — and **fixed** it via
`macos_pf_mesh_cidr::validate_mesh_egress_source_cidr`. Verified at this
baseline: that fix is live and well generalized, wired into
`macos_blind_exit.rs:269`, `macos_exit_nat.rs:195`, **and** `linux_blind_exit.rs:251`.

So the useful question was not "is this reviewed" but **"did that fix
generalize to the sibling parameters?"** It did not, and that is the substance of
Part III. The prior entry also noted that neither the per-module `validate_cidr`,
nor the helper rule-shape assert, nor the self-referential evaluator caught the
`mesh_cidr` case — PF-05 explains why that is structural and still true.

| ID | Finding | Severity | New? |
|---|---|---|---|
| PF-01 | `allow_egress_interface=true` is a one-boolean full-IPv4 killswitch off-switch, and it passes the repo's own killswitch assertion | High | **New** |
| PF-02 | `ssh_cidr=0.0.0.0/0` opens unrestricted off-tunnel TCP/22 — **even under `strict=true`**, and not interface-scoped. Confirmed on macOS pf, Linux nft **and** Windows netsh (WIN-05) | High | **New** |
| PF-03 | `apply_pf_rules` flushes the old anchor **before** loading the new one, on every reconcile — a failed load leaves egress wide open | High | **New** |
| PF-04 | The allowed `pfctl -a <anchor> -F all` arm lets the daemon empty the live killswitch anchor, bypassing the whole regeneration boundary | High (adjacent) | **New** |
| PF-05 | Killswitch assertions validate rule **presence, not precedence** — the root cause of PF-01/PF-02 being silent | Medium | Cross-platform analogue of **RN-27** (open), which records the identical defect on the Linux nft killswitch |
| PF-06 | Specs that pass decode but that `pfctl` rejects (iface length/keywords, `/+N` prefixes) — feeds PF-03 | Medium | **New** |
| PF-07 | `generation` is an unbounded daemon-chosen `u64` | Low-Medium | **New** |
| PF-08 | `MAX_MANAGED_PEER_ENDPOINTS = 256` is unreachable through the 16 KiB wire budget; no test pins the budget | Low | **New** |
| PF-09 | `push_list` does not bound a single over-cap list element | Low | **New** |
| PF-10 | A root `pfctl -f` on a predictable `$TMPDIR` file survives in the killswitch-precedence validator | Medium (adjacent) | **New** |
| PF-11 | `contains_forbidden_route_primitive` is evadable but unreachable — defence-in-depth only | Info | **New** |
| PF-12 | This production privilege-boundary file has zero audit-ledger rows | Low (bookkeeping) | **New** |
| PF-13 | Three round-trip tests pin render equality, not spec equality | Low (test coverage) | **New** |
| PF-14 | `reject_nonempty` is a content guard with a presence-guard name | Info | **New** |
| PF-15 | **`block_all_egress` does not block all egress** — entering `FailClosed` leaves up to 320 UDP passes (and possibly TCP/22) rendered, in honest operation | Medium | **New** (resolves the former "candidate missing finding") |

## 13. Findings

### PF-01 — `allow_egress_interface=true` is a one-boolean killswitch off-switch (High, CONFIRMED by execution)

Files: `crates/rustynetd/src/phase10.rs:2653-2662`; entitlement at `:3356`

With `strict_fail_closed=false` and `allow_egress_interface=true`, the render emits
an unconditional pass on the **physical** interface:

```text
set block-policy drop
pass quick on lo0 all
pass out quick on utun9 inet all keep state
pass out quick on en0 inet all keep state      <-- ALL IPv4 egress, cleartext, off-tunnel
block drop out quick inet6 all
block drop out quick all
```

pf `quick` is first-match-wins, so every local-origin IPv4 packet leaves on `en0`
before the terminator is ever consulted. The terminal block is still present,
`assert_rule_invariants` passes, and `render()` returns `Ok`. **The killswitch is
off.** Confirmed by reading `:2653-2662` directly and by an out-of-repo replica
whose output was fed to the host's real `/sbin/pfctl -n -f`.

Entitlement is the crux. In honest operation this flag is set `true` in exactly
one place — `apply_nat_forwarding` (`:3356`), the exit-node/NAT path — and reset to
`false` at `:3314`, `:3349`, `:3391`. It is gated on a **signed exit capability at
the daemon layer**. The helper accepts `allow_egress_interface=true`
unconditionally and has no way to observe that capability. So a daemon compromised
to the helper's uid obtains full cleartext IPv4 egress by flipping one boolean it
is not entitled to flip.

This directly contradicts the module doc's claim (`macos_pf_load_spec.rs:13-15`)
that a compromised daemon "can never inject rule text, redirect the anchor, or
load a foreign file" — the first two clauses hold (see §14), but the *goal* behind
them, that a compromised daemon cannot defeat default-deny egress, does not.

**What makes this materially worse than PF-04**, and the reason it is ranked
first: it is **silent**. See PF-05 — the repo's own `assert_killswitch` is a
substring-presence check that this ruleset satisfies. Emptying the anchor (PF-04)
trips that assertion; a permissive `quick` pass inside a loaded anchor does not.
One route is loud, this one is not.

Proposed enforcement (review-only — do NOT apply): make the exit posture a
distinct spec *kind* the helper can reason about, or require a helper-visible
attestation of the signed exit capability, rather than a bare boolean the helper
must trust.

---

### PF-02 — `ssh_cidr=0.0.0.0/0` opens unrestricted off-tunnel TCP/22, even in strict mode (High, CONFIRMED by execution)

Files: `crates/rustynetd/src/phase10.rs:2663-2677`; `ManagementCidr::from_str` at `:188-210`

**Correction to my own earlier assessment.** On first read I judged this defended
and said so, on two grounds: the rules are scoped to `proto tcp … port 22` rather
than general egress, and the authors reference `0.0.0.0/0` for SSH explicitly at
`:1207`. Both grounds were wrong. The `:1207` comment is diagnosing a
*route-assertion* bug (iproute2 renders the default route as `default`, breaking a
literal string compare), not endorsing `0.0.0.0/0` as safe. And "only TCP/22" is
not narrow — unrestricted outbound SSH to anywhere is a serviceable exfil and
tunnelling channel; SSH is precisely the protocol one would choose for it. The
finding stands and I had it backwards.

Three aggravating details, all confirmed:

1. **It fires in the strictest posture.** The `if spec.fail_closed_ssh_allow` block
   at `:2663` sits **outside** the `if !strict_fail_closed` guard that closes at
   `:2662`. So `strict=true` — the fail-closed mode — does not suppress it.
2. **The outbound rule is not interface-scoped.** It renders
   `pass out quick {af} proto tcp from any to {cidr} port 22 keep state`
   (`:2671-2676`) with no `on <iface>` clause, so it covers the physical NIC.
3. **Being `quick`, it pre-empts the IPv6 block.** With `ssh_cidr=::/0` the v6
   `pass out` precedes `block drop out quick inet6 all` (`:2696`), so `ipv6_blocked=true`
   does not contain it.

`ManagementCidr::from_str` (`:188-210`) checks only `prefix > max_prefix`, so
prefix 0 is accepted with no width floor. Independently reproduced by a second
probe, which pinned the ordering positionally: the v6 `pass out` lands at offset
141 and `block drop out quick inet6 all` at 177, so the bypass of `ipv6_blocked`
is confirmed by construction, not inferred. Grep confirms there is **no** range
bound on `ManagementCidr` anywhere in the crate.

**Scope correction — this is not macOS-only.** The Linux nftables killswitch
emits the same unbounded shape from the same `fail_closed_ssh_allow_cidrs`
values: `phase10.rs:930-947` adds `<family> daddr <cidr> tcp dport 22 accept`
(plus the `sport 22` counterpart). Verified by reading. So the correct fix site is
`ManagementCidr::from_str` itself — bounding there covers the pf path, the nft
path, and the operator flag in one change, and is the only placement that cannot
drift between platforms.

A second, independent narrowing worth considering: the outbound half
(`pass out … to <cidr> port 22`) is only needed for node-*initiated* SSH, because
the inbound rule is `keep state` and therefore already covers sshd's reply
traffic. If nothing legitimately initiates outbound SSH from the node, deleting
that half removes the egress channel without any policy change at all. Worst case
at the cap is 64 CIDRs → 128 unbounded port-22 rules.

**This is the same bug class as the fixed `mesh_cidr` HIGH, left unfixed on the
sibling parameter.** The reasoning in `macos_pf_mesh_cidr.rs:101-105` transfers
verbatim — "a global or default-route range would carry local-origin egress past
the killswitch." The asymmetry reads as an oversight rather than a decision.
Note `blind_exit`'s `management_ssh_allow_cidrs` go through
`macos_blind_exit.rs:315-330` `validate_cidr` rather than the bounding validator,
so it shares the gap.

Honest mitigation: the operator config path (`main.rs:3514-3535`) also accepts
`0.0.0.0/0`, so the helper is not loosening relative to configuration — an
operator can already choose this. The counter-argument is that management-SSH
CIDRs are bounded operator networks by definition, so a width floor (or
private/CGNAT/ULA containment, mirroring `mesh_cidr`) would never false-reject a
real deployment. There is also a correct guard already present and worth
crediting: `:780-784` rejects `fail_closed_ssh_allow=true` with an empty CIDR
list, so the inconsistent config fails closed.

---

### PF-03 — the anchor flush precedes the load, so a failed load leaves egress wide open (High, CONFIRMED)

File: `crates/rustynetd/src/phase10.rs:2940-2998`, with recovery at `:3585-3588`

`apply_pf_rules` flushes the **previous** anchor (`:2944-2948`,
`run_allow_failure(Pfctl, ["-a", previous, "-F", "all"])`) and only then loads the
new one (`:2971`), setting `self.anchor_name` on success (`:2973`).

Because `current_anchor_name` is `com.apple/rustynet_g{generation}` (`:2838-2843`)
and the generation bumps on every apply cycle (`:3199`, `:5170`), the
previous-anchor branch fires on **every normal reconcile** — this is not a rare
error path. If the load then fails for any reason (a PF-06 input-shaped rejection,
a transient `pfctl` error, a full filesystem), the state is:

- old anchor `…_g(N-1)`: **flushed, empty**
- new anchor `…_gN`: **never loaded, empty**
- macOS `/etc/pf.conf`'s wildcard `anchor "com.apple/*"` evaluates the empty
  anchors → **no block rule anywhere** → egress wide open
- `self.anchor_name` still points at the flushed old anchor

Recovery does not save it: `block_all_egress` (`:3585-3588`) is
`apply_pf_rules(true)` — the same path with the same inputs — so a deterministic
input-shaped failure re-fails while egress stays open, and the daemon surfaces
`BlockEgressFailed`. This is exactly the "stranding the node undefended" outcome
that `macos_pf_load_spec.rs:20-21` calls *worse than the original vulnerability*,
and it violates the repo's fail-closed constraint.

Proposed enforcement (review-only — do NOT apply): reorder to load-then-flush.
**Safety caveat added 2026-07-29 (meta-review) — do not implement this without
the experiment PF-07 already asks for.** An earlier revision asserted that "pf
tolerates both anchors being briefly populated — both terminators are `quick` and
identical in effect — so the overlap is strictly safer than the gap." That
asserts as fact precisely the pf property PF-07 marks **inferred and explicitly
unverified**: how `anchor "com.apple/*"` orders and evaluates sub-anchors. If
PF-07's inference holds, then during the overlap the *old* anchor's
`block drop out quick all` preempts every pass in the new anchor — a full egress
**blackout on every reconcile**, since PF-03 establishes that the
previous-anchor branch fires on every normal cycle. Worse, the flush is
`run_allow_failure` (result deliberately discarded), so a failed flush would make
the blackout persist. The terminators are indeed identical; their position
relative to the *other* anchor's passes is not. The direction is fail-closed, so
this is an availability hazard rather than a security one — but a two-line
reorder that blackholes a live fleet is worse than the window it closes. Gate it
behind the on-box sub-anchor-ordering experiment. Folding the flush into the
builtin has the same overlap property and needs the same gate.

---

### PF-04 — the daemon can simply empty the killswitch anchor via the allowed flush arm (High, adjacent, CONFIRMED)

File: `crates/rustynetd/src/privileged_helper.rs:2169`, with `is_anchor_name_token` at `:1402-1418`

The boundary's `pfctl` allowlist includes:

```rust
["-a", anchor, "-F", "all"] if is_anchor_name_token(anchor) => Ok(()),
```

and `is_anchor_name_token` admits **any** `com.apple/rustynet_g*` (plus the two
fixed anchors). The check is stateless — the helper has no notion of which
generation is live. So a compromised daemon sends
`pfctl -a com.apple/rustynet_g<current> -F all` and the killswitch anchor is
emptied: no spec, no injection, no `-f`. The elaborate regeneration boundary is
bypassed by the flush arm sitting immediately beside it.

The asymmetry in the code is striking and worth recording: the `-f` denial
directly below (`:2170-2177`) carries a thorough do-not-re-add rationale and
regression tests, while the flush arm has no equivalent analysis. I found no
mention of this capability in `documents/`.

This is a genuine design tension, not a simple oversight — flush is required for
rotation and teardown, and the helper is stateless by design. It matters for how
the `-f` closure is described: it **narrows the attack surface** (no arbitrary
rule text, no foreign file, no anchor redirection) rather than eliminating the
impact (egress can still be opened). PF-01 remains the more serious of the two
because it is silent where this is detectable.

Proposed enforcement (review-only — do NOT apply): have the helper own generation
state; or move flush inside the atomic builtin (fixes PF-03 too); or drop the
boundary flush arm and rely on the next load overwriting the anchor.

---

### PF-05 — the killswitch assertions check presence, not precedence (Medium, CONFIRMED)

Files: `crates/rustynetd/src/phase10.rs:3515`; `crates/rustynetd/src/macos_pf_load_spec.rs:186-207`

`assert_killswitch` reduces to:

```rust
if !output.stdout.contains("block drop out quick all") {
    return Err(SystemError::KillSwitchAssertionFailed("pf killswitch rule missing"));
}
```

Because pf `quick` is first-match-wins, a ruleset containing
`pass out quick on en0 inet all keep state` **followed by** that terminator
satisfies this assertion while providing zero egress protection. The assertion
validates that a string is present, not that it is reachable.

`assert_rule_invariants` has the same blind spot from the other side: it requires
the last non-empty trimmed line to be the terminator and rejects route primitives,
but it never checks for over-broad passes. Executed:
`assert_rule_invariants("pass out quick all\n   block drop out quick all   \n")`
returns `Ok(())`. The existing test at `:941` gives false confidence — its fixture
omits the terminator, so it fails for the terminator reason rather than for the
blanket pass.

This is the **root cause of PF-01's and PF-02's stealth**, and it explains the
prior review's observation that neither the per-module validator nor the helper
rule-shape assert caught the `mesh_cidr` case: none of these checks model pf
evaluation order, so none of them can distinguish a defended anchor from a fully
open one.

Proposed enforcement (review-only — do NOT apply): assert *precedence*, not
presence — e.g. reject any `pass` whose match set is broader than an allowlisted
shape appearing before the terminator, or model the render as an ordered rule list
and assert no rule preceding the terminator matches "all egress".

---

### PF-06 — specs that pass decode but that `pfctl` rejects (Medium, CONFIRMED against real `pfctl`)

Three classes, each verified by feeding rendered output to the host's
`/sbin/pfctl -n -f`. Each is a validated-but-unloadable spec, which lands as a
failed load and therefore triggers PF-03.

1. **Interface-name length.** `parse_interface` (`macos_pf_load_spec.rs:507`) and
   `macos_blind_exit::validate_interface_name` allow length ≤ **31**; pf's limit is
   `IFNAMSIZ-1` = **15** (`len=16` → `interface name too long`). The same codebase
   already has the correct bound: `privileged_helper.rs:1330-1332`
   `is_interface_name` uses `value.len() <= 15` for other programs. Straight
   inconsistency.
2. **Charset-legal but grammatically invalid names.** All pass `parse_interface`;
   all are `pfctl` syntax errors: `0`, `123`, `08`, `-`, `.`, `all`, `inet`,
   `state`, `route-to`. Pure-digit names lex as `NUMBER`; the others collide with
   pf keywords.
3. **Non-canonical prefixes on the raw-string CIDR paths.** `u8::from_str` accepts
   a leading `+`, so `10.0.0.0/+8` validates and renders verbatim → `pfctl` syntax
   error. This affects `blind_exit`'s `ssh_cidr` and both `mesh_cidr` paths, which
   carry the raw string through to rule text. The killswitch `ssh_cidr` path is
   **immune**, because `ManagementCidr` re-renders from typed fields
   (`phase10.rs:182-186`), turning `10.0.0.0/+8` into `10.0.0.0/8`.

That last contrast is the fix pattern for the whole class: parse to typed fields
and re-render, rather than validating a string and passing it through. §14 credits
it as the strongest construct in the module.

Two related details, both confirmed by execution:

- **The `decode` docstring is not literally accurate.** `macos_pf_load_spec.rs:227-230`
  states every field is re-parsed through a typed validator. For the three
  raw-string CIDR fields (`blind_exit` `ssh_cidr`, and `mesh_cidr` on both
  `blind_exit` and `exit_nat`) it is validate-then-pass-through: the daemon's exact
  bytes reach the rule text, which is how `/+10` and `/0010` survive.
- **`blind_exit`'s `ssh_cidr` prefix is not range-checked at decode.**
  `ssh_cidr=192.168.0.0/99` and `.../abc` both decode `Ok` and fail later in
  `render()`; `pf_family_for_cidr_str` (`:529-538`) parses only the base address,
  **Corrected 2026-07-29 (meta-review):** an earlier revision said "the comment at `:366-367` admits this." It does not — that comment documents the split as intentional layering ("`new` validates interfaces … `build` (in `render`) re-validates the ssh CIDRs"). The behavioural claim is unaffected and consistent with the comment; only the characterisation was wrong. This was an error at the baseline, not drift — `macos_pf_load_spec.rs` is unmodified since `22847b12`. The killswitch equivalent *is* caught
  at decode. Direction is safe: `execute_macos_pf_load`
  (`privileged_helper.rs:996-1000`) always decodes **then** renders, while the
  standalone preflight (`:1299-1301`) is only an admission gate — so execute is
  strictly stricter than preflight.

---

### PF-07 — `generation` is an unbounded daemon-chosen `u64` (Low-Medium, CONFIRMED; one part inferred)

File: `crates/rustynetd/src/macos_pf_load_spec.rs:155-163`, `:292`

The anchor is `format!("com.apple/rustynet_g{generation}")` from a `parse_u64`
value that is never bounded, range-checked, or compared against helper-side state.
Daemon-side the generation is monotonic (`phase10.rs:5060` `saturating_add(1)`),
but a compromised daemon speaks the IPC directly.

What is genuinely safe here and worth crediting: the reachable anchor set is
exactly `com.apple/rustynet_g` + digits, so there is no traversal and no escape
from the namespace; and because the name is formatted from the *parsed* integer,
`generation=007` and `generation=7` both yield `…_g7`, so no shadow/duplicate
anchor pair can be created.

Two further executed results narrow this finding, and both cut against inflating
it. First, non-canonical spellings cause **no** anchor divergence: `generation=+7`
and `generation=00007` are accepted by `u64::from_str` but format back to
`…_g7`, identical to what `encode` emits for 7, so the decoded spec compares equal
to the canonical one; `1_0`, `-1`, `" 1"`, `0x10`, `1e3`, and `u64::MAX + 1` are
all rejected. Second, **stale anchors are reclaimed**: `phase10.rs:3000-3007`
enumerates `com.apple/rustynet_g*` and flushes anchors the daemon no longer owns,
so a healthy daemon cleans up after a hostile one. Every minted anchor is also
content-fail-closed, since the terminator is asserted at
`macos_pf_load_spec.rs:201`.

Residual is therefore anchor *residue* and exhaustion rather than bypass: a
hostile generation can write into a stale or not-yet-used generation's anchor and
mint many anchors, but each is fail-closed and reclaimable. **Inferred and
explicitly unverified:** pf evaluates `anchor "com.apple/*"`
sub-anchors in lexicographic order while rustynet orders them numerically
(`macos_exit_killswitch_precedence.rs:141-196` sorts by parsed generation
descending), so a chosen generation might be made to sort before the legitimate
anchor and win first-match-`quick`. Confirming this needs an on-box pf experiment
that was not run; do not treat it as established.

---

### PF-08 — the module's list caps exceed what the wire can frame (Low, CONFIRMED)

Files: `crates/rustynetd/src/macos_pf_load_spec.rs:52-55`; `crates/rustynetd/src/privileged_helper.rs:79`, `:82-83`

`MAX_ARGS = 128` and `MAX_ARG_BYTES = 256` are both enforced before `decode` runs
(`:709`, `:714-719` in `read_request`; again in `validate_request` `:1261-1278`) —
correct ordering, credited in §14. But the binding constraint is
`MAX_MESSAGE_BYTES = 16_384` (`:79`), and at the module's own decode caps with
all-IPv6 values the request cannot be framed at all: the first failing IPv6
`managed_peer` count alongside full 64-entry `ssh_cidr` and `traversal` lists is
≈**202**, well under `MAX_MANAGED_PEER_ENDPOINTS = 256`.

No legitimate configuration is rejected today — `MAX_AUTO_TUNNEL_PEER_COUNT = 128`
(`daemon.rs:374`), and 128 IPv6 peers frame at ≈12,737 of 16,384 bytes (78%). So
this is not a live defect. It is recorded because (a) the module's cap and the wire
budget are mutually inconsistent, (b) headroom in the IPv6 direction is only
≈1.6×, and (c) the module's tests assert `MAX_ARGS`/`MAX_ARG_BYTES` (`macos_pf_load_spec.rs:1007-1011`, `:1051-1052`) but **nothing asserts the frame budget** — so a future peer-cap
raise would not be caught by tests, and would surface as a failed load, i.e.
PF-03.

---

### PF-09 — `push_list` does not bound a single over-cap element (Low, CONFIRMED)

File: `crates/rustynetd/src/macos_pf_load_spec.rs:417-435`

The chunking guard flushes *before* appending, so every emitted token satisfies
`len(key) + 1 + len(current) <= MAX_ARG_BYTES` by induction. But after a flush
`current` is empty and the next value is appended unconditionally, with no check
that the element itself fits: a 300-byte element yields a 313-byte token.
Unreachable today — the longest legitimate element is a full IPv6 `SocketAddr`
(~47 bytes) or IPv6 CIDR (~43), with an observed maximum token of 255. Worth a
one-line assert rather than a fix.

---

### PF-10 — a root `pfctl -f` on a predictable `$TMPDIR` file survives in the precedence validator (Medium, adjacent, CONFIRMED)

File: `crates/rustynetd/src/macos_exit_killswitch_precedence.rs:275`, `:285-290`, with `write_restore_file` at `:349-362`

While the boundary's `-f` arm is gone, one root `pfctl -f` remains in the tree:

```rust
let restore_path = write_restore_file(anchor.as_str(), baseline_rules.as_str())?;
…
run_pfctl_status(&["-a", anchor.as_str(), "-f", restore_path.to_string_lossy().as_ref()])
```

`write_restore_file` does `std::env::temp_dir().join(format!("rustynet-macos-killswitch-{}-{now}.pf", …))`
then a plain `fs::write` — a **predictable name**, **symlink-following** write,
with no `O_EXCL`, no `O_NOFOLLOW`, no mode, and no ownership check. That is exactly
the artifact-custody shape the helper's `write_root_owned_pf_temp` (`O_EXCL`, 0600,
128-bit `OsRng` nonce, root-only 0700 directory) exists to avoid, and it writes
into the **killswitch anchor**.

Scoped honestly: this is a CLI subcommand (`main.rs:2285`, `:362`) run as root by
the live-lab validator, not the daemon service, and on macOS `env::temp_dir()` is
normally the per-user 0700 `/var/folders/…`. So it is **not** the daemon-uid
boundary bypass that `fd1b50d1` closed. But it is a root `pfctl -f` on a file whose
integrity is never established, `$TMPDIR` is inherited from the invoking
environment, and it matches the ask already recorded as SR-020
(`documents/archive/SecurityReview-2026-03-24.md:1715`). It simply was not
converted to the regeneration builtin.

---

### PF-11 — `contains_forbidden_route_primitive` is evadable but unreachable (Info, CONFIRMED)

File: `crates/rustynetd/src/macos_pf_load_spec.rs:540-547`

The matcher lowercases each line and tests `" route-to "`, `" reply-to "`,
`" dup-to "` with required surrounding single spaces. Executed evasions: a **tab**
delimiter, `route-to(en1 …)` with no space before the paren, and `route-to` at
line start or line end all pass undetected; doubled spaces and CRLF are caught.

**None of it matters, and it should not be inflated.** The function has exactly one
call site — `assert_rule_invariants` (`:187`), reached only from `render()` (`:178`)
— so it asserts over text produced by the three reviewed builders in the same
process, none of which emit any route primitive in any branch, and per §14 no
parameter can introduce a tab, newline, or paren. It is defence-in-depth against a
future builder regression, with no exploitable path today. Note the test at `:635`
deliberately blesses the `route-to(en0)` gap, so tightening the matcher means
updating that test.

Two same-named functions elsewhere (`macos_blind_exit.rs:161`,
`macos_exit_nat.rs:156`) *do* run against live `pfctl -s` output; those are drift
detectors, not boundary filters.

---

### PF-12 — this file has no audit-ledger row (Low, bookkeeping, CONFIRMED)

`SecurityAuditLedger_2026-06-18.md` contains 594 file rows and zero mentions of
`macos_pf_load_spec.rs`, even though the boundary was reviewed in
`AutonomousSecurityParityPassLog_2026-06-24.md`. Anyone auditing coverage via the
ledger — its stated purpose — would conclude this production privilege boundary
was never examined, or would miss it entirely. Recording a row that cross-links
the parity-log review (and this Part) would close the tracking gap.

### PF-13 — three round-trip tests pin render equality, not spec equality (Low, test coverage, CONFIRMED)

File: `crates/rustynetd/src/macos_pf_load_spec.rs:715`, `:769`, `:970`

The round-trip property itself holds — a probe over 2592 killswitch specs
(booleans × 0..2 entries per list × `generation ∈ {0, 1, u64::MAX}`) plus
blind-exit and exit-NAT variants confirmed `decode(encode(spec)) == spec` in every
case. The gap is what the *committed* tests pin:

- `killswitch_roundtrip_renders_identically` (`:639`) and `ipv6_endpoints_roundtrip`
  (`:787`) correctly assert `decoded == original`.
- `blind_exit_roundtrip` (`:715`) and `exit_nat_roundtrip_is_nat_only` (`:769`)
  assert only that the *render* matches — two specs differing in a field that does
  not affect rule text would pass.
- `no_false_reject_cartesian_sweep` (`:970`) sweeps encode→decode→render but pins
  `strict=false` and `generation=1`, so the strict-mode and generation dimensions
  are unswept.

Cheap to close, and worth it because the round-trip is the property that keeps
`decode` from accepting more than `encode` can emit — the core boundary invariant.

---

### PF-14 — `reject_nonempty` is a content guard with a presence-guard name (Info, CONFIRMED)

File: `crates/rustynetd/src/macos_pf_load_spec.rs:466`, with `extend_csv` at `:437-443`

`extend_csv` drops empty parts, so a cross-kind list key whose value is only
separators leaves the vector empty and slips past `reject_nonempty`. Executed:
`kind=exit_nat … ssh_cidr=,` and `kind=killswitch … mesh_cidr=,` are both
**accepted**.

No reachable effect — the resulting spec and render are byte-identical to the same
token list with the offending token removed, which was verified. Recorded only
because the sibling scalar guard `reject_present` (`:457`) genuinely is
presence-based, so the two guards with parallel names have different semantics; a
future field addition could reasonably assume presence semantics from the name.

### PF-15 — `block_all_egress` does not block all egress (Medium, CONFIRMED by execution against real `pfctl`)

Files: `crates/rustynetd/src/phase10.rs:3628-3631` (`block_all_egress`), `:5453-5459` (`force_fail_closed`), render at `:2658-2744`

This finding replaces the "candidate missing finding" that section 14 item 14 was
downgraded into, and it resolves it in a different place than expected.

Only two rule families sit inside the `!strict_fail_closed` guard (`:2674-2706`):
the DNS quartet and the two `inet all` passes. **Four families render under
strict** — the SSH pass pair (up to 64 CIDRs → 128 rules), the traversal passes (up
to 64), the managed-peer passes (up to 256), and the v6 block. So up to **320 UDP
passes on the physical interface survive strict mode**, and `assert_rule_invariants`
plus `assert_killswitch` both report healthy in every case.

**The sharp part is not the mode inversion.** `block_all_egress` is
`apply_pf_rules(true)` and its only production caller is `force_fail_closed`, which
transitions to `DataplaneState::FailClosed`. Verified by reading: it sets
`current_serve_exit_node = false`, calls `block_all_egress()`, sets
`ExitMode::Off`, and transitions — it **never clears**
`traversal_bootstrap_allow_endpoints`, `managed_peer_egress_endpoints`, or
`fail_closed_ssh_allow_cidrs`, all of which are persistent `MacosCommandSystem`
fields. `managed_peer_egress_endpoints` is populated during normal reconcile, i.e.
exactly the state you are in when you fail closed.

So this is a fail-closed-guarantee violation reachable in **honest operation with
no compromise at all**. Worked example, confirmed against the host's real
`/sbin/pfctl -n -vv`: a node with an operator STUN server and a live peer hits a
dataplane error → `force_fail_closed` → the rendered "fail closed" ruleset is

```text
set block-policy drop
pass quick on lo0 all
pass out quick on en0 inet proto udp to 203.0.113.10 port 3478 keep state
pass out quick on en0 inet proto udp to 203.0.113.7 port 51820 keep state
block drop out quick all
```

— two off-tunnel cleartext UDP channels on the physical NIC, in the state named
"fail closed".

Held at **Medium**, not High, for three reasons: the passes are narrow by
construction (single `ip:port`, UDP, outbound, `keep state`, interface-scoped),
unlike PF-01's blanket `inet all`; in the compromised-daemon model it is *strictly
dominated* by PF-01, since a daemon that can set `strict` can instead set
`strict=false, allow_egress_interface=true` for full cleartext IPv4, so "strict is
weaker" is not an attacker lever; and in honest operation the endpoints are
legitimate, so the residual channels go to hosts the node was already talking to.

**The mode inversion is a corollary, and narrower than first described.** Strict is
genuinely weaker than non-strict for one case only — IPv4 UDP/TCP **port 53** with
`dns_protected=true`, where non-strict's `quick` DNS block matches first (verified
at `@3` vs the traversal pass at `@6`) and strict has no DNS block at all. For any
other port both modes pass it, and for IPv6 endpoints both modes pass it, because
the v6 endpoint pass renders *before* `block drop out quick inet6 all` — so
`ipv6_blocked=true` does not contain a v6 traversal or managed-peer endpoint in
either mode. That last point is the same shape as PF-02's aggravating detail 3, on
a different parameter.

**Test assurance is false here, and demonstrably so.**
`strict_killswitch_is_minimal_and_terminal` (`macos_pf_load_spec.rs:660-681`) still
passes at HEAD, but only because its fixture empties all four lists — it pins
"minimal" over a fixture that cannot express the non-minimal case, as does
`macos_render_pf_rules_strict_fail_closed_snapshot` (`phase10.rs:12326-12339`). The
decisive evidence is that
`macos_render_pf_rules_allow_configured_traversal_bootstrap_endpoints`
(`phase10.rs:12513-12531`) calls `render_pf_rules(true)` and asserts the traversal
pass **is** present. Both tests are green simultaneously: the repo pins two
contradictory claims about what strict renders, and they coexist only because the
fixtures differ. That also means the endpoint-under-strict behaviour is deliberate
and test-pinned — which is the strongest argument that the defect is the missing
list-clearing in `block_all_egress` rather than the guard placement.

**Unresolved escalation lever (INFERRED — needs its own check).**
`managed_peer_egress_endpoints` derives from `controller.managed_peer_endpoint(...)`
(`daemon.rs:6317`), i.e. control-plane or peer-advertised data. A
`validate_runtime_relay_candidate_endpoint` exists for relay candidates
(`daemon.rs:14520`); whether the managed-peer path has an equivalent guard was not
verified. If a remote peer can advertise an arbitrary endpoint and have a pass
minted for it, this becomes **High** — a remote attacker minting an egress hole that
survives fail-closed. Worth a targeted follow-up.

Proposed enforcement (review-only — do NOT apply): have `force_fail_closed` clear
the three lists (or have `apply_pf_rules(true)` ignore them) so the strict render
is genuinely minimal; and replace the two "minimal" tests with ones whose fixtures
populate all four lists, so the assertion cannot pass vacuously.

## 14. Defences that hold — verified, for the record

The regeneration design is well built and most of what was aimed at it failed.
Each item below was probed and held:

1. **Rule-text injection is genuinely impossible.** Every parameter reaching rule
   text was enumerated and attacked: interface names (`[A-Za-z0-9._-]`, len 1..=31,
   `:505-517`) exclude all whitespace and every pf metacharacter; `ssh_cidr` on the
   killswitch path is parsed to typed fields and **re-rendered** via `Display`
   (`phase10.rs:182-186`) so the raw string never reaches text; endpoints are
   decomposed to `IpAddr` + `u16` before rendering; booleans are exact-match;
   `generation` is a `u64`. Executed and rejected at decode: newline, space, tab,
   CR, `{`, `$`, `#`, `<table>`, and `route-to (…)` payloads in interface, CIDR, and
   endpoint positions. **IPv6 brackets never reach rule text** because `SocketAddr`
   is decomposed — only `endpoint.ip()` is interpolated.
2. **Anchor derivation is airtight.** No `anchor=` token exists in the wire grammar
   and unknown keys are rejected (`:256-273`), so anchor redirection is foreclosed;
   the name is a pure helper-side function of kind + generation; formatting from the
   parsed integer canonicalises leading zeros so no shadow anchor pair is possible.
3. **`decode` is the sole ingress.** The wire request is exactly
   `{ program: String, args: Vec<String> }` (`privileged_helper.rs:537-540`) — no
   path, env, fd, or cwd crosses the boundary. The `pfctl` binary is resolved from a
   fixed candidate list and validated root-owned, non-group-writable, regular
   (`:1167-1205`); the temp file is helper-owned with `O_EXCL`, mode 0600, a
   128-bit `OsRng` nonce, inside a verified root-only 0700 directory (`:1038-1112`).
   A peer-credential gate precedes everything (`:493-500`).
4. **`-f` is genuinely gone from the boundary.** `validate_pfctl_args`
   (`:2159-2184`) accepts only six read-only/flush shapes, with a reasoned
   do-not-re-add comment and regression tests (`:3844-3874`, `:3959-3975`), and
   `MacosPfLoad` is a builtin with an empty binary-candidate set so it can never
   reach `resolve_binary`/exec.
5. **Wire caps are enforced before `decode`**, in `read_request` (`:709`,
   `:714-719`) and again in `validate_request` (`:1261-1278`) — correct ordering.
6. **The terminator cannot be defeated.** `render_macos_killswitch_pf_rules`
   returns `String` (not `Result`), has no early return on any path, and pushes
   `block drop out quick all` unconditionally as its final statement
   (`phase10.rs:2699`); `build_macos_blind_exit_pf_rules` likewise
   (`macos_blind_exit.rs:133`), its only early exits being `?` on validation, which
   abort before any text. The `quick` discipline is coherent: because the terminator
   itself is `quick`, last-match-wins never engages for `out` traffic, and every
   builder-emitted pass is `quick` and ordered before it. `ExitNat` correctly gets a
   *different* invariant (every non-empty line must start with `nat `,
   `macos_pf_load_spec.rs:208-222`) since it is a translation anchor.
7. **Cross-kind and malformed-token rejection is thorough — mechanically verified,
   not spot-checked.** All 14 field keys were fired at all 3 kinds: **23/23**
   cross-variant combinations are rejected, so no field is silently ignored
   (e.g. `blind_exit + strict=false` → rejected at `:340`;
   `killswitch + mesh_cidr=0.0.0.0/0` → rejected at `:290`;
   `exit_nat + ipv6_blocked=true` → rejected at `:393`). Dropping each scalar in
   turn from each kind's minimal token list fails closed in **15/15** cases with
   `missing required token` — **no field silently defaults**, so there is no
   defaulting downgrade lever. An unknown key is **rejected**, not ignored
   (`:272`), so there is no forward-compat security cost, and a token with no `=`
   is rejected at `:253-255`.
8. **`parse_bool` is exact.** Rejected: `TRUE`, `True`, `tRue`, `1`, `0`, `yes`,
   `on`, `"true "`, `" true"`, `"true\n"`.
9. **List caps apply to the accumulated total and run before per-element parsing.**
   `ssh_cidr` split across two tokens totalling 65 entries yields
   `list length 65 exceeds maximum 64`; 64 across two tokens is accepted. A
   1000-element junk `managed_peer` token returns the *bound* error, never a parse
   error — so hostile input cannot force unbounded parse work.
10. **The parse is order-independent.** `decode` is two-phase (collect `:252-274`,
    dispatch `:285`); verified `decode(tokens) == decode(tokens.reversed())`, and
    `kind=` last is equivalent to `kind=` first, with list element order preserved.
11. **The round-trip property holds** across 2592 killswitch specs plus blind-exit
    and exit-NAT variants: `decode(encode(spec)) == spec` in every case. No token
    list was found that `decode` accepts but `encode` could never emit, other than
    the inert cases recorded as PF-14 and the non-canonical spellings in PF-06/PF-07.
12. **Both daemon senders check their result.** `phase10.rs:2971` uses
   `.map_err(...)?` and `:3092-3110` checks and additionally flushes + restores
   forwarding on error. The RN-03 `let _ =` pattern is absent **from the two
   pf-load senders specifically** — note the *previous-anchor flush* in the same
   function is `run_allow_failure`, a helper whose purpose is discarding the
   result, which is what PF-03 and PF-04 both turn on.
13. **`mesh_cidr` semantics are policed, and policed well.**
   `validate_mesh_egress_source_cidr` rejects `0.0.0.0/0`, `::/0`, `8.8.8.0/24`,
   `100.0.0.0/8`, and `::ffff:10.0.0.0/104` at decode (executed), and the fix was
   generalized to macOS blind-exit, macOS exit-NAT, **and** Linux blind-exit. PF-01
   and PF-02 are precisely the parameters that did not receive this treatment.
14. **DNS ordering holds only when `strict_fail_closed` is false — WITHDRAWN as a
    general defence (meta-review 2026-07-29).** With `dns_protected=true` and
    `strict=false`, the DNS blocks are `quick` and precede the endpoint passes, so
    a hostile `traversal=8.8.8.8:53` cannot punch through them. But verified at
    HEAD: the `!strict_fail_closed` guard opens at `phase10.rs:2674` and **closes
    at `:2706`**, so the DNS blocks (`:2688`, `:2692`) sit *inside* it while the
    traversal and managed-peer endpoint passes (`:2721`, `:2730`) sit *outside*.
    Under `strict_fail_closed = true` — the posture `block_all_egress` itself uses
    — there is no DNS block at all and the endpoint pass stands unopposed. That is
    the same "fires even under strict" property PF-02 flags for SSH, on a
    parameter this part did not flag. **Now resolved as PF-15** — and the
    re-verification changed the conclusion twice over: the sharp defect is not the
    mode inversion but that `block_all_egress` leaves those passes rendered, and
    the render function turns out to be **byte-identical to the baseline**, so this
    was an error in the original credit rather than drift.

## 15. Suggested triage order for Part III

1. **PF-03** — the two-line reorder (load, then flush). Cheapest fix with the
   largest blast-radius reduction, and it converts every PF-06-class rejection from
   "node stranded open" into "apply failed, old killswitch intact."
2. **PF-02** — apply `mesh_cidr`-style bounding to `ManagementCidr` on the pf path,
   and move the SSH block inside the `strict_fail_closed` guard (or justify in a
   comment why it must fire in strict mode).
3. **PF-05** — assert precedence rather than presence. This is what makes PF-01 and
   PF-02 detectable at all, and it retroactively covers the already-fixed
   `mesh_cidr` class.
4. **PF-01** — needs a design decision (distinct spec kind, or helper-visible
   capability attestation), so it is slower than the three above despite ranking
   highest on severity.
5. **PF-04** — decide the flush model; folding flush into the atomic builtin
   resolves this and PF-03 together.
6. **PF-06** — align the interface bound to 15 — but note that adopting
   `is_interface_name` *verbatim* also drops `.` from the charset that
   `parse_interface` allows, which would silently reject dotted interface names,
   so port the bound rather than the whole predicate — and adopt the parse-to-typed-then-re-render pattern for the
   three raw-string CIDR sites.
7. **PF-07, PF-08, PF-09, PF-11, PF-12, PF-13, PF-14** — bounded-cost hygiene;
   PF-08/PF-09 are asserts, PF-12 is a ledger row, PF-13 is three test
   strengthenings, PF-14 is a rename or a comment.
8. **PF-10** — owner of the live-lab validator: convert `write_restore_file` to the
   `write_root_owned_pf_temp` pattern or route its restore through the builtin.

## 16. Reproduction (Part III)

```bash
git -C ~/Desktop/rustynet rev-parse --short HEAD   # baseline was 22847b12; the tree has since advanced
```

Findings marked CONFIRMED-by-execution were verified by replicating the validators
and the three renderers verbatim in a scratch crate **outside** the repository,
driving them with a hostile parameter matrix, and feeding the rendered rule text to
the host's real `/sbin/pfctl -n -f` — which is what established PF-06's three
rejection classes and confirmed that PF-01's and PF-02's renders are accepted by
pf. PF-07's anchor-ordering component is the one item left **inferred**: it needs an
on-box experiment on pf wildcard sub-anchor evaluation order that was not run.

---

# Part IV — relay untrusted-input path (remote attacker surface)

Crate baseline: `crates/rustynet-relay/src/{transport.rs,session.rs,rate_limit.rs,hello_limiter_audit.rs}`; `cargo test -p rustynet-relay` **84/84 green** at this commit

> ## ✅ Six of these findings are FIXED — commit `1c44ed3f`
>
> **RLY-01, RLY-02, RLY-04, RLY-05, RLY-10, RLY-11** are closed in code, each with a
> negative test. Gates at that commit: fmt clean, clippy `-D warnings` (all-targets,
> `--features daemon`) clean, **93 lib + 76 bin** tests pass, workspace checks.
>
> Fix efficacy was verified by **mutation**, not by the tests merely being green —
> six of seven mutations are caught, and the seventh is named as uncatchable:
>
> | Mutation | Caught? |
> |---|---|
> | RLY-01 remove check / loosen to 104 days | ✅ / ✅ |
> | RLY-11 remove self-pair check | ✅ |
> | RLY-02 prune on every error | ✅ |
> | RLY-05 raise cap to 60000 | ✅ |
> | RLY-10 revert retention | ✅ (build error) |
> | RLY-04 remove parent-dir fsync | ❌ **not observable from a unit test** |
>
> **RLY-10's first fix was wrong**, and the correction changes this finding's
> content. Lowering the skew ceiling by one second assumed skew applies *once*. It
> applies **twice** on independent axes — check 4b admits `issued_at <= now + skew`
> and `is_expired` then admits `now <= expires_at + skew` — so the real acceptance
> window is `ttl + 2*skew`. At the daemon's default skew of 90 that is `300 > 240`:
> a **61-second** replay window, opening for any token with `ttl >= 60`, reproduced
> by execution. RLY-10 as originally written understated the window and its proposed
> fix would have left it open behind a false compile-time guarantee. Fixed properly
> by sizing retention from the true bound (`ttl + 2*skew + 1 = 359`) and correcting
> **two** guards, one of them pre-existing.
>
> Still open in this part: RLY-03, RLY-06, RLY-07, RLY-08, RLY-09, RLY-12, RLY-13,
> RLY-14, RLY-15, RLY-16.
Scope: the relay's handling of bytes from remote hosts — `RelayHello` validation and its ed25519 trust root, the disk-persisted nonce replay store, clock-skew handling, session pairing and caps, `forward_packet` and the dataplane port demux, and the rate limiters
Out of scope for this part: `main.rs`'s CLI/wiring except where it determines reachability or effective limits, and the relay *client* in `rustynetd`

## 17. Why this area, and the threat-model shift

Parts I–III all assumed a **local** adversary: a misconfigured policy, an attacker with filesystem access, or a daemon compromised to the helper's uid. Part IV covers the one component that processes bytes from **arbitrary remote hosts that hold no credential at all**. That completes the threat-model coverage of this review.

Two honest calibrations before any finding, both of which bound how alarming the rest should read:

1. **The shipped unit binds loopback by default.** `scripts/systemd/rustynet-relay.service` sets the control bind to `127.0.0.1:4500`; an operator must widen it for the relay to serve peers. A relay's *purpose* is to be publicly reachable, so the deployed posture is public — but the out-of-box posture is not, and "remotely exploitable" below means "once deployed as intended."
2. **The relay performs no membership check at all.** `validate_hello` consults no allowlist and no signed membership state; a `node_id` is legitimate iff the control-plane key signed a token naming it. Revocation is therefore not enforced at the relay until the token expires, which is bounded by `MAX_RELAY_SESSION_TOKEN_TTL_SECS = 120` plus skew. That is a defensible short-lived-token design rather than a defect, but it is an explicit trust assumption worth recording, and it connects directly to Part I's revocation findings: the relay inherits whatever the issuer decided.

### 17.1 Prior coverage — most of this area is already tracked

This crate has ledger rows for all five source files, and the relay is the most heavily tracked area in this review. Enumerated before writing:

| ID | Sev | Status | This review |
|---|---|---|---|
| RSA-0037 | Medium | **applied** 2026-06-24 | Confirmed fixed; RLY-05 is its residual *size* dimension |
| RSA-0040 | Low | open | **Confirms** — this is where my own "no relay fuzz target" observation lands, not a new finding |
| RSA-0041 | Low | open (+2026-07-27 correction) | Confirms; RLY-08 is the log-write twin |
| RSA-0082 | Medium | open | **Confirms and quantifies** — see RLY-02 |
| RSA-0083 | Low | open | Re-confirmed still open (zero `SO_RCVBUF` sites) |
| RSA-0086 | Medium | open, *"needs first-hand confirmation"* | **Confirmed first-hand with measurements** |
| RSA-0087 | Medium | open, *"needs first-hand confirmation"* | **Confirmed, with a refinement** |
| RSA-0088 | Low | open, partially verified | **Confirmed with a measured figure** |
| AUDIT-031 | High | listed **Open**, named a ship-blocker | **Stale** — same defect as the applied RSA-0037 (RLY-14) |
| RSA-0043 / RSA-0077 | — | **both applied** | Not on this path; `verify_strict` confirmed here. RSA-0077 was migrated by `6e0d0f0` (2026-06-21) and a repo-wide grep for plain `.verify(` returns zero hits |

`hello_limiter_audit.rs` has no ledger row, which is chronological rather than an oversight: it was created 2026-07-01, after the 2026-06-18 ledger.

| ID | Finding | Severity | New? |
|---|---|---|---|
| RLY-01 | No lower bound on `issued_at_unix` — a future-dated token is accepted and replays forever after nonce prune | Medium | **New** |
| RLY-02 | One unauthenticated datagram to a live dataplane port forces O(N) work under both global locks | High | RSA-0082 (quantified) |
| RLY-03 | Signed-payload field boundaries are not bound by the signature; the relay's binary parser omits the canonicality check its text sibling has | Low-Medium | **New** |
| RLY-04 | Replay store is not parent-dir fsync'd, and a doc asserts that it is | Medium | **New** |
| RLY-05 | Pre-auth hello limiter bounds entry *count* but not key *size* — ~1 GB retained pre-authentication | Medium | RSA-0088 (measured) |
| RLY-06 | Pre-auth ed25519 verify is keyed on an attacker-chosen `node_id` and runs under the transport mutex | Medium | RSA-0086 (confirmed) |
| RLY-07 | Rate limiting is per-`node_id` only — no aggregate or per-destination cap | Medium | **New** |
| RLY-08 | Reject-path log writes are the unbudgeted twin of the budgeted notice path | Low | **New** |
| RLY-09 | Bind mutation precedes the rate-limit check; IP-only TOFU bind lets a spoofer lock out the real peer | Low | **New** |
| RLY-10 | Replay window whenever `ttl + 2*skew >= retention` — **61 s at the shipped default skew**, any `ttl >= 60`. Originally recorded as a one-second window at `skew == 120`; that undercounted because skew applies twice | Medium (corrected up from Low) | **New** — ✅ fixed `1c44ed3f` |
| RLY-11 | No self-pair rejection — the relay echoes to the sender | Low | **New** |
| RLY-12 | `node_id` written unescaped into log lines; `NodeId::new` permits newlines | Low | **New** |
| RLY-13 | Assorted: unreachable size guard, invisible tuple rejections, data-path skew inconsistency, O(n) persist per hello | Info | **New** |
| RLY-14 | Ledger maintenance: AUDIT-031 stale; three findings promotable from "needs confirmation" | Low (bookkeeping) | **New** |
| RLY-15 | `now_unix()` returns `0` on a pre-1970 clock, which makes **every token unexpired** in both `is_expired` and the data path | Low-Medium | **New** (promoted from a withdrawn defence) |
| RLY-16 | The replay store's **file-side** permission check is skipped on any non-`NotFound` stat error | Low | **New** (promoted from a narrowed defence) |

## 18. Findings

### RLY-01 — no lower bound on `issued_at_unix`, so a future-dated token is accepted and replays indefinitely (Medium, CONFIRMED by execution)

Files: `crates/rustynet-relay/src/transport.rs:348-365`, `:50-59`; `crates/rustynet-control/src/lib.rs:1886-1891`

`validate_hello` bounds the token from **above** only. Check 3 rejects `ttl_secs() > MAX_RELAY_TTL_SECS` and Check 4 rejects `is_expired(now, skew)`, which is `now > expires_at + skew`. Nothing checks `now >= issued_at - skew`. Verified by reading `:348-365` directly.

Because `ttl_secs()` is a *difference*, a token with `issued_at = now + 3_153_600_000` and `expires_at = issued_at + 120` passes both checks. And because nonce retention is measured from **insert** time (`:796`), not from the token's own window, the documented invariant at `:50-59` — retention ≥ maximum validity window — silently depends on `issued_at <= now`, which is never verified. Confirmed by execution: the hello is accepted, an immediate replay is correctly `ReplayedNonce`, and after ageing the stored stamp past the 240 s retention and running the shipped `prune`, the same captured hello is **Accepted again** — repeatable indefinitely from one capture, since the hello is plaintext UDP.

The repo's own bar already states the correct rule. `documents/SecurityMinimumBar.md:87` requires signed material be fresh *and* "not future-dated beyond clock-skew tolerance"; the relay implements only the first half.

**Reachability, stated honestly:** every in-repo token producer is clock-based, so this is not a live unauthenticated path today. `LocalRelaySessionTokenIssuer::issue_token` (`rustynetd/src/relay_client.rs:124-146`) uses `try_sign` with the local clock, and the trait takes only `ttl_secs`. But `ControlPlaneCore::issue_relay_session_token` (`control/lib.rs:2995`) passes `request.requested_at_unix` verbatim into `try_sign_at` with only a `!= 0` check and no bound against its own clock, and `parse_relay_session_token_wire` (`:2024-2028`) also permits arbitrary future timestamps. So the defect is a fail-open in the relay's *own* enforcement — it trusts a property nothing establishes.

Proposed enforcement (review-only — do NOT apply): reject `issued_at_unix > now + skew` in `validate_hello`. That single check restores the retention invariant the comment already claims.

---

### RLY-02 — one unauthenticated datagram to a live dataplane port forces O(N) work under both global locks (High; confirms **RSA-0082**, newly quantified)

Files: `crates/rustynet-relay/src/main.rs:779-782`, `:788-833`; `crates/rustynet-relay/src/transport.rs:528-548`

The mechanism is tracked as RSA-0082 (open). What this review adds is measurement and a precise statement of *why* the wrong error is in the wrong arm.

Verified by reading: `forward_packet` returns `Err(UnauthorizedSourceTuple)` at `transport.rs:534`/`:537` — and returns it **before** the rate-limit check at `:544`, so no budget is consulted. There is no per-IP limiter on dataplane ports at all (the pre-auth limiter is control-socket only). In `main.rs`, *any* `Err` from `forward_packet` lands in one arm:

```rust
Err(_) => {
    Self::prune_inactive_allocated_sockets(&allocated_sockets, &transport).await;
}
```

That prune performs, per bad packet, an O(N) pass that takes the transport mutex **and** an exclusive write lock on `allocated_sockets` — the same two locks every forward task needs per frame.

Measured against a faithful reproduction (release build, real `RelayTransport`, 4096 sessions / 4096 ports): **204.8 µs of prune work per bad packet** versus 0.042 µs for the reject itself — a **~4900× amplification** — with one core saturated by **~4884 bad packets/s ≈ 1.1 Mbit/s** of 29-byte datagrams from a single unauthenticated host. The reproduction also showed `ports_after_prune = 4096`: the session **survives**, so the same port can be hammered indefinitely.

Two details sharpen it. First, the prune-on-`Err` arm is legitimate for `SessionExpired` (that is how a stale port is reclaimed) — the flaw is that `UnauthorizedSourceTuple`, the one error an unauthenticated attacker can trigger at will and which by definition means *the session is healthy*, is lumped in with it. Second, the correct handling already exists a few lines away: the keepalive path at `main.rs:754` discards the identical error without pruning. And the codebase already fixed this exact class on the control path — `main.rs:880-891` documents removing an O(4096) scan costing "~9.5 µs/packet"; this instance is ~20× more expensive per packet and far cheaper to trigger.

Proposed enforcement (review-only — do NOT apply): match on the error and prune only for the reclamation-worthy variants, or rate-limit the prune itself.

---

### RLY-03 — signed-payload field boundaries are not bound by the signature (Low-Medium, CONFIRMED by execution)

Files: `crates/rustynet-control/src/lib.rs:1873-1884`, `:1970`, `:2045-2049`; `crates/rustynet-relay/src/main.rs:1173-1275`

`canonical_payload` is built by `format!` with `\n` and `=` delimiters and **no length prefixes**, interpolating `node_id` and `peer_node_id` raw — verified by reading `:1873-1884`. Neither field has any charset validation anywhere: `NodeId::new` only rejects empty, `is_valid_node_id_text` is a not-blank check and is not applied on this path, and the relay's parser accepts any UTF-8.

So one signature can cover two different field splits. Confirmed by execution: a token issued for `node_id = "a"`, `peer_node_id = "b\npeer_node_id=c"` produces a payload byte-identical to one for `node_id = "a\npeer_node_id=b"`, `peer_node_id = "c"`. The re-split token passes `verify_strict` with the **same 64 signature bytes**, and `handle_hello` accepts the re-split identity end to end — creating a session under a `(node_id, peer_node_id)` pair the control plane never authorized, and under a different key for both the per-node session cap and the packet rate limiter.

The instructive part is an asymmetry between two parsers of the same token. The **text** parser `parse_relay_session_token_wire` defends this properly: it rejects duplicate keys (`:1970`) and re-canonicalizes, comparing `token.canonical_payload() != payload` (`:2045-2049`). The relay's **binary** `parse_relay_token` (`main.rs:1173-1275`) has neither check, and also omits the text path's `issued_at != 0 && expires > issued` sanity checks — which is the same gap RLY-01 exploits from the other direction.

Precondition: a registered node id containing `"\npeer_node_id="`, which no layer currently forbids. Proposed enforcement (review-only — do NOT apply): reject `\n`, `\r`, and `=` in `node_id`/`peer_node_id` at parse time, or length-prefix the signed payload, or port the text parser's re-canonicalization check to the binary parser.

---

### RLY-04 — the replay store is never parent-dir fsync'd, and a doc asserts that it is (Medium, CONFIRMED)

Files: `crates/rustynet-relay/src/transport.rs:946-984`; `documents/operations/Arm32BitEmbeddedSupportReference_2026-06-23.md:919`

`persist_nonce_map` writes a temp file with mode 0600, `write_all`s, `sync_all`s **the file**, re-applies permissions, and then `fs::rename`s — and returns. Verified by reading: there is no `File::open` of the parent directory and no `sync_all` on it after the rename. A crash immediately after the rename can therefore lose the directory-entry update and drop recently accepted nonces, reopening the replay window for exactly those tokens until they expire (≤120 s + skew) — in a store whose entire purpose is crash-durable replay prevention.

Two things make this worth recording rather than shrugging at:

- **A normative doc claims the opposite.** `Arm32BitEmbeddedSupportReference_2026-06-23.md:919` states "All state writes use atomic temp→fsync→rename pattern **with parent dir fsync**." That is false for this path.
- **The repo already does it correctly elsewhere, including in this review.** Part II §11 credits `rustynet-crypto`'s `write_atomic_encrypted_key_file` for precisely the missing step — file `sync_all` before rename, then the parent directory opened and `sync_all`'d after (`crypto/src/lib.rs:1557-1558`) — and `vm_lab/orchestrator/context.rs::atomic_write_fsync` is a general primitive. So this is an inconsistency between two crates, with a doc asserting the stronger property globally.

No ledger or plan row covers replay-store durability.

---

### RLY-05 — the pre-auth hello limiter bounds entry count but not key size (Medium; confirms **RSA-0088**, newly measured)

Files: `crates/rustynet-relay/src/transport.rs:336`, `:1057`, `:1023`; `crates/rustynet-relay/src/main.rs:1128-1136`

`validate_hello`'s first check calls `hello_limiter.check(&hello.node_id)` at `:336`, **before** the signature verification at `:341`, and `HelloLimiter::check` does `counts.entry(node_id.to_owned())` (`:1057`) — an owned `String` copy of an unverified attacker-chosen value. `MAX_HELLO_LIMITER_ENTRIES = 16_384` bounds the *count*; nothing bounds key *length*. `parse_relay_hello` reads a `u16` length with no maximum, the control receive buffer is 64 KiB, and no charset or length rule for `node_id` exists anywhere in the tree.

Measured: **16,384 entries holding 1,064,960,000 key bytes ≈ 1015.6 MiB retained entirely pre-authentication**, plus per-entry map overhead. Entries drop only at capacity or on the 10 s cleanup tick, so a ~1 Gbps flood of maximum-size hellos parks ~1 GB of RSS. The ratio is roughly 1:1 so it is not an amplifier, but it converts bandwidth into an OOM-shaped resource.

This is precisely the residual of the **applied** RSA-0037 fix: the count dimension was closed, the size dimension was not. Proposed enforcement (review-only — do NOT apply): cap `node_id` length at parse time — a one-line change at `main.rs:1128-1136`.

---

### RLY-06 — pre-auth ed25519 verify keyed on attacker-chosen `node_id`, under the transport mutex (Medium; confirms **RSA-0086**, which the ledger marks unverified)

Files: `crates/rustynet-relay/src/transport.rs:336` vs `:341`; `crates/rustynet-relay/src/main.rs:604-607`, `:760`

Both of RSA-0086's mechanism claims hold at this baseline, so the finding can move off "needs first-hand confirmation":

- The limiter is keyed on the claimed `node_id` and consulted **before** the signature check, and `validate_hello_from_tuple` takes `_observed_addr` and discards it — the limiter is bound to no verified key and to no source address. Confirmed by execution: **2000/2000** hellos with rotated `node_id`s reached ed25519 verification, versus exactly 5 for a fixed `node_id`.
- The transport mutex **is** held across the verify (`main.rs:604-607` scopes the lock around the whole `validate_hello_from_tuple` call), and every forward task takes that same mutex per frame (`:760`) — so pre-auth crypto cost lands on the dataplane.

Measured cost: **25.9 µs/hello ≈ 38,600 hello/s/core**, dominated by `verify_strict`, with no disk write per packet.

**One correction to the ledger entry's premise, in the defenders' favour:** RSA-0086 says the limiter "sheds nothing under a flood of distinct ids." That is now stale — the RSA-0037 fix bounds it. At capacity the limiter prunes and returns `false`, and `validate_hello` returns `RateLimitExceeded` *before* the verify, so admitted-verify rate is capped by cap turnover rather than unbounded. Upstream, the per-IP limiter (50/IP/s over a 4096-IP table) means saturating one core needs ~773 spoofed source IPs ≈ 39k pps ≈ 5 MB/s. *(Those two rate figures are arithmetic from the constants, not measured.)*

Also confirmed: the same signature is verified **twice** per accepted hello — once in the advisory preflight and again in the commit — by the deliberate design documented at `transport.rs:244-249`.

---

### RLY-07 — rate limiting is per-`node_id` only, with no aggregate or per-destination cap (Medium, CONFIRMED by execution)

Files: `crates/rustynet-relay/src/rate_limit.rs:13`, `:18-19`, `:39-49`; `crates/rustynet-relay/src/transport.rs:21-22`

`RateLimiter.buckets` is a `HashMap<String, TokenBucket>` keyed on `node_id` — not per-session, not global. Confirmed by execution: 50 node ids at `max_pps = 10` yielded **500 aggregate accepted packets**.

Two wiring facts make this concrete. `set_rate_limits` is **never called in production** (only the example and the bench), so `RateLimiter::default()` stands: **10,000 pps / 100 Mbps per `node_id`**. And with `max_total_sessions = 4096` and `max_sessions_per_node = 8`, at least 512 distinct node ids can be live, giving a **~51 Gbps aggregate ceiling with no global bound** — against a module header at `transport.rs:21-22` that claims "Bounded resources." There is likewise no per-*destination* cap, so a victim holding its 8 permitted sessions can be fed 8 × 100 Mbps.

Honest bound: every node id requires a control-plane-signed token, so the real limit is identity issuance rather than the relay. A node's ≤8 sessions also share one bucket, which is the correct direction. The finding is that the module's stated property is aggregate-bounded resources and no aggregate bound exists.

---

### RLY-08 — reject-path log writes are the unbudgeted twin of the budgeted notice path (Low, CONFIRMED)

Files: `crates/rustynet-relay/src/transport.rs:345`, `:352`, `:363`, `:369`, `:380`, `:391`, `:398`, `:404`, `:416`, `:428`; `crates/rustynet-relay/src/main.rs:996-1013`

Every rejected hello writes at least two unconditional `eprintln!`s — one of the ten sites inside `validate_hello`, plus one at `main.rs:614`. The daemon's `PreAuthNoticeBudget` deliberately budgets the pre-parse notice datagram and the malformed-packet line, and `main.rs:996-1013` reasons explicitly about leaving the post-parse reject *datagram* unbudgeted — but the transport's own log writes sit outside that accounting entirely, and the rationale does not address them even though the code's own measurements put a log write at 1.1–7.9 µs, the same order as the `send_to` it does budget.

Fronted only by the 50/IP/s limiter over a 4096-IP table, policy therefore admits 50/IP/s × 4096 IPs = **204,800 rejected hellos/s**, and since each writes *at least two* lines, **on the order of 400,000 log lines/s** — which saturates a core and grows the journal without bound. *(Corrected 2026-07-29: an earlier revision gave ~200,000 log lines/s, conflating the hello rate with the line rate and understating it 2×. Figures are arithmetic from the two constants.)* This is the log-write sibling of RSA-0041's datagram residual.

---

### RLY-09 — bind mutation precedes the rate-limit check, and the TOFU bind is IP-only (Low, CONFIRMED by execution)

File: `crates/rustynet-relay/src/transport.rs:536-540` vs `:544`

On the unbound branch, `forward_packet` compares only `session.hello_source_addr.ip() != from_addr.ip()` and then writes `session.bound_peer_addr = Some(from_addr)` — **before** the rate limiter at `:544`. Confirmed by execution: a first packet on a new tuple binds successfully even with an empty token bucket, so claiming a session's bind costs zero rate budget.

**Corrected 2026-07-29 (meta-review):** an earlier revision called the IP-only comparison "intentional (a NAT concession, reasoned at `main.rs:4544-4549`)". Those lines are a **test** priming comment, and no NAT-concession rationale exists anywhere in the crate. Removing that false framing changes the disposition — nothing recorded blocks tightening this, and **Low may be understated**, since the lockout is permanent for the session's life at zero rate-limit cost. The consequence is that an off-path attacker who can spoof the victim's source IP and hit the right dataplane port can bind the session to a port **of the attacker's choosing**; because `bound_peer_addr` is written exactly once and there is no rebind path, the real peer then receives `UnauthorizedSourceTuple` for the rest of the session's life — until the 30 s idle reap. Both independent reviewers found this, and neither located it in the ledger.

The ordering half is a free hardening win: consulting the limiter before mutating the bind costs nothing and removes the zero-budget bind.

---

### RLY-10 — a one-second replay window opens at exactly `skew == 120` (Low, latent, CONFIRMED by execution)

Files: `crates/rustynet-relay/src/transport.rs:823`, `:50-59`; `crates/rustynet-control/src/lib.rs:1886-1891`

`prune` drops an entry when `now - inserted_at >= NONCE_RETENTION_SECS` (240), while `is_expired` retains a token when `now == expires_at + skew` (the comparison is `>`, not `>=`). With `ttl = 120`, `skew = 120`, and the hello accepted in the same second the token was issued, both conditions are true in the single second `now == inserted_at + 240`: the nonce is pruned while the token is still valid, so a replay is accepted. Confirmed by execution, together with the two controls that isolate the cause — one second later the replay is refused, and reducing skew by one second closes the window entirely.

The comment at `:50-59` asserts the clamp establishes `TTL + skew <= NONCE_RETENTION_SECS`; it holds only by *equality* (240 ≤ 240), and the mismatched comparison operators make that exactly one second too loose. Not reachable in the shipped daemon — the default skew is 90, leaving a 30 s margin, and there is no flag to raise it — but reachable by any library consumer constructing `RelayTransport` with a skew of 120. Fix is a ceiling of `MAX_RELAY_TTL_SECS - 1`, or making `prune` use `>`.

---

### RLY-11 — no self-pair rejection, so the relay echoes to the sender (Low, CONFIRMED by execution)

File: `crates/rustynet-relay/src/transport.rs:330-436`, `:319-322`, `:581`

Nothing rejects `node_id == peer_node_id`. With both equal, `node_pair_index` is keyed `(A, A)` and the forward-path reverse lookup key is also `(A, A)`, resolving to the session's **own** id, which `is_paired_with` accepts. Confirmed by execution: the self-pair is accepted and the forward target is the sender's own bound address, so the relay echoes each frame back.

Impact is bounded and should not be overstated: strictly 1:1 bytes, no amplification, and the target IP was verified against the sender's own hello, so it cannot be aimed at a third party. It also requires a validly signed token — and the containment is in fact **stronger than this finding originally stated**: the control plane has an explicit `if request.node_id == request.peer_node_id { return Err(...) }` at `control/lib.rs:3015-3019`, so an honest issuer already refuses to mint a self-pair. The relay-side assertion remains worth adding as defence in depth.

---

### RLY-12 — `node_id` is written unescaped into log lines, and newlines are permitted (Low, CONFIRMED)

Files: `crates/rustynet-relay/src/transport.rs:429-431`, `:405-407`

**Corrected 2026-07-29 (meta-review) on two points.** First, only `:428-431` interpolates the node id; `:405-407` prints the token **`scope`**, so "both sites interpolate [the node id]" was wrong. Second, the mechanism was cited to the wrong type: `NodeId::new` lives in `rustynet-backend-api` and is used by **neither** the relay nor `rustynet-control` — the relay's `node_id` is a plain `String`. As written an engineer would harden `NodeId::new` and change nothing on this path. The conclusion survives via the correct citation: `is_valid_node_id_text` (`control/lib.rs:3713-3715`) is `!value.trim().is_empty()`, and enrollment applies no validation at all, so an *enrolled* malicious peer can forge relay log lines by deliberately tripping the per-node capacity rejection. These sites are post-signature, so the id must be control-plane-signed — which bounds the attacker set to enrolled nodes and makes this a log-integrity issue rather than a pre-auth one. Everything on the daemon side is safe by contrast: it logs hex, `SocketAddr`, and `Debug` enums.

---

### RLY-13 — assorted smaller items (Info, CONFIRMED)

1. **The `MAX_PACKET_SIZE_BYTES` guard is unreachable.** `transport.rs:513` drops when `payload.len() > 65_536`, but both receive buffers are exactly `[0u8; 65536]` and `recv_from` truncates, so the condition can never hold. Harmless — but the `rate_limit.rs` ledger row justifies its PASS partly on "caller caps len at 64 KiB first", and that cap is vacuous; the safety of `len * 8` in `check_packet` actually rests on the buffer size. Worth restating in the row rather than changing code.
2. **Unauthorized source-tuple rejections are invisible.** The error is discarded at `main.rs:754` and only triggers a prune at `:779-782`; there is no counter and no log line, so an attacker probing dataplane ports leaves no trace while control-port probing is counted by `PreAuthStats`. Observability gap, and it is the same path as RLY-02.
3. **Skew tolerance is applied at admission but not on the data path.** `is_expired(now, skew)` gates the hello, but `forward_packet`, `touch_session_from_tuple`, and the cleanup pass all use a bare `expires_at_unix <= now_unix`. A session admitted on a token up to 90 s stale burns a slot and an allocated port and can never forward a byte. Fail-closed direction, but inconsistent.
4. **`NonceStore::insert` rewrites the whole file and `sync_all`s it on every accepted hello**, plus two `stat` calls via `validate_replay_store_path`. The comment at `:790-795` records removing an O(n) map clone, but the O(n) full-file fsync remains, so the O(n²) total work it describes still exists in the I/O.

---

### RLY-14 — ledger maintenance (Low, bookkeeping, CONFIRMED)

- **AUDIT-031 is stale.** It is listed `Open`/High in `SecurityAndQualityAudit_2026-06-10.md:66` and named a ship-blocker at `:32`, but it describes the same defect as RSA-0037, which has been `applied` since 2026-06-24.
- **RSA-0086, RSA-0087, and RSA-0088 can move off "needs first-hand confirmation."** All three mechanisms are confirmed at this baseline, with numbers in RLY-05/RLY-06, one premise correction (RSA-0086's shedding claim is now bounded by the RSA-0037 fix) and one refinement: RSA-0087's IPv6 lockout hits **new/unseen** sources only, because the `contains_key` test precedes the capacity branch, so established peers keep working.
- **`hello_limiter_audit.rs` needs a row** (created after the ledger). It is a report-only self-audit harness driving the real shipped `HelloLimiter` at production cap, wired as a CLI subcommand and consumed by live-lab stage 45 — it enforces nothing at runtime. Minor: it hardcodes `AUDIT_MAX_PER_SEC = 5` rather than reading `MAX_HELLOS_PER_NODE_PER_SEC`; the two are equal today, so the audit is honest by coincidence rather than by construction.
- **Constant drift worth pinning:** the code default dataplane port range and the shipped systemd unit's range differ (50000-59999 vs 40000-49999). Both are internally consistent; the ledger should name which is authoritative.

### RLY-15 — `now_unix()` failing to `0` disables expiry enforcement entirely (Low-Medium, CONFIRMED by reading)

Files: `crates/rustynet-relay/src/transport.rs:861-866`; `crates/rustynet-control/src/lib.rs:1886-1891`; data path at `transport.rs:521`

**Promoted from a withdrawn defence.** §19 originally credited `now_unix` for
"failing closed to 0 rather than panicking". The meta-review narrowed that, and it
should have become a finding at the same time — this entry closes that gap.

`now_unix()` is `SystemTime::now().duration_since(UNIX_EPOCH).map(...).unwrap_or(0)`.
It is fail-closed against a *panic*, which is the repo's own framing, but with
`now = 0` the freshness logic inverts:

- `is_expired` is `now_unix > expires_at_unix.saturating_add(skew)` — `0 > anything`
  is **false**, so every token is unexpired.
- the data path's `session.expires_at_unix <= now_unix` never fires, so no session
  is ever reaped for expiry.

So a clock that fails to initialise does not merely lose freshness — it disables
the 120 s token TTL that bounds every other relay guarantee, including the
maximum session lifetime credited in §19.

Reachability is genuinely low: it needs a clock strictly before 1970, which on a
normal host does not happen. It is recorded because the repo explicitly targets
RTC-less Raspberry Pi Zero 2 W-class hardware for relay and exit nodes
(`Requirements.md:141-143`), where an uninitialised clock at boot is the expected
state rather than a fault.

Proposed enforcement (review-only — do NOT apply): make the clock failure explicit
— return `Result` and fail closed at the call sites, or substitute a sentinel that
makes every token *expired* rather than unexpired, so a broken clock denies rather
than admits.

### RLY-16 — the replay store's file-side permission check is skipped on a stat error (Low, CONFIRMED by reading)

File: `crates/rustynet-relay/src/transport.rs:909-925`

**Promoted from a narrowed defence**, for the same reason as RLY-15. §19 credited
the replay-store path check as requiring `mode & 0o077 == 0` "for both file and
parent". That is unconditionally true for the parent, which propagates its error
with `?`. For the *file* it is not: on any `symlink_metadata` error other than
`NotFound`, the permission check is skipped and only a warning is logged.

Unlike most findings here, this carries a **documented rationale** — the comment
states that `NotFound` is expected on first run and that "the parent directory is
the relevant security surface and is checked below." That reasoning is defensible,
so this belongs in the same category as CRY-08 and CTL-03: a recorded decision, not
an oversight. The finding is narrow — that the *blanket* claim "fails closed" is
wrong, and that a permission-denied or I/O error on the file is silently tolerated
in a store whose integrity is the whole replay defence.

Proposed enforcement (review-only — do NOT apply): treat a non-`NotFound` stat
error as fail-closed, or keep the skip and narrow the surrounding documentation so
nobody relies on the stronger reading. **This is a DECISION, not a defect fix.**

## 19. Defences that hold — verified, for the record

This is the best-defended area in the review, and several of my own attack hypotheses were refuted outright:

1. **No unauthenticated write into the replay store.** The nonce is checked at `:368`, *after* signature verification at `:341`, and `contains` is a read-only lookup; the insert happens only in the commit path. Confirmed by execution: 50 bad-signature hellos leave the store empty. My "cheap unauthenticated disk write" hypothesis is **refuted**.
2. **Signature coverage is complete.** `canonical_payload` signs version, `node_id`, `peer_node_id`, `relay_id`, scope, `issued_at_unix`, `expires_at_unix`, and nonce; the hello carries no field outside the token, and the source address and allocated port come from the UDP header and the daemon rather than the attacker. My "field outside the signature" hypothesis is **refuted** — RLY-03 is about boundaries *within* the payload, not a missing field.
3. **`verify_strict` is used**, and a repo-wide grep for plain `.verify(` returns zero hits in `crates/` — RSA-0043's assertion holds here.
4. **Pre-auth ordering is cheapest-first and correct.** Limiter → signature → TTL → expiry → nonce read → `ct_eq` bindings → capacity. No session, no nonce entry, no disk write, and no port allocation happens pre-auth; a shipped test pins that the preflight does not consume the nonce.
5. **Session identity is the allocated port, not a guessable id.** Ciphertext frames carry no session id — `spawn_forward_task` captures it at spawn time — so learning a session id grants nothing on the data path. `SessionId` is 128 bits from `OsRng` with a fail-closed error variant and no degraded fallback.
6. **Source-tuple enforcement is real; there is no rebinding or takeover.** `bound_peer_addr` is written exactly once; a second port on a bound session is refused and the original tuple keeps working.
7. **No third-party reflection and no amplification on the data path.** The forward target is always the *peer's* own verified bound address, the target type carries no payload by construction, and the daemon sends exactly the received slice — strict 1:1 bytes and packets. A sender cannot choose the destination host.
8. **Pairing is symmetric and cannot evict a third party.** `node_pair_index` is only ever keyed `(node_id, peer_node_id)`, both `ct_eq`-bound to the signed token, so `remove_session_for_pair` can only replace the same pair. Confirmed by execution — a re-hello left the other peer's session intact. My "eviction primitive" hypothesis is **refuted**.
9. **Caps refuse rather than evict, and a single credential cannot fill the table.** At the global cap the newcomer is refused; the per-node cap is 8, so filling 4096 slots needs ~512 distinct signed identities, and an unauthenticated attacker gets zero.
10. **Half-open and idle timeouts cannot be defeated by keepalives.** `is_stale_half_open` uses `established_at`, written only at creation, and `touch_session_from_tuple` refuses to refresh an unbound session. My "half-open forever if touched" hypothesis is **refuted**. Maximum session lifetime is bounded by the 120 s token TTL regardless of traffic.
11. **Eviction is complete — no partial removal.** Sessions, pair index, rate-limiter buckets, hello-limiter windows, and allocated sockets plus their tasks are all reclaimed, with nonces deliberately retained for the replay window. No stale routes, no leaks.
12. **No error reaches a data-path sender**, so there is no session-id or node-id oracle; control-path rejects collapse to one generic datagram and `RejectReason` never leaves the process. My "error oracle" hypothesis is **refuted**.
13. **Token-bucket arithmetic is correct.** Monotonic `Instant` (not `SystemTime`), saturating `duration_since` so no backwards-time credit, all-`f64` with no integer truncation, both dimensions capped, no free-packet edge, and burst is exactly one refill period.
14. **The replay store fails closed and is path-validated.** Load and startup-prune failures abort the daemon; insert failure rejects the hello and rolls back the in-memory entry; the path check requires a regular non-symlink file with `mode & 0o077 == 0` for the parent (fail-closed) and, **with one documented exception**, for the file: on any `symlink_metadata` error other than `NotFound` the file-side permission check is *skipped* with only a warning, on the recorded rationale that the parent directory is the relevant security surface — so "fails closed" is accurate for the parent and for load/insert, but not unconditionally for the file check; persist is temp-then-rename with 0600 applied at open and again after. The one non-fail-closed path — a cleanup-tick prune failure — is safe in the replay direction because it *retains* nonces.
15. **Mostly-correct choices, with one correction:** `now_unix` returns `0` instead of panicking on a pre-1970 clock — which is fail-closed against a *crash* (the repo's own framing) but **fails OPEN on freshness**: with `now = 0`, `is_expired`'s `now > expires_at + skew` is false for every token, and `forward_packet`'s `expires_at_unix <= now_unix` never fires, so nothing expires. Low reachability (needs a clock strictly before 1970), but the repo explicitly targets RTC-less Raspberry Pi Zero 2 W-class hardware. Also correct: skew is clamped downward with a warning; `set_max_total_sessions` propagates its error and aborts startup; `cleanup_idle_sessions` is driven on a 10 s timer and a zero interval is rejected; the verifier key path is validated absolute, regular, non-symlink, `mode & 0o022 == 0` including its parent; the health endpoint is loopback-enforced and exposes only aggregate counters; and the serialized control loop closes the preflight/commit TOCTOU on the nonce.

## 20. Suggested triage order for Part IV

1. **RLY-02** — match on the error variant instead of pruning on any `Err`. Smallest change, largest measured effect, and it removes the cheapest total-denial lever in the system.
2. **RLY-05** — cap `node_id` length at parse time. One line, closes ~1 GB of pre-auth memory and the residual of an already-applied fix.
3. **RLY-01** and **RLY-03** together — both are missing sanity checks the codebase already implements elsewhere (the bar text for RLY-01, the text parser's re-canonicalization for RLY-03), so both are ports rather than designs.
4. **RLY-06** — key the pre-auth limiter on the source IP rather than the claimed identity, and consider moving the verify out from under the transport mutex.
5. **RLY-04** — add the parent-dir fsync using the existing primitive, and correct the doc that claims it is already universal.
6. **RLY-07** — add a global bucket, or amend the module header's "bounded resources" claim to match reality.
7. **RLY-08, RLY-09** — the log budget and the limiter-before-bind reorder; both cheap.
8. **RLY-10 … RLY-14** — latent, informational, and bookkeeping; RLY-14 is ledger edits only.
9. **RSA-0040** — the relay still has no fuzz target, which is the one gap that would have found RLY-03 mechanically. Worth pairing with the Part I fuzz recommendation.

## 21. Reproduction (Part IV)

```bash
git -C ~/Desktop/rustynet rev-parse --short HEAD   # expect 22847b12
cargo test -p rustynet-relay                       # expect 84/84 green
```

CONFIRMED-by-execution findings were verified two ways, both entirely outside the
repository. For the auth path, `transport.rs`/`session.rs`/`rate_limit.rs` were
copied verbatim into a scratch crate with a path dependency on the real
`rustynet-control`, plus a child module so private items are drivable; 12
adversarial tests were added and the suite ran 93 passed / 0 failed. For the
dataplane, a faithful reproduction with 4096 live sessions and ports measured
RLY-02's prune cost and RLY-05's retained memory. Rate figures derived by
arithmetic from constants rather than measured are labelled as such inline.

---

# Part V — `rustynet-control` as the trust issuer

Crate baseline: `crates/rustynet-control/src/lib.rs` (8192 lines). **Baseline drift:** Parts I–IV were taken at `22847b12`; this part was verified as the tree advanced (`fe634559`, and `c5018acb` by the time of writing). Line references were re-checked at write time, but this area is under active development and refs should be treated as approximate.
Scope: the signed-artifact issuance and verification surface — `SignedPeerMap`, `SignedEndpointHintBundle`, `SignedRelayFleetBundle`, `SignedAutoTunnelBundle`, `SignedTraversalCoordinationRecord`, the relay-session-token path, enrollment, and `derive_gossip_signing_key`
Out of scope for this part: the sibling files with their own ledger rows (`membership.rs`, `enrollment.rs`, `role_audit.rs`, `scale.rs`, `persistence.rs`, `admin.rs`, `operations.rs`) except where cited

## 22. Why this area — it is what Parts I and IV delegate to

Part I established that `ControlPlaneCore`'s issuance membership gate is *unconditionally inert* in production (POL-06), and Part IV established that the relay performs **no** membership check of its own, delegating the entire decision to whoever signed the token. Both parts therefore end at the same place: the issuer. Part V audits it, following two concrete leads Part IV left behind — RLY-01 (`issue_relay_session_token` trusts a caller-supplied timestamp) and RLY-03 (the signed payload is delimiter-framed with no length prefixes).

Prior coverage, enumerated before writing: **RSA-0008** (Medium, open — issuance gated by revocation-blind `evaluate`), **RSA-0010** (Low, open), **RSA-0011** (Info, open — `TrustState` has no anti-rollback floor), **RSA-0005** (Low, open), RSA-0043 (applied), **RSA-0077 (also applied** — migrated by `6e0d0f0`; a repo-wide grep for plain `.verify(` returns zero hits, so the ledger row is stale).

| ID | Finding | Severity | New? |
|---|---|---|---|
| CTL-01 | `is_valid_node_id_text` is a non-blank check, so node-id-bearing signed payloads are delimiter-injectable | Medium (latent — enrollment is test-only) | Class tracked as **AUDIT-042**; extension to the issuance payloads is new |
| CTL-02 | `verify_signed_endpoint_hint_bundle` is the only bundle verifier with no re-canonicalization | Medium | **New** |
| CTL-03 | `SignedPeerMap` leaves `generated_at_unix` outside the signature and permits full record injection | Medium (latent) | **New** |
| CTL-04 | Enrollment evaluates credential expiry against a caller-supplied clock | Medium (latent) | **New** |
| CTL-05 | No bundle verifier checks expiry — all four accept artifacts expired for decades | Medium | **New** |
| CTL-06 | No signed artifact carries a generation, so there is no anti-rollback | Medium | Partly RSA-0011 |
| CTL-07 | Ledger maintenance: RSA-0010 and RSA-0017 are applied, not open | Low | **New** |

### CTL-01 — the node-id guard is non-blank only, and the correct guard already exists beside it (Medium-latent, CONFIRMED by execution; partly **AUDIT-042**)

**Re-rated and re-attributed 2026-07-29 (meta-review).** This finding was originally rated High and called "the single highest-leverage fix in the whole document." Both claims were wrong and are corrected here, because leaving them would have sent an engineer down a day-long path for nothing:

- **The Medium rating is right, but the reason first given for it was wrong — corrected again after Part VIII.** The first re-rating argued that `enroll_with_throwaway` and its persisting sibling have zero production callers, so the precondition was unreachable. Those two do indeed have no production callers, but they are **not** the only writers. `NodeRegistry::upsert` (`lib.rs:1354-1358`) is `pub`, is a bare `guard.insert(...)` with **no validation at all** — not even the non-blank check — and is called with operator-supplied node ids by **three shipped CLI verbs**: `auto-tunnel issue` (`rustynet-cli/src/main.rs:6892`), `dns-zone issue` (`:6999`), and `traversal issue` (`:7090`), all verified directly. Part VIII confirmed by execution that `rustynet traversal issue` registers `source_node_id = "exit-1\ntarget_node_id=victim"` and emits a **validly signed** endpoint-hint bundle carrying the injected line. So the precondition **is** reachable in production. What actually holds this at Medium is **consumer-side containment, not unreachability**: the daemon's `parse_traversal_bundle_section` (`rustynetd/src/daemon.rs:13870-13917`) enforces a strict key allowlist plus duplicate-key rejection and refuses the injected bundle, and the issuer's own `verify_signed_endpoint_hint_bundle` returns `false` on it. Recording the correct reason matters: containment can be weakened by a future consumer, whereas unreachability could not.
- **The `=` half is overstated — narrow to `\n`/`\r`.** Part VIII tested `=` on both the membership snapshot and the endpoint-hint payload: every parser splits on the *first* `=` (`split_once('=')`), so `node_id=exit-1=x` round-trips and verifies `true`. `|` and tab are likewise harmless. Only `\n` and `\r` bite, and `\r` has its own distinct effect (ENR-03).
- **The class is already tracked.** `SecurityAndQualityAudit_2026-06-10.md:422` (**AUDIT-042**, Low) records the same defect in `membership.rs` — fields embedding `node_id` "with only `trim().is_empty()` checks — no rejection of embedded `\n`/`=`" — and explicitly names the contrast with `is_single_line_payload_value`. Extending the class to `is_valid_node_id_text` and the issuance payloads is legitimate new work; calling the class itself new was not.
- **Scope contradiction, now acknowledged.** Part V's header lists enrollment as in scope *and* `enrollment.rs` as out of scope. The production enrollment surface is `rustynet_control::enrollment` plus the IPC enrollment commands — the module that would actually determine reachability — and it was **not** reviewed (it has its own ledger row, RSA-0015, open). A High rating for this finding cannot be argued without covering it.

Verified by direct reading:

```rust
fn is_valid_node_id_text(value: &str) -> bool { !value.trim().is_empty() }   // :3713-3715
fn is_single_line_payload_value(value: &str) -> bool {                        // :4007-4012
    !value.is_empty() && !value.bytes().any(|b| matches!(b, b'\n' | b'\r' | b'='))
}
```

The second function is exactly the guard needed, lives in the same file, and **is** applied to relay-fleet `relay_id`/`region`. It is not applied to node ids — which reach `\n`/`=`-delimited signed payloads. (**Corrected 2026-07-29:** the list given in an earlier revision — `:2840`, `:3088`, `:3093`, `:3151-3152`, `:3232-3233`, `:4284-4285` — is the **`is_valid_node_id_text` call-site list**, not the interpolation sites; it also omits `:2816`/`:2821`, and `:2840` is in fact a `policy_allows_node_pair` line copied in error from POL-06.). `enroll_with_throwaway` applies **no** validation to `request.node_id` before `nodes.upsert` (`:2338`, `:2358`); confirmed by execution that a node id containing `\n` and `=` enrolls successfully.

That asymmetry is the real content: relay-fleet resists the field-boundary attack and the node-id paths do not, for no reason other than which helper was called.

**Corrected scope of the fix.** An earlier revision claimed applying `is_single_line_payload_value` "closes CTL-01, CTL-02, CTL-03 and the issuance half of RLY-03 in one change." It does not. The guard rejects only `\n`, `\r` and `=` — whereas `SignedPeerMap`'s payload is **`|`-delimited**, which the guard does not reject; CTL-03's demonstrated injection went through the **`os`** field rather than a node id; CTL-03's other half (`generated_at_unix` outside the signature) is untouched by any charset guard; and CTL-02's verifier stays unsound no matter what issuance validates. The honest claim is that it closes **the node-id vector of CTL-01 and the issuance half of RLY-03**; CTL-02 and CTL-03 each need their own change.

Reassuringly, the fix is **safe to apply**: real node ids in this tree are hostname slugs (`exit-1`, `client-1`, `relay-1`), none derived from base64 or any encoding that emits `=`, so adding the guard would not reject an already-enrolled id or strand a live fleet.

### CTL-02 — one bundle verifier omits the re-canonicalization its siblings have (Medium, CONFIRMED by execution)

`verify_signed_endpoint_hint_bundle` (`:3137-3211`) cross-checks outer fields against the payload with `endpoint_hint_payload_field_matches` (`:3863-3874`), which **returns on the first occurrence of a key**. It never compares a re-serialized payload against the received bytes — whereas `verify_signed_traversal_coordination_record` (`:3265-3269`) and `verify_signed_relay_fleet_bundle_with_key` (`:1573-1580`) both do.

Worked example, executed: enroll a node whose id is `node-a\ntarget_node_id=node-victim`, issue a hint bundle for that node → `node-b`. The **legitimately issued** bundle verifies `false`, while re-framing the outer struct to `source_node_id="node-a"`, `target_node_id="node-victim"` — with the **same 64 signature bytes** — verifies `true`. Direct issuance for that pair is refused. So the only framing of those bytes the verifier accepts is one the control plane never authorized.

Reachability, stated honestly: there is no `parse_signed_endpoint_hint_bundle_wire`, so the outer struct is never reconstituted from untrusted bytes in this crate; the daemon's parser rejects duplicate keys and drops the injected payload. Exploiting it needs an in-process consumer building the struct from attacker-influenced fields, and today's consumers self-verify their own freshly issued bundles. This is a live inconsistency in a public verifier, not a live end-to-end bypass. `verify_signed_auto_tunnel_bundle` (`:3321-3367`) shares the gap with a narrower achievable re-frame.

### CTL-03 — `SignedPeerMap` signs the records but not the timestamp, and does not validate them (Medium, latent, CONFIRMED by execution)

Verified by reading `:2478-2492`: the signed payload is only `node_id|hostname|os|owner|last_seen_unix|pubkey` lines — **no version line, no `generated_at_unix`, no nonce**. The timestamp lives in the outer struct and is never signed; executed, rewriting it to `99999999999` still verifies `true`. There is no expiry, generation, or signed freshness of any kind, so a captured peer map replays indefinitely and is indistinguishable from a current one.

`verify_signed_peer_map` (`:2498-2509`) performs only a bare signature check — no field cross-check, no re-canonicalization, no duplicate-record rejection. **This is a recorded deliberate decision, not an oversight**, and honesty requires quoting it: the cited lines are themselves a comment explaining that there is "no `version=N` line to gate on", that a version prefix "would be a wire-format change that breaks compatibility with existing peer maps and is tracked as a separate followup", and — explicitly — "Do NOT add a `payload_field_matches` gate here without a coordinated wire-format change." This document honours exactly that kind of recorded decision for RSA-0003 in CRY-08, and must here too: the finding is that the *compatibility* constraint leaves a real hole, not that anyone forgot. Combined with CTL-01, executed: enrolling with an `os` field carrying `|` and `\n` produced a **verifying** map whose injected second record binds `victim-node` to the **attacker's own public key** — key substitution under a valid control-plane signature.

This is also the sharpest answer to Part I's POL-06 follow-up: `signed_peer_map` calls neither `policy_allows_node_pair` nor any membership check, and simply names every registered node. It is not merely revocation-blind, it is **policy-blind by construction**. Severity is held at Medium-latent only because the type has zero consumers outside this crate.

### CTL-04 — enrollment trusts the enrolling party's clock (Medium, latent, CONFIRMED by execution)

`EnrollmentRequest.now_unix` (`:1381`) is supplied by the enrolling party and used verbatim as the clock for the credential-expiry decision, in both the in-memory store (`:816`) and the SQL backend (`persistence.rs:341-359`). Executed on a credential expiring at 160: an honest `now_unix = 1_000_000` gives `credential expired`, while a back-dated `now_unix = 150` **enrolls**. Nothing sweeps unused expired credentials, so back-dating revives them indefinitely; the same field also sets the access-token window, and `now_unix = 4_000_000_000` mints a token accepted until 2096.

Latent, and **confirmed not to repeat on the production path (Part VIII)**: `verify_and_consume_token` takes **no clock argument** — it calls `current_unix_seconds()` internally, and every production caller (the IPC handler and the CLI) uses that trusted-clock entry point. The `_with_now` variants exist but are test-only. So this defect is confined to the unwired `ControlPlaneCore` surface. `EnrollmentRequest` has no production construction and `enroll_with_throwaway` has no callers outside tests. Answering the sub-questions directly — enrollment is authenticated only by possession of a single-use `credential_id`; there is no rate limit, nonce, or replay guard beyond the credential's use counter; and state allocation correctly happens *after* the credential is consumed, so there is no pre-auth allocation.

### CTL-05 — no bundle verifier checks expiry (Medium, CONFIRMED by execution)

None of the four `verify_*` functions (`:1524`, `:3137`, `:3216`, `:3321`) takes a `now` parameter. They validate internal timestamp *consistency* but never compare against a clock. Executed under a real 2026 wall clock: an endpoint-hint bundle and a relay-fleet bundle both dated `expires_at_unix = 260` — 1 January 1970 — verify `true`.

`SecurityMinimumBar.md:87` requires signed material be fresh *and* not future-dated beyond skew; these verifiers implement neither half, and the name `verify_signed_X` does not signal that freshness is the caller's job. The one type that does implement expiry is the relay session token, via a separate `is_expired(now, skew)` that callers must remember to call — and which is upper-bound-only, which is RLY-01.

### CTL-06 — no anti-rollback on any signed artifact (Medium; partly **CONFIRMS RSA-0011**)

No `Signed{PeerMap, EndpointHintBundle, RelayFleetBundle, AutoTunnelBundle, TraversalCoordinationRecord}` carries a generation, sequence, or monotonic counter, and no stored floor exists to compare against.

Chasing the rollback question honestly: for the four bundle types the answer is **bounded, not open** — replay is limited by `expires_at_unix` (TTL ≤ 86400 s, or ≤ 300 s for relay-fleet), and the daemon does enforce freshness, exposing `traversal_stale_rejections`, `traversal_replay_rejections`, and `traversal_future_dated_rejections` counters. The exception is `SignedPeerMap`, which has no expiry in its signed bytes at all (CTL-03) and is therefore replayable without limit — but is unwired. `TrustState`'s missing floor is already RSA-0011.

### CTL-07 — two ledger rows are stale (Low, bookkeeping, CONFIRMED)

- **RSA-0010 is applied, not open.** `issue_relay_session_token` now mints via `try_sign_at` (`:3038`) with an explicit `// RSA-0010:` rationale. Residual: the second half of the proposed enforcement was not done — `sign_at` (`:1752`) is still `pub` and not `#[cfg(test)]`-gated.
- **RSA-0017 is applied, not open.** `SqliteStore::open` rejects group/other-accessible DB files, with a negative test in `persistence.rs`.

## 23. Defences that hold (Part V)

Four hypotheses I handed the reviewer were **refuted**, which is the useful part:

1. **`verify_strict` is universal in this scope.** A grep for `.verify(` over `crates/rustynet-control/src/` returns **zero** hits; all eight verification sites use `verify_strict`, and `rustynet-dns-zone` is now `verify_strict` too, confirming RSA-0043 applied. **Correction:** an earlier revision referred to "RSA-0077's remaining plain-`verify` sites"; there are none — that finding is applied and the repo-wide grep is zero.
2. **`derive_gossip_signing_key` is sound.** Real HKDF-SHA256 with a fixed salt and a distinct domain-separation string, different from all four sibling constants; no truncation, no key reuse; both the by-value secret and the intermediate seed are zeroized. Confirmed by execution that the derived key differs from siblings and from the raw identity key.
3. **The relay-fleet bundle is the correctly-built one** — two independent controls: `is_single_line_payload_value` on the interpolated fields, *and* re-canonicalization in both the parser and the verifier. Executed: injecting `"r1\nrelay_count=99"` is refused at issuance.
4. **`split_signed_relay_fleet_wire` is solid.** Executed against seven hostile inputs — trailing data, duplicate signature line, blank line, empty-key line, leading whitespace — all rejected with distinct errors. Only CRLF is accepted, benignly (the payload is rebuilt with `\n` and is signature-identical). Parse and verify enforce the same invariant set, so there is no parse/verify asymmetry.
5. **Traversal re-canonicalization genuinely defeats the re-split**, which the reviewer expected to fail. The check forces the outer fields to account for *all* payload bytes, so any alternative split leaves the injected text inside an outer field rather than yielding a clean victim id. Executed: the clean re-split verifies `false`.
6. **The daemon's parsers contain the injection class.** All three reject duplicate keys and enforce strict allowed-key lists plus a key-charset check. A deliberate cross-type confusion attempt (injecting traversal keys into an endpoint-hint payload) was blocked by three independent barriers: an *exact* field count of 9, a nonce format mismatch (32 hex vs decimal `u64`), and duplicate-key rejection.
7. **Enrollment allocates no state before authenticating**, and nonce generation fails closed on CSPRNG failure.

Fuzz coverage: five `pub fn` text parsers in this scope have none — `parse_signed_relay_fleet_bundle_wire`, `parse_relay_session_token_wire`, `split_signed_relay_fleet_wire`, `parse_relay_fleet_payload_fields`, and the `TrustState` parser. `fuzz/Cargo.toml` already depends on this crate, so each is a three-line addition. Same class as RSA-0040.

---

# Part VI — Windows privileged and at-rest surface

Crate baseline: `crates/rustynetd/src/windows_ipc.rs` (901), `windows_key_custody.rs` (930), `crates/rustynet-windows-native/src/lib.rs` (1948), plus the Windows arms of `rustynet-crypto` and `phase10.rs`
Scope: the named-pipe privilege boundary, DPAPI key custody, and the WFP killswitch — the Windows counterparts of Part III
Out of scope for this part: Windows installer scripts (RSA-0084) and the smoke-module hygiene items (HB-1…HB-5)

## 24. Reachability — shipped and compiled, never live-exercised

This distinction governs every finding below, so it is stated once. Windows is **not** build-blocked: `rustynetd` and `rustynet-windows-native` are compiled, clippy-gated at `-D warnings`, and unit-tested on `windows-2022` on every PR. The code ships.

**Corrected 2026-07-29 (meta-review).** An earlier revision of this section claimed these paths had "never run outside a unit test", based on the *node* matrix (`live_lab_node_run_matrix.csv`, 97 rows), where `windows_named_pipe_acl` and `windows_dpapi_key_custody` are indeed `not_run` 97/97. **That was wrong**, and wrong in a way this repo has already caught once: `LiveLabFindings_2026-07-03.md:364-368` records an identical error and its correction, noting the agent "had generalized from the *node-identity* columns." The authoritative matrix is `documents/operations/live_lab_run_matrix.csv` (549 rows), verified directly:

| Stage | Result |
|---|---|
| `windows_named_pipe_acl` | **13 pass**, 529 not_run, 2 skip, 2 na |
| `windows_dpapi_key_custody` | **13 pass**, 529 not_run, 2 skip, 2 na |
| `windows_stage_bootstrap` | **66 pass**, 8 fail, 466 not_run |

So the DPAPI custody validator and the named-pipe ACL evaluator **have** executed against real Windows SDDL, in 13 distinct dated runs (2026-07-03/04/07) with evidence bundles in-tree. That materially improves this part: several `INFERRED` premises below are **checkable against those runs** rather than unverifiable, and confirming them there is the cheapest next step. `PlatformSupportMatrix.md:70-71` does genuinely exclude Windows from the release gate — that half of the original claim stands.

Nothing below is dead code. Because this host is macOS, every claim about *Win32 runtime semantics* is marked **INFERRED**; the SDDL and path string logic was extracted and executed.

Prior coverage: all three target files carry **`PASS`/`audited` ledger rows with zero findings**, so this part had a high bar to clear. Related open IDs: **RSA-0002** (Medium — but its body explicitly *carves out* the DPAPI path as "does validate SDDL"), **RSA-0025** (Medium), **RSA-0036** (Info), **AUDIT-027** (High), **AUDIT-028/029/030** (Medium/Medium/Low), **RN-06** (fixed), **RN-07** (partial). Part III explicitly excluded Windows WFP, and `windows_ipc.rs` had no findings in any namespace — both genuinely unexamined.

| ID | Finding | Severity | New? |
|---|---|---|---|
| WIN-01 | The DPAPI custody ACL gate is a three-alias substring denylist, not default-deny | High | **New** |
| WIN-02 | Named-pipe lifecycle leaves the name unowned between messages, and the client never authenticates the server | High | **New** |
| WIN-03 | WFP installs only a max-weight PERMIT that can veto the firewall block, and the assertion checks existence not scope | Medium-High | **New** |
| WIN-04 | `validate_windows_binary_path` System32 check is a substring test — UNC and user-writable prefixes pass | Medium | **New** |
| WIN-05 | PF-02 generalizes to the Windows backend | **High** (aligned to PF-02 — same root cause, one validator) | CONFIRMS PF-02 |
| WIN-06 | `validate_windows_dpapi_file` accepts an inherited DACL | Medium | **New** |
| WIN-07 | The pipe security policy type is decorative — zero production callers | Low | **New** |
| WIN-08 | Self-check pipe leaf is an unbounded prefix match | Low | **New** |
| WIN-09 | All three SDDL evaluators are blind to conditional (`XA`) ACEs | Low | **New** |
| WIN-10 | Confirmations of AUDIT-028/029/030, plus a precision correction to this document's own CRY-05 | Info | Mixed |

### WIN-01 — the enforcing DPAPI custody ACL gate is a denylist (High, CONFIRMED by execution)

Verified by direct reading of `crates/rustynet-crypto/src/lib.rs:1011-1042`. The entire ACL test in `validate_windows_dpapi_root` and `validate_windows_dpapi_file` is a substring check: require `D:P` (root) or `D:` (file), then reject exactly three literals — `;;;WD)`, `;;;AU)`, `;;;BU)`.

This is the whole security boundary, by the code's own account: `store_in_windows_dpapi` states that NTFS ACLs on the custody directory "are the access boundary" and that DPAPI LocalMachine encryption only protects against off-machine extraction. With `CRYPTPROTECT_LOCAL_MACHINE` and null entropy (AUDIT-028), **any local principal who can read the blob can decrypt it** — so a three-entry denylist is all that stands between an unprivileged local user and the WireGuard private key.

Executed against the extracted logic, all of these are **accepted** where they should be rejected: a single unprivileged user SID, `IU` (every interactive logon), `BG` (Guests), `AN` (Anonymous), `AC` (all application packages), and three further spellings of Everyone itself — `(XA;;FA;;;WD;(TRUE))`, `(A;;FA;;;WD;(X))`, `(OA;;FA;g1;g2;WD)`. The `;;;WD)` marker requires the SID to be followed immediately by `)`, which is why the alternate Everyone spellings slip past.

Worked example: an administrator or repair script runs `icacls C:\ProgramData\RustyNet\secrets\key-custody /grant alice:(OI)(CI)R`. The validator returns `Ok`, `alice` reads the blob, calls `CryptUnprotectData` with no entropy, and recovers the key. `windows-key-custody-check` also reports green.

**This is not RSA-0002.** That entry's body explicitly excludes the DPAPI path on the grounds that it *does* validate SDDL. It validates SDDL; it does not validate it soundly.

The finding's force is the contrast: `windows_ipc.rs:285-294` implements exactly the right shape — a **default-deny allowlist** requiring the allow-ACE principal set to be a subset of `{SY, BA, service SID}`, plus owner and group pinning. The named-pipe boundary got default-deny; the key files got a denylist. Proposed enforcement (review-only): port the `windows_ipc.rs` pattern to both validators.

Fair mitigation, and it matters: an *unhardened* directory fails closed. A default-inherited `C:\ProgramData` child grants `Users` read and is not protected, so it fails both the `D:P` requirement and `;;;BU)`. WIN-01 requires a directory deliberately hardened to a wrong-but-not-well-known principal — not the out-of-box state.

### WIN-02 — the pipe name is unowned between messages, and the client never authenticates the server (High; server-side CONFIRMED by reading, Win32 semantics INFERRED)

`serve_named_pipe_one_message_authorized` creates the pipe, serves **one** message, and drops the handle; `daemon.rs:10050-10096` calls it in a bare `loop { … }` with no persistent instance, no pre-creation, and no backoff. Between close and the next `CreateNamedPipeW` there is a window in which zero instances of the name exist. Since the NPFS root permits any authenticated user to create a pipe name (INFERRED — documented Windows behaviour), an attacker looping on `CreateNamedPipeW` wins that race — and because the daemon passes `FILE_FLAG_FIRST_PIPE_INSTANCE`, its own re-create then fails permanently. The flag that correctly prevents startup squatting becomes the mechanism that locks the daemon out afterwards, and the error path retries immediately, adding a CPU spin and log flood.

Compounding it, the client performs **no server authentication**: `call_named_pipe` uses `CallNamedPipeW`, which cannot request `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, and named-pipe clients default to `SecurityImpersonation` (INFERRED). So a squatting server can impersonate an arriving administrative client.

Note the asymmetry this exposes: the operator-run `collect_windows_named_pipe_acl_report` *would* detect a squat, because its evaluator rejects a non-`SY` owner — but that is a diagnostic, not something the client consults before talking. Proposed enforcement (review-only): hold one persistent listening instance so the name is never unowned; use `CreateFileW` with `SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS` plus a `GetNamedPipeServerProcessId` token check on the client side; add bounded backoff.

### WIN-03 — WFP has no block filter, and the killswitch assertion checks filter existence rather than scope (Medium-High; CONFIRMED by reading, WFP arbitration INFERRED)

There is **no `FWP_ACTION_BLOCK` anywhere in the repository**. Windows blocking is `netsh advfirewall … blockoutbound`; WFP contributes exactly one filter, a **permit**, installed at `weight = u16::MAX` with `FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`. On a permit, `CLEAR_ACTION_RIGHT` strips lower-weight sublayers of the right to veto — so this filter can override the Windows Firewall default-block. That is the WFP analogue of pf's first-match-`quick` from Part III.

Its only condition is `FWPM_CONDITION_IP_LOCAL_INTERFACE == luid`, derived from `interface_alias_to_luid(&self.interface_name)`, and **nothing validates that the alias is the tunnel adapter rather than the physical NIC**. Meanwhile `assert_killswitch` verifies the netsh rules and every profile's `DefaultOutboundAction`, plus `wfp_tunnel_permit_present()` — which is `FwpmFilterGetByKey0` on two fixed GUIDs, i.e. **pure existence**.

So the answer to Part III's question, transposed: **yes.** A filter set installed with `interface_name = "Ethernet"` yields both GUIDs present, all netsh rules correct, every profile default-block — `assert_killswitch` returns `Ok` — while a max-weight `CLEAR_ACTION_RIGHT` permit passes all egress on the physical NIC. Green killswitch, cleartext egress. PF-01 plus PF-05, reproduced on the platform Part III excluded.

Honest severity calibration: unlike macOS, **no privilege boundary is crossed** — `apply_wfp_tunnel_permit` runs in-process in a daemon already executing as SYSTEM, so a compromised daemon gains nothing by lying. The live weight is therefore (a) a typo or misconfiguration in `interface_name` silently disables the killswitch while every assertion reports green, and (b) the assertion is structurally incapable of detecting a permissive filter, so the class stays invisible. Secondary and **INFERRED**: both sublayer and filters are `PERSISTENT`, so a stale permit keyed to a LUID the OS later reassigns to a different adapter would hold veto power from boot — narrowed by the fact that LUIDs encode `IfType`, so collisions are confined to same-type adapters.

### WIN-04 — the System32 check is a substring test (Medium, CONFIRMED by execution)

`phase10.rs:6366-6440` gates the `netsh.exe`/`powershell.exe` path that the SYSTEM-running daemon executes, resolved from an environment variable. Its own comment names the threat as "equivalent to RCE as SYSTEM". Executed against the extracted logic:

| Path | Accepted |
|---|---|
| `C:\Windows\System32\netsh.exe` | yes (intended) |
| `\\attacker-host\share\Windows\System32\netsh.exe` | **yes** — UNC satisfies the absoluteness test |
| `C:\Users\Public\Windows\System32\netsh.exe` | **yes** — world-writable prefix |
| `C:\Windows\System32\..\Temp\evil.exe` | no (`..` caught) |

The check only asks whether `\windows\system32\` appears *anywhere* in the lowercased string. `C:\Users\Public` is world-writable by default, so an unprivileged user can pre-stage the payload; the remaining gate is service-environment write access. Compounding: no Authenticode verification is performed before execution — `verify_authenticode_chain` is reachable only from a CLI report, consistent with open S3-10. Proposed enforcement (review-only): resolve `%SystemRoot%` via `GetSystemDirectoryW` and require a canonicalized **prefix** match; reject UNC unconditionally; verify Authenticode before first exec.

### WIN-05 — PF-02 generalizes to Windows (Medium, **CONFIRMS PF-02**)

Windows uses the same unbounded `ManagementCidr`. `windows_firewall_allow_ssh_out_args` renders `dir=out action=allow protocol=tcp remoteport=22 remoteip={cidr}` with **no interface scoping**, and it fires whenever `fail_closed_ssh_allow` is set — not gated on strictness, exactly as PF-02 describes for macOS. `ssh_cidr=0.0.0.0/0` therefore opens unrestricted off-tunnel TCP/22 on Windows too, and the PowerShell assertion checks only that each egress rule is Allow/Outbound/Enabled, never its scope.

**PF-02 is therefore confirmed on all three platforms** — macOS pf, Linux nftables, and Windows netsh — from one unbounded validator. That materially raises its priority: the single fix at `ManagementCidr::from_str` recommended in Part III now covers three backends.

### WIN-06 — `validate_windows_dpapi_file` accepts an inherited DACL (Medium, CONFIRMED by execution)

The file check tests `contains("D:")` where the root check tests `contains("D:P")`. `"D:"` is satisfied by essentially every SDDL Windows emits, including `D:AI` (auto-inherited). The blob is created by `write_windows_dpapi_blob` with a plain `create_new` and **no explicit DACL**, so it carries whatever it inherits, and the read-side check cannot tell. This is the DPAPI-blob analogue of RSA-0025's write-time gap at a different site.

### WIN-07 … WIN-09 — smaller items (Low, CONFIRMED)

- **WIN-07:** `WindowsNamedPipeSecurityPolicy`, `WindowsNamedPipeClientFacts`, and `is_client_authorized` (`windows_ipc.rs:41-136`) have **zero production callers** — only definitions and two unit tests. The runtime decision is a separate hardcoded `is_local_system || is_builtin_administrator || matches_service_identity` that never receives the policy. Setting `allow_builtin_administrators: false` would omit the ACE but leave the authorization OR intact, and the tests would still pass — false assurance that the policy governs the boundary. Same "dead security control" pattern as POL-10 and CRY-09.
- **WIN-08:** the self-check pipe leaf accepts any suffix beginning `rustynet\rustynetd-privileged.check-`, and the charset allowlist permits `\` and `.`. Executed: `…check-attacker-controlled-anything` and `…check-\..\..\evil` both validate, defeating the stated purpose of pinning the reviewed leaf. Whether NPFS grants `..` traversal semantics is **INFERRED, low confidence**; the unbounded-suffix property itself is confirmed. This one is cross-platform and ungated.
- **WIN-09:** all three SDDL evaluators match the ACE type token exactly (`== "A"`), so conditional-allow `XA` ACEs never match. Executed: `(XA;;GA;;;WD;(TRUE))` appended to an otherwise-canonical pipe DACL is accepted by **the named-pipe evaluator too** — the one that otherwise held everything. Requires `WRITE_DAC` on the object already, so it is a drift-detection gap rather than a primary vector.

### WIN-10 — confirmations, and a correction to this document (Info/Medium)

- **CONFIRMS AUDIT-028:** `dpapi_protect` passes `null()` for `pOptionalEntropy`, and every production call site uses `LocalMachine` scope; `CurrentUser` is defined and never used. `dpapi_unprotect` also discards the description, so nothing binds a blob to its intended key id — blobs are freely substitutable within the directory.
- **CONFIRMS AUDIT-029:** the DPAPI plaintext is `to_vec()`'d then `LocalFree`'d with no zeroization of the OS buffer.
- **CONFIRMS AUDIT-030:** `to_wide` still truncates at an interior NUL, so an `inspect_file_sddl` target can diverge from the path actually opened.
- **Correction to this document's CRY-05.** Part II states that `CryptoError::PermissionValidationUnavailable` is "defined but never constructed." That is true of `validate_key_custody_permissions`, but the variant **is** constructed at `crypto/src/lib.rs:1016` and `:1033` — verified directly. CRY-05's text has been narrowed accordingly; the substance of CRY-05 (the `cfg(not(unix))` no-op) is unaffected.

## 25. Defences that hold (Part VI)

The named-pipe boundary is the best-built surface in this part, and both of the hypotheses I handed the reviewer about it were **refuted**:

1. **The pipe is not openable by an unprivileged user.** The SDDL is `O:SYG:SYD:P` plus `(A;;GA;;;SY)(A;;GA;;;BA)` and an optional service SID — no `Everyone`, no `Authenticated Users` — and `PIPE_REJECT_REMOTE_CLIENTS` is set, so the kernel refuses remote clients.
2. **The server does authenticate its client**, genuinely: `ImpersonateNamedPipeClient` → `OpenThreadToken` → `TokenUser`/`TokenGroups` SID comparison, with `RevertToSelf` in a `Drop` guard so impersonation is dropped on every path including early return.
3. **UAC-filtered admin tokens are handled correctly** — the group check requires `SE_GROUP_ENABLED` *and* `!SE_GROUP_USE_FOR_DENY_ONLY` before `S-1-5-32-544` counts, with named tests. This is frequently got wrong; it is right here.
4. **The named-pipe evaluator is a real default-deny allowlist** and resisted everything thrown at it except WIN-09's conditional ACEs. Executed: an appended unprivileged SID, `IU`, an inherited non-`D:P` DACL, and an attacker-owned squatted descriptor were all rejected with specific errors. Notably `--service-sid WD` does **not** whitelist Everyone, because the forbidden-principal loop runs before the allowlist loop — correct and deliberate ordering.
5. **Parse-before-authenticate is safe here, and the reasoning is documented:** the message must be read before impersonating because `ImpersonateNamedPipeClient` returns `ERROR_CANNOT_IMPERSONATE` until the first read completes — a real Win32 constraint. The read is size-capped, caps are enforced **before** decode on both directions, and the bytes never reach the handler until authorization succeeds.
6. **Only data crosses the pipe, never commands.** The request type is `Probe { protocol_version }` or `InspectRuntimePathAcl { path }` — no command strings, no argv, no rule text — and the one path that crosses is validated **twice**, at decode and again in the daemon handler, by a validator that normalizes separators and rejects Linux roots, UNC, non-absolute paths, and `..`/`.` segments before requiring membership in a reviewed-root allowlist. This is Part III's re-derivation discipline, correctly applied.
7. **The Windows killswitch apply order is fail-CLOSED — the inverse of PF-03.** It deletes the allow rules first, sets `blockoutbound`, then adds allows, so a failure at the WFP or scoped-egress step returns `Err` with the block policy already in force. I looked for PF-03's flush-before-load hazard specifically; it does not exist here.
8. **`assert_killswitch` queries real OS state**, iterating `Get-NetFirewallProfile` and requiring every profile's `DefaultOutboundAction` to be `Block` — stronger than pf's substring-presence check, and it defeats `netsh advfirewall reset` drift. Rule names are passed as PowerShell **parameters**, never interpolated into the script body. WIN-03 is that it never checks the WFP filter's *content*, not that it is a stub.
9. **`block_all_egress` explicitly removes the WFP permit**, with a comment noting that deleting the netsh rule alone "would leave the WFP permit in place and fail OPEN" — exactly the right instinct about `CLEAR_ACTION_RIGHT`.
10. **WFP mutations are transactional**, wrapping begin/commit with abort on every error path and closing the engine unconditionally, with filter deletion ordered before sublayer deletion for a documented `FWP_E_IN_USE` reason.
11. **Reparse points and junctions are rejected** on the DPAPI custody path via `symlink_metadata` + `is_symlink()`, which on Windows covers both symlink and mount-point tags (INFERRED from Rust std behaviour).
12. **Other correct choices:** the `write_windows_dpapi_blob` temp dance is not a TOCTOU because the create is `create_new`; key identifiers are restricted to `[A-Za-z0-9_-]` before the filename join, foreclosing traversal; `named_pipe_missing_error` is correctly tokenized rather than substring-matched, so a "missing pipe" drift signal cannot be misclassified as benign; and the Authenticode stub, while a real gap (RSA-0036), fails safe in direction — the thumbprint is always `None`, so pinned policy can never falsely accept.

## 26. Suggested triage order for Parts V and VI

1. **CTL-01** — apply the guard that already exists. One change closes CTL-01, CTL-02, CTL-03 and the issuance half of RLY-03; the highest-leverage fix in this document.
2. **WIN-01** — replace the DPAPI ACL denylist with the default-deny allowlist already implemented in `windows_ipc.rs`. It is the enforcing gate on the WireGuard private key, and the code itself names it as the boundary.
3. **PF-02 / WIN-05** — now confirmed on three platforms from one validator; fix at `ManagementCidr::from_str`.
4. **CTL-05** — add a `now_unix` parameter to the four bundle verifiers, or rename them so callers cannot mistake a signature check for a freshness check.
5. **WIN-02** — persistent pipe instance plus client-side server verification.
6. **WIN-03** — assert the WFP filter's content and condition, and reject a tunnel alias that resolves to the egress interface.
7. **WIN-04** — prefix-match under `GetSystemDirectoryW`, reject UNC.
8. **CTL-03, CTL-04, CTL-06** — latent because unwired; fix before anything wires them, since each becomes live the moment a consumer appears.
9. **WIN-06 … WIN-09, CTL-07, WIN-10** — bounded hygiene and ledger edits.
10. **Fuzz coverage** — RSA-0040 plus the five `rustynet-control` parsers; `fuzz/Cargo.toml` already has the dependency.

## 27. Reproduction (Parts V and VI)

Part V's CONFIRMED-by-execution findings were driven by two standalone binaries outside the repo, built against the real `rustynet-control` with an isolated `CARGO_TARGET_DIR`: they enroll node ids containing delimiters, re-frame signed bundles against the same signature bytes, and exercise the wire-splitter battery.

Part VI could not execute Windows syscalls on this macOS host. The SDDL evaluators and the path validators were extracted verbatim into a scratch program and **run**, which is what established WIN-01, WIN-04, WIN-06, WIN-08, and WIN-09. Every claim about Win32 runtime behaviour — NPFS name ownership, client impersonation defaults, WFP arbitration, reparse-point handling — is labelled **INFERRED** and should be confirmed on a Windows host before being treated as established.

---

# Part VII — IPv6 leak prevention + blind-exit dataplane (Linux, macOS)

Crate baseline: `crates/rustynetd/src/{linux_ipv6_leak.rs, macos_ipv6_leak.rs, linux_blind_exit.rs, linux_blind_exit_dataplane.rs}` — 1753 lines, **all four with zero audit-ledger rows**
Scope: what actually prevents IPv6 traffic egressing outside the tunnel on Linux and macOS, the verifiers that certify it, and the blind-exit forward-chain posture
Out of scope for this part: `linux_killswitch_boot.rs` and `linux_runtime_nftables.rs` (both already have rows, used as context only)

## 28. Why this area, and the result that reframes RN-07

`SecurityReview_2026-05-24.md` records **RN-07**: on Windows, "disable IPv6" only suppresses router advertisements while native IPv6 egress is still permitted — a real traffic leak. Its remediation (`:231`, `:516`) is to bring Windows "to **Linux parity**", so Linux is treated as the reference.

**The reference holds on the path it is credited for, and fails on a path nobody checked.** My sharpest hypothesis — that Linux suppresses rather than blocks — is **refuted**: there is not a single `accept_ra` write anywhere in `crates/` (verified directly), and `disable_ipv6=1` on `all` is a stack-level kill. RN-07's specific defect is genuinely absent from Linux *enforcement*.

But three things fall out that matter more:

1. **RN-07's own premise sentence is false on exit-serving nodes.** `SecurityReview_2026-05-24.md:118` asserts "Linux … uses an `inet` killswitch (drops v4+v6)". IPV-01 shows it does not, for any NATing exit.
2. **macOS is the *stronger* platform on family scoping, not the weaker one** — the opposite of what the remediation assumes. Anyone acting on "bring Windows to Linux parity" should target macOS's rendering discipline instead.
3. **RN-07's defect class is alive inside the Linux reference's own verifier** (IPV-04), which credits an RA-suppression rule as IPv6 egress containment.

All four files postdating the ledger's snapshot (added 2026-06-22 … 2026-07-02) is the root cause of **PF-12**, now confirmed as systematic.

| ID | Finding | Severity | New? |
|---|---|---|---|
| IPV-01 | The Linux exit own-egress accept is **family-agnostic**, so an `inet` killswitch does not contain IPv6 on any NATing exit — and the assertion *requires* that rule | High | **New**; extends RN-12, contradicts RN-07's premise |
| IPV-02 | `ipv6_parity_supported=true` removes the only working IPv6 control and replaces it with a table that does not exist | High (latent) | **New** — no security ID owns the hazard |
| IPV-03 | `nft_ruleset_has_v6_drop` credits chain `policy drop` while ignoring every `accept` above it | High | New site; CONFIRMS RN-27 / PF-05 class |
| IPV-04 | `rule_is_v6_drop` credits RA suppression, single-address, DNS-only, input-hook, unhooked and **foreign-table** drops | High | **New** — RN-07's defect relocated into the verifier |
| IPV-05 | `probe_attempted` only proves the ping binary exists; a failed pcap capture reads as zero leaks | Medium-High | **New**; withdraws an "exemplar" credit the repo currently gives these files |
| IPV-06 | The sole production IPv6 control is an unasserted, allowlist-revocable sysctl, with no Linux drift loop | Medium | **New** |
| IPV-07 | `prior_ipv6_disabled` is re-captured on every apply, clobbering the true baseline | Medium | **New** |
| IPV-08 | Blind-exit drift checks are exact-string equality — evaded by `counter`, set syntax, comments; blind to supersets and `policy accept` | Medium | **New** |
| IPV-09 | The blind-exit mesh allow is credited from any table and any chain, including unhooked and foreign ones | Medium | **New** |
| IPV-10 | The blind-exit evaluator is not on the daemon runtime assert path at all, contradicting its own module doc | Medium | **New** |
| IPV-11 | The blind-exit re-author is three `nft` invocations, not one transaction | Low-Medium | **New**, adjacent to PF-03 |
| IPV-12 | The WireGuard port allows are family-agnostic — the one rule RN-07 holds up as the narrow model | Low | **New** |
| IPV-13 | macOS `pf_rules_have_v6_block` never checks direction, interface, or anchor reachability | Low | **New** for direction/scope; precedence half CONFIRMS PF-02/PF-05 |
| IPV-14 | Orchestrator passes no `--killswitch-table`, so the nft branch evaluates a stale generation | Info | **New** |

## 29. Findings

### IPV-01 — the Linux `inet` killswitch does not contain IPv6 on an exit node (High; CONFIRMED by reading, nftables matching INFERRED)

`phase10.rs:2385-2402` adds, for every regular NATing exit, `add rule inet <table> killswitch oifname <egress> accept` — verified directly: the argv contains `oifname`, the interface, and `accept`, with **no `ip` or `ip6` qualifier**. In an `inet` table that matches **both families** (INFERRED — nftables semantics), so the node's own native IPv6 egress out the physical NIC is accepted before `policy drop` is ever consulted.

`assert_firewall_ruleset` does not merely tolerate this — it **requires** it (`:1421-1427`, "egress-interface killswitch allow rule missing while nat forwarding is active"), verified directly. So the assertion enforces the rule that defeats the containment.

Contrast macOS (`:2697-2705`): every `pass out` is explicitly `inet all` — verified, both occurrences — so IPv6 falls through to `block drop out quick inet6 all` and the terminal block **by construction**, independent of the `ipv6_blocked` flag. That is why macOS, not Linux, is the tighter reference.

Reachability today is **masked, not absent**: `phase10.rs:5307-5310` runs `hard_disable_ipv6_egress()` whenever `!ipv6_parity_supported`, and production hardcodes that false, so the sysctl covers it. The nft path becomes the only control the moment that flag flips — which is IPV-02. RN-12 already records the *DNS* dimension of this same rule; the IPv6 dimension is recorded nowhere.

### IPV-02 — flipping `ipv6_parity_supported` removes the working control and substitutes one that does not exist (High, latent)

`:5307` skips the kernel disable when the flag is true and `:5346-5350` actively *rolls back* a previously applied disable. The intended replacement — an `ip6` sibling table — is still listed as unbuilt in `PlatformImprovementBacklog_2026-05-14.md:248-252`, and the only checker of that invariant (`linux_runtime_nftables.rs:192-210`) is recorded in the ledger as "entire module is unwired in production." Apply ordering is fine, but `apply_nat_forwarding` then installs IPV-01's accept, so the post-flip end state on an exit node is: IPv6 enabled, IPv6 egress accepted, nothing checking. The *plan* is tracked; the *hazard* is owned by no security ID.

### IPV-03 / IPV-04 — the IPv6-leak verifier certifies leaks (High, CONFIRMED by execution)

Two independent defects in `linux_ipv6_leak.rs`:

**IPV-03** credits containment on `line_is_terminal_drop` (`:220`, `:237-247`) inside an egress base chain — but `policy drop` is the chain *default*, applied only after every rule fails to match, and the function never inspects rules. Fed the exact ruleset IPV-01 produces, the whole chain returns a clean pass: `killswitch_v6_drop_present=true`, `leaked=0`, `PASS containment=inet/ip6-killswitch-drop`. The module's own fixture `INET_KILLSWITCH_WITH_TERMINAL_DROP` (`:369-374`) already contains an `accept` after `policy drop` and asserts `true`, so the blind spot is **pinned as correct behaviour**. RN-27 records exactly this for `block_all_egress` and PF-05 for macOS pf; neither names this module.

**IPV-04** is the sharper one: `rule_is_v6_drop` (`:227-235`) needs only a v6 *selector* plus the substring `drop`, and `:215` evaluates it **before** any table or hook gate. All of these returned `killswitch_v6_drop_present=true`:

| Rule credited as IPv6 egress containment | What it actually does |
|---|---|
| `icmpv6 type nd-router-advert drop` | suppresses autoconfiguration — **verbatim RN-07** |
| `icmpv6 type echo-request drop` | blocks only what the `ping -6` probe measures — circular |
| `ip6 daddr 2606:4700:4700::1111 drop` | one address |
| `ip6 daddr ::/0 udp dport 53 drop` | DNS only |
| `meta nfproto ipv6 drop` on `hook input` | inbound only |
| the same in an unhooked chain | never evaluated by the kernel |
| the same in a **foreign table** | not ours at all |

So an operator who adds `icmpv6 type nd-router-advert drop` believing it stops IPv6 gets `containment=inet/ip6-killswitch-drop` while TCP and UDP over IPv6 egress freely. This is RN-07 with the platforms swapped: the Windows *implementation* has been fixed, while the Linux *verifier* still accepts the defective shape.

### IPV-05 — the evidence path fails open twice, and the repo credits these files as the exemplar (Medium-High, CONFIRMED by execution)

`linux_ipv6_leak.rs:346` / `macos_ipv6_leak.rs:242`: `let probe_attempted = ping_status.is_ok();`. `Command::status()` returns `Ok` for any process that spawned and exited, so a guest with **no IPv6 upstream at all** reports `attempted=true, reached=false, leaked=0` → clean pass. Only a genuinely absent `ping` binary is caught. That is the weak-negative anti-pattern `LiveLabCoverageAndHonestyAudit_2026-06-25.md:170` names explicitly.

`linux_ipv6_leak.rs:351-355`: the pcap read is `.unwrap_or_default()`. `tcpdump` `spawn()` succeeds for a nonexistent interface, no pcap is written, the read returns empty, and `count_pcap_datagrams("")` → `0` → "no leak". Since `--egress-iface` is orchestrator-supplied, a wrong interface name produces a clean pass. Same `unwrap_or_default()` fail-open already recorded **CRIT** for `linux_exit_nat_lifecycle.rs` in that audit's items #1/#2 — this is its unfixed twin.

**This withdraws a credit the repo currently gives.** `LiveLabCoverageAndHonestyAudit_2026-06-25.md:176-181` and `LiveLabWave0_LinuxHonestyFixes_2026-06-25.md:20-23` both hold these two files up as the *exemplary* anti-vacuous template. That credit is not earned.

### IPV-06 / IPV-07 — the sysctl is unasserted and its baseline is clobbered (Medium)

**IPV-06:** no assertion re-reads `/proc/sys/net/ipv6/conf/all/disable_ipv6`. The asymmetry is stark — `assert_nat_forwarding` *does* re-read `ip_forward` and fails closed on drift. `sysctl -w …disable_ipv6=0` is an allowlisted argv (`privileged_helper.rs:2081-2084`), necessary for legitimate rollback but revocable by a daemon compromised to helper uid, with nothing noticing. There is also **no periodic reconcile on Linux**: macOS has a fixed-interval poller, Linux runs its asserts only inside `apply_dataplane`, so an external `nft flush ruleset` goes undetected until the next apply. RN-07's own remediation demands verification in `assert_killswitch`; the reference platform never does it either.

**IPV-07:** `:2561-2568` captures the prior value unconditionally, where the IPv4 twin at `:1705-1710` guards with `if self.prior_ipv4_forwarding.is_none()` and its comment calls the unguarded form a "residue release-blocker". Second apply reads the already-set `1` and overwrites the true baseline `0`, so rollback leaves the operator's host with IPv6 permanently disabled. Fail-*closed* for leaks, so this is residue rather than a leak — but it means the captured prior is untrustworthy after the first re-enforce.

### IPV-08 … IPV-11 — the blind-exit posture (Medium / Low-Medium)

- **IPV-08:** `linux_blind_exit.rs:196-217` compares whole normalized lines with `==`. Every one of `oifname "eth0" counter packets 12 bytes 900 accept` (how nft actually renders counters), `ct state new accept`, `oifname { "eth0" } accept`, `oif "eth0" accept`, a trailing `comment "…"`, `iifname "rustynet0" accept`, `oifname "eth0" ip saddr 0.0.0.0/0 accept`, and `policy accept;` produced **zero drift reasons**. The last two are the serious ones: a **superset** allow beside the correct mesh-scoped rule is invisible, so the "scoped to the mesh CIDR" guarantee is unverified. The module doc claims the forward chain "keeps `policy drop`" — the builder never sets it and the evaluator never checks it. The repo already knows `counter` breaks naive matching (`phase10.rs:2175-2185` documents it for `assert_chain_contains`); the blind-exit evaluator uses equality, so it does not survive it.
- **IPV-09:** `:168`, `:182-192` flatten the whole ruleset with no table or chain scoping — the mesh rule is credited from an unhooked chain, from the output chain with no forward chain at all, and from a foreign table.
- **IPV-10:** the module doc says the evaluator "is what the runtime assert path and the unit tests both call." It is not — the only non-test caller is the lab subcommand. The daemon path degenerates: `assert_exit_serving` calls `assert_killswitch` + `assert_nat_forwarding`, and the latter returns `Ok(())` immediately when `nat_table` is `None`, always true for blind_exit by design. So a blind_exit node's exit-serving assertion is just the base killswitch check, and `chain_contains_all_tokens` matches tokens as independent substrings, so it **cannot distinguish** the mesh-scoped rule from an unrestricted one. macOS imports its blind-exit evaluator into the daemon; Linux does not.
- **IPV-11:** the re-author is three separate `nft` invocations in a loop. Flush succeeds, an `add` fails → the forward chain is **empty**, which is fail-closed *only because* the chain policy is drop — the property IPV-08 shows is neither set nor verified. Same shape as PF-03, opposite outcome today, resting on an unchecked invariant.

### IPV-12 … IPV-14 — smaller items (Low / Info)

- **IPV-12:** `phase10.rs:1811-1866` adds the WireGuard `udp dport`/`sport` allows with no family qualifier, so UDP/51820 egresses over IPv6 too. Every *other* parameterised allow is family-scoped. `SecurityReview_2026-05-24.md:518` cites this rule as the narrow model Windows should mirror; it is not as narrow as claimed.
- **IPV-13:** `macos_ipv6_leak.rs:144-162` credits `block drop in quick all` (inbound), a loopback-scoped block, a DNS-only block, and a ruleset where `pass out quick on en0 inet6 all` precedes the block, as IPv6 *egress* containment. It also never verifies the anchor is referenced by the main ruleset — an orphaned anchor reports identically. The precedence half is PF-02's mechanism; the direction/scope crediting is new.
- **IPV-14:** `role_validation/ipv6_leak.rs:54-59` passes no `--killswitch-table`, so it always evaluates `rustynet_g1` while the daemon rotates the generation. Conservative in effect (a real drop in `g2` is *not* credited), but it means the nft branch mis-evaluates on any rotated generation.

## 30. Defences that hold (Part VII)

Two of my hypotheses were refuted outright, which is the most useful part of this pass:

1. **Linux does not suppress-instead-of-block.** Zero `accept_ra` writes in `crates/`, verified. `disable_ipv6=1` is a stack-level kill covering statically configured addresses and pre-installed default routes (INFERRED: kernel semantics). RN-07 has no Linux twin on the enforcement path — only in the verifier.
2. **The mesh CIDR cannot be widened into an open relay — hypothesis refuted.** `validate_mesh_egress_source_cidr` *is* correctly applied on the Linux dataplane path (`linux_blind_exit_dataplane.rs:85` → `LinuxBlindExitConfig::new` → `:251`, re-validated at render). Executed: `0.0.0.0/0`, `::/0`, `0.0.0.0/1`, `8.8.8.0/24`, `100.0.0.0/8` all rejected; `100.64.0.0/10`, `10.0.0.0/8`, `fc00::/7` accepted.
3. **The nft parser's hook state machine is correct per chain** — an `input` chain following an `output` chain is not credited, and `policy drop;` on its own line after `hook input` is not credited.
4. **Table-name matching is exact** — `rustynet_g1x` is not credited for `rustynet_g1`; generation mismatch fails closed.
5. **Two of the three captures fail closed** — a `capture_proc_flag` read error yields `ipv6_disabled=false`, and a `capture_nft_ruleset` failure yields `drop_present=false`. Only the pcap read fails open (IPV-05).
6. **`read_sysctl_bool` refuses unknown values**, so a garbage or unreadable sysctl aborts the apply rather than recording a false baseline.
7. **The blind-exit NAT-absence check is the right shape** — substring over the whole normalized ruleset, table-unscoped, which for a *forbidden* item is the correct direction; it caught an injected `snat` in execution.
8. **Blind-exit input validation is solid** — identical tunnel/egress rejected, interface and table names charset- and length-bounded, argv-only with shell-metacharacter tests pinned.
9. **The blind-exit checker's expected mesh CIDR is a hardcoded constant** and the orchestrator passes no overrides, so an operator cannot talk it into blessing a wider installed rule.
10. **`build_unobservable_report` fails closed rather than skip-as-pass** — off-Linux, `nft` failure, and egress-detection failure all set `host_observable=false` → `overall_ok=false`. A genuinely better shape than the IPv6 modules', which have no such field.
11. **Apply ordering is fail-closed** — the killswitch is installed before obsolete controls are rolled back, and rollback runs stages in reverse.
12. **blind_exit irreversibility holds** — rollback re-applies the hard lock rather than relaxing to open NAT, and removal is `FactoryReset`-only with all five events pinned by test.
13. **Rules do not duplicate on re-apply** — each apply bumps the generation so the table is rebuilt, and blind_exit flushes before re-adding. Idempotence holds; drift *detection* between applies does not (IPV-06).

---

# Part VIII — Enrollment (token, ledger, admit path)

Crate baseline: `crates/rustynet-control/src/enrollment.rs`, `membership.rs`; `crates/rustynetd/src/{enrollment_token.rs, enrollment_consume.rs}`; the `enrollment` CLI verbs in `rustynet-cli/src/main.rs`
Scope: what authenticates an enrollment, how single-use is enforced and persisted, what the enrollee receives, and whether operator-supplied identifiers can corrupt signed state
Purpose: this part exists to close an **acknowledged gap** — Part V listed enrollment in scope while excluding `enrollment.rs`, and CTL-01's severity turned on it

## 31. The CTL-01 question, answered

**CTL-01's Medium rating is correct, but the reason first given for it was wrong**, and CTL-01 has been corrected in place. The discount rested on `enroll_with_throwaway` having no production callers. True, but not the only writer: `NodeRegistry::upsert` is `pub`, validates **nothing**, and has three production CLI callers. A node id containing `\n` **can** be registered in production, and `rustynet traversal issue` was shown by execution to emit a validly signed bundle carrying the injected line. What holds the severity down is **consumer-side containment** — the daemon's strict key allowlist and duplicate-key rejection — not unreachability. That distinction matters, because containment can be weakened by a future consumer while unreachability could not.

Two precisions also folded back into Part V: the `=` half of CTL-01 is **overstated** (every parser splits on the first `=`, so `=`, `|` and tab are harmless; only `\n`/`\r` bite), and CTL-04's caller-supplied-clock defect **does not repeat** on the production path.

Prior coverage: **RSA-0015** (Info, open), **RSA-0023** (Medium, applied 2026-06-24 — but both per-file rows still read `open`), **RSA-0079** (Low, open), **AUDIT-042** (Low, open), **AUDIT-011** (Low, open), **RN-26** (open), RSA-0059/RSA-0029 adjacent. No prior coverage exists for the operator CLI entry point, the TTL cap, the `<ledger>.lock` file, `load_ledger`'s permission handling, or the push-address policy.

| ID | Finding | Severity | New? |
|---|---|---|---|
| ENR-01 | `enrollment admit --node-id` with a newline **permanently corrupts the persisted membership snapshot** | Medium | CONFIRMS AUDIT-042 class; new at the operator entry point |
| ENR-02 | `NodeRegistry::upsert` has zero validation and three production callers | Medium | **New** — corrects CTL-01 |
| ENR-03 | A `\r` silently mutates an identifier across encode/decode, producing state-root drift | Medium | **New** |
| ENR-04 | `admit` burns the single-use token *before* validating the collision or loading the signing key | Medium | **New** |
| ENR-05 | The role bridge drops 8/14 capability tokens **and** grants `Anchor` from 4 tokens the canonical parser rejects | Medium | CONFIRMS RSA-0015 — whose severity rationale is wrong |
| ENR-06 | A `--roles blind_exit` typo at admit is irreversible by design, with no confirmation | Low | **New** |
| ENR-07 | On non-Unix the `<ledger>.lock` file wedges enrollment permanently after a crash | Medium (Windows) | **New** |
| ENR-08 | `load_ledger` lacks the permission gate and size cap that `load_secret` has | Low | **New** |
| ENR-09 | The persisted single-use ledger has no MAC, generation, or anti-rollback | Low | **New** (partly by design) |
| ENR-10 | No rate limit or attempt counter anywhere on the consume path | Low | **New** |
| ENR-11 | `purge_expired_against` is a genuine no-op | Info | CONFIRMS RN-26 |
| ENR-12 | The daemon never provisions the enrollment secret, contradicting the module doc | Low | **New** |
| ENR-13 | `enrollment mint --output` writes the bearer token under the default umask | Low | CONFIRMS AUDIT-011 |
| ENR-14 | Two per-file ledger rows still read `open` for an applied RSA-0023 | Low | **New** (bookkeeping) |
| ENR-15 | A stale ledger reachability claim: `build_gossip_node` is a second, production setter | Low | **New** (correction) |

## 32. The findings that matter most

**ENR-01 (CONFIRMED by execution).** `--node-id` is taken raw with no charset check and flows into `MembershipNode.node_id`, where `MembershipState::validate` only rejects blank. `canonical_payload` then writes `node.{index}.node_id={}`. Executed end to end through sign → apply → persist → reload:

- `--node-id 'minipc-2'$'\n''node.1.status=revoked'` → admit **accepted**, epoch advances, snapshot persists, and every later load fails with `duplicate field node.1.status`. The signed-update envelope is equally unparseable, so co-signing is dead too. **A single operator typo bricks the membership snapshot.**
- `--node-id 'minipc-2'$'\n''zz.injected=1'` → reloads fine but silently drops the injected line, so the stored root **≠** the recomputed root: root drift under a valid approver signature.

**ENR-04 (CONFIRMED by reading).** `execute_enrollment_admit` consumes and durably persists the token at step 1, then checks the duplicate `node_id` at step 2, builds the record at step 3, and loads the signing key at step 4. The author reasoned about this ordering for the pubkey only ("Decode the enrollee pubkey early so a malformed input fails before we burn a token"). So a wrong `--node-id`, a wrong passphrase, or an unwritable `--output` destroys a single-use token unrecoverably and forces an out-of-band re-delivery.

**ENR-05 (CONFIRMS RSA-0015, and corrects its rationale).** Executed against every token `RoleCapability::parse` accepts: **8 of 14** are silently dropped to `Client` (`anchor.gossip_seed`, `anchor.bundle_pull`, `anchor.enrollment_endpoint`, `anchor.relay_colocation`, `anchor.port_mapping_authoritative`, `anchor.port_mapping_pinned`, `serves_nas`, `serves_llm`), so `--roles anchor.bundle_pull` yields a client-only node and reports success. Worse in the other direction: `admin`, `tag:owners`, `tag:admins` and `tag:servers` — all **rejected** by the canonical parser — grant `Anchor`. RSA-0015's severity rationale reads "fail-safe — can only *drop* privilege"; that is not accurate, since `--roles tag:servers` is a plausible operator shorthand that grants a control-plane capability. Recommend re-rating from Info.

## 33. Defences that hold (Part VIII)

The enrollment token surface is the best-built area in this entire document, and four of my hypotheses were refuted:

1. **CTL-04's caller-supplied clock does not repeat here** — `verify_and_consume_token` takes no clock argument and reads the host clock internally; the `_with_now` variants are test-only.
2. **Single-use is enforced atomically; there is no check/consume TOCTOU.** RSA-0023 is genuinely applied — both the daemon and the CLI hold an exclusive `flock` across the whole `load → verify → register → write` sequence, and the HMAC is verified *before* the ledger is touched, so a tampered token never records a consume (executed: `consumed_count == 0`). The repo ships its own adversarial prover for this, including an 8-thread race case.
3. **`inspect_token` does not consume — refuted.** Executed: inspecting a fresh token leaves `consumed_count=0`, and after a real consume it correctly reports `already_consumed: true`. Nor is `enrollment verify` an unauthenticated oracle — it requires read access to the 0o600 daemon-owned secret.
4. **`=`, `|` and tab in identifiers are harmless — refuted**, which is what narrowed CTL-01.
5. **Expiry and freshness are bounded and correct.** Executed: `ttl=0` rejected, `86400` accepted, `86401` and `u64::MAX` rejected; `issued_at` more than 300 s in the future rejected; expiry is `expires_at <= now`, so there is **no off-by-one open window** — unlike RLY-01.
6. **Token hygiene is thorough** — domain separation, `subtle` constant-time tag compare, `OsRng` with fail-closed RNG handling, redacting `Debug`, `Drop` zeroizing both fields, `Zeroizing` around the base64 intermediate, and a length cap applied *before* the decode allocates.
7. **Nothing is persisted before authentication**, and the ledger write deliberately precedes peer registration so a crash cannot register a peer without a durable consume record.
8. **Authorization is layered and Admin-only** — every local IPC command clears a uid/gid gate, `EnrollmentConsume` additionally requires `NodeRole::Admin`, and the remote path pins the subject, enforces a 60 s two-sided window, uses `verify_strict`, and keeps a per-subject nonce replay set, failing closed with no verifying key.
9. **What the enrollee receives is correctly minimal** — no keys and no token, just a routing-table registration. Its identity is the raw 32-byte verifying key, never an operator string, so **the entire CTL-01 injection class is structurally absent from the IPC consume path**.
10. **The signed-update envelope is hex-framed, not delimiter-framed** (`payload_hex=<hex>`), so the record payload cannot be reframed at the envelope layer — materially better than the raw-delimited issuance payloads Part V criticises.
11. **`write_ledger` does the full `temp(0o600) → write → fsync → rename → parent fsync` sequence** — the same discipline Part II §9 credits `rustynet-crypto` for, and which RLY-04 found missing in the relay. Three data points now: crypto and enrollment do it, the relay does not.
12. **Snapshot integrity plumbing is sound** — the digest is recomputed and compared on load, `validate()` re-runs, and an attestation that does not bind to `(network_id, epoch, state_root)` is refused, as are duplicate approver ids.
13. **`BlindExit` immutability is enforced at the trust boundary**, not in an advisory helper — executed and confirmed refused. ENR-06 is a UX gap on top of a correct control.

---

## 34. Addendum — findings surfaced while remediating (2026-07-30)

Added after the fact, during the S1–S5 remediation. Kept in this document so
every finding stays in one place, and marked separately because it was not part
of the original review pass.

**Numbering note.** These were first filed as `PF-11` and `IPV-05`, which
COLLIDED with existing findings of those ids (`PF-11` is the evadable-but-
unreachable route-primitive guard; `IPV-05` is the evidence path failing open
twice). Renumbered to `PF-16` and `IPV-15` on the same day. Commit messages from
before the renumber (`3b598514`, `cecb8773`) still say `PF-11`; they mean
`PF-16`.

| ID | Problem | Severity | Status |
| --- | --- | --- | --- |
| PF-16 | `macos_blind_exit`'s own terminal-block check was presence-only — a fifth site of the PF-05 class the review did not name | Medium | **FIXED** `3b598514` |
| IPV-15 | On an exit node with DNS protection, the wide-open egress accept is ordered ABOVE the port-53 fail-closed drops, so plaintext DNS out the underlay is accepted before the drop is reached | **High** | **OPEN — needs a decision** |
| POL-15 | `selected_exit_node` is tracked twice — daemon and controller — and the restore + auto-exit paths assign only the daemon's, so the LAN-route gate can never pass in those states | Medium | **OPEN — needs a decision** |
| RLY-17 | The daemon-side clock helper carries the same false "returns 0 ⇒ fail-closed" claim as RLY-15, and its safety comes from a different check than the one the comment names | Low | **Comment FIXED; hardening open** |

### PF-16 — a fifth presence-only terminal-block check (Medium; FIXED)

`evaluate_macos_blind_exit_pf_rules` asserted only that the line `block drop out
quick all` appeared somewhere in the ruleset. pf is first-match-wins and `quick`
takes effect immediately, so an interface-wide `quick` pass above that block wins
outright while the block stays literally present. Found while fixing PF-05, and
closed with the same shared precedence walk. The pre-existing test appended its
wide-open pass *after* the block, where it is genuinely unreachable, which is why
nothing caught the hoisted case.

### IPV-15 — DNS fail-closed is void on an exit node (High; CONFIRMED by reading the call order; OPEN)

Two controls contradict each other, and the ordering decides which wins.

Both rules land in the **same** nft chain (`killswitch`, `hook output`), and both
are added with `nft add rule`, which **appends**:

1. `apply_nat_forwarding` (`phase10.rs:2445`) appends
   `oifname "<underlay>" accept` — the wide-open output-chain accept, PF-01's
   Linux twin, here confirmed in the **installer** and not merely in the
   assertion.
2. `apply_dns_protection` (`phase10.rs:2508`+) appends
   `udp dport 53 oifname != "<tunnel>" drop` and the tcp twin.

The runtime calls them in exactly that order (`phase10.rs:~5350` then `~5360`):
`apply_nat_forwarding` runs under
`exit_mode == FullTunnel || serve_exit_node`, then `apply_dns_protection` under
`protected_dns`. So on any node that is both, the accept sits at a **lower index**
than the drops, nftables takes the first match, and **plaintext DNS to a LAN or
ISP resolver egresses freely** while `assert_dns_protection` — a presence check —
reports the protection installed.

Why S2 does not catch it: the precedence walk added in S2 decides whether the
chain's *general* egress terminator is reachable, and it treats the underlay
accept as an acknowledged exception so that verifier change would not fail every
exit node closed. DNS is a **different traffic class** with its **own**
terminator, so it needs its own walk. Same defect, different class.

**Why this is a decision and not a patch.** Reordering is not obviously safe or
obviously wrong:

- The output-chain accept is arguably *intended* on an exit node: that node is
  the internet gateway, and its own locally-generated traffic legitimately
  leaves via the underlay.
- But `dns_protected` exists specifically to stop plaintext DNS to a LAN/ISP
  resolver, and it is silently void exactly where an exit node most wants it.

Plausible directions, none validated: insert the DNS drops at index 0 rather than
appending (`nft insert rule` / `add rule ... index N`); scope the underlay accept
to exclude port 53; or refuse the `serve_exit_node + protected_dns` combination
at config time and say why. Pick one deliberately — and extend the precedence
walk to the DNS traffic class afterwards so the choice is enforced rather than
assumed.

### POL-15 — `selected_exit_node` is tracked in two places that can disagree (Medium; CONFIRMED by test; OPEN)

Surfaced by fixing POL-14: the discarded `let _ =` had been hiding it.

`DaemonRuntime::selected_exit_node` and `Phase10Controller::selected_exit_node`
are **separate fields**. `IpcCommand::ExitNodeSelect` keeps them consistent — it
sets the daemon's only when `controller.set_exit_node` returns `Ok`
(`daemon.rs:8004-8016`) — but two other paths assign the daemon's field alone:

- **state restore**, `daemon.rs:~8919`: `self.selected_exit_node = snapshot.selected_exit_node;`
- **auto-exit selection**, `daemon.rs:~7626`: `self.selected_exit_node = auto_exit;`

`ensure_lan_route_allowed` reads the **controller's** copy, so in either state it
returns `ExitNotSelected` and the LAN-route grant can never be authorised, no
matter how the ACL and policy are configured. The daemon meanwhile reports an
exit node as selected.

**Confirmed, not inferred:** consuming the previously-discarded `Result` made
`daemon::tests::role_auth_matrix_runtime_is_exhaustive_and_fail_closed` fail with
`role=admin mode=manual hop=one_hop command=lan-access on message=lan-access
denied: exit node not selected` — an admin, in a supported configuration, on a
command the matrix classifies as allowed.

Reachability is what keeps this Medium rather than High: the consequence is a
*refused* grant, so the divergence fails safe. The hazard is the shape, not this
instance — two sources of truth for an authorization input, where the one the
gate reads is not the one the rest of the daemon maintains.

**Why it is a decision.** Deduplicating is the obvious answer and is not a
one-liner: the daemon's copy is what `persist_state`/`restore` serialise, the
controller's is what the ACL gate and `apply_dataplane_generation` consume, and
making restore call `controller.set_exit_node` would run a policy evaluation
during startup — which may be correct (it would fail closed on a revoked
persisted exit node) or may break boot ordering. Options: have the daemon read
through to the controller and delete its own field; make restore and auto-exit
call `set_exit_node` and handle the denial; or keep both and add an invariant
check that fails closed on divergence. The POL-14 fix currently warns on it and
declines to grant, which is safe but leaves the inconsistency in place.

### RLY-17 — the daemon-side clock twin is safe by accident, and says so incorrectly (Low; CONFIRMED by reading; comment fixed, hardening open)

Found by sweeping for RLY-15's shape across the workspace rather than by reading
the review, which cited only `relay/transport.rs` and `control/lib.rs`.

`rustynetd/src/relay_client.rs`'s `current_unix()` is the same
`unwrap_or(0)` helper, carrying nearly the same doc comment: *"Now returns 0 on
failure, which makes any relay session token's `expires_at_unix > 0` look
already-expired — fail-closed."* **That mechanism is false**, for exactly the
reason RLY-15 gives: the check is `token.expires_at_unix <= now_unix`
(`:854`), and with `now_unix = 0` no real token satisfies it, so the expiry
check does **not** fire.

**But the outcome here IS fail-closed, via a different check.** Two lines later
`:857` rejects `token.issued_at_unix > now_unix + skew`; with `now = 0` that is
true for every real token, so everything is refused as future-dated. Nothing
validates while the clock is broken.

So the daemon side is safe *by accident*. That matters for two reasons:

1. The comment names the wrong guarantee, so a reader auditing the expiry path
   would come away believing a check fires that does not. This is the POL-06
   failure mode — a doc asserting a control the code does not implement.
2. The safety rests entirely on the future-dating check, which is RLY-01's twin
   and is exactly the kind of check a future refactor might relax or move. If it
   goes, the fail-open appears with no other guard behind it.

**Scope of the sweep, for the record.** 59 production sites use the
`duration_since(UNIX_EPOCH) … unwrap_or(0)` idiom. Triaged, **58 are benign** —
temp-filename uniqueness, report timestamps, and recorded `*_at_unix` fields
where `0` is inert. Notably the two most trust-sensitive candidates,
`rustynet-control/src/membership.rs:1487` and `:2208`, are both temp-filename
uniqueness. Only this one feeds a freshness comparison. The idiom is therefore
widespread but not widely dangerous; what makes it dangerous is a freshness
consumer, and there is exactly one besides the relay's.

Remaining work: give `current_unix()` the same `Option` treatment as
`now_unix_checked()` so the daemon side is fail-closed by construction rather
than by a neighbouring check.
