# Adversarial Security Review — 2026-07-29

Status: review only — **no code changed**, no enforcement applied; findings await owner triage
Audit baseline: repository at commit **`22847b12`** ("refactor(live-lab): call the key-custody report writer in-process"), on `main`
Method: rolling adversarial review, one focused area per part. Each part names its own crate baseline, scope, and reachability conclusions.

| Part | Area | Findings | Status |
|---|---|---|---|
| **I** | `rustynet-policy` — ACL / policy evaluation engine | POL-01 … POL-14 | complete |
| **II** | `rustynet-crypto` — key custody, key envelopes, signing | CRY-01 … CRY-12 | complete |

This is a single rolling document by intent: the areas share the same baseline
commit and the same fail-closed/default-deny constraints, and several findings
cross-reference each other (Part I's membership gate depends on Part II's signed
key custody). Splitting them would hide those links.

Out of scope throughout: WireGuard backends, relay framing, live-lab evidence,
and the GUI.

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
| POL-05 | `LlmAccessScope` absence = maximum privilege, and three separate paths reach absence silently | Medium | Inert (see POL-13) |
| POL-06 | `is_populated()` doc advertises a removed fail-open; its live caller is **unconditionally inert in production** | Medium (re-rate) | **Yes**, issuance layer |
| POL-07 | `validate_policy_safety` is evadable and context-blind | Low | Inert (controller unwired) |
| POL-08 | `stage_revision` silently overwrites a revision — the rollback target is mutable and not content-addressed | Low (High as design) | Inert |
| POL-09 | `rollback_to` activates never-promoted revisions, bypassing canary review | Low | Inert |
| POL-10 | `PolicyRolloutController` is decorative — no accessor returns the active policy | Low (doc divergence) | Inert |
| POL-11 | Scope key format mismatch: policy emits `node:<id>`, gateway looks up bare `<id>` | Low (latent) | Inert |
| POL-12 | `scope_for` doc claims specificity tiering the code does not implement | Low | Inert |
| POL-13 | No fuzz target covers the policy engine | Low (process) | n/a |
| POL-14 | Adjacent: two daemon ACL results discarded with `let _ =` | Medium | **Yes** |

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
`policy_allows_node_pair` reduces to the revocation-blind `PolicySet::evaluate`
(`:3443`) on every issuance path — peer-map, exit-node, dns-zone, endpoint-hint,
relay-fleet, and relay-session tokens (callers `:2609`, `:2642`, `:2748`,
`:2840`, `:3028`, `:3116`).

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

### CRY-05 — Windows permission validation is a no-op on both directions (Medium; confirms **RSA-0002**)

File: `crates/rustynet-crypto/src/lib.rs:1715-1720`, plus `:1498-1511`, `:1519`, `:1532-1536`

Confirms RSA-0002. The `#[cfg(not(unix))]` branch returns `Ok(())` with
`// Windows ACL validation not yet implemented; defer to OS enforcement.` Two
details to add to the existing entry:

1. **The write side is unprotected too, not just the check.**
   `write_encrypted_key_file`'s permission-tightening block is `#[cfg(unix)]`
   (`:1498-1511`) and `write_atomic_encrypted_key_file` applies `options.mode(_mode)`
   only under `#[cfg(unix)]` (`:1532-1536`), so on Windows the key file is created
   with inherited directory ACLs, never restricted *and* never validated.
2. **The error variant the fix needs already exists and is unused.**
   `CryptoError::PermissionValidationUnavailable` (`:84`, "permission validation
   unavailable on this platform") is defined but never constructed here — which is
   exactly what RSA-0002's proposed enforcement calls for
   (`SecurityAuditLedger_2026-06-18.md:869`). The one-line fail-closed change is
   already expressible in the existing type.

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

Severity is held at *Medium-if-used* because **there is no non-test consumer** of
`from_raw` — it is dead public API. The correct shape already exists in the same
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
