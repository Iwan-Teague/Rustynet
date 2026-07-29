# Adversarial Security Review — 2026-07-29

Status: review only — **no code changed**, no enforcement applied; findings await owner triage
Audit baseline: repository at commit **`22847b12`** ("refactor(live-lab): call the key-custody report writer in-process"), on `main`
Method: rolling adversarial review, one focused area per part. Each part names its own crate baseline, scope, and reachability conclusions.

| Part | Area | Findings | Status |
|---|---|---|---|
| **I** | `rustynet-policy` — ACL / policy evaluation engine | POL-01 … POL-14 | complete |
| **II** | `rustynet-crypto` — key custody, key envelopes, signing | CRY-01 … | complete |

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
