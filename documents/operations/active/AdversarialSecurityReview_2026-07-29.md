# Adversarial Security Review — 2026-07-29

Status: review only — **no code changed**, no enforcement applied; findings await owner triage
Audit baseline: repository at commit **`22847b12`** ("refactor(live-lab): call the key-custody report writer in-process"), on `main`
Method: rolling adversarial review, one focused area per part. Each part names its own crate baseline, scope, and reachability conclusions.

| Part | Area | Findings | Status |
|---|---|---|---|
| **I** | `rustynet-policy` — ACL / policy evaluation engine | POL-01 … POL-14 | complete |
| **II** | `rustynet-crypto` — key custody, key envelopes, signing | CRY-01 … CRY-12 | complete |
| **III** | macOS `pf` privileged-helper boundary — killswitch rule regeneration | PF-01 … PF-14 | complete |

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

---

# Part III — macOS `pf` privileged-helper boundary (killswitch rule regeneration)

Crate baseline: `crates/rustynetd/src/macos_pf_load_spec.rs`, 1061 lines, added by `fd1b50d1` ("macos pf: close the pfctl -f privileged boundary via rule regeneration")
Scope: the `macos-pf-load` privileged builtin end to end — `MacosPfLoadSpec` encode/decode across the daemon→root boundary, anchor derivation, the three rule renderers it drives (`render_macos_killswitch_pf_rules`, `build_macos_blind_exit_pf_rules`, `build_macos_exit_nat_pf_rules`), the `assert_rule_invariants` guard, and the surrounding apply/assert ordering in `phase10.rs` and `privileged_helper.rs`
Out of scope for this part: Linux nftables killswitch paths except where they share a validator, and Windows WFP

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
with **no ledger row** showed almost all of them are lab/test tooling
(`vm_lab/`, `lab-monitor`, `live_lab_*`), which the charter explicitly places
outside the production trust path. Two were production daemon code, and this file
is the load-bearing one.

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
| PF-02 | `ssh_cidr=0.0.0.0/0` opens unrestricted off-tunnel TCP/22 — **even under `strict=true`**, and not interface-scoped | High | **New** |
| PF-03 | `apply_pf_rules` flushes the old anchor **before** loading the new one, on every reconcile — a failed load leaves egress wide open | High | **New** |
| PF-04 | The allowed `pfctl -a <anchor> -F all` arm lets the daemon empty the live killswitch anchor, bypassing the whole regeneration boundary | High (adjacent) | **New** |
| PF-05 | Killswitch assertions validate rule **presence, not precedence** — the root cause of PF-01/PF-02 being silent | Medium | **New** |
| PF-06 | Specs that pass decode but that `pfctl` rejects (iface length/keywords, `/+N` prefixes) — feeds PF-03 | Medium | **New** |
| PF-07 | `generation` is an unbounded daemon-chosen `u64` | Low-Medium | **New** |
| PF-08 | `MAX_MANAGED_PEER_ENDPOINTS = 256` is unreachable through the 16 KiB wire budget; no test pins the budget | Low | **New** |
| PF-09 | `push_list` does not bound a single over-cap list element | Low | **New** |
| PF-10 | A root `pfctl -f` on a predictable `$TMPDIR` file survives in the killswitch-precedence validator | Medium (adjacent) | **New** |
| PF-11 | `contains_forbidden_route_primitive` is evadable but unreachable — defence-in-depth only | Info | **New** |
| PF-12 | This production privilege-boundary file has zero audit-ledger rows | Low (bookkeeping) | **New** |
| PF-13 | Three round-trip tests pin render equality, not spec equality | Low (test coverage) | **New** |
| PF-14 | `reject_nonempty` is a content guard with a presence-guard name | Info | **New** |

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
pf tolerates both anchors being briefly populated — both terminators are `quick`
and identical in effect — so the overlap is strictly safer than the gap. Better
still, fold the flush into the `macos-pf-load` builtin so the helper flushes the
old anchor only after its own load succeeds, which also addresses PF-04.

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

1. **Interface-name length.** `parse_interface` (`macos_pf_load_spec.rs:509`) and
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
  and the comment at `:366-367` admits this. The killswitch equivalent *is* caught
  at decode. Direction is safe: `execute_macos_pf_load`
  (`privileged_helper.rs:996-1000`) always decodes **then** renders, while the
  standalone preflight (`:1299-1301`) is only an admission gate — so execute is
  strictly stricter than preflight.

---

### PF-07 — `generation` is an unbounded daemon-chosen `u64` (Low-Medium, CONFIRMED; one part inferred)

File: `crates/rustynet-crypto` n/a — `crates/rustynetd/src/macos_pf_load_spec.rs:155-163`, `:292`

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
≈1.6×, and (c) the module's tests assert `MAX_ARGS`/`MAX_ARG_BYTES` (`:1007-1011`,
`:1051-1052`) but **nothing asserts the frame budget** — so a future peer-cap
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
   forwarding on error. The RN-03 `let _ =` fail-open pattern is absent from this
   path.
13. **`mesh_cidr` semantics are policed, and policed well.**
   `validate_mesh_egress_source_cidr` rejects `0.0.0.0/0`, `::/0`, `8.8.8.0/24`,
   `100.0.0.0/8`, and `::ffff:10.0.0.0/104` at decode (executed), and the fix was
   generalized to macOS blind-exit, macOS exit-NAT, **and** Linux blind-exit. PF-01
   and PF-02 are precisely the parameters that did not receive this treatment.
14. **DNS ordering is correct.** With `dns_protected=true` the global DNS blocks
    (`:2644-2651`) are `quick` and precede the endpoint passes, so a hostile
    `traversal=8.8.8.8:53` cannot punch through them.

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
6. **PF-06** — align the interface bound to 15 using the existing
   `is_interface_name`, and adopt the parse-to-typed-then-re-render pattern for the
   three raw-string CIDR sites.
7. **PF-07, PF-08, PF-09, PF-11, PF-12, PF-13, PF-14** — bounded-cost hygiene;
   PF-08/PF-09 are asserts, PF-12 is a ledger row, PF-13 is three test
   strengthenings, PF-14 is a rename or a comment.
8. **PF-10** — owner of the live-lab validator: convert `write_restore_file` to the
   `write_root_owned_pf_temp` pattern or route its restore through the builtin.

## 16. Reproduction (Part III)

```bash
git -C ~/Desktop/rustynet rev-parse --short HEAD   # expect 22847b12
```

Findings marked CONFIRMED-by-execution were verified by replicating the validators
and the three renderers verbatim in a scratch crate **outside** the repository,
driving them with a hostile parameter matrix, and feeding the rendered rule text to
the host's real `/sbin/pfctl -n -f` — which is what established PF-06's three
rejection classes and confirmed that PF-01's and PF-02's renders are accepted by
pf. PF-07's anchor-ordering component is the one item left **inferred**: it needs an
on-box experiment on pf wildcard sub-anchor evaluation order that was not run.
