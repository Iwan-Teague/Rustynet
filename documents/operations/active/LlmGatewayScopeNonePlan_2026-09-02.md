# LLM Gateway `scope = None` Authorization Semantics — Decision Plan (F-1)

- **Date:** 2026-09-02
- **Status:** PROPOSED — decision input for owner gate **OG-1** (`ServiceHostingPhase2Design_2026-08-29.md` §5, "Policy default posture for 'grant without scope'"). No code changes made by this document.
- **Ground finding:** F-1 (P3) from `documents/operations/active/RepoCodeWorkHunt_2026-09-01.md`: "LLM gateway: a granted peer with no scope entry is unrestricted by design; confirm this is the intended product semantics."
- **Scope:** the `llm` service-hosting role's model/quota/rate authorization layer. The admission layer (who may talk to the gateway at all) is separately default-deny and is NOT in question here.

## 1) Current behaviour, exactly

**Admission vs. scoping.** Two layers exist and they have opposite fail directions:

- **Admission (grant) — fail-closed, verified wired.** A peer's tunnel source IP is mapped to a node id via the daemon-distributed peers map; an unmapped identity is refused (`crates/rustynet-llm-gateway/src/main.rs:328-330`), and a node id with no grant line is refused with "your admin hasn't enabled LLM access for this device (peer {node_id}; default-deny)" (`main.rs:331-334`). Grants come from `grants.v1`, one authorised node id per line (`crates/rustynetd/src/service_access_state.rs:13-24`), rendered from the signed policy snapshot by `derive_service_access_snapshot` (`service_access_state.rs:76-118`: ACTIVE membership nodes, excluding self, where `evaluate_service_access` == Allow). An unreadable/corrupt access state refuses peers fail-closed (`main.rs:322-327`). Grants are re-checked per frame and per token event (`main.rs:365-375`, `main.rs:460`).
- **Scoping (what a granted peer may do) — fail-open by design.** Three enforcement points in `crates/rustynet-llm-gateway/src/enforce.rs` all treat a missing scope entry as "unrestricted":
  - `admit_request(..., scope: Option<&LlmAccessScope>, ...)` returns `Ok(())` early when scope is `None` — any model, no quota, no rate ceiling (`enforce.rs:82-86`, checked model/rate/token paths at `:87`, `:97-104`, `:107-118`).
  - `record_tokens` only severs a stream when a scope with a limit is present (`enforce.rs:138-146`); with `None` the peer can stream unbounded tokens.
  - `visible_models` filters with `.map(...).unwrap_or(true)` — no scope ⇒ every model visible (`enforce.rs:166-174`).
  Unit tests codify all three (`enforce.rs:198-209` "no scope ⇒ unrestricted grant" with `u32::MAX` tokens; `:294` "No scope ⇒ everything visible"; `:328`/`:331` "no quota without scope").

**Who can produce `None` today.** Three sources, all live:

1. **Absent scopes file — this is the universal case today.** The gateway loader treats a genuinely missing `scopes.v1` as "no entries" (doc comment `main.rs:221-228`: "a missing scopes file leaves grants unrestricted by documented design (scopes restrict, they never grant)"). The daemon side never writes scope lines at all: `derive_service_access_snapshot` hardcodes `scopes: Vec::new()` (`service_access_state.rs:116`), with the comment "Empty for now: admin scope distribution rides the signed policy bundle later — we render nothing rather than something wrong, and an absent/empty scope entry means 'unrestricted grant' on the gateway side". **Therefore every admitted peer on every deployed llm node today is unrestricted.**
2. **A grants line with no matching selector.** Scope lookup is an exact node-id key match (`main.rs:336`); a peer present in `grants.v1` but absent from the scope map resolves to `None` (mirrors `scope_for` in `crates/rustynet-policy/src/lib.rs:350-359`, whose doc says returning `None` "leaves the grant unrestricted. That fail-open direction is deliberate here").
3. **A scope line with no restrictive keys.** Each parsed line starts from `LlmAccessScope::default()` (`main.rs:274`), whose fields are all `None`; `LlmAccessScope { allowed_models: None /* unrestricted */, max_tokens_per_window: None /* no quota */, max_requests_per_minute: None /* no ceiling */ }` (`rustynet-policy/src/lib.rs:290-299`).

**Is the scope signed?** No. `grants.v1`/`scopes.v1` are materialised artifacts whose authority is the signed snapshot they were rendered from (`ServiceHostingPhase2Design_2026-08-29.md`, "access files" row, `:33`) — but the scope half of that snapshot is never populated (`service_access_state.rs:116`), and no signed scope distribution path exists yet. Scope state is local config in every practical sense today. There is also a selector-specificity caveat (POL-12, `rustynet-policy/src/lib.rs:316-330`): specificity resolution is the caller's responsibility, and a mis-ordered selector silently resolves to a broader scope.

## 2) Requirement basis

- **`documents/Requirements.md` is silent on llm.** A verified grep for "llm" across `documents/Requirements.md` returns nothing; the llm role's requirements live in the service-hosting track (`ServiceHostingRolesRoadmap_2026-06-11.md`, `LlmNodeRoleDesign_2026-06-11.md`) and the security bar.
- **`documents/SecurityMinimumBar.md` §6.E** (service-hosting minimum bar) is the operative requirement: "changes what an **authorised** peer can reach, never who is trusted" (`SecurityMinimumBar.md:573-576`); E2 mandates per-peer service authorisation where "being inside the tunnel is necessary, not sufficient", with empty/missing/stale policy ⇒ Deny and identity taken from the authenticated tunnel source, never client-supplied (`:609-639`). E2's enforcement point is admission (`evaluate_service_access`, `crates/rustynetd/src/service_exposure.rs:257`, fed by `service_access_state.rs:90`). §6.E does not explicitly address per-peer *capability* scoping within a granted service — that silence is exactly what OG-1 asks the owner to settle.
- **AGENTS.md §3 / §10.4 (default-deny).** "Default-deny policy is mandatory across ACL, routes, and trust-sensitive flows" and "empty/missing/malformed → deny". Scoping is a trust-sensitive flow (it decides what an authenticated peer may consume), and its current missing-entry answer is "allow everything". Applying the house rule to the scope layer yields: **missing scope ⇒ deny**, not "unrestricted".
- Admission already satisfies default-deny; the conflict is only in the scope layer, which currently documents its fail-open direction as deliberate (`rustynet-policy/src/lib.rs:344-349`, `main.rs:221-228`).

## 3) Threat analysis — what unrestricted `None` permits

| # | Abuse case | Likelihood | Impact |
|---|---|---|---|
| T1 | **Granted-but-unscooped peer uses the model without limits.** Any peer with a signed-policy Allow reaches every model with no quota and no rate ceiling — not a hypothetical: the daemon renders no scope lines at all (`service_access_state.rs:116`), so this is the behaviour of every deployment today. Cost/runaway-token exposure on whatever loopback inference engine the node fronts. | High (default state) | High |
| T2 | **Mis-shipped/lost scopes file silently widens.** A deleted, truncated, or not-yet-deployed `scopes.v1` does not fail closed — it *maximally opens* ("missing scopes file leaves grants unrestricted", `main.rs:221-228`). An operator who believes "no scopes file = nothing scoped = safe" is wrong in the expensive direction. | Medium–high | Medium–high |
| T3 | **Scope removal as unauthorised widening.** Because scopes are unsigned local files, deleting one selector line (or the whole file) widens that peer to unlimited with no signed audit trail. The signed-snapshot chain that protects grants has no equivalent witness for scope narrowing. | Low–medium | High |
| T4 | **Selector-ordering widening (POL-12).** A newly added broader selector placed before a specific one silently serves the broader scope (`rustynet-policy/src/lib.rs:316-330`, `:350-359`); combined with fail-open `None` the error class extends to "entry forgotten entirely". | Low | Medium |
| T5 | **`Some([])` vs `None` asymmetry.** `allowed_models: Some(vec![])` denies every model while `None` allows every model (`rustynet-policy/src/lib.rs:290-305`); an admin tool that renders "no models configured" and then writes `None` inverts the operator's intent. Flagged in OG-1 itself. | Medium (tooling-dependent) | High |

Context worth noting: the E1 tunnel-only bind enforcement is not fully wired for the service binaries (`SecurityMinimumBar.md:578-607`; gateways start under the weaker shaped-bind check, `main.rs:163`), so the blast radius of any scope-layer openness is not strictly confined to tunnel peers in the current state. This strengthens the case for the scope layer to fail closed on its own.

## 4) Options, ranked by the decision lens (serves core goals → most secure → best long-term)

**Option A — `None` ⇒ deny-all, no opt-out.** Absent/`None` scope denies every model. Strictest and simplest to reason about, but it makes "grant full model access" inexpressible: there is no signed scope-distribution path yet (`service_access_state.rs:116` — "admin scope distribution rides the signed policy bundle later"), so until phase 2 lands, an admin who wants a peer to use any model has no way to say so. Breaks the llm role's core goal (a usable model service behind per-device policy, `LlmNodeRoleDesign_2026-06-11.md:296`) for the interim.

**Option B — `None` ⇒ deny-all, with an explicit `unrestricted` opt-out (RECOMMENDED).** Absent scope denies; the only way to reproduce today's behaviour is a scope line that says so explicitly (`unrestricted` key in the existing `scopes.v1` line grammar, which already fails closed on unrecognized keys — `main.rs:300-308`). Keeps the house default-deny invariant, keeps the grant-expressive (an admin *can* still authorise full access, deliberately and auditably), and costs little because:
- The M5 llm live-lab evidence rows have **never run** (`ServiceHostingRolesDeltaPlan_2026-06-11.md:82` — Linux M5 rows open; macOS/Windows ⛔ per platform matrix), so there are no live deployments or evidence rows to migrate; the flip is cheap now and expensive later.
- No signed scope distribution exists to break (`service_access_state.rs:116`).
- The daemon side needs no change to be safe: its always-empty scope render simply becomes deny-by-default until phase 2 wires signed scopes.
Migration impact (all enumerated, nothing hidden): (1) four codifying tests flip — `enforce.rs:198-209` (becomes "no scope denies"), `:294` (becomes "no scope ⇒ nothing visible"), `:328`, `:331`; (2) the loader gains the `unrestricted` key and rejects it combined with quota/rate keys (an unrestricted scope with a quota is a contradiction); (3) `docs`/lab profile fixtures that rely on absent-scope-unrestricted must add explicit `unrestricted` lines; (4) the CLI gains the emission surface in §5.

**Option C — keep unrestricted `None`, require an explicit acknowledging flag.** Gateway config would need e.g. `allow_unscooped_unrestricted = true` to preserve today's behaviour. Retains a fail-open default one flag away; the flag itself becomes the new "accidentally shipped" surface. Weaker than B on the most-secure axis with no long-term payoff.

**Option D — status quo + documentation only.** The behaviour is already documented (`main.rs:221-228`, `rustynet-policy/src/lib.rs:285-289`, `ServiceHostingPhase2Design_2026-08-29.md:31`), and documentation has not prevented the daemon from rendering zero scope lines — i.e. the unrestricted case is not an edge case but the universal case. Weakest; does not satisfy AGENTS.md §10.4 as applied in §2.

**Why B over A:** A is the asymptote of B minus expressiveness; B reaches the same fail-closed default while keeping the product usable before signed scope distribution exists, and it degrades gracefully into A-equivalence later (drop the `unrestricted` key once scopes ride the signed policy bundle). This resolves OG-1 in the direction of the "stricter" posture OG-1 describes, with the explicit-marker escape hatch OG-1's asymmetry warning (T5) demands.

## 5) Implementation sketch (for the recommended Option B)

- **`crates/rustynet-policy/src/lib.rs`** — keep `LlmAccessScope` as-is; flip the documented resolution contract: "no entry applies" now means *no access* (update `:285-289`, `:344-349`). Add an `unrestricted` constructor/marker so the opt-out is a first-class value, not the absence of one.
- **`crates/rustynet-llm-gateway/src/main.rs`** — loader (`load_access_state`, `:229-315`): accept a new `unrestricted` key mapping to the marker; hard-error on `unrestricted` combined with `allowed_models`/quota/rate keys (extend the existing unrecognized/contradiction handling at `:300-308`). `admitted_peer` (`:320-338`) returns a resolved scope that is *required*: grant-present + scope-absent ⇒ refuse the frame with a message that names the missing scope (mirroring the existing default-deny refusal style at `:331-334`).
- **`crates/rustynet-llm-gateway/src/enforce.rs`** — `admit_request`: `None` ⇒ `Err` (deny every model); `record_tokens`: `None` ⇒ sever; `visible_models`: `None` ⇒ empty. Preserve the current shape of the unrestricted marker path so the existing non-None tests mostly survive.
- **Fail-closed test list (first test is the headline behaviour):**
  1. missing/`None` scope ⇒ `admit_request` denies every model;
  2. `record_tokens` without scope severs the stream;
  3. `visible_models` without scope returns empty;
  4. explicit `unrestricted` admits any model with no quota/rate (the only path to today's behaviour);
  5. `unrestricted` + any limit key ⇒ loader error (contradiction fails closed);
  6. grant-present/scope-absent end-to-end through `serve_connection` ⇒ refused with the scope-missing message;
  7. existing malformed-line fail-closed tests unchanged and still pass (`main.rs:284-308`).
- **CLI surface (operators must not be able to ship `None` by accident).** `rustynet llm allow` gains mandatory scope emission: either `--models/--max-tokens/--rate` values or an explicit `--unrestricted` flag; `rustynet llm access list` renders "UNRESTRICTED (explicit)" vs "DENY (no scope line)" distinctly so an admin reading the list can see the posture. (The current CLI llm verbs are recorded in `ServiceHostingRolesDeltaPlan_2026-06-11.md:81`; the exact argv surface there was not re-verified in this worktree — treat as UNVERIFIED and confirm at implementation time.)
- **Gate:** extend `scripts/ci/llm_default_deny_gates.sh` with the deny-on-absent-scope cases (the extension point is already named in `ServiceHostingPhase2Design_2026-08-29.md:192-194`).
- **Live proof (parity mandate):** the M5 llm stage chain — deploy → advertise → authorise → stream-no-key → exit-coexistence → revoke → undeploy (`ServiceHostingPhase2Design_2026-08-29.md:203-206`) — gains one sub-check: a granted peer *without* a scope line is denied, and a peer with an explicit scoped line streams within its limits. Linux llm live rows are still open (`ServiceHostingRolesDeltaPlan_2026-06-11.md:82`); macOS/Windows parity for the llm role remains ⛔ per the platform matrix until those cells run.

## 6) What NOT to do

- **No fallback path.** Do not add "treat None as unrestricted if legacy mode enabled" — one hardened execution path (AGENTS.md §3). The `unrestricted` marker replaces the old semantics; the old semantics are deleted, not demoted.
- **No silent default quota as a fig leaf.** "None ⇒ some small default quota" looks restrictive but invents policy an admin never wrote; absence must deny outright.
- **No per-request bypass.** No admin escape hatch evaluated at request time; scope changes go through the access-state file reload, which already fails closed on corruption (`main.rs:322-327`).
- **Do not encode unrestricted as absence anywhere else.** The asymmetry OG-1 warns about (`Some([])` deny vs `None` allow) is exactly the trap this plan removes; reintroducing "absence means something permissive" in a new field recreates it.
- **Do not weaken the admission layer while touching the scope layer** — E2's verified chain (`service_exposure.rs:257` ← `service_access_state.rs:90` ← `daemon.rs:4512`) stays untouched.

## 7) Open questions for adversarial review

1. **OG-1 disposition:** does the owner accept Option B as the resolution of "confirm this is the intended product semantics" (F-1), or is the documented fail-open posture being kept deliberately for a product reason not recorded in the docs surveyed here?
2. **Marker naming and grammar:** is `unrestricted` the right key for the `scopes.v1` line grammar, and should it be selector-scoped (`<selector> unrestricted`) or a per-peer boolean? The existing grammar is selector-keyed with `allowed_models=`/`max_tokens_per_window=`/`max_requests_per_minute=` keys (`main.rs:262-311`).
3. **Does `nas` need the parallel decision?** OG-2 (`ServiceHostingPhase2Design_2026-08-29.md:226-231`) asks the same posture question for the nas scope type; if OG-1 lands as Option B, should OG-2 be resolved identically in the same change so the two service roles do not diverge?
4. **POL-12 interplay:** with deny-on-absent, does selector mis-ordering now fail safer (widest realistic outcome = wrong *narrow* scope ⇒ confusing denies) or still risk widening? Should the loader enforce that selector specificity be structural rather than caller-ordered?
5. **Migration timing:** because M5 llm live rows have never run, Option B can land before any live evidence exists — confirm no out-of-tree llm deployments rely on absent-scope-unrestricted before flipping the tests (`enforce.rs:198-209`, `:294`, `:328`, `:331`).
6. **Admin-UI/tooling rendering:** with the marker explicit, what should `access list` show for a granted peer with no scope line — "DENY (no scope line)" as proposed, and does anything downstream parse that output today?
7. **Phase-2 handoff:** when signed scope distribution lands (`service_access_state.rs:116`'s "admin scope distribution rides the signed policy bundle later"), does the local `unrestricted` marker remain legal, or does phase 2 retire it in favour of signed-only scope lines?
8. **E1 dependency:** should the scope-layer flip be sequenced after E1 tunnel-only bind enforcement is wired (`SecurityMinimumBar.md:578-607`), or is it independent? This plan treats it as independent and strictly improvement, but the review should confirm.
