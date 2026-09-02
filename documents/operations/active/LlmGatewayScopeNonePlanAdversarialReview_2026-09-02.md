# Adversarial Review — LLM Gateway `scope = None` Decision Plan (F-1)

- **Date:** 2026-09-02
- **Subject:** `documents/operations/active/LlmGatewayScopeNonePlan_2026-09-02.md` (the "Plan").
- **Method:** every file:line anchor in the Plan was re-verified in this worktree; the cited sources were read in full; the claims were attacked for accuracy, completeness, and security soundness. All line numbers below are from this worktree unless stated otherwise.
- **Verdict:** **READY-WITH-AMENDMENTS** — Option B stands, but six of its supporting claims are wrong or overstated, one codifying test is missing from the migration list, the sketch has one wrong anchor and one real enforcement gap (mid-stream scope staleness), and the migration section lists a fixture item that does not exist while omitting six doc/comment sites that do.

## §0) Verdict table

| Plan section | Verdict | One-line reason |
|---|---|---|
| §1 Current behaviour | Accurate with gaps | The three fail-open points, three `None` sources, unsigned scope state: all verified. Misses a fourth consequence (the daemon *rewrites* `scopes.v1` empty on every signed apply), a fifth codifying test, and a doc-comment contradiction on the daemon side. |
| §2 Requirement basis | Sound, both sides under-argued | §6.E reaches admission only; extending §10.4 to scoping is defensible but must be argued against the thrice-documented "scopes restrict, never grant" design rather than asserted. Decided for the Plan (see §2 below). |
| §3 Threats T1–T5 | T1/T2/T3/T5 correct; T4 inflated | T4's selector-ordering widening cannot occur in current code — the gateway never consults `LlmScopePolicy::scope_for`; it does an exact node-id map get. Two real threats missing (shared-engine starvation; mid-stream scope staleness). |
| §4 Options | Conclusion right, argument partly false | B's claimed advantage over A ("an admin *can* still authorise full access") is **false today** — no CLI, signed, or durable path can deliver any scope line to the gateway. The true argument for B is grammar continuity, not current expressiveness. |
| §5 Implementation sketch | Feasible; one wrong anchor, one real gap | Test-list anchor `main.rs:284-308` is production code, not tests; the sketch does not handle mid-stream scope capture; the CLI claim is half right (flags exist, names differ, and their output has no landing zone). |
| §6 What NOT to do | Sound | No disagreements. |
| §7 Open questions | Good set; two now answered | Q8 (E1) resolvable: independent, no sequencing constraint. Q3 (OG-2): nas has no scope consumption in code; resolve direction now, sequence nothing. |
| **Overall** | **READY-WITH-AMENDMENTS (Option B, amended)** | Apply amendments A1–A10 (§9) before owner gate OG-1 is taken. |

## §1) Attack 1 — Is the Plan's reading of current behaviour exact?

### 1.1 Verified as stated

- **Three fail-open enforcement points — exact.** `admit_request` early-returns `Ok(())` on `None` (`crates/rustynet-llm-gateway/src/enforce.rs:82-86`), checked paths at `:87` (model), `:97-104` (rate), `:107-118` (quota); `record_tokens` severs only when a scope *with a limit* is present (`:138-146`); `visible_models` uses `.map(...).unwrap_or(true)` (`:172`, fn `:166-174`). The three unit tests are where the Plan says: `no_scope_admits_any_model_without_quota_or_rate` (`:198-210`, `u32::MAX` tokens at `:208`), the "No scope ⇒ everything visible" assertion (`:294-296`), and the two "no quota without scope" expects (`:328`, `:331`).
- **Admission fail-closed — exact.** Unmapped tunnel source refused (`main.rs:328-330`); no grant line refused with the default-deny message (`main.rs:331-334`); unreadable/corrupt state refuses (`main.rs:322-327`); per-frame re-check (`main.rs:365-375`); snapshot derivation ACTIVE-membership, self-excluded, `evaluate_service_access`-gated (`crates/rustynetd/src/service_access_state.rs:76-118`, enforcement call at `:90`); `evaluate_service_access` at `crates/rustynetd/src/service_exposure.rs:257`.
- **Three `None` sources — exact.** Absent scopes file treated as "no entries" with the quoted doc comment (`main.rs:221-228`); daemon hardcodes `scopes: Vec::new()` with the quoted comment (`service_access_state.rs:56-61`, render at `:116`); exact node-id key lookup resolving to `None` (`main.rs:336`), mirroring `scope_for`'s documented fail-open direction (`crates/rustynet-policy/src/lib.rs:344-349`, fn `:350-361`); per-line `LlmAccessScope::default()` (`main.rs:274`) with all-`None` fields (`lib.rs:289-299`).
- **Unsigned — exact.** The access files are materialised artifacts whose authority is the signed snapshot ("The files are **materialised artifacts, not signed documents**", `ServiceHostingPhase2Design_2026-08-29.md:33`); the scope half of the snapshot is never populated (`service_access_state.rs:116`).
- **POL-12 caveat — accurately quoted** (`lib.rs:316-330`).

### 1.2 What the Plan missed that changes the picture

1. **A fifth codifying test.** `absent_scopes_file_keeps_documented_unrestricted_grant` (`crates/rustynet-llm-gateway/src/main.rs:705-716`) asserts end-to-end through `admitted_peer` that a granted peer with no scopes file admits with `scope.is_none()`. The Plan's migration list (§5/§4 item 1) names only the four `enforce.rs` tests; missing this one breaks the flip at the loader level, not just the enforce level. The Plan's own sketch (§5 test 6) would create its replacement, but the migration inventory must retire this test explicitly.
2. **The daemon actively re-writes `scopes.v1` to empty on every signed apply.** `materialize_service_access_state` (`crates/rustynetd/src/daemon.rs:5538`) calls `write_access_state_atomic` or `write_grants_and_scopes_atomic` (`daemon.rs:5561`/`:5565`; the latter at `service_access_state.rs:179-187` renders `scopes.v1` from the always-empty snapshot). Consequence: **even a hand-authored scope line is volatile** — the next membership apply or signed-state commit silently reverts `scopes.v1` to empty. This is a fourth `None` source the Plan does not name ("daemon rewrote the file"), and it falsifies the Plan's §4 claim that Option B "keeps the grant expressive" (see §3 below).
3. **A doc-comment contradiction on the daemon side.** `service_access_state.rs:22-24` states "A missing or unreadable file means deny-all on the binary side" — false for `scopes.v1`, whose absence the gateway itself documents as unrestricted (`main.rs:221-228`). The Plan's §4 Option D ("documentation has not prevented…") could cite this: the module's own summary is internally inconsistent today.
4. **Module docs that will be stale under B and are not in the Plan's update list:** `enforce.rs:1-7` ("Scopes come from the owner-signed policy") — already inaccurate today (scope state is unsigned local files; only grants derive from signed policy); `crates/rustynet-llm-gateway/src/lib.rs:20-23` ("restrictions on a grant, never a grant source" — survives, but the surrounding contract text needs the deny-on-absent statement).
5. **No other consumer of `LlmAccessScope` exists.** A workspace-wide search finds `LlmAccessScope` only in `rustynet-policy` (definition, `scope_for`, tests) and `rustynet-llm-gateway` (`main.rs`, `lib.rs` doc, `enforce.rs`). There is no admin tool, no gossip path, and no daemon consumer. The blast radius of the flip is exactly two crates.
6. **The nas scope twin does not exist in code.** `scopes.v1` is documented LLM-only (`service_access_state.rs:18-20`), and `crates/rustynet-nas/src/main.rs` contains no scope parsing at all. OG-2 is a pure design question (see §7 below).

## §2) Attack 2 — Requirement basis: does §6.E reach the scope layer, and does §10.4 apply?

**What §6.E actually says.** E2 (`SecurityMinimumBar.md:609-639`, verified wired) mandates per-peer service *authorisation*: "Being inside the tunnel is necessary, not sufficient", empty/missing/stale policy ⇒ Deny, identity from the authenticated tunnel source. Its enforcement point is admission (`evaluate_service_access`, `service_exposure.rs:257`). §6.E is silent on per-peer *capability* scoping inside a granted service — the Plan says so, correctly.

**The case for applying §10.4 to scoping (the Plan's position):** AGENTS.md §10.4 says "empty/missing/malformed → deny" for "ACL, routes, and trust-sensitive flows". Scoping decides what an authenticated peer may consume — a trust-sensitive flow by any reading. AGENTS.md §2's tie-break rule ("choose the strictest secure practical default") also points the same way. And the current asymmetry is not a neutral design choice: `Some([])` denies every model while `None` allows every one (`lib.rs:291-293`; demonstrated in code at `enforce.rs:297-299`), so "absence" is already the *widest* value in the type — the fail-open direction is not merely documented, it is structurally privileged.

**The case against (steel-manned):** "Scopes restrict, they never grant" is a coherent, thrice-documented layering (`lib.rs:281-288`, `main.rs:221-228`, `ServiceHostingPhase2Design_2026-08-29.md:31` + OG-1 at `:219-224`): the authorisation decision is complete at `Decision::Allow`; a scope is an optional admin refinement, and the ACL layer that §10.4's own wrong-example targets ("empty ACL → allow") is `grants.v1`, which *is* default-deny. Under this reading the house rule is already satisfied at the layer it was written for, and the plan is overriding a deliberate product decision with a house style. The `LlmNodeRoleDesign_2026-06-11.md:296` Definition-of-Done bullet ("The admin signs a policy authorising one device (optionally model/quota-scoped); a RustyAI client on that device streams…") arguably codifies unscoped-full-access as the shipped product behaviour.

**Decision — the Plan's reading stands, for three reasons the Plan should state explicitly:**
1. §6.E's phrase "necessary, not sufficient" is a capability-level statement, not only an admission-level one; a granted-but-unbounded capability is the exact shape E2's wording warns about, even if E2's enforcement text stopped at admission.
2. The "deliberate design" defence fails the AGENTS.md §2 test because the strictest-secure-default rule resolves the ambiguity the other way, and because the design's own documentation is inconsistent (`service_access_state.rs:22-24` vs `main.rs:221-228`) — it is documented, but not coherently.
3. OG-1 exists precisely because this is an open owner decision; the Plan is the decision input, and the house rule is the correct tie-breaker the owner is being asked to ratify. The `LlmNodeRoleDesign:296` DoD conflict is real but is an argument for *amending that DoD in the same change* (A9), not for keeping the fail-open posture.

## §3) Attack 3 — Is Option B the most secure workable option? The A/B/B' comparison done honestly

**The Plan's decisive claim for B over A is false today.** §4 says B "keeps the grant expressive (an admin *can* still authorise full access, deliberately and auditably)". Verified reality:

- No CLI path writes `scopes.v1`. `rustynet llm allow` renders an **unsigned record for the owner to sign** (`crates/rustynet-cli/src/llm_cli.rs:82-113`; DeltaPlan `:81` — "unsigned-record-for-owner-signing"), and the signed policy rule schema (`ContextualPolicyRule`: src/dst/protocol/action/contexts, `lib.rs:370-377`) has **no scope field at all** — so even a fully-signed record's `models=`/`max_tokens_per_window=`/`max_requests_per_minute=` lines have no schema home to land in.
- The daemon renders `scopes.v1` empty and **re-writes it empty on every signed apply** (`daemon.rs:5538-5565`; `service_access_state.rs:116`, `:179-187`).
- Therefore the only way to ship an `unrestricted` line under Option B is to hand-edit a 0700/0600 daemon-owned file — which is neither auditable (no signed witness, T3 applies) nor durable (wiped at the next signed apply, consequence 1.2.2 above).

**So A and B are behaviourally identical on every daemon-managed deployment until phase-2 signed scope distribution lands.** The Plan must say this. What actually differentiates them:

- **Fail-closed default:** identical (both deny absent scope). This is the security payload of the decision and it is not in dispute.
- **Grammar continuity:** B wins. A makes "full access" inexpressible now *and* requires a second semantic decision at phase 2; B fixes the file grammar once (`unrestricted` as a first-class marker) so phase 2 changes *who writes the file*, not *what the file means*. One hardened semantic, one flip.
- **Simplicity/auditability today:** A wins marginally (no marker to reason about, nothing to document about marker provenance).
- **Marker-as-fail-open ("one line away"):** the residual risk is real but bounded. The marker is explicit, grep-able, loader-validated, and contradiction-checked (Plan §5 item 5); widening by adding it requires write access to a 0700-dir/0600-file daemon-owned path (`service_access_state.rs:146-168`, `:216-230`) — the same trust level as forging `grants.v1`, which is already the trust anchor. The marker does not reintroduce a fail-open *default*; it makes full access an explicit, spelt-out act. The Plan should add one mitigation: under B, a bare scope line (selector, no keys) parses to `default()` — under B semantics that becomes deny-all (an improvement over today, where it silently means unrestricted via source 3), and the loader should treat a marker-less line as an explicit deny scope, which the grammar already does naturally.

**Option B′ (signed marker) — not feasible now; the Plan is right to defer it.** A signed scope line requires either a `ContextualPolicyRule` schema field (a policy-schema/wire-format change that lands squarely in OG-3's governance, `ServiceHostingPhase2Design_2026-08-29.md:232-236`) or the phase-2 signed-bundle scope distribution the daemon comments already anticipate (`service_access_state.rs:56-60`). Neither is a same-change item. An interim half-measure worth recording: have the daemon record a digest of whatever `scopes.v1` it leaves on disk at each materialisation, so a hand-authored marker is at least *visible* (not endorsable) at the next apply. Optional; not a blocker.

**Decision:** **Option B (amended)** — its security content equals A, its grammar avoids a second flip, and its expressiveness gap is a phase-2 problem either way. But amendments A3/A4 (§9) must replace the false expressiveness argument and state the daemon-clobber consequence, or the owner is approving B on a premise that is not true.

## §4) Attack 4 — Threats T1–T5: correct, complete, inflated?

- **T1 — correct and correctly sized.** The daemon renders zero scope lines (`service_access_state.rs:116`), so unrestricted-everyone is the universal deployed state, not an edge case.
- **T2 — correct, and understated by one detail.** Beyond a deleted/truncated *file*: a *line* truncated to its bare selector parses without error to `LlmAccessScope::default()` (all-`None` = unrestricted; loader `main.rs:270-311` errors only on **unrecognized keys** and malformed values, never on "no keys present"). Today a mid-write partial line silently widens. Under B this same input becomes deny-all — the flip retroactively fixes this class, which is an argument the Plan should claim and does not.
- **T3 — correct; residual risk correctly bounded.** Unsigned local files, no signed witness for narrowing. Under B the residual widening act (adding an `unrestricted` line) requires daemon-trust file access (`:146-168`), and the daemon's own rewrite pass wipes hand lines at the next apply — the exposure is self-healing toward deny, which is the right direction but operationally surprising (see A4).
- **T4 — inflated for current code.** The gateway never calls `LlmScopePolicy::scope_for` and never resolves multiple selectors: `admitted_peer` does a single exact node-id `BTreeMap::get` (`main.rs:336`). Selector *ordering* cannot widen anything today because no caller supplies an ordered selector list; POL-12 is a live hazard only for a future multi-selector caller (as `lib.rs:316-330` itself says). Keep T4 but demote it to forward-looking: "relevant when scope resolution gains group selectors (OG-1 Q2/Q4), not today."
- **T5 — correct.** `Some([])` deny vs `None` allow is real in type, doc (`lib.rs:291-293`), and enforced behaviour (`enforce.rs:297-299`); OG-1's asymmetry warning is at `ServiceHostingPhase2Design_2026-08-29.md:223-224`.
- **T6 (new) — shared-engine starvation across peers.** Quota/rate counters are per-peer (`enforce.rs:92`, `:132`), but the inference engine is one loopback process shared by all granted peers. An unscoped peer with no rate ceiling degrades latency for *correctly scoped* peers even though it cannot touch their counters. This is a fairness/availability consequence of `None` that T1's cost framing misses.
- **T7 (new) — mid-stream scope staleness.** The mid-stream re-check adopts only the *grant* half of a fresh `admitted_peer` result; the freshly-read scope is discarded (`main.rs:501-512`), and `record_tokens` keeps using the scope captured at frame admission (`main.rs:520`). So under *any* semantics, narrowing or removing a scope does not affect an in-flight generation — only the next `Complete` frame. The Plan's §5 must decide this deliberately: under B, sever (or at minimum re-bind) on a mid-stream change from `unrestricted` to anything narrower, mirroring the existing grant-severance pattern (`main.rs:505-511`). Left undecided, B inherits "revoke narrows only at frame boundaries" as an undocumented exception to its own story.
- **T8 (new, minor) — reload race / partial-file read.** `admitted_peer` re-reads from disk every frame (`main.rs:230-236`); a non-atomic hand edit can transiently present fewer lines. Daemon writes are atomic temp+fsync+rename (`service_access_state.rs:241-286`), so the daemon path is safe; the hand-edit path transiently reads short. Direction: under current semantics the transient state is as wide as the status quo (no regression); under B the transient state is deny (fail-safe). Document, don't engineer around it — the fix is "don't hand-edit", which A4 says loudly.

## §5) Attack 5 — Implementation sketch: real tests/files/lines, one hardened path, contradiction rule, CLI surface

- **Named tests and files are real, with one wrong anchor.** Sketch test 7 cites "existing malformed-line fail-closed tests (`main.rs:284-308`)" — that range is the loader's *production* parse code, not tests. The actual fail-closed loader tests are `malformed_scope_limit_values_deny_peer_instead_of_unlimited` (`main.rs:626-646`), `unrecognized_scope_key_denies_peer` (`:649-665`), `unreadable_scopes_state_denies_peer` (`:668-681`), plus `well_formed_scope_still_enforced` (`:684-703`, survives) and `missing_grant_denies_even_without_scopes` (`:719-724`, survives). All other anchors in the sketch check out: loader `:229-315`, contradiction extension point `:300-308`, `admitted_peer` `:320-338`, refusal style `:331-334`, `lib.rs` doc update points `:281-288`/`:344-349`.
- **One hardened path — yes, with a caveat.** The sketch correctly refuses a legacy branch (Plan §6 item 1). But test 6 ("end-to-end through `serve_connection`") targets a function that has **no test harness today** (the existing tests drive `admitted_peer` directly); the sketch should say a new `serve_connection`-level test is required, not imply one exists. And per T7, the mid-stream decision must be part of this sketch or the "one hardened path" has an unstated exception at event boundaries.
- **Contradiction rule fails closed — yes.** Extending the existing unrecognized-key hard error (`main.rs:300-308`) to reject `unrestricted` combined with `models=`/`quota=`/`rate=` is a natural fit; the pattern (any ambiguity ⇒ `Err` ⇒ peer refused at `main.rs:322-327`) is already fail-closed and tested.
- **CLI surface — half right, and the Plan's own UNVERIFIED flag was warranted.** Verified: `rustynet llm allow|deny|access list` exist (`crates/rustynet-cli/src/main.rs:2052-2071`; help text at `:20349-20351`), and `llm allow` **already accepts scope flags** — `--models`, `--quota`, `--rate` (`llm_cli.rs:40-46`, parser `parse_allow_flags` at `main.rs:2053`). Refuted detail: the Plan's §5 names `--max-tokens`; the real flag is `--quota`. Bigger gap the Plan missed: those flags' output fields have **no landing zone** — they are rendered into the unsigned owner record (`llm_cli.rs:88-98`), but the signed policy schema carries no scope field (§3 above), so today the CLI's scope half evaporates between record and policy. The amendment must state that the CLI's `--unrestricted` flag (new) and the existing scope flags remain *record-only* until phase 2, and that `access list` reads only `grants.v1` today (`llm_cli.rs:28-33`) — it cannot render "UNRESTRICTED (explicit)" vs "DENY (no scope line)" from `scopes.v1` without being taught the new file (fine, but say so).
- **Gate extension point — verified.** `scripts/ci/llm_default_deny_gates.sh` exists, pins tests by name via `run_required_test`, and does **not** pin any of the four (five, with A5) flipping tests — so the flip cannot break the existing gate; only the planned additions are needed. Note for the same change: the pinned policy test name `llm_scope_policy_scope_for_prefers_most_specific_selector` (`lib.rs:2734`, pinned in the gate) encodes the "prefers most specific" claim that POL-12 (`lib.rs:316-330`) documents as refuted — renaming it is out of scope here but should not be forgotten when this file is next touched.

## §6) Attack 6 — Migration claims

- **"M5 llm live rows have never run" — verified, stronger than claimed.** The `--node` ledger `documents/operations/live_lab_node_run_matrix.csv` contains **no llm stage column at all** (header audit: nas/llm service stages are absent from the column list; a case-insensitive search for `llm` across the file returns zero rows). DeltaPlan `:82` ("Linux live-lab evidence rows (M5 — blocked…)") and `:131` ("Both roles have a green Linux live-lab evidence row" as an *unmet* gate) corroborate. There is nothing to migrate and no evidence row to invalidate.
- **"Docs/lab profile fixtures that rely on absent-scope-unrestricted must add explicit `unrestricted` lines" — refuted as stated.** A search for `scopes.v1` across `scripts/`, `profiles/`, `crates/rustynet-cli/`, and `crates/rustynetd/tests` returns **nothing** outside `service_access_state.rs` and the gateway itself. No fixture, no lab profile, no test seeds a scopes file. The real migration work is the opposite of what the Plan lists: six doc/comment sites must be amended (A6–A9), and the fixture item should be deleted.
- **No out-of-tree dependency can be ruled out** — the Plan's own §7.5 caveat stands (unverifiable from the repo; see §10).

## §7) Attack 7 — The E1 dependency and the OG-2 (nas) twin: sequence together?

**E1 (Plan §7.8): independent — confirmed, with sharper reasoning than the Plan gives.** E1's gap (`SecurityMinimumBar.md:589-607`) is that service binaries accept non-tunnel binds (only `validate_tunnel_shaped_bind` at `main.rs:163` runs, rejecting unspecified/loopback/multicast). But the *authorization* layer still refuses off-mesh sources: `admitted_peer` resolves the source IP through `peers.v1`, which the daemon renders exclusively from signed membership (`service_access_state.rs:103-111`), so a LAN client hitting a mis-bound listener dies at `main.rs:328-330` ("no signed identity"). E1's residual exposure is bind-surface/DoS, not authorization bypass. The scope flip narrows post-admission capability and is strictly improvement regardless of E1. **Do not sequence.**

**OG-2 (Plan §7.3): resolve the direction now, sequence nothing.** nas has no scope semantics in code (`scopes.v1` is documented LLM-only, `service_access_state.rs:18-20`; `rustynet-nas/src/main.rs` parses no scope file), so there is nothing to flip in the same change. But leaving OG-2 fully open invites the divergence OG-1 is closing: if OG-2 later elects option (b) (`NasAccessScope`, `ServiceHostingPhase2Design_2026-08-29.md:226-231`), its absent-scope posture should be decided *by the same owner gate* as OG-1, as a recorded default (deny-on-absent, same marker discipline), so the two service roles cannot drift into opposite fail directions. Record the default; block nothing.

## §8) Attack 8 — Every file:line anchor

Legend: VERIFIED (exact in this worktree) / STALE (was right somewhere else, wrong here) / WRONG (never matched the claim).

| Plan anchor | Verdict | Note |
|---|---|---|
| `main.rs:328-330` (unmapped identity refused) | VERIFIED | |
| `main.rs:331-334` (default-deny refusal message) | VERIFIED | |
| `service_access_state.rs:13-24` (grants/peers/scopes contract) | VERIFIED | Files doc `:13-20`; note `:22-24` contradicts the gateway for scopes (see 1.2.3). |
| `service_access_state.rs:76-118` (derive snapshot) | VERIFIED | fn `:76-118`. |
| `main.rs:322-327` (corrupt state refuses) | VERIFIED | |
| `main.rs:365-375` (per-frame re-check) | VERIFIED | |
| `main.rs:460` (per-token-event re-check) | **STALE** | Inherited from `SecurityMinimumBar.md:630`, which is stale too. The mid-stream re-check is at `main.rs:505` (inside `stream_completion`), and it adopts the grant half only — scope discarded (T7). |
| `enforce.rs:82-86`, `:87`, `:97-104`, `:107-118` | VERIFIED | |
| `enforce.rs:138-146` (record_tokens) | VERIFIED | |
| `enforce.rs:166-174` (visible_models) | VERIFIED | `.unwrap_or(true)` at `:172`. |
| `enforce.rs:198-209`, `:294`, `:328`, `:331` | VERIFIED | Plus missed test `main.rs:705-716` (A5). |
| `main.rs:221-228` (loader doc) | VERIFIED | |
| `service_access_state.rs:116` (`scopes: Vec::new()`) | VERIFIED | Comment block `:56-61`. |
| `main.rs:336` (exact node-id scope lookup) | VERIFIED | |
| `lib.rs:350-359` / `:344-349` (`scope_for` + None paragraph) | VERIFIED | fn `:350-361`; the None paragraph is exactly `:344-349`. |
| `lib.rs:290-299` (struct fields) | VERIFIED | struct `:289-299`. |
| `lib.rs:316-330` (POL-12) | VERIFIED | |
| `ServiceHostingPhase2Design :33` ("access files" row) | VERIFIED | "Materialised access state" row; quote matches. |
| `SecurityMinimumBar :573-576`, `:609-639`, `:578-607` | VERIFIED | Note `:626-630`'s own anchors (`daemon.rs:4512`, llm `main.rs:460`) are stale in this worktree — see below. |
| `service_exposure.rs:257` (`evaluate_service_access`) | VERIFIED | |
| `lib.rs:285-289` (Plan §5 doc-update point) | PARTIAL | The full doc block is `:281-288`; `:285-289` clips its head and adds the struct line. Amend to `:281-288`. |
| `main.rs:163` (shaped-bind check) | VERIFIED | |
| `LlmNodeRoleDesign :296` (role core goal) | VERIFIED | The admin-signs/streams DoD bullet; it also *conflicts* with B until phase 2 (A9). |
| `ServiceHostingRolesDeltaPlan :81` (CLI verbs) | VERIFIED | |
| `ServiceHostingRolesDeltaPlan :82` (Linux M5 open) | VERIFIED | |
| `main.rs:300-308` (unrecognized-key error) | VERIFIED | |
| `main.rs:229-315` (loader fn) | VERIFIED | |
| `main.rs:320-338` (`admitted_peer`) | VERIFIED | |
| `main.rs:284-308` ("existing malformed-line fail-closed tests") | **WRONG** | Production parse code. The tests are `main.rs:626-646`, `:649-665`, `:668-681`. |
| `ServiceHostingPhase2Design :192-194` (gate extension point) | VERIFIED | Acceptance text at `:191-192` must also flip (A8). |
| `ServiceHostingPhase2Design :203-206` (M5 stage chain) | VERIFIED | |
| `daemon.rs:4512` (materialise seam) | **STALE** | `materialize_service_access_state` is at `daemon.rs:5538` (write calls `:5561`/`:5565`; production callers `:6006`, `:8846`, `:9907`, `:10579`). Inherited from `SecurityMinimumBar.md:627`. |
| `main.rs:262-311` (scopes.v1 line grammar) | VERIFIED | Parse block `:262-313`; key loop `:275-309`. |
| `ServiceHostingPhase2Design :226-231` (OG-2) | VERIFIED | |

## §9) Exact replacement wording for every amendment

**A1 — §1, after the "Who can produce `None` today" list, add a fourth source:**

> 4. **The daemon rewrites the scopes file on every signed apply.** `materialize_service_access_state` (`crates/rustynetd/src/daemon.rs:5538`) re-renders all three access files from the snapshot on every signed-state commit (`daemon.rs:5561`/`:5565`, callers `:6006`, `:8846`, `:9907`, `:10579`), and the snapshot's scope half is always empty (`service_access_state.rs:116`). Any scope line that reaches the gateway by any means other than the daemon is therefore **ephemeral** — it silently reverts to `None` at the next membership apply or signed-state commit.

**A2 — §1, add to the "Is the scope signed?" paragraph:**

> The daemon-side module doc contradicts the gateway on this exact point: `service_access_state.rs:22-24` claims "a missing or unreadable file means deny-all on the binary side", which is false for `scopes.v1` (`main.rs:221-228` documents absence as unrestricted). Documentation-only posture (Option D) has failed here in both directions.

**A3 — §4, replace the "Why B over A" paragraph with:**

> **Why B over A:** on every daemon-managed deployment A and B are behaviourally identical until phase-2 signed scope distribution lands — no CLI or signed path can deliver any scope line to the gateway today (`rustynet llm allow` renders an unsigned record for owner signing, `llm_cli.rs:82-113`, and the signed policy rule schema carries no scope field), and the daemon rewrites `scopes.v1` empty on every signed apply. B's advantage is not current expressiveness but grammar continuity: B fixes the file semantics once (`unrestricted` as an explicit, validated, contradiction-checked marker), so phase 2 changes *who writes the file*, not *what the file means*; A requires a second semantic flip later. Both share the security payload — absent scope denies. The marker does not reintroduce a fail-open default: it makes full access an explicit act requiring write access to a 0700/0600 daemon-owned path (`service_access_state.rs:146-168`), the same trust level as forging `grants.v1`.

**A4 — §4 Option B migration impact, replace item (3) and add item (5):**

> (3) *(replaces the fixture item — no fixture, lab profile, or test seeds a scopes file; verified by search across `scripts/`, `profiles/`, `crates/rustynet-cli/`, `crates/rustynetd/tests`)* — update the six doc/comment sites that codify the old posture: `service_access_state.rs:22-24` and `:56-61`/`:75`, `enforce.rs:1-7`, `rustynet-llm-gateway/src/lib.rs:20-23`, `rustynet-policy/src/lib.rs:281-288` and `:344-349`, `ServiceHostingPhase2Design_2026-08-29.md:31` and the P2-M3 acceptance line `:191-192` ("no scope entry ⇒ full grant"), and the `LlmNodeRoleDesign_2026-06-11.md` §13 Definition-of-Done bullet at `:296`.
> (5) document loudly that a hand-authored `unrestricted` line is **ephemeral** — the daemon wipes it at the next signed apply (A1) — and that the CLI's scope flags (`--models/--quota/--rate`, existing; `--unrestricted`, new) remain record-only until phase 2 gives their fields a signed landing zone.

**A5 — §5 fail-closed test list, amend item 7 and add item 8:**

> 7. *(corrected anchor)* existing malformed-line fail-closed tests unchanged and still pass: `main.rs:626-646` (malformed limit values), `:649-665` (unrecognized key), `:668-681` (unreadable scopes state), plus survivors `well_formed_scope_still_enforced` (`:684-703`) and `missing_grant_denies_even_without_scopes` (`:719-724`).
> 8. the codifying test the Plan's §4 missed — `absent_scopes_file_keeps_documented_unrestricted_grant` (`main.rs:705-716`) — is **retired** and replaced by the deny-on-absent equivalent at the `admitted_peer` level.

**A6 — §5, add a mid-stream bullet (resolves T7):**

> - **Mid-stream scope change:** the existing per-event re-check adopts only the grant half of a fresh `admitted_peer` result (`main.rs:501-512`; `record_tokens` keeps the frame-admission scope, `main.rs:520`). Define it: a mid-stream transition from `unrestricted` (or scoped) to anything narrower severs the stream at the next event boundary, mirroring grant revocation; a transition to equal-or-wider scope does not retroactively widen the in-flight request.

**A7 — §5 CLI bullet, replace with:**

> - **CLI surface (verified):** `rustynet llm allow|deny|access list` exist (`crates/rustynet-cli/src/main.rs:2052-2071`; help `:20349-20351`); `llm allow` already accepts `--models/--quota/--rate` (`llm_cli.rs:40-46` — note the quota flag is `--quota`, not `--max-tokens`). Add an explicit `--unrestricted` flag to `parse_allow_flags`, make the emission rule "at least one restriction or `--unrestricted`", and teach `access list` to read `scopes.v1` (it reads only `grants.v1` today, `llm_cli.rs:28-33`) so it can render "UNRESTRICTED (explicit)" vs "DENY (no scope line)". State plainly that all scope fields remain unsigned-record-only until phase 2.

**A8 — §5 live-proof bullet, add:**

> The Phase2Design acceptance wording that codifies the old posture — "no scope entry ⇒ full grant (see §5 OG-1 before changing this)" (`ServiceHostingPhase2Design_2026-08-29.md:191-192`) and the "LLM scopes" table row at `:31` — flips in the same change as OG-1's resolution, so the design doc and the code never disagree.

**A9 — §7, answer open questions 3 and 8 instead of leaving them open:**

> 3. **OG-2 (nas):** nas has no scope consumption in code (`scopes.v1` is LLM-only, `service_access_state.rs:18-20`; the nas binary parses no scope file), so nothing flips in the same change. OG-1's resolution records the default for OG-2 — deny-on-absent and the same marker discipline for any future `NasAccessScope` — so the two service roles cannot drift into opposite fail directions. Sequenced as a recorded default, not as coupled work.
> 8. **E1 dependency:** independent. Even with E1's bind enforcement unwired (`SecurityMinimumBar.md:589-607`), off-mesh sources are refused at admission because `peers.v1` is derived exclusively from signed membership (`service_access_state.rs:103-111`) and lookup failure denies (`main.rs:328-330`); E1's residual gap is bind-surface exposure, not authorization. The scope flip is strictly improvement and waits for nothing.

**A10 — §3 threat table, amend T4 and append T6–T8** (wording as in §4 of this review: T4 demoted to forward-looking — the gateway performs an exact node-id map get (`main.rs:336`) and never resolves ordered selectors, so mis-ordering cannot widen anything until a multi-selector caller exists; T6 shared-engine starvation across peers; T7 mid-stream scope staleness; T8 hand-edit reload race, fail-safe under B).

## §10) What could not be verified

- **Out-of-tree llm deployments** that might rely on absent-scope-unrestricted (Plan §7.5): unverifiable from the repository; remains a genuine owner-side confirmation item.
- **`parse_allow_flags` internals** (flag-combination enforcement, error wording) beyond its existence and call site (`main.rs:2053`) — the body was not audited line-by-line; the flag *names* were verified via the help text and the `LlmCommand` enum.
- **Whether any operator currently hand-edits `scopes.v1`** on deployed nodes — no repo evidence either way; the A4 ephemerality warning is the mitigation.
- **The exact current anchors inside `SecurityMinimumBar.md` beyond the cited range** — `:626-630` was found stale (`daemon.rs:4512` → `:5538`; llm `main.rs:460` → `:366`/`:505`); other SMB anchors were not audited. Fixing SMB itself is a separate doc-sync task and intentionally untouched here.
- **Runtime behaviour** — this is a docs-only review; no tests were executed and no lab run was performed. All code claims are from reading this worktree's source at the lines cited above.
