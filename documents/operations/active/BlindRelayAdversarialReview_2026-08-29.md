# Blind Relay — Adversarial Security Review (Phases 1–4 on `main`)

**Status:** Review complete. **No exploitable BROKEN defect found** in the reviewed surface; five findings recorded (three minor wire-canonicalization items, one pre-exploitable design gap that must close before the forwarding phase, one defense-in-depth note). **Production advertisement verdict: NO-GO** — correctly held closed by the phase-1 gates; this review does not by itself authorize flipping the go-live bit.
**Date:** 2026-08-29
**Reviewer:** GLM (Zhipu) adversarial first pass, single model, doc-only. **This is NOT the full independent cryptographic/protocol review that `BlindRelayRoleDesign_2026-08-27.md` §15.1 requires; a second independent review (different model or human) is recommended before `BLIND_RELAY_V2_ADVERSARIAL_REVIEW_APPROVED` is considered.**
**Scope reviewed:** `blind_relay` phases 1–4 as merged on `main`, against the design mandate `BlindRelayRoleDesign_2026-08-27.md` (§3 threat model, §5 fail-closed tables, §7 protocol, §12.2 pre-auth ordering, §16 open items, §17 checklist) and the proposed selections in `BlindRelayProtocolSelection_2026-08-28.md` (§1 encoding, §2 PoP, §3 replay). Conventions follow `AnchorBundlePullAttestationSecurityReview_2026-07-20.md`.
**Method:** per-attack HELD/BROKEN with file:line code evidence; no code changed; no gates run (doc-only deliverable).

## 1. Why this review exists

`BlindRelayRoleDesign_2026-08-27.md` §16 states that until the wire-format/PoP/replay decisions are resolved, "`blind_relay` remains design-only and must not be advertised by production signed state." §17 makes an independent adversarial review part of design acceptance, and §15.1 makes an independent cryptographic/protocol review a production-rollout gate. Phases 1–4 landed the capability taxonomy, presets, v2 wire types + PoP transcript, the ten-step admission listener, and the go-live gate. This review attacks that code as the design's adversary R (relay operator with root, §3.1): reading all relay memory, files, logs, token and hello bytes, ciphertext, and network tuples, attempting to (a) break canonical parsing before signature use, (b) forge or replay proofs, (c) reorder admission to spend relay resources before authorization, (d) advertise `blind_relay` through production signed state ahead of sign-off, (e) open the listener through a single-gate flip, (f) recover a stable endpoint identity, or (g) find any fail-open continuation on missing/invalid/unavailable state.

Files reviewed in full: `crates/rustynet-control/src/blind_relay.rs` (2459 lines), `crates/rustynet-relay/src/blind_relay_listener.rs` (2528 lines). Reviewed by targeted read/grep: `crates/rustynet-control/src/role_presets.rs`, `crates/rustynet-control/src/membership.rs`, `crates/rustynet-control/src/enrollment.rs`, `crates/rustynetd/src/daemon.rs` (36k lines, grep-only), both design documents, and the precedent review.

## 2. Attack 1 — Wire format: non-canonical acceptance

**Verdict: HELD.** Three minor findings (F1–F3 below); none is exploitable to forge a signature, smuggle fields past the canonical-equality check, or overflow.

Evidence that the canonical discipline holds:

- Size gates first, before any parsing: token/hello wire ≤4096 B, fleet ≤16 KiB (`blind_relay.rs` constants block); UTF-8 gate immediately after size. Nothing attacker-controlled is allocated before these gates.
- Parser structure (`parse_blind_relay_leg_token_v2_wire`): allowlisted keys only (unknown key rejected, line ~696); duplicate key rejected via `BTreeSet` (line ~711); signature must be the final line; canonical re-encode equality enforced **before** the parsed token is used for anything cryptographic — `token.canonical_payload() != payload` ⇒ reject (line ~828). Reordering lines therefore fails: the re-encode of the parsed struct is in canonical order and will not equal the presented payload, and the repo's own test `reordered-with-valid-signature` rejects (16-vector set from `BlindRelayProtocolSelection` §1.3, all implemented).
- Integers go through `parse_canonical_u64`: empty, leading-zero, sign character, non-digit, and out-of-range (>20 digits / >u64) all rejected. Text fields ≤32 B, ASCII printable, `=` and control characters excluded. Fixed-width hex for all 32/16-byte fields; all-zero rejected for `circuit_handle`, `leg_handle`, `presenter_public_key`, `nonce`.
- Hello v2 pins the line count at exactly 19 (15 token lines + 3 envelope lines in fixed order), rejects duplicate/unknown envelope keys and all-zero `client_nonce`/`relay_challenge`, and enforces a **full-wire** re-encode equality (`hello.to_wire() != wire` ⇒ reject), so trailing data, envelope reordering, and token-level canonicalization escapes are caught at the hello boundary — which is the boundary the listener actually parses.
- Fleet descriptor v2: closed `relay_mode` enum; `identity_blind` forces token/hello version lists to exactly `[2]` (no v1 fallback); canonical re-encode + `verify_strict`.
- Closed enums (`token_kind`, `scope`, `leg_slot`) are pinned to single values; the parser accepts the `blind-relay` hyphen alias on input but serializes only the canonical `blind_relay` form (`role_presets.rs` lines 65/90/165/262 vs. 137/184/288), matching design §4.

Findings (minor, documented for follow-up; not fixed per review mandate):

- **F1 — signature value whitespace.** The parser trims the signature value (line ~702), so `signature= <hex>` with leading/trailing spaces is accepted at the *token* parse level. The payload re-encode does not cover the signature line, so token-level canonical equality does not catch it. The hello-level full-wire compare does catch it, and the listener only consumes hello-level parses, so no production path is affected today. Fix shape: reject any whitespace in the signature value instead of trimming.
- **F2 — CRLF normalization.** Rust `lines()` strips `\r`, so a CRLF-terminated token wire normalizes to an LF payload and passes token-level re-encode. Again caught by the hello-level full-wire compare. Fix shape: reject `\r` at the UTF-8 gate so token-level parsing is byte-canonical on its own.
- **F3 — attacker-value echo in enum errors.** `from_wire` errors for `token_kind`/`scope`/`leg_slot` embed the attacker-supplied value (`token_kind is invalid: {other}`, lines ~97–99, ~126–129, ~155–158). Reflection is bounded at ≤4096 B and leaks no identity, but §7.3 requires closed reason classes only. Fix shape: fixed-string errors naming the field, not the value.

## 3. Attack 2 — Proof-of-possession

**Verdict: HELD.**

- Transcript domain separation: `BlindRelayPopTranscript::canonical_bytes` opens with `domain=rustynet-control-blind-relay-pop-v1` and binds `token_digest` (SHA-256 of the **parsed token's canonical payload** — and because parse enforced presented == canonical, the digest binds the exact presented bytes), plus `relay_challenge`, `circuit_handle`, `leg_handle`, `leg_slot`, `privacy_epoch`, `client_nonce`. Every field of the transcript is exercised by a per-field mutation test that rejects.
- Cross-circuit replay is impossible: the token digest is inside the transcript, so a proof valid for one token cannot verify against a different token (new nonce ⇒ new digest); the dedicated cross-circuit-proof-reuse test rejects.
- Verification uses `verify_strict` only (`verify_signature` on the token and `verify_blind_relay_pop_signature` both call it); there is no `verify()` fallback anywhere in the crate.
- Degenerate keys: all-zero presenter key rejected before key construction; `VerifyingKey::from_bytes` is fallible and its error propagates (no unwrap/expect). Per-circuit key freshness is structural — the presenter key is a token field bound by the issuer's signature, and the listener enforces distinct `presenter_digest` across the two legs of one circuit (step 9 pairing checks), so both legs cannot share a key.
- Library is ed25519-dalek v2 per the §2.2 selection; no custom cryptography.

## 4. Attack 3 — Ten-step admission ordering and replay

**Verdict: HELD** (with pre-exploitable design gap F4 that must close before the forwarding phase).

- Ordering is cheap-before-expensive exactly as §7.5 specifies, and the **stage-order witness tests prove it adversarially**: an oversize frame enters only `EnvelopeParse` (no rate-limit stage recorded); a rate-limited source stops after stage 2; a missing address artifact stops after stage 3 with no `IssuerVerification` stage recorded; an unknown issuer id stops at `IssuerVerification`; a `None` clock yields `ClockUnavailable`. No signature, HMAC, or session allocation occurs before frame parse + per-source rate limit.
- Pre-auth rate limit: 5/sec per source prefix (/24 v4, /48 v6), limiter map hard-capped at 16,384 entries with prune-then-reject — never allocates above the cap under a flood.
- Clock is checked **first inside step 3** (`now_unix.ok_or(ClockUnavailable)`), before any HMAC work — a clock-less relay admits nothing.
- Address validation: truncated HMAC-SHA256 (160-bit tag) over (source address octets, client nonce, key epoch, expiry) with a domain-separated prefix; keyed by a rotating keyring (≤8 epochs, forward-only rotation, zero key refused, `Zeroizing`-held); artifact TTL 30 s checked with the skew clamp; constant-time tag compare. The artifact is never persisted and expires in seconds — it cannot become the stable linkability cookie §7.5 forbids.
- Replay: three digest namespaces (leg, nonce, pop) with domain-separated digest strings (`"v2"`, `"v2-nonce"`, `"v2-pop"`); step 8 rejects on `contains`; step 10 commits atomically via `insert_all` with full rollback on persist failure. The store is **durable-required**: no memory-only mode exists; a missing file is created, an existing file that fails exact-shape parse is refused (no TOFU reset); a full store **rejects** admission rather than evicting; retention is `ttl + 2*skew + 1` with a compile-time assertion; prune skips (retains everything) on clock failure.
- Pairing (step 9) rejects: duplicate slot, mismatched profile, mismatched expiry, repeated leg handle, repeated presenter digest, and a second leg from the same source tuple (self-pair). Capacity limits (256 total / 16 per-prefix / 64 per-profile) gate new circuits; a full waiting set yields `Capacity`, never eviction.
- Reject classes are closed: `Malformed / RateLimited / AddressValidation / Unauthorized / Replayed / Capacity / ClockUnavailable / ReplayStoreUnavailable`, with `Display` impls that are fixed strings — no attacker content is echoed (contrast F3, which is in `blind_relay.rs` control-plane errors, not listener admission errors).

**F4 — third-leg admission after pairing (design gap, not exploitable in phase 4).** When the second leg pairs, the circuit is removed from the waiting map (line ~1266). A *third* hello for the same `(privacy_epoch, circuit_handle)` with a fresh token/nonce then falls into the `NewCircuit` branch and allocates a **fresh waiting circuit** for a handle that is already paired. §7.6 requires third leg ⇒ close/quarantine. Today nothing forwards — the forwarding plane is later-phase and the paired circuit holds no persisted state — so this cannot be exploited yet. It MUST be closed before forwarding lands: track `Paired` circuits (bounded, expiring, keyed `(privacy_epoch, circuit_handle)`) and send any post-pairing leg to the close/quarantine path. Recorded as the highest-priority follow-up in §9.

## 5. Attack 4 — Reducer and advertisement: can production signed state carry `blind_relay`?

**Verdict: HELD.** The capability parses and reduces, but every production path that mints capability-carrying signed state refuses it, exactly as the phase-1 gate intends:

- `MembershipOperation::AddNode` rejects any node carrying `RoleCapability::BlindRelay` ("blind_relay capability is design-only; pending §16 wire-format sign-off", `membership.rs` ~2041–2046).
- `MembershipOperation::SetNodeCapabilities` rejects the same (`membership.rs` ~2076–2080).
- Enrollment admission rejects it for both spelling aliases (`enrollment.rs` ~257–265, test ~470–477).
- These are enforced **at the reducer**, not in an advisory helper — the same trust-boundary lesson as the RSA-0009/DD-03 blind_exit fix documented in the adjacent comment.
- When the gate is eventually lifted, the signed-state validator enforces the §5.1 exact set as an **allowlist**: `blind_relay` requires `relay_host`, and `capabilities.len() == 2 && contains(RelayHost) && contains(BlindRelay)` — any other capability (including any future one) fails with "blind_relay permits exactly the canonical set {relay_host, blind_relay}; no other capability may co-exist" (`membership.rs` ~2737–2754). Tests cover: requires-relay-host, exact-pair-validates, rejects-every-other-co-capability (`membership.rs` tests ~3244–3264). Future capabilities are refused by default — an attacker who later adds `Capability::Foo` cannot ride it onto a blind relay.
- Preset and daemon projections agree: preset capabilities `&[ServesRelay, BlindRelay]` (`role_presets.rs` ~357–364), daemon projects `&[RelayHost, BlindRelay]` for `NodeRole::BlindRelay` (`daemon.rs` ~1974, ~21673). `BlindRelay` is appended last in the canonical capability ordering (`role_presets.rs` ~995–997).
- Role exclusivity: entering `blind_relay` is blocked from Client/Exit/Anchor/Nas/Llm (`role_presets.rs` ~640–652), and the daemon-side local-role alignment check rejects any of `[Client, EntryRelay, ExitServer, BlindExit, Anchor, ServesNas, ServesLlm]` plus all anchor sub-capabilities with no warn-and-continue exception (`daemon.rs` ~2119–2144) — §5.2's explicit demand that the BlindExit warn-and-continue not become precedent is honored.

**F5 — alignment check is a forbidden-list, not the exact set (defense-in-depth note).** The daemon alignment check verifies *absence* of forbidden capabilities but not *presence* of the exact `{RelayHost, BlindRelay}` pair, so a `blind_relay`-roled node whose membership lacks the pair entirely would pass alignment. No production path reaches this today (the membership cannot contain `blind_relay` at all pre-sign-off, and the signed-state validator is exact-set). Before go-live, the alignment check should compare the full canonical set, mirroring `membership.rs` ~2737–2754.

## 6. Attack 5 — Go-live gate: can the listener open in production today?

**Verdict: HELD.**

- `pub const BLIND_RELAY_V2_ADVERSARIAL_REVIEW_APPROVED: bool = false;` (`blind_relay_listener.rs` line 83) — flipping it requires a code change that any reviewer will see; it is not config.
- `try_open` (line ~964) requires **all three** of: the review constant, `signed_capability_granted`, and `operator_enabled`, in a single `&&` chain — flipping any one gate alone leaves the listener closed, which is exactly what the mutation-obligation test `try_open_refuses_without_all_three_gates` asserts, alongside `adversarial_review_gate_is_closed`.
- The gate is fail-closed by construction even if the constant were flipped: `signed_capability_granted` can never be true in production while Attack 4's reducer/enrollment gates refuse `blind_relay` capabilities. The listener is therefore triply closed today: no signed capability can exist, the review bit is false, and no operator flag exists in the shipped config surface.
- `build()` is module-private; external callers can only construct through `try_open`. There is no runtime fallback constructor and no config key that bypasses the chain.

## 7. Attack 6 — BR-P1: does the relay learn a stable identity?

**Verdict: HELD.**

- The v2 token carries no identity fields at all: no node id, no WireGuard/gossip/enrollment public key, no membership index, no hostname/label, no policy rule id, no networks, no stable pseudonym, and nothing identity-derived. Every multi-byte field is either a fresh random handle (`circuit_handle`, `leg_handle`, `nonce` — CSPRNG, all-zero rejected), a per-circuit fresh presenter key, or coarse public metadata (`profile_id`, timestamps, epoch). This satisfies §7.2's "eliminate stable identities instead of hashing them."
- Hello v2 carries only the token, a fresh `client_nonce`, the address-validation artifact, and the PoP signature.
- Relay-resident state is §7.7-conformant: waiting legs store `leg_handle`, a SHA-256 `presenter_digest` (never the raw key), the observed socket tuple (explicitly admitted residual evidence, §3.3), and an expiry — memory only. Replay entries are keyed by one-way digests; nothing links a leg to a Rustynet identity.
- Logging/persistence: the listener emits no per-hello log lines at all; the only console output is a skew-clamp warning. Error strings are fixed-class (see §4). `Debug` impls on token/hello fully redact secrets (verified in `blind_relay.rs`).
- F3's bounded value echo is the only attacker-controlled string in any error path, contains no identity, and does not touch the BR-P1 property.

## 8. Attack 7 — Fail-open hunt

**Verdict: HELD.** Systematic sweep of "missing/invalid/unavailable ⇒ continue?":

| Condition | Behavior |
| --- | --- |
| Clock unavailable | `ClockUnavailable` at step 3, before any crypto; prune skips on clock failure (retains) |
| Replay store corrupt | refuse to open (no TOFU reset) |
| Replay store write failure | full rollback of the in-memory insert; admission rejected |
| Replay store full | reject, never evict |
| Replay store unavailable | `ReplayStoreUnavailable` — there is no memory-only fallback mode |
| Rate limiter map full | prune then reject; never allocates above cap |
| Waiting legs / capacity exhausted | `Capacity` reject, never evict |
| All-zero handle/key/nonce | rejected at parse |
| Unknown issuer key id | rejected at step 4 before signature work |
| Missing/invalid address artifact | rejected at step 3 |
| Invalid signature / PoP / degenerate key | rejected (verify_strict, fallible key construction, error propagated) |
| Backend capability flags vs. `blind_relay` | currently returns "no flags gate it" (`daemon.rs` ~12839–12844) with the phase-3/§16 deferral documented — platform eligibility and dataplane posture are explicitly open deliverables, not silent grants |

The §9 requirement "CSPRNG unavailable ⇒ no allocation" applies to minting surfaces (issuer/client v2, §14.5) not yet implemented; on the relay side the artifact-issuance API takes the challenge bytes from its caller, so no weak-RNG fallback exists in reviewed code. Noted as pending, not a defect in phases 1–4.

## 9. Findings register

| ID | Severity | Where | Summary | Fix shape |
| --- | --- | --- | --- | --- |
| F1 | Minor | `blind_relay.rs` ~702 | Token parse trims signature value; whitespace-padded signature accepted at token level (caught at hello level) | Reject whitespace in signature value |
| F2 | Minor | `blind_relay.rs` parse | `lines()` strips `\r`; CRLF wire normalizes at token level (caught at hello level) | Reject `\r` at the UTF-8 gate |
| F3 | Minor | `blind_relay.rs` ~97–158 | Enum `from_wire` errors echo attacker-supplied values; violates §7.3 closed-class phrasing (no identity leak; listener errors already fixed-class) | Fixed-string errors naming the field only |
| F4 | **Design gap — must close before forwarding phase** | `blind_relay_listener.rs` ~1266 | Third leg for a paired `(epoch, circuit_handle)` allocates a fresh waiting circuit instead of close/quarantine (§7.6). Not exploitable while nothing forwards | Track Paired circuits (bounded, expiring) keyed `(privacy_epoch, circuit_handle)`; post-pairing leg ⇒ close/quarantine |
| F5 | Defense-in-depth | `daemon.rs` ~2119–2144 | Local-role alignment is forbidden-list-only; does not assert presence of the exact `{RelayHost, BlindRelay}` pair (unreachable today due to phase-1 gate + exact-set validator) | Compare full canonical set, mirroring `membership.rs` ~2737–2754 |

None of F1–F5 was fixed here (review-only mandate). F4 is a blocking obligation for whoever lands the forwarding phase.

## 10. §17 design-acceptance checklist verdict

| # | Item | Verdict | Evidence |
| --- | --- | --- | --- |
| 1 | BR-P1 falsifiable, BR-R1 prominent | Yes | Design §3.2 falsification criteria, §3.3 honest framing; §7 of this review found no violation |
| 2 | Adversary explicit incl. compromised relay host | Yes | Design §3.1 adversary R |
| 3 | No IP/timing/flow anonymity claim | Yes | Design §3.3; same-circuit tuple visibility stated as residual evidence |
| 4 | Same-circuit leg association admitted | Yes | Design §3.2/§3.3 |
| 5 | `BlindRelay` modifier requiring `RelayHost` + dedicated local role | Yes | `role_presets.rs` ~357–364; `daemon.rs` ~1974 |
| 6 | Signed state exactly `{RelayHost, BlindRelay}`, future rejected by default | Yes | `membership.rs` ~2737–2754 + tests ~3244–3264 |
| 7 | Reversibility without ENR-06 factory-reset hazard | Yes | Only `blind_exit` is immutable (`membership.rs` ~2066–2074); blind_relay transitions reversible with privacy-boundary acknowledgement (`role_presets.rs` ~691–704) |
| 8 | Transition ordering / crash recovery / residue explicit | Yes (design) | Design §6/§13.2; implementation is later-phase (§14.7) |
| 9 | Token/hello v2 eliminate identities, not hash them | Yes | §7 of this review — no identity fields exist |
| 10 | Endpoint-bound fresh PoP keys | Yes | Presenter key is a signed token field; §3 of this review |
| 11 | Negotiation / replay namespaces / downgrade / anti-rollback / anti-fork / software rollback fail-closed | Yes | Fleet descriptor forces `[2]` on `identity_blind`; generation/digest/epoch acceptance checks; §15.2 rollback semantics; replay namespaces in §4 of this review |
| 12 | Every control names enforcement + verification | Yes | Mutation-obligation tests present (gate, ordering witnesses, replay, pairing, vectors) |
| 13 | Linux/macOS/Windows independently enforced | Design yes; code pending | Per-OS paths are §14.8, not yet built — correctly not claimed |
| 14 | UI honest, no silent fallback | Design yes; code N/A | §15.2/§6.3 UX obligations; no UI surface for blind_relay exists yet |
| 15 | Remaining choices OPEN, not fabricated | Yes | §16 items 4–7 open; 1–3 PROPOSED pending this review + owner approval |
| 16 | Parity-plan modification deferred | Yes | Design §13.3; parity matrix untouched |

## 11. Verdict and production decision

**No BROKEN finding.** All seven attacks HELD against the phase 1–4 implementation. The canonical-parsing discipline, PoP binding, admission ordering, advertisement blocking (phase-1 gates), triple go-live gate, identity elimination, and fail-closed posture all match the design's mandates, with the five documented findings as follow-ups.

**GO/NO-GO for production advertisement: NO-GO.** This is the correct outcome and the gates are working as designed:

1. §16 items 1–3 remain **PROPOSED** (`BlindRelayProtocolSelection_2026-08-28.md` §6 names the PoP composition review as the remaining open gate); items 4–7 are unresolved. Owner approval is required to lift the phase-1 gates in `membership.rs`/`enrollment.rs`.
2. §15.1 requires an *independent* cryptographic/protocol review plus live-lab evidence stages (§13.2) that have not run. **This document is a GLM first pass and satisfies neither**; a second independent review (different model or human) is recommended before `BLIND_RELAY_V2_ADVERSARIAL_REVIEW_APPROVED` is set, and F4 must be closed before the forwarding phase lands regardless.
3. When advertisement is enabled, F5 should be fixed in the same change so the local-role alignment check enforces the exact set, and F1–F3 should be folded into the wire-freeze change so token-level parsing is byte-canonical on its own, not merely hello-level.
