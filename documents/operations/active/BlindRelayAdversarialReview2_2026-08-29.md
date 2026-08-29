# Blind Relay — Independent SECOND Adversarial Security Review (Phases 1–4 on `main`)

**Status:** Review complete. **No exploitable BROKEN defect found** in the reviewed
surface. Independently confirms the five findings of the first review (F1–F5) and
adds three observations (O1–O3). **Production advertisement verdict: NO-GO** — the
gate is correctly held closed; this review does not flip `BLIND_RELAY_V2_ADVERSARIAL_REVIEW_APPROVED`
and does not authorize advertisement.
**Date:** 2026-08-29
**Reviewer:** Claude (Opus) — the genuinely-independent second review. The FIRST
review (`BlindRelayAdversarialReview_2026-08-29.md`) was performed by GLM (Zhipu),
the same model family that WROTE the phases-1–4 code; per design §15.1 that is not
an independent review. This document is the required different-model second pass.
Doc-only; no code changed; no gate flipped; no gates run.
**Scope reviewed:** `blind_relay` phases 1–4 as merged on `main`, against
`BlindRelayRoleDesign_2026-08-27.md` (§3 threat model, §5 fail-closed tables, §7
protocol, §16 open items, §17 checklist) and the proposed selections in
`BlindRelayProtocolSelection_2026-08-28.md` (§1 encoding, §2 PoP, §3 replay).
Conventions follow `AnchorBundlePullAttestationSecurityReview_2026-07-20.md`.
**Method:** every claim re-verified against the code with file:line evidence; the
first review's HELD verdicts were treated as claims to break, not facts to trust.

## 1. Files read in full and by targeted probe

Read in full: `crates/rustynet-control/src/blind_relay.rs` (2460 lines);
`crates/rustynet-relay/src/blind_relay_listener.rs` (2529 lines). Verified by
targeted read/grep: `crates/rustynet-control/src/membership.rs`
(reducer + exact-set validator + the `MembershipOperation` enum),
`crates/rustynet-control/src/enrollment.rs`,
`crates/rustynet-control/src/role_presets.rs`,
`crates/rustynet-control/src/lib.rs` (`decode_hex_to_fixed`), and
`crates/rustynetd/src/daemon.rs` (role projection + alignment check + advertisement
posture). Both design documents and the first review were read in full.

## 2. Attack 1 — Wire format: force acceptance of a non-canonical form

**Verdict: HELD.** I tried each malformation the task names and each is rejected
before any signature use.

- **Oversize:** size gate before allocation — `blind_relay.rs:650`, `:669`
  (token), `:1104`, `:1119` (hello), `:1409`, `:1427` (fleet). Nothing
  attacker-sized is allocated first.
- **Non-UTF-8:** rejected at the `std::str::from_utf8` gate before any line work
  (`:655`, `:1109`, `:1414`).
- **Unknown key / duplicate key / signature-not-final:** allowlist
  (`is_allowed_blind_relay_token_v2_key`, `:624`, checked `:696`), `BTreeSet`
  seen-key duplicate reject (`:711`), and signature-must-be-final-line
  (`:686–690`).
- **Reorder / trailing data / noncanonical:** the canonical re-encode equality
  `token.canonical_payload() != payload` at `:828` (fleet `:1566`) is the decisive
  guard — a parsed struct is re-serialized in canonical order and byte-compared to
  the presented payload, so a reorder with a valid signature is still rejected.
- **Leading-zero / signed integer:** `parse_canonical_u64` (`:181`) rejects empty,
  `>20` digits, a leading `0` on a multi-digit value (`:187`), and any non-digit
  byte (`:192`) — so `+5` and `007` are both rejected. This is stricter than the
  v1 `u64::from_str` path, as the selection §1.3 requires.
- **`verify_strict`, never `verify`:** confirmed — `grep '\.verify('` returns
  **zero** hits in both files; every acceptance path calls `verify_strict`
  (`:521` token, `:977` PoP, `:1378` fleet).
- **Unbounded fields:** none. Every field is a fixed-width hex `[u8; N]`, a
  ≤32-byte ASCII text field, a ≤20-digit integer, a closed enum, or a
  bounded/deduped/sorted list (`MAX_BLIND_RELAY_PROTOCOL_VERSION_ENTRIES = 8`,
  `MAX_BLIND_RELAY_PROFILE_IDS = 64`).
- **Hex strictness:** `decode_hex_to_fixed` (`lib.rs:3723`) `trim()`s its input
  and accepts **uppercase** hex (`decode_hex_nibble`, `:3740`). Both are neutralized
  for every payload field by the re-encode equality: `hex_bytes` renders lowercase
  with no padding, so an uppercase or space-padded field fails
  `canonical_payload() != payload`. I confirmed this reasoning holds for all hex
  payload fields; the only field the token-level re-encode does not cover is the
  final `signature` line (see F1).

**Re-encode equality enforced BEFORE signature use? YES.** In the token parser the
re-encode check (`:828`) runs before the token is handed to any verifier — the
parser returns the struct, and the listener calls `verify_signature` only after a
successful parse (`blind_relay_listener.rs:1106`). The listener's actual input is
the *hello* parser, whose full-wire re-encode `hello.to_wire() != wire`
(`:1195`) covers the entire datagram including the token's signature line and the
three envelope lines — so the token-level F1/F2 gaps below cannot reach it.

**Agreement with first review:** AGREE, HELD. F1–F3 confirmed (below). One
non-material arithmetic slip in the first review: it states the hello "pins the
line count at exactly 19 (15 token lines + 3 envelope lines)"; 15 + 3 = **18**,
and the code agrees — `BLIND_RELAY_HELLO_V2_WIRE_LINES = 15 + 3 = 18`
(`blind_relay.rs:1033`, checked at `:1130`). The code is correct and self-consistent;
only the prose "19" is wrong.

## 3. Attack 2 — Proof of possession

**Verdict: HELD.**

- **Domain separation:** transcript opens `domain=rustynet-control-blind-relay-pop-v1`
  (`canonical_bytes`, `:924–936`).
- **Bound to exact token bytes (`token_digest`):** the transcript carries
  `token_digest = SHA-256(token.canonical_payload())` (`payload_digest_hex`,
  `:511`; wired in `pop_transcript`, `:1069`). Because the parser already enforced
  presented-bytes == canonical, the digest binds the exact presented token.
- **Cross-circuit replay:** impossible via two independent mechanisms — the token
  digest is inside the transcript (a different token ⇒ different digest ⇒ PoP
  fails), AND the listener records a defense-in-depth `pop_digest` over
  `(client_nonce, relay_challenge, pop_signature)` in the replay store
  (`blind_replay_digest_pop`, `:574`; checked step 8, `listener:1161–1171`).
- **Per-field transcript mutation:** the relay reconstructs the transcript from
  the hello/token fields (`pop_transcript`, `:1067`) and verifies with
  `verify_strict`; any mutation of `relay_challenge`, `circuit_handle`,
  `leg_handle`, `leg_slot`, `privacy_epoch`, or `client_nonce` changes the
  reconstructed bytes and fails the proof. Every bound field is a token/hello field
  and each is exercised by the §1.3 vector-14 mutation tests.
- **Degenerate/all-zero presenter key:** rejected before `VerifyingKey::from_bytes`
  (`reject_all_zero`, `verify_blind_relay_pop_signature:969`), and the key decode is
  fallible with the error propagated (`:970`) — no `unwrap`/`expect`.
- **Per-circuit key freshness:** structural — the presenter key is an issuer-signed
  token field, and the listener's pairing step rejects two legs sharing a
  `presenter_digest` (`listener:1201`).

**Agreement:** AGREE, HELD.

## 4. Attack 3 — Ten-step admission ordering and replay

**Verdict: HELD**, with the same pre-forwarding design gap F4 the first review
flagged (independently reproduced below).

- **Cheap-before-expensive is structural.** Step 1 parse + step 2 rate limit run
  before any crypto; the clock is fetched inside step 3
  (`now_unix.ok_or(ClockUnavailable)`, `:1088`) before the HMAC; no signature,
  HMAC, or circuit allocation precedes frame-parse + source-prefix rate-limit. The
  `BlindAdmissionStage` observer makes the order test-witnessable (`:1070` onward).
  I traced every early-return and none allocates circuit state before step 10.
- **Rate-limit key is identity-free and bounded-map fail-closed.** `SourcePrefix`
  is /24 (v4) or /48 (v6), family-tagged (`:266–282`); `SourcePrefixLimiter::check`
  prunes-then-rejects at `MAX_SOURCE_PREFIX_LIMITER_ENTRIES = 16_384`
  (`:304–322`) — never allocates above the cap under a flood. It does NOT reuse the
  v1 per-`node_id` key (v2 carries no node id).
- **Replay store unavailable ⇒ REJECT, never fail-open.** `BlindReplayStore::open`
  refuses a corrupt existing store (no TOFU re-init, `:627–669`); `insert_all`
  rolls back the in-memory insert on persist failure (`:699–711`); a full store
  prunes-once then **rejects admission** rather than evicting live entries
  (`:684–693`); `prune` **skips** (retains everything) on clock failure
  (`:718–724`). There is no memory-only mode — the config requires a
  `replay_store_path`. Retention `TTL + 2*skew + 1` is compile-time asserted
  (`:93–99`).
- **Address-validation HMAC key genuinely rotates (not a stable linkability
  cookie).** `AddressValidationKeyRing` holds keys `Zeroizing`, rotates
  strictly-forward (`epoch <= active ⇒ reject`, `:398`), refuses a zero key
  (`:380`, `:395`), and evicts beyond 8 epochs (`:403`). The artifact carries a
  30-second expiry (`BLIND_ADDR_VALIDATION_TTL_SECS`, `:134`), is never persisted,
  and binds `(observed addr, client_nonce, privacy_epoch, key_epoch, expiry)` with
  a constant-time tag compare (`verify_artifact:522`). It cannot become a stable
  cookie. I confirmed the rotation is genuine key material, not a relabeled
  constant.
- **Replay: three digest namespaces**, domain-separated `"v2"`/`"v2-nonce"`/`"v2-pop"`
  (`:158–160`); the leg digest is exactly the §3 key
  `sha256("v2"|privacy_epoch|nonce|leg_handle)` (`:547`). Step 8 rejects on any
  `contains`; step 10 commits all three atomically via `insert_all` before the
  in-memory allocation (`:1238`), so a retry of the exact hello is rejected at
  step 8.

**F4 (independently reproduced) — third leg after pairing.** At `:1263–1268` a
paired circuit is `self.circuits.remove(&circuit_key)`. A subsequent hello for the
same `(privacy_epoch, circuit_handle)` finds no waiting entry (`self.circuits.get`
⇒ `None`, `:1188`) and takes the `NewCircuit` branch (`:1212`), allocating a fresh
waiting circuit for an already-paired handle. §7.6 requires third-leg ⇒
close/quarantine. **Not exploitable in phase 4** — nothing forwards, capacity caps
still bound it (256 total), and a fresh leg needs a fresh issuer-signed token, so it
is not a DoS either. **Blocking obligation before the forwarding phase.** AGREE with
the first review's F4, severity and framing.

## 5. Attack 4 — Reducer / advertisement: can production signed state carry `blind_relay`?

**Verdict: HELD.** I enumerated every capability-mutating path.

- The `MembershipOperation` enum (`membership.rs:402`) has exactly two ops that
  introduce or change a node's capabilities: `AddNode` and `SetNodeCapabilities`.
  Both refuse `RoleCapability::BlindRelay` fail-closed at the **reducer**
  ("design-only; pending §16 wire-format sign-off", `:2043–2046`, `:2075–2078`).
  `RestoreNode`/`RevokeNode`/`RotateNodeKey` cannot introduce a capability the node
  never had, so they are not additional entry points.
- **Enrollment admission** refuses it for both spellings
  (`enrollment.rs:262–265`; test `:473`).
- **Exact-set is future-proof (a NEW capability refused by default).** The
  signed-state validator `validate_membership_node_capabilities`
  (called on every node at `membership.rs:251`) checks
  `capabilities.len() == 2 && contains(RelayHost) && contains(BlindRelay)`
  (`:2742–2756`) — a full-set allowlist, not a forbidden-values list, so any
  future `Capability::Foo` added onto a blind relay is refused. Tests cover
  requires-relay-host, exact-pair, and rejects-every-other-co-capability
  (`:3244–3301`).
- **Trust boundary caveat (verified, not a defect).** The exact-set validator
  *permits* the canonical `{relay_host, blind_relay}` set — it is the
  forward-looking invariant for when the gate lifts. The actual block on
  advertisement is the reducer/enrollment construction gates above. Since adversary
  R holds no issuer signing key, R cannot craft a signed snapshot that bypasses
  those operation gates. This is sound.
- Preset/daemon projections agree: preset `{ServesRelay, BlindRelay}`
  (`role_presets.rs:364`), daemon `{RelayHost, BlindRelay}` for
  `NodeRole::BlindRelay` (`daemon.rs:1974`, `:21673`); `BlindRelay` appends last in
  the capability ordering. Entering `blind_relay` is `Blocked` from any source but
  Admin/Relay (`role_presets.rs:587–588`, `:647–661`), and `blind_relay →
  blind_exit` stays `Irreversible` (`:706–709`).

**F5 (independently reproduced, and I raise its framing).** The daemon local-role
alignment check for `NodeRole::BlindRelay` (`daemon.rs:2119–2148`) is a
**forbidden-list** of 7 capabilities plus anchor sub-caps. It verifies *absence* of
those, but does NOT assert *presence* of the exact `{RelayHost, BlindRelay}` pair,
and — the sharper point — a **future** capability `Foo` not in the FORBIDDEN array
would pass. That is precisely the "a list of currently forbidden values silently
becomes permissive when a new capability is appended" anti-pattern the design's
§5.1 explicitly forbids, at validation site (3) of the six §5.2 requires. The first
review classifies F5 as "defense-in-depth"; I agree it is **unreachable today**
(signed state cannot carry `blind_relay` at all, and the signed-state validator is
exact-set), but I record it as a **direct §5.1 mandate violation** at site (3), not
merely a hardening nicety. It must be converted to a full-canonical-set compare
(mirroring `membership.rs:2742`) before go-live.

**Agreement:** AGREE, HELD. F5 confirmed; framing elevated.

## 6. Attack 5 — Go-live gate: can the listener open in production today?

**Verdict: HELD — and materially stronger than a triple gate.**

- **O1 (new, strengthens the first review): the listener is entirely DORMANT.** A
  repo-wide search for any use of `BlindRelayListener`, `try_open`, or
  `BLIND_RELAY_V2_ADVERSARIAL_REVIEW_APPROVED` outside
  `blind_relay_listener.rs` returns **only the `pub mod`/`pub use` re-exports** in
  `crates/rustynet-relay/src/lib.rs:3,10–14`. Nothing in `rustynetd` or anywhere
  else constructs the config or calls `try_open`. The admission listener is
  compiled but never instantiated on any production path. Even if all three gates
  were flipped, no code path opens it. This is a stronger property than the gate
  chain itself.
- **Triple gate.** `BLIND_RELAY_V2_ADVERSARIAL_REVIEW_APPROVED: bool = false`
  (`:83`) is a compile-time const — flipping it is a visible code change, not
  config. `try_open` (`:964`) requires all three of the const,
  `signed_capability_granted`, and `operator_enabled` in one `&&` chain (`:965–970`);
  any single gate alone leaves it `GateClosed`.
- **Fail-closed even if the const flips.** `signed_capability_granted` can never be
  true in production while Attack 4's reducer/enrollment gates refuse the capability
  — the config field would be derived from live signed membership that cannot carry
  `blind_relay`.
- **No config bypass.** `build()` is module-private (`:974`); external callers
  reach it only through `try_open`. No runtime fallback constructor exists.
- **O2 (new): a second, independent fail-closed layer if it ever opened.** The
  address-validation *first exchange* (the relay issuing the artifact a client
  presents back) is not wired in phase 4 — only `issue_address_validation_artifact`
  is exposed (`:1035`) with no datagram handler calling it. So even a fully-opened
  listener would reject **every** hello at step 3 (no client could obtain a valid
  `relay_challenge`). Moot given O1, but it is an additional closed door, not an
  open one.

**Agreement:** AGREE, HELD; I add O1/O2 as reinforcing evidence.

## 7. Attack 6 — BR-P1: does the relay learn a stable identity?

**Verdict: HELD.**

- The v2 token (`BlindRelayLegTokenV2`, `:341`) carries no identity field: no node
  id, no peer id, no WireGuard/gossip/enrollment key, no membership index, no
  hostname/label, no policy id, no network, no stable pseudonym, nothing
  identity-derived. Every multi-byte field is a fresh CSPRNG handle
  (`circuit_handle`/`leg_handle`/`nonce`, all-zero rejected), a per-circuit
  presenter key, the public `audience_relay_id` (the relay's own id, not an
  endpoint's), or coarse public metadata (`profile_id`, timestamps, epoch).
- Hello v2 adds only `client_nonce`, the address-validation artifact
  (`relay_challenge`), and the PoP signature — no endpoint identity.
- Relay-resident state is §7.7-minimal: `BlindWaitingLeg` holds `leg_handle`, a
  SHA-256 `presenter_digest` (never the raw key, `:1179`), the observed tuple
  (admitted residual per §3.3), and an expiry — memory only. Replay entries are
  one-way digests; nothing links a leg to a Rustynet identity.
- **No identifier logged or persisted.** The admission path emits no per-hello log
  line; the only `eprintln!` is the skew-clamp warning at open (`:1006`). Reject
  classes are fixed strings (`BlindRejectReason::Display`, `:188–202`) — no attacker
  content, no identity. All `Debug` impls redact secrets
  (token `:369`, transcript `:873`, hello `:1016`, keyring `:366`, config `:928`).
  The persisted replay file holds only `<digest> <timestamp>` lines, mode-0600.

**Agreement:** AGREE, HELD. The only attacker-controlled string in any error path is
F3's bounded enum-value echo in `blind_relay.rs` control-plane errors (`:97`, `:126`,
`:155`), which carries no identity and never reaches the listener's admission errors.

## 8. Attack 7 — Fail-open hunt

**Verdict: HELD.** Every "missing/invalid/unavailable" branch I traced rejects:

| Condition | Behavior | Evidence |
| --- | --- | --- |
| Clock unavailable | `ClockUnavailable` at step 3 before crypto; prune retains on clock failure | `:1088`, `:718–724` |
| Replay store corrupt | refuse to open (no TOFU) | `:627–669` |
| Replay store write failure | in-memory rollback; admission rejected | `:699–711` |
| Replay store full | prune-once then reject, never evict | `:684–693` |
| Replay store missing mode | none — `replay_store_path` is required, no memory-only path | config `:917` |
| Rate-limiter map full | prune then reject, never over-allocate | `:306–311` |
| Waiting/capacity exhausted | `Capacity`, never evict | `:1214–1231` |
| All-zero handle/key/nonce | rejected at parse | `reject_all_zero` throughout |
| Unknown issuer key id | `Unauthorized` at step 4 before signature | `:1102–1105` |
| Missing/foreign/stale address artifact | `AddressValidation` at step 3 | `:1089–1098` |
| Invalid sig / PoP / degenerate key | rejected (`verify_strict`, fallible decode) | `:1106`, `:1149` |
| Empty issuer allowlist / empty profiles / zero relay id | listener refuses to open | `build`, `:975–991` |
| Zero/omitted resource limit | clamped up to ≥1 (never read as "unlimited") | `:992–1003` |

The §9 "CSPRNG unavailable ⇒ no allocation" rule applies to the not-yet-built
minting surfaces (issuer/client); the relay side takes challenge bytes from its
caller, so no weak-RNG fallback exists in reviewed code. Correctly pending, not a
phase-4 defect.

**Agreement:** AGREE, HELD.

## 9. Findings register (this review)

| ID | Severity | Where | Status vs first review |
| --- | --- | --- | --- |
| F1 | Minor | `blind_relay.rs:702` | CONFIRM — signature value trimmed at token level; inert (hello full-wire compare catches it; listener consumes only hello). Fix: reject whitespace in the signature value. |
| F2 | Minor | `blind_relay.rs` `lines()` | CONFIRM — `\r` stripped, CRLF normalizes at token level; inert at hello level. Fix: reject `\r` at the UTF-8 gate. |
| F3 | Minor | `blind_relay.rs:97,126,155` | CONFIRM — enum `from_wire` errors echo attacker value (≤4096 B, no identity); violates §7.3 closed-class phrasing. Fix: fixed-string field-named errors. |
| F4 | **Blocking before forwarding** | `blind_relay_listener.rs:1263–1268` | CONFIRM — third leg for a paired `(epoch, circuit_handle)` allocates a fresh waiting circuit instead of close/quarantine (§7.6). Not exploitable while nothing forwards. Fix: track `Paired` circuits (bounded, expiring); post-pair leg ⇒ close/quarantine. |
| F5 | **§5.1 violation at site (3) — fix before go-live** | `daemon.rs:2119–2148` | CONFIRM + ELEVATE — alignment is a forbidden-list, so it is future-permissive (the exact anti-pattern §5.1 forbids) and does not assert the exact pair. Unreachable today; fix to a full-canonical-set compare mirroring `membership.rs:2742`. |
| O1 | Positive (strengthens gate) | `rustynet-relay/src/lib.rs:3,10` | NEW — the listener is never instantiated on any production path; `try_open` has zero callers. Dormant code, stronger than the triple gate. |
| O2 | Positive (extra closed door) | `blind_relay_listener.rs:1035` | NEW — the address-validation first-exchange (artifact issuance) is unwired, so an opened listener would reject every hello at step 3. Moot given O1. |
| O3 | Doc nit | first review §2 | NEW — first review says hello is "19 lines"; code is 18 (`15 + 3`, `blind_relay.rs:1033`). Code correct; prose wrong. Non-material. |

None fixed here (review-only mandate). I DISAGREE with the first review on no
substantive verdict; the only correction is O3's arithmetic.

## 10. §17 design-acceptance checklist verdict (independently re-judged)

| # | Item | Verdict | Evidence |
| --- | --- | --- | --- |
| 1 | BR-P1 falsifiable, BR-R1 prominent | Yes | Design §3.2/§3.3; §7 above found no violation |
| 2 | Adversary explicit incl. compromised relay host | Yes | Design §3.1 |
| 3 | No IP/timing/flow anonymity claim | Yes | Design §3.3 |
| 4 | Same-circuit leg association admitted | Yes | Design §3.2/§3.3; tuple stored as residual (`:829`) |
| 5 | `BlindRelay` modifier requiring `RelayHost` + dedicated local role | Yes | `role_presets.rs:364`; `daemon.rs:1974` |
| 6 | Signed state exactly `{RelayHost, BlindRelay}`, future rejected by default | Yes | `membership.rs:2742–2756` + tests `:3244–3301` |
| 7 | Reversibility without ENR-06 factory-reset hazard | Yes | Only `blind_exit` immutable (`role_presets.rs:624`); blind_relay reversible with privacy-boundary reinit (`:698`, `:733`) |
| 8 | Transition ordering / crash recovery / residue explicit | Yes (design); code phase 4+ | Design §6/§13.2 |
| 9 | Token/hello v2 eliminate identities, not hash them | Yes | §7 above — no identity fields exist |
| 10 | Endpoint-bound fresh PoP keys | Yes | §3 above |
| 11 | Negotiation/replay/downgrade/anti-rollback/anti-fork/rollback fail-closed | Yes | `identity_blind ⇒ [2]` (`:1325`); `check_..._acceptance` (`:1598`); replay namespaces §4 above |
| 12 | Every control names enforcement + verification | Yes | Mutation-obligation tests: gate, stage-order witnesses, replay, pairing, 16 vectors |
| 13 | Linux/macOS/Windows independently enforced | Design yes; code pending | Per-OS paths §14.8, correctly not claimed |
| 14 | UI honest, no silent fallback | Design yes; code N/A | No UI surface exists yet |
| 15 | Remaining choices OPEN, not fabricated | Yes | §16 items 4–7 open; 1–3 PROPOSED pending owner approval |
| 16 | Parity-plan modification deferred | Yes | Parity matrix untouched |

Every item independently reaches the same verdict as the first review.

## 11. Verdict and production decision

**No BROKEN finding.** All seven attacks HELD against phases 1–4. Canonical parsing,
PoP binding, ten-step admission ordering, advertisement blocking, the triple
go-live gate (plus the dormant-listener property O1), identity elimination, and
fail-closed posture all match the design mandates. The five findings F1–F5 are
confirmed exactly as the first review recorded them, with F5's framing elevated to a
§5.1 mandate violation and three positive/nit observations added.

**GO / NO-GO for opening production advertisement: NO-GO.** This is correct and the
gates work as designed. Advertisement must stay closed because:

1. **§16 owner sign-off is unmet.** Items 1–3 remain PROPOSED in
   `BlindRelayProtocolSelection_2026-08-28.md`; items 4–7 are unresolved. Owner
   approval is required to lift the phase-1 reducer/enrollment gates.
2. **§15.1 live-lab evidence is unmet.** The §13.2 stages
   (`blind_relay_identity_privacy`, `_protocol_negatives`, `_resource_limits`,
   `_transition_residue`, `_revocation`, `_platform_verifier`) have not run. No live
   proof exists.
3. **F4 must close before the forwarding phase lands**, and **F5 must close before
   go-live** (fold F1–F3 into the same wire-freeze change so token-level parsing is
   byte-canonical on its own).

**On the independent-review gate specifically:** this Claude review is the
different-model second pass §15.1 asks for, and for the phase-1–4 composition **as
reviewed** it found no exploitable defect. That satisfies the *review* precondition
for the reviewed surface — but it is only ONE of the gates above, and it explicitly
does NOT authorize flipping `BLIND_RELAY_V2_ADVERSARIAL_REVIEW_APPROVED`: the owner
§16 approval and the §13.2 live-lab evidence remain independent, unmet gates, and
F4/F5 are open obligations. The compile-time review bit and the reducer/enrollment
gates must stay as they are. Production advertisement is **NO-GO**.

## 12. References

- `documents/operations/active/BlindRelayRoleDesign_2026-08-27.md` (§3, §5, §7, §8, §9, §16, §17)
- `documents/operations/active/BlindRelayProtocolSelection_2026-08-28.md` (§1, §2, §3, §6)
- `documents/operations/active/BlindRelayAdversarialReview_2026-08-29.md` (first review — GLM)
- `documents/operations/active/AnchorBundlePullAttestationSecurityReview_2026-07-20.md` (house standard)
- `crates/rustynet-control/src/blind_relay.rs`, `crates/rustynet-control/src/membership.rs`,
  `crates/rustynet-control/src/enrollment.rs`, `crates/rustynet-control/src/role_presets.rs`,
  `crates/rustynet-control/src/lib.rs`
- `crates/rustynet-relay/src/blind_relay_listener.rs`, `crates/rustynet-relay/src/lib.rs`
- `crates/rustynetd/src/daemon.rs`
