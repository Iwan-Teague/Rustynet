# Blind relay protocol selection — §16 items 1–6 resolved by composition

**Status:** PROPOSED — doc-only. Selections for §16 items 1–3, measurement plans for
items 4 and 6, and a retention proposal for item 5 of
`BlindRelayRoleDesign_2026-08-27.md` ("the design"). No code, no schema, no
platform claim, and no release claim is created by this document. Nothing here is
accepted until architecture/security review and owner approval; the design's §16
list stays authoritative until then. This document supplements the design and does
not modify it except for the dated pointer line in its §16.

**Method (mandatory survey-before-select).** Each item first enumerates what the
repository already uses, with file:line evidence, and only then selects by
composition of those primitives. AGENTS.md §3 forbids custom cryptography and new
wire-format invention where an existing pattern serves; the design's §0 requires
approved primitives only. Consequently every selection below reuses an in-tree
dependency and an in-tree pattern; the only genuinely new artifacts are the v2
schemas themselves and their test vectors, which the design already mandates.

**Related owner-decision surface:** `OwnerDecisionDigest_2026-08-27.md` already
carries "the blind-relay token/hello v2 selection" as a pending owner decision;
the selections here are the input to that decision, not the decision itself.

## 0. Survey summary — what the repo already uses for signed material

The single most load-bearing survey finding: **the repository does not use serde,
JSON, CBOR, protobuf, or bincode for signed control material.** Every signed
artifact in the trust plane is a hand-rolled, line-oriented canonical
`key=value` text grammar with an exact parser that re-encodes and compares:

| Artifact | Canonical form | Evidence |
|---|---|---|
| RelaySessionToken v1 | `version=1\nnode_id=…\n…\n` lines + `signature=<hex>` final line | `crates/rustynet-control/src/lib.rs:1947-1958` (payload), `:1998-2004` (wire), `:2006-2125` (exact parser) |
| Membership snapshot / signed update envelope | `canonical_payload()` / `canonical_envelope()` string builders; `parse_key_values` line parser | `crates/rustynet-control/src/membership.rs:307`, `:491`, `:682`, `:1181`, `:2220`, `:2514` |
| Relay fleet bundle | canonical-payload equality check + explicit version gate | `crates/rustynet-control/src/lib.rs:1584`, `:3317-3321` |
| Local key-rotation ledger | canonical payload + `digest=` line, atomic persist | `crates/rustynetd/src/key_rotation.rs:222-235` |

House parser norms visible in the v1 token parser (`lib.rs:2006-2125`), all of
which are fail-closed and all of which v2 inherits:

- key allowlist — unknown key rejected (`:2029`);
- duplicate key rejected via a `BTreeSet` of seen keys (`:2044-2048`);
- `signature` must be the final line (`:2019-2023`, `:2054`);
- version pinned explicitly (`:2057-2062`); scope pinned (`:2063-2068`);
- binary fields are fixed-width hex into `[u8; N]` (`:2082-2091`);
- degenerate values rejected (empty/self-pair ids `:2071-2080`, all-zero nonce
  `:2086-2090`, invalid timestamps `:2098-2102`);
- bounded TTL enforced at parse (`:2114-2118`, `MAX_RELAY_SESSION_TOKEN_TTL_SECS
  = 120` at `:1722`);
- **canonical re-encode equality check** — the parsed struct is re-serialized and
  must byte-match the payload, rejecting reorderings and noncanonical forms
  (`:2119-2123`);
- constant-time comparison for secret fields via `subtle::ConstantTimeEq`
  (`:1976-1995`); `Debug` redacts secret fields (`:1773-1786`).

Serialization-library facts: `serde_json` is *not* a signed-material dependency —
in `rustynet-relay` it is optional behind the `daemon` feature
(`crates/rustynet-relay/Cargo.toml:16,39`) and in `rustynetd` it serves
local/config state (`crates/rustynetd/Cargo.toml:32`). No postcard, bincode, or
CBOR dependency exists anywhere in the workspace.

Crypto facts: Ed25519 via **ed25519-dalek v2** in every crypto-touching crate
(`rustynet-control/Cargo.toml:16`, `rustynet-crypto/Cargo.toml:14`,
`rustynetd/Cargo.toml:24`, `rustynet-relay/Cargo.toml:10` with `rand_core`);
verification uses **`verify_strict`** (`lib.rs:1940`) — strict (malleability-
rejecting) verification is the house norm. Digests are SHA-256 via `sha2 0.10`
(`rustynet-control/Cargo.toml:13`) with a NIST known-answer test in tree
(`crates/rustynet-crypto/src/lib.rs:4937-4938`). MACs are HMAC-SHA256 via `hmac
0.12` (`lib.rs:1222-1244`, trust-state integrity). Randomness is the kernel
CSPRNG with fail-closed error propagation (`rand::rngs::OsRng.try_fill_bytes`,
`lib.rs:1868-1873`). Domain separation is an established convention of
`rustynet-control-<purpose>-v1` byte strings used as HKDF salt/info
(`lib.rs:47-52`: signing-seed, assignment, dns-zone, access-token, endpoint-hint,
gossip).

Persistence facts: watermarks are per-domain files under `/var/lib/rustynet/`
(`crates/rustynetd/src/daemon.rs:204` trust, `:269` membership, `:288` assignment,
`:311` traversal, `:316` **relay-fleet**, `:363` dns-zone), consumed through a
fail-closed preflight that loads the previous watermark, verifies the bundle
against it, then persists the new one (`daemon.rs:4663-4680`). Atomic file
replacement is the temp-file/single-fsync/single-rename pattern:
`atomic_write_secure` (`crates/rustynetd/src/key_rotation.rs:931`; the rename
boundary is documented as the crash-recovery point at `:222-228`), `write_atomic`
(`crates/rustynetd/src/key_material.rs:1342`, with the Windows directory-fsync
caveat at `:1447`), and `atomically_replace_file`
(`crates/rustynetd/src/linux_dns_protect.rs:405`). A **local key-rotation ledger
already exists**: `LocalKeyRotationLedger` holds `epoch + verifier archive +
PerEpochReplayWatermark` in one atomic record with a fail-closed `LedgerCorrupt`
loader (`key_rotation.rs:79-110`, `:236-243`). The relay already has an optional
durable replay store (`NonceStore::load(replay_store_path)`,
`crates/rustynet-relay/src/transport.rs:254-256`).

Measurement facts are surveyed in §4.

---

## 1. Item 1 — Encoding and framing

**Design requirement (§16.1):** "select the exact reviewed, bounded canonical
representation for fleet v2, token v2, and hello v2. The decision must include
duplicate/unknown-field behavior and cross-language test vectors."

### 1.1 Survey (evidence)

- RelaySessionToken v1 canonical payload is a plain-text line grammar — not a
  binary serializer — and the parser re-encodes and compares
  (`lib.rs:1947-1958`, `:2119-2123`). The doc comment pins the contract:
  "Canonical signed payload. All fields that appear here are covered by the
  signature. **Changing this format is a breaking change.**" (`:1945-1946`).
- Membership snapshots/updates, assignment/traversal bundles, and the fleet
  bundle use the same family: string canonical payloads, `parse_key_values`
  line parsing, typed bounded field parsers (`membership.rs:2514`, `:2534-2552`),
  capability parsing (`:2751`), fleet canonical check (`lib.rs:1584`) and version
  gate (`:3317-3321`).
- The gossip datagram path is "strictly version-gated, length-checked"
  (`crates/rustynetd/src/gossip_transport.rs:23`) with an `Oversized { length,
  max }` typed error (`:69-70`) — framing bounds are enforced at the transport
  edge, which hello v2 inherits.
- Existing bounded-size precedents: `MAX_PACKET_SIZE_BYTES = 65_536`
  (`transport.rs:49`), `MAX_HELLOS_PER_NODE_PER_SEC = 5` (`:111`),
  `MAX_HELLO_LIMITER_ENTRIES = 16_384` (`:1241`),
  `MAX_CLOCK_SKEW_TOLERANCE_SECS` (`:91`), `MAX_TRUST_STATE_FILE_BYTES = 64 KiB`
  (`lib.rs:1090`), `MAX_GOSSIP_WATERMARK_BYTES = 256 KiB`
  (`crates/rustynetd/src/gossip_runtime.rs:81`), relay-id label ≤ 16 ASCII bytes,
  single-line (`lib.rs:1726-1743`).
- Cross-language vectors: **none exist today.** The closest in-tree precedents
  are the NIST SHA-256 KAT (`rustynet-crypto/src/lib.rs:4937-4938`) and the
  canonical-order/signed-preimage fixtures
  (`lib.rs:6584` `endpoint_hint_signer_payload_pins_canonical_ordering`,
  `:6625` "payload must be order-independent (canonical sort)"). The v2 vector
  set is therefore new work to *define* (below) and later to *generate*.

### 1.2 Duplicate-field and unknown-field behavior (verified house norm, inherited)

Fail-closed rejection of both is already the enforced norm, not an aspiration:
duplicate keys are rejected by the seen-key set (`lib.rs:2044-2048`); unknown
keys are rejected by the allowlist (`:2029-2033`); and any reordering that
changes the canonical byte form is rejected by the re-encode equality check
(`:2119-2123`) even if every field is individually well-formed. v2's parsers
must implement exactly these three rejections, plus: signature-final-line
enforcement, noncanonical numeric rejection (no leading `+`, no leading zeros),
invalid UTF-8 rejection, and trailing-data rejection — each of which has a v1
analogue or is already specified for v2 by the design's §7.3 and BR-C22.

### 1.3 SELECTED — canonical line-based `key=value` text, v1 grammar, v2 schemas

All three v2 surfaces (fleet descriptor v2, `BlindRelayLegTokenV2`,
`BlindRelayHelloV2`) use the same grammar as RelaySessionToken v1:
newline-terminated `key=value` lines, `version=2` first line, fixed field order,
signature (where present) as the final line, hex for binary fields, decimal for
integers, and the canonical re-encode equality check before any signature
verification or application. Rationale: it is the only signed-wire mechanism the
repository has; it is already proven fail-closed on exactly the axes the design
demands (BR-C22); it is trivially consumable cross-language (a plain-text
grammar needs no schema compiler, which is why the v2 vector set below can be
consumed by any language); and inventing a binary format here would be exactly
the "new wire-format invention" AGENTS.md §3 forbids when an existing pattern
serves.

**Proposed bounded sizes (every field; values are proposals for security
review, mechanism is the selection):**

| Field | Bound | Precedent |
|---|---|---|
| whole token wire | ≤ 4096 bytes | v1 token is ≤ ~400 bytes; headroom without unboundedness (`MAX_TRUST_STATE_FILE_BYTES` style cap, `lib.rs:1090`) |
| whole hello datagram | ≤ 4096 bytes | datagram edge check pattern, `gossip_transport.rs:69-70` |
| whole fleet descriptor | ≤ 16 KiB | `MAX_TRUST_STATE_FILE_BYTES = 64 KiB` family, `lib.rs:1090` |
| `relay_id`/audience | ≤ 16 ASCII bytes (32 hex on wire) | `canonical_relay_id_from_label`, `lib.rs:1737-1742` |
| handles (`circuit_handle`, `leg_handle`), nonces, presenter key, digests | fixed-width hex only (32/32/32/32/64 chars) | fixed-width hex decode, `lib.rs:2082-2091` |
| ids/kind/scope/profile_id/epoch strings | ≤ 32 ASCII bytes, single-line, no control chars | `is_single_line_payload_value`, `lib.rs:1734` |
| integers | ≤ 20 decimal digits, no sign, no leading zeros | `parse_relay_token_u64` path, `lib.rs:2094-2097` |
| enum-valued fields (`leg_slot`, `relay_mode`, `token_kind`) | exact closed value sets, checked before signature use | scope pin, `lib.rs:2063-2068` |

**Test-vector set (defined here; generating the fixtures is implementation
work).** Each vector is a wire byte string plus the required verdict, published
as hex fixtures so a non-Rust checker can consume them:

1. `v2_token_roundtrip` — minted token → wire bytes → parse → re-encode is
   byte-identical (canonical round trip).
2. `v2_token_preimage` — fixed field inputs → exact canonical payload string +
   Ed25519 signature under a fixed test seed (signed-preimage fixture, the v1
   `:6584` pattern).
3. `v2_token_duplicate_field` — one duplicated key → reject.
4. `v2_token_unknown_field` — one unknown key → reject.
5. `v2_token_missing_field` — each field omitted in turn → reject.
6. `v2_token_reordered` — canonical fields permuted → reject via re-encode
   equality even with valid signature.
7. `v2_token_overlong` — each string field at bound+1 → reject; whole-wire at
   bound+1 → reject.
8. `v2_token_noncanonical_numeric` — leading zeros / `+` sign → reject.
9. `v2_token_invalid_utf8_and_control` — non-UTF-8 byte and control char in a
   text field → reject.
10. `v2_token_trailing_data` — bytes after the signature line → reject.
11. `v2_version_confusion` — `version=1`, `version=3`, missing version → reject
    (v1/unknown rejected before allocation, design §8.2).
12. `v2_degenerate_crypto_fields` — all-zero nonce, all-zero presenter key,
    short hex fields → reject (all-zero nonce precedent `lib.rs:2086`).
13. `v2_binding_mutations` — wrong audience / scope / epoch / profile / slot /
    kind, each mutated → reject (BR-C07).
14. `v2_pop_transcript` — positive: valid proof verifies; plus per-field
    transcript mutations, wrong presenter key, and cross-circuit proof reuse →
    reject (BR-C06).
15. `v2_fleet_fork` — same generation, different digest → reject; lower
    generation/epoch → reject (BR-C09, `daemon.rs:24410-24447` test names pin
    the v1 behaviours this extends).
16. `v2_hello_envelope` — oversize, wrong order of cheap checks observable only
    as closed reason classes (no content echo, design §7.3).

**Rejected alternatives (one line each):**
- `serde_json` / canonical JSON — not used for any signed material in tree;
  duplicate-key handling is parser-dependent and the re-encode-equality norm
  does not transfer.
- bincode/postcard/CBOR — no workspace dependency; a binary format would need
  new cross-language tooling the text grammar gets for free.
- protobuf — new dependency + codegen, violates composition-only method.
- Reusing v1 payload unchanged — carries `node_id`/`peer_node_id`; the exact
  leak the role exists to remove (design §7.1).

---

## 2. Item 2 — Proof-of-possession suite

**Design requirement (§16.2):** "select the established signature algorithm and
library, canonical transcript, key validation, challenge/address-validation
mechanism, and key-erasure boundary. Security review required; no custom
cryptography."

### 2.1 Survey (evidence)

- Algorithm/library: Ed25519 via ed25519-dalek v2 everywhere; the relay already
  verifies hello tokens with `verify_strict`
  (`lib.rs:1936-1943`); the `rand_core` feature is enabled in the relay crate
  for key generation (`rustynet-relay/Cargo.toml:10`). The hardening campaign
  record `CryptoPolicyHardening_2026-08-25.md` shows the signing surface is
  under active mutation-tested hardening (zero-seed refusal, empty-signature
  fallback removal), so the suite has a live owner.
- Transcript canonicalization precedent: the enrollment/trust-plane HMAC builds
  its MAC over the exact canonical payload bytes — `compute_trust_state_mac`
  MACs `payload` as given, with the key read from a bounded file and the key
  material zeroized immediately after decode (`lib.rs:1205-1215`,
  `:1222-1244`). There is no length-prefixed binary transcript convention to
  inherit; the canonical line grammar is the transcript convention.
- Domain-separation convention: `rustynet-control-<purpose>-v1` ASCII byte
  strings as HKDF salt/info (`lib.rs:47-52`).
- Digest primitive: SHA-256 (`sha2 0.10`; `sha256_hex` used by the rotation
  ledger, `key_rotation.rs:230`; NIST KAT in tree,
  `rustynet-crypto/src/lib.rs:4937-4938`).
- Zeroize patterns: `zeroize` is a direct dependency of control, crypto, and
  rustynetd. `rustynet-crypto` applies it **unconditionally**: `SecretKey::Drop`
  zeroizes ("Unconditional: SecretKey::Drop and the key-envelope helpers
  zeroize derived…", `lib.rs:26-29`), the zeroize call is comment-pinned
  against optimizer elision (`:63-66`), `Zeroizing<String>` wraps persisted
  passphrases (`:384`, `:406`, `:414`), and parsed key lines are zeroized
  immediately after use (`:530`, `:979`, `:1009`; trust-state key line
  `lib.rs:1210-1215`). So the house pattern is **zero-on-Drop as the backstop
  plus explicit zeroize at the earliest use boundary**.
- Challenge/address validation: **nothing exists today** — there is no
  challenge/cookie mechanism in the relay crate. The existing pre-crypto gates
  are the per-node hello rate limit (`transport.rs:389`, keyed on `hello.node_id`
  — an identity-bearing key v2 must replace) and the replay store. The design
  (§7.5) already selects the shape: a QUIC-Retry-style stateless token; RFC 9000
  §8 is in the design's references.
- Keyed-state rotation for such a token: `LocalKeyRotationLedger`
  (`key_rotation.rs:79-110`) already implements epoch + fail-closed reload.

### 2.2 SELECTED — Ed25519 (ed25519-dalek v2, `verify_strict`) over a canonical line transcript; HMAC-SHA256 rotating-key stateless address validation

Pending the security review the design itself requires; the composition below
uses only in-tree dependencies.

**(a) Algorithm + library.** Ed25519 via ed25519-dalek v2 — the only signature
library in the trust plane. Presenter keys are fresh `SigningKey`s per circuit
(generated via the kernel CSPRNG; fail-closed on RNG error, `lib.rs:1868-1873`
pattern). The relay verifies with **`verify_strict`** exclusively — `verify` is
not used anywhere on acceptance paths today and must not appear in v2.

**(b) Canonical transcript layout.** The transcript is a canonical line document
in the §1 grammar (so it inherits exact parsing, single-line values, and
bounded fields), signed as its UTF-8 bytes:

```text
domain=rustynet-control-blind-relay-pop-v1
token_digest=<sha256 hex of the leg token's canonical payload>
relay_challenge=<hex, relay-generated>
circuit_handle=<64 hex>
leg_handle=<64 hex>
leg_slot=<0|1>
privacy_epoch=<decimal>
client_nonce=<hex, endpoint-generated>
```

Domain string follows the `rustynet-control-<purpose>-v1` convention
(`lib.rs:47-52`); it is version-suffix bumped (`-v1` → `-v2`) if the transcript
layout itself ever changes, which is the same breaking-change discipline the v1
token payload documents (`lib.rs:1945-1946`). `token_digest` is SHA-256 of the
token canonical payload — the ledger's `sha256_hex(payload)` precedent
(`key_rotation.rs:230`) — binding the proof to the exact signed token bytes.

**(c) Key validation.** A presented `presenter_public_key` is accepted only via
the library's fallible decode (length/type checked, rejecting malformed input)
and only for `verify_strict`; in addition the all-zero public key is rejected
as degenerate before use — the direct analogue of the all-zero nonce rejection
(`lib.rs:2086-2090`).

**(d) Challenge / address binding.** A stateless address-validation token in
the QUIC-Retry pattern (RFC 9000 §8; design §7.5): the relay HMACs
`(observed address, client nonce, privacy epoch, short expiry)` with
**HMAC-SHA256** (`hmac 0.12` + `sha2 0.10`, the trust-state MAC pair,
`lib.rs:1222-1244`) under a **rotating local key tracked in
`LocalKeyRotationLedger`** (`key_rotation.rs:79-110`). The token is returned in
a first exchange and must be presented in the hello; it is never persisted on
the relay, is bounded to the token-TTL window (mirroring the nonce-retention
window discipline, `transport.rs:50-105`), and therefore cannot become a
stable linkability cookie — the explicit warning the design carries. This is
an anti-amplification resource measure, not identity authentication (design
§7.5); v2's pre-auth rate limiter is keyed per source prefix, replacing v1's
per-`node_id` keying (`transport.rs:389`) because v2 has no node id.

**(e) Key-erasure boundary.** The presenter `SigningKey` exists only between
circuit request and circuit close. Erasure points, in order: (1) explicit
zeroize at circuit close/pair-failure/expiry and at §6.3 transition purge —
the explicit-at-boundary pattern (`lib.rs:1210-1215`, `:530`); (2) zeroize-on-
`Drop` as the crash backstop — the unconditional pattern
(`rustynet-crypto/src/lib.rs:26-29`, `:63-66`). The key is never written to
disk (the design's §7.7 memory-only rule), so there is no at-rest erasure
problem; the erasure boundary is process-lifetime of one circuit.

**(f) What the relay verifies, and in what order.** The order extends the
documented v1 order ("All security checks are performed in a deliberate order",
`transport.rs:312-325`) with the design §7.5 admission sequence:

1. bounded datagram/frame size + exact v2 envelope parse (cheap, no crypto);
2. per-source-prefix pre-auth rate limit (identity-free key);
3. stateless address-validation token verify (HMAC, rotating key) — before any
   session allocation;
4. issuer key-ID allowlist + token `verify_strict`;
5. version, kind, audience, scope, privacy epoch, profile, slot, and canonical
   field checks (the §1 rejections);
6. usable-clock, not-before/future-date, expiry, and TTL checks;
7. proof-of-possession transcript `verify_strict` against
   `presenter_public_key`;
8. durable replay-store availability + nonce/leg replay rejection;
9. global / per-source-prefix / waiting-leg / profile resource limits;
10. atomic nonce commit and bounded waiting-leg allocation.

Cheap-before-expensive is enforced: no signature work before (1)–(2), no state
allocation before (3), matching both the v1 discipline ("shed load before
signature work", `transport.rs:388-391`) and design §12.2.

**Rejected alternatives (one line each):**
- P-256/ECDSA or `ring` — a second signature stack in a single-algorithm repo;
  no in-tree precedent to inherit key handling from.
- Adopting CWT/COSE encoding — the design cites RFC 8747 for the *semantics*
  only and forbids new encodings where the house grammar serves (§7.4).
- HMAC-only possession proof — would make the relay a verifier of shared
  secrets per endpoint and reintroduce an issuer→relay secret channel; Ed25519
  public-key proof is the existing relay trust shape.
- Bearer token without PoP — rejected by the design itself (§7.4).
- Persistent (non-rotating) address-validation key — becomes a stable
  linkability cookie; forbidden by design §7.5 and solved by the existing
  rotation ledger.

---

## 3. Item 3 — Replay persistence

**Design requirement (§16.3):** "choose the minimum durable representation and
local key-rotation scheme that survives restart without creating a stable
telemetry identifier or weakening retention."

### 3.1 Survey (evidence)

- The relay's replay store is **already durably pluggable**: memory-only by
  default, disk-backed when constructed with a path
  (`NonceStore::load(replay_store_path)` + prune,
  `transport.rs:254-256`). Its on-disk format is line-based
  `nonce_hex,inserted_at_unix` with exact-field-count rejection
  (`:895-908`), insert-then-persist with rollback-on-failure so memory and
  disk never diverge, and refusal to stamp entries from a substituted clock
  (RLY-15, `:910-930`). Retention is
  `NONCE_RETENTION_SECS`, const-asserted to strictly exceed the full
  acceptance window `ttl + 2 × skew` (`:50-105`).
- The watermark constellation is per-domain files under `/var/lib/rustynet/`
  (§0) consumed by fail-closed preflight (`daemon.rs:4663-4680`); anti-rollback
  comparison is the membership watermark's replay test
  (`membership.rs:1559`, `persist` `:1632`).
- Atomic persistence is the single-temp/single-fsync/single-rename write with
  the rename boundary as the crash-recovery point
  (`key_rotation.rs:222-235`, `:931`).
- The **local key-rotation scheme already exists**: `LocalKeyRotationLedger` —
  epoch + verifier archive + `PerEpochReplayWatermark` in one atomic record,
  genesis-initiated, reloaded to exactly one consistent epoch, fail-closed
  (`LedgerCorrupt`) on structural/digest/monotonicity mismatch, bounded by
  `MAX_ROTATION_LEDGER_BYTES` (`key_rotation.rs:79-110`, `:236-243`).

### 3.2 SELECTED — digest-keyed line store on the existing NonceStore; rotation only for the address-validation key, via the existing ledger

**(a) Minimum durable representation.** Keep the v1 store shape — one line per
accepted hello, `key,inserted_at_unix`, exact-field-count reject — but key the
v2 entries by `sha256("v2" | privacy_epoch | nonce | leg_handle)` rendered as
fixed-width hex, exactly the one-way keying the design §7.7 mandates, using
SHA-256 (approved, KAT-tested in tree). The stored value stays a single
insertion timestamp; no handle, address, or nonce preimage is ever persisted.
Insert-then-persist-rollback and the RLY-15 clock refusal carry over
unchanged; the store is written with `atomic_write_secure` (mode 600) so a
crash leaves either the prior or the new committed file, never a torn one.

**(b) Retention bound.** Unchanged from the v1 discipline: entries live
exactly `NONCE_RETENTION_SECS = MAX_RELAY_TTL_SECS + 2 × MAX_CLOCK_SKEW_TOLERANCE_SECS`
(`transport.rs:50-86`), which satisfies the design's survival requirement
("at least token TTL, allowed clock skew, and persistence margin", §8.5) with
the existing const-assertion as the proof. The file gains a hard byte cap in
the `MAX_TRUST_STATE_FILE_BYTES` style; a full store rejects admission
(BR-C11) rather than evicting live entries — eviction would silently shorten
retention below the acceptance window.

**(c) Local key rotation.** The replay store needs **no key at all** — its
entries are keyless one-way digests — so nothing in it rotates. The only keyed
local state in the v2 path is the address-validation HMAC key, and that
rotates through the existing `LocalKeyRotationLedger` epoch mechanism
(`key_rotation.rs:79-110`), with the rotation epoch recorded per entry so an
old-epoch validation token dies at its own short TTL, never extended by
rotation. No new key-rotation scheme is invented.

**(d) Why this survives restart without becoming a stable telemetry
identifier.** Restart survival is the rename-atomic rewrite plus reload
(`transport.rs:254-256`). Non-identifiability is structural, three ways: (1)
every key is a digest of fresh per-circuit CSPRNG values (`OsRng.try_fill_bytes`
minting, `lib.rs:1868-1873`), so cross-circuit key equality is collision-level,
not identity-derived; (2) every entry is pruned on the fixed retention bound
(`transport.rs:50-105`), so the file is a bounded short-history artifact, not a
ledger; (3) the file is mode-600 local state whose keys are never emitted to
logs or metrics (BR-C16 aggregate-only rule), and preimages are nowhere on
disk to join against. A forensic reader of the relay host learns a set of
opaque, expiring digests — the same class of artifact the v1 nonce store
already produces, with strictly less linkage (epoch-namespaced digests vs raw
nonces).

**Rejected alternatives (one line each):**
- SQLite/embedded KV — new dependency and a format jump; the line store is
  already restart-safe and human-auditable.
- Raw `(nonce, leg_handle)` keying à la v1 — ignores the design's
  version/epoch namespace requirement (§8.5) and persists more linkage than
  the digest.
- Memory-only store — explicit fail-open, forbidden (design §9 "never run
  memory-only fail-open").
- TOFU re-init on corrupt store — forbidden; corrupt/missing-after-init makes
  the blind service unavailable (design §8.4).
- Keyed (encrypt/MAC) replay entries — adds a key for no adversary gain (the
  store holds only digests an attacker with host access could recompute) and
  re-creates the rotation burden for nothing.

---

## 4. Items 4 + 6 — Measurement plans (no invented numbers)

**Design requirement (§16.4/§16.6):** profiles and performance budgets are set
"after baseline measurement"; §12.2 fixes the metric list (hello p50/p95/p99,
issuer latency, first-packet latency, sustained throughput, CPU per
accepted/rejected hello, memory per waiting/paired circuit, loss under load,
recovery after exhaustion) and states "Numeric budgets are intentionally OPEN".

### 4.1 MEASUREMENT-PLAN — normal-relay baseline

**Existing machinery (survey):**
- Micro: `cargo bench -p rustynet-relay` —
  `crates/rustynet-relay/benches/relay_forward.rs` measures the per-frame
  forward path ("session lookup, source-tuple authorisation, rate limiting,
  and pair resolution — the everything-but-the-syscall cost of relaying one
  ciphertext frame", benches file header) with criterion's percentile
  reporting; `crates/rustynetd/benches/phase1_runtime_baseline.rs` covers the
  runtime baseline; `scripts/perf/run_phase1_baseline.sh` +
  `collect_phase1_measured_env.sh` capture the phase-1 environment/baseline.
- Live-lab stages (`crates/rustynet-cli/src/live_lab_stage_registry.rs`):
  `deploy_relay_service` (`:708`), `relay_validation` (`:717`),
  `live_two_hop_validation` (`:909`), `traffic_test_matrix` (`:931`; impl
  `crates/rustynet-cli/src/vm_lab/orchestrator/stage/traffic_test_matrix.rs`),
  the per-OS relay lifecycle cells
  `validate_linux_relay_service_lifecycle` (`:1672`) and its macOS/Windows
  counterparts (`:1180`, `:1461`), `extended_soak` (`:2072`), and the chaos
  family `chaos_clock_attack` / `chaos_crash_recovery` / `chaos_daemon_fault`
  (`:2082-2098`).
- Recording surfaces: each run's report directory (per-stage logs,
  `state/stages.tsv`, report state JSON), one auto-appended row per run in
  `documents/operations/live_lab_node_run_matrix.csv`, and
  `documents/operations/gate_timings.csv` (appended by `rustynet-xtask` per
  gate stage).

**Honest gap:** no existing stage computes live handshake p95/p99 or samples
relay process CPU/RSS — the benches give per-operation distributions, not
end-to-end percentiles, and the live stages assert correctness, not latency.
The plan therefore names what must be *added* (implementation work, gated on
this design's acceptance):

1. A relay-side aggregate latency metric: per-accepted-hello handling time and
   per-frame forward time, collected as fixed-bucket histograms, exposed in
   the existing aggregate metrics surface only (BR-C16 — no per-circuit
   labels).
2. A stage-harness sampler (Linux cell first): fixed-interval sampling of the
   relay process CPU% and RSS for the duration of `traffic_test_matrix` and
   `extended_soak`, reported as p50/p95/p99 in the stage's report artifact.
3. A baseline-recording document under `documents/operations/` capturing the
   numbers from (1)+(2) plus the criterion outputs, per OS cell, with commit,
   node identity, and report dir — the evidence row the budget approval cites.

**Baseline procedure:** run the Linux relay cell (deploy → relay_validation →
live_two_hop_validation → traffic_test_matrix → extended_soak, chaos stages as
stability context) with (1)+(2) enabled; record per §4.1(3). Repeat per OS as
its relay cell reaches live status.

### 4.2 MEASUREMENT-PLAN — blind-relay comparison

Same suite, same metrics, against the v2 blind runtime, plus the design §13.2
stages as correctness context (`blind_relay_resource_limits` for
signature-CPU pressure and waiting-leg exhaustion, `blind_relay_protocol_negatives`
for rejection cost). Comparison deltas to record, per §12.2: hello
p50/p95/p99 (now including address-validation + PoP cost), issuer latency,
first-packet latency, sustained throughput, CPU per accepted/rejected hello
(separating pre-auth gates from `verify_strict` cost), memory per waiting/
paired circuit, loss under load, and recovery time after exhaustion. The
comparison run appends its own run-matrix row; both rows are prerequisites for
the owner to set §16.4 profile limits and §16.6 budgets. **No budget number is
proposed in this document.**

---

## 5. Item 5 — Operational retention

**PROPOSED — OWNER APPROVAL REQUIRED.** Aggregate metrics only, per the
design's telemetry rules (§7.7, BR-C16, BR-C17). No value below is a
commitment; per-OS/legal-environment variations are explicitly the owner's
call.

| Surface | Content (aggregate only) | Hot retention (proposed) | Rollup / archive (proposed) | Hard rules |
|---|---|---|---|---|
| Relay aggregate metrics | Counters by (relay, protocol version, closed reason class, public profile); gauges (active/waiting/capacity) | 24 h | 90 d of daily rollups | No label below the four fixed dimensions; forbidden-field lint (BR-C16) |
| Security-transition audit events | Role, direction, result, signed-state generation, software version, aggregate residue verdict (§6.1) | local append-only audit log | 1 year, then owner-reviewed disposal | Never contains session handles or endpoint identities (§6.1) |
| Replay store | Expiring digests only (§3) | `NONCE_RETENTION_SECS` only | none — never archived | Pruned on the bound; never exported |
| Address-validation tokens / HMAC key | in-process only | rotation-epoch lifetime | rotation ledger epoch record only | Never persisted beside the relay state |
| Crash dumps / cores | disabled by default (BR-C17) | — | — | Incident mode only, time-bounded, owner-approved |
| Incident-mode capture (packet/verbose) | owner-approved per activation | max 1 h default, single activation | deleted after incident analysis; access-controlled storage | Cannot reveal stable Rustynet IDs (relay never receives them, design §7.7); UI states the metadata-privacy weakening (§7.7) |

Retention is a design gate, not an implementation detail: BR-C17's
verification already requires "retention-bound timing checks", so each row
above must get an expiry test when implemented.

**Rejected alternative:** retention "until disk pressure" — unbounded residue,
contradicts BR-C17 and §6.3 purge verification.

---

## 6. What §17 acceptance still needs (checklist delta)

The design's §17 checklist gains these items; an answer of "yes" to each is a
delta this document creates or leaves open:

1. Are all three v2 wire surfaces on the canonical line grammar with
   allowlist, duplicate, unknown, and canonical-re-encode rejection
   (§1.2-§1.3)? — *answered by this doc; verified at implementation by the
   §1.3 vector set.*
2. Does every v2 field carry an explicit bound (§1.3 table)?
3. Is the PoP suite composed only of ed25519-dalek `verify_strict` + sha2 +
   hmac with the §2.2(b) transcript, §2.2(f) order, and §2.2(e) erasure
   boundary? — *security review of exactly this composition is the remaining
   open gate (design §7.4 requires it).*
4. Does the replay store survive restart within `ttl + 2 × skew`, digest-keyed,
   bounded, with rotation only via the existing ledger (§3.2)?
5. Have the §4 baselines been recorded (per OS) **before** any profile limit
   (§16.4) or budget (§16.6) is approved?
6. Is the §5 retention table owner-approved, aggregate-only, with per-row
   expiry tests planned?
7. Still open after this doc, by design: §16 item 7 (stronger two-relay
   privacy) is a separate owner decision and must not delay this role; and
   the design remains not-added-to-parity-plan until acceptance (§13.3).

## References

- `documents/operations/active/BlindRelayRoleDesign_2026-08-27.md` (§0, §6, §7,
  §8, §9, §12.2, §13, §16, §17)
- `documents/operations/active/OwnerDecisionDigest_2026-08-27.md` (pending
  blind-relay v2 selection entry)
- `documents/operations/active/CryptoPolicyHardening_2026-08-25.md`
- `crates/rustynet-control/src/lib.rs`, `crates/rustynet-control/src/membership.rs`
- `crates/rustynet-relay/src/transport.rs`, `crates/rustynet-relay/Cargo.toml`,
  `crates/rustynet-relay/benches/relay_forward.rs`
- `crates/rustynetd/src/daemon.rs`, `crates/rustynetd/src/key_rotation.rs`,
  `crates/rustynetd/src/key_material.rs`, `crates/rustynetd/src/gossip_transport.rs`,
  `crates/rustynetd/src/gossip_runtime.rs`
- `crates/rustynet-crypto/src/lib.rs`
- `crates/rustynet-cli/src/live_lab_stage_registry.rs`,
  `crates/rustynet-cli/src/vm_lab/orchestrator/stage/traffic_test_matrix.rs`
- `scripts/perf/run_phase1_baseline.sh`, `scripts/perf/collect_phase1_measured_env.sh`
- `documents/operations/live_lab_node_run_matrix.csv`,
  `documents/operations/gate_timings.csv`
- RFC 8747, RFC 9000 §8 (via the design's §18 references)
