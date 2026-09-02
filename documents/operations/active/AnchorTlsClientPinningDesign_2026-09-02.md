# Anchor TLS — Client-Side Certificate Pinning Design (AT-2) (2026-09-02)

**Status:** Design — docs-only, no code changed. Implements the analysis required by AT-2 (P2) of `AnchorTlsUnreviewedCheckpointsSecurityReview_2026-09-02.md` and discharges Item 1 of the QH-26 follow-up (`documents/operations/active/QualityHardeningTodo_2026-07-25.md` §follow-up design).
**Scope:** Client-side certificate pinning for the anchor control-plane TLS listeners (bundle pull and enrollment over `--allow-lan`). Server-side posture is already landed and reviewed; this document covers the client half only.
**Method:** Every anchor cited below was re-verified by grep/read against this worktree at HEAD `00f7e13d` (branch `ai-edit/edit-1788331391554-41042-0`), not carried forward from earlier documents. Two findings in that review doc describe code that has since moved: the AT-1 handshake deadline is now implemented (`ANCHOR_TLS_HANDSHAKE_DEADLINE`, `daemon.rs:299`; `complete_anchor_tls_handshake`, `daemon.rs:1678`, with the dribbling-peer test at `daemon.rs:18883`), and AT-9's "no in-process load verification" is partially addressed by `verify_cert_and_key_are_paired` (`anchor_tls.rs:475`). Neither change affects AT-2.

---

## §0 Client-path inventory — who dials the anchor control plane, and over what

The first question any pinning design must answer is *which code actually dials these ports today*. The answer defines the exposure precisely, because it is narrower than the review's threat narrative assumes:

| # | Client path | Dials | Transport today |
| --- | --- | --- | --- |
| 1 | `AnchorCommand::PullBundle` in `rustynet-cli` (`rustynet-cli/src/main.rs` ~7569-7740) | anchor bundle-pull TCP port, **loopback only** — resolves the addr and errors `anchor bundle-pull addr must resolve to loopback` unless the resolved address is loopback (`main.rs:7602`) | **Plaintext** `TcpStream::connect_timeout` 5s (`main.rs:7603`); line protocol `{token}\n` + optional `have {epoch} {root}\n`, response header `UNCHANGED`/`OK <size>`, snapshot verified against the pinned owner key (`verify_attested_snapshot`) **before** disk write |
| 2 | Enrollment consume in `rustynet-cli` (`main.rs:8224-8248`, `send_command`) | **never dials the anchor TCP enrollment port** — goes over the daemon's local UDS IPC socket | Plaintext over a Unix domain socket (local-only; out of TLS scope) |
| 3 | macOS lab validator `crates/rustynet-cli/src/bin/live_macos_anchor_test.rs` | anchor bundle-pull TCP port, loopback, in-lab only | Plaintext TCP probes (`:392-407`), byte-for-byte snapshot check (`:199-205`), token-leak scans (`:338-341`), and a negative control that a non-loopback bind is refused without `--allow-lan` (`:261-305`) |
| 4 | The daemon itself | **listens**, never dials: `bind_anchor_bundle_pull_listener` (~`daemon.rs:1855-1893`) and `bind_anchor_enrollment_listener` (`daemon.rs:1981-2014`); TLS wraps the accepted stream iff `allow_lan` is set, identity is loaded **before** bind, and load failure refuses the bind — no plaintext fallback for a LAN-exposed listener (documented `daemon.rs:1970-1977`) | Server-side TLS 1.3-only (`build_anchor_server_config`, `anchor_tls.rs:359-369`) |

Grepping the whole workspace for `ClientConfig|ClientConnection|ServerCertVerifier|danger_accept` finds the pinned-fingerprint verifier **only** inside `anchor_tls.rs`'s `#[cfg(test)]` module (`tls_handshake_succeeds_with_pinned_fingerprint` `:991`, `tls_handshake_rejects_wrong_fingerprint` `:1024`, `connect_pinned` `:1056`, `PinnedFingerprintVerifier` `:1086/:1106`). `danger_accept_invalid_certs` appears nowhere. The `rustls` dependency in `rustynet-cli/Cargo.toml:123-126` (AT-7) is dead: nothing in the crate compiles a TLS client today.

**Consequence (matching the review §6 and `M1AnchorTlsPinningVerification_2026-08-31.md`):** there is **no production client that can reach a `--allow-lan` anchor at all**. The plaintext CLI client is loopback-asserted, and the LAN-exposed TLS listener has zero callers. The vulnerability is therefore *latent*: the day a LAN client is added without pinning, the anchor becomes encryption-without-transport-authentication. AT-2's real deliverable is (a) a pin distribution channel, (b) a productionized verifier, and (c) the rule that any future LAN client is hard-wired to use them — so the gap cannot be quietly re-introduced.

---

## §1 Q1 — Where does the client's pin come from? (trust bootstrap)

Requirements: the pin must arrive over a channel an attacker between client and anchor cannot forge, and the design must not rely on trust-on-first-use (TOFU), which `AGENTS.md` §3 ("fail closed when trust state is missing") excludes — a first-connection MITM would mint a permanent pin.

The pin is the SHA-256 of the anchor certificate's DER (`AnchorTlsIdentity::fingerprint`, `anchor_tls.rs:158` — lowercase hex over DER). The anchor certificate exists on disk at `<membership snapshot dir>/anchor-tls/anchor-cert.pem` (`daemon.rs:1733-1740`) and both control-plane listeners share that one identity (`daemon.rs:1978-1980`), so **one fingerprint pins both listeners**.

**Recommended channel: a signed attestation field (QH-26 Item 2), consumed as the pin source.** The membership head attestation is already signed by the owner key the client independently pins (`load_membership_owner_key_pub`, `main.rs:7583/:7766` — loaded *before* any network I/O in `PullBundle`). Carrying the fingerprint there reuses the exact trust root that already authenticates bundle content, so transport trust and data trust converge on one operator-controlled key. Placement analysis (from QH-26, re-verified here):

- `MEMBERSHIP_SCHEMA_VERSION = 1` (`membership.rs:21`); head attestation v1, domain tag `rustynet:membership-head:v1` (`membership.rs:31/:28`); `head_attestation_canonical_payload` is byte-pinned by test (`membership.rs:946-959`, `:5598`) — any field added to the v1 canonical payload invalidates every existing head signature; the append-only chain hash `sha256(index|prev|hex(canonical_envelope))` (`membership.rs:1835-1850`) means an envelope change breaks persisted chains.
- **Placement A (recommended): an attestation-level field, `attestation.anchor_tls_cert_fingerprint_sha256_hex`, introduced with a version bump** to `rustynet:membership-head:v2` / `MEMBERSHIP_HEAD_ATTESTATION_VERSION = 2`. The v1 parser stays intact for persisted snapshots (fail-closed `UnsupportedVersion` at `membership.rs:1266-1313`); a v1 snapshot simply means *no pin learned* — never an error, never a fallback to TOFU. No canonical-envelope change, so the chain hash is untouched. This is the owner-decision item (§7).
- Placement B (a per-signature `Option<String>` field à la FIS-0014, `head_signature_hex` `membership.rs:640-656`) avoids the version bump but touches the canonical envelope, breaking the chain hash for mixed fleets. Rejected.

**Bootstrap sequencing.** Until the signed field exists, the only admissible stopgap is an operator-supplied pin obtained out-of-band by the same person who controls the owner key (read from the anchor host; note the daemon does not currently print the fingerprint at bind — `daemon.rs:1881` logs only `addr` + `tls={bool}` — so a `rustynet anchor fingerprint` reader command is a prerequisite for both the stopgap and the live stage). Plain TOFU is rejected: first use would be exactly the moment a MITM is cheapest.

**Why not the enrollment token?** The bundle-pull token (`anchor-bundle-pull.token`, seeded at `/usr/local/var/rustynet/anchor-bundle-pull.token` by `ops_e2e.rs:1286/:1481-1547`) authorizes *pulling*; it is shared, transported on the same channel, and says nothing about the server's identity. Using it as a pin source conflates capability with identity. Rejected.

---

## §2 Q2 — Pinning mechanics (the productionized verifier)

The test module already contains the shape; productionizing it is a hardening list, not an invention:

1. **Move `PinnedFingerprintVerifier` out of `#[cfg(test)]`** into the daemon/backend layer (not a domain crate — `rustls` types must not leak into `rustynet-control`/`rustynet-policy`, §8/§10.3).
2. **Constant-time comparison** of computed vs expected fingerprint (`subtle::ConstantTimeEq`, matching the existing token compare `constant_time_ascii_eq`, `daemon.rs:2092-2103`). The current test verifier uses a plain slice `==`.
3. **Boundary validation:** accept the pin only as exactly 64 hex characters (case-normalized), rejected at CLI-parse time, fail-closed. The test helper's `new()` currently parses two chars per byte with `expect("hex")` and no length check — that must not survive.
4. **Error taxonomy — three distinct cases** so an operator can tell a typo from an attack:
   - `config-missing-pin`: a non-loopback pull without a pin (refused before connect);
   - `pin-format-invalid`: malformed pin (refused before connect);
   - `pin-mismatch`: handshake-time verifier refusal (`anchor TLS certificate fingerprint does not match the pinned value`).
5. **Config identical to the server's:** ring provider, `.with_protocol_versions(&[&rustls::version::TLS13])`, `with_no_client_auth`, `ServerName::try_from(ANCHOR_TLS_CERT_NAME)` (`anchor_tls.rs:31` — fixed SNI name; the server's resolver is SNI-ignoring, `anchor_tls.rs:336`, which is correct for IP-dialing), `verify_tls12_signature` hard-rejects (as the test verifier already does).
6. **No webpki chain validation.** The cert is self-signed (`IsCa::ExplicitNoCa`, ServerAuth EKU only, `anchor_tls.rs:164-172`); the *only* trust decision is the fingerprint. Name verification of `rustynet-anchor.local` is explicitly not performed — the review §2 records this as harmless by design.
7. **Hard fail, no fallback.** A pinned connection that fails never retries in plaintext. Loopback pulls keep plaintext (unchanged behavior) and never require a pin.
8. **Surface rule (default-deny):** `PullBundle` gains an explicit policy switch (QH-26 wording: `--allow-lan-anchor`, default off). Non-loopback target ⇒ pin **required** and TLS **mandatory**; loopback target ⇒ plaintext, pin ignored. The existing loopback assertion (`main.rs:7602`) becomes the branch point.

The end-entity-vs-chain selection question (SHA-256 over the *end-entity* DER, which is the only cert the resolver serves) is settled by the server's single-cert `AnchorCertResolver`; the adversarial review required before code (QH-60 convention) should still confirm SAN handling and ServerName choice.

---

## §3 Q3 — Rotation

The identity is deliberately long-lived (3650 days, `anchor_tls.rs:35`) and regeneration is a manual delete-both-files operation (`PartialIdentity` refusal on a mixed pair, `anchor_tls.rs:175`, makes a silent fingerprint change impossible). Rotation therefore has exactly one cause — an operator regenerating the identity — and one safe path:

1. Regenerate on the anchor (delete both files; next bind generates fresh — fingerprint changes).
2. Re-issue the pin through the **signed** channel: a new head attestation (new epoch, fresh signatures, existing freshness bound) carrying the new fingerprint.
3. Clients accept a *changed* pin only from a verified attestation — never from an unverified pull, never by overwriting a stored pin on connection failure. A stale pin ⇒ every connection refused with `pin-mismatch`, loud, until the operator pulls the new attested state. This is the correct failure direction: an attacker who cannot forge attestation signatures cannot rotate the pin, and a compromised anchor cert cannot silently re-pin clients.
4. Because deleting the identity files *is* the rotation trigger, the fingerprint change is a deliberate re-pin event, not an incident. Document it as such (the review §2 notes nothing currently "documents or assists the re-pin" — this section is that documentation).

Multi-anchor: one fingerprint per anchor attestation; clients pin per anchor identity they pull from. Do not generalize to a pin set until a second anchor exists (QH-26).

---

## §4 Q4 — Pin storage per platform, and live-lab proof

**Storage.** The pin is operator trust material and gets the custody rules of other operator trust material (QH-26):

- **Linux/macOS:** a `0600` file alongside the other operator secrets (next to the pinned owner public key the client already loads), read once at command start, never logged (`anchor_bundle_pull_token_thumbprint`, `daemon.rs:1833`, is the house pattern for logging only a thumbprint).
- **Windows:** DPAPI-protected blob via `rustynet-windows-native` (the crate already owns DPAPI integration), same read-once discipline.
- In-memory only after load; no `Debug` output of pin material (AT-3/AT-4 discipline applies by symmetry).

**Live-lab proof — new stage `anchor_tls_pinning_validation`** (naming per the existing `validate_macos_anchor_bundle_pull` stage, `lab-monitor app.rs:1402/:3181`), fail-loud per the Roadmap's live-stage spec (live result = stage status; no dry-run-as-pass):

1. Positive control: start anchor with `--allow-lan`, client pulls over TLS with the correct pin ⇒ pull succeeds; snapshot byte-identical to the signed bundle; attestation verifies.
2. **Negative control (the stage's point):** client dials the same listener with a *wrong-but-well-formed* pin (64 hex chars, not the anchor's) ⇒ connection refused at handshake with the named `pin-mismatch` error, **zero bytes of line protocol exchanged**, and no file written.
3. Refusal-without-pin control: non-loopback target, no pin ⇒ `config-missing-pin`, nothing dialed.
4. Assert server logs show the connection attempt but no snapshot bytes served to the mismatched client.

The stage runs first on the macOS guest (where `validate_macos_anchor_bundle_pull` already exercises the loopback path end-to-end, `live_macos_anchor_test.rs`), then the same cell on Windows. The existing macOS install plist (`ops_install_macos_anchor.rs:380-410`, allow-lan=false, drift guard `:576-602`) is untouched — the plist keeps the loopback-only posture; the LAN path exists for explicit operator opt-in.

---

## §5 Q5 — Threat model

**Today (no pinning, no LAN client):** the review §6 and M1 both conclude the same thing — with no LAN-dialing client in the tree, transport MITM of the anchor listeners has no victim. The loopback CLI path's security rests on the ed25519 attestation against the pinned owner key, not on transport; a local eavesdropper learns that pulls happen (metadata) and can DoS, but cannot inject a bundle (signature check fails before disk). The M1 doc's residual exposure is exactly that: DoS + metadata on an unauthenticated transport.

**After AT-2 (LAN client + pin):** the pin closes the transport-MITM gap — an active attacker cannot present the pinned certificate, so the connection dies at handshake with zero application bytes. What the pin does **not** do, and what the attestation layer remains solely responsible for: authenticating bundle *content* (a pinned-but-compromised anchor can still serve a signed-but-stale bundle, bounded by the freshness watermark), authorizing the pull (the token), or authenticating enrollment (the enrollment-token/IPC layer). Defense in depth is preserved deliberately: transport trust (pin) and data trust (owner-key attestation) are independent layers with independent compromise paths. `SecurityMinimumBar.md` L105-118's warning stands even after this work — pinning authenticates the *anchor's transport*; it is never cited as client-side authentication of bundle content.

**Residual, accepted:** a MITM can still refuse connections (DoS — visible, loud, same as any network adversary); metadata (pull timing/volume) is visible to a passive LAN observer pre-handshake; the pin does not survive a compromised anchor host (cert + attestation key would both be at the attacker's mercy — that is the owner-key threat model, out of scope).

---

## §6 Ordered steps (tests-first) and sizing

Sequence follows QH-26: **Item 2 (signed field) first**, Item 1 (client pinning) second — the client should not grow a LAN dial path before the pin it must require can be distributed signed. Both need adversarial review before code (QH-60 convention).

1. **Signed field (Item 2, owner-decision pending §7):** v2 head attestation with `anchor_tls_cert_fingerprint_sha256_hex`. Tests: v2 round-trip; v1 snapshot still parses (no pin learned, not an error); canonical-byte pin updated; chain-hash continuity across v1→v2; cross-signature (v1-signed state offered at v2) rejected fail-closed.
2. **Fingerprint reader command** (`rustynet anchor fingerprint` — the daemon never prints it today, `daemon.rs:1881`): prints the on-disk identity's fingerprint, owner-verifiable against the anchor host. Test: matches `AnchorTlsIdentity::fingerprint` output.
3. **Productionized verifier** (§2 items 1-7). Tests: accepts pinned; rejects mismatched fingerprint; rejects a self-signed cert that is not the anchor's; rejects TLS 1.2 ClientHello; constant-time compare; 64-hex boundary parse rejects 63/65-char and non-hex input at parse time.
4. **Client wiring** (§2 item 8): policy switch, pin requirement, TLS-mandatory-for-LAN. Tests: loopback pull unchanged (plaintext, no pin); non-loopback without pin refused pre-connect (`config-missing-pin`); non-loopback with pin dials TLS; mismatch refused with zero line-protocol bytes.
5. **Dead dep resolution (AT-7):** the `rustls` dependency in `rustynet-cli/Cargo.toml:123-126` is either consumed by the real client (step 4) or deleted — the misleading comment does not survive this work either way.
6. **Live stage** `anchor_tls_pinning_validation` (§4) on macOS then Windows; row appended to `documents/operations/live_lab_node_run_matrix.csv` per §10.9.

Sizing: steps 2-5 are daemon/CLI-scoped (one verifier module + CLI arg plumbing, ~300-500 lines with tests); step 1 is the higher-risk half (byte-pinned canonical format, version-gated parser, anchor persistence — QH-26's own risk assessment). Step 1 is release-gated on the §7 decision.

## §7 Open questions and the owner decision

1. **OWNER DECISION — new signed field:** add `anchor_tls_cert_fingerprint_sha256_hex` to the head attestation with a `rustynet:membership-head:v2` bump (recommended, §1 Placement A), or defer Item 2 and ship the operator-supplied pin stopgap only? Deferral is admissible only because no LAN client exists today (§0) — the stopgap must then keep the LAN dial path *unimplemented*, which is the current fail-closed-by-absence posture.
2. Whether the pin file should live beside the owner public key or under the OS-secure store once AT-8's custody work lands (do not solve twice).
3. Whether the enrollment listener ever gains a TCP client (§0 shows it has none); if it never does, "pins both listeners" remains a property of the shared identity, not a client requirement to test separately.
4. ServerName/SAN behavior of the production verifier needs the adversarial review's sign-off (§2 closing note) even though the fixed `ANCHOR_TLS_CERT_NAME` matches the cert's only SAN.
