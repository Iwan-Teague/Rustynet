# Anchor TLS — Security Review of Three Unreviewed Checkpoints (2026-09-02)

**Status:** Complete — adversarial security review, docs-only.
**Scope:** Commits `9a723960`, `1a5bcb21`, `5757e55c` (all landed on main 2026-08-30 with subject `WIP: automatic checkpoint (timed_out)`), plus later commits that touched the same code (`621c4cd0`, `e2ff2c82`, `30355d1c`, `8d6ad7cc`), reviewed as they exist in the current tree at worktree HEAD `55658131` on branch `ai-edit/edit-1788313152819-31898-0`.
**Provenance of this review:** Per the Qh26HonestRetirementPlanAdversarialReview_2026-09-02.md §4 finding, these three delegated-edit WIP checkpoints reached main without the human review that `AGENTS.md` §12.6 requires before a delegated-edit branch merges. This document is that after-the-fact review. It is an audit of already-landed code, not an approval of the process that landed it.
**Method:** Static reading of the three commit diffs (`git show`) and the current source (`crates/rustynetd/src/anchor_tls.rs`, `crates/rustynetd/src/daemon.rs`, both `Cargo.toml`s, `crates/rustynet-cli/src/main.rs` client path), cross-checked against `documents/SecurityMinimumBar.md` §4 anchor TLS block (the 2026-08-30 correction that describes this subsystem) and `documents/Requirements.md` §5 (DA-01 amendment at line 168). No lab run, no packet capture, no test execution — see §10.

---

## §0 Findings summary

| ID | Severity | Finding | Primary location |
| --- | --- | --- | --- |
| AT-1 | P2 | No overall TLS handshake deadline: a dribbling peer can hold a handshake open indefinitely, and the inline single-connection serve loop means one slowloris client wedges both anchor control-plane listeners | `daemon.rs:1549-1608`, `daemon.rs:1686-1698`, `daemon.rs:1976-1981` |
| AT-2 | P2 | No client-side fingerprint pinning anywhere in production; the `rustls` dependency in `rustynet-cli` is dead and its comment claims a capability that does not exist — a LAN anchor is transport-encryption-without-transport-authentication for any future TLS client | `rustynet-cli/Cargo.toml:123-126`, `SecurityMinimumBar.md:105-110` |
| AT-3 | P3 | TLS private key and PEM material are not zeroized after load | `anchor_tls.rs:102-110`, `anchor_tls.rs:291-303` |
| AT-4 | P3 | `AnchorTlsIdentity` derives `Debug` over a struct holding the private key DER; redaction of `rustls::pki_types::PrivateKeyDer`'s own `Debug` is unverified | `anchor_tls.rs:102-110` |
| AT-5 | P3 | `read_tls_file` TOCTOU: symlink/regular-file/mode checks run on `symlink_metadata`, then a separate `File::open` re-resolves the path | `anchor_tls.rs:237-283` |
| AT-6 | P3 | `Box::leak` in `read_tls_file` error-context construction leaks on every permission error (bind-time only, bounded in practice) | `anchor_tls.rs:262-270` |
| AT-7 | P3 | Dead `rustls` dependency in `rustynet-cli` with a misleading capability comment (same finding as AT-2's process half; listed separately because the fix is a one-line Cargo.toml removal if AT-2 is deferred) | `rustynet-cli/Cargo.toml:123-126` |
| AT-8 | P3 | Key at rest is plain PEM with filesystem modes only — no OS-secure key storage, no encrypted-at-rest fallback, below the `AGENTS.md` §4 custody bar | `anchor_tls.rs:182-231`, `daemon.rs:1642-1653` |
| AT-9 | P3 | Test gaps: no negative tests for corrupt/mismatched identity pairs, expired certs, TLS 1.2 ClientHello rejection, oversized ClientHello, handshake timeout disposition, or an over-permissive cert file (only the key file has that negative test) | `anchor_tls.rs:372+` (test module) |
| AT-10 | Info | No ALPN, no client certificate auth (by design — the token/attestation layer is the auth), default rustls session-ticket handling relied on but not verified; SNI-ignoring resolver is correct for IP-dialing clients | `anchor_tls.rs:336-369` |

No P0 or P1 findings. The subsystem's fail-closed posture held up under every attack vector probed — details per area below. The disposition (§9) is **ACCEPT-WITH-FIXES**.

---

## §1 Key and identity custody

**Generation.** `anchor_tls.rs:161` generates an ECDSA P-256 key via `rcgen::KeyPair::generate_for(PKCS_ECDSA_P256_SHA256)` — a standard, non-custom primitive (constraint satisfied). Generation happens only when **both** identity files are absent (`load_or_generate`: `(false, false) → generate`); a mixed present/absent pair is refused with `PartialIdentity` rather than silently repaired. That refusal is the single most important custody property here: the certificate fingerprint a relying party may have pinned can never be silently rotated by a half-deleted state directory.

**Storage.** `daemon.rs:1642-1653` places the identity under `<membership state dir>/anchor-tls/` (`anchor-cert.pem`, `anchor-key.pem`). On write (`anchor_tls.rs:182-231`): parent directory created with `create_dir_all`, then `set_permissions(0700)`; cert written `0644`; key written `0600`. `write_private_bytes` uses `OpenOptions::create_new(true)` — no clobbering of an existing file and no following a pre-planted symlink at the create site. One residual window: the key file briefly exists under the process umask before `set_permissions` lands; the `0700` parent directory mitigates this to the local-user threat model only. Acceptable for a daemon that already stores the enrollment secret and bundle-pull token as same-class files, but it is the same class of gap AT-8 records against the custody bar.

**Load and mode enforcement.** `read_tls_file` (`anchor_tls.rs:237-283`) refuses symlinks, refuses non-regular files, and on unix refuses any file whose mode does not exactly match the expected mode (`!= expected`, both directions — an over-permissive key is an error, `anchor_tls.rs:264-277`). `load_anchor_tls_identity` (`:291-303`) then parses both PEM slices and eagerly builds the signing key, so a key that does not match the certificate fails at bind time, not at first handshake. All failures propagate as `AnchorTlsError` → `DaemonError::InvalidConfig` → the listener is not bound. Fail-closed throughout.

**Logged or Debug-printed?** No. The identity struct is never logged; handlers log only the `sha256(token)[:8]` thumbprint, never the token; there is no `unwrap()`/`expect()` on any TLS path. One caveat is AT-4: the struct derives `Debug` while holding `key_der`, and whether `rustls::pki_types::PrivateKeyDer`'s own `Debug` redacts is unverified (§10). The struct is not printed on any path found in this review, so this is hardening, not an open leak.

**Zeroize.** Absent (`AT-3`). Contrast `enrollment_token.rs:58`/`:1007`, which zeroizes token secrets and compares HMAC tags with `subtle::ConstantTimeEq`. The TLS identity deserves the same treatment.

**OS-secure vs encrypted-at-rest.** Neither (`AT-8`). `AGENTS.md` §4 requires "OS-secure key storage when available; otherwise encrypted-at-rest fallback with strict permissions and startup permission checks." What landed is the third thing: plaintext-at-rest with strict permissions and startup permission checks. The startup permission check part is genuinely implemented and enforced; the custody mechanism is not. Consistent with existing daemon secret practice, but the bar is the bar.

**TOCTOU.** `AT-5`: the symlink/mode checks and the actual `open` are two separate syscalls over the path. A local attacker who can write to the directory could theoretically swap in a symlink between check and open — but the directory is `0700`, so the practical window requires already having the very ownership the files protect. Fix is cheap (open first, `fstat` the fd, or `O_NOFOLLOW`), so it should be done, but the exploitability on a `0700`-dir default is low.

---

## §2 Certificate and identity properties

- **Self-signed, explicit non-CA** (`IsCa::ExplicitNoCa`, `anchor_tls.rs:164-172`): correct for a pinned-fingerprint trust model — the cert asserts nothing about third parties.
- **Key type:** ECDSA P-256 (`:161`), matching the signature scheme the test verifier enforces. No RSA, no ed25519 — consistent with the ring provider default suite set.
- **Validity window:** 3650 days (`:33`) with a 1-hour `not_before` back-skew (`:30-31`). The ten-year lifetime is deliberate for an unmanaged self-hosted identity; it makes expiry handling moot in practice but also means a *compromised* identity is valid for a decade — the regeneration story is therefore a manual delete-both-files-and-re-pin operation. That operation is safe by construction (bind fails with mixed files; fingerprint changes only when both are regenerated), but nothing documents or assists the re-pin. Recorded under AT-2's umbrella: pin *rotation* needs the same distribution channel as the initial pin.
- **Subject/SAN:** CN and SAN DNS both `rustynet-anchor.local` (`:35`). Clients do not (and must not) name-verify this — the pinned fingerprint is the identity. Harmless.
- **Extensions:** keyUsage `DigitalSignature`, EKU `ServerAuth` only. Minimal and correct.
- **Corrupt/expired identity at bind:** refuse, never silently regenerate (`AT-clear`). Only the both-absent state generates. This is what keeps pinning *possible* even before it is *implemented*.

---

## §3 Server TLS configuration

`build_anchor_server_config` (`anchor_tls.rs:359-369`):

```rust
builder_with_provider(ring)
    .with_protocol_versions(&[&version::TLS13])
    .with_no_client_auth()
    .with_cert_resolver(...)
```

- **TLS 1.3-only, double-enforced:** the `rustls 0.23` dependency is declared `default-features = false, features = ["ring", "std", "logging"]` (`rustynetd/Cargo.toml:41-44`) — no `tls12` feature — *and* `with_protocol_versions(&[&version::TLS13])` selects 1.3 explicitly. A TLS 1.2 ClientHello cannot even be parsed into an offered version. Structural, not advisory.
- **Cipher suites:** rustls 0.23's ring-provider defaults (TLS13_AES_256_GCM_SHA384, TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256). All modern AEAD; no action needed.
- **Client auth:** none (`with_no_client_auth`). This is the right call *given* the design: the auth layer for these listeners is the bundle capability check / enrollment token, not client certificates. mTLS would add a second PKI to operate for no marginal security while the pin distribution channel (AT-2) doesn't exist. Not a finding beyond the AT-10 informational note.
- **ALPN:** not configured. These are bespoke line protocols behind TLS, not HTTP; ALPN would be defense-in-depth against protocol confusion with a co-located HTTPS service on the same port, which does not apply here. No action.
- **Session resumption/tickets:** rustls defaults (in-memory ticketer, keys die with the process). Resumption cannot outlive a restart, so a stolen ticket has a bounded life. Semantics of the default ticketer not independently verified against the vendored source (§10) — acceptable residual.
- **Max fragment size:** default (full records). Not a concern for these 256-byte-line protocols.
- **`dangerous()` APIs:** none on the server side. The only `dangerous()` use in the tree is the *test-only* pinned verifier inside `anchor_tls.rs`'s `#[cfg(test)]` module — the legitimate pattern for fingerprint pinning, and the existence proof that AT-2's client-side fix is straightforward once a pin distribution channel exists.
- **Cert resolver:** `AnchorCertResolver` (`:336`) returns the single configured cert regardless of ClientHello/SNI. Correct for IP-address-dialing clients; no SNI-based downgrade surface exists.

---

## §4 Handshake behavior and fail-open analysis

**Mechanics.** `AnchorControlStream` (`daemon.rs:1549-1608`) is `Plain(TcpStream) | Tls(Box<rustls::StreamOwned<ServerConnection, TcpStream>>)`. The `ServerConnection` is constructed in `anchor_control_stream` (`:1624-1640`) *before* any handler I/O, and the handshake itself is lazy — rustls completes it inside the first `read`/`write` through the stream. `socket()` exposes the inner `TcpStream`, and both handlers set 2-second read and write timeouts on it **first** (`:1686-1698`, `:1976-1981`), so every individual TLS record read/write is socket-bounded. `ServerConnection::new` failure maps to `DaemonError::Io` — no `unwrap`.

**Fail-open? No — proven closed.** The decisive trace: `bind_anchor_bundle_pull_listener` sets `tls = Some(..)` **iff** `allow_lan` (`:1781-1785`), loading the identity *before* `TcpListener::bind` — identity failure refuses the bind entirely. Same in `bind_anchor_enrollment_listener` (`:1902-1904`). `anchor_control_stream` wraps the accepted socket in TLS before the handler sees it. A hostile or failed handshake surfaces as an I/O error inside the handler → logged (peer + error, no secrets) → connection dropped → `poll_*_once` returns `Ok(true)`. **There is no code path from a TLS failure to a plaintext continuation.** The `Plain` arm exists only when `tls = None`, and `tls = None` holds only when the address validated as loopback (`validate_anchor_bundle_pull_addr`, `daemon.rs:1189-1203`: non-loopback without `--anchor-bundle-pull-allow-lan` → `Err`). The loopback-only default means the unencrypted arm never faces the LAN.

**DoS — the one real finding (AT-1).** The 2-second socket timeouts bound each *record*, but not the *handshake*. rustls may perform many socket reads inside a single `stream.read()` call, and `read_line_bounded`'s deadline (`daemon.rs:1448-1487`) is checked *before* each call to `read` — so a peer that sends one ClientHello byte every 1.9 seconds keeps resetting the record timeout while never letting the outer deadline be reached (the outer deadline only fires between reads). Meanwhile `poll_anchor_bundle_pull_once` / `poll_anchor_enrollment_once` serve inline and synchronously: the accept loop does not take the next connection until the current one finishes or errors. Net effect: **one dribbling LAN client can wedge both anchor control-plane listeners for as long as the dribble continues.** Availability-only, opt-in exposure only (`--allow-lan` flags), no confidentiality impact. Strict fix: drive the handshake explicitly to completion — `ServerConnection::complete_io` in a loop under a total `Instant` deadline — before entering the line protocol, plus a negative test that a dribbled ClientHello is dropped when the total budget expires.

**Hostile-handshake error handling:** no panics possible on the reviewed paths — no `unwrap`/`expect`/index panics in `anchor_control_stream`, the `Read`/`Write` impls, `read_line_bounded`, or the handlers. The enrollment handler additionally re-checks node capability at accept time *before reading any client byte* (`:1987-1994`), so a revoked node cannot even spend handshake budget on the enrollment listener after revocation, and the bundle-pull handler does the same (`:1703-1710`).

---

## §5 Token and request reader

- **Bounded reads, enforced:** `read_line_bounded` (`daemon.rs:1448-1487`) reads byte-at-a-time, checks the deadline before each byte, and errors the instant the byte cap (`MAX_ANCHOR_BUNDLE_PULL_TOKEN_BYTES`/`MAX_ANCHOR_ENROLLMENT_REQUEST_LINE_BYTES`, both 256, `:236`/`:274`) is exceeded. No accumulation buffer can grow past the cap. The budget constants (`:245`/`:279`, 2s) and write budgets (`:262` 30s, `:285` 5s) wrap every response in the pre-existing `DeadlineWriter` (`:1506-1524`, FIS-0020-era, not part of these checkpoints).
- **Newline termination:** the enrollment path requires a `\n`-terminated line; an EOF-truncated fragment is refused (`:2001-2005`). Truncation cannot smuggle a prefix match.
- **Constant-time compare — confirmed in both protocols.** Bundle-pull: `constant_time_ascii_eq` (`daemon.rs:1364`, implementation `:2092-2103` — xor-fold, length-mixed so length itself does not gate early). Enrollment: `subtle::ConstantTimeEq` on the HMAC tag (`enrollment_token.rs:58`, applied at `:1007`).
- **Token logging — negative confirmed.** Only `sha256(presented.trim())[..8]` hex thumbprints are logged (`:1747-1750`); the raw token never appears in a log statement on any reviewed path.
- **Verb whitelist, default-deny:** the enrollment TCP handler parses *only* `IpcCommand::EnrollmentConsume`; anything else gets the fixed string `ERR unsupported operation` (`:2011-2021`). No reflection of client input in error strings.
- **Residual:** the *handshake* phase lacks a total deadline (AT-1, §4). The post-handshake line protocol is fully bounded.

---

## §6 Client side: what a LAN attacker can actually do today

**There is no production TLS client in the tree.** The commit `9a723960` added `rustls` to `rustynet-cli/Cargo.toml:123-126` with a comment claiming "pinned server-cert fingerprint verification" for the bundle-pull command — **no `rustls` symbol is referenced anywhere in `crates/rustynet-cli/src/`**. The dependency is dead weight, and the comment asserts a capability that was never written (AT-2/AT-7). The only pinned verifier in the repository is the test-only `PinnedFingerprintVerifier` inside `anchor_tls.rs`'s test module.

**The actual client path** (`rustynet-cli` `AnchorCommand::PullBundle`, `main.rs:7569+`): loads the pinned owner public key *before* any network I/O (`:7581`), restores the rollback watermark floor (`:7592-7594`), resolves the anchor address and **requires it to resolve to loopback** (`:7598-7600` — non-loopback is a hard error), connects over plain `TcpStream::connect_timeout(5s)` (`:7601-7608`), and runs `verify_attested_snapshot` (ed25519 attestation against the pinned owner key) *before anything is written to disk*. Consequences:

1. **Today, no in-tree client can reach a LAN anchor at all.** The loopback guard means the server-side TLS surface currently has zero production clients exposed to it. The gap is prospective — it opens the moment someone implements LAN anchor pull without the pin (which is exactly why QH-26 deferred client-side pinning behind a documented prerequisite).
2. **What an on-path LAN attacker can do against the *current* client:** nothing new — the client refuses non-loopback anchors, so on the LAN there is no client to attack. Against the *server*, an attacker can attempt AT-1's slowloris wedge, can complete handshakes and probe the fixed-vocabulary responses, and can present garbage tokens (rate-unlimited beyond the 2s-per-connection cost) — none of which yields key material, tokens (constant-time compare, never logged), or bundle content (the capability check gates the response).
3. **If a TLS client existed without pinning:** the attacker could present their own self-signed cert and become a transparent MITM of the *transport*. Crucially, the data-layer auth would still hold for bundle-pull — the snapshot's ed25519 attestation would fail against the pinned owner key, so a MITM cannot inject a bundle — but the MITM learns that pulls happen, can deny service, and can replay/fuzz. That is encryption-without-authentication at transport: exactly what `SecurityMinimumBar.md:105-110` already records as "not yet done," with the honest caveat that the pin is "server-side posture only." The docs do not overclaim; the code gap is real and tracked.

**Minimum fix (matches QH-26 Item 1's design):** distribute the anchor certificate's SHA-256 fingerprint through the existing signed channel — a field in the signed membership/assignment state the client already verifies with the pinned owner key — then implement the client verifier as a copy of the test module's `PinnedFingerprintVerifier` (which already proves the pattern works against this exact server config). Sized M; blocked on the distribution-field design, not on TLS mechanics.

---

## §7 Tests: what the seven tests prove and what they don't

`anchor_tls.rs`'s `#[cfg(test)]` module contains exactly seven tests:

1. `generated_identity_is_valid_and_fingerprinted` — generation produces parseable cert+key and a fingerprint.
2. `generated_identity_is_stable_when_reloaded` — reload of a written identity yields the same fingerprint (pin-stability property).
3. `generated_key_file_permissions_are_0600` (unix) — key file mode.
4. `partial_identity_is_refused` — the mixed present/absent state fails closed.
5. `over_permissive_key_file_is_refused_on_reload` (unix) — mode enforcement on the key.
6. `tls_handshake_succeeds_with_pinned_fingerprint` — end-to-end handshake with the test pinned verifier.
7. `tls_handshake_rejects_wrong_fingerprint` — the verifier rejects a mismatched pin.

Genuine strengths: tests 2 and 4 verify the two properties pinning *depends on* (stability and no-silent-regeneration), and 6–7 exercise a real rustls handshake in both directions.

Missing negative coverage (AT-9):
- **Corrupt cert / mismatched key pair** → must refuse at bind. (Code path exists — eager `build_certified_key` — but untested.)
- **Expired or not-yet-valid cert** → must refuse. With a 10-year lifetime this needs synthesized time, but the acceptance behavior is unspecified in tests.
- **TLS 1.2 ClientHello** → must be rejected (proves the double enforcement end-to-end rather than structurally).
- **Oversized ClientHello** → bounded disposition (ties into AT-1's fix verification).
- **Handshake timeout** → the dribbling-peer case AT-1 describes; currently nothing pins the intended behavior.
- **Over-permissive *cert* file** — mode enforcement is tested only for the key; the cert's `0644` check has no negative test.

---

## §8 Process: the three checkpoints, their later modifications, and blast radius

**Commit scope (all three):** strictly the anchor control plane.
- `9a723960`: new `anchor_tls.rs` (664 lines), `rustls`/`rcgen`/`time` added to `rustynetd/Cargo.toml`, `rustls` added to `rustynet-cli/Cargo.toml` (the dead dep, AT-7). Nothing else.
- `1a5bcb21`: `daemon.rs` +174/−8 (the control-stream enum, identity paths, config loader, bundle-pull listener wiring) + `lib.rs` module registration.
- `5757e55c`: `daemon.rs` +42/−8 (enrollment listener wired to the same pattern).

**Nothing outside the anchor TLS scope was touched** — no other trust path, no membership, no policy, no killswitch, no dataplane code appears in any of the three diffs. Blast radius of the unreviewed landing is contained to the new subsystem.

**Landed diff vs current code:** the checkpoints are *not* byte-identical to today's tree. `621c4cd0` ("Fix anchor TLS control-plane compile errors for rustls 0.23") changed the `crypto::ring::signer`→`sign` path, boxed the `Tls` arm of `AnchorControlStream`, and wrapped `build_anchor_server_config` in `Ok(())`; `e2ff2c82` and `30355d1c` were fmt/clippy passes (including the `Box::leak` that AT-6 records — that pattern is in the current tree); `8d6ad7cc` added the M-1 verification document. One semantic delta worth noting: `AnchorTlsIdentity` no longer derives `Clone` (the original checkpoint had it; the comment now explains `PrivateKeyDer` isn't `Clone`). **This review therefore audits the current tree, which is the code that actually runs** — the exact-landed-diff question is answered above (scope containment), and §10 notes the caveats.

**Process defect (the reason this review exists):** all three commits carry `WIP: automatic checkpoint (timed_out)` subjects — they are the delegated-edit auto-checkpoint commits, and they reached main with no human pass, violating `AGENTS.md` §12.6's contract that such branches "never merge without human review." The QH-26 acceptance criteria already propose the systemic fix (a `delegated_edit_marker_gate` CI guard that fails on merge of WIP-checkpoint subjects) — this review is the after-the-fact human pass for these three commits specifically; the gate remains the thing that prevents the *next* occurrence.

---

## §9 Disposition of the three checkpoints

**Verdict: ACCEPT-WITH-FIXES.** No P0/P1. The subsystem is structurally TLS-1.3-only, opt-in LAN exposure only, fail-closed at every trust boundary probed (§1–§5), with constant-time token comparison, bounded parsers, and no silent identity regeneration. Reverting would remove real, correctly-postured protection behind flags that default off, contradict the `SecurityMinimumBar.md` 2026-08-30 correction that already documents this subsystem as landed, and reopen the DA-01 question that `Requirements.md:168` resolved by deliberate amendment.

Fix list, ordered by severity (S = small, M = medium):

1. **AT-1 (P2, S-M):** enforce a total handshake deadline — drive `ServerConnection::complete_io` to completion under an `Instant` deadline before entering the line protocol, instead of relying on per-record socket timeouts under a lazy handshake. Add the dribbled-ClientHello negative test.
2. **AT-2 (P2, M):** implement client-side pinning per the existing QH-26 Item 1 design — fingerprint distribution field in signed membership/assignment state + a production pinned verifier (pattern already proven by the test module). Until then, treat the LAN anchor transport as unauthenticated-by-transport with data-layer attestation as the real control, per `SecurityMinimumBar.md:105-110`.
3. **AT-7 (P3, S):** remove the dead `rustls` dependency from `rustynet-cli/Cargo.toml:123-126` (or fold into AT-2 when the client lands — but do not carry a dependency whose comment claims an unimplemented capability).
4. **AT-3 (P3, S):** zeroize PEM/DER buffers on load, mirroring `enrollment_token.rs`.
5. **AT-4 (P3, S):** replace the derived `Debug` on `AnchorTlsIdentity` with a manual impl that redacts `key_der` (and `certificate_der` beyond length), independent of rustls's `Debug` behavior.
6. **AT-5 (P3, S):** eliminate the `read_tls_file` TOCTOU — open the fd first, then `fstat` it for type/mode (or `O_NOFOLLOW`), instead of stat-then-open.
7. **AT-6 (P3, S):** replace `Box::leak` in the error-context path with a borrowed/owned non-leaking construction.
8. **AT-9 (P3, M):** add the missing negative tests from §7.
9. **AT-8 (P3, M):** platform key custody (OS keychain where available, encrypted-at-rest fallback otherwise) — aligns the TLS identity with the `AGENTS.md` §4 bar; can ride the same work as any future platform-custody effort rather than blocking on it.

AT-10 requires no action beyond recording it.

---

## §10 What could not be verified

- **No live exposure test.** This is a static review: no lab run, no packet capture, no actual hostile handshake against a listening daemon. AT-1's slowloris reasoning is derived from rustls's buffered-read semantics and the inline serve loop in the code, not observed on the wire.
- **`rustls::pki_types::PrivateKeyDer` `Debug` redaction** — not verified against the vendored/source rustls version (basis of AT-4).
- **rustls default session-ticket rotation semantics** — assumed (in-memory ticketer, process-lifetime keys) but not verified against the pinned rustls 0.23 source.
- **The intended remote client of the enrollment listener** — no in-tree dial client to `anchor_enrollment_addr` exists (enrollment consumption goes through the local daemon's UDS IPC at `main.rs:8224-8248`); which external component is meant to speak TLS to that listener is unverified. The loopback-default + explicit-LAN-flag gating is sound either way.
- **No tests were executed** for this review (docs-only change; gates limited to formatting per the review-task constraints).
- **`M1AnchorTlsPinningVerification_2026-08-31.md`** — existence verified (added by `8d6ad7cc`); its content was not independently re-audited and this review's AT-2 finding was derived independently from code and from `SecurityMinimumBar.md:105-110`.
