# M-1 Verification — Anchor Control-Plane Fingerprint Pinning

Date: 2026-08-31
Subject: finding M-1 from `LiveLabCoverageGapAudit_2026-08-31.md` (L24, L28, L50)
Method: read-only code tracing against the working tree; no code was changed.

## Verdict

**CONFIRMED — high confidence.**

The audit's claim is accurate, and understated: the production client that pulls
anchor bundles does not merely "fail to pin" — it does not use TLS at all. The
only fingerprint-pin verifier in the tree lives inside a `#[cfg(test)]` module in
`rustynetd/src/anchor_tls.rs`. No pin distribution field exists anywhere in the
signed-state schema. The enforcement point SecurityMinimumBar demands (a client
that refuses a wrong-fingerprint server before the handshake completes) does not
exist outside tests. Already tracked upstream: SecurityMinimumBar says so itself
in its own control text, and QH-26 in the QualityHardeningTodo defers exactly
this work by design.

## The claim, restated

> [BLOCKING, NEW — M-1] Anchor control-plane fingerprint pinning is not enforced
> end-to-end… Server-side TLS landed (QH-26), but rustynet-cli's bundle-pull/enroll
> clients do not pin the server fingerprint; the pin verifier exists only as a
> `#[cfg(test)]` pattern inside `rustynetd/src/anchor_tls.rs` (SecurityMinimumBar
> L105–114)… no pin distribution field, no CLI pinning. No stage can assert what
> does not exist. Release-blocking. Product first: pin distribution + CLI pinning;
> then anchor_tls_pinning_validation stage.

## Evidence

### 1. Server side of the pinning story is complete

`crates/rustynetd/src/anchor_tls.rs`:

- `AnchorTlsIdentity::cert_fingerprint_sha256_hex()` — L101–102 (the pin value's
  source).
- `fingerprint()` helper — L105.
- Identity built at L293–297.
- The `#[cfg(test)]` module starts at L359. Inside it, and nowhere else:
  - `connect_pinned()` test helper — L575.
  - `PinnedFingerprintVerifier` — L605, implementing
    `rustls::client::danger::ServerCertVerifier` at L625; rejection message
    "anchor TLS certificate fingerprint does not match the pinned value"
    (~L639).
  - Tests `tls_handshake_succeeds_with_pinned_fingerprint` (L510) and
    `tls_handshake_rejects_wrong_fingerprint` (L543).

The pin verifier is test-only. This half of the claim matches exactly.

### 2. Server TLS posture (the half that did land)

`crates/rustynetd/src/daemon.rs`:

- `AnchorListenerBinding { listener, tls: Option<Arc<rustls::ServerConfig>> }`
  (~L1595–1601), documented: `tls` is `Some` exactly when the listener is
  exposed beyond loopback (`--allow-lan`); in that mode every accepted
  connection must complete TLS 1.3 before any line protocol, with **no
  plaintext fallback**.
- `anchor_control_stream()` — L1608–1619: `tls == None` →
  `AnchorControlStream::Plain(stream)`; `Some` → wrap in a
  `rustls::ServerConnection`. Enum at L1533–1545.
- `load_anchor_tls_server_config` — L1649–1666.
- TLS binding used at L1771 (LAN-exposed anchor listener) and L1892
  (bundle-pull listener).
- Enrollment accepts on the daemon side at L2054.

Loopback binds remain plaintext by design — that is the documented QH-26/DA-01
posture, not an accident.

One code comment is wrong and worth flagging for whoever lands the fix:
`daemon.rs` L1882–1883 claims the "client pins the same certificate fingerprint
for enrollment and bundle-pull". No such client pin exists anywhere in the
production code — the comment is aspirational and describes a control that is
currently test-only.

### 3. The production client does not use TLS at all

`crates/rustynet-cli/src/main.rs`, the `pull-bundle` command (~L7570–7620):

- `TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5))` — L7601.
  Plain TCP. No TLS client, no certificate check, nothing to pin with.
- The command refuses any address that does not resolve to loopback
  (`candidate.ip().is_loopback()`, else error "anchor bundle-pull addr must
  resolve to loopback" — L7600).

This is a stronger form of the audit's claim. The CLI bundle-pull client is
plaintext-TCP loopback-only, which is consistent with the server's
loopback-plaintext-by-design posture. The `--allow-lan` path — the one place
where the server actually requires TLS 1.3 — has **no CLI client at all** today:
a plaintext client could not complete the handshake against a LAN anchor even
if pointed at one. Fail-closed by absence, but the absence is the gap M-1 names.

The same gap class covers the audit's "enroll client" wording: enrollment
consumption is daemon-side (`daemon.rs` L2054 accept) and gossip-driven; there
is no separate enrollment-consume TLS client in `rustynet-cli` to pin with
either. The only other `TcpStream::connect_timeout` call sites in `main.rs` are
connectivity diagnostics (L20186, L21127), not control-plane clients.

A repo-wide search for `ClientConfig|ClientConnection|ServerCertVerifier|danger_accept`
over `crates/*/src` returns only the test-only `anchor_tls.rs` hits plus
struct-name false positives (`RelayClientConfig`, `E2eHttpProbeClientConfig`).
`danger_accept_invalid_certs` appears nowhere. There is no production rustls
client in this codebase.

### 4. Trust root of the expected fingerprint — and the missing distribution field

The expected fingerprint's root is `AnchorTlsIdentity`, generated/loaded
server-side on the anchor host by `load_or_generate_anchor_tls_identity`
(`anchor-tls/` directory under the state root, mode 0700). That is a server-side
secret; nothing distributes its fingerprint to clients.

No pin distribution field exists in signed bundles or enrollment tokens. A
search for `fingerprint` across `crates/rustynet-control/src` hits only
`scale.rs` L288–307 — `presented_fingerprint` vs `signing_fingerprint` — which
is a different control entirely (the ed25519 signing-fingerprint authorization
input for scale limits, not TLS certificate pinning). It must not be mistaken
for the missing distribution field.

### 5. What this does and does not put at risk

Bundle authenticity does **not** rest on transport trust, so a MITM on the
anchor control plane cannot forge bundles:

- The pulled bundle is verified against the pinned owner pubkey
  (`load_membership_owner_key_pub`, the §6.B pin), loaded **before** any network
  I/O, hard error if missing.
- Attestation verification (`verify_attested_snapshot`) and the persistent
  watermark anti-rollback floor run on top.
- SecurityMinimumBar L116–118 states the model explicitly: signed membership
  updates are authenticated by ed25519 signature verification, never on
  transport trust.

The residual M-1 exposure is therefore: denial of service and metadata exposure
on an unauthenticated transport, plus the fact that the enforcement point
SecurityMinimumBar demands — a client that refuses a wrong-fingerprint server
pre-handshake — does not exist. The moment a real TLS-requiring client path is
built (e.g. a CLI client for `--allow-lan` anchors), building it without the
pin would turn a design gap into an exploited one. That is the release-blocking
framing: the control is design contract only.

## Release-blocking: YES

Per the audit's own framing and SecurityMinimumBar's control text, the
fingerprint-pin trust model is currently "design contract, not an enforced
end-to-end control". A live-lab stage cannot assert a control that has no
production enforcement point, hence the audit's "no stage can assert what does
not exist" and its acceptance order (L50): pin distribution + CLI pinning
first, then the `anchor_tls_pinning_validation` stage (correct pin → pull
succeeds; wrong certificate → refusal before the handshake completes, zero
bytes of line protocol, named refusal).

## Already tracked: YES

This is not a new gap; two owners already record it:

1. **`documents/SecurityMinimumBar.md` L105–114** says it verbatim in the
   control's own text: "**NOT yet done — the pin is server-side posture only so
   far.** There is no client-side fingerprint pinning in rustynet-cli's
   bundle-pull/enroll commands yet: the only pin verifier in the tree is a
   test-only `PinnedFingerprintVerifier` pattern inside anchor_tls.rs's own
   `#[cfg(test)]` module. There is also no signed-bundle fingerprint
   distribution field yet… Until both exist, the fingerprint-pin trust model is
   design contract, not an enforced end-to-end control — do not cite this item
   as client-side authentication of the anchor."

2. **`documents/operations/active/QualityHardeningTodo_2026-07-25.md`** — QH-26
   (HIGH, VERIFIED, L1937) landed DA-01 (TLS 1.3 for LAN-exposed listeners, no
   plaintext fallback, loopback stays plaintext) and explicitly deferred two
   follow-up items as "DESIGN ONLY, NOT IMPLEMENTED" (L1991): client-side
   pinning and pin distribution.

The audit's M-1 is a correct restatement of these tracked items, elevated to a
release-blocking gap. The verification therefore closes with: claim confirmed,
evidence traced, and the remaining work is exactly what SecurityMinimumBar and
QH-26 already prescribe — pin distribution field in the signed state, a
production CLI pin verifier, and only then the
`anchor_tls_pinning_validation` live stage.
