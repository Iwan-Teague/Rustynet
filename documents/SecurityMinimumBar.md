# Rustynet Security Minimum Bar

## 1) Purpose
This document defines non-negotiable security and reliability controls that must be met before release milestones.

If this document conflicts with implementation plans, [Requirements.md](./Requirements.md) remains the source of truth and this file should be updated accordingly.

## 2) Release Blocking Rules
- Any unmet `Critical` control blocks release.
- Any unmet `High` control requires explicit, documented risk acceptance by security and engineering owners.
- `Medium` controls may be time-bounded only with a tracked remediation plan.

## 3) Critical Controls (Must Pass)
1. Proven crypto only:
- No custom cryptographic protocol design in production paths.
- Tunnel encryption uses WireGuard-style authenticated encryption.

2. Control-plane transport security:
- Mesh control traffic rides the WireGuard tunnel's authenticated encryption
  (Noise IK handshake, ChaCha20-Poly1305; vendored at
  `third_party/boringtun/src/noise/handshake.rs:13`). No control-plane TLS
  terminator exists: the workspace contains no HTTP or gRPC server framework
  at all (`axum`, `actix-web`, `hyper`, `tonic` are all absent from
  `Cargo.lock`), and `rustynet-control` has no network listener — its binary
  is a 49-line scaffold (`crates/rustynet-control/src/main.rs`).
  - **CORRECTION 2026-07-27.** This control previously read "there is no
    separate TLS stack and no TLS library is a workspace dependency". The
    second half was false. `rustls` 0.23.41 **is** a workspace dependency
    (`Cargo.lock:1278`), pulled in by `ureq` 2.12.1
    (`crates/rustynet-mcp/Cargo.toml:29`); `rustynet-mcp` is a member of the
    security-gated workspace (`Cargo.toml:20`, deliberately not in the
    `exclude` list) and makes real outbound HTTPS calls through it
    (`crates/rustynet-mcp/src/bin/ai_agent.rs:750`). TLS is therefore inside
    this project's supply-chain, SBOM, and CVE-triage scope. Do not use this
    control to justify skipping TLS advisories.
  - **SUPERSEDED 2026-07-28 — the requirement was amended, the dead code was
    not.** This block previously read "UNMET REQUIREMENT — code gap, not a doc
    gap. Do not delete." and cited `Requirements.md:166` as mandating TLS 1.3 for
    the control plane. That mandate was amended by the owner on 2026-07-27 to
    "authenticated, encrypted transport and signed peer maps"
    (`Requirements.md:168`), so there is no longer an unmet TLS requirement to
    record here, and reinstating one would be a product decision rather than a
    documentation edit. Corrected because the audit that wrote this block was
    working from a base that predated the amendment.
    What REMAINS true, and is the residual worth acting on — dead code shaped
    like a control. Nothing in the tree negotiates TLS 1.3. The only enforcement
    code —
    `ControlPlaneTransportPolicy::validate_negotiated_tls`
    (`crates/rustynet-control/src/lib.rs:209`) and
    `ControlPlaneCore::validate_transport_security` (`:2327`) — receives the
    "negotiated" version as a caller-supplied argument instead of observing a
    real handshake, and its only callers are its own unit test (`:7010`,
    `:7016`; the single `#[cfg(test)]` boundary in that file is line 4355).
    A reader can mistake either symbol for a live control. With the requirement
    amended away, the honest dispositions are to delete them or to wire them to a
    real handshake; leaving them is what let this be read as an enforced control
    in the first place.
- Signed membership updates (gossip convergence, `membership apply-update`)
  are authenticated by ed25519 signature verification against the current
  approver set before being applied — fail closed on any verification error,
  never on transport trust.
- Anchor bundle-pull is cryptographically authenticated via the **membership
  head attestation**: ed25519 signatures over the snapshot's exact
  `(network_id, epoch, state_root)` identity plus a freshness timestamp,
  minted in the same signing session as every membership update signature and
  materialized into the persisted snapshot at apply time (anchors stay
  trust-inert — they never mint, they only re-serve what a signing session
  produced). A device pulling a bundle accepts it only when: the §6.B pinned
  membership owner public key is an Owner in the attested approver set AND
  its private-key holder actually signed the attestation (roster presence
  alone is rejected — but this list is NOT exhaustive; see the pin-rotation
  grace path recorded below, which the original wording omitted); valid
  signatures from the attested state's active
  approvers, one per DISTINCT signing key (no two approver ids may share a
  key — `MembershipState::validate` rejects that roster shape outright, so it
  can never even acquire a state root, let alone be signed or persisted), meet
  its quorum threshold; the attestation is fresh within a bounded window
  (default 7 days, tighten-only — there is no bypass flag) and not
  future-dated beyond clock-skew tolerance; and the epoch does not regress
  against the previously verified local bundle (same-epoch different-root is
  surfaced verbatim as fork evidence, never silently resolved). Every failure
  mode rejects BEFORE any byte is written to disk. Enforcement points:
  `rustynet_control::membership::verify_attested_snapshot` (invoked by
  `anchor pull-bundle` ahead of any output write) and
  `MembershipState::validate` (the pubkey-uniqueness gate, invoked
  transitively by every state-root/signing/persist path in the crate).
  Verification: `verify_attested_snapshot_rejects_missing_attestation` and its
  sibling negative tests in `crates/rustynet-control/src/membership.rs`
  (including `validate_rejects_duplicate_approver_pubkeys` and
  `verify_attested_snapshot_rejects_quorum_inflation_via_duplicate_approver_pubkey`),
  plus the enforcement-ordering integration test
  `pull_bundle_never_writes_unverified_bytes` in
  `crates/rustynet-cli/src/main.rs`. Full review trail — original design,
  implementation, three independent adversarial reviews, and the fix each
  produced — recorded in
  [`operations/active/AnchorBundlePullAttestationSecurityReview_2026-07-20.md`](./operations/active/AnchorBundlePullAttestationSecurityReview_2026-07-20.md).

  **ADDED 2026-07-27 — second accept path (pin-rotation grace), previously
  undocumented here.** The acceptance list above read as exhaustive but omitted
  a real accept path that the code implements and self-documents. A pinned key
  that matches a **Revoked** former Owner in the attested state is still
  accepted, provided a currently-Active Owner co-signed the same attestation
  (`crates/rustynet-control/src/membership.rs:1308-1346`; the pin is classified
  Active-vs-Revoked at `:1318-1319`, and the grace check — reject only when the
  pin is not an active owner AND no active owner co-signed — is at `:1338-1346`.
  The design note and its stated residual risk are at `:1207-1213`.) The code
  states the residual risk plainly and this document should too: a **compromised
  old owner key can still satisfy this grace path on any device that never
  received the new pin.** That is a second residual limit alongside the
  watermark-deletion TOFU reset described below — the phrase "the honest
  residual limit" in that paragraph is scoped to stale-cache rollback only and
  must not be read as the complete residual set for this control.
  Verified against code 2026-07-27; the rest of this control's attestation,
  quorum, freshness, fork-detection, and pubkey-uniqueness claims were
  independently re-verified and hold as written
  (`membership.rs:1214-1381` for the verifier, `:237-260` for the
  pubkey-uniqueness gate).

  **Stale-cache rollback — CLOSED (2026-07-20).** Epoch-regression
  protection previously read its floor fresh from the client's OWN local
  cache on every pull, so a brand-new device (the primary bundle-pull
  scenario) or one whose cache had aged past the freshness window skipped
  the check entirely, letting a holder of an old, already-revoked signing
  key resurrect a superseded epoch with a freshly-timestamped attestation.
  Fixed by relocating `rustynetd`'s existing, already-production-tested
  `MembershipWatermark` mechanism (persistent, monotonic, TOFU-on-absence —
  previously wired only into the daemon's own bootstrap/apply paths) into
  `rustynet_control::membership` and wiring `anchor pull-bundle` to consult
  and advance the SAME on-disk watermark file the daemon already maintains,
  independent of `--output`'s existence, freshness, or deletion. Enforcement
  point: the `prior_identity` argument to `verify_attested_snapshot` is now
  sourced from `load_membership_watermark`, not from `--output`.
  Verification:
  `pull_bundle_rejects_epoch_regression_on_brand_new_device_after_first_watermark_established`
  (the exact vulnerability, reproduced and closed),
  `pull_bundle_accepts_first_ever_pull_with_no_watermark_and_establishes_one`
  (TOFU case), and
  `pull_bundle_watermark_survives_output_deletion_but_not_watermark_deletion`
  (the honest residual limit — deleting the watermark's own storage, not
  just `--output`, is a real, acknowledged TOFU-reset boundary, pinned by
  test rather than left implicit) in `crates/rustynet-cli/src/main.rs`.
  Investigation, design rationale, and the full residual-risk discussion:
  [`operations/active/AnchorBundlePullRollbackWatermarkInvestigation_2026-07-20.md`](./operations/active/AnchorBundlePullRollbackWatermarkInvestigation_2026-07-20.md)
  and the review trail doc above.

  **Remaining adjacent gap (tracked separately, out of this control's
  scope):** the bundle-pull endpoint still authenticates the CLIENT with a
  static long-lived bearer token rather than the single-use enrollment token
  `Requirements.md` specifies — that token gates roster confidentiality only;
  bundle authenticity no longer depends on it.
- Signed peer/control data validated by clients before application.

3. Auth and enrollment hardening:
- Per-IP and per-identity rate limiting.
- Lockout/backoff for repeated auth failures.
- Anti-replay protections (nonce/state + short token lifetime + skew policy).
- One-time credential consumption is atomic and race-safe under concurrent requests.

4. Secret and key handling:
- OS key store usage where available.
- Encrypted-at-rest fallback with strict permissions and startup permission checks.
- Sensitive in-memory material handling includes zeroization strategy.
- Trusted authorization/signing state fails closed when unavailable or corrupt.
- Secret redaction verified across MDM, env, CLI, API, and UI ingestion paths.

5. Host-OS boundary enforcement:
- Startup/setup path must detect host OS and enforce host profile behavior.
- Linux-only dataplane/runtime provisioning must be blocked on non-Linux hosts.
- Linux runtime roots (`/etc/rustynet`, `/var/lib/rustynet`, `/run/rustynet`, `/var/log/rustynet`) must not be created/used on non-Linux hosts.
- Non-Linux compatibility mode must enforce platform-safe user-scoped storage paths and reject/normalize unsafe Linux-root paths fail-closed.

6. Policy and privilege enforcement:
- Default-deny ACL behavior across mesh, routes, and exit-node access.
- RBAC enforced on admin API/UI paths.
- MFA required for privileged mutations.

7. Web/admin security:
- CSRF protections for state-changing UI/API flows.
- Secure cookie/session policy.
- Clickjacking defenses.
- Privileged helper/system integration paths use argv-only command invocation with strict input validation.

8. Data-plane leak prevention:
- Tunnel fail-close behavior in protected-routing modes.
- DNS fail-close behavior in protected DNS modes.
- Protocol-filter ACL behavior is validated in shared subnet-router and shared-exit scenarios.
- Direct/relay traversal transitions require authenticated, replay-protected, freshness-bounded endpoint-hint state.
- Path failover/failback cannot bypass ACL, trust-state, or leak-prevention controls.

9. Audit and forensics:
- Tamper-evident, append-only audit logging.
- Retention policy and integrity-verification process active.

10. Supply-chain integrity:
- Signed artifacts required for beta+ releases.
- SBOM generated and retained for released artifacts.
- Staged release tracks (unstable/canary/stable) required for security-sensitive rollout paths.

## 4) High Controls
1. API abuse detection and anomaly alerting.
2. Backup/restore validation with integrity checks.
3. Relay failover tested under fault scenarios.
4. Tenant-boundary isolation tests (multi-tenant modes).
5. Incident runbooks and response drills.
6. Patch SLA tracking and reporting:
- Critical: mitigation or patched build within 48 hours.
- High: patched build within 7 calendar days.
- Medium: patched build within 30 calendar days.
7. Relay abuse/capacity controls validated under traversal load and reconnect churn.

## 5) Performance Minimum Bar
1. Idle daemon CPU: <= 2% of one core on Raspberry Pi-class target.
2. Idle daemon memory: <= 120 MB RSS (normal profile).
3. Reconnect after transient drop: <= 5 seconds target.
4. Route/policy apply latency: <= 2 seconds p95 target.
5. Throughput overhead vs baseline WireGuard path: <= 15% target.
- Benchmark matrix must cover declared hardware/OS/network profiles.
- Release-candidate soak tests must run for at least 24 continuous hours.

These budgets are release gates once benchmarking harnesses are active.

## 6) Required Test Evidence
- Unit tests for policy logic, credential lifecycle, and DNS naming behavior.
- Integration tests for mesh, exit-node routing, LAN toggle, and relay fallback.
- Negative tests for auth abuse (rate limits, replay, lockout/backoff).
- Leak tests for tunnel and DNS fail-close behavior.
- Traversal security tests for signed endpoint-hint validation, replay rejection, and failover/failback policy integrity.
- Shared-router/shared-exit protocol-filter ACL tests.
- Audit-log integrity verification tests.
- Performance benchmark report with regression thresholds.
- Concurrent one-time-key consume race tests.
- Privileged-helper command-input safety tests.
- Patch-SLA and emergency-release drill evidence.

## 6.B) Bootstrap Trust Anchor (Membership Owner Public Key)

A new node's first contact with the mesh consumes a *signed
membership snapshot*. The owner-signing-key public part is the
trust anchor that lets the node verify subsequent snapshots,
assignment bundles, traversal bundles, and DNS-zone bundles. The
private side never leaves the membership owner's secure keystore.

The public side (`membership.owner.key.pub`) MUST reach the
new node *out of band*, before the daemon is allowed to load any
signed state. Every reviewed Rustynet install carries the public
key at:

- Linux: `/etc/rustynet/membership.owner.key.pub`
- Windows: `C:\ProgramData\RustyNet\trust\membership.owner.key.pub`

Approved out-of-band delivery channels (in decreasing preference):

1. **Pre-baked into the install image.** The reviewed bootstrap
   helper for the install track (e.g. `cloud-init` user-data on
   Linux, MDM device profile on Windows) lays the public key down
   before the daemon's first start. This is the most-secure
   default — the trust anchor is bound to the image build, not
   to any post-deployment trust transfer.

2. **Out-of-band copy from a trusted operator workstation** —
   the operator distributes the public key via SSH or a signed
   file-transfer channel rooted in the operator's existing trust.
   The target host's daemon refuses to start until the file is
   present + ACL'd to root/SYSTEM-only.

3. **Sneakernet / printed thumbprint with pre-distributed
   software.** For air-gapped deployments, the public key is
   printed (or QR-coded) and visually verified against a known
   source. This is rare in normal Rustynet deployments and is the
   fallback for environments that forbid in-band trust transfer.

**Forbidden / not approved:**
- Fetching the public key over plaintext HTTP (no trust anchor
  yet, so HTTPS is the *minimum* but the daemon SHOULD prefer
  pre-baking instead).
- Fetching the public key over a TLS-only channel without the
  operator visually verifying the thumbprint — TLS alone does not
  bind the certificate to the membership owner.
- Sharing the public key over a chat channel that does not
  publish key material in a tamper-evident form.

**Verification (post-install):**
- `sha256sum /etc/rustynet/membership.owner.key.pub` (Linux) or
  `Get-FileHash -Algorithm SHA256
  C:\ProgramData\RustyNet\trust\membership.owner.key.pub` (Windows)
  must match the operator's published key thumbprint.
- The file's ACL must be SYSTEM/Administrators / root-only;
  Rustynet's runtime ACL verifier (Linux) and W1.2 verifier
  (Windows) reject non-canonical ACLs at daemon start.

This subsection captures the previously-implicit Tofu (trust on
first use) handshake the Rustynet bootstrap performs with the
out-of-band trust anchor; making it explicit closes
SecurityHardeningAudit_2026-04-28.md §B.9.1.

## 6.C) Anchor Node Capability Controls

The anchor role (see
[`operations/active/AnchorNodeRoleDesign_2026-05-21.md`](./operations/active/AnchorNodeRoleDesign_2026-05-21.md))
introduces a small number of LAN-exposed surfaces that must satisfy the
following minimum-bar controls. Anchor is operational metadata, not a
trust authority: anchor flags are never consulted before signature
verification, and an anchor cannot self-promote — capability changes
require an owner-signed membership bundle.

Required controls when any `anchor.*` capability is advertised on a
running daemon:

1. **Signed capability advertisement.** Anchor capabilities live in the
   canonical-payload pre-image of the signed membership bundle.
   Tampering with the `node_capabilities` field invalidates the bundle
   signature. The membership reducer MUST reject unsigned/invalid
   bundles regardless of capability contents.

2. **Bundle-pull endpoint default-deny.** The `anchor.bundle_pull`
   endpoint defaults to loopback bind
   (`127.0.0.1:51822` — verified, `crates/rustynetd/src/daemon.rs:193`).
   LAN-IP bind requires explicit opt-in and documented operator
   acknowledgement. Non-loopback packets MUST be dropped when the
   endpoint is loopback-only.
   - **CORRECTION 2026-07-27.** This control previously named an
     `--anchor-bundle-pull-lan-bind` flag. **No such flag exists** — it
     appears nowhere in the codebase, only in this document and in
     `operations/active/AnchorNodeRoleDesign_2026-05-21.md:121,276`. An
     operator following the old wording would get an unknown-argument
     error. The real opt-in is `--anchor-bundle-pull-allow-lan <true|false>`
     (`crates/rustynetd/src/main.rs:2903-2919`), which takes a mandatory
     value rather than being a bare flag, or the environment variable
     `RUSTYNET_ANCHOR_BUNDLE_PULL_ALLOW_LAN`
     (`crates/rustynetd/src/daemon.rs:199`). The bind-time refusal itself is
     real and fail-closed (`daemon.rs:966-976`, called from `:1271`, `:9957`,
     `:11056`).
   - **Scope note on "non-loopback packets MUST be dropped" (verified
     2026-07-27).** This holds today only by kernel socket semantics — the
     listener is bound to `127.0.0.1` (`daemon.rs:1275`). There is no
     application-layer peer check: `poll_anchor_bundle_pull_once`
     (`daemon.rs:1292-1331`) reads `peer_addr` but only logs it, and no
     nftables/pf rule scopes port 51822. Consequently, once
     `--anchor-bundle-pull-allow-lan true` is set, the sole remaining gate is
     the shared bearer token (`daemon.rs:1054`, `constant_time_ascii_eq`, inside
     `write_anchor_bundle_pull_response_with_have` at `:1047`).

3. **Token-gated bundle-pull + enrollment redemption.** Anchor
   bundle-pull and anchor-hosted enrollment redemption MUST share a
   single-use enrollment-token ledger so a token cannot be consumed
   for both. Replay of a consumed token MUST be rejected fail-closed.
   - **UNMET REQUIREMENT — code gap, not a doc gap. Do not delete.**
     Verified 2026-07-27: bundle-pull does **not** use the single-use
     enrollment-token ledger. It authenticates with a static, long-lived
     bearer token read from a file
     (`crates/rustynetd/src/daemon.rs:195` for the default path
     `/var/lib/rustynet/anchor-bundle-pull.token`, loader at `:978-993`,
     constant-time comparison at `:1054`), so there is no consumption, no ledger
     sharing, and no replay rejection on this surface. The single-use ledger
     that this control describes does exist and is production-wired, but only
     for enrollment-token redemption
     (`crates/rustynetd/src/enrollment_token.rs:833-867`, reached from
     `daemon.rs:8268`). §3 control 2 already acknowledges this gap; the two
     statements are now cross-referenced rather than left to contradict each
     other.

4. **Anchor secret custody.** The anchor enrollment-endpoint HMAC
   secret MUST be stored in OS-secure custody:
   - Linux: systemd `LoadCredentialEncrypted` credential
     (`anchor_enrollment_secret.cred`); plaintext custody rejected.
   - macOS: Keychain item `rustynet.anchor_enrollment_secret`;
     plaintext custody rejected.
   - Windows: DPAPI-protected `anchor_enrollment_secret.dpapi` blob
     under `C:\ProgramData\RustyNet\secrets\`; ACL must be
     SYSTEM/Administrators-only and validated by the W4 verifier.
   - **UNMET REQUIREMENT ON ALL THREE PLATFORMS — code gap, not a doc gap.
     Do not delete.** Verified 2026-07-27 by grepping each named artifact.
     `anchor_enrollment_secret.cred` and `anchor_enrollment_secret.dpapi`
     appear **nowhere in the codebase or in any systemd unit** — only in this
     document and in
     `operations/active/AnchorNodeRoleDesign_2026-05-21.md:192,209,278`. The
     macOS Keychain label `rustynet.anchor_enrollment_secret` has exactly one
     occurrence in Rust, `crates/rustynet-crypto/src/lib.rs:2456`, and it is a
     **`#[cfg(test)]` fixture** (test module begins at `:1723`) inside
     `validate_macos_keychain_label_accepts_canonical_descriptors` — it asserts
     only that the string passes a charset/length validator. No Keychain item
     with that service is ever stored or read. Do not mistake that test for
     custody evidence.
     What actually ships, on every platform, is a **plaintext 32-byte file at
     mode 0600** — i.e. exactly the "plaintext custody" this control says is
     rejected: `RUSTYNET_ENROLLMENT_SECRET=/var/lib/rustynet/keys/enrollment.secret`
     (`scripts/systemd/rustynetd.service:27`), loaded by
     `enrollment_token::load_secret` (`crates/rustynetd/src/enrollment_token.rs:720-749`),
     consumed at `crates/rustynetd/src/daemon.rs:8239`, and generated as a
     plain file on macOS too
     (`scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh:622-670`). The only
     `LoadCredentialEncrypted=` entry in the Linux unit is
     `wg_key_passphrase` (`scripts/systemd/rustynetd.service:66`), not the
     anchor enrollment secret.

5. **Anchor downgrade is fail-closed.** A bundle that removes anchor
   capabilities from a previously-anchored node without a higher epoch
   MUST be rejected by the existing membership replay-watermark path.

6. **No anchor PII in logs.** Anchor bundle-pull request logs MUST
   record only token thumbprint (not the token) plus duration. Peer
   identifiers and candidate IPs MUST be redacted at the same level
   as gossip surfaces, per
   [`operations/PrivacyRetentionPolicy.md`](./operations/PrivacyRetentionPolicy.md).

7. **Multi-anchor port-mapping coordination.** When multiple anchors
   advertise `anchor.port_mapping_authoritative=true` on the same
   LAN, only the lex-min `node_id` MUST request the router lease;
   the others MUST stand down. Racing the router lease is rejected.

8. **Mobile anchor consumption is read-only.** iOS and Android clients
   MUST treat anchor metadata as read-only display information and
   MUST NOT host any anchor capability locally. The mobile
   `anchor_bundle_pull_client` FFI surface is consumption-only.

Each control must have an enforcement point in code and a verification
method (unit test, integration test, negative test, or gate). The
anchor design document §8 maps controls to enforcement points and
§10 maps to gates.

## 6.D) Node Role Transition Controls

The six user-selectable node roles (`relay`, `anchor`, `exit`,
`blind_exit`, `client`, `admin`; canonical taxonomy:
[`operations/active/NodeRoleTaxonomy_2026-05-21.md`](./operations/active/NodeRoleTaxonomy_2026-05-21.md))
have non-negotiable transition controls beyond the general signed-state
floor in §6.B.

Required controls for every role transition:

1. **Transition matrix validated fail-closed.** The role-preset table
   in `crates/rustynet-control/src/role_presets.rs` is the
   authoritative source for which transitions are allowed
   (`local` / `signed` / `blocked` / `irrev`). Blocked transitions
   MUST be rejected by `validate_transition` and never reach
   side-effect execution.

2. **BlindExit irreversibility.** A node currently in role
   `blind_exit` MUST refuse every other-role transition without an
   explicit factory-reset operator step that wipes node identity +
   re-enrolls. The wizard surface MUST require typed confirmation
   (not just Enter) when entering or leaving `blind_exit`. This
   matches the existing immutable-blind-exit security posture.

3. **Capability changes require owner signature.** Any role
   transition that changes Axis-2 mesh capabilities
   (`serves_exit`, `serves_relay`, `anchor.*`) MUST emit an unsigned
   `MembershipUpdateRecord` for the membership owner to sign + apply.
   Local-only acceptance of capability changes is forbidden.

4. **Service deploy precedes capability advertisement.** When a
   transition adds `serves_relay` (or anchor's
   `relay_colocation`), the platform-specific service installer
   MUST successfully deploy and verify `rustynet-relay` BEFORE the
   signed bundle is emitted. Failure to deploy MUST abort the
   transition and preserve previous state.

5. **Service undeploy precedes capability revocation.** When a
   transition removes `serves_relay` (or revokes the anchor
   `relay_colocation`), the installer MUST successfully stop and
   remove the relay service BEFORE the signed revocation bundle is
   emitted. Failure to undeploy MUST keep the previous state and
   raise a fail-closed alarm.

6. **Tamper-evident transition audit.** Every role transition
   (successful, failed, or aborted) MUST emit an append-only audit
   log entry with: timestamp, from-role, to-role, side-effects
   attempted, outcome, operator id where available. The audit log
   MUST satisfy §3 control 9 (tamper-evident, append-only,
   retention-bound).

7. **Exit-serving NAT activation is fail-closed on revocation.**
   When a transition revokes `serves_exit`, the daemon MUST tear
   down forwarding + NAT before the capability is removed from
   local state. Forwarding/NAT residue after revocation is a
   release-blocking defect.

8. **Mobile role lock.** iOS and Android FFI surfaces MUST refuse
   any `role set` request targeting anything other than `client`.
   Mobile daemon-equivalent MUST advertise only `client`
   capabilities on every snapshot reload.

9. **Platform-blocked roles fail closed.** On platforms where a
   role is gated behind dataplane parity work (today: all
   non-client roles on Windows; `blind_exit` on macOS), the
   wizard MUST grey out the blocked role and `rustynet role set`
   MUST return an explicit `platform-blocked` error rather than
   silently proceeding with a partial-effect transition.

10. **Read-only status available to all primary roles.**
    `rustynet role status` and `rustynet capability list` MUST be
    available to `Client` and `BlindExit` primary roles so
    operators can verify resolved role state without elevation.

Enforcement points map to verification tests in
`scripts/ci/role_taxonomy_gates.sh` and
`scripts/ci/role_transition_audit_gates.sh` (added in D12).

**CORRECTION 2026-07-27.** This paragraph previously also listed
`scripts/ci/blind_exit_irreversibility_gates.sh`. **That script does not
exist** — it is absent from `scripts/ci/` and from the whole repository,
while three documents assert it (this file, plus
`operations/active/NodeRoleTaxonomy_2026-05-21.md:417` and
`operations/active/LiveLabSecurityTestCoverage_2026-06-22.md:229`, where the
row carrying it is marked as passing). Control 2 above (BlindExit
irreversibility) therefore has **no gate-level verification method**, which
is a violation of the "each control must have an enforcement point in code
and a verification method" rule stated in §6.C. The control itself stands;
the missing gate is code/CI work.

## 6.E) Service-Hosting Role Controls (`nas`, `llm`)

The two service-hosting presets (`nas`, `llm`; canonical design:
[`operations/active/NodeRoleTaxonomyExtension_2026-06-11.md`](./operations/active/NodeRoleTaxonomyExtension_2026-06-11.md))
inherit every §6.D control unchanged and add four category-specific
controls. A service-hosting role changes what an **authorised** peer
can reach, never who is trusted: `serves_nas`/`serves_llm` are signed
metadata, and no verifier may consult them before validating
signatures.

1. **E1 — Service endpoint binds tunnel-only.** The service API
   binds the node's mesh tunnel address only — never `0.0.0.0`,
   loopback, LAN, or public. A non-tunnel bind configuration is a
   fail-closed startup error; there is no LAN-bind escape hatch for
   service-hosting roles. The LLM inference engine is the inverse:
   loopback-only, never tunnel- or LAN-reachable.
   Enforcement: `rustynetd::service_exposure::validate_tunnel_only_bind`
   / `validate_loopback_only_bind`, the bin-side startup checks in
   `rustynet-nas` / `rustynet-llm-gateway`, and the
   `inet rustynet_svc_<service>` nftables scope table
   (`linux_runtime_nftables::render_service_port_tunnel_scope_table`).
   - **ENFORCEMENT NOT ACTUALLY WIRED (verified 2026-07-27) — code gap, not a
     doc gap. Do not delete the control.** All three named enforcement points
     exist as production code but have **zero production callers**:
     `validate_tunnel_only_bind` (`crates/rustynetd/src/service_exposure.rs:169`)
     and `validate_loopback_only_bind` (`:207`) are invoked only from that
     file's own `#[cfg(test)]` module (boundary `:596`; calls at `:662`, `:674`,
     `:682`, `:693`, `:704`), and
     `render_service_port_tunnel_scope_table`
     (`crates/rustynetd/src/linux_runtime_nftables.rs:437`) has exactly one
     non-definition reference in the repo — a `rg` presence check in
     `scripts/ci/service_hosting_role_gates.sh:35`.
     Neither service crate even depends on `rustynetd`
     (`crates/rustynet-nas/Cargo.toml`, `crates/rustynet-llm-gateway/Cargo.toml`).
     Each binary instead ships its own **weaker** check —
     `validate_tunnel_shaped_bind` (`crates/rustynet-nas/src/main.rs:185`,
     `crates/rustynet-llm-gateway/src/main.rs:163`) — which rejects only
     unspecified / loopback / multicast and has **no tunnel-address list**.
     Consequence: today a NAS or LLM listener bound to a LAN or public IP
     passes startup validation, which is precisely the state E1 forbids.

2. **E2 — Default-deny per-peer service authorisation.** Being inside
   the tunnel is necessary, not sufficient. Every new service session
   is gated by `ContextualPolicySet::evaluate_with_membership` for
   `TrafficContext::NasService` / `TrafficContext::LlmService`;
   empty/missing/stale policy ⇒ `Decision::Deny`. Rules with an empty
   `contexts` list MUST NOT match service contexts (a pre-D13
   wildcard-context rule never silently grants application-layer
   access). Identity comes from the authenticated tunnel source
   resolved against signed state — never from a client-supplied
   header or key; there is no API key.
   Enforcement: `service_exposure::evaluate_service_access`, the
   (crate-private) `context_matches` helper in `rustynet-policy`, per-frame
   grant re-checks in both service binaries (deny-all when no signed access
   state is materialised).
   - **VERIFIED WIRED 2026-07-27 — this is the one §6.E control that is
     genuinely enforced at runtime.** `evaluate_service_access`
     (`crates/rustynetd/src/service_exposure.rs:257`) is reached in production
     via `crates/rustynetd/src/service_access_state.rs:90` ←
     `materialize_service_access_state` (`daemon.rs:4512`), called from
     `daemon.rs:4938`, `:7536`, `:8489`, `:9051`; both binaries then enforce
     per-frame (`crates/rustynet-nas/src/main.rs:307-317`,
     `crates/rustynet-llm-gateway/src/main.rs:460`). Default-deny is real and
     doubly enforced: `evaluate_with_membership` (`:224`) falls through past the
     rule loop to a bare `Decision::Deny`
     (`crates/rustynet-policy/src/lib.rs:255`) and denies outright when
     membership does not resolve (`:229-231`); and an empty `contexts` list
     cannot match a service context — `context_matches` returns
     `!candidate.is_service_context()` for the legacy empty form (`:386-397`).
     One naming correction: the path `rustynet_policy::context_matches` given
     in the old wording is not reachable — `context_matches`
     (`crates/rustynet-policy/src/lib.rs:386`) is private, not `pub`.

3. **E3 — Service teardown precedes capability revocation.** On
   `serves_nas`/`serves_llm` removal the daemon closes the listener
   and severs all in-flight sessions BEFORE the capability leaves
   local state. A revoked service host keeping an already-connected
   peer served is a release-blocking defect (the service-hosting
   analogue of §6.D control 7).
   Enforcement: `service_exposure::ServiceExposureController` —
   `capability_release_ready()` is true only after `begin_revocation`
   and the severance of every active session; the LLM gateway
   additionally re-checks grants per token event so revocation cuts
   in-flight generations mid-stream.
   - **ENFORCEMENT NOT ACTUALLY WIRED (verified 2026-07-27) — code gap, not a
     doc gap. Do not delete the control.** `ServiceExposureController`
     (`crates/rustynetd/src/service_exposure.rs:364`), `begin_revocation`
     (`:511`) and `capability_release_ready` (`:538`) are production code, but
     **the controller is never constructed outside tests**: every
     `ServiceExposureController::new` call site is inside the `#[cfg(test)]`
     module (`:803`, `:889`, `:906`, `:934`; boundary `:596`). The
     teardown-before-revoke state machine is therefore a unit-tested library,
     not an active runtime control. The per-token-event grant re-check in the
     LLM gateway IS real (`crates/rustynet-llm-gateway/src/main.rs:460`) and is
     what actually limits exposure today.

4. **E4 — App-layer token cannot exceed signed policy.** Any
   node-issued service session token is short-lived, single-audience,
   node-signed (existing ed25519 primitives — no new crypto/PKI), and
   re-checked against CURRENT signed policy on every use. A token
   outliving its peer's authorisation MUST be rejected before TTL
   expiry. Tokens are defence-in-depth only — never an identity
   source, never a substitute for the tunnel.
   Enforcement: `rustynet_llm_gateway::session::verify_session_token`
   (signature → validity window → audience/peer binding → current
   policy decision, in that order).
   - **ENFORCEMENT NOT ACTUALLY WIRED (verified 2026-07-27) — code gap, not a
     doc gap. Do not delete the control.** `verify_session_token`
     (`crates/rustynet-llm-gateway/src/session.rs:152`) exists and implements
     exactly the ordering claimed (`:166-168` signature, `:169-171` validity
     window, `:172-177` audience then peer, `:178-180` current policy). But
     **neither it nor `issue_session_token` is ever called from the gateway
     binary** — the only references repo-wide are the definitions, that file's
     own tests, and a `rg` presence check in
     `scripts/ci/service_hosting_role_gates.sh:34`. `main.rs` handles
     `--session-signing-key` by stat-validating the file only
     (`crates/rustynet-llm-gateway/src/main.rs:146-147`, `:181-208`); the key is
     never loaded and no session token is ever minted or verified at runtime.
     Live authorisation rests entirely on the E2 access-dir grant check.
     Note this means E4's "defence-in-depth" layer is currently absent, so E2
     is load-bearing alone.

Inherited essentials restated for the category: capability grant
requires the owner signing key (no self-promotion); deploy-before-
advertise and undeploy-before-revoke per §6.D; NAS data is
AEAD-encrypted at rest with a key from OS-secure custody and
location-binding associated data; attacker-influenced wire input
(uploads, prompts) is length-bounded and deny-on-malformed; logs
carry ids/thumbprints/counts only — never tokens, prompts,
completions, or file contents.

Enforcement points map to verification tests in
`scripts/ci/service_hosting_role_gates.sh`,
`scripts/ci/nas_default_deny_gates.sh`,
`scripts/ci/llm_default_deny_gates.sh`, and
`scripts/ci/llm_exit_coexistence_gates.sh` (D13). All four scripts exist
(verified 2026-07-27).

**METHODOLOGICAL WARNING, added 2026-07-27 — read before trusting a green
§6.E gate.** These gates verify E1/E3/E4 with **symbol-presence greps**, not
with call-path assertions:

```
rg -q 'validate_tunnel_only_bind' crates/rustynetd/src/service_exposure.rs   # E1
rg -q 'capability_release_ready'  crates/rustynetd/src/service_exposure.rs   # E3
rg -q 'verify_session_token'      crates/rustynet-llm-gateway/src/session.rs # E4
```
(`scripts/ci/service_hosting_role_gates.sh:29-35`)

A grep for a symbol's own definition, in its own defining file, passes whether
or not anything calls it. That is exactly how E1, E3, and E4 stayed green in CI
while having zero production call sites — the accompanying `run_required_test`
lines exercise the functions as isolated units, never through the daemon or the
service binaries. A gate of this shape proves a symbol exists; it cannot prove a
control is enforced. Any future control added here needs a
reachability/integration assertion, not a presence check.

## 7) Phase Mapping
- Phase 1: baseline standards and threat model defined.
- Phase 2: auth/enrollment abuse controls + key custody baseline + atomic one-time key handling.
- Phase 3: encrypted Linux mesh + conformance + initial perf baselines.
- Phase 4: exit/LAN/DNS with fail-close leak prevention.
- Phase 5: tamper-evident audit + early signing/SBOM + perf regression + SLA operations.
- Phase 6: admin UI with RBAC/MFA + CSRF/session/clickjacking + privileged helper hardening.
- Phase 7: HA, tenant boundary hardening, trust-state fail-closed enforcement, and relay/traversal hardening controls.
- Phase 8: external audit cadence + advanced compliance/key custody.
- Phase 9: GA readiness with SLO/DR/performance gates fully enforced.
- Phase 10: real Linux dataplane enforcement for encrypted exit-node traffic, traversal failover/failback integrity, NAT/forwarding hardening, and tunnel/DNS leak-prevention verification in live networking paths.

## 8) Sign-off Checklist
- [ ] Security owner approval
- [ ] Engineering owner approval
- [ ] Operations owner approval
- [ ] Release artifact signing and SBOM verification complete
- [ ] Critical controls all green
