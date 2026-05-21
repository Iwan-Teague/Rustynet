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
- TLS 1.3 enforced for control-plane APIs.
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
   (`127.0.0.1:51822`). LAN-IP bind requires an explicit
   `--anchor-bundle-pull-lan-bind` flag and documented operator
   acknowledgement. Non-loopback packets MUST be dropped when the
   endpoint is loopback-only.

3. **Token-gated bundle-pull + enrollment redemption.** Anchor
   bundle-pull and anchor-hosted enrollment redemption MUST share a
   single-use enrollment-token ledger so a token cannot be consumed
   for both. Replay of a consumed token MUST be rejected fail-closed.

4. **Anchor secret custody.** The anchor enrollment-endpoint HMAC
   secret MUST be stored in OS-secure custody:
   - Linux: systemd `LoadCredentialEncrypted` credential
     (`anchor_enrollment_secret.cred`); plaintext custody rejected.
   - macOS: Keychain item `rustynet.anchor_enrollment_secret`;
     plaintext custody rejected.
   - Windows: DPAPI-protected `anchor_enrollment_secret.dpapi` blob
     under `C:\ProgramData\RustyNet\secrets\`; ACL must be
     SYSTEM/Administrators-only and validated by the W4 verifier.

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
`scripts/ci/role_taxonomy_gates.sh`,
`scripts/ci/role_transition_audit_gates.sh`, and
`scripts/ci/blind_exit_irreversibility_gates.sh` (new gates added
in D12).

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
