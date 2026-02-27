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

5. Policy and privilege enforcement:
- Default-deny ACL behavior across mesh, routes, and exit-node access.
- RBAC enforced on admin API/UI paths.
- MFA required for privileged mutations.

6. Web/admin security:
- CSRF protections for state-changing UI/API flows.
- Secure cookie/session policy.
- Clickjacking defenses.
- Privileged helper/system integration paths use argv-only command invocation with strict input validation.

7. Data-plane leak prevention:
- Tunnel fail-close behavior in protected-routing modes.
- DNS fail-close behavior in protected DNS modes.
- Protocol-filter ACL behavior is validated in shared subnet-router and shared-exit scenarios.

8. Audit and forensics:
- Tamper-evident, append-only audit logging.
- Retention policy and integrity-verification process active.

9. Supply-chain integrity:
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
- Shared-router/shared-exit protocol-filter ACL tests.
- Audit-log integrity verification tests.
- Performance benchmark report with regression thresholds.
- Concurrent one-time-key consume race tests.
- Privileged-helper command-input safety tests.
- Patch-SLA and emergency-release drill evidence.

## 7) Phase Mapping
- Phase 1: baseline standards and threat model defined.
- Phase 2: auth/enrollment abuse controls + key custody baseline + atomic one-time key handling.
- Phase 3: encrypted Linux mesh + conformance + initial perf baselines.
- Phase 4: exit/LAN/DNS with fail-close leak prevention.
- Phase 5: tamper-evident audit + early signing/SBOM + perf regression + SLA operations.
- Phase 6: admin UI with RBAC/MFA + CSRF/session/clickjacking + privileged helper hardening.
- Phase 7: HA, tenant boundary hardening, and trust-state fail-closed enforcement.
- Phase 8: external audit cadence + advanced compliance/key custody.
- Phase 9: GA readiness with SLO/DR/performance gates fully enforced.

## 8) Sign-off Checklist
- [ ] Security owner approval
- [ ] Engineering owner approval
- [ ] Operations owner approval
- [ ] Release artifact signing and SBOM verification complete
- [ ] Critical controls all green
