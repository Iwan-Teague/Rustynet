# Rustynet Phase 5 Plan (Observability and Reliability Hardening)

## 0) Document Relationship and Scope
- This plan extends networking feature outputs from [Phase4.md](./Phase4.md).
- Requirement ownership remains in [Requirements.md](./Requirements.md).
- Phase 5 outputs are prerequisites for [Phase6.md](./Phase6.md).
- If this plan conflicts with [Requirements.md](./Requirements.md), requirements take precedence.

## 1) Phase 5 Objective
Harden runtime reliability and operational visibility so the platform can be operated safely at small production scale.

## 2) Phase 5 Scope
1. Observability foundation:
- Structured logs with redaction rules.
- Metrics for control, relay, and client health.
- Health endpoints and status views.
- Tamper-evident, append-only audit log pipeline with integrity verification.

2. Diagnostics tooling:
- `netcheck`/connectivity diagnostics.
- Route and DNS diagnostics.
- Exit-node path visibility (direct vs relay).

3. Reliability hardening:
- Better reconnect and retry behaviors.
- Session persistence behavior across control-plane restarts.
- Backup/restore procedure for control-plane state.

4. Relay hardening:
- Stability improvements for fallback transport.
- Relay health checks and failover behavior.

5. Early release integrity baseline:
- SBOM generation for build artifacts.
- Artifact signing and provenance capture in CI for internal and beta releases.

6. Performance regression guardrails:
- Automated benchmark runs in CI for CPU, memory, reconnect, and route-apply latency.
- Regression thresholds and alerting for performance drift.

7. Vulnerability response operations:
- Define security advisory intake, triage, and disclosure workflow.
- Define patch SLAs by severity and emergency patch release process.
- Define staged release tracks (unstable/canary/stable) for security-sensitive changes.
- Minimum patch SLAs:
- Critical: mitigation or patched build within 48 hours.
- High: patched build within 7 calendar days.
- Medium: patched build within 30 calendar days.

8. Policy safety validation:
- Require policy/ACL validation tests in CI before merge and before rollout.
- Require staged policy rollout with rollback path.

9. Secret redaction assurance:
- Validate secret redaction coverage across MDM, env vars, CLI args, API payloads, and UI-form inputs.
- Add negative tests to ensure no credential/token leakage in normal and error logging paths.

## 3) Deliverables
- Metrics and logs available for all critical components.
- Diagnostics commands usable by operators.
- Reliability tests for reconnect/restart/fallback scenarios.
- Initial runbook set for common operational incidents.
- Tamper-evident audit storage and integrity-check tooling.
- Signed beta artifacts plus SBOM outputs.
- Performance regression dashboard and alerts.
- Security advisory and emergency patch runbooks.
- Policy validation and rollout guardrail tooling.
- Secret-redaction coverage report across all ingestion paths.

## 4) Security Gates
- Logging pipeline verified to avoid credential/token leakage.
- Audit events preserved for operationally sensitive actions.
- Restore procedure validated with integrity checks.
- Audit log integrity checks are automated and detect tampering.
- Build/release pipeline produces signed artifacts and SBOM before distribution.
- Vulnerability response SLAs and emergency patch path are test-exercised.
- Policy changes cannot bypass CI validation and staged rollout controls.
- Critical/high/medium patch SLA compliance is measurable and reported.
- Secret-redaction tests for all ingestion paths are green before release.

## 5) Phase 5 Exit Criteria
- Operators can diagnose major mesh/exit/DNS failures from tooling.
- Recovery from control-plane restart is reliable and tested.
- Relay fallback and recovery are validated under fault scenarios.
- Backup and restore workflow is documented and tested.
- Audit forensics pipeline is operational and tamper-evident.
- Performance regressions are gated by defined thresholds.
- Security operations can produce SLA compliance evidence for advisories and fixes.

## 6) Handoff to Phase 6
- Phase 6 expands user/admin surface and platform support using hardened operational foundations.
- Use [Phase6.md](./Phase6.md) as the next execution plan once Phase 5 exit criteria are met.
