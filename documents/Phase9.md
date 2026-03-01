# Rustynet Phase 9 Plan (Completion Readiness and Long-Term Operations)

## 0) Document Relationship and Scope
- This plan extends assurance/compliance outputs from [Phase8.md](./Phase8.md).
- Requirement ownership remains in [Requirements.md](./Requirements.md).
- Phase 9 is the completion-readiness phase for broad commercial operation.
- If this plan conflicts with [Requirements.md](./Requirements.md), requirements take precedence.

## 1) Phase 9 Objective
Finalize GA-grade operational maturity, compatibility guarantees, and long-term protocol agility readiness.

## 2) Phase 9 Scope
1. Compatibility and lifecycle policy:
- Versioned API and client compatibility guarantees.
- Upgrade/migration policy for control plane and clients.
- Deprecation process with support windows.
- Cryptographic deprecation policy and removal cadence for legacy algorithms/options.
- Insecure compatibility modes default to disabled and require explicit, time-bounded, auto-expiring exception policy.

2. Operational excellence:
- SLOs/error budgets as release gates.
- Incident response drills and postmortem standards.
- Full production runbook and on-call readiness.
- Performance budget compliance (CPU, memory, reconnect, route-apply latency, throughput overhead) as release gate.
- Release benchmark matrix and minimum 24-hour soak-test criteria enforced before GA promotions.

3. Resilience completion:
- Multi-region failover drills against declared RPO/RTO targets.
- Disaster recovery validation with restore confidence metrics.

4. Protocol agility validation:
- Keep WireGuard as default backend.
- Add at least one additional non-simulated backend path through same interface.
- Require backend conformance suite pass and security review before support claims.
- Produce post-quantum transition plan with hybrid migration experiment and decision gates.

## 3) Deliverables
- Published compatibility and support policy.
- Production SLOs, alerting, and incident playbooks.
- Multi-region DR/failover validation reports.
- Backend agility validation report showing architecture remains swappable.
- Published crypto deprecation and migration schedule.
- Published post-quantum migration readiness and hybrid-evaluation report.
- Measured evidence generation workflow documented in `documents/operations/MeasuredEvidenceGeneration.md`.

## 4) Security Gates
- No release without passing SLO, incident, and DR readiness gates.
- Protocol modularity boundary remains enforced by tests and architecture checks.
- Final launch checklist includes security, compliance, and operational sign-offs.

## 5) Phase 9 Exit Criteria
- GA readiness approved across engineering, security, and operations.
- Reliability targets are consistently met.
- Compatibility policy is active and enforced in release process.
- Backend modularity remains proven and unbroken.
- Performance budgets are met in sustained benchmark and soak-test runs.

## 6) Post-Phase Continuity
- Continue incremental roadmap planning after GA using the same governance model.
- Update [Requirements.md](./Requirements.md) for any new strategic initiatives.
