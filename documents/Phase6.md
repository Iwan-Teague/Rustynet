# Rustynet Phase 6 Plan (Admin UX and Cross-Platform Expansion)

## 0) Document Relationship and Scope
- This plan extends hardening outputs from [Phase5.md](./Phase5.md).
- Requirement ownership remains in [Requirements.md](./Requirements.md).
- Phase 6 outputs are prerequisites for [Phase7.md](./Phase7.md).
- If this plan conflicts with [Requirements.md](./Requirements.md), requirements take precedence.

## 1) Phase 6 Objective
Expand product usability through a web admin experience and broaden client support beyond Linux.

## 2) Phase 6 Scope
1. Web admin UI v1:
- Node inventory and state visibility.
- Policy management workflows.
- Exit-node and route control workflows.
- Throwaway credential lifecycle management.

2. Multi-user workflows:
- User and group administration.
- Access review and ownership boundaries.
- Baseline role-based access control (RBAC) for all admin actions.
- Baseline MFA enforcement for privileged admin operations.
- Safe-by-default policy bootstrap to avoid implicit allow-all behavior.

3. Platform expansion:
- macOS client beta quality.
- Windows client beta quality.
- Platform-specific route/firewall/DNS integration hardening.
- Cross-platform leak-class mitigation parity with Linux baseline.
- Privileged helper hardening: argv-only command invocation, strict input validation, and least-privilege execution model.

4. Packaging and updates:
- Installer strategy and versioning basics.
- Upgrade safety checks.
- Signed artifacts and SBOM are mandatory for beta distribution.

## 3) Deliverables
- Operational web admin UI for core controls.
- Multi-user management workflows functioning.
- macOS and Windows beta clients validated for core use cases.
- Packaging and update flow documentation.
- Policy bootstrap guardrails and unsafe-policy warnings in UI/API flows.

## 4) Security Gates
- Admin operations require authenticated, authorized access.
- Privileged UI actions generate auditable events.
- Platform clients meet same crypto and policy enforcement requirements as Linux.
- RBAC is enforced for admin routes and APIs with deny-by-default behavior.
- MFA is required for privileged mutations (policy, credential, and exit-node administration).
- Admin UI and APIs enforce CSRF protections, secure session/cookie policy, and anti-clickjacking controls.
- Default policy posture cannot silently become allow-all in new deployments.
- macOS/Windows pass leak-class tests required by Phase 4 mitigation matrix.
- Privileged helper paths prove no shell-command construction with untrusted values.

## 5) Phase 6 Exit Criteria
- Admins can manage nodes, policies, and credentials via UI.
- macOS and Windows clients complete enrollment and core mesh connectivity reliably.
- Cross-platform policy and exit-node behavior are consistent with Linux baseline.
- RBAC/MFA and web-surface protections pass security tests.

## 6) Handoff to Phase 7
- Phase 7 scales infrastructure and commercial controls after cross-platform and admin UX stabilization.
- Use [Phase7.md](./Phase7.md) as the next execution plan once Phase 6 exit criteria are met.
