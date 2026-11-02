# Security Assurance Program

## External Validation Cadence
- Independent penetration test: twice per year.
- Architecture/security audit: annually.
- Focused reassessment required after major control-plane/auth changes.

## Triage Workflow
1. Intake report and assign severity.
2. Reproduce and scope impact.
3. Track remediation owner and SLA target.
4. Validate fix with regression/security tests.
5. Publish internal advisory and external disclosure as required.

## Disclosure Channels
- Private security contact for coordinated disclosure (published in the repository-root `SECURITY.md`: GitHub private vulnerability reporting).
- Internal escalation channel for active incidents.
- Optional bug-bounty intake path with response SLO.

## Bug-Bounty Response Targets
- Initial acknowledgment within 3 business days (bug-bounty intake only; the root `SECURITY.md` publishes a stricter 48-hour acknowledgement target for private vulnerability reports, which governs reports sent through that channel).
- Triage decision within 7 business days.
- Severity/SLA alignment with `VulnerabilityResponse.md`.
