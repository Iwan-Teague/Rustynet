# Architecture Decision Records

This directory captures point-in-time design decisions whose rationale
would otherwise live only in commit messages or backlog entries.

ADRs here are immutable once accepted: if a later decision supersedes
one, add a new ADR with `Status: Accepted` that references the old one
as `Supersedes ADR-NNN`, and update the old ADR's `Status:` to
`Superseded by ADR-MMM`. Do not edit accepted decisions in place.

## Format

Each ADR follows the standard skeleton:

```markdown
# ADR-NNN: <title>

- Status: Accepted | Superseded by ADR-MMM
- Date: YYYY-MM-DD

## Context
## Decision
## Consequences
## Implementation
## Related
```

## Index

| ADR | Title                                                       | Status   | Date       |
|-----|-------------------------------------------------------------|----------|------------|
| 001 | [Static no-secret-leakage source-walk audit](./ADR-001-secret-log-audit.md) | Accepted | 2026-05-17 |
| 002 | [Per-module regression-coverage floor gate](./ADR-002-regression-coverage-floor-gate.md) | Accepted | 2026-05-17 |
| 003 | [Shared CLI exit-code taxonomy](./ADR-003-cli-exit-code-taxonomy.md) | Accepted | 2026-05-17 |
| 004 | [Dual-plane live-lab VM network architecture](./ADR-004-dual-plane-live-lab-network.md) | Accepted | 2026-07-10 |

## Related Reference Material

- [`SecurityPostureSummary.md`](../SecurityPostureSummary.md) — reviewer-facing snapshot of every fail-closed verifier, audit gate, and security-tied invariant.
- [`CliExitCodeTaxonomy.md`](../CliExitCodeTaxonomy.md) — operator runbook for the exit-code contract established by ADR-003.
