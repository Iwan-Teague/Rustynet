# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately via GitHub's **"Report a vulnerability"** (repository → Security → Advisories → Report a vulnerability). If private reporting is unavailable, contact the maintainer through the address on their GitHub profile and mark the subject `[rustynet-security]`.

Please include: affected component/crate, version or commit, a description, and a reproduction or proof-of-concept if you have one.

## Response SLA

Measured from advisory publication (for dependency issues) or from a valid report being received:

| Severity | Meaning | Patch SLA |
|---|---|---|
| **Critical** | Blocks release | **48 hours** |
| **High** | Ships only with a dated, owner-signed risk acceptance | **7 days** |
| **Medium** | Needs a tracked remediation plan | **30 days** |

We aim to acknowledge a report within 48 hours.

## Detection

- **Dependabot security updates** (see `.github/dependabot.yml`) for vulnerable dependencies.
- A scheduled **`cargo audit`** run and **`cargo deny`** (advisories/bans/licenses/sources) in CI.
- Vulnerable/yanked/unmaintained crates are denied by default (`deny.toml`, advisories v2).

## Scope

This policy covers the `rustynet` workspace crates in this repository. Findings in third-party dependencies are handled via the dependency-update path above.

## Disclosure

We practice coordinated disclosure: we will work with you on a fix and a disclosure timeline, and credit you unless you prefer otherwise.

<!--
Owner action required to fully activate this policy (repository settings — cannot be set from code):
  Settings → Security → enable "Private vulnerability reporting".
Suite alignment: SLA matches the charter T2 §F6 (Critical 48h / High 7d / Medium 30d). Do not diverge without a §K exemption.
-->
