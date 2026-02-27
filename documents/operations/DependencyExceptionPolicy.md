# Dependency Exception Governance

## Purpose
Define controlled exceptions for dependency-policy checks while preserving security ownership and expiry discipline.

## Workflow
1. Add exception entries to `documents/operations/dependency_exceptions.json`.
2. Required fields: `id`, `crate`, `reason`, `owner`, `approved_by`, `expires_utc`.
3. Exceptions must be time-bounded and tied to an accountable owner.
4. CI verifies exceptions are structurally valid and not expired.

## Enforcement
- `scripts/ci/check_dependency_exceptions.sh` is mandatory in release gates.
- Expired or malformed exceptions fail CI.
- Security and engineering owners must approve any new exception.
