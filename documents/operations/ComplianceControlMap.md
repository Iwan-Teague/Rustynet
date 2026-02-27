# Compliance Control Evidence Map

| Control Domain | Rustynet Control | Evidence Source |
|---|---|---|
| Access Control | RBAC + MFA + tenant boundary guard | `crates/rustynet-control/src/admin.rs`, `crates/rustynet-control/src/scale.rs`, test suite |
| Cryptography | Algorithm allowlist/denylist, key custody fallback, trust-state integrity | `crates/rustynet-crypto/src/lib.rs`, `crates/rustynet-control/src/lib.rs` |
| Logging and Monitoring | Redaction-safe structured logs, diagnostics summaries | `crates/rustynet-control/src/operations.rs` |
| Change Management | Policy rollout staging/canary/rollback controller | `crates/rustynet-policy/src/lib.rs` |
| Incident Response | Vulnerability intake and SLA workflow | `documents/operations/VulnerabilityResponse.md`, `artifacts/security/patch_sla_tracker.json` |
| Supply Chain | SBOM, provenance generation, attestation verification | `scripts/release/*`, `scripts/ci/verify_release_attestation.sh` |
| Privacy | Data minimization and retention windows | `documents/operations/PrivacyRetentionPolicy.md` |
