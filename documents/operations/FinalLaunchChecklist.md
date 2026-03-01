# Final Launch Checklist

## Security and Compliance
- [ ] Security Minimum Bar critical controls verified.
- [ ] Supply-chain integrity verified (signed artifacts + SBOM + provenance).
- [ ] Dependency governance checks passed.
- [ ] Audit integrity and retention controls verified.

## Reliability and Operations
- [ ] SLO and error-budget gates passed.
- [ ] Performance budgets and soak-duration gate passed.
- [ ] Incident drill and postmortem standards validated.
- [ ] Multi-region DR/failover drill meets RPO/RTO targets.
- [ ] All phase9 artifacts generated from measured raw evidence and include measured-evidence metadata.

## Protocol and Backend Agility
- [ ] WireGuard remains adapter-only backend boundary.
- [ ] Additional non-simulated backend path validated with measured evidence.
- [ ] Backend conformance and leakage checks passed with non-simulated backend evidence.
- [ ] Compatibility/support policy published and enforced.

## Crypto and Lifecycle
- [ ] Crypto deprecation schedule published.
- [ ] Insecure compatibility exceptions disabled by default with auto-expiry policy.
- [ ] Post-quantum hybrid transition plan published.

## Final Sign-Off Record
| Role | Approver | Date (UTC) | Status |
|---|---|---|---|
| Engineering Owner | Iwan Teague | 2026-03-01 | Pending |
| Security Owner | Iwan Teague | 2026-03-01 | Pending |
| Operations Owner | Iwan Teague | 2026-03-01 | Pending |

## Gate Commands
- `scripts/ci/phase9_gates.sh`
