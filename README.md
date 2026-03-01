# Rustynet

## Quick Start Wizard

Run the interactive setup/menu wizard:

```bash
./start.sh
```

The wizard handles:
- first-run bootstrap (dependencies, keys, trust material, systemd wiring)
- daemon/service lifecycle
- centrally signed auto-tunnel defaults with fail-closed enforcement
- break-glass manual peer connection helpers (explicit acknowledgement + audit logging)
- encrypted key custody at rest + runtime key management
- local key rotation/revocation and peer rotation-bundle apply flow
- exit-node and LAN-access toggles
- route advertisement and status checks

After first setup, run `./start.sh` again anytime to open the terminal control menu.

## Release Readiness Evidence (Fail-Closed)

Rustynet no longer accepts static/pass-through readiness JSON artifacts.

Before Phase 6/9 gates can pass, generate measured evidence artifacts from real inputs:

```bash
# Phase 6 platform parity evidence
RUSTYNET_PHASE6_PARITY_ENVIRONMENT=lab \
./scripts/release/generate_platform_parity_report.sh

# Phase 9 operational evidence
RUSTYNET_PHASE9_EVIDENCE_ENVIRONMENT=prod-lab \
./scripts/operations/generate_phase9_artifacts.sh
```

Raw measured inputs must exist first:
- `artifacts/release/raw/platform_parity_linux.json`
- `artifacts/release/raw/platform_parity_macos.json`
- `artifacts/release/raw/platform_parity_windows.json`
- `artifacts/operations/raw/*.json` for all phase9 reports

Then run gates:

```bash
./scripts/ci/phase6_gates.sh
./scripts/ci/phase9_gates.sh
./scripts/ci/phase10_gates.sh
./scripts/ci/membership_gates.sh
```
