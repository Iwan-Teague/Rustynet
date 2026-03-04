# Rustynet

## Quick Start Wizard

Run the interactive setup/menu wizard:

```bash
./start.sh
```

The wizard handles:
- role selection (`admin` or `client`) during setup, with role-specific console permissions
- host OS detection on startup with strict host-profile enforcement (`linux` dataplane vs `macos` compatibility)
- first-run bootstrap (dependencies, keys, trust material, systemd wiring)
- optional signer-backed trust-evidence auto-refresh timer on Linux to keep trust freshness valid during unattended runtime
- daemon/service lifecycle
- centrally signed auto-tunnel defaults with fail-closed enforcement
- break-glass manual peer connection helpers (explicit acknowledgement + audit logging)
- encrypted key custody at rest + runtime key management
- local key rotation/revocation and peer rotation-bundle apply flow
- exit-node and LAN-access toggles
- route advertisement and status checks

Host-profile behavior:
- Linux host: full runtime/dataplane provisioning.
- macOS host: compatibility mode only (build/validation workflows); Linux dataplane actions are blocked.
- macOS path policy: Linux runtime roots (`/etc/rustynet`, `/var/lib/rustynet`, `/run/rustynet`, `/var/log/rustynet`) are not used; user-space paths are enforced instead.

After first setup, run `./start.sh` again anytime to open the terminal control menu.

Role model:
- `admin`: full operational console (policy/trust/key/exit-node administration, with break-glass controls).
- `client`: limited console for joining/using the network (status, connect/disconnect from exit nodes, LAN toggle), with admin-only actions blocked at daemon runtime.

Linux trust-refresh behavior:
- When admin setup has signer-key access (`AUTO_REFRESH_TRUST=1`), install flow enables `rustynetd-trust-refresh.timer` and performs periodic signed trust evidence refreshes.
- Trust refresh jobs write trust evidence as `root:<daemon-group>` with `0640` mode so `rustynetd` can validate trust state without exposing signer key material.

## Release Readiness Evidence (Fail-Closed)

Rustynet no longer accepts static/pass-through readiness JSON artifacts.

Before Phase 6/9 gates can pass, generate measured evidence artifacts from real inputs:

```bash
# Phase 6 probe collection + parity evidence
./scripts/release/collect_platform_parity_bundle.sh

# Phase 6 platform parity evidence
RUSTYNET_PHASE6_PARITY_ENVIRONMENT=lab \
./scripts/release/generate_platform_parity_report.sh

# Phase 9 raw evidence collection from logs/probes
./scripts/operations/collect_phase9_raw_evidence.sh

# Phase 9 operational evidence
RUSTYNET_PHASE9_EVIDENCE_ENVIRONMENT=prod-lab \
./scripts/operations/generate_phase9_artifacts.sh
```

Raw measured inputs must exist first:
- `artifacts/release/raw/platform_parity_linux.json`
- `artifacts/release/raw/platform_parity_macos.json`
- `artifacts/release/raw/platform_parity_windows.json`
- `artifacts/operations/source/*.ndjson|*.json` phase9 source logs/config:
  - `compatibility_policy.json`
  - `crypto_deprecation_schedule.json`
  - `slo_windows.ndjson`
  - `performance_samples.ndjson`
  - `incident_drills.ndjson`
  - `dr_drills.ndjson`
  - `backend_security_review.json`

Then run gates:

```bash
./scripts/ci/phase6_gates.sh
./scripts/ci/phase9_gates.sh
./scripts/ci/phase10_gates.sh
./scripts/ci/membership_gates.sh
```

## Phase 1 Measured Baseline Inputs

Phase 1 baseline gates require measured runtime inputs (`RUSTYNET_PHASE1_*` vars).  
Generate them from measured evidence sources (fail-closed, no synthetic fallback):

```bash
./scripts/perf/collect_phase1_measured_env.sh
./scripts/perf/run_phase1_baseline.sh
```

`run_phase1_baseline.sh` will auto-run the collector when env vars are missing.
If present, the collector can use `artifacts/operations/performance_budget_report.json`
as measured Phase1 input source.
