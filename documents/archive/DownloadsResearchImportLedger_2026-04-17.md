# Downloads Research Import Ledger

Status: historical import ledger
Date: 2026-04-17

## Purpose

This document records the useful research material that was living in
`/Users/iwan/Downloads` and where that knowledge now lives inside the Rustynet
repository.

This keeps the project from depending on ad hoc local bundle folders for
important implementation context.

## Rules

- Active implementation guidance belongs in the active ledgers and plans.
- Historical reviews and superseded bundle conclusions belong in the archive.
- Downloads-side bundle language does not override current repo truth.

## Import Outcomes

| Downloads source | Subject | Repo disposition | Repo location(s) | Notes |
| --- | --- | --- | --- | --- |
| `rustynet_windows_runtime_bundle_final` | early Windows runtime bundle | imported selectively | `documents/operations/active/WindowsWorkingNodePlan_2026-04-17.md` | useful milestone vocabulary and fail-closed “definition of done” language preserved; outdated “host path missing” baseline not treated as current truth |
| `rustynet_windows_working_bundle_revalidated` | current Windows working-node bundle | imported selectively | `documents/operations/active/WindowsWorkingNodePlan_2026-04-17.md` | useful current truth, Windows 11 compatibility notes, Windows 11 test matrix, and “working node” definition carried forward |
| `Rustynet_windows_gap_closure_review_bundle_v3` | Windows gap-closure review | historical / already reflected | current code plus `documents/operations/active/WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md` | bootstrap/orchestration findings largely already landed in repo code and current Windows access plan |
| `Rustynet_windows_bootstrap_spec_bundle_v2` | Windows bootstrap spec | historical / already reflected | current Windows helper/provider code and support docs | bootstrap/provider direction was useful historically, but current repo now has stronger, newer truth |
| `Rustynet_windows_utm_orchestrator_bundle_v1` | Windows UTM orchestration extension | historical / already reflected | `documents/operations/active/WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md` and current `vm_lab` code | useful for the access/orchestration project; now superseded by repo-native plan and implementation |
| `bundle_v3` and `rustynet_livelab_reviewed_bundle_v3.zip` | live-lab workflow audit | historical / already reflected | current live-lab docs, active ledgers, and `vm_lab` code | useful conclusions around readiness ladders, report contracts, and setup/run boundaries were cross-checked against current repo state |
| `Rustynet_live_lab_audit_pack.zip` and `Rustynet_live_lab_audit_pack_v2.zip` | live-lab security audit | historical / already reflected | active release/evidence ledgers and live-lab docs | useful route-truth, provenance, and release-gate integrity concerns are already tracked in repo-native ledgers |
| `Rustynet_bundle_review_v4.zip` | release-path review | historical / already reflected | active release-readiness docs and current code | useful warning about gate integrity preserved as historical context; current repo truth must still be checked directly |
| `RustynetMobileArchitectureDesign_2026-04-17.md` | mobile architecture | imported | `documents/mobile/RustynetMobileArchitectureDesign_2026-04-17.md` | useful future architecture material preserved as repo docs |
| `RustynetMobileRoadmap_2026-04-17.md` | mobile roadmap | imported | `documents/mobile/RustynetMobileRoadmap_2026-04-17.md` | useful future roadmap material preserved as repo docs |
| `rustynet_mobile_docs_bundle_2026-04-17.zip` | complete mobile docs bundle | imported intact | `documents/mobile/imported/rustynet_mobile_docs_bundle_2026-04-17/` | preserved as-is for future reference, including scaffold/security/FFI/lifecycle/platform file specs |
| `rustyfin_dictionary_hardening_pack.zip` | Rustyfin app hardening | not imported into Rustynet docs | n/a | out of scope for the Rustynet repository itself; not a Rustynet implementation document |

## Carry-Forward Notes By Topic

### Windows Working-Node Research

The most useful durable conclusions from the Windows bundle family were:

- separate `runtime-host-capable` from `dataplane-capable`
- keep `windows-unsupported` explicit until a real backend exists
- treat Windows service-host smoke proof separately from node-connectivity proof
- use a Windows 11 validation matrix with architecture and artifact-signature
  capture

Those now live in:

- `documents/operations/active/WindowsWorkingNodePlan_2026-04-17.md`
- `documents/operations/PlatformSupportMatrix.md`

### Windows UTM / Access Orchestration Research

The useful orchestration conclusions were:

- access bootstrap must be verification-based
- Windows local UTM result retrieval/callback truth must be explicit
- readiness must be more precise than a single SSH-ready boolean
- diagnostics must remain available on failure

Those now live in:

- `documents/operations/active/WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md`
- current `crates/rustynet-cli/src/vm_lab/` implementation

### Live-Lab Audit Research

The useful live-lab audit conclusions were:

- measured route truth matters more than label truth
- release-gate code must match the repo’s documented gate claims
- readiness and report contracts should be explicit and fail-closed
- SSH trust, provenance, and credential-only secret handling must not be
  weakened

Those conclusions are already represented in current repo-native docs and code,
including:

- active release-readiness and evidence ledgers
- current live-lab runbooks
- current `vm_lab` readiness/reporting code

### Mobile Research

The mobile architecture and roadmap were useful future-looking materials but
did not belong in Downloads.

They now live in:

- `documents/mobile/README.md`
- `documents/mobile/RustynetMobileArchitectureDesign_2026-04-17.md`
- `documents/mobile/RustynetMobileRoadmap_2026-04-17.md`
- `documents/mobile/imported/rustynet_mobile_docs_bundle_2026-04-17/`

## What This Ledger Does Not Mean

This ledger does not mean every Downloads-side snippet or prompt was imported
verbatim. In most cases, the useful value was:

- current truth correction
- phased implementation ordering
- test/evidence checklists
- risk framing

That material was preserved in repo-native form instead of copying every bundle
artifact wholesale.
