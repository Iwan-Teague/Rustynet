# VM Lab Capability Reporting Plan

**Status:** Active planning document

## Purpose

This document captures the next documentation and implementation slice for the
top-level Rustynet live-lab wrappers: make them report capability truth
explicitly instead of collapsing every unsupported combination into one coarse
Linux-only rejection.

Source-backed platform facts for the OS and shell layers that underpin this
planning work are collected in [VmLabCapabilitySources_2026-04-14.md](./VmLabCapabilitySources_2026-04-14.md).

Reusable implementation scaffolding, phased implementation notes, and code
snippets are collected in [VmLabCapabilityCookbook_2026-04-14.md](./VmLabCapabilityCookbook_2026-04-14.md).

The goal is not to broaden support yet. The goal is to make the wrapper tell
the truth, early and machine-readably, while keeping the current fail-closed
security posture intact.

## Current Problem Statement

The wrapper boundary already knows more than it currently reports:

- some helper paths are platform-aware
- some bootstrap and diagnostics paths are partially implemented
- top-level live-lab wrappers still present that as a coarse Linux-only guard

That makes the operator story less precise than the actual implementation
truth. It also makes future mixed-platform work harder because there is no
first-class capability vocabulary to attach to a command, stage, source mode,
or target platform mix.

## Goals

The planned capability layer should answer, for a given command or stage:

- supported
- partially supported
- unsupported
- why

The evaluation should be pure classification logic. It should not run any
setup, bootstrap, restart, or diagnostics work.

## Non-Goals

- Do not broaden execution support yet
- Do not remove Linux-only execution guards
- Do not invent fallback runtime paths
- Do not weaken fail-closed behavior
- Do not infer support from helper presence alone

## Proposed Capability Model

Planned record shape:

- `scope`
- `stage_or_phase`
- `target_role`
- `platform`
- `source_mode`
- `status`
- `reason_code`
- `message`
- `implementation_owner`
- `blocking_requirements`

Planned status taxonomy:

- `Supported`
- `PartiallySupported`
- `Unsupported`

Recommended reason-code families:

- `linux-shell-orchestrator-only`
- `target-platform-unsupported`
- `partially-implemented-subcapability`
- `source-mode-incompatible`
- `topology-mismatch`
- `stage-blocked-by-missing-helper`
- `no-execution-path-available`
- `capability-unknown`

## Evaluation Inputs

The evaluator should inspect:

- selected command
- selected stage or phase
- source mode
- target platform metadata
- topology mix
- whether the path is Linux shell orchestrator based or target-aware Rust based

The evaluator should not mutate state. It should only classify truth and emit a
record that the wrapper can surface directly.

## Initial Wrapper Truth To Encode

These are the current planning expectations to represent in the capability
model, without changing enforcement. They describe Rustynet wrapper-support
truth, not general OS capability claims; use the source-backed notes document
for the underlying platform facts.

- `vm-lab-setup-live-lab`
  - Linux targets: supported through the current shell orchestrator path
  - Windows targets: unsupported at the top-level setup wrapper because the
    active setup graph is still Linux-shell based
  - iOS/Android: unsupported / scaffold-only
- `vm-lab-run-live-lab`
  - Linux targets: supported through the current shell orchestrator path
  - mixed Linux/non-Linux inventories: unsupported when the selected topology
    cannot satisfy the Linux shell path
- `vm-lab-orchestrate-live-lab`
  - composite capability derived from discovery, restart, setup, run, and
    diagnose
  - overall support is limited by the weakest required subcommand
- `vm-lab-bootstrap-phase`
  - Linux: current phases supported
  - Windows `sync-source` and `build-release`: supported through the current
    PowerShell helper path, subject to source-mode and toolchain preconditions
  - Windows `install-release`: protective stub only, not runtime-capable proof
  - Windows `restart-runtime`, `verify-runtime`, and `all`: unsupported as
    current runtime-capable proof until a real Windows service/config host
    exists in `rustynetd`
- `vm-lab-diagnose-live-lab-failure`
  - should report platform-aware support truth for diagnostics collection
  - helper-based collection should be explicit about what is available today

## Artifact Contract

The planned machine-readable artifact is:

- `state/platform_capabilities.json`

The artifact should live in the report directory and be written by the
preflight/capability-evaluation path. It should be usable without executing the
full live-lab workflow.

Optional follow-up CLI:

- `ops vm-lab-report-capabilities`

That command would be a read-only inspection surface for operators who need to
understand mixed-platform truth before they start the live-lab workflow.

## Rollout Slices

The step-by-step phase contract lives in the cookbook. This plan keeps the
high-level scope and the implementation slices aligned with that stricter
matrix.

### Slice 1

Add a pure evaluator and unit tests.

- no execution-path changes yet
- no support broadening yet
- capability output stays internal until the model is stable

### Slice 2

Use the evaluator in the top-level wrappers.

- keep fail-closed behavior
- replace coarse error text with capability-derived messages
- preserve current Linux-only execution boundaries

### Slice 3

Emit the machine-readable artifact.

- write `state/platform_capabilities.json`
- keep the existing report contract stable
- make the artifact suitable for offline inspection

### Slice 4

Add the optional inspection CLI.

- expose the same capability truth without running setup
- keep it read-only
- keep it strict and deterministic

## Tests And Evidence

The first implementation pass should add coverage for:

- Linux setup profile => supported
- Windows setup profile => unsupported with Linux-shell reason
- mixed Linux/Windows profile => top-level setup unsupported
- Windows bootstrap sync-source/build-release => explicit platform-aware truth
- Windows bootstrap install-release => protective blocked runtime-host reason
- Windows diagnostics => explicit platform-aware truth
- iOS/Android => unsupported for the current wrapper surface

## Cross-References

- Live-lab runbook: [../LiveLinuxLabOrchestrator.md](../LiveLinuxLabOrchestrator.md)
- Script function map: [../../../scripts/e2e/README.md](../../../scripts/e2e/README.md)
- Current platform truth: [../PlatformSupportMatrix.md](../PlatformSupportMatrix.md)
- Source-backed platform notes: [VmLabCapabilitySources_2026-04-14.md](./VmLabCapabilitySources_2026-04-14.md)

## Notes

- Keep this plan aligned with the live-lab runbook and the script-local function
  map.
- Do not reclassify unsupported paths as supported until the corresponding code
  path exists and is tested.
- The reporting gap is the current target, not expanded execution support.
