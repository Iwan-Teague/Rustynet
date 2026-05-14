# VM Lab Capability Reporting Plan

**Status:** Active planning document. Slices 1, 3, and 4 complete; Slice 2 in
partial-rollout (RustOrchestrator reject site wired through the umbrella
validator). All 14 cookbook helpers (reusable building blocks + security-first
set) are landed and tested; see the Slice 2 entry for the full catalog.

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

**Status (2026-05-14): complete.** Implemented in
`crates/rustynet-cli/src/vm_lab/capability.rs` as a new internal submodule of
`vm_lab`. Carries the full taxonomy (`VmLabCapabilityStatus`,
`VmLabCapabilityScope`, `VmLabPlatform`, `VmLabSourceMode`,
`VmLabBootstrapPhase`, `VmLabCapabilityContext`, `VmLabCapabilityRecord`), a
stable `reason_code` namespace, the pure `evaluate_vm_lab_capability`
classifier, the `evaluate_vm_lab_capabilities_for_profile` profile helper, the
`command_scope` mapping, and `render_capability_summary` /
`render_capability_report` rendering helpers. 24 unit tests cover Linux/
Windows/macOS/iOS/Android setup/run/orchestrate/bootstrap/diagnostics paths,
mixed-platform topology rejection on Linux setup, Windows helper-backed
bootstrap phases as `Supported`, Windows runtime-host bootstrap phases as
`Unsupported` with `runtime-host-not-yet-implemented`, the
`BootstrapPhase`-scope-without-phase guard, command-name mapping, the
one-line rendering format, profile-evaluator determinism, idempotent repeat
invocations, and reason-code ASCII-kebab-case shape. The module is
`#![allow(dead_code)]` for the duration of Slice 1 because no wrapper calls
into it yet; Slice 2 wiring will drop that attribute.

### Slice 2

Use the evaluator in the top-level wrappers.

- keep fail-closed behavior
- replace coarse error text with capability-derived messages
- preserve current Linux-only execution boundaries

**Status (2026-05-14): partial.** The most prominent coarse-text reject in
the wrapper trait surface — `RustOrchestrator::execute_live_lab`'s
heterogeneous-topology rejection in
`crates/rustynet-cli/src/vm_lab/mod.rs` — is now derived from the Slice-1
capability evaluator and routed through the canonical umbrella validator
`validate_vm_lab_capability_preconditions`. The reject message keeps its
existing operator-facing "heterogeneous live-lab execution" / W4.1
references for continuity, and additionally embeds the canonical Slice-1
capability summary (e.g. `scope=RunLiveLab status=Unsupported
reason_code=topology-mismatch message=...` for mixed topologies, or
`reason_code=linux-shell-orchestrator-only` for pure-non-Linux topologies),
so downstream tooling can grep on the stable capability reason code
instead of the free-form prose. Enforcement is unchanged: the trait
boundary still fails closed for any non-Linux target. The profile-time
gate `ensure_live_lab_profile_capabilities` (W4.1 vocabulary) remains
untouched and continues to do the per-stage capability gating it already
does; folding that gate into the Slice-1 vocabulary is left for a later
pass.

Cookbook helpers landed as part of Slices 1-4 and Slice-2 follow-up
(`crates/rustynet-cli/src/vm_lab/capability.rs`):

Reusable building blocks:
- `evaluate_vm_lab_capability`
- `evaluate_vm_lab_capabilities_for_profile`
- `evaluate_composite_scope`
- `merge_vm_lab_capability_records` (weakest-link)
- `command_scope` (the cookbook's `select_vm_lab_capability_scope`)
- `collect_vm_lab_capability_inputs`
- `normalize_vm_lab_platform_mix` + `From<VmGuestPlatform>`
- `render_capability_summary` / `render_capability_report`
- `render_vm_lab_capability_error` (multi-line operator block)
- `render_vm_lab_capability_failure_block` (with command identity)
- `render_platform_capabilities_artifact_json` /
  `write_platform_capabilities_artifact`
- `VmLabCapabilityFailureContext`

Security-first helpers:
- `sanitize_vm_lab_capability_message`
- `validate_vm_lab_target_topology`
- `validate_vm_lab_report_dir_fresh`
- `validate_vm_lab_capability_preconditions` (umbrella validator,
  consumed by `RustOrchestrator::execute_live_lab`)

### Slice 3

Emit the machine-readable artifact.

- write `state/platform_capabilities.json`
- keep the existing report contract stable
- make the artifact suitable for offline inspection

**Status (2026-05-14): complete.** Implemented as an opt-in extension of the
Slice 4 read-only inspection CLI. When the operator passes
`--output-dir <path>` to `ops vm-lab-report-capabilities`, the handler
additionally writes
`<output_dir>/state/platform_capabilities.json` (relative path also exported
as the public constant `PLATFORM_CAPABILITIES_ARTIFACT_RELATIVE_PATH`)
containing the single evaluated record for the requested
`(scope, platform, source_mode, mixed_platform_topology, bootstrap_phase)`
tuple. JSON shape:

```text
{
  "schema_version": 1,
  "records": [
    {"scope": "...", "status": "...", "reason_code": "...", "message": "..."},
    ...
  ]
}
```

The artifact emitter is exposed as `render_platform_capabilities_artifact_json`
plus `write_platform_capabilities_artifact` and accepts a slice of records, so
it can be reused by Slice 2 wrapper integration when that lands. The fail-closed
contract is preserved: when the handler refuses the request (e.g. missing
`--bootstrap-phase` on a `--scope=bootstrap-phase` invocation), the artifact is
never written. Eight additional tests cover schema-version + records-array
shape, ordered serialization of multiple records, JSON escaping for `"` and
`\\` in message bodies, idempotent writes against the same input, artifact
emission when `--output-dir` is set, no artifact when `--output-dir` is
unset, and no artifact when the handler fails closed. CLI is smoke-tested:
`ops vm-lab-report-capabilities --scope setup-live-lab --platform linux
--source-mode local-head --output-dir <dir>` writes the expected JSON.

### Slice 4

Add the optional inspection CLI.

- expose the same capability truth without running setup
- keep it read-only
- keep it strict and deterministic

**Status (2026-05-14): complete.** Implemented in the existing
`crates/rustynet-cli/src/vm_lab/capability.rs` module with CLI parser and
dispatch wiring in `crates/rustynet-cli/src/main.rs`. The new command
`ops vm-lab-report-capabilities` accepts
`--scope`, `--platform`, `--source-mode`, optional `--bootstrap-phase`, and
optional `--mixed-platform-topology` flags, parses them through fail-closed
helpers (`parse_scope_arg`, `parse_platform_arg`, `parse_source_mode_arg`,
`parse_bootstrap_phase_arg`), feeds them through the Slice 1 evaluator
(`evaluate_vm_lab_capability`), and prints the stable one-line
`render_capability_summary` form. The handler is read-only: it never touches
filesystem, network, or process state; it fails closed when
`--scope=bootstrap-phase` is requested without `--bootstrap-phase`. Slice 4
ordering note: although the cookbook lists Phase 4 after Phase 3 artifact
emission, the inspection surface only depends on the Slice 1 evaluator and
can stand on its own; the `state/platform_capabilities.json` artifact
remains a separate Slice 3 deliverable. 15 unit tests cover label and
canonical-name scope parsing, lowercase-only platform parsing, kebab-case
source-mode and bootstrap-phase parsing, the read-only handler's stable
summary for Linux setup, Windows setup, Windows install-release bootstrap,
mixed-platform-topology rejection, the `bootstrap-phase` scope guard,
idempotent repeat invocation, and tolerance of a redundant
`bootstrap_phase` value on non-`BootstrapPhase` scopes. Parser dispatch is
exercised through `tests::parse_supports_ops_commands`.

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
