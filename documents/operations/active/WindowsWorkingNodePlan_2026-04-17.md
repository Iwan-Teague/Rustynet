# Windows Working Node Plan (Imported From Downloads Research)

Status: active implementation plan

## Purpose

This document carries forward the useful, still-relevant Windows research that
was living in the Downloads-side bundle families and makes it part of the
repository source tree.

It is intentionally repo-native and conservative:

- current repo truth comes first
- historical bundle language does not override current code or active ledgers
- Windows is still described as `runtime-host-capable only` until real measured
  backend/dataplane proof exists

## Imported Research Basis

This plan distills the useful parts of these Downloads-side research bundles:

- `rustynet_windows_runtime_bundle_final`
- `rustynet_windows_working_bundle_revalidated`
- `Rustynet_windows_gap_closure_review_bundle_v3`
- `Rustynet_windows_bootstrap_spec_bundle_v2`
- `Rustynet_windows_utm_orchestrator_bundle_v1`

Those bundles are historical inputs, not normative sources. Their useful
conclusions are preserved here because they still align with current repo truth.

## Current Repo Truth

As of current `main`:

- `rustynetd` exposes a reviewed Windows `--windows-service --env-file` host
  path.
- the Windows service/config host is real enough to support smoke validation
  and explicit fail-closed blocker reporting.
- the explicit fail-closed backend label `windows-unsupported` and the opt-in
  reviewed backend label `windows-wireguard-nt` now both exist behind the
  backend abstraction.
- Windows support is still not fresh-install evidenced, not mixed-node
  evidenced, not release-gated, and must still be treated as
  `runtime-host-capable only` in support posture.
- Linux-only live-lab wrappers still reject non-Linux targets fail-closed and
  must continue to do so.

Primary truth anchors:

- `crates/rustynetd/src/windows_service.rs`
- `crates/rustynetd/src/windows_backend_gate.rs`
- `crates/rustynet-cli/src/vm_lab/bootstrap/windows.rs`
- `documents/operations/PlatformSupportMatrix.md`
- `documents/operations/active/WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md`

## Current Phase 2 Baseline

Measured repo truth after the current Phase 2 runtime-boundary work:

- reviewed Windows runtime files are pinned under
  `C:\ProgramData\RustyNet\{config,logs,trust,membership,keys,secrets}` with a
  protected `secrets\key-custody` subtree for OS-secure key custody material
- reviewed Windows runtime passphrase custody now uses DPAPI-protected
  `.dpapi` blobs under the reviewed secret root instead of plaintext long-lived
  runtime passphrase files
- reviewed local privileged IPC is Windows-native named-pipe IPC only, pinned
  to the `\\.\pipe\RustyNet\` namespace with narrow probe and runtime-ACL
  inspection request shapes
- the service installer now repairs reviewed runtime ACLs, provisions the
  reviewed secret roots, and requires an unrestricted service SID
- the Windows verify/diagnostics helpers now capture Windows 11 facts,
  elevation state, service SID state, and the `rustynetd
  windows-runtime-boundary-check` report
- none of this Phase 2/runtime-boundary evidence, and none of the later
  `windows-wireguard-nt` label wiring by itself, is dataplane proof or
  release-gate proof

Current Phase 2 validation commands:

- `rustup run 1.88.0 cargo test -p rustynetd windows_`
- `rustup run 1.88.0 cargo test -p rustynet-crypto`
- `rustup run 1.88.0 cargo check -p rustynetd -p rustynet-crypto -p rustynet-windows-native`
- `RUSTC=/Users/iwan/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin/rustc rustup run 1.88.0 cargo check -p rustynet-windows-native --target x86_64-pc-windows-msvc`
- `RUSTC=/Users/iwan/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin/rustc rustup run 1.88.0 cargo check -p rustynet-crypto --target x86_64-pc-windows-msvc`

Current Phase 2 validation blocker:

- full `rustynetd` Windows-target compilation from this macOS host still stops
  in the existing `libsqlite3-sys` cross-compilation path before daemon-level
  Windows code generation completes; this is an environment/toolchain blocker,
  not measured proof of a Windows backend

## Current Phase 4 Evidence Snapshot

Latest measured local Windows UTM attempt on 2026-04-17:

- the guest was first recovered from link-local IPv4 back onto the reviewed
  shared subnet as `192.168.64.14`
- `sync-source`, `build-release`, and `smoke-service-host` completed for
  current `HEAD`
- discovery still reported `execution_ready=false` because the Windows
  local-UTM callback/readiness probe timed out waiting for a guest POST back
  to the host
- `install-release` failed closed on the same callback/access-bootstrap
  timeout before install/runtime proof
- guest-side SSH state still remained absent on that same run:
  `host_key_file_exists=True`, `sshd_service_count=0`,
  `sshd_registry_present=False`, `ssh_listener_count=0`
- diagnostics on the blocked path still hit
  `UTM Windows capture output was missing rc marker`
- there is still no measured join/connectivity, restart, or reinstall proof,
  so Windows remains outside the release gate

Current measured artifact root:

- `artifacts/windows_phase4/20260417T174942Z/phase4_evidence_summary.md`

## What “Windows Works” Must Mean

Windows is only considered genuinely working when all of the following are
true:

1. the Windows service host starts a reviewed runtime path
2. the backend label is no longer `windows-unsupported`
3. a reviewed Windows backend exists behind the stable backend abstraction
4. the Windows node can join a Rustynet network
5. the Windows node can connect to Linux and/or macOS peers
6. route behavior is correct and fail-closed
7. DNS behavior is correct and fail-closed
8. restart preserves the expected safe state
9. reinstall from a clean Windows snapshot works
10. diagnostics and verification scripts collect authoritative evidence
11. fresh-install evidence exists for the current commit
12. docs and release gates move only after measured proof exists

Until then, service-host smoke proof must stay separate from node-connectivity
proof.

## Remaining Work Streams

### 1. First Real Windows Backend

This is the primary blocker.

Required outcome:

- replace `windows-unsupported` with at least one reviewed backend mode behind
  the existing backend abstraction
- keep backend-specific behavior inside backend adapter code rather than
  leaking it through daemon/domain layers

Not acceptable:

- using test-only or in-memory behavior as “production” Windows runtime proof
- exposing Windows-looking backend labels that still route to unsupported
  behavior

### 2. Tunnel / Device / Artifact Lifecycle

Required outcome:

- a real Windows tunnel/device path exists for the selected backend
- artifact presence, architecture fit, and signature state are validated
- create / up / down / remove lifecycle is explicit and repeatable

Research carry-forward:

- Windows 11 supports the service lifecycle and route/DNS API families needed
  for this work
- Wintun-like artifact validation belongs in the evidence path, not as an
  undocumented manual assumption

### 3. Route And DNS Runtime Truth

Required outcome:

- route add / readback / remove is correct
- DNS set / readback / remove is correct
- uninstall and rollback do not silently leave stale state behind

Security rule:

- wrong-state cleanup must fail closed rather than drift silently

### 4. Windows-Safe Local Operations

Required outcome:

- finish the Windows-safe privileged local IPC path
- finish Windows-safe secret custody and path/ACL enforcement
- keep helper/system integration argv-only and PowerShell-first

Security rules preserved from the imported research:

- no Unix-socket fallback on Windows
- no remote/UNC pipe use for local privileged IPC
- DPAPI scope should stay narrow by default when service/user scope is enough

### 5. Mixed-Node Validation

Required outcome:

- Windows node joins a real Rustynet network
- Windows node connects to Linux peer(s)
- Windows node connects to macOS peer(s) when that topology is in scope
- restart and reinstall are proven on current code

Evidence classes must stay separate:

- host-surface smoke proof
- runtime-boundary proof
- backend functionality proof
- mixed-node proof
- release-gate proof

### 6. Fresh-Install And Release Evidence

Required outcome:

- clean Windows snapshot or clean guest install proof exists
- current release/fresh-install docs are updated to measured truth only
- required gates run in a proper environment

Windows must remain outside the release gate until that proof exists.

## Windows 11 Compatibility Carry-Forward

The Downloads-side Windows working bundle contained a useful compatibility and
test matrix. The still-relevant conclusions are preserved here:

- Windows 11 is the correct validation target for this work.
- Windows 11 is not itself the blocker; the blocker is the missing reviewed
  backend/dataplane implementation and the evidence burden around it.
- route and DNS API availability are not the main platform concern on Windows
  11; reviewed runtime integration and measured proof are.
- guest architecture, tunnel artifacts, and signature state must be captured in
  every Windows validation run.

## Windows 11 Validation Matrix

Capture these on every Windows proof run:

- Windows edition, version, and build number
- guest architecture
- UTM guest identifier or snapshot name
- whether the session is elevated/admin
- current Rustynet commit hash
- artifact hashes and signature status

### Phase 1: service/config host

Positive checks:

- help output advertises `--windows-service`
- help output advertises `--env-file`
- help output advertises `windows-unsupported`
- service image path pins the reviewed binary path and env file
- service start reaches the expected explicit blocker for unsupported backend
- remove/reinstall is repeatable

Negative checks:

- relative env-file path rejected
- inline daemon flags in service mode rejected
- unknown Windows backend label rejected
- non-reviewed path roots rejected

### Phase 2: runtime boundary and secure local operations

Positive checks:

- runtime paths stay under reviewed Windows roots
- named-pipe paths stay under the Rustynet namespace
- local-only IPC policy is enforced
- reviewed secret protection round-trip succeeds
- Windows 11, elevation, and service-SID prerequisites are reported explicitly
- diagnostics are sufficient to explain failure without guesswork

Negative checks:

- Linux runtime roots on Windows rejected
- remote UNC pipe paths rejected
- unauthorized local client identity rejected
- wider-than-necessary secret scope not used by default

### Phase 3: first real backend mode

Positive checks:

- reviewed backend label parses and dispatches
- required tunnel artifacts exist for the guest architecture
- tunnel artifact signature status is captured
- tunnel create / up / down / remove succeeds
- peer add / update / remove succeeds
- route add / read / remove succeeds
- DNS set / read / remove succeeds
- restart preserves safe runtime behavior

Negative checks:

- missing tunnel artifacts fail closed
- invalid or unsigned artifact policy fails closed when required
- wrong-state route or DNS cleanup fails closed
- unsupported capability requests return explicit blocker codes

### Phase 4: mixed-node proof and release evidence

Positive checks:

- clean Windows snapshot install succeeds
- Windows joins a Rustynet network
- Windows connects to Linux peer
- Windows connects to macOS peer when in scope
- restart proof succeeds
- reinstall proof succeeds
- diagnostics and evidence are current-commit and snapshot-clean

Negative checks:

- wrong backend/runtime state remains blocked
- service/binpath drift is detected
- route/DNS cleanup after uninstall is validated
- stale artifact/signature drift is detected

## Non-Goals

This plan does not support:

- claiming Windows is already release-ready
- weakening Linux-only live-lab shell-stage guards
- pretending `windows-unsupported` is usable
- moving backend-specific behavior out of the backend boundary
- replacing OS-native protections with ad hoc shell or crypto shortcuts
- promoting helper/bootstrap parity into dataplane/runtime parity

## Definition Of Done

This plan closes only when:

- Windows is no longer merely `runtime-host-capable only`
- a reviewed backend exists and is proven on Windows
- mixed-node evidence exists
- fresh-install evidence exists
- release docs/gates are updated to measured truth

Until then, this document should stay active.
