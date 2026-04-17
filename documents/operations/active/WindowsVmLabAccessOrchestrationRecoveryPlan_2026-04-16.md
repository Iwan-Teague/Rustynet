# Windows VM-Lab Access And Orchestration Recovery Plan

## Objective

Close the current Windows VM-lab orchestration gap so Windows UTM guests can be
bootstrapped, reached, and validated authoritatively through the Rustynet
Windows PowerShell path without routing Windows into Linux-only shell stages and
without false-green results.

## Current Status

- Windows VM execution is **proven** through local UTM guest exec.
- Windows source sync is **proven** through the current ZIP/PowerShell sync
  path.
- Windows compile capability is **proven** on the live UTM guest by building
  real Rust targets there.
- Windows SSH/access orchestration is **not yet authoritative**.
- Windows bootstrap/install/verify evidence is **not yet authoritative** because
  the access/bootstrap transport and readiness proof remain weaker than the
  guest’s actual execution capability.

## Current Repo Truth To Preserve

- `documents/Requirements.md` and `documents/SecurityMinimumBar.md` remain the
  governing source of truth.
- Windows is currently `runtime-host-capable only`, not release-gated and not
  dataplane-capable.
- Linux-only live-lab wrappers remain fail-closed for any target that is not
  `platform=linux` / `remote_shell=posix` / `guest_exec_mode=linux_bash` /
  `service_manager=systemd`.
- Windows helper/system integration stays argv-only and PowerShell-first.
- Windows must not silently reuse Linux runtime roots or Linux shell stages.

## Problem Statement

The Windows VM itself is not the primary blocker. The stronger evidence is:

- local source sync to the Windows guest works
- guest-side PowerShell execution works
- real Rust code compiled successfully inside the Windows guest

The orchestration gap is instead in the Windows access/reachability path:

- the access bootstrap helper mutates guest state but does not verify end-state
- local UTM Windows capture still depends too heavily on stdout marker parsing
- Windows local UTM execution falls back to SSH too early, including while SSH
  is still being established
- discovery/readiness collapses distinct Windows failure modes into coarse
  reason codes
- higher Windows bootstrap phases consume those weak lower-level signals

## Scope

This plan covers:

- Windows access bootstrap hardening
- Windows UTM transport and capture hardening for access/bootstrap operations
- Windows readiness classification improvements
- Windows bootstrap/provider integration for authoritative blocked or passing
  results
- clean-snapshot validation and evidence requirements

This plan does not cover:

- Windows dataplane/backend implementation beyond the current reviewed
  `windows-unsupported` truth
- release-gate promotion
- Linux live-lab wrapper broadening
- SSH trust weakening or host-key TOFU in the active wrapper path

## Primary Files

- `scripts/vm_lab/windows/Enable-WindowsVmLabAccess.ps1`
- `scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1`
- `scripts/bootstrap/windows/Collect-RustyNetWindowsDiagnostics.ps1`
- `crates/rustynet-cli/src/vm_lab/mod.rs`
- `crates/rustynet-cli/src/vm_lab/bootstrap/windows.rs`

## Failure Map

### F1. Access bootstrap returns success too early

Current behavior:

- installs or starts OpenSSH
- writes `administrators_authorized_keys`
- may create the firewall rule
- returns host-key text

Missing proof:

- `sshd -t` configuration validation
- deterministic ACL repair/verification
- listener validation
- firewall enabled-state validation
- host-side SSH reachability proof
- structured pass/fail result

### F2. UTM Windows capture is too fragile for authority

Current behavior:

- PowerShell capture wraps stdout with markers
- CLI parser expects those markers to survive `utmctl exec` output handling

Observed failure shape:

- `UTM Windows capture output was missing rc marker`

### F3. SSH fallback sequencing is wrong during access establishment

Current behavior:

- Windows local UTM command failures fall back to SSH

Problem:

- SSH is the thing being established, so fallback obscures the real failure and
  produces compound error noise instead of a clear root cause

### F4. Windows readiness is under-specified

Current behavior:

- discovery emits coarse readiness such as `ssh-auth-not-ready`

Missing distinction:

- host route broken
- guest agent unavailable
- guest IP not authoritative
- firewall closed
- `sshd` not running
- listener missing
- host key missing
- auth rejected
- auth timeout

### F5. Higher Windows phases depend on weak lower-level truth

Current behavior:

- install/restart/verify depend on helper capture and current transport truth

Problem:

- if access bootstrap truth is weak, higher-level Windows phase results cannot
  be treated as authoritative

## Phase Plan

### Phase 1. Harden Windows Access Bootstrap

**Goal:** make the guest-side access helper verification-based instead of
mutation-only.

Files:

- `scripts/vm_lab/windows/Enable-WindowsVmLabAccess.ps1`
- `scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1`

Implementation tasks:

- ensure OpenSSH capability installation remains explicit
- ensure `sshd` startup type is correct
- recreate or re-enable the firewall rule when disabled or malformed, not only
  when missing
- rewrite `administrators_authorized_keys` deterministically
- repair SSH file ACLs deterministically using localized administrator/system
  principals
- validate `sshd_config` with `sshd -t`
- restart `sshd` after config/key mutation
- verify the `sshd` service is `Running`
- verify a listener exists on port `22`
- emit structured JSON result instead of only returning the host key

Required JSON fields:

- `openssh_installed`
- `service_running`
- `firewall_rule_enabled`
- `authorized_keys_applied`
- `host_key_present`
- `listener_ready`
- `default_shell_configured`
- `status`
- `reason`

Tests and checks:

- PowerShell syntax validation
- unit tests or parser tests on the CLI side for the result schema if the JSON
  contract is parsed there
- negative guest validation for a disabled firewall rule, bad key state, and
  invalid config

Phase exit criteria:

- guest helper fails closed on invalid SSH config
- guest helper does not report success unless `sshd`, firewall, and listener
  state all validate
- helper output is machine-readable and deterministic

### Phase 2. Split Windows UTM Transport Into Status And Capture Paths

**Goal:** stop using fragile stdout-marker capture as the authority for Windows
access/bootstrap bring-up.

Files:

- `crates/rustynet-cli/src/vm_lab/mod.rs`

Implementation tasks:

- separate Windows local UTM execution into:
  - status/probe path
  - capture-output path
- use exit status or guest-written result files for access/bootstrap probes
- reserve capture-output parsing for workflows that genuinely need payload
  output after transport is already stable
- keep Linux and macOS behavior unchanged

Required behavior:

- access bootstrap must not depend on stdout markers to prove pass/fail
- access/bootstrap diagnostics must still fail closed if proof cannot be
  retrieved

Tests and checks:

- unit tests for Windows status-only command execution and parse paths
- negative tests for missing result files or malformed result payloads
- regression tests proving Linux UTM and SSH paths were not weakened

Phase exit criteria:

- Windows access bootstrap no longer depends on
  `__RUSTYNET_CAPTURE_RC__=...` markers for authority
- result retrieval failures return direct root-cause errors

### Phase 3. Remove Premature SSH Fallback During Windows Access Establishment

**Goal:** make Windows access/bootstrap failures report the real broken layer.

Files:

- `crates/rustynet-cli/src/vm_lab/mod.rs`

Implementation tasks:

- remove SSH fallback for Windows local UTM access-establishment steps
- keep SSH fallback only for operations that are explicitly post-bootstrap and
  already require a healthy SSH transport
- tag Windows transport failures with the exact UTM/probe/readiness cause

Tests and checks:

- negative tests proving Windows access bootstrap does not attempt SSH fallback
  when the UTM step fails
- regression tests proving non-Windows fallback behavior is preserved where
  currently intended

Phase exit criteria:

- Windows access bootstrap failure output reports one dominant root cause
- compound `UTM failed; SSH fallback failed` noise is removed from the access
  establishment path

### Phase 4. Add A Real Windows Readiness Ladder

**Goal:** make discovery and preflight tell operators exactly what is broken.

Files:

- `crates/rustynet-cli/src/vm_lab/mod.rs`

Implementation tasks:

- extend Windows readiness and reason-code generation so distinct failure modes
  are preserved
- keep Linux readiness behavior unchanged
- surface the finer-grained reason codes in JSON and user-visible failure
  output

Recommended reason codes:

- `process-not-ready`
- `guest-agent-not-ready`
- `live-ip-not-authoritative`
- `ssh-service-not-running`
- `ssh-firewall-not-open`
- `ssh-listener-not-ready`
- `ssh-host-key-not-ready`
- `ssh-auth-rejected`
- `ssh-auth-timeout`
- `no-authoritative-ssh-target`

Tests and checks:

- unit tests for Windows readiness classification
- regression tests proving existing Linux readiness expectations still pass
- report-contract checks for new reason codes in discovery artifacts

Phase exit criteria:

- discovery reports identify the broken access layer precisely enough to drive
  deterministic remediation
- `ssh-auth-not-ready` is no longer the only Windows access failure summary

### Phase 5. Rewire Higher Windows Bootstrap Phases To Proven Access Truth

**Goal:** make `install-release`, `restart-runtime`, and `verify-runtime`
depend on real Windows access/readiness proof.

Files:

- `crates/rustynet-cli/src/vm_lab/bootstrap/windows.rs`
- `crates/rustynet-cli/src/vm_lab/mod.rs`
- `scripts/bootstrap/windows/Collect-RustyNetWindowsDiagnostics.ps1`

Implementation tasks:

- gate higher Windows bootstrap phases on the strengthened readiness/access
  contract
- keep diagnostics collection available on failure
- preserve the current reviewed backend/dataplane truth
- ensure blocked backend cases still return explicit fail-closed reasons

Tests and checks:

- unit tests for phase gating and blocked-reason reporting
- diagnostics regression tests proving failures still produce a Windows
  diagnostics path when transport truth is available

Phase exit criteria:

- install/restart/verify consume proven access state instead of weak inferred
  state
- unsupported backend/dataplane truth remains explicit and blocked

### Phase 6. Clean-Snapshot Validation And Proof Refresh

**Goal:** prove the new orchestration path on a clean Windows guest instead of a
contaminated troubleshooting state.

Operational requirements:

- work from a known-clean Windows UTM snapshot
- do not accept stale guest state as fresh proof
- keep host-key trust pinned
- do not weaken Linux-only live-lab guardrails

Validation sequence:

1. `ops vm-lab-discover-local-utm`
2. Windows access bootstrap helper run through the UTM path
3. host-side pinned SSH readiness proof
4. `ops vm-lab-bootstrap-phase --phase install-release`
5. `ops vm-lab-bootstrap-phase --phase restart-runtime`
6. `ops vm-lab-bootstrap-phase --phase verify-runtime`
7. diagnostics collection on at least one forced negative case

Required artifacts:

- dated discovery JSON for the clean snapshot
- dated access-bootstrap result artifact
- host-side SSH proof log or machine-readable result
- install/restart/verify reports
- diagnostics output root for at least one negative case

Phase exit criteria:

- Windows access is proven from the host, not only from guest-local checks
- install/restart/verify results are authoritative for the current supported
  backend scope
- blocked backend/dataplane cases remain blocked, explicit, and non-green

### Phase 6 Immediate Closure Checklist

- patch `scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1` so
  `-ResultPath` writes fail-closed JSON on both success and top-level failure
- rebuild `rustynet-cli` after helper-path changes
- rerun `ops vm-lab-start` and confirm Windows access bootstrap no longer
  collapses to `produced no output`
- rerun `ops vm-lab-discover-local-utm` and capture the updated Windows
  readiness artifact
- if access bootstrap still fails, preserve the dominant root cause verbatim and
  do not advance to runtime install/restart/verify
- only resume host-side pinned SSH proof after the access helper result file is
  present and machine-readable

## Milestones

### M1. Verified Windows Access Bootstrap

Reached when:

- Phase 1 is complete
- the helper emits structured JSON
- success requires real guest-side SSH/firewall/listener proof

### M2. Authoritative Windows Bootstrap Transport

Reached when:

- Phases 2 and 3 are complete
- access/bootstrap no longer relies on fragile stdout markers for authority
- Windows access bootstrap no longer falls back to SSH while trying to
  establish SSH

### M3. Actionable Windows Readiness Reporting

Reached when:

- Phase 4 is complete
- discovery and preflight distinguish the real broken layer

### M4. Authoritative Windows Runtime Wiring

Reached when:

- Phase 5 is complete
- install/restart/verify depend on proven access truth and still fail closed on
  unsupported backend/dataplane cases

### M5. Clean Guest Proof

Reached when:

- Phase 6 is complete
- a clean Windows UTM snapshot produces dated, repeatable install/restart/verify
  evidence for the current supported scope

## Validation Gates

Code-side validation for implementation slices:

- `cargo fmt --all -- --check`
- `cargo check -p rustynet-cli`
- `cargo test -p rustynet-cli`
- `cargo clippy -p rustynet-cli --all-targets --all-features -- -D warnings`
- `cargo check --workspace --all-targets --all-features`
- `cargo test --workspace --all-targets --all-features`

Real-environment validation for the orchestration gap:

- `rustynet-cli ops vm-lab-discover-local-utm ...`
- Windows access bootstrap through the Windows PowerShell helper path
- host-side pinned SSH probe
- `rustynet-cli ops vm-lab-bootstrap-phase --phase install-release ...`
- `rustynet-cli ops vm-lab-bootstrap-phase --phase restart-runtime ...`
- `rustynet-cli ops vm-lab-bootstrap-phase --phase verify-runtime ...`

## Definition Of Done

This plan is complete only when all are true:

- Windows access bootstrap is verification-based and machine-readable
- Windows access establishment no longer depends on fragile marker-only capture
- Windows readiness reports the broken layer precisely
- higher Windows bootstrap phases depend on proven access truth
- diagnostics still work on failure where transport is available
- clean-snapshot Windows evidence exists for the currently supported scope
- Windows remains outside Linux-only live-lab shell stages
- unsupported backend/dataplane cases still fail closed and do not produce
  false-green results

## Notes

- The Windows VM itself is not the dominant blocker; the orchestration and
  recovery path around it is.
- Do not treat compilation proof or guest-local service/listener checks as a
  substitute for host-side access proof.
- Do not promote Windows support posture based on this plan alone. Docs and
  release gates move only after measured clean-snapshot evidence exists.
