# Windows Working Node Plan — Adversarial Status Review (2026-09-04)

> **UNTRUSTED — MACHINE-GENERATED.** This review was produced by an automated
> agent against a single snapshot of the repository and has **not** been
> human-verified. Every file:line citation below was read from the reviewed
> commit, but classifications and judgments are machine output and must be
> confirmed by a human before being used to change any status, gate, or ledger.
> Do not treat this document as source-of-truth evidence.

- **Reviewed commit:** `f454cbd87208e96e8f1e84d194b7a9b4754ed14b` (`f454cbd8` — "fix(sysinfo): add missing Windows arm for apparmor_profile_status_internal", 2026-09-04)
- **Subject:** `documents/operations/active/WindowsWorkingNodePlan_2026-04-17.md` (346 lines at this commit)
- **Method:** every status line, claim, and cited path in the plan was checked against the tree at the reviewed commit by direct grep/read (`rg`, file reads). Claims about historical lab runs are classified by whether the cited evidence artifact still exists; no claim was inferred from memory or from other documents.
- **Classifications:** LANDED (exists with file:line proof), DRIFTED (exists but the plan's cited name/location is wrong), OPEN (genuinely absent), UNVERIFIABLE (cannot be confirmed or denied from this tree/commit).

## Verdict Summary

The plan's core "Current Repo Truth" claims — the reviewed Windows
`--windows-service --env-file` host path, the two backend labels, the
runtime-boundary work (ProgramData roots, DPAPI custody, named-pipe IPC,
installer ACL/SID hardening), and the Linux-only live-lab guards — all remain
**LANDED** at `f454cbd8`. The plan's one stale anchor is the recovery-plan
document (moved to `documents/archive/`). The plan's Phase 4 evidence snapshot
points at a gitignored artifact root that no longer exists on this checkout,
so the historical run claims are **UNVERIFIABLE** from the repository alone.
The plan's central posture — Windows is still `runtime-host-capable only`,
not dataplane-proven, not release-gated — is **consistent with the current
tree**: no reviewed Windows production backend label beyond
`windows-wireguard-nt` (opt-in, reviewed) exists, and the platform matrix
still carries the `runtime-host-capable only` qualification.

## 1. "Current Repo Truth" claims (plan lines 33–46)

| # | Plan claim | Classification | Evidence at `f454cbd8` |
|---|---|---|---|
| T1 | `rustynetd` exposes a reviewed Windows `--windows-service --env-file` host path | **LANDED** | `crates/rustynetd/src/windows_service.rs:131` (`"--windows-service" =>`), `:142` (`"--env-file" =>`) |
| T2 | Service/config host supports smoke validation + explicit fail-closed blocker reporting | **LANDED** | `crates/rustynetd/src/windows_service.rs:73` — explicit blocker string `windows-runtime-backend-not-configured: ... the env-file did not specify --backend ...`; `:112` rejects inline daemon flags in service mode |
| T3 | Fail-closed label `windows-unsupported` and opt-in reviewed label `windows-wireguard-nt` both exist behind the backend abstraction | **LANDED** | `crates/rustynetd/src/windows_backend_gate.rs:3` `WINDOWS_UNSUPPORTED_BACKEND_LABEL: &str = "windows-unsupported"`, `:4` `WINDOWS_WIREGUARD_NT_BACKEND_LABEL: &str = "windows-wireguard-nt"` |
| T4 | Windows not fresh-install evidenced / not release-gated; `runtime-host-capable only` posture | **LANDED** (posture still held) | `documents/operations/PlatformSupportMatrix.md:16` (posture definition), `:110` (client row: "today: `runtime-host-capable only`"), `:154` ("`runtime-host-capable only` and not dataplane-evidenced") |
| T5 | Linux-only live-lab wrappers reject non-Linux targets fail-closed | **LANDED** | `crates/rustynet-cli/src/vm_lab/mod.rs:980`, `:13639`, `:14104`, `:15678`, `:15741`, `:22932` — repeated hard error `"alias {} resolved to non-Linux platform: {}"` guards |

## 2. Truth anchors (plan lines 48–54)

| Anchor cited by plan | Classification | Actual location at `f454cbd8` |
|---|---|---|
| `crates/rustynetd/src/windows_service.rs` | **LANDED** | exists |
| `crates/rustynetd/src/windows_backend_gate.rs` | **LANDED** | exists |
| `crates/rustynet-cli/src/vm_lab/bootstrap/windows.rs` | **LANDED** | exists (see §5 for its manifest flow) |
| `documents/operations/PlatformSupportMatrix.md` | **LANDED** | exists |
| `documents/operations/active/WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md` | **DRIFTED** | file exists but at `documents/archive/WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md` — the plan cites it under `active/`; it has been archived since. Nothing named `*WindowsVmLabAccess*` or `*OrchestrationRecovery*` remains under `documents/operations/`. |

## 3. "Current Phase 2 Baseline" claims (plan lines 56–91)

| # | Plan claim | Classification | Evidence at `f454cbd8` |
|---|---|---|---|
| P2-1 | Runtime files pinned under `C:\ProgramData\RustyNet\{config,logs,trust,membership,keys,secrets}` with protected `secrets\key-custody` subtree | **LANDED** | `crates/rustynetd/src/windows_paths.rs:13` `DEFAULT_WINDOWS_KEY_CUSTODY_ROOT: &str = r"C:\ProgramData\RustyNet\secrets\key-custody"`; `:270` registers it as "key-custody root" in the reviewed-root set; `ProgramData` also in `windows_key_custody.rs`, `windows_service_hardening.rs`, `key_material.rs` |
| P2-2 | Passphrase custody uses DPAPI-protected `.dpapi` blobs under the reviewed secret root | **LANDED** | `crates/rustynetd/src/windows_key_custody.rs:146` (`.dpapi` extension in custody entry shape), `:291` `path: format!(r"C:\ProgramData\RustyNet\secrets\{label}.dpapi")`, `:339/:364/:416` `wireguard.passphrase.dpapi` fixtures |
| P2-3 | Local privileged IPC is Windows named-pipe only, pinned to `\\.\pipe\RustyNet\` | **LANDED** | `crates/rustynetd/src/windows_ipc.rs:7` `DEFAULT_WINDOWS_DAEMON_PIPE_PATH = r"\\.\pipe\RustyNet\rustynetd"`, `:9` privileged pipe `r"\\.\pipe\RustyNet\rustynetd-privileged"`, `:167` namespace enforcement error `"{} must stay under the RustyNet named-pipe namespace: {}"`, plus negative tests `:703/:718/:719` rejecting out-of-namespace and traversal pipe names |
| P2-4 | Installer repairs runtime ACLs, provisions reviewed secret roots, requires unrestricted service SID | **LANDED** | `scripts/bootstrap/windows/Install-RustyNetWindowsService.ps1:338-343` (provisions `secrets` + `secrets\key-custody` roots, SYSTEM/Administrators-only DACL), `:521` `function Repair-RustyNetRuntimeAcl` with `icacls /setowner` (`:534`), `/inheritance:r` (`:538`) and `throw` on each failure; SID requirement in `crates/rustynetd/src/windows_service_hardening.rs:56-59` `REVIEWED_SERVICE_SID_TYPES: &[&str] = &["unrestricted", "restricted"]` with `None` rejected (per-service SID isolation) |
| P2-5 | Verify/diagnostics helpers capture Windows 11 facts, elevation, service SID, and `rustynetd windows-runtime-boundary-check` report | **LANDED** | `crates/rustynetd/src/main.rs:353` subcommand dispatch `cmd == "windows-runtime-boundary-check"`, `:802` fail-closed `"windows-runtime-boundary-check is only available on Windows hosts"`; the bootstrap verify helper that collects them is `scripts/bootstrap/windows/Verify-RustyNetWindowsBootstrap.ps1` (exists) |
| P2-6 | Phase 2 validation commands (`rustup run 1.88.0 cargo test -p rustynetd windows_` etc.) | **LANDED** (as command surface) | `rust-toolchain.toml` still pins `channel = "1.88.0"`; `windows_`-prefixed test functions exist in `rustynetd` (58 in `phase10.rs`, 6 in `windows_service.rs`, 5 in `windows_paths.rs`, 2 in `windows_ipc.rs`, plus more). The commands themselves were not executed during this review — only their viability was checked. |
| P2-7 | Full `rustynetd` Windows-target cross-compilation stops in `libsqlite3-sys` from this macOS host | **UNVERIFIABLE** | Environment/toolchain claim; cannot be confirmed from a static tree read, and no cross-compile was attempted for this review. Nothing in the tree contradicts it. |

## 4. "Current Phase 4 Evidence Snapshot" claims (plan lines 93–116)

All of §"Current Phase 4 Evidence Snapshot" describes one measured run of
2026-04-17. Its cited artifact root is:

- **`artifacts/windows_phase4/20260417T174942Z/phase4_evidence_summary.md` — UNVERIFIABLE / evidence not retained in git.** `artifacts/windows_phase4` is gitignored (confirmed via `git check-ignore`), and the directory does not exist on this checkout. The run-fact claims below therefore cannot be confirmed or denied from the repository; they are historical observations, not current-tree facts:
  - guest recovered to `192.168.64.14` — UNVERIFIABLE
  - `sync-source`, `build-release`, `smoke-service-host` completed — UNVERIFIABLE (but note the phase names still exist in current code: `smoke_service_host` parses as a `BootstrapPhase` at `crates/rustynet-cli/src/vm_lab/mod.rs:41749`; `build-release` is a first-class bootstrap phase, see §5)
  - `execution_ready=false` from a guest-POST readiness-callback timeout — UNVERIFIABLE (the mechanism described was not located in `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows.rs` by this review's greps; it may live elsewhere or have been refactored — not confirmed either way)
  - `install-release` failed closed on the same timeout — UNVERIFIABLE
  - `host_key_file_exists=True`, `sshd_service_count=0`, `sshd_registry_present=False`, `ssh_listener_count=0` — UNVERIFIABLE
  - diagnostics hit `UTM Windows capture output was missing rc marker` — **DRIFTED**: that exact error string no longer exists anywhere under `crates/` at `f454cbd8` (grep for `rc marker` and `capture output` both return nothing), so the diagnostics surface that produced it has been refactored/renamed since 2026-04-17
  - "no measured join/connectivity, restart, or reinstall proof, so Windows remains outside the release gate" — **CONSISTENT** with the current tree: `documents/operations/PlatformSupportMatrix.md:154` still carries the same posture (see T4)

**Doc-hygiene consequence:** the plan presents this snapshot as "Latest
measured local Windows UTM attempt", but its only artifact root is
unretrievable from git. The snapshot section is now history-only; the plan
should either cite a durable evidence location (report dirs / run-matrix
ledger) or mark the section historical.

## 5. Task-focus items: Windows bootstrap/install path (verified as extra coverage)

These items are not all cited by the plan by name, but were verified against
the reviewed commit per the review's focus mandate:

| Item | Classification | Evidence at `f454cbd8` |
|---|---|---|
| `Bootstrap-RustyNetWindows.ps1` build-release phase | **LANDED** (at `scripts/bootstrap/windows/`, not `scripts/windows/`) | `scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1:2` phase `ValidateSet` includes `build-release`; `:116` `if ($Phase -eq 'build-release')`; `:181` throws `"build-release result path must have a parent directory"`; `:691` refuses SYSTEM-context build without interactive desktop; `:1652` toolchain-resolution fail-fast. 65 `throw` gates total in the script. |
| `rustynet-windows-trust-cli` build | **LANDED** | Binary source: `crates/rustynet-cli/src/bin/rustynet-windows-trust-cli.rs` (a `[[bin]]` of `rustynet-cli`, `crates/rustynet-cli/Cargo.toml:23+`); the bootstrap builds it offline: `scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1:1702` `$trustCliBuildArgs = @('build', '--locked', '--release', '-p', 'rustynet-cli', '--bin', 'rustynet-windows-trust-cli')`; orchestrator-side dispatch validation at `crates/rustynet-cli/src/vm_lab/mod.rs:19349`/`:50549` (`"unknown rustynet-windows-trust-cli command: status"`) |
| `Install-RustyNetWindowsService.ps1` throw gates | **LANDED** (at `scripts/bootstrap/windows/`) | 45 `throw` gates, e.g. `:102` empty service name, `:105` >128 chars, `:108` charset rejection, `:115-121` node-id validation, `:139-142` SSH-CIDR validation; ACL/secret-root provisioning at `:338-343` and `Repair-RustyNetRuntimeAcl` at `:521` (see P2-4) |
| Orchestrator `windows_install.rs` manifest flow | **LANDED** | `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_install.rs` — `:14` `WINDOWS_SERVICE_NAME: &str = "RustyNet"`, `:77` manifest constant `r"C:\Windows\Temp\rustynet-stage\build-release\manifest.json"`, `:82/:96/:105` PS encode/quote helpers, `:200/:210` `run_remote_ps(_check)`, `:227` `windows_build_timeout_from_env`, `:278` `install_daemon`, `:521` `enforce_daemon`, `:562` `start_daemon` with service-start probe. Companion manifest validation in `crates/rustynet-cli/src/vm_lab/bootstrap/windows.rs:113-179` — the guest-side helper must write a complete `manifest.json` (required fields `phase/status/reason/report_root/stdout_path/stderr_path/exit_code_path/toolchain_path/manifest_path/complete_marker_path`, phase must equal `build-release`, plus `complete.marker`) or the wrapper fails closed |
| WinNAT / `MSFT_NetNat` exit gating | **LANDED** | `crates/rustynetd/src/phase10.rs:6026` `WINDOWS_PS_REQUIRE_EXIT_CMDLETS` (requires `New-NetNat`/`Get-NetNat`/`Remove-NetNat` cmdlets + `Get-CimClass -Namespace root/standardcimv2 -ClassName MSFT_NetNat`, else explicit `throw` naming the WinNAT/HNS requirement), `:6027` `WINDOWS_PS_PREFLIGHT_EXIT_SERVING` (admin-token check, distinct tunnel/egress aliases, default-route presence on egress); tests at `:14529-14578` assert the preflight verifies the WinNAT WMI class; teardown fail-closed on `'No MSFT_NetNat'` CimException at `crates/rustynet-cli/src/vm_lab/script_template.rs:1577-1587` |

## 6. Remaining Work Streams / Validation Matrix / Non-Goals / DoD (plan lines 139–346)

These sections are forward-looking requirements and checklists, not status
claims; they have no direct land/open classification. Two current-tree
observations relevant to them:

- **Stream 1 ("First Real Windows Backend") — still genuinely OPEN as
  described.** No production Windows backend beyond the opt-in reviewed
  `windows-wireguard-nt` label exists (`windows_backend_gate.rs:3-4`); the
  fail-closed blocker path is still the default posture
  (`windows_service.rs:73`). Nothing in the tree contradicts the plan's "this
  is the primary blocker" framing.
- **"Windows Works" criteria 11–12 (fresh-install + release-gate evidence) —
  still OPEN**, consistent with `PlatformSupportMatrix.md:154`.

## 7. Claim-by-claim counts

- **LANDED:** 14 claim groups (T1–T5, anchors 1–4, P2-1–P2-6, and all five task-focus items)
- **DRIFTED:** 2 (archived recovery-plan anchor, §2; `missing rc marker` diagnostics string, §4)
- **OPEN (as the plan itself claims):** first real backend as production default; fresh-install/release evidence
- **UNVERIFIABLE:** 7 Phase-4 historical run facts (§4) + the `libsqlite3-sys` cross-compile blocker (P2-7)

## 8. Recommended plan amendments (docs-only, for a human to apply)

1. Update the fifth truth anchor to `documents/archive/WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md` (or drop the anchor and cite the current Windows ledgers).
2. Mark the Phase 4 Evidence Snapshot section as historical (2026-04-17 run; artifact root gitignored and no longer present) or repoint it at a durable ledger.
3. Optionally name the now-canonical script location `scripts/bootstrap/windows/` so future readers do not look under `scripts/windows/`.

No plan status was changed by this review. This document makes no code change
and flips no gate; per its header it is untrusted machine output pending human
verification.
