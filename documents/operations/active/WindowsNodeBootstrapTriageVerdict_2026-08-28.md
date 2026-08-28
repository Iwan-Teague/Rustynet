# CP-4 Verdict: Windows `--node` Bootstrap Failure — Code vs Guest (2026-08-28)

**Triage deliverable for CP-4** of
[CrossPlatformRoleParityRefresh_2026-07-23.md](./CrossPlatformRoleParityRefresh_2026-07-23.md)
§2, which recorded the root cause as "unverified — code vs guest health" and
directed that it be triaged **first among the Windows work** because
`windows_stage_bootstrap` gates the entire Windows `--node` column (~30 cells).

**Verdict: BOTH, and the code defect is primary.** The named failing step is
`Ensure-WingetConfigurationDependencies` →
`& winget configure --file <RustyNetBootstrap.winget.yml> --accept-configuration-agreements --disable-interactivity`
at
[`scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1:1130`](../../../scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1),
throwing at `:1132`. The bootstrap hard-depends on WinGet **Configuration**, an
opt-in WinGet feature, which it never enables and never precondition-checks —
so a guest that is otherwise perfectly healthy fails bootstrap unless somebody
enabled that feature out of band. The 2026-07-19 guest had it disabled; that is
the guest half. Nothing in this repository ever runs `winget configure --enable`
(verified by exhaustive grep over `scripts/`, `crates/`, and the runbooks); that
is the code half, and it is the half that reproduces on every fresh guest.

No code was changed. This is a triage document, per the CP-4 scope.

## 0. The three corrections that matter more than the verdict

Read this section even if you read nothing else. The CP-4 evidence base as
stated in the Refresh doc is wrong in three ways, and two of them were actively
preventing the triage from concluding.

**(a) The "5 fails" are not 5 bootstrap failures. Only 3 are.** The Refresh doc
§1 records `windows_stage_bootstrap` as `n=5 fail`. That count is read from the
roll-up column in
[`live_lab_node_run_matrix.csv`](../live_lab_node_run_matrix.csv). Joining it
against the per-stage ledger
[`live_lab_node_stage_results.csv`](../live_lab_node_stage_results.csv) shows
`bootstrap_hosts` actually **ran and failed 3 times** and was **`skip` twice**,
because those two runs died upstream at `preflight`. The correct statement is
"3 bootstrap failures, 2 upstream preflight failures that never reached
bootstrap".

**(b) The 5 are not one cause. There are at least four distinct causes**, across
two guests, two commits and two days. See §1.

**(c) The `*_stage_bootstrap` roll-up columns record `fail` for a stage that was
`skip`, on every OS at once.** On run `livelab-1784489499-db3ff1aaafe6`
(2026-07-19, `first_failed_stage=preflight`), the per-stage ledger has
`bootstrap_hosts=skip` for every node — yet the run-matrix row reads
`linux_stage_bootstrap=fail`, `macos_stage_bootstrap=fail`, **and**
`windows_stage_bootstrap=fail`. The same shape appears on
`livelab-1785005557-b7667cce46db`. A run-scoped `preflight` failure is being
absorbed into all three OS bootstrap columns by the status merge in
[`crates/rustynet-cli/src/live_lab_run_matrix.rs`](../../../crates/rustynet-cli/src/live_lab_run_matrix.rs)
(`merge_status`, `:2215-2231`, which ranks `fail` above `skip` — correct in
isolation, wrong when a run-scoped stage and a node-scoped stage share a
column). This is **not** a Windows-specific defect and it inflates the Linux and
macOS fail counts too. It is the same class of ledger-integrity bug as the
`traffic_test_matrix` aliasing recorded in AGENTS/CLAUDE §12.3, and it deserves
its own task.

The practical consequence of (a) and (c) together: **CP-4's headline evidence
overstates the Windows bootstrap problem by 40%**, and any future re-count that
reads the roll-up column alone will reproduce the error. Per §12.3, take the
verdict from the stage's own report artifact, never from the column.

## 1. The five rows, individually

All five come from the `--node` engine ledger. Reproduce with a quote-aware
reader (§12.3); `awk -F,` will read the wrong column.

| # | Date | Run id | Commit | Guest | `bootstrap_hosts` | Actual cause |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 2026-07-19T19:31:16Z | `livelab-1784489499-db3ff1aaafe6` | `db3ff1aa` | windows-utm-1 | **skip** | `preflight` fail — topology: *"lab requires exactly 1 Exit node, found 0"* |
| 2 | 2026-07-19T20:05:03Z | `livelab-1784492387-db3ff1aaafe6` | `db3ff1aa` | windows-utm-1 | **fail** | WinGet Configuration feature disabled |
| 3 | 2026-07-19T20:26:17Z | `livelab-1784493982-db3ff1aaafe6` | `db3ff1aa` | windows-utm-1 | **fail** | WinGet Configuration feature disabled (same as #2) |
| 4 | 2026-07-25T18:52:19Z | `livelab-1785005557-b7667cce46db` | `b7667cce` | windows-x86-1 | **skip** | `preflight` fail — *"guest clock skew is 3602s (maximum 90s)"* |
| 5 | 2026-07-25T19:01:17Z | `livelab-1785006739-b7667cce46db` | `b7667cce` | windows-x86-1 | **fail** | `Install-RustyNetWindows…` — inner cause not retrievable (see §4) |

Four distinct causes: a topology-config error (#1), the WinGet Configuration
gap (#2, #3), a one-hour guest clock skew (#4), and an unresolved third failure
on a different guest (#5). Note also that #1 and #4 are not Windows problems at
all — #1 is a lab-topology mistake (no exit node elected) and #4 is generic guest
NTP drift of exactly 3602 s, i.e. one hour plus two seconds, the signature of a
timezone/DST offset rather than clock wander.

**Answer to "are all 5 the same failure?": no.** Only #2 and #3 share a cause,
and they are the same guest on the same commit eighteen minutes apart — that is
one fault observed twice, not two independent data points.

## 2. The primary code defect — a hard dependency on an opt-in WinGet feature

### 2.1 The evidence

The failing run's stage log
(`state/live-lab-direct-1784492687/logs/bootstrap_hosts.log`) carries the answer
in its **stdout tail**, not in its error field:

```
[stdout: [bootstrap] Defender exclusions skipped (opt-in disabled).
Configuration is not enabled. Run `winget configure --enable` to enable it.]
```

That is WinGet's own message. `winget configure` returns non-zero, and the
script's `$LASTEXITCODE` gate converts it into a `throw`.

### 2.2 The code path

```powershell
# scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1:1123-1135
function Ensure-WingetConfigurationDependencies {
    param([string]$ConfigPath = '')
    $candidate = Resolve-WingetConfigurationPath -ConfigPath $ConfigPath
    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "WinGet configuration file not found: $candidate"
    }
    Require-Winget | Out-Null
    & winget configure --file $candidate --accept-configuration-agreements --disable-interactivity
    if ($LASTEXITCODE -ne 0) {
        throw 'winget configure failed for RustyNet bootstrap configuration'
    }
    Assert-RustyNetWingetDependenciesInstalled
}
```

`Ensure-WingetConfigurationDependencies` is not optional or best-effort — it is
called unconditionally on both source paths (`:1415` in `Sync-SourceGit`, `:1539`
in the archive path), and it is what installs Git, PowerShell 7, rustup **and
WireGuard** (`scripts/bootstrap/windows/RustyNetBootstrap.winget.yml`). Without
it there is no toolchain and no WireGuard, so `rustynetd` would fall back to
`windows-unsupported` even if the stage were allowed to continue. It is a genuine
hard dependency, correctly placed; the problem is its unmet precondition.

### 2.3 Why the precondition is never checked

The script has an elaborate WinGet preflight that checks the wrong thing:

- `Require-Winget` (`:548-571`) gates solely on `$state.winget_command_present`,
  attempts App Installer re-registration if absent, and throws a good, specific
  message if `winget.exe` cannot be found. It says nothing about Configuration.
- `Get-WindowsBootstrapToolingState` (`:456-...`) collects ten-plus facts about
  the WinGet install — `winget_command_present`, `winget_command_source`,
  `appinstaller_present`, the full `Microsoft.DesktopAppInstaller` Appx package
  list, `C:\Program Files\WindowsApps` matches — and **not** the Configuration
  feature's enabled state.

So the script proves `winget.exe` exists and then immediately invokes a WinGet
*sub-feature* whose availability it never established. `winget.exe` being present
does not imply `winget configure` is enabled; Configuration ships disabled and
requires an explicit, elevated `winget configure --enable` (or the equivalent
`experimentalFeatures` settings entry).

**Grep result, repository-wide:** no occurrence of `winget configure --enable`,
`EnableConfiguration`, `winget features`, or `winget settings` anywhere in
`scripts/`, `crates/`, or `documents/operations/`. Nothing in this repo has ever
enabled the feature. Every green Windows bootstrap in the project's history
therefore ran on a guest where a human had enabled it out of band — which is
exactly why the state is fragile and why re-imaging or replacing a guest silently
reintroduces the failure.

### 2.4 Why this is CODE, not merely GUEST

The distinction the Refresh doc asks for is "does the bootstrap path have a
defect, or did the environment drift". Enabling a documented-nowhere, opt-in,
per-machine WinGet feature is a **precondition the bootstrap owns and does not
state**. Concretely:

- It is not in the guest-prep runbook. `WindowsExitNodeRunbook_2026-06-04.md`
  documents two prerequisites (a WinNAT/HNS-capable image; internet egress) and
  **does not mention WinGet at all** — verified by grep. So an operator following
  the runbook exactly will build a guest that cannot bootstrap.
- The bootstrap is fail-loud everywhere else about its preconditions
  (`Require-Winget`, `Resolve-InstallHelperPath`, `Resolve-VerifyHelperPath`,
  `Assert-RustyNetWingetDependenciesInstalled` all throw named, actionable
  errors). This one gap is inconsistent with the script's own standard.
- The failure is deterministic on any fresh Windows image. That is the definition
  of a code defect, not drift.

The guest half is real and should be recorded — the 2026-07-19 `windows-utm-1`
had the feature disabled — but fixing only the guest leaves the next guest
broken.

## 3. The bash-vs-`--node` asymmetry, and what it does *not* prove

`BashRetirementGapEnumeration_2026-08-22.md` §B2 records
`windows_stage_bootstrap` as **66 pass** on the frozen bash archive against
**0 pass** on `--node`. That asymmetry is suggestive but must not be cited as
evidence here, for the reason AGENTS/CLAUDE §2 gives explicitly: the two engines
use different stage vocabularies and *"never read a stage result from one ledger
as evidence for the other engine"*. The bash engine was deleted in W5.7, so the
comparison can no longer be run.

What the asymmetry does justify is a **question for whoever takes the fix**: the
66 bash passes were collected on the same physical `windows-utm-1`, so either the
bash path did not route through `winget configure`, or the feature was enabled on
that guest at that time and has since been lost. Either answer is worth knowing
before the fix is designed, but neither is established by this triage.

## 4. Failure #5 — unresolved, and why

Row #5 (2026-07-25, `windows-x86-1`, commit `b7667cce`) failed in a **different
script**: the error record names `Install-RustyNetWindows…` at `char:108`,
whereas #2/#3 name `Bootstrap-RustyNetWindows.ps1` at `char:149`. Its inner cause
is not in the ledger's `error_detail` and its report directory
(`/home/ubuntu-server/lab-reports/winnat-20260725T190000Z/`) lives on the
`ubuntu-kvm-1` host, which is **unreachable today** — both the tailnet endpoint
`100.117.1.47` and the LAN endpoint `172.23.56.5` time out on TCP/22.

So #5 is honestly **unresolved**, not merged into the WinGet finding. It may be
the same root cause surfacing one script later (plausible: `Install-` runs after
`Ensure-WingetConfigurationDependencies`, so a missing toolchain would surface
there), or it may be independent. Do not assume.

## 5. The diagnosability defect that kept CP-4 open for five weeks

This is the second code finding, and arguably the more valuable one, because it
explains why a cause sitting in plain text inside the report was recorded as
"unverified" for over a month.

The ledger's `error_detail` for #2 and #3 reads:

```
windows-utm-1: remote command failed (exit Some(1)): tBootstrap.winget.yml_x000D__x000A_
</S><S S="Error">At line:1 char:149_x000D__x000A_</S><S S="Error">+ ... \Rustynet'; &
'C:\Windows\Temp\rustynet-stage\Bootstrap-RustyNetWindo ..._x000D__x000A_</S>
<S S="Error">+                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```

Three things are wrong with this, all in code:

1. **Raw CLIXML reaches the ledger.** `AdapterError::Command` renders `stderr`
   verbatim at
   [`crates/rustynet-cli/src/vm_lab/orchestrator/error.rs:154-156`](../../../crates/rustynet-cli/src/vm_lab/orchestrator/error.rs).
   A CLIXML stripper **already exists** —
   `strip_powershell_clixml_noise`, `crates/rustynet-cli/src/vm_lab/mod.rs:35006` —
   but it is only applied on the `utmctl exec` path (`mod.rs:34973`), never on the
   SSH adapter path that `BootstrapHostsStage` uses. The fix is to route the SSH
   path through the stripper the repo already owns.
2. **The message is truncated from the front.** It begins mid-token
   (`tBootstrap.winget.yml`), so the first and most informative lines of the
   PowerShell error record are gone before the field is written.
3. **PowerShell's error record points at the invocation, not the cause.** The
   `char:149` caret underlines the outer `& 'C:\…\Bootstrap-RustyNetWindows.ps1'`
   call, because the script surfaces its failure via `Write-Error $_` at `:39`.
   The `FullyQualifiedErrorId` confirms it: `WriteErrorException,
   Bootstrap-RustyNetWindows.ps1`. The actual sentence naming the cause went to
   **stdout**, which the ledger records only as a trailing `[stdout: …]` note and
   which no triage tool surfaces.

Net effect: the operator-visible error says a script failed somewhere around
column 149, while `Configuration is not enabled. Run \`winget configure --enable\``
sat in the same log file, unread. Any Windows fix that does not also fix this
will simply produce the next unreadable error.

## 6. Fresh-evidence attempt — guest health of `windows-utm-1` (2026-08-28)

The CP-4 brief asks for a fresh minimal `--node` run that plans
`windows_stage_bootstrap`. **That run was not launched, deliberately.** The guest
cannot be reached, so the run's outcome is known in advance and launching it
would actively damage the evidence base. Findings, all measured today:

| Probe | Result |
| --- | --- |
| `utmctl` power state (pre-triage) | `stopped` |
| Power on | started via UTM; booted |
| ICMP `192.168.64.25` | **replies**, 2/2 packets, ~2.3 ms |
| TCP/22 (SSH) | **closed**, continuously, over 19 min of uptime |
| TCP/135 (RPC), 139 (NetBIOS), 445 (SMB) | **open** |
| TCP/3389 (RDP) | closed |
| TCP/5985 (WinRM) | closed |
| QEMU guest agent | not installed — `power_on_vm` fails with *"The QEMU guest agent is not running or not installed on the guest"* |
| Guest CPU after boot | ~0.7 %, i.e. idle at a login screen, not mid-boot |

**Interpretation.** Core Windows services (RPC/NetBIOS/SMB) are listening, so the
OS is fully booted and networked. The OpenSSH Server service is **not listening**.
Since RDP and WinRM are also closed and the QEMU guest agent is absent, there is
**no remote management path into `windows-utm-1` at all**.

Two consequences:

- **No remediation was applied.** The only remaining access path is the UTM
  graphical console, which is outside what this triage can do and outside
  "config-level remediation on the guest". The remediation is named precisely in
  §7 instead.
- **No fresh run was launched.** A `--node` run would fail at
  `verify_ssh_reachability`, which is upstream of `bootstrap_hosts` — producing a
  row where `bootstrap_hosts=skip` but, per §0(c), the `windows_stage_bootstrap`
  column would still read `fail`. That would be a **sixth spurious bootstrap
  failure** in the ledger, worsening exactly the miscount this document exists to
  correct. The guest-health evidence above is itself fresh, dated evidence and is
  decisive on its own.

`windows-x86-1`, the only other Windows guest, is on the unreachable
`ubuntu-kvm-1` host (§4), so no Windows guest is currently runnable.

**Disk headroom at triage time:** 190 GiB free on the repo volume, well above the
5 GiB threshold. Not a factor.

## 7. Remediation and the fix backlog

### 7.1 Guest remediation (not applied — requires console access)

On `windows-utm-1`, from the UTM graphical console as an administrator:

```powershell
# 1. Restore the remote management path the orchestrator needs.
Get-Service sshd | Set-Service -StartupType Automatic
Start-Service sshd
Get-NetFirewallRule -Name *OpenSSH-Server* | Enable-NetFirewallRule

# 2. Enable the WinGet feature the bootstrap depends on (§2).
winget configure --enable

# 3. Confirm the clock, since row #4 shows this fleet drifts (§1).
w32tm /resync
```

Then re-verify from the host: `nc -z 192.168.64.25 22`.

### 7.2 What the first Windows fix task should be

**Do the code fix, not the guest fix, first.** The guest fix is a prerequisite for
*testing* but resolves nothing durable — §2.3 shows every future guest reproduces
the failure.

Recommended order:

1. **W-FIX-1 (code, S) — make the WinGet Configuration precondition explicit and
   self-healing.** Add the feature's enabled state to
   `Get-WindowsBootstrapToolingState`, and in `Require-Winget` (or a new
   `Require-WingetConfiguration`) either enable it (`winget configure --enable`,
   the bootstrap already runs elevated) or throw a named, actionable error in the
   same style as the existing `winget.exe is not available; …` message. This is
   the change that turns a fresh Windows guest into a bootstrappable one, and it
   is a configuration/precondition fix inside the bootstrap script — not a
   redesign.
2. **W-FIX-2 (code, S) — apply the existing CLIXML stripper to the SSH adapter
   path** (§5, `error.rs:154-156` + `mod.rs:35006`), and stop truncating
   `error_detail` from the front. Cheap, and it is what makes every *subsequent*
   Windows failure diagnosable on the first read instead of the fifth week.
3. **W-FIX-3 (ledger, S) — stop run-scoped `preflight` failures poisoning the
   per-OS `*_stage_bootstrap` columns** (§0(c)). Affects Linux and macOS counts
   too, so it is not Windows-column work and can be owned separately. Until it
   lands, every published Windows/Linux/macOS bootstrap fail count is inflated.
4. **W-FIX-4 (guest/ops) — apply §7.1, then re-run** the minimal topology
   (`debian-headless-2:exit` + `windows-utm-1:client`, the smallest topology that
   satisfies preflight's "exactly 1 Exit node" rule and still plans
   `windows_stage_bootstrap`) to confirm W-FIX-1 and produce the first
   `windows_stage_bootstrap=pass` row in `--node` history.
5. **W-FIX-5 (ops) — restore `ubuntu-kvm-1`**, without which failure #5 (§4)
   cannot be closed and `windows-x86-1` (the CP-3 WinNAT candidate) is
   unavailable.

Only after W-FIX-4 produces a pass does the AcceptanceSpec §5.4 stability rule
apply (3-of-3 at a single clean commit) before any Windows cell below bootstrap
can be called proven.

### 7.3 Explicitly out of scope

The two standing Windows code gaps recorded in
`BashOrchestratorRetirementProgram_2026-08-22.md` — no gossip transport
(`windows.rs:157-160`, `DeferredPlatform`) and no self-issued signed bundles
(`windows.rs:288-311`, ephemeral local mint) — sit **behind** bootstrap and are
untouched by this triage. They cap Windows anchor/gossip cells regardless of
CP-4 and keep their existing disposition.

## 8. Evidence index

- Per-stage ledger: `documents/operations/live_lab_node_stage_results.csv`
  (filter `os_family=windows`; 5 runs, 75 rows).
- Run-matrix roll-up: `documents/operations/live_lab_node_run_matrix.csv`
  (188 rows; 5 with `windows_stage_bootstrap=fail`, 183 `not_run`).
- Failing stage logs, retained locally:
  `state/live-lab-direct-1784491409/logs/bootstrap_hosts.log`,
  `state/live-lab-direct-1784492687/logs/bootstrap_hosts.log`.
- `stage_triage_history(stage=windows_stage_bootstrap)` returns **"No attempts
  recorded"** — no fix has ever been attempted against this stage, so this is a
  first triage, not a repeat.
- Guest-health probes of `windows-utm-1`: §6, measured 2026-08-28.
