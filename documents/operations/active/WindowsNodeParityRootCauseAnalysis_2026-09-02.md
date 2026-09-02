# Windows Node Parity — Root-Cause Analysis on the `--node` Ledger (2026-09-02)

**Scope:** docs-only analysis. Subject: why the Windows guest cells (`windows-utm-1` = x64-emulated
UTM guest on the Mac; `windows-x86-1` = the Lenovo/x86 host guest) have never produced a `pass` on
the Rust `--node` live-lab engine, what exactly failed, which code path produced it, and what
remediation order unblocks the most downstream Windows cells.

**Relationship to prior work.** This doc builds on, and does not replace,
[`WindowsNodeBootstrapTriageVerdict_2026-08-28.md`](./WindowsNodeBootstrapTriageVerdict_2026-08-28.md)
(the CP-4 verdict) and
[`CrossPlatformRoleParityRefresh_2026-07-23.md`](./CrossPlatformRoleParityRefresh_2026-07-23.md)
§2 CP-4 / §4. The verdict doc triaged the same five ledger rows on 2026-08-28; this analysis
re-derives every claim independently from the primary evidence (per-stage CSV, triage JSONL, run
logs, source at HEAD and at the failing commits), adds the stage-level tabulation and the two
failure classes the verdict doc did not map to code (the clock-skew preflight gate and the cleanup
artifact collector), and produces a ranked remediation plan with offline-testable cores.

**Method / evidence standard.** The per-stage ledger
(`documents/operations/live_lab_node_stage_results.csv`, 36,666 rows) was parsed with the Python
`csv` module (quote-aware — never `awk -F,`, per AGENTS §12.3). The triage ledger
(`documents/operations/live_lab_stage_triage.jsonl`, 160 entries) was grepped for windows entries.
Run logs were read from the report dirs named in the CSV's `report_dir` column. Failing-commit
source was read with `git show <commit>:<path>`. Every quoted error string below is verbatim from
the ledger or the logs. Nothing here is inferred without a citation.

---

## 1. The complete Windows population of the `--node` ledger

All rows whose `alias` or `platform` contains `windows` (Python `csv` parse, 2026-09-02):
**185 rows across 5 runs, zero `pass` on any Windows-node stage other than run-setup plumbing.**
Per `(stage, status)` over those rows:

| status | stages |
|---|---|
| `fail` (5) | `preflight` ×2, `bootstrap_hosts` ×3 |
| `not_proven` (2) | `cleanup` ×2 |
| `pass` (15) | `preflight` ×3, `prepare_source_archive` ×3, `verify_ssh_reachability` ×3, `cleanup_hosts` ×3, `cleanup` ×3 — setup plumbing only; **no validation or role stage has ever run live on a Windows node** |
| `skip` (163) | every collect/distribute/validate/live/cross-network stage — all downstream of the bootstrap wall |

The five runs, oldest first (columns: run id, start, commit, alias, role, report dir):

| # | run_id | started_utc | commit | alias | role | report_dir |
|---|---|---|---|---|---|---|
| 1 | `livelab-1784489499-db3ff1aaafe6` | 2026-07-19T19:31:16Z | `db3ff1aaafe6` (dirty:worktree) | windows-utm-1 | client | `/Users/iwan/Desktop/Rustynet/state/live-lab-ll-1784489393278-23919-3` |
| 2 | `livelab-1784492387-db3ff1aaafe6` | 2026-07-19T20:05:03Z | `db3ff1aaafe6` (dirty:worktree) | windows-utm-1 | client | `/Users/iwan/Desktop/Rustynet/state/live-lab-direct-1784491409` |
| 3 | `livelab-1784493982-db3ff1aaafe6` | 2026-07-19T20:26:17Z | `db3ff1aaafe6` (dirty:worktree) | windows-utm-1 | client | `/Users/iwan/Desktop/Rustynet/state/live-lab-direct-1784492687` |
| 4 | `livelab-1785005557-b7667cce46db` | 2026-07-25T18:52:19Z | `b7667cce46db` (clean) | windows-x86-1 | exit | `/home/ubuntu-server/lab-reports/winnat-20260725T185101Z` |
| 5 | `livelab-1785006739-b7667cce46db` | 2026-07-25T19:01:17Z | `b7667cce46db` (clean) | windows-x86-1 | exit | `/home/ubuntu-server/lab-reports/winnat-20260725T190000Z` |

**No Windows-node row exists after 2026-07-25T19:01.** Every fix landed since (§3) is therefore
unproven live; the entire Windows column of the parity matrix is gated on one re-run.

Matching `live_lab_stage_triage.jsonl` windows entries (stub ids): `livelab-1784489499…::preflight`
(line 6), `livelab-1784492387…::bootstrap_hosts` (line 8), `livelab-1784493982…::bootstrap_hosts`
(line 9), `livelab-1785005557…::preflight` (line 50), `livelab-1785006739…::bootstrap_hosts`
(line 51) — all with `patch: null` except where noted below. (The JSONL also matches substrings
inside non-Windows rows, e.g. line 32's Debian build log that happens to name the
`rustynet-windows-native` crate; those are not Windows failures.)

---

## 2. The failures, individually — exact command + error, mapped to code

### F1 — Run 1, `preflight` fail: topology, not Windows

```
lab requires exactly 1 Exit node, found 0
```

Evidence: CSV row `livelab-1784489499-db3ff1aaafe6`/`windows-utm-1`/`preflight`, `stage_scope=topology`,
`error_detail` verbatim above; triage JSONL line 6. The launch elected `windows-utm-1:client` with no
exit node anywhere in the topology; the preflight topology gate (stage `preflight`,
`crates/rustynet-cli/src/vm_lab/orchestrator/stage/preflight.rs`) failed the run before any Windows
code ran. **Nothing Windows-specific happened in this run.** Same class as the verdict doc's
correction (1): a run that died upstream recorded a spurious Windows-adjacent row.

### F2 — Run 2, `bootstrap_hosts` fail: winget config file not found on the staging copy

Verbatim `error_detail` (CLIXML, front-truncated in the ledger — the tail that survives):

```
windows-utm-1: remote command failed (exit Some(1)): tBootstrap.winget.yml_</S><S S="Error">At line:1 char:149_</S><S S="Error">+ ... \Rustynet'; &amp; 'C:\Windows\Temp\rustynet-stage\Bootstrap-RustyNetWindo ...</S>… + CategoryInfo : NotSpecified: (:) [Write-Error], WriteErrorException + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,Bootstrap-RustyNetWindows.ps1
```

`stdout`: `[bootstrap] Defender exclusions skipped (opt-in disabled).`

The truncated head `tBootstrap.winget.yml` is the tail of `…RustyNetBootstrap.winget.yml`, and the
only `Write-Error`-class throw in `Bootstrap-RustyNetWindows.ps1` **at the failing commit** whose
message ends in that filename is
`git show db3ff1aaaf:scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1` line 1127:
`throw "WinGet configuration file not found: $candidate"`.
The failing command is the one-liner the adapter renders (the `char:149` caret points at the `&`
invocation), built by `build_windows_release_script` in
`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_install.rs`:
`Set-StrictMode -Version Latest; … & 'C:\Windows\Temp\rustynet-stage\Bootstrap-RustyNetWindows.ps1' -Phase build-release -RustyNetRoot 'C:\Rustynet' …`
— the bootstrap script is SCP'd **standalone** into the ephemeral staging dir, so its
`$PSScriptRoot`-relative default lookup for the winget yml found nothing.

**Already fixed, same day:** `7bb72149` 2026-07-19 "Fix Windows build-release invoking bootstrap
without its config paths". At HEAD the adapter passes the source-archive copies explicitly —
`build_windows_release_script` (`windows_install.rs:622-651`, comment block `:626-635` documents
this exact failure verbatim: "an unqualified invocation fails with \"WinGet configuration file
not found\"").

### F3 — Run 3, `bootstrap_hosts` fail: WinGet Configuration feature never enabled

Verbatim `stdout` (the smoking gun):

```
[bootstrap] Defender exclusions skipped (opt-in disabled).  Configuration is not enabled. Run `winget configure --enable` to enable it.
```

Verbatim `error_detail` tail: `…[Write-Error], WriteErrorException
+ FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,Bootstrap-RustyNetWindows.ps1`
at the same `char:149` invocation (command as F2).

At `db3ff1aaaf` the bootstrap ran `winget configure --file` unconditionally
(`git show db3ff1aaaf:scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1` has **zero**
occurrences of `Enable-WingetConfigurationFeature`; the throw at what is now the
`winget configure failed for RustyNet bootstrap configuration` site fires on winget's non-zero exit).
Root cause per the CP-4 verdict §2 (cited here, re-verified): a hard dependency on the opt-in,
per-machine WinGet **Configuration** feature that nothing enabled or checked.

**Already fixed:** `03483da6` 2026-08-28 "Fix Windows bootstrap CLIXML diagnosability and winget
Configuration precondition (W-FIX-1/W-FIX-2)" (+ tests in `575ea24f`). At HEAD,
`Enable-WingetConfigurationFeature` (`scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1:1209-1246`)
self-heals by running `winget configure --enable` (idempotent) before `winget configure --file`
(`Ensure-WingetConfigurationDependencies`, `:1248-1261`), and fails closed with a named, actionable
error (`:1240-1245`) when enabling is rejected. Regression test:
`bootstrap_script_enables_winget_configuration_feature_before_configuring`
(`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_install.rs:1827`).

### F4 — Run 4, `preflight` fail: guest clock skew — OPEN, no live re-proof

Verbatim `error_detail`:

```
windows-x86-1: guest clock skew is 3602s (maximum 90s; host=1785005541, guest=1785001939)
```

Evidence: CSV row `livelab-1785005557-b7667cce46db`/`windows-x86-1`/`preflight`, triage JSONL
line 50. Code path: `validate_clock_skew`
(`crates/rustynet-cli/src/vm_lab/orchestrator/stage/preflight.rs:55-64`) — a pure, fail-closed
gate comparing the guest's reported Unix time to the host's, tolerance 90 s. The remote time is
obtained via `parse_remote_unix_time` (`preflight.rs:47-53`) with a transient-failure retry helper
(`retry_transient`, `:26-45`); there is **no repair path and no remedy text** — a drifted guest just
fails the run.

The skew is 3602 s ≈ exactly one hour, on the x86-emulated Windows guest on the remote host. That
magnitude is the classic RTC/timezone-interpretation offset (Windows historically stores local time
in the RTC; a hypervisor presenting UTC shifts the guest by the TZ offset), not gradual drift — but
**the actual mechanism on `windows-x86-1` is unverified** because the report dir lives on the
`ubuntu-kvm-1` host, which was unreachable at the 2026-08-28 triage (verdict doc §4) and whose
current state is unknown (see §5). Classification: **lab-environment primary** (guest clock/RTC
setup), with an **orchestrator-hardening gap** (no self-heal or actionable remedy in the error).

### F5 — Run 5, `bootstrap_hosts` fail: arm64 signtool selected on an x86 host

Verbatim `stdout`:

```
[install-helper] authenticode: using signtool at C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\arm64\signtool.exe
[install-helper] authenticode: minting new code-signing cert
[install-helper] authenticode: added code-signing cert to LocalMachine\Root
```

Verbatim `error_detail` tail: `…[Write-Error], WriteErrorException
+ FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,Install-RustyNetW
   indowsService.ps1` at `char:108` — i.e. the `& 'C:\Windows\Temp\rustynet-stage\Install-RustyNetWindowsService.ps1 …`
invocation rendered by `build_windows_service_install_script`
(`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_install.rs:654-670`).

The stdout proves the cause: the Windows SDK's **arm64** `signtool.exe` was picked on the x86 host,
where it cannot execute; the subsequent sign step wrote the error. Code path at the failing commit:
the install helper's signtool discovery had no architecture filter
(`git show b7667cce46:scripts/bootstrap/windows/Install-RustyNetWindowsService.ps1`).

**Already fixed:** `003d5edc` 2026-07-26 "bootstrap(windows): select a signtool.exe that can run on
the host architecture". At HEAD, `Resolve-RustyNetSigntoolPath`
(`scripts/bootstrap/windows/Install-RustyNetWindowsService.ps1:1076-1136`, "shared signtool
resolver") maps the host architecture to the matching SDK directory in every branch and throws a
named error (`:1104`, `:1140-1144`) when no runnable signtool exists; the resolver's comment block
(`:1053-1076`) cites this exact run (`winnat-20260725T190000Z`). Note also `d6ee2968` (QH-28,
2026-07-27) removed the self-signed-root-CA minting this stdout shows, so the whole failure surface
is now behind an opt-in flag.

### F6 — Runs 4+5, `cleanup` `not_proven`: artifact collector crashes on an empty log dir (recurring, post-failure only)

Verbatim `error_detail` (identical in both runs):

```
pre-cleanup diagnostics failed: collect failure artifacts for 'windows-x86-1': remote command failed (exit Some(1)): …<S S="Error">The property 'Count' cannot be found on this object. Verify that the property exists._…</S><S S="Error">+ ... Net\keys\*' } } else { @() }; if ($filesToArchive.Count -gt 0) { Comp …</S>    + CategoryInfo : NotSpecified: (:) [], ParentContainsErrorRecordException_    + FullyQualifiedErrorId : PropertyNotFoundStrict
```

Code path: the artifact-collection one-liner built in
`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_traffic.rs` (the diagnostics collector
the cleanup stage runs per node). At the failing commit (`git show
b7667cce46:crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_traffic.rs`, lines 257-262)
it read:

```powershell
$filesToArchive = if (Test-Path -LiteralPath $logsDir) { Get-ChildItem … } else { @() }
if ($filesToArchive.Count -gt 0) { … }
```

Under `Set-StrictMode -Version Latest` (the one-liner's own first statement), a `$logsDir` that
**exists but contains no matching files** makes PS 5.1's `Get-ChildItem` return `$null`, assigns
`$filesToArchive = $null`, and `$null.Count` raises `PropertyNotFoundStrict` — exactly the observed
`FullyQualifiedErrorId`. Both runs that hit it had just failed `bootstrap_hosts`/`preflight`, i.e.
no logs existed yet; the collector meant to degrade to an empty zip and instead turned "bootstrap
failed" into "bootstrap failed AND diagnostics uncollectable".

**Already fixed:** `45d27d56` 2026-07-26 "live-lab: stop Windows artifact collection throwing on an
empty log directory" — the array subexpression wrapper at HEAD
(`windows_traffic.rs:485-488`: `$filesToArchive = @(if (Test-Path …) { … } else { @() })`) forces an
array, with content-pin tests at `windows_traffic.rs:1260` and `:1274`.

---

## 3. Classification

| # | Failure | Class | Status at HEAD |
|---|---|---|---|
| F1 | Run 1 preflight "exactly 1 Exit node, found 0" | **launch/topology config** (not a Windows defect) | n/a — launch-time choice |
| F2 | Run 2 bootstrap "WinGet configuration file not found" | **orchestrator defect** (adapter shipped the bootstrap script without its config siblings) | **fixed** `7bb72149`; unproven live |
| F3 | Run 3 bootstrap "Configuration is not enabled" | **both**: code (bootstrap hard-depended on an opt-in feature) + guest (feature off on `windows-utm-1`) | **fixed** `03483da6` (W-FIX-1); unproven live |
| F4 | Run 4 preflight clock skew 3602 s | **lab-environment** (guest RTC/time source) + **orchestrator-hardening gap** (fail-only gate, no remedy/self-heal) | **OPEN** |
| F5 | Run 5 bootstrap arm64 signtool on x86 | **orchestrator/install-helper defect** (architecture-blind SDK path selection) | **fixed** `003d5edc`; unproven live |
| F6 | Runs 4+5 cleanup `PropertyNotFoundStrict` | **orchestrator defect** (diagnostics collector) | **fixed** `45d27d56`; unproven live |

**Product layer: zero evidence of a `rustynetd` / `rustynet-windows-native` defect.** Every failure
above is at the orchestrator/bootstrap/diagnostics layer, before the daemon is ever installed or
launched — no Windows row has ever reached `validate_baseline_runtime` or beyond, so the product's
Windows behaviour remains **unproven, not failed**. (This matches the parity Refresh doc's framing:
Windows parity is ~0% *proven* on the engine of record.) The one product-adjacent design refusal on
record is `live_managed_dns_validation`, which fails a Windows guest up front because the validator
reads bundles over `sudo`/`sh -lc` from a POSIX state root (triage JSONL line 67, patch note of run
`livelab-1786636166-625856314ca5`) — a known stage limitation, listed in §5.

---

## 4. Ranked remediation plan

Ordering principle: what unblocks the most downstream Windows cells first. Every Windows validation
stage (`collect_pubkeys` onward) is downstream of one green `bootstrap_hosts`; F4 additionally gates
the run before any stage at all.

### R1 — Land the first `windows_stage_bootstrap=pass` (unblocks: all 163 skipped cells) — **effort M, operator + ops**

The code half of the wall is already fixed (F2/F3/F5/F6 above; W-FIX-1 landed). What remains is the
guest/ops half, exactly the verdict doc's W-FIX-4/W-FIX-5, restated here with the current failure
map: either (a) restore `windows-utm-1`'s remote management path from the UTM console — as of
2026-08-28 it answers ICMP with RPC/NetBIOS/SMB up but TCP/22, 3389, 5985 all closed and no QEMU
guest agent (verdict doc §6) — then run the minimal `debian-headless-2:exit` + `windows-utm-1:client`
topology; or (b) restore `ubuntu-kvm-1` reachability and re-run `windows-x86-1:exit`
(`winnat-*` shape), which additionally exercises the F4 clock path first.

Offline-testable core (already in tree, verify green before spending lab time):
`bootstrap_script_enables_winget_configuration_feature_before_configuring`
(`windows_install.rs:1827`) and the content-pin tests over the `include_str!`-embedded scripts
(`windows_install.rs:1736-1739`, `:2059-2076`; `windows_traffic.rs:1260-1336`). The live-lab proof
stage is `bootstrap_hosts` (node scope) — the first `pass` row in that column ever.

### R2 — Clock-skew hardening (unblocks: `windows-x86-1` runs; hardens every guest) — **effort S, code**

`validate_clock_skew` (`preflight.rs:55-64`) is already a pure function — extend the offline core:
a `propose_clock_remediation(host, guest, max)` style pure helper (returns drift direction, whether
the skew is consistent with a whole-hour TZ/RTC offset, and the exact remedial action text), unit
tests for the ≤90 s pass, >90 s fail, and hour-offset classification cases, plus a negative test
that the gate still fails closed on unparseable remote time. Then either keep preflight fail-only
but append the remedy to the error, or add an explicit, logged `w32tm /resync` self-heal attempt for
Windows guests before re-checking (one hardened path, no silent continue). Live-lab proof stage:
`preflight` on a re-run `windows-x86-1` topology (R1 option b), where the real skew value and
mechanism become observable — today they are not.

### R3 — Keep F6 fixed under test and prove it live — **effort S, code+lab**

The `@()` wrapper fix (`45d27d56`) has content-pin tests; add the behavioural case as a pure
builder-level test if the renderer exposes one (empty-input → `@()` branch → empty-zip literal,
`windows_traffic.rs:527-528`), then confirm on the next Windows run that a post-failure `cleanup`
records `pass` (not `not_proven`) even when the node produced no logs. Live proof: `cleanup` stage
of the R1 run.

### R4 — Signtool resolver + CLIXML diagnosability: no further code; prove live — **effort 0 (code) / folded into R1**

F5's resolver and W-FIX-2's CLIXML handling are landed and tested; they need only the R1 re-run to
flip from fix-landed to lab-proven. If any future Windows bootstrap failure again surfaces raw
CLIXML in `error_detail`, re-open W-FIX-2 (`strip_powershell_clixml_noise` coverage on the SSH
adapter path) rather than re-triaging from scratch.

### R5 — Windows exit cell (CP-3) — **effort: external, hardware**

`promote_windows_exit_active` needs `MSFT_NetNat`/HNS, which cannot run in UTM on Apple Silicon;
requires a physical Windows 11 Pro/Ent-on-ARM device (Refresh doc §2 CP-3). Not addressable by code
or the current fleet. Runs 4 and 5 — both role `exit` — were evidently the attempt to exercise this
cell on the x86 host; they never got past preflight/bootstrap, so **the WinNAT question itself
remains untested**, not failed.

### R6 — Defer-and-track: stage-level Windows refusals — **effort M, design follow-up**

`live_managed_dns_validation`'s up-front Windows refusal (§3) and the `validate_windows_*` posture
trio's coverage gap (adversarial live custody/secrets tests, GAP-6 design
`LiveLabCrossPlatformCustodySecretsAclStageDesign_2026-09-01.md`) gate specific downstream cells,
not the bootstrap wall. Schedule after R1 produces the first green bootstrap; do not let them gate
it.

---

## 5. Unknown / needs a live probe (explicitly not evidence)

1. **Current clock state of both Windows guests** — whether `windows-x86-1` still reads ~1 h behind
   host time (F4) and whether `windows-utm-1`'s clock is healthy. The 3602 s value is one sample
   from 2026-07-25; the mechanism (RTC-localtime vs true drift) is unconfirmed.
2. **`ubuntu-kvm-1` reachability** — the host holding runs 4-5's report dirs
   (`/home/ubuntu-server/lab-reports/winnat-*/logs/{preflight,bootstrap_hosts,cleanup}.log`) was
   unreachable at the 2026-08-28 triage (verdict doc §4); its current state, and therefore whether
   the F4/F5/F6 raw logs can be re-read for fuller context, is unknown from this machine.
3. **Whether the current tree passes `bootstrap_hosts` on a healthy Windows guest** — W-FIX-1
   (`03483da6`) and the F2/F5 fixes are unit/content-pin-tested only; no `--node` run has exercised
   them. This is the single highest-value live probe (R1).
4. **`windows-utm-1` remote-management restorability** — whether TCP/22 can be re-enabled from the
   UTM console (or the guest needs a template rebuild), and what the guest's WinGet Configuration
   feature state is today; both were last observed 2026-08-28 (verdict doc §6).
5. **WinNAT behaviour on `windows-x86-1`** — CP-3's core question has never been reached by any run;
   nothing is known about `MSFT_NetNat` on that host beyond the installability assumption.
6. **Downstream Windows behaviour** (`enforce_baseline_runtime`, `validate_baseline_runtime`,
   traffic, role cells) — zero rows of any status; there is no failure evidence and no pass
   evidence. The first run past bootstrap will be generating first-of-kind signal, and per the
   Refresh doc's JOIN note it should be planned as "run once and triage", not "make it green".

---

## 6. Evidence index

- `documents/operations/live_lab_node_stage_results.csv` — rows quoted in §1/§2 (parsed with Python
  `csv`; window = `alias`/`platform` contains `windows`; 185 rows / 5 runs).
- `documents/operations/live_lab_stage_triage.jsonl` lines 6, 8, 9, 50, 51 (windows stubs), 67
  (managed-DNS Windows refusal patch note).
- Run logs: `state/live-lab-direct-1784491409/logs/bootstrap_hosts.log` (run 2, one line — same
  CLIXML as the ledger), `state/live-lab-direct-1784492687/logs/bootstrap_hosts.log` (run 3, same);
  runs 4-5 logs are on `ubuntu-kvm-1` (see §5.2). Stage logs carry no content beyond the CSV
  `error_detail`.
- Source at failing commits: `git show db3ff1aaaf:scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1`
  (`:1127` throw), `git show b7667cce46:crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_traffic.rs`
  (`:257-262` unwrapped assignment).
- Source at HEAD: `preflight.rs:47-64` (clock gate), `windows_install.rs:622-651` (config-path
  fix), `windows_install.rs:654-670` + `Install-RustyNetWindowsService.ps1:1053-1144` (signtool
  resolver), `Bootstrap-RustyNetWindows.ps1:1209-1261` (W-FIX-1), `windows_traffic.rs:475-529`
  (artifact collector), with tests at `windows_install.rs:1827` and `windows_traffic.rs:1260-1336`.
- Fix commits: `7bb72149` (2026-07-19), `45d27d56` (2026-07-26), `003d5edc` (2026-07-26),
  `d6ee2968` (2026-07-27, QH-28), `03483da6` + `575ea24f` (2026-08-28, W-FIX-1/W-FIX-2).
- Prior analysis: `WindowsNodeBootstrapTriageVerdict_2026-08-28.md` (§1-§9, W-FIX backlog and
  dispositions), `CrossPlatformRoleParityRefresh_2026-07-23.md` §2 CP-4, §3 Track W, §4 table.
