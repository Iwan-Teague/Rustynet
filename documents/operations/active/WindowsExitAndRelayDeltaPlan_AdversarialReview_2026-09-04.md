# Adversarial Review — WindowsExitAndRelayDeltaPlan_2026-05-10.md

**Status: UNTRUSTED** — machine-generated adversarial review (docs-only; no code changed). Reviewed `documents/operations/active/WindowsExitAndRelayDeltaPlan_2026-05-10.md` (1227 lines) against the working tree at commit `816562e5` (branch `ai-edit/edit-1788552400960-26537-17`, 2026-09-04). Every file:line, symbol, and SHA below was re-verified by grep/`git cat-file` against this tree immediately before writing; line numbers are as-of this commit and will drift. The plan's own §11 ledger was written 2026-05-10 → 2026-05-24; the tree has moved far past it.

**One-line verdict:** The plan's substance is real — every structural claim (exit NAT/killswitch/DNS/NRPT machinery, relay service hardening, orchestrator stages) landed and is verifiable in the tree — but essentially every line number has drifted, one named symbol (`WINDOWS_PS_DETECT_DEFAULT_EGRESS_INTERFACE`) no longer exists anywhere, several "remaining" items (§A.4 subcommands, §E.1 tamper tests, §E.4 DPAPI self-test) are in fact DONE and the plan never credited them, and §E.2 (peer-map wire bump) plus the §D posture promotion remain genuinely open.

---

## 1. Plan claims vs tree reality — findings

Severity: **HIGH** = a reader would act wrongly on the claim; **MED** = citation wrong but findable; **LOW** = cosmetic drift.

### 1.1 Symbols the plan cites that DO exist (stale line numbers only)

The plan's file:line cites are uniformly stale (the plan was written against the 2026-05-10 tree). All of the following symbols exist today at different lines — the claims are substantively correct, the coordinates are not:

| Plan cite | Symbol | Actual location (816562e5) |
| --- | --- | --- |
| ~2770 | `apply_windows_exit_nat_forwarding` | `crates/rustynetd/src/phase10.rs:5950` |
| :2845 | `WINDOWS_PS_ASSERT_KILLSWITCH` | `crates/rustynetd/src/phase10.rs:6080` |
| ~3456 | `apply_dataplane_generation` | `crates/rustynetd/src/phase10.rs:7155` |
| :4509 | `validate_windows_interface_alias` | `crates/rustynetd/src/phase10.rs:8757` |
| :4531 | `validate_windows_nat_prefix` | `crates/rustynetd/src/phase10.rs:8788` |
| :413 | `establish_session` | `crates/rustynet-relay/src/transport.rs:450` (plus `establish_session_with_round_trip` at :487 — the plan does not mention the round-trip variant) |
| :10995 | `select_runtime_relay_candidate_with_verified_fleet` | `crates/rustynetd/src/daemon.rs:16594` |
| :2947 | `verify_signed_endpoint_hint_bundle` | `crates/rustynet-control/src/lib.rs:3215` |
| :2552 / :2577 | `signed_peer_map` / `verify_signed_peer_map` | `crates/rustynet-control/src/lib.rs:2552` / `:2577` (these two happen to still match) |

Relay service-hardening helpers (plan §B) all exist in `crates/rustynet-relay/src/main.rs`: `load_windows_relay_service_args` :2102, `parse_windows_relay_env_file` :2453, `evaluate_windows_relay_service_hardening` :2675, `build_windows_relay_service_hardening_report` :2873, `run_windows_relay_service_host` :3122; the `windows-relay-service-hardening-check` subcommand dispatches at main.rs:1981 with loopback-only `--health-bind` validation at :262-265. `MAX_CLOCK_SKEW_TOLERANCE_SECS` is at `crates/rustynet-relay/src/transport.rs:91`. The orchestrator helper test `windows_relay_service_helpers_exist_and_keep_reviewed_roots` is at `crates/rustynet-cli/src/vm_lab/mod.rs:41163`. **Severity: MED** (every one requires a re-grep to use).

### 1.2 `WINDOWS_PS_DETECT_DEFAULT_EGRESS_INTERFACE` — GONE (HIGH)

The plan §2.1 states this constant lives in `daemon.rs`. It does not exist anywhere in the repository (`rg` across the whole tree: zero hits). Egress-interface selection evidently moved to a reviewed, parameterized model: `WINDOWS_PS_PREFLIGHT_EXIT_SERVING` (`crates/rustynetd/src/phase10.rs:6029`) takes `$TunnelAlias`/`$EgressAlias` as PowerShell parameters, validates administrator elevation, requires `Get-NetRoute -DestinationPrefix '0.0.0.0/0'` on the egress alias, and rejects `$TunnelAlias -eq $EgressAlias`. The plan's description of how egress detection works is **stale architecture, not just stale lines**. Anyone debugging "why did exit serving pick interface X" should read the parameterized preflight, not hunt for the deleted constant.

### 1.3 §A.4 verifier subcommands — DONE, plan understates (MED)

Both `windows-killswitch-assert` (dispatch `crates/rustynetd/src/main.rs:383-384`, impl `run_windows_killswitch_assert_command` main.rs:2842; landed in commit `dc614ce`) and `windows-dns-failclosed-check` (main.rs:377, module `windows_dns_failclosed`) exist. `WINDOWS_PS_ASSERT_KILLSWITCH` (phase10.rs:6080) now verifies rules **by DisplayName** and additionally asserts every firewall profile's `DefaultOutboundAction -eq 'Block'` — it supersedes the plan's `name=`-based rule-text sketch (matches commit `1860106`). Also present: `WINDOWS_PS_ASSERT_NAT` (:6077), `WINDOWS_PS_ASSERT_FORWARDING_ENABLED` (:6078), `WINDOWS_PS_ASSERT_DNS` (:6084), and the live-OS-state assertion design note (phase10.rs:6069-6075, "QH-29 coupling note"). Generation-invariant unit tests exist at phase10.rs:15303/15349/15410; `force_fail_closed` at phase10.rs:7747.

### 1.4 §E.1 bundle-tamper tests — DONE via `8d5de44`, not credited as E.1 (MED)

All four tests exist in `crates/rustynetd/src/daemon.rs`: `load_auto_tunnel_bundle_rejects_sig_tamper_at_reload` :26142, `load_auto_tunnel_bundle_rejects_equal_watermark` :26200, `load_relay_fleet_bundle_accepts_signed_fleet_and_rejects_tamper` :26540, `load_relay_fleet_bundle_rejects_replay_and_stale` :26577. Commit `8d5de44` ("activate auto-tunnel tamper reload coverage") landed the first pair; the plan's §11 never marks §E.1 closed against it. Config plumbing exists: `relay_fleet_bundle_path` daemon.rs:2579, load path :5087-5101.

### 1.5 §E.4 DPAPI startup self-test — DONE (via `9394053`) (MED)

`crates/rustynet-crypto/src/key_material.rs:89` holds `static WINDOWS_DPAPI_STARTUP_SELF_TEST: OnceLock<Result<(), String>>` — the fail-closed startup self-test the plan lists as work. Marked DONE.

### 1.6 §E.2 peer-map wire bump — genuinely OPEN (LOW, status correct)

No `PEER_MAP_WIRE_VERSION`, `peer-map v2`, or `peer_map_version` symbol exists in `crates/rustynet-control/src/lib.rs` (the v2→v3 bump never landed). Note at lib.rs:7048 references the unknown-version rejection test only. Plan's "open" status is correct.

### 1.7 §E.3 relay benchmarks + §E.5 cargo-fuzz for `decode_helper_request` — OPEN (LOW)

No `crates/rustynet-relay/benches/` directory. `fuzz/` contains only `ipc_parse_command`, `membership_decode_state`, `membership_decode_signed_update` — no relay helper target. Commit `38525a1` added a no-panic regression test instead of a fuzz target, so the *panic-safety* concern is partially covered, but the plan's literal ask (cargo-fuzz) is not done. Status "open" correct.

### 1.8 §C.1 linux-only gate — DONE/obsolete, plan cites dead call sites (MED)

`ensure_live_lab_profile_linux_only` is still *defined* at `crates/rustynet-cli/src/vm_lab/mod.rs:27329` but has **no active call sites** (only doc-comment mentions at mod.rs:27186 and :27204). The plan cites it at old lines 4681/4762 as an active gate. The enforcement the plan wanted now lives elsewhere (per-node role/platform election in the `--node` engine); the function is dead code. Either the gate landed in a different mechanism (research per-run if you need the live equivalent) or the concern was retired with the bash orchestrator (W5.7) — do not "re-enable" the dead function without checking which.

### 1.9 §A.5/A.6 artifacts — no live-proof artifacts landed (MED)

`artifacts/` contains **no** `windows_exit/` or `windows_relay/` directories. The plan's §A.5 three orchestrator stages / §A.6 cross-network live-proof closure have no committed evidence. Combined with `documents/operations/PlatformSupportMatrix.md` (Windows still `runtime-host-capable only` at lines 16, 110, 154; Windows exit row "gated on D7 NetNat + killswitch evidence"), §Track D posture promotion is correctly still open. `documents/operations/active/WindowsWorkingNodePlan_2026-04-17.md` also remains in active/ (not archived), consistent with the work not being closed.

### 1.10 All 34 §11 ledger SHAs verified real (LOW, credit where due)

Every commit SHA in the plan's §11 progress ledger resolves via `git cat-file` and its subject matches the ledger description: 0c3d78e, 0cabab0, 2439f42, 80164f8, 0fa8faf, 9283b72, 3f5432f, ceeda2a, afa6476, 38ac236, 022d2b0, 8d5de44, dc614ce, 9394053, 38525a1, d9823b9, dff6fcf, 0a699e2, 32fa4fa, f43ef30, 0574a4d, 0d321ad, bbd7d1a, e4c3653, cb3b99f, 1f7eb02, 6339c64, 1860106, a92d4ff, cb00565, 65b867e, c61f4a4, 2530ed7, 770b2ac. Zero fabricated SHAs. The final row (`770b2ac`, 2026-05-24, "wire Windows backend autoselect and macOS relay dispatch") postdates the plan's own base, showing the ledger was kept current *through* May — it simply has not been touched since.

### 1.11 Cross-referenced plan docs — wrong filename (LOW)

The plan's §B Step 3 references the os-agnostic orchestrator plan as `..._2026-04-29.md`; the actual file is `documents/operations/active/OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md`. In `PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md` (~lines 750-780) the Phase C/D relay checkboxes remain `- [ ]` unchecked with "In progress 2026-03-30" notes (failover/failback/roaming open); only the active-path consent/liveness box is `[x]`.

### 1.12 Fail-closed posture — intact, and stronger than the plan describes (verified, no findings)

The plan's proposed work never weakens a fail-closed control, and the current tree is *stricter* than the plan's text: `WINDOWS_PS_REQUIRE_EXIT_CMDLETS` (phase10.rs:6026) now **fails closed on a missing WinNAT WMI provider** (`Get-CimClass MSFT_NetNat` in `root/standardcimv2`, throw on absence) in addition to cmdlet presence; `WINDOWS_PS_PREFLIGHT_EXIT_SERVING` (:6029) adds an explicit administrator-token check. `validate_windows_nat_prefix` (:8788) still rejects non-RFC1918/IPv6 NAT prefixes (IPv6 fail-closed intact, §A.7 deference holds). Windows `WINDOWS_IPV6_RULE_BLOCK_LAN` (:6021) blocks all IPv6 LAN egress because the tunnel is IPv4-only. The non-exit residue plan (`windows_exit_nat_residue_plan`, phase10.rs:6033) forces forwarding back to Disabled on both interfaces when a generation stops serving exit. Nothing here should be "relaxed" to make an install succeed — see §2.4.

---

## 2. Current Windows bootstrap/install path (for the active Windows-11 debug)

This section is the map of what actually exists and runs today. All paths verified at `816562e5`.

### 2.1 `scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1` (1981 lines) — what `-Phase build-release` builds

Three artifacts, in order (lines ~1691-1783):

1. **Daemon**: `cargo build --locked --release -p rustynetd` (`$daemonBuildArgs`, :1701). Throws `cargo build failed for Windows daemon build-release` on failure.
2. **Trust CLI**: `cargo build --locked --release -p rustynet-cli --bin rustynet-windows-trust-cli` (:1702), with an `--offline` retry variant (:1710). The comment at :1695 states the reason: **rustynet-cli's default `main.rs` binary remains Unix-oriented** — the whole `vm-lab`/orchestrator surface is default-off (RNQ-17) and the shipped CLI does not target Windows. The only Windows-runnable `rustynet-cli` binary is `crates/rustynet-cli/src/bin/rustynet-windows-trust-cli.rs` (exists; the only windows/trust bin in that directory) — a trust-evidence-only CLI, not the full `rustynet` CLI.
3. **Relay**: `cargo build --locked --release -p rustynet-relay --features daemon` (:1703).

It then verifies `expectedBinary = Join-Path $InstallRoot 'rustynetd.exe'` (:1821). **Debug takeaway:** if your Windows-11 box fails at build-release, the failure is one of these three cargo invocations; the trust-CLI leg is the one that can fail confusingly because it builds a *subset* of `rustynet-cli`, and an offline guest needs the `--offline` retry (registry cache must be seeded — see the lab-state `seed_cargo_cache` flow) to succeed.

### 2.2 `scripts/bootstrap/windows/Install-RustyNetWindowsService.ps1` (1716 lines) — what it does and every Write-Error/throw gate

Fail-closed validations, all throwing before any mutation:

- Service name: empty / >128 chars / non-ASCII → throw (:102-108). Node-id validation (:115-121). SSH allow-CIDR validation (:139-142).
- **Fixed roots**: install root must be `C:\Program Files\RustyNet` (:150), state root `C:\ProgramData\RustyNet` (:158). A non-default install location is not supported — do not "fix" a debug failure by relocating.
- ACLs: `sc.exe sidtype` (:517); `icacls` setowner/inheritance/grant each throw (:536-630); `sc.exe failure` config (:650).
- `Build-ReviewedDaemonArgsJson` rejects an unknown `--backend` label (:696). `netsh` interface validation (:787). DNS fail-closed posture config failure (:821).
- Binary presence: `rustynetd.exe was not found under the Windows release output directory` (:855/:858); `rustynet CLI binary not found` (:882) — this is the **trust CLI** from §2.1, so a build-release that skipped the trust-CLI leg surfaces here; `rustynet-relay.exe not found` (:888).
- Main wraps everything in try/catch → `Write-Error $_` (:223); any failure = non-zero exit, no partial install.

### 2.3 Exit/relay service scripts (the delta-plan deliverables)

- **`Install-RustyNetWindowsExitService.ps1` (102 lines)** — this is Track B Step 3 (B1.4), and it is **preflight only**: it enables IPv4 forwarding on every IP-bound interface (`Set-NetIPInterface -Forwarding Enabled`), writes the reviewed install report to `C:\ProgramData\RustyNet\install-evidence\rustynet-exit-install.json`, and validates the fixed roots (:34/:42). The header comment states explicitly that the runtime exit lifecycle (NetNat, firewall killswitch, default-route programming) is **owned by the rustynetd Windows service, not this script** — "one hardened execution path per security-sensitive flow, per AGENTS.md." Fail-closed: any per-interface failure → `status=fail` + throw `RustyNet Windows exit preflight failed for N interface(s)` (:99). **Debug takeaway:** this script succeeding does NOT mean exit serving works; it only means forwarding is enabled and evidence was written. The real NAT/killswitch application happens in-daemon via the `phase10.rs` payloads (§1.12).
- **`Install-RustyNetWindowsRelayService.ps1` (538 lines)** — service name must be exactly `RustyNetRelay` (:51); fixed roots (:58/:65); relay paths confined under `C:\ProgramData\RustyNet\relay` with traversal-segment rejection (:75-96); relay id 1-16 ASCII (:93); endpoint IPv4:port, loopback-only (:107-118); port range 1..65535 with start<end (:125-130); **signtool required**: per-arch selection (:203), `signtool.exe not found under any Windows SDK path` (:240), relay binary must exist to be signed (:257), `signtool sign` failure (:309); icacls/sc.exe failure+sidtype (:323-376); main `Write-Error` (:418); health-bind port must differ from the relay UDP control port (:432); `rustynet-relay.exe was not found under release output` (:438); **`relay verifier key must exist before service install`** (:441); `sc.exe delete` first (:484); `New-Service -Name RustyNetRelay -StartupType Automatic` (:495). **Debug takeaway:** the two most common Windows-11 failures here will be a missing Windows SDK signtool and a missing verifier key — both are hard throws by design.
- Uninstallers exist for all three (`Uninstall-RustyNetWindowsService` 352, `Uninstall-ExitService` 92, `Uninstall-RelayService` 163 lines).

### 2.4 What the lab orchestrator does with all this (the `-Phase build-release` manifest flow)

`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_install.rs` (2522 lines) is the remote driver:

- Fixed expectations: `WINDOWS_RUSTYNETD_PATH = r"C:\Program Files\RustyNet\rustynetd.exe"` (:17); trust evidence at `C:\ProgramData\RustyNet\trust\rustynetd.trust` (:43); build-release manifest at `C:\Windows\Temp\rustynet-stage\build-release\manifest.json` (:77).
- `install_daemon` ships source via `tar.exe` then runs `Bootstrap-RustyNetWindows.ps1 -Phase build-release -RustyNetRoot {workdir}` (:278; script builder :631; invocation :653). Build budget is overridable via `RUSTYNET_WINDOWS_BUILD_TIMEOUT_SECS` (:66/:227) and a budget timeout is *relabeled*, not hidden, by `classify_windows_build_outcome` (:255). Remote `rustynetd.exe not found` check (:426).
- `enforce_daemon` patches `C:\ProgramData\RustyNet\config\rustynetd.env` into enforce mode (:450/:521/:526). `start_daemon`/`stop_daemon`/`restart_daemon`/`uninstall_daemon` (:562-588).
- `run_windows_e2e_bootstrap` runs `rustynetd key init --passphrase-file` + membership init remotely (:921, :1057-1068).
- Readiness fragments: service-install script builder (:663), start-probe (:690), ACL repair (:716), native helper (:740), tunnel-IP readiness (:848), and daemon-status readiness that **requires the reviewed env file to be present** (:876-883).

`crates/rustynet-cli/src/vm_lab/bootstrap/windows.rs` (4102 lines) is the phase machinery: `BootstrapPhase` enum (SyncSource/BuildRelease/SmokeServiceHost/InstallRelease/RestartRuntime/VerifyRuntime/TunnelSmoke/KillswitchSmoke/DnsSmoke/Ipv6Smoke/All); `phase_requires_proven_access` gates BuildRelease..Ipv6Smoke (:19-29) with `render_windows_access_gate_error` (:33). The build-release result validator is **fail-closed on the manifest**: missing manifest (:113-115), missing `complete.marker` (:121), empty manifest (:129), each required field `phase/status/reason/report_root/stdout_path/stderr_path/exit_code_path/toolchain_path/manifest_path/complete_marker_path` (:132-135), `phase` must equal `build-release` (:138), report-path agreement (:142-148), missing report file (:152), and it records `build-release-wrapper-fallback` notes (:173). `-Phase` is passed via `build_bootstrap_script_invocation` (:200-206); service-install invocation :260; service-host smoke :279; `format_windows_phase_failure_with_diagnostics` :185.

**Debug takeaway for the active Windows-11 issue:** the chain is orchestrator → `Bootstrap -Phase build-release` (3 cargo builds) → manifest+complete.marker under `C:\Windows\Temp\rustynet-stage\build-release\` → `Install-RustyNetWindowsService.ps1` (fixed roots, trust CLI + relay exe + daemon exe all required) → `enforce_daemon` env patch → daemon-status readiness gated on the reviewed env file. A failure naming `manifest.json`/`complete.marker` means the *build* phase did not finish cleanly even if cargo printed nothing fatal to the captured stream; a failure naming a missing exe under `C:\Program Files\RustyNet` means install ran against an incomplete build output. Note `WINDOWS_PS_REQUIRE_EXIT_CMDLETS` (phase10.rs:6026, invoked at :5952) hard-fails exit serving on hosts lacking the WinNAT/HNS `MSFT_NetNat` WMI class — a stock Windows-11 Home/Pro client without HNS will throw exactly `RustyNet exit serving requires the Windows WinNAT WMI provider (MSFT_NetNat in root/standardcimv2)…` — this is intentional fail-closed behavior (matches the active-debug symptom class), not an install-script bug.

### 2.5 Landed vs remaining (exit/relay delta scorecard)

**Landed (verified in tree):** exit NAT apply/residue/delete payloads + generation invariants (phase10.rs); killswitch apply + live-state assert by DisplayName + profile DefaultOutboundAction=Block check; DNS fail-closed rules (UDP+TCP LAN block) + NRPT loopback (fixed GUID key, `WINDOWS_NRPT_REG_KEY` phase10.rs:6095) + `windows-dns-failclosed-check`; IPv6 LAN block (G8); `windows-killswitch-assert` subcommand; relay service hardening helpers + `windows-relay-service-hardening-check`; relay signed-fleet/endpoint-hint/auto-tunnel bundle verification + all four tamper/replay tests; DPAPI startup self-test; relay `--features daemon` Windows service path (install script + env-file parsing + hardening report); exit preflight script; orchestrator Windows install/bootstrap/phase machinery; all §11 ledger commits.

**Remaining / open:** §A.5/A.6 live-proof stages + artifacts (nothing under `artifacts/windows_*`); §A.7 IPv6 parity (deliberately deferred; block rule keeps it fail-closed meanwhile); §C.2 heterogeneous evidence, §C.3 CI gates for the windows cells (verify per-run); §D.1 posture promotion (`PlatformSupportMatrix.md` Windows still `runtime-host-capable only`, exit row gated on D7 evidence); §E.2 peer-map wire bump; §E.3 relay benches; §E.5 cargo-fuzz for `decode_helper_request`; §E.6/E.7 per plan. The bash-orchestrator references anywhere in older docs are dead post-W5.7 — the `--node` engine is the only path.

**Fail-closed flags (flag only, do not do):** any debugging shortcut that (a) loosens `Install-RustyNetWindowsService.ps1`'s fixed-root or binary-presence throws, (b) downgrades `WINDOWS_PS_REQUIRE_EXIT_CMDLETS`' MSFT_NetNat probe to a warning, or (c) lets daemon-status readiness pass without the reviewed env file would weaken deliberate fail-closed controls. If the Windows-11 host lacks WinNAT/HNS, the correct fix is provisioning a host that has it (or the HNS feature), not softening the gate.

---

## 3. Verified-correct list (plan claims checked and accurate)

- §2.1's core assertion that exit+relay+cross-cutting *code* is substantially done — confirmed; the code exists and is larger than the plan describes.
- Killswitch assertion design (live OS state, rule-name constants shared apply/assert) — confirmed at phase10.rs:6069-6080.
- IPv6 fail-closed NAT-prefix validation — confirmed (phase10.rs:8788).
- Relay clock-skew tolerance constant — confirmed (transport.rs:91).
- Signed endpoint-hint / peer-map / fleet-bundle verification surface — confirmed at the cited crate (`rustynet-control`, `rustynetd`).
- §E.2/E.3/E.5 open statuses — confirmed open.
- §D posture promotion open — confirmed via PlatformSupportMatrix + absent artifacts.
- All 34 §11 SHAs — real, subjects match.

## 4. Self-verification (per task, 4 key citations re-grepped)

1. `WINDOWS_PS_REQUIRE_EXIT_CMDLETS` → `crates/rustynetd/src/phase10.rs:6026` (re-grep hit; invocation :5952). ✔
2. `WINDOWS_PS_ASSERT_KILLSWITCH` → `crates/rustynetd/src/phase10.rs:6080` (re-grep hit). ✔
3. `rustynet-windows-trust-cli` build → `scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1:1702` (`-p rustynet-cli --bin rustynet-windows-trust-cli`), comment :1695 (re-grep hit). ✔
4. `WINDOWS_RUSTYNETD_PATH` → `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows_install.rs:17` (read at verification). ✔
