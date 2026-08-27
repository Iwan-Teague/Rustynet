# Repo State Assessment and Next Steps

Date: 2026-08-19 · Status: assessment/discovery only — no code changed. **Adversarially verified in two full passes 2026-08-19** (ten parallel read-only source/ledger/cross-doc agents + direct git/source checks) — §1–§3 are now independently source-verified against `main` at `09daefdf`, subject to two read-only coverage limits (CI-green-since-08-15 is run-history; D# "mock-tested" verified as code-present not tests-run). Corrections applied inline; **the two materially-wrong claims were QH-46 (actually FIXED/LIVE-PROVEN 08-14, not open) and QH-01 (integrated on `main`, not pending on a deleted branch)** — both because a source ledger this doc summarized had itself gone stale. First-pass pitfall catalog + resolved non-issues in §8; second-pass full-coverage catalog, confirmations, and coverage statement in §8a.
Source: fresh read of `AGENTS.md`, active ledgers in `documents/operations/active/`,
the `--node` live-lab ledger, `git log`, and the six newest (three uncommitted) work docs.
This document is a **planning artifact only**. It is not an owning ledger and changes nothing.

> Index note: this file and its three sibling docs (`LiveLabCoverageGapDiscovery_2026-08-19.md`,
> `LiveLabTestCoverageImplementationDesign_2026-08-19.md`,
> `SignedTraversalAuthorityLifecycleDeepDive_2026-08-18.md`) are now listed in the active-dir
> README index (synced 2026-08-19 when this work was committed to `main`).

---

## 1) Where the project actually is (verified snapshot)

### 1.1 Git / working tree
- `main` at `09daefdf`, **0 commits behind `origin/main`** (not stale — safe to work).
- Working tree is **dirty**: 3 modified docs, 3 untracked new docs:
  - modified: `documents/operations/active/README.md`, `RustNativeMultiPlatformOrchestratorPlan_2026-04-28.md`, `SharedUdpRelayTransportDeepDive_2026-08-17.md` (+338/−93, uncommitted open-work surface)
  - untracked: `LiveLabCoverageGapDiscovery_2026-08-19.md`, `LiveLabTestCoverageImplementationDesign_2026-08-19.md`, `SignedTraversalAuthorityLifecycleDeepDive_2026-08-18.md`
- Stale `ai-edit/edit-1786154936952-11678-0` branch + likely worktree under `state/edit-worktrees/` from the delegated-edit harness — review or prune.
- Recent commit shape: QH-57→58→59→60→61→62 (close/fix churn), run 42–44 evidence, CI hermeticity repairs. The last several commits are **ledger-closing + live-lab evidence**, not new feature work.

### 1.2 Engine of record: Rust `--node` live-lab
- **Linux: green end-to-end for the first time.** Run 41 (`qh53-liveproof-20260815a`, `f2cd7d09`) passed `live_network_flap_validation` first time; run 44 (`qh61-sudopath-20260816b`, `5510b726`) was **44 pass / 0 fail / 15 skip — first zero-failure run**.
- **macOS and Windows: 0% on the engine of record.** As of `LiveLabStageStatus_2026-08-14.md`: both "NOT EXERCISED AT ALL" — no platform node elected, no stages present, not even skipped. The `--node` ledger (143 rows) has **zero overall-pass runs**; Windows bootstrap (`CP-4`) fails every row; macOS `two_hop` (`CP-1`) fails 8/8 and caps every macOS overall verdict. Cross-OS carrier `live_mixed_topology_validation` has never run — 0 of 143 rows (**corrected 2026-08-19**: the earlier "0-for-88" figure was a stale total-row-count carried forward unchanged from `CrossPlatformRoleParityRefresh_2026-07-23.md`, three and a half weeks old and inconsistent with this doc's own "143" one paragraph up — not an attempt-count for this stage specifically, since there is no valid N-for-88 fraction to begin with. The correct signal is stronger than what "88" implied, not weaker: zero attempts across the full current 143-row history).
- The bash-orchestrator archive (`live_lab_run_matrix.csv`) shows many mac/win ✅ — **these do not count** (release proof requires the `--node` engine; `CrossPlatformRoleParityRefresh_2026-07-23.md` re-scoped the mandate to G2/`--node`).

### 1.3 CI
- `QH-58` (closed 2026-08-15): **CI matrix green for the first time since March** (10 hermeticity defects fixed `bf84290c..767b32a3`). Prior inventory claims (Debian 13 + `linux_e2e` failing at `cargo: not found`) predate this fix — re-verify those legs rather than assuming either way.
- Local gates must run with `--locked` to match CI (AGENTS.md §7).

### 1.4 Lab
- `windows-x86-1` on `ubuntu-kvm-1` (192.168.121.108) — **hardware WinNAT problem SOLVED** (supersedes older "needs physical Win-on-ARM" claims). Windows exit cell is now *queued, not blocked*.
- `windows-utm-1` (192.168.64.25): **port 22 closed** — blocks `--node` windows client/admin/relay cells until fixed.
- `macos-utm-1` on a different UTM bridge (`.65` vs `.64`, Apple-Virtualization vs QEMU = separate "Shared" networks) — **blocks every mixed-OS run**; that is `QH-41`, still open.
- Cross-network substrate is untested/not confirmed; `flap4` (2026-07-29) still shows `linux_stage_cross_network=fail` at `cross_network_preflight`.

---

## 2) What the docs say vs. what's real (divergence list)

| Claim / doc | Reality |
|---|---|
| Cross-platform parity near-complete (bash-era ✅ matrix, ParityPlan 06-21) | Bash proof is **excluded** from release (ParityRefresh 07-23 re-scoped to `--node`/G2). On `--node`: macOS 3 stage-greens only, Windows 0, cross-OS never run. |
| CI red since March | Green since 2026-08-15 (QH-58). Re-verify Debian/linux_e2e legs. |
| relay/`relay_active` end-to-end proven | **Unproven on every OS** (HP-3). D4 production relay is code-only (~5.5k lines in `rustynet-relay/src/main.rs`); the live two-node + tcpdump integration never ran. |
| nas/llm service roles (M1–M4 code, docs + gates landed) | Code/gates done, **zero live-lab rows** (M5 open). macOS/Windows `⛔`. |
| Cross-network substrate phases X1–X4 (Spec 06-21) | The spec text is stale: the wiring it claimed was missing now **exists** (`--cross-network-substrate` parsed at `main.rs:4378/4464` with `--cross-network-nat-profiles` five lines earlier at each site; help at 20576; `CrossNetworkOptions::from_cli` spans `vm_lab/orchestrator/native.rs:50-56` — **line numbers corrected 2026-08-19**, were off by a few). X1 Tier-A netns: Increment 1 + 2 code **landed** (`ad7cfad9`, `92b8d486`, `b63cbbe3`); the old commit ref `ae5c7ce` cited for the `crossnet1` run is **unresolvable on current tree — do not cite it**. Open: live proof of the daemon-path Direct validator, Increment 3 (relay-fallback), X2 vxlan, X3 stages, X4 slirp. **Corrected 2026-08-19 — only the redesign is parked, not "the whole spec," and work continued after the park date.** Owner directive 2026-07-13 parks only §4-5 (the redesign) — the spec's core, §1-3/§6-10, stays "Active implementation spec" per its own line 3. A newer **§0 "RESOLVED ARCHITECTURE"** section, added 2026-07-19 (six days *after* the park), already resolves the brainstorm the park was waiting on and reads "DESIGN PROPOSAL, not yet built" — this doc's own §6 decision item 6 already names "spec §0" without connecting it back here; that's the same proposal. Anyone reading only the old wording here would think the whole direction needed a from-scratch brainstorm; it doesn't — §0 exists and needs review, not reinvention. |
| OpenWorkIndex 04-17 | **Corrected 2026-08-19:** "point-in-time, not live" is FullTodoInventory's own self-description (confirmed verbatim), but "superseded" is this doc's own unlabeled inference, not a sourced claim — FullTodoInventory names only `RustynetUnifiedTodoLedger_2026-07-10.md` as what it supersedes, and OpenWorkIndex still calls itself "active summary index." Read as: OpenWorkIndex is undated-stale by content (contradicted by current reality below) but not formally superseded by anything. Several entries contradict current reality (e.g. vm-lab capability reporting now complete; Windows access recovery progressed). |
| Windows exit "blocked" on WinNAT hardware | Solved 08-04 via `windows-x86-1`; cell unrun, not blocked. |
| QH ledger says 43 items (banner) | File carries through **QH-62**; corrected priority QH-07→QH-13→QH-01→QH-04→… Many items fixed/closed since the banner. |
| CI gate list | `--workspace` skips `rustynet-lab-monitor`, `fuzz/`, `gui/` (own workspaces). Fuzz/gui have **no wired gate**; lab-monitor has its own gate script. |

---

## 3) Open-work inventory (grouped, with status and acceptance)

### 3.A Evidence integrity & lab foundation (gates everything else)
| Item | Status | What it needs | Acceptance / verification |
|---|---|---|---|
| **QH-07** `two_hop` false-green | DONE — alias dropped 2026-07-27, guard in place — **re-verified against source code 2026-08-19, holds** | (a) **done**: the `traffic_test_matrix` alias onto the `two_hop` column was removed; defect documented at `live_lab_stage_registry.rs:885-889`, regression guard `traffic_test_matrix_feeds_no_two_hop_rollup_but_keeps_cross_os` confirmed present at `live_lab_stage_registry.rs:2465` and referenced (not re-defined — **file corrected 2026-08-19**: this is `crates/rustynet-cli/src/live_lab_run_matrix.rs:3926`, not `rustynet-lab-monitor`'s file of the same name, which has zero hits) by a comment quoting the same test's path; `live_lab_run_matrix.rs:3744/3747` is a *different* concurrency test (`append_csv_row_serializes_concurrent_appends`) and `:3770` is a *third*, unrelated test — neither relates to the old alias, but they are two tests, not one. Remaining: (b) explicit synonym table; (c) optional schema migration. 43 historical rows stay contaminated (forward-only). Note: the QH ledger's own prose for this item still frames the alias-drop as a to-do ("(a) NOW... drop the alias") and calls the synonym table "the real guard" not yet built — that ledger text is itself stale against the code; this row's "DONE" is the accurate one, confirmed against `live_lab_stage_registry.rs` directly rather than against the ledger's wording. | Ledger column reflects real two-hop stages only; regression test on the registry ✓ |
| **QH-41** `macos-utm-1` isolated bridge | OPEN — blocks every mixed-OS run | UTM Apple-Virt vs QEMU "Shared" bridges are separate; repair was a no-op. Unblock mac/win cross-OS coverage. | Bidirectional ping re-verify |
| **QH-39** macOS baseline green with **no daemon** | OPEN — High | Oracle repair: **negative tests first**; scope question must be resolved (a prior attempt was reverted — freshness bound invalid, probe removal = fail-open). Also `/etc/resolv.conf` non-authoritative (defer `scutil --dns`, in the DNS-failclosed adapters — a separate file); substring `overall_ok` match too loose (confirmed, `vm_lab/orchestrator/adapter/ssh.rs:584-587`, `validator_report_ok`) — **split 2026-08-19**: these are two separate findings in two separate files, not one citation as previously written. | Per-check negative case first; green only with real daemon |
| Coverage-discovery **G9** (same root as QH-39) | P0 | Trustworthy active evidence before any parity claim. | Negative-fixture oracles; one isolated live control per window |
| Coverage-design **L0** | next step | NotProven outcome + StageContract/AdmissionContract/ScenarioEvidenceContract + independent verifier; 12 framework tests. **Adversarial review against 4 questions first** (can a scenario pass without every witness; can skip read as full coverage; can fault injection leak/residue; can verifier be fooled). | Mutation tests listed in design §5 (L0) |
| **QH-44** 4-of-5 guests lost `authorized_keys` | OPEN | Diagnosed only by elimination; record WHEN — first step: `authorized_keys` mtime+hash in discovery summary. | — |

### 3.B Cross-platform role parity — RELEASE-BLOCKING (mandate in `CrossPlatformRoleParityPlan`)
Remaining work is **live proving + a few real impls**, not missing framework (ParityPlan §4).

| Item | Status | Needs | Acceptance (per cell) |
|---|---|---|---|
| **CP-4 Windows `--node` bootstrap** | OPEN — gates the **entire Windows column** | **Triage first** (code vs guest, unverified), n=3 fails 07-19; fix `windows-utm-1` :22 or target `windows-x86-1` | Windows bootstrap green on `--node`; then per-cell |
| **CP-1 macOS `two_hop`** | OPEN — caps every macOS verdict | **Fresh triage** (stale 07-15 shared-socket hypothesis, unverified on current code) | macOS client cell green |
| Windows exit cell | unrun (hardware solved) | Run on `windows-x86-1`: `promote_windows_exit_active` + NAT lifecycle + residue reconcile + egress via `Get-NetNatSession` | `--node` win exit cell green |
| macOS exit egress (pf NAT) | lifecycle proven only | S2: egress proof **not waived** — equivalent-strength end-to-end translated-client-session assertion | `--node` mac exit cell cannot be G2-green without it |
| Anchor sub-surfaces | bundle-pull done both OS | `enrollment_endpoint` has **zero runtime enforcement** — needs design+impl before any live stage; gossip_seed; port_mapping_authoritative (Win) | per-cell stages |
| Role transitions | LocalOnly done both OS | `SignedMembership`-kind transitions are **design-only both OS** (CrossOsRoleSwitchPlan, verbatim) — **nuanced 2026-08-19**: not zero implementation. `role_cli.rs:620-660` has real `TransitionKind::SignedMembership` match arms producing concrete action plans (e.g. `AdvertiseDefaultRoute`, `DeployExitService`). What's actually missing is the capability-signing sub-flow (today requires manually running separate `assignment issue`/`enrollment admit` commands, not automated within the transition) and any live-lab proof cross-OS — the planning/action logic exists, the automation and proof don't. | design + live flip test |
| macOS/Windows admin | bash-proven only | Re-prove on `--node` (admin is one of the 3 macOS stage-greens; Windows needs CP-4 first) | G2 green run |
| Cross-OS join | never attempted | `live_mixed_topology_validation` first step = **run + triage**, not make-green | first green `--node` cross-OS run |

G2 parity DoD: green under a **valid `--node` run**, N-of-N flake-sized at a single **clean commit** (default 3-of-3, 5-of-5 for a flake-recorded stage), row in `live_lab_node_run_matrix.csv` **and** the stage's own report artifact, FAIL-LOUD (live result = stage status; no dry-run-as-pass).

### 3.C QH ledger — remaining OPEN items by priority
- **CLOSED since this doc's first draft — do not action (corrected 2026-08-19):** **QH-46** (firewalld awareness) is **not open** — its ledger status header reads "FIXED and LIVE-PROVEN 2026-08-14" (`live_two_hop_validation` PASSED for the first time on run `qh46-firewalld-20260814c`; this is the same firewalld-forward-chain root cause that unblocked Linux `two_hop`). The "zero firewalld awareness / release-blocking / NOT implemented" wording this doc previously carried is *preserved audit text* inside the ledger entry that predates the 08-14 fix — do not read it as current status. QH-46 has been removed from the HIGH list below and from both Phase 4 (§4) mentions (it was not in §6); it is neither a release blocker nor an open plan.
- **HIGH / need owner or operator:** QH-04 (assignment/traversal atomicity — **release-blocking product defect, UNASSIGNED**; "permanently restricts itself" is false — confirmed the daemon clears `restriction_mode` **and** `reconcile_failures` even from `Permanent`; the "~5s" is the failure-*tolerance* window before it fails closed — `DEFAULT_MAX_RECONCILE_FAILURES = 5` (`daemon.rs:338`) × `DEFAULT_RECONCILE_INTERVAL_MS = 1000` (`:337`) — not a fixed heal duration; recovery happens on the next successful reconcile); QH-26 (3 unreviewed WIP commits on trust path + DA-01 TLS decision — **operator**); QH-28 (Windows installer mints self-signed cert into `LocalMachine\Root` — **operator, do not fix autonomously**); QH-54 (worker-death recovery — **corrected 2026-08-27:** the firewalld re-bind half is now FIXED, by the periodic posture assert; the "3 blueprints" counted here are the P1/P2/P3 *transport-incarnation and relay-session* designs, which are unrelated to the re-bind and remain unimplemented); QH-30 (`extra_peers` fail-closed branch wholly uncovered — no test); QH-13 (SSH post-host argv sink — 7 of 8 sites open; validate in single chokepoint); QH-40 (launchd SIGTERM → rollback always fails, exit 0 — fail-closed question first); QH-45 (entry-role nft rule rejected by privileged-helper allowlist — security-sensitive, need exact argv); QH-01 (template injection — **corrected 2026-08-19: integrated on `main`, not pending on a branch.** Both this doc and the QH ledger entry say "integration pending (branch `claude/wsd-qh01`)" — but that branch no longer exists locally or on `origin`, and commit `0aff3c07` (ancestor of HEAD) "route every host-script render site through the renderer" states it *"Convert all 32 production render sites onto the named `script_template` render functions, and delete the local `render_host_launch_script` chain"* + adds the `pool`/`image` allowlist validators. Verified on current `main`: `render_host_launch_script` is gone from `mod.rs`, zero `.replace("__` render chains remain in production `mod.rs`, and `script_template.rs`'s `shell_quote`-owning renderer is present. So the template-rendering half of the injection class is integrated and live — the "pending on branch" status is stale in *both* documents. **Note the scope limit** the ledger itself flags: this closes template rendering only; the SSH-argv sink and stdout-derived `device` remain open under QH-13 (7 of 8 sites). Reconcile the QH-01 ledger status header to "integrated on main; QH-13 carries the remainder"); QH-16 (pipeline swallows tool exit codes — convention not enforced); QH-18 (singleton gate flock — design corrected 07-26, not implemented).
- **MED:** QH-05/06 (conventions), QH-08 (run worktree), QH-09 (evidence disclosure line), QH-11 (`/tmp` ledger rows), QH-14 (Fedora toolchain), QH-15 (Windows build budget), QH-17 (Windows image provisioning), QH-19 (escape-rule classification), QH-21 (1 sibling `$dnsRules.Count` at `script_template.rs:1302` — **corrected 2026-08-19**, was cited as :1281, which is inside the rule-building loop a few lines earlier), QH-24 (remote-script adapter test reachability), QH-25 (NAT-session identity-check), QH-27 (rebase practice), QH-29 (fail-closed string-match sweep), QH-31 (TUI relative report-dir), QH-32 (orchestrator progress seam), QH-33 (unit tests do real TCP probes), QH-34 (dirty-worktree inventory decide), QH-36 (gossip key rotation residue — design), QH-38 (nextest stdio leak), QH-47 (NAT w/o conntrack flush), QH-48 (dependency chain: 1 fail ⇒ 21 skips), QH-51 (network-flap `configure_peer` no-op — fix shape known, tests-first), QH-52 (firewalld unbind residue), QH-55 (silent 1s retry loop), QH-62 (Windows installer `-SshAllowCidrs` validate-then-discard — read installer + WFP surface first).

### 3.D In-flight design programs (the three uncommitted docs)
These represent the currently-chosen direction; all three enforce **deterministic-proof-first, `--node` live-lab last**.

1. **Shared UDP relay transport** (modified deep-dive, 08-17) — **21-row** issue register (**corrected 2026-08-19**: counted 21 data rows in the register table on current `main`, not 24 — the doc was edited since the count was taken; it is in the dirty working set) + required backend contract + relay V2 protocol (frames 0x11–0x14, all confirmed defined). The 8-step merge order, the 9 required acceptance gates, and the `ManagedPeer.direct_endpoint`-is-a-candidate-cache-not-baseline rule are all confirmed present in the doc. **Merge order (reranked):** 1. common candidate-state policy transaction (fixes P0: endpoint transition refreshes policy from stale peer state; macOS exact-SocketAddr pf allow-list drops E1; initial-apply pre-policy egress window) → 2. typed worker loss → 3. incarnation/status parity → 4. V2 hello ACK → 5. narrow mux → 6. relay liveness → 7. signed capability + rollout → 8. controlled `--node` live-lab. 9 acceptance gates; deterministic fault points; no timing sleeps. Critical rule: `ManagedPeer.direct_endpoint` is a **candidate cache, never the recovery baseline**.
2. **Signed traversal authority lifecycle** (08-18) — P0: (a) block raw candidate consumption (immutable `VerifiedCandidateRecord` only; **port-zero handoff forbidden**; make `applied_endpoints` private); (b) atomic `NodeId↔GossipKey` authorization snapshot (residual authority after Remove/Rotate; current-epoch mint possible via `sync_gossip_data_plane`); (c) enrollment bootstrap creates full gossip authority pre-membership. P1: dissemination ACL-scoping, cache/restart/path-loss design, bind≠delivery statuses, wildcard-bind constrain, fail-closed expiry. **Implementation order §9: 1–2 first, cut over exclusively last.** §10 needs design-owner decisions before code authorization (5 open questions).
3. **Live-lab coverage + implementation design** (08-19) — discovery G1–G9, priorities P0 = G9, G1/G2/G3, one mixed-OS baseline; then implementation slices L0→L5, **start L0**, not another test binary.

### 3.E Cross-network / dataplane (D#) — `RustynetDataplaneExecutionPlan`
- **Done (code, mock-tested):** D2 STUN, D2.3 uPnP, D2.4 IPv6 producer, D3 shared transport, D2.5 signed gossip, D2.7 enrollment, D4 relay binary (code), D5.5 ICE, D11 anchor (code), D12 taxonomy (code), D13.a–e (code).
- **Open:** D5 Linux↔Linux cross-LAN baseline (**not started**, needs 5 artifacts: WG handshake ≤5s, iperf3 -t 60, tcpdump direct-path, forced-relay, zero CIDR leaks); D14.a–f (all **not started**; e/f **gated on user sign-off**); D6/D7/D9/D10 (Windows readiness/exit-evidence/mixed/platform-promotion — not started); substrate: X1 Increment 1+2 code **landed** (`ad7cfad9`, `92b8d486`, `b63cbbe3`) with **live proof of the daemon-path Direct validator open**; **Increment 3 (relay-fallback) — nuanced 2026-08-19**: not code-absent as previously implied — a full `CrossNetworkStageKind::RelayRemoteExit` stage exists (`stage/cross_network.rs`, with `--relay-host`/`--relay-node-id`/`--relay-network-id` wiring and a `live_linux_cross_network_relay_remote_exit_test` binary). What's open is *live proof* and confirming it's wired to the same netns substrate path as Increments 1+2 (it may be a separate/older cross-network track); X2/X3/X4 open; **substrate redesign PARKED** (proposal-only; but see §2 — only the redesign is parked, and spec §0 already proposes a resolved architecture). D13 M5 live rows open (see 3.F — nas/llm crates, binaries, and all 4 gate scripts confirmed present; zero nas/llm stages wired into the live-lab registry, so M5 genuinely open).
- Plan DoD: 24h+ real-world two-device soak, no placeholders, D11/D12 live on Linux+macOS.

### 3.F Service-hosting (nas/llm)
- M0–M4 complete (crates, binaries, installers, gates: `nas_default_deny_gates.sh`, `llm_default_deny_gates.sh`, `llm_exit_coexistence_gates.sh`, `service_hosting_role_gates.sh`).
- **M5 open:** green Linux rows in `--node` ledger — nas: deploy→advertise→authorise→backup→restore→revoke(severance)→undeploy (Debian 13 + spare data disk); llm: same + no-API-key stream + exit-coexistence + revoke-mid-stream (model-loadable guest, GPU not required). MagicDNS overlay names (`vault.nas.<mesh>`, `brain.llm.<mesh>`) pending. macOS/Windows `⛔` until live evidence.

### 3.G Security / trust (parallel, operator-decisions first)
- **DA-01** and **DA-17** first, then DA-36, then High runbook findings (DocCodeDiscrepancyAudit priority). **Corrected 2026-08-19 — the parenthetical citation pointed backward and made a still-open Critical finding read as closed.** `tls13_valid` genuinely was deleted from `main` (`f1ef83b1`, 2026-07-20, confirmed an ancestor of HEAD) — but that fact is narrated by **QH-26**, not DA-01, and citing "DA-01... deleted" is misleading: DA-01 itself (`DocCodeDiscrepancyAudit_2026-07-18.md:78`) says the *opposite* — `tls13_valid` "hardcoded to `true`... the gap has widened, not narrowed" — because DA-01 was written two days before the deletion. The deletion did not close DA-01: `SecurityMinimumBar.md` still claims "TLS 1.3 enforced for control-plane APIs" with no real TLS stack anywhere in the workspace — that Critical documentation-vs-reality gap is **still open**, arguably harder to evidence now that the field claiming it is gone too. Track DA-01 as open against `SecurityMinimumBar.md`, and cite QH-26 (not DA-01) for the `tls13_valid` deletion history.
- RSA findings (`SecurityAuditLedger_2026-06-18.md`: 66 open, 528 audited — "~60" magnitude confirmed; Med RSA-0001/0002/0025/0026/0064/0065 all confirmed open); SecurityReview 21 open (`SecurityReview_2026-05-24.md`; RN-02/06/07 confirmed High/Open); **SecurityMinimumBar §6.C controls #3 and #4 UNMET** — **clarified 2026-08-19**: "3/4" means *controls number 3 and number 4* (of the **8** numbered controls in §6.C), i.e. 2 of 8 unmet, NOT "3 out of 4"; control #3 = token-gated single-use bundle-pull ledger (`SecurityMinimumBar.md:355`), control #4 = anchor-secret custody (`:379`). The "on all 3 platforms" qualifier is stated literally only for control #4; control #3's UNMET is stated generally. §8 sign-off: all five boxes unchecked (confirmed). **NO-SHIP until the P0 set closes.**
- Supply-chain / audit gates: `cargo audit --deny warnings`, `cargo deny check bans licenses sources advisories`, `secrets_hygiene_gates.sh`, `check_backend_boundary_leakage.sh`.

### 3.H Housekeeping
- Commit the 6 dirty docs + sync the active-dir README index (AGENTS.md §6).
- Review/prune the leftover `ai-edit/edit-1786154936952-11678-0` branch + worktree.
- QH-56 (hardcoded SSH usernames) — **corrected 2026-08-19, both the date and the "cosmetic" framing were wrong.** Fixed live **2026-08-15** (`edc71ad0`; both the QH ledger text and `git log` agree — "2026-08-16" above was an off-by-one-day error), but "only cosmetic residue remains" and "`default_ssh_user` is dead" do not hold. `resolve_ssh_user` (the real single-owner fix) is only actually called from 3 stage files. `ssh_params_for_role` is **independently re-implemented in 12 different stage files**, at least two of which disagree on defaults — `live_two_hop_validation.rs` defaults Linux to `"root"`, `chaos.rs`/`cross_network.rs` default to `"debian"`. `default_ssh_user` itself has live, non-test call sites in both `chaos.rs:223` and `cross_network.rs:662,685` (both reached from production code, not test-only) — it is not dead and must not be deleted as cleanup. This is a real open item: platform-dependent SSH-user defaults duplicated across 12 files, at least one confirmed inconsistency, and a genuine source of exactly the kind of hard-to-reproduce lab flakiness this whole doc is trying to eliminate — re-file it as such rather than treating QH-56 as closed-with-only-cosmetic-tail.

---

## 4) Recommended order of operations

Rationale: evidence must be trustworthy before release claims; lab plumbing gates cross-OS coverage; the `--node` parity mandate is the release blocker; the deep-dive programs are large and should run on their own tracks but never before the lab can actually test them.

### Phase 0 — Protect state + make evidence trustworthy (days)
1. **Commit the 6 dirty docs + sync the active-dir README index.** Check `git rev-list --count HEAD..origin/main` is 0 first (it is today). This protects the uncommitted deep-dive work per AGENTS.md §5.1.3. Review/prune the stale `ai-edit` branch.
2. **QH-07(a) already DONE** — the `two_hop` alias was dropped 2026-07-27 with a regression guard (defect + guard refs in §3.A). Replace step with the optional **QH-07(b) synonym table / (c) schema migration** only if the column taxonomy is worth formalizing now.
3. **QH-41: unblock `macos-utm-1`** — no mixed-OS parity run is possible until this is fixed; bidirectional ping re-verify.
4. **Coverage-design L0 adversarial review (4 questions), then build L0** — NotProven outcome + contracts + independent verifier + monitor update. This is the "trust the evidence" foundation the parity mandate depends on.

### Phase 1 — Release-blocking cross-platform parity (the mandate) (weeks)
5. **CP-4 triage: Windows `--node` bootstrap** — first fix `windows-utm-1` :22 or switch to `windows-x86-1`; determine code vs guest cause before any fix.
6. **CP-1 fresh triage: macOS `two_hop`** — current hypothesis is stale; triage, then fix.
7. **Windows exit cell on `windows-x86-1`** (hardware solved — run it).
8. Then per-cell re-proving on `--node`, in the roadmap's order (admin → blind_exit → role-transitions → relay-lifecycle → anchor-live), each cell to the G2 N-of-N DoD.
9. **Cross-OS join:** first `live_mixed_topology_validation` run + triage.

### Phase 2 — The in-flight design programs (parallel tracks; deterministic-proof-first)
10. **SharedUDP** merge order step 1 (candidate-state policy transaction) → steps 2–8. `--node` proof dead last.
11. **SignedTraversalAuthority** §9 items 1–2 (block raw candidates; atomic NodeId↔GossipKey snapshot) after §10 design-owner decisions; then 3–8.
12. **QH-54** worker-death recovery (biggest single design item; blueprints already reviewed — implement against the required test matrix).

### Phase 3 — Release-adjacent tail
13. **HP-3 relay frame-forwarding** (unproven on all OS — promotes `relay_forwards_frame` to a unique stage, closes the relay role).
14. **nas/llm M5 live rows** (Linux) + MagicDNS overlay names.
15. **Cross-network:** D5 live evidence, D14.a–d (e/f need sign-off), X-series **after** the substrate `--node`-first-class redesign decision.

### Phase 4 — Security/quality backlog (continuous, decisions first)

> **Ordering caution (added 2026-08-19):** several items here are release-*blocking*, not "backlog" — QH-04 (release-blocking product defect), the RSA/SecurityReview/SecurityMinimumBar §6.C/§8 NO-SHIP set in §3.G, and QH-28 (an operator security decision). The "Phase 4 of 4" number reads as "do last," which is the wrong signal for a release blocker. This phase is labelled "continuous, decisions first" precisely so it runs *alongside* Phases 1–3, not after them — a linear reading that defers the NO-SHIP set behind parity and the design programs would gate release on work that hadn't been started. Treat the security P0/NO-SHIP set and QH-04's owner-assignment as parallel-track-from-day-one, not phase-ordered.
- Operator decisions first: QH-26/DA-01, QH-28, QH-04 owner + shape, D14.e/f, SignedTraversal §10. (**QH-46 firewalld product plan removed 2026-08-19 — already FIXED and LIVE-PROVEN 2026-08-14, not an open decision; see §3.C.**)
- Then the High queue: QH-13, QH-30, QH-40, QH-45, QH-01 integration, QH-16, QH-18.
- Then MED sweep + conventions (QH-05/06/08/09/11/14/15/17/19/21/24/25/27/29/31–38/44/47/48/51/52/55/62).
- Keep CI green (QH-58 is fragile — every commit must pass `--locked` gates).

---

## 5) How each phase gets done properly + verified correct

**Every code change (any phase):**
- Scoped first: `cargo check -p <crate> --all-targets --all-features` (+ `--locked`), then `cargo run -p rustynet-xtask -- gates` for the fast-fail loop. Bare `cargo check -p <crate>` silently under-tests (AGENTS.md §13.1).
- Landing: the full §7 list — fmt, clippy `-D warnings`, check, test, `cargo audit`, `cargo deny` — all with `--locked`; plus `secrets_hygiene_gates.sh` and `check_backend_boundary_leakage.sh` where trust/backend code is touched. Gate `rustynet-lab-monitor` via `./scripts/ci/lab_monitor_gates.sh` when in scope; fuzz/`gui/` have no wired gate — gate by hand and say so.
- Security controls: 1 enforcement point + 1 verification test each (SecurityMinimumBar §4); fail-closed + default-deny invariants; **negative tests first**; mutation tests where the repo's pattern exists.
- Git hygiene: never commit stale (check ahead count), diff vs HEAD, commit before experiments, small imperative commits.

**Parity cells:** G2 DoD — valid `--node` run, N-of-N (3-of-3; 5-of-5 for flake-recorded stages) at one clean commit, FAIL-LOUD stage spec, row in the `--node` ledger **plus** the stage's own report artifact, pass/fail taken from the artifact not the column, quote-aware CSV reads, clean-worktree evidence.

**Coverage framework (L0):** the 7-field evidence contract (identity/env, precondition, injection never inferred from exit code, safety oracle, functional oracle, after-state — unproven cleanup = fail/tainted, explicit limits); the 12 framework tests; independent verifier; adversarial review before build.

**Deep-dive programs:** deterministic fault injection (no sleeps), exact-pair evidence (current authenticated session event, not last-send/STUN echo/stale WG timestamp), every non-valid case leaves the controller fail-closed, `--node` live-lab only after deterministic proof ("validates environment, not state-machine correctness").

**Evidence honesty:** never reuse a bash-archive row as `--node` evidence; never let a skip read as a pass; a green column is only a pointer — the report artifact is the proof.

---

## 6) Decisions the operator must make (blocking items)

1. **QH-26 / DA-01:** implement real control-plane TLS, or correct the SecurityMinimumBar claim. Disposition of the 3 unreviewed WIP commits on the trust path.
2. **QH-28:** Windows installer self-signed-cert policy (mint/trust, delivery mechanism, release-note wording).
3. **QH-04:** assign an owner + choose the staged-pair set-equality grace shape.
4. **D14.e/f:** approve (or not) symmetric-NAT port-delta prediction and the out-of-band endpoint mailbox.
5. **SignedTraversalAuthority §10:** the 5 design-owner questions (bootstrap/resync channel, enrollment exception, exact-pair evidence contract, PeerSignedV2 platform-independence, cutover exclusivity).
6. **Cross-network substrate:** confirm the `--node`-first-class redesign (spec §0) so X2–X4 aren't built on a superseded shape.
7. **QH-34 / QH-08 / QH-55:** decide inventory-dirty exclusion, worktree enforcement, and the bounded-LOUD retry design.
8. **Windows CI leg:** acknowledge the package-subset gap (Windows CI does not gate `rustynet-cli` at all).

---

## 7) Overall program Definition of Done (unchanged mandate)

Per `CrossPlatformRoleParityPlan` + G2 refresh: every node role + capability (client, admin, anchor, exit, blind_exit, relay, + nas/llm) is **live-lab-proven on macOS AND Windows** under the `--node` engine at the G2 N-of-N standard; the cross-OS join is green; no OS is a capability limiter. SecurityMinimumBar §6.C/§8 controls are met on all platforms, CI is green, and the evidence ledger rows are attributable to real stage artifacts. Anything claiming "complete" must survive §9 Definition of Done (no in-scope blockers, no TODO/FIXME in completed deliverables, gates green or blocker explicitly documented outside the claimed completion).

---

## 8) Adversarial review record — 2026-08-19

Read-only: no edits, builds, tests, or VM/lab actions. Method: direct `git`/source verification (ahead/behind count, SHA-ancestor checks for every cited commit, file line counts) plus five parallel read-only agents, each independently re-deriving a cluster of this doc's claims from the actual current source, `git log`, the run-matrix CSV, the QH ledger, and every cross-referenced doc — never from this doc's own summary of them. Corrections are applied inline above at their original location, not just listed here; this section is the traceable catalog of what changed and why, plus what was checked and held.

### Pitfalls found and corrected (inline, at point of claim)

| rank | finding | why it was wrong | correction applied |
| --- | --- | --- | --- |
| P0 | §3.G DA-01 citation pointed backward | Cited "DA-01... `tls13_valid` deleted" as if that closed a Critical finding. DA-01 (2026-07-18) says the *opposite* (hardcoded `true`, "gap has widened"); the deletion (`f1ef83b1`, 2026-07-20) is narrated by QH-26, and `SecurityMinimumBar.md`'s TLS 1.3 claim is still false today — DA-01 stays open. | §3.G rewritten: cite QH-26 for the deletion, track DA-01 as open against `SecurityMinimumBar.md` |
| P0 | §3.H QH-56 called the gap "cosmetic residue" / "dead code" | `ssh_params_for_role` is independently duplicated across 12 stage files with at least one confirmed default mismatch (Linux user `"root"` vs `"debian"` depending on which copy runs); `default_ssh_user` has live non-test call sites in `chaos.rs`/`cross_network.rs`, not dead code that's safe to delete. | §3.H rewritten with the 12-file inconsistency and the live call sites named; date corrected 08-16→08-15 |
| P1 | §2 CrossNetworkSubstrateIntegrationSpec described as "whole spec parked... nothing built" | Only §4-5 (the redesign) is parked 2026-07-13; the spec's core stays "Active implementation spec." A newer §0 "RESOLVED ARCHITECTURE" (added 2026-07-19, after the park) already proposes a resolved design — this doc's own §6 item 6 already names "spec §0" without connecting it here. | §2 row rewritten to scope the park correctly and name §0 |
| P1 | §1.2 "0-for-88" cross-OS denominator | "88" is a stale 2026-07-23 total-row-count snapshot, inconsistent with this doc's own "143" one line earlier, and not a real attempt-count (there is no live_mixed_topology_validation attempt to count at all). Understated the actual (stronger) signal. | Corrected to "0 of 143 rows" |
| P1 | §2 "OpenWorkIndex... superseded by FullTodoInventory" | "Superseded" is this doc's own inference, stated as if sourced. FullTodoInventory names only `RustynetUnifiedTodoLedger_2026-07-10.md` as superseded; OpenWorkIndex calls itself "active summary index." | §2 row corrected to separate the confirmed half ("point-in-time, not live") from the unlabeled inference |
| P1 | §3.B "SignedMembership transitions are design-only both OS" | Verbatim-sourced from CrossOsRoleSwitchPlan and directionally right (no live-lab proof, signing sub-flow is manual), but `role_cli.rs:620-660` has real transition-planning code producing concrete action plans — not zero implementation. | §3.B row nuanced |
| P2 | §3.A QH-39 conflated two file citations under one | `adapter/ssh.rs:584` only covers the `overall_ok` substring-match half; the `resolv.conf`/`scutil` half is a different file entirely. | Split into two citations |
| P2 | §2 line numbers for `main.rs`/`native.rs` cross-network wiring | `native.rs:51-59` → actual span is 50-56; `--cross-network-nat-profiles` parses 5 lines before the cited line. | Corrected |
| P2 | §3.C QH-21 `script_template.rs:1281` | Actual `$dnsRules.Count` check is at line 1302; 1281 is inside the rule-building loop. | Corrected |
| P2 | §3.A QH-07 `run_matrix.rs:3926` citation | Resolves to `crates/rustynet-cli/src/live_lab_run_matrix.rs`, not the more obviously-named `rustynet-lab-monitor` file (zero hits there); is a comment referencing the registry test, not a second definition; `:3770` is a third, separate test, not part of "a concurrency test." | Corrected, and the ledger-prose-staleness context added |

### Resolved — investigated, doc's original claim held

- **§1.2 "Run 41" / "Run 44" numbering, initially looked contradictory** (commit `5510b726`'s own message says "Record run 43"). Resolved: the CSV's `git_commit` column records the code-under-test, not the recording commit — Run 44's row was added by `5510b726`'s child commit `dea73a75` ("Record run 44: the first zero-failure node-engine run"). The doc's "Run 41" / "Run 44" labels are correct; no error.
- **§3.A QH-07 "DONE, guard in place."** Confirmed directly against `live_lab_stage_registry.rs` — the alias is gone and the named regression-guard test exists at the cited line. The QH ledger's own prose for QH-07 is what's stale (still phrases the fix as a to-do and calls the synonym table "the real guard" not yet built) — this doc is more current than the ledger entry it draws from, not the other way round.
- **§1.4 windows-x86-1 WinNAT "SOLVED".** Confirmed against `CrossPlatformRoleParityPlan_2026-06-21.md:64` and `vm_lab_inventory.json:302`, and confirmed this doc scopes it correctly — "queued, not blocked," not an overclaim that the exit cell already ran.

### Confirmed sound, unchanged

Git/working-tree snapshot (0 ahead, 0 behind, exact dirty-file list) — exact match at time of writing. Every cited commit SHA (`f2cd7d09`, `5510b726`, `bf84290c`, `767b32a3`, `ad7cfad9`, `92b8d486`, `b63cbbe3`, `edc71ad0`) verified a real ancestor of `HEAD` — no history-rewrite orphaning. §2's "bash proof excluded from release, re-scoped to G2" is verbatim-accurate against `CrossPlatformRoleParityRefresh_2026-07-23.md`. §3.A/3.C QH-41, QH-44, QH-58 status claims all exactly confirmed against the ledger. The QH banner-vs-highest-item check (banner says 43, ledger carries through QH-62) is accurate, and **no QH-63 or higher exists** — this doc is not stale in that respect. §3.B `enrollment_endpoint` zero-runtime-enforcement, §3.C QH-30's uncovered `extra_peers` branch, and §3.G's SecurityMinimumBar §6.C controls-3/4-unmet-on-all-platforms are all confirmed precisely against source, down to exact file:line. §1.2's run-matrix claims (zero overall-pass, Windows fails every row, macOS `two_hop` fails 8/8 with zero passes ever, mixed-topology never run) were re-derived from the actual per-stage CSV columns with a quote-aware reader, not assumed from column labels — and hold exactly.

### Bottom line

No finding here would have caused a false release/security certification — this doc doesn't gate anything directly. But the three P0/P1 pitfalls that skewed "safer than reality" (DA-01, QH-56, the substrate-spec framing) are the same failure direction this project's own culture treats as the dangerous one. All are now corrected at their original location, not just noted here.

---

## 8a) Second verification pass — 2026-08-19 (full-coverage sweep)

The first pass (§8) checked five clusters. The gaps it left — the ~35 remaining QH items, the whole D#/dataplane block, nas/llm, the security-finding counts, the two design deep-dives, and the CI-leg claims — were then swept by five more parallel read-only agents plus direct `git`/source checks. This closes most of the "not yet independently verified" surface the first pass left open. New findings and corrections are applied inline above; catalogued here.

### New pitfalls found and corrected

| rank | finding | why it was wrong | correction applied |
| --- | --- | --- | --- |
| **P0** | §3.C/§4 listed **QH-46 as open + release-blocking** (firewalld) | Ledger status header reads "**FIXED and LIVE-PROVEN 2026-08-14**" (`live_two_hop_validation` passed on run `qh46-firewalld-20260814c` — the firewalld-forward-chain fix that unblocked Linux `two_hop`). The "release-blocking / zero firewalld awareness / NOT implemented" text this doc carried is *preserved pre-fix audit text* inside the entry. This inflated the release-blocker list and could have caused re-work of a done fix. | Removed from §3.C HIGH list and both §4 Phase-4 mentions; explicit CLOSED note added at §3.C |
| **P1** | §3.C QH-01 status "**integration pending on branch `claude/wsd-qh01`**" | Branch does not exist locally or on `origin`. Commit `0aff3c07` (ancestor of HEAD) converted all 32 render sites to the audited `script_template` renderer and deleted the vulnerable chain; verified on `main`: `render_host_launch_script` gone, zero `.replace("__` production chains, `script_template.rs` renderer present. The security fix is integrated; the "pending on branch" status is stale in *both* this doc and the source QH ledger. | §3.C rewritten: integrated on main, QH-13 carries the SSH-argv remainder; flagged the ledger's own status header for reconciliation |
| P2 | §3.G "§6.C controls **3/4** UNMET on all 3 platforms" was ambiguous | §6.C has **8** numbered controls; "3/4" means controls **#3 and #4** (2 of 8 unmet), not "3 out of 4"; and "on all 3 platforms" is stated literally only for control #4. | §3.G clarified with the control names and the per-platform qualifier scoped correctly |
| P2 | §3.D "**24-row** issue register" (SharedUDP) | Current `main` has **21** data rows in the register table (the doc is in the dirty working set and was edited since the count). | Corrected to 21; noted the 9 gates / 8-step merge order / candidate-cache rule all confirmed |
| P2 | §3.E implied Increment 3 (relay-fallback) is **code-absent/open** | A full `CrossNetworkStageKind::RelayRemoteExit` stage exists (`stage/cross_network.rs`, arg wiring, `live_linux_cross_network_relay_remote_exit_test` binary). What's actually open is *live proof* + confirming it shares the netns substrate path. | §3.E nuanced |
| P2 | §4 Phase-4 ordering | Release-*blocking* items (QH-04, the §3.G NO-SHIP set, QH-28) sit in "Phase 4 of 4," which reads as "do last." | Ordering-caution box added at Phase 4 stating these run parallel-from-day-one |
| P3 | §3.C QH-04 "self-heals ~5s" | The ~5s is the failure-*tolerance* window (`MAX_RECONCILE_FAILURES=5` × `RECONCILE_INTERVAL_MS=1000`, `daemon.rs:337/338`), not a fixed heal duration; recovery is on the next successful reconcile. | §3.C precision fix |

### Confirmed sound this pass (previously unverified, now checked)

- **QH HIGH items:** QH-04 (release-blocking/unassigned + the `daemon.rs:337/338` constants), QH-26 (3 WIP commits `f1ef83b1`/`f54edda5`/`15cf9f11` on `origin/main`), QH-28, QH-54 (3 blueprints, unimplemented — **corrected 2026-08-27:** those blueprints are the transport/relay P1/P2/P3 designs, *not* the firewalld re-bind; the re-bind had only two one-line options in the ledger and is now fixed), QH-13 (7-of-8 open), QH-40, QH-45, QH-16, QH-18 (design corrected 07-26, no lock exists) — **all confirmed against the ledger with quoted status markers** (only QH-46 and QH-01 above diverged).
- **QH MED list:** all 26 IDs (QH-05/06/08/09/11/14/15/17/19/21/24/25/27/29/31/32/33/34/36/38/47/48/51/52/55/62) **exist and read OPEN** — no already-closed item masquerading as open, no missing ID. Detail claims QH-48 "21 skips", QH-51, QH-62-is-newest all confirmed.
- **Dataplane D# "Done (code)":** D2 STUN (`stun_client.rs`, 1895 lines), D2.3 uPnP (`port_mapper.rs`), D2.4 IPv6, D3 shared transport, D2.5 signed gossip, D2.7 enrollment, D4 relay (`rustynet-relay/src/main.rs`, 5499 lines), D5.5 ICE (`ice_priority.rs`), D11 anchor, D12 taxonomy, D13.a–e — **all real code, not stubs.** D5/D6/D7/D9/D10 absence (not-started) confirmed.
- **nas/llm:** both crates have real `[[bin]]` targets (718 / 615 lines of `main.rs`); all four gate scripts present under `scripts/ci/`; no nas/llm stages wired into the live-lab registry → M5 genuinely open. All confirmed.
- **Security-finding counts:** RSA `SecurityAuditLedger_2026-06-18.md` = 66 open (cited Med IDs confirmed open); SecurityReview `SecurityReview_2026-05-24.md` = 21 open, RN-02/06/07 High; SecurityMinimumBar §6.C controls #3/#4 UNMET; §8 all five sign-off boxes unchecked. All confirmed.
- **Design deep-dives:** SharedUDP frames 0x11–0x14 defined, 8-step merge order, 9 required gates, `direct_endpoint`-is-candidate-cache rule — confirmed. SignedTraversalAuthority §9 (block-raw-first, cutover-last), the three P0 sections (§2/§2a/§4), §10's 5 open questions — confirmed; `applied_endpoints` confirmed public at `gossip_runtime.rs:220` (the doc wants it private), `VerifiedCandidateRecord` confirmed not-yet-existing (target type).
- **CI legs (§1.3/§6):** `.github/workflows/cross-platform-ci.yml` has macOS, Debian 13, `linux_e2e`, and Windows jobs; macOS/Debian use `--workspace`, the **Windows job gates an explicit 10-package subset that excludes `rustynet-cli`** (confirmed against the workflow YAML) — §6 item 8's claim is exact. (The runtime "green since 2026-08-15" assertion is CI-run history, outside static-file scope — still take it as the doc states, unverified here.)
- **Housekeeping (§3.H):** the `ai-edit/edit-1786154936952-11678-0` branch + `state/edit-worktrees/…` worktree (commit `58b19ce4`) confirmed present. D14.e/f "gated on user sign-off" confirmed against the dataplane plan (`:671-683`).

### Coverage statement (what this doc's verification does and does not cover)

After both passes, independently source-verified: the entire git/lab/CI snapshot (§1), every divergence-table row (§2), all of §3.A–§3.H's status claims, the recommended-order structure (§4), and the design-program summaries (§3.D). **Two known limits remain**, neither a defect in the claims, only in what a read-only check can prove: (1) the "**CI green since 2026-08-15**" assertion is run-history, not statically checkable here; (2) the D# "**mock-tested**" qualifier was verified as *code-present*, not as *tests-passing* — no test suite was run this pass (read-only constraint). Everything else in this document has been checked against current `main` source, `git`, or the cited ledger, at the stated commit (`09daefdf`). As with any snapshot doc, this holds *as of 2026-08-19* — a later commit can re-stale §1/§3 the same way QH-46/QH-01 went stale between this doc's drafting and this pass.

### Bottom line (second pass)

The doc's factual spine held up well under full verification — of ~70 individually-checked claims, two were materially wrong (QH-46 closed-not-open; QH-01 integrated-not-pending), both because a *source ledger the doc faithfully summarized* had itself gone stale, not because the doc misread anything. That is the dominant risk mode for a synthesis doc like this: it is only as current as the ledgers under it, and two of those ledgers drifted. Net effect of this pass: **the release-blocker list shrank** (QH-46 removed) and a shipped security fix (QH-01) was correctly re-classified from pending to integrated — both moving the picture toward *more done than the doc claimed*, the opposite of the first pass's "safer than reality" skew. An agent picking up this work can now trust §1–§3 as source-verified at `09daefdf`, subject only to the two coverage limits above.
