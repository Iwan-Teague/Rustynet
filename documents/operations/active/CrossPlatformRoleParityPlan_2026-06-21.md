# Cross-Platform Role Parity Plan — 2026-06-21

> **READ THIS IF YOU ARE ASSESSING PROJECT COMPLETENESS.** This document is the
> single source of truth for the requirement that **every Rustynet node role and
> capability must work — and be live-lab-proven — on Linux, macOS, AND Windows.**
> It consolidates a requirement that was previously scattered across several
> delta plans so it cannot be missed.

## 1. Mandate (non-negotiable completeness criterion / release blocker)

Rustynet **cannot be called complete** until a user can run it on whatever
computer they have — Linux, macOS, or Windows — and operate that node as **any**
role with no OS being a capability limiter:

> client · admin · anchor · exit · blind_exit · relay · (service-hosting: nas · llm)

**Linux is the reference platform and has full role parity, proven live.**
**macOS and Windows do NOT yet.** Closing that gap — every role, every
capability, every constraint/config/variable, proven live in the UTM lab on both
macOS and Windows — is a **release blocker**. Security is never traded for parity:
each role's platform-native dataplane must preserve fail-closed, default-deny,
kill-switch, DNS-fail-closed, signed-state verification, and anti-replay exactly
as Linux does.

## 2. What "parity" means per role (must hold on macOS AND Windows)

For each role, the node must do, **live**, everything Linux does:
- **client** — enroll, ingest signed membership/assignment/traversal/dns, bring up
  the WireGuard tunnel, route through its assigned exit, kill-switch + DNS
  fail-closed in protected mode.
- **admin** — hold signing authority; mint/issue + distribute signed membership
  and assignment bundles to peers; append-only role audit.
- **anchor** — serve the anchor capabilities live: `gossip_seed`, `bundle_pull`,
  `enrollment_endpoint`, `relay_colocation`, `port_mapping_authoritative`.
- **exit** — NAT/masquerade peer egress to the internet with the platform-native
  dataplane (Linux nftables, macOS `pf`, Windows WinNAT/WFP), advertise the
  default route, enforce the exit kill-switch + DNS leak prevention.
- **blind_exit** — the irreversible exit variant (destructive transition;
  factory-reset-only exit path) with the same dataplane + the immutability gate.
- **relay** — run the relay service and forward live sessions for peers that
  cannot hole-punch.
- **service-hosting (nas, llm)** — tracked under the D13 program (see
  `ServiceHostingRolesRoadmap_2026-06-11.md`); parity for these is in-scope for
  completeness too once their base roles land.

Plus **live role transitions** between these roles on each OS (Linux launchd/
systemd ✓; macOS launchd + Windows windows_service — see §6).

## 3. LIVE-PROVEN status matrix (code-present ≠ proven)

Legend: ✅ live-proven · 🟡 implemented, not yet run green live · 🟠 contract/dry-run
validator only (no live runtime) · ❌ untested / not implemented · 🔒 blocked.

| Role / capability | Linux | macOS | Windows |
|---|---|---|---|
| client (tunnel + route through exit) | ✅ | ✅ (mac2, 2026-06-21: ExitActive, live handshake) | ✅ join+security proven (win3); active client traffic pending cross-OS run |
| admin (mint/issue signed bundles) | ✅ | ✅ **live-proven 2026-06-22** (`validate_macos_admin_issue` stage, run `livelab-1782135034`): the macOS node mints its own assignment signing authority (`assignment init-signing-secret`) + issues a valid signed assignment bundle (`assignment issue`, 447 bytes) on the guest; `--admin-platform macos` selector + `is_macos_active_admin` gate + FAIL-LOUD stage. The earlier "self-mint deliberately disabled" note was unbacked by code. | ❌ (trust keygen works; live issuing untested — port the `validate_macos_admin_issue` pattern via the Windows PowerShell-encoded path) |
| anchor (gossip/bundle-pull/enrollment/port-map) | ✅ | ✅ **bundle-pull LIVE-PROVEN 2026-06-22** (run `live-lab-anchor-fix2`, `validate_macos_anchor_bundle_pull` PASS): implemented end-to-end (launchd `com.rustynet.anchor.plist` loopback bundle-pull profile + `ops install-macos-anchor` verify-before-serve installer + `macos_service_hardening` reviewed-shape validator + `ops e2e-bootstrap-macos` seeds the bundle-pull token + live `live_macos_anchor_test` bin asserting loopback byte-for-byte / token gate / LAN-bind refused / secrets hygiene, wired into the `validate_macos_anchor_bundle_pull` vm_lab stage, FAIL-LOUD: the live result is authoritative and the dry-run plan is informational-only, never a Pass) — **deploy + listener live-proven**: `deploy_macos_anchor_profile` now DERIVES the anchor launchd profile from the proven `com.rustynet.daemon.plist` (inheriting its node-specific keychain account + `/bootstrap/` passphrase custody + state paths) and adds ONLY the bundle-pull listener (verify-before-serve loopback + allow-lan=false asserted in-stage); `amend_membership_for_macos` grants `anchor.bundle_pull` when elected; `ops seed-macos-anchor-token` chowns the token to the `rustynetd` daemon user. This fixed three layered crash-loop bugs found via the focused-loop on .210 (generic keychain account `wg-passphrase-daemon-local` → node-specific from the client plist; static-plist state-path divergence → derive-from-client; root-owned token → chown). Listener binds `127.0.0.1:51822` and the live test passes loopback byte-for-byte + token gate + LAN refused + secrets hygiene. (Known follow-up: `cleanup_hosts` must bootout `com.rustynet.anchor` between runs.) gossip/enrollment/port-map still via the shared `live_linux_anchor_test --platform macos` path | 🟠 dry-run plan contract only (`validate_windows_anchor_bundle_pull_plan_contract`) |
| exit (NAT egress + route advertise + killswitch) | ✅ (nftables) | 🟡 **capture implemented, ACTIVATION MISSING (gap found 2026-06-22)** — the evidence machinery exists end-to-end (`capture_macos_exit_evidence_artifacts` + 3 wrappers: `capture_macos_exit_nat_lifecycle.sh` / `_dns_failclosed.sh` / `_killswitch_precedence.sh`; the `rustynetd macos-exit-nat-lifecycle-snapshot` tool, confirmed present on .210; `macos_exit_killswitch_precedence.rs` pf report) and the NAT wrapper is a *real* lifecycle proof (snapshot daemon-in-exit-mode → `launchctl bootout system/com.rustynet.daemon` → snapshot torn-down → restart). **But nothing in `run_macos_orchestration_stages` activates the exit**: `is_macos_active_exit` only gates the capture stage (8638/8656/8704), `amend_membership_for_macos` does not grant exit caps, and there is no role-transition-to-exit / daemon exit-mode bring-up. On .210 `role transition-check --to exit` returns a multi-step operator flow (`role set admin` → restart → `role set exit` → restart) and pf `com.rustynet/nat` is absent in client mode. So a `--exit-platform macos` run would snapshot a **client** daemon (`pf_anchor_present=false` during) and fail/degenerate. **Deeper (2026-06-22, definitive code audit): the regular macOS exit NAT _dataplane_ is itself unimplemented, not merely unactivated.** `macos_exit_nat_lifecycle.rs` is read-only (`pfctl -a com.rustynet/nat -s nat` show + `sysctl -n net.inet.ip.forwarding` read — no `-f` load, no `-w` write); the only macOS pf NAT _builder_ is `build_macos_blind_exit_pf_rules` (blind_exit, which **blocks** egress — the semantic opposite of a regular exit that **NATs** egress); and `validate_sysctl_args` permits only the Linux `net.ipv4.ip_forward` toggle, **not** the macOS `net.inet.ip.forwarding` the exit needs (the privileged boundary already permits the pf anchor load `-a <anchor> -f <path>`). So the regular macOS exit is missing, in order: (1) a regular-exit pf NAT ruleset builder; (2) a `net.inet.ip.forwarding=1/=0` schema in `validate_sysctl_args`; (3) the daemon exit-role activation caller + teardown; (4) the orchestration exit-cap grant + role transition.<br>**UPDATE 2026-06-22 — dataplane pieces 1–3 IMPLEMENTED + adversarially reviewed (commits `6571f48`→`2a54ca7`):** (1) `crates/rustynetd/src/macos_exit_nat.rs` — pure pf NAT translation-rule builder + strict evaluator (rejects wrong `on`/`-> ()` interface, injected filter rules, route-to bypass; fail-closed config) for the `com.rustynet/nat` anchor; (2) `privileged_helper.rs` — `net.inet.ip.forwarding=1/=0` write + `-n` read + the `com.rustynet/nat` anchor + `-s nat` show added to the argv allowlist, default-deny preserved by exact-match + negative tests; (3) `phase10.rs` — explicit `ApplyOptions.blind_exit` flag (set from `node_role.is_blind_exit()`; the old `exit_mode==Off` proxy conflated blind vs regular exit) threaded through `apply_nat_forwarding`; `MacosCommandSystem::activate_exit_nat` (filter anchor first → forwarding-enable → load+verify NAT anchor, fail-closed prior-read) + `rollback_nat_forwarding`/`teardown_exit_nat` (flush-then-restore, idempotent, teardown-before-cap-removal per §10.7). IPv6 mesh fails closed (v6 forwarding unwired — tracked follow-up). A 4-dimension adversarial review (31 findings, 27 verified) found + fixed the forwarding-state fail-closed/idempotency bugs and the evaluator strictness gaps; the privileged boundary + blind/regular logic passed clean. gates: fmt + clippy -D warnings clean, all 1650 rustynetd lib tests pass. **REMAINING (piece 4 + live proof): the orchestration `--exit-platform macos` wiring (grant exit caps in membership + drive the role transition so the daemon enters the regular-exit role) + a live `.210` run proving the snapshot reads exit-active during / torn-down after. Live forwarding throughput stays HP-3-gated.** | 🟡 implemented (`promote_windows_exit_active`, `validate_windows_exit_nat_lifecycle`) but 🔒 the lab Windows guest lacks the WinNAT/HNS stack (`MSFT_NetNat` absent) — see `WindowsExitNodeRunbook_2026-06-04.md` |
| blind_exit (irreversible exit) | ✅ | ❌ deferred | ❌ untested |
| relay (live session forwarding) | ✅ | 🟡 **lifecycle focused-proven 2026-06-22 on .210** (`356f8a3`): `install-macos-relay` → relay `state=running`, `127.0.0.1:4501` bound, `/healthz={"status":"ok",...}` → `--uninstall` → released. Live cell `exercise_macos_relay_lifecycle_live` fixed (upload the static reviewed `com.rustynet.relay.plist` + run from a temp cwd since the bootstrap build dir is ephemeral; derive `--verifier-key` from the distributed trust verifier `trust-evidence.pub` written root-owned via `tee`, since `assignment.pub` is not distributed to macOS). Awaiting a `--relay-platform macos` orchestrate-stage pass to flip ✅. **Live session forwarding is HP-3-gated** (no live forwarding proven on ANY OS yet). | 🟠 SCM lifecycle **contract** only (`validate_windows_relay_service_lifecycle_contract`, "without guest mutation") — no live forwarding |
| live role transitions (cross-OS) | ✅ (`role_switch_matrix`) | ❌ not implemented | ❌ not implemented (banked design: `../../../state/cross_os_role_switch_plan.md`) |

## 4. The gap is LIVE PROVING + a few real impls — not (mostly) missing framework

The topology + validator **framework largely landed already** (see
`AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md` Track B — "all seven
steps landed": the `--exit-platform / --relay-platform / --anchor-platform`
topology selectors, macOS exit validators, the platform-aware role-transition
planner + per-OS exit/relay installers, the Windows active-exit promotion stage,
the macOS relay lifecycle dry-run, and `ops e2e-bootstrap-{macos,windows}`
non-Linux genesis verbs). What remains:

1. **Run each role green LIVE** on real macOS/Windows guests (the stages exist but
   are gated off / skipped / contract-only by default).
2. **Upgrade contract/dry-run validators to live** — Windows relay (real session
   forwarding) and Windows anchor (real bundle serving); implement + test macOS
   relay + anchor live.
3. **Close hard blockers** — chiefly a WinNAT/HNS-capable Windows lab guest for
   the exit role.
4. **Implement live cross-OS role transitions** (macOS launchd, Windows
   windows_service StateRefresh) per `state/cross_os_role_switch_plan.md`.
5. **admin + blind_exit** parity decisions + impl for macOS/Windows.

## 5. Live-lab test matrix (acceptance — this is how we PROVE parity)

For every role R ∈ {exit, relay, anchor, admin, blind_exit} × OS ∈ {macOS, Windows}
there must be a recorded GREEN live-lab run that elects that OS into R and exercises
the role's **runtime** (not a contract/dry-run), with the row captured in
`documents/operations/live_lab_run_matrix.csv`.

Driver pattern (same CLI wrapper the loop uses):
```
target/debug/rustynet-cli ops vm-lab-orchestrate-live-lab \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --ssh-identity-file <key> --known-hosts-file <kh> --report-dir state/live-lab-<name> \
  --legacy-bash-orchestrator --stage-timeout-secs 1500 \
  --exit-vm debian-headless-1 --client-vm debian-headless-2 --entry-vm debian-headless-3 \
  --aux-vm macos-utm-1 --windows-vm windows-utm-1 \
  --<role>-platform <macos|windows>   # e.g. --exit-platform windows
  [--promote-... flags as the role requires]
  --skip-soak --source-mode local-head
```
Per role, the stage(s) that must move from contract/skip → live-green:
- **exit (macOS):** `is_macos_active_exit` path + `capture_macos_exit_evidence_artifacts` + `validate_macos_exit_*` (NAT lifecycle, DNS leak, killswitch precedence) — assert live client egress via the macOS node.
- **exit (Windows):** `promote_windows_exit_active` + `validate_windows_exit_nat_lifecycle` + `capture_windows_exit_evidence_artifacts` — asserts `route advertise 0.0.0.0/0` → forwarding + NAT + client egress (`Get-NetNatSession`). **Needs a WinNAT-capable guest.**
- **relay (Windows/macOS):** upgrade `validate_windows_relay_service_lifecycle_contract` / the macOS relay dry-run to a **live relay-forwarding** stage (a peer that can only relay actually forwards through the macOS/Windows relay).
- **anchor (Windows/macOS):** upgrade `validate_windows_anchor_bundle_pull_plan_contract` to **live bundle serving** (a peer actually pulls a bundle from the macOS/Windows anchor); cover gossip_seed / enrollment_endpoint / port_mapping_authoritative live.
- **admin (Windows/macOS):** a live stage where the macOS/Windows node mints + issues a signed membership/assignment that a peer ingests.
- **blind_exit (Windows/macOS):** the destructive-transition + irreversible-exit serving path, with the immutability gate verified.
- **role transitions:** the `role_switch_matrix` stage driving a real transition on a macOS and a Windows node (see `state/cross_os_role_switch_plan.md`).

Each stage must verify the role's **security controls** live: kill-switch, DNS
fail-closed, signed-state verify-before-apply, anti-replay, default-deny ACL/route.

## 6. Known blockers + dependencies

- **Windows exit:** `windows-utm-1` lacks WinNAT/HNS (`MSFT_NetNat` class absent).
  Needs a WinNAT-capable Windows lab guest. Details + run command +
  WinNAT-readiness probe in `WindowsExitNodeRunbook_2026-06-04.md`.
- **Windows relay/anchor:** currently contract/dry-run validators — need live
  serving implementations + live stages.
- **macOS relay/anchor/blind_exit/admin:** untested/undecided live.
- **Cross-OS live role transitions:** not implemented — banked design at
  `state/cross_os_role_switch_plan.md` (note: Windows `StateRefresh` IPC already
  exists; reuse the single verified apply path, never add a second/weaker one).
- **Lab connectivity prerequisites:** `HomelabConnectivityParityDeltaPlan_2026-05-21.md`
  (macOS/Windows tunnel connectivity gap vs Linux).

## 7. Consolidated references (this doc unifies these)

- `AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md` — framework that landed (Track B) + anchor live-lab (Track A).
- `WindowsExitAndRelayDeltaPlan_2026-05-10.md`, `WindowsExitNodeRunbook_2026-06-04.md` — Windows exit/relay specifics + WinNAT blocker.
- `WindowsLiveLabReadinessPlan_2026-05-31.md`, `WindowsLabVmStabilityAndSessionModel_2026-04-30.md` — Windows live-lab path.
- `HomelabConnectivityParityDeltaPlan_2026-05-21.md` — macOS/Windows connectivity gap.
- `NodeRoleTaxonomy_2026-05-21.md` / `NodeRoleTaxonomyExtension_2026-06-11.md` — role definitions + per-platform eligibility.
- `LiveLabExecutionEfficiencyPlan_2026-06-20.md` — how to run the labs efficiently.
- `CrossPlatformRoleParityRoadmap_2026-06-22.md` — **the execution roadmap for this mandate**: per-cell remaining work + effort, ordered program, file-by-file plans for the first cells, the FAIL-LOUD live-stage spec, the concurrent-Windows+macOS test pipeline, and the all-on-`main` workflow.
- `state/cross_os_role_switch_plan.md` — live cross-OS role-transition design **(to author — currently missing; the role-transition cell depends on it; see Roadmap §4/§11.2)**.
- Code anchors: `crates/rustynet-cli/src/vm_lab/mod.rs` (`is_macos_active_exit`, `promote_windows_exit_active`, `validate_windows_{exit_nat_lifecycle,relay_service_lifecycle_contract,anchor_bundle_pull_plan_contract}`, `--*-platform` selectors); `crates/rustynetd/src/macos_exit_killswitch_precedence.rs` (pf); `crates/rustynetd/src/phase10.rs` + `windows_service.rs` (netsh/WFP); `crates/rustynet-cli/src/role_cli.rs` (role presets + transitions).

## 8. Definition of Done (cross-platform role parity)

Parity is complete only when, for **both macOS and Windows**, **every** role in §2
has:
1. a platform-native runtime implementation (no Linux-only assumption),
2. a **green live-lab run** recorded in `live_lab_run_matrix.csv` exercising that
   role's runtime on a real guest,
3. its security controls (fail-closed, default-deny, kill-switch, DNS
   fail-closed, verify-before-apply, anti-replay) verified live, and
4. a verification test (unit/integration + the live stage).

Until all cells in the §3 matrix are ✅, **Rustynet is not cross-platform
complete**, regardless of how polished Linux is.
