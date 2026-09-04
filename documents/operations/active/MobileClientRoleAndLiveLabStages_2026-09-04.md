# Mobile Client Node Role & Live-Lab Stage Design (iOS + Android)

- **Date:** 2026-09-04
- **Status:** DESIGN ONLY — greenfield proposal, **untrusted until reviewed and built**. No code, stage, or matrix row in this document exists yet. Every "proposed" marker below means exactly that.
- **Companion:** `MobileClientRustArchitecture_2026-09-04.md` (architecture of the mobile Rust stack itself: engine, PacketTunnelProvider / VpnService integration, key custody). This document owns the **node-role semantics** and the **live-lab proving plan**. The architecture doc does not yet exist in the tree at the time of writing; this doc references it by its planned name only.
- **Relationship to the parity mandate (corrected 2026-09-04):** this is a **newly-scoped greenfield program, not part of the existing release-blocking parity mandate.** `CrossPlatformRoleParityPlan_2026-06-21.md` scopes parity to **macOS + Windows** and explicitly classifies mobile clients as *"out of scope by design … not a parity gap"* (§3 matrix; echoed at `CrossPlatformRoleParityRoadmap_2026-06-22.md`:81). This design does **not** claim mobile is mandated; it *adopts* the mandate's Definition of Done — no role is complete until it is **LIVE-LAB-PROVEN** on the engine of record (the Rust `--node` orchestrator ledger `documents/operations/live_lab_node_run_matrix.csv`, status of record `CrossPlatformRoleParityRefresh_2026-07-23.md` §1) — as the quality bar a mobile program would have to clear. Promotion is gated on live evidence exactly as the desktop cells are, but **adding mobile is a scope decision for the owner, not a pre-existing obligation.**
- **Read order:** this document follows the repository precedence (`AGENTS.md` §2): Requirements → SecurityMinimumBar → the parity ledgers → this design.

---

## 0. Summary

1. **No new `NodeRole` variant.** The mobile client *is* `NodeRole::Client`, on a new *platform* (`VmGuestPlatform::Ios` / `::Android`). The platform plumbing already exists; the role-assignment gate and the stage set do not.
2. **Product capability set on a phone is client-only:** membership, gossip, managed DNS, tunnel dataplane. No exit, anchor, relay, blind-exit, or service-hosting capability is proposed for mobile.
3. **Enrollment reuses the existing signed single-use token flow unchanged** — new *transports* (QR / deep-link / adb intent), same `verify_and_consume` semantics, same single-use ledger, same replay posture.
4. **Eight new live-lab stage IDs** (plus one setup stage) are proposed for the `--node` engine, with an honest simulator/emulator vs. real-device split per stage, driven by a new **mobile probe transport** (the orchestrator's SSH plane does not apply to a phone or a Simulator).
5. **Parity matrix gains `ios_client` and `android_client` cells** on the `--node` engine, with the same LIVE-LAB-PROVEN Definition of Done as every desktop cell.
6. **Phased plan M0–M4**, smallest live proof first: boot → enroll+join → dataplane → resilience → parity promotion. The role gate (`role.rs:94,110` and the sibling arms in expanded §1.4) is widened **only after** M1–M3 are green — the same posture-promotion discipline the Windows exit role followed.

---

## 0.1 Corrections and caveats from adversarial review (2026-09-04)

This design was adversarially reviewed in
`MobileClientRoleAndLiveLabStages_AdversarialReview_2026-09-04.md`. Its findings
are folded in here, each re-verified against the working tree:

- **This is not mandated parity work.** The header's original "mandate served"
  framing was corrected: `CrossPlatformRoleParityPlan_2026-06-21.md` scopes
  parity to macOS + Windows and classifies mobile clients as "out of scope by
  design … not a parity gap" (§3 matrix; echoed at
  `CrossPlatformRoleParityRoadmap_2026-06-22.md`:81). Mobile is a greenfield
  program that *adopts* the parity Definition of Done; adding it is a scope
  decision for the owner, not a pre-existing release obligation. Summary item 5's
  "same LIVE-LAB-PROVEN DoD as every desktop cell" is the bar a mobile cell would
  have to clear, not a claim that the mandate already requires it.
- **The promotion gate is wider than §1.4 first stated.** Beyond
  `is_supported_for_platform` / `is_lab_assignable_for_platform`,
  `daemon_node_role_for_platform` (`role.rs:172`),
  `product_capabilities_for_platform` (`role.rs:183`, which returns `Err`), and
  `impl TryFrom<VmGuestPlatform> for TopologyPlatform` (`vm_lab/topology.rs:101`)
  also fail closed on `Ios | Android` and must be widened in the same commit —
  see the expanded §1.4 item 4. A promotion that flips only the support gate
  dead-ends at daemon-role assignment and capability emission.
- **Citation fix:** the replay-report evaluator is `evaluate_enrollment_replay_report`
  at `vm_lab/mod.rs:21222`, not `lab_state.rs:7620` (corrected at §1.5 and §7).
  The separate MCP flag-mapping cite `lab_state.rs:6491-6495` is correct and
  unchanged.
- **Stage count fix:** the summary said "six new stage IDs"; the §3.3 table and
  §3's own "nine rows" wording list **eight** new live-lab stages plus one setup
  stage (nine total). Corrected to eight.

Review verdict: buildable as a newly-scoped program, sound in its
reuse-`Client`-add-a-platform thesis, provided the mandate framing and the full
gate list above are read as corrected here.

---

## 1. Role model: reuse `NodeRole::Client`, add a platform

### 1.1 Current state (verified in tree, HEAD `9467599d`)

- `crates/rustynet-cli/src/vm_lab/orchestrator/role.rs:12-23` — `enum NodeRole { Exit, Anchor, Admin, Relay, BlindExit, Client, Entry, Aux, Extra, Custom(String) }`.
- `role.rs:75-99` — `is_supported_for_platform` is the role×platform gate. Its doc table (`role.rs:61-71`) lists `Client` for Linux/Windows/macOS and **✗ for iOS and Android**. The iOS/Android match arm returns `false` (`role.rs:93-94`) with the comment at `role.rs:73-74`: mobile adapters "fail closed with security-specific rejection messages (unreviewed key custody + connection model + daemon coverage)".
- `role.rs:105-113` — `is_lab_assignable_for_platform` likewise refuses iOS/Android (`role.rs:110`), so the orchestrator cannot even *assign* a mobile node today, independent of product support.
- `crates/rustynet-cli/src/vm_lab/mod.rs:1894-1900` — `enum VmGuestPlatform { Linux, Macos, Windows, Ios, Android }` (serde snake_case), parse accepts `"ios"|"iphoneos"|"ipad_os"|"ipados"` and `"android"` (`mod.rs:1903-1914`), alias inference at `mod.rs:1916-1954`. **The platform enum is ready; the roles are not assignable to it.**

### 1.2 Decision: no new `NodeRole`

Adding `NodeRole::MobileClient` is rejected, for the same reasons the control-plane keeps capabilities coarse:

- `NodeRole` is the **orchestrator's lab scheduling concept** (uniqueness, membership ownership, plan building — `role.rs:27-40`). "Which OS runs the client" is not a scheduling concept; "which guest platform" already is (`VmGuestPlatform`).
- On the control plane the node is identified by **`RoleCapability`** (`crates/rustynet-control/src/roles.rs:6-41`). A phone holds exactly `RoleCapability::Client`. A new role would demand a new capability variant, and `RoleCapability` variants are **append-only and order-sensitive** — the derived ordering feeds the canonical signed pre-image (`roles.rs:18-21`), so variants are not to be added casually. No new variant is needed: `Client` already means "member that terminates its own traffic".
- Every role-specific code path that would fork on "is mobile" is a platform gate (`is_supported_for_platform`), not a role gate. Precedent: `daemon_node_role_for_platform` already maps one lab role to different daemon roles per platform (`role.rs:130-140`).

**Consequence:** the orchestrator slot stays `"alias:client"` with `platform=ios|android`; the gate that must move is the *platform* arm, not the role enum.

### 1.3 Mobile capability envelope (fail-closed by omission)

A phone is granted, by design, **only**:

| Capability | Mobile | Rationale |
|---|---|---|
| `RoleCapability::Client` | yes | membership, gossip, DNS, tunnel |
| `ExitServer` | **no** | phones roam; exit NAT residency on a device that leaves the LAN is a policy foot-gun; not in scope |
| `Anchor` | **no** | anchor roles require inbound reachability + gossip seed duty; a phone has neither |
| `RelayHost` / `EntryRelay` | **no** | same inbound-reachability argument |
| `BlindExit` | **no** | irreversible role (factory reset to leave) is inappropriate for a personal device |
| `ServesNas` / `ServesLlm` | **no** | service hosting on a phone contradicts the roles' server semantics |

Default-deny is the implementation: the mobile client's capability set is **exactly** what the signed membership bundle assigns, and the mobile engine refuses any bundle granting more than `Client`-class capabilities (fail closed on over-broad trust state, per `AGENTS.md` §3). This refusal is a **security control** and must ship with a negative test in the mobile engine from day one (control + verification pairing, `AGENTS.md` §4).

### 1.4 What has to change in the gate — and when

The fail-closed rejection at `role.rs:93-94` / `role.rs:110` is **correct today** and stays until live evidence exists. Promotion path (mirrors how Windows exit posture was promoted from "lab-assignable, pending evidence" to supported):

1. `is_lab_assignable_for_platform` widened for `Client × (Ios | Android)` **first** — lab-only, so the orchestrator can run the new stages against a Simulator/emulator without the product claiming support.
2. `is_supported_for_platform` widened for `Client × (Ios | Android)` **only after** M2 (dataplane) and M3 (resilience) are green on real devices (§5), and the parity refresh matrix is updated in the same change.
3. The role×platform doc table at `role.rs:61-71` is updated in the same commit as whichever gate moves — the table and the match arms must never drift.
4. **The other fail-closed mobile arms must widen in the same lockstep, or promotion dead-ends at capability emission.** Widening `is_supported_for_platform` (`role.rs:94`) and `is_lab_assignable_for_platform` (`role.rs:110`) is necessary but not sufficient: the `Ios | Android` arms of `daemon_node_role_for_platform` (`role.rs:172`) and `product_capabilities_for_platform` (`role.rs:183`, which returns `Err`), plus `impl TryFrom<VmGuestPlatform> for TopologyPlatform` (`vm_lab/topology.rs:101`), also reject mobile today. Each is a correct default now, and each must be widened — keeping its negative test for the roles that stay unsupported — in the same commit that flips `is_supported_for_platform`; otherwise a "supported" mobile client still cannot be assigned a daemon role or emit capabilities. (The bootstrap / `VerifySshReachability` plane is handled separately by the mobile probe transport, §2.2, not here.)

---

## 2. Enrollment / onboarding on the phone

### 2.1 Reuse, do not fork

The enrollment machinery is platform-agnostic and is reused **unchanged**:

- Token model: `rustynetd/src/enrollment_token.rs:104` (`pub struct EnrollmentToken`), 32-byte secret, `mint_token(_with_clock)` / `verify_and_consume_token(_with_now)`; the secret is zeroised on drop (`enrollment_token.rs:1359`) and `Debug` redacts to tag + token id (`enrollment_token_audit.rs:55`, `secret_log_audit.rs:263`).
- Consumption is a **two-step** verify-then-ledger (`rustynetd/src/enrollment_consume.rs:9-11`), with the single-use ledger under a lock (RSA-0023, `acquire_ledger_lock`).
- Replay posture is already lab-proven (ENR-1 / TOCTOU-1 / RSA-0023 — sequential replay denied; 8 concurrent racers yield exactly 1 winner; validator `evaluate_enrollment_replay_report`, cited at `vm_lab/mod.rs:21222`).
- Anchor serves the enrollment endpoint (`RoleCapability::AnchorEnrollmentEndpoint`, `roles.rs`); the admin path writes hardened 0600 token files (`rustynet-cli/src/main.rs:8129-8315`, consume at `main.rs:8265`, mint subcommand at `main.rs:8181-8196`).

### 2.2 New piece: token *transport* to the phone (design)

The lab and the product share one requirement — get the token to the device **without** logging or persisting the secret:

1. **QR code (product + lab).** The admin surface renders the token (or a scannable encoding of it) as a QR; the mobile app scans it. Lab driving: display QR on the admin node's console/UI, capture via simulator/device camera is *not* automatable reliably — see (4).
2. **Deep link (product).** `rustynet://enroll?...` handled by the app; the app must treat the URL's secret fragment as sensitive-in-memory-only. **No secret in any log line, no secret in the app's persisted state before consumption** — the existing redaction guarantees (`enrollment_token.rs`) must be re-asserted by a mobile-side secrets test.
3. **Direct injection (lab-only automation).**
   - Android: `adb shell am start -a android.intent.action.VIEW -d "<enroll url>"` or a debug-only content provider; the token transits adb, not the network.
   - iOS Simulator: `xcrun simctl openurl booted "<enroll url>"` — the sanctioned automation path for deep links.
   - Real iOS device: no equivalent of `simctl openurl` over the wire; the lab falls back to QR (camera) or manual paste on the device, or — preferred for automation — the app exposes a **debug-build-only** local enrollment listener bound to loopback, reachable via `adb reverse` (Android) or a USB-tunneled port (iOS, `iproxy`-style), removed entirely from release builds.

**Anti-requirement:** no enrollment-over-gossip, no self-service token generation on the phone. The phone never mints; it only consumes. Fail closed: a phone handed a token whose signature/epoch/expiry checks fail consumes nothing and reports an error state.

### 2.3 Key custody on the phone

Out of scope here beyond the gate: the mobile engine's long-term identity keys live in iOS Keychain / Android Keystore (or the encrypted-at-rest fallback with strict permissions per `AGENTS.md` §4). This is the **companion architecture doc's** subject (`MobileClientRustArchitecture_2026-09-04.md`); this document treats "key custody verified" as an input to M2 and cites the existing fail-closed comment at `role.rs:73-74` as the reason it must be designed before promotion, not after.

---

## 3. Live-lab stages for the mobile client

### 3.1 The transport problem (be honest about it)

Every existing stage drives guests **over SSH** (`VerifySshReachability`, `BootstrapHosts`, the `DaemonProbe` trait family — `vm_lab/mod.rs:10216-10255`). A phone has no SSH server (iOS: none, by platform rule; Android device: not stock). The Simulator/emulator are host-local processes, not network guests.

**Proposed: a second probe transport alongside SSH.** `DaemonProbe` already isolates *what* to run (`build_argv`, shell-safe-token validation `mod.rs:10241-10250`) from *how* it reaches the target (`platform_label`). The design adds a `MobileProbe` implementor per platform:

- **iOS Simulator:** host-local `xcrun simctl` (boot/install/launch/openurl/push/privacy/status_bar) + the **iOS Simulator MCP** already present on this Mac (`mcp__Claude_Code_iOS_Simulator__*`: boot, install, UI drive, screenshot) as the interactive driver; `simctl` remains the scriptable primitive the orchestrator calls, so the stage does not *depend* on an MCP being attached. App stdout/diagnostics via `simctl launch --console-pty` or unified log (`simctl spawn booted log show`).
- **Android emulator:** headless AVD (`emulator -avd … -no-window -no-audio -gpu swiftshader_indirect -no-snapshot`), driven by `adb install / shell am start / shell uiautomator` / `adb exec-out`. `adb shell` is the honest moral equivalent of the SSH plane and needs no new daemon.
- **Real devices (M2+):** Android over `adb` (USB/TCP, `adb tcpip`); iOS over USB with a helper (XCUITest runner or `devicectl`), explicitly **slower and less parallel** — one device per run lane.

The inventory type stays `VmGuestPlatform::Ios/Android` (`mod.rs:1894-1900`); a mobile "guest" entry records its driver (`simulator`, `emulator`, `device`) instead of an SSH endpoint. Bootstrap stages (`BootstrapHosts`, `VerifySshReachability`) **skip** mobile guests; a new `MobileRuntimeReady` setup stage replaces them (below).

### 3.2 Simulator vs. real device — the honest split

| Concern | iOS Simulator | Android emulator | Real device needed? |
|---|---|---|---|
| App process, UI, enrollment UX, state machine | yes | yes | no |
| Deep-link/QR/token consume + ledger effects (server-side verifiable) | yes (`simctl openurl`) | yes (`am start`) | no |
| Gossip/membership control plane (outbound TCP from app) | yes (shares Mac network) | yes (beh emulator NAT) | no |
| **`PacketTunnelProvider` (NetworkExtension) tunnel** | **NO — NetworkExtension VPN provider processes do not run in the iOS Simulator; this is a platform limitation, not a rustynet gap** | partial — `VpnService` *does* run in the emulator, but dataplane traverses emulator NAT; treat as smoke, not proof | **iOS: YES for every tunnel stage. Android: yes for proof-grade dataplane** |
| Killswitch / leak semantics (routing enforced by the tunnel provider) | no | weak | **yes** |
| Roaming (Wi-Fi ↔ cellular), real interface churn | no (`simctl` cannot switch networks) | faked at best | **yes** |

This split is the load-bearing honesty of the doc: **M1 (control plane) is provable in Simulator/emulator; M2/M3 (dataplane, killswitch, roaming) are not**, and no stage in §3.3 may claim device-grade status from a simulator run. The FAIL-LOUD contract (§4.5) forbids labeling a simulator pass with a device-stage's name.

### 3.3 Proposed stage family

All names are proposed `StageId` wire names. Suite/Tier follow the existing catalog conventions (`stage/mod.rs:134-167` row shape `Variant => "wire_name" @ Suite / Tier`; tier vocabulary T0–T5 from `NodeEngineAcceptanceSpec_2026-07-23.md` §3/§9).

| # | Proposed StageId (wire name) | Suite / Tier | What it proves | Sim/emulator? |
|---|---|---|---|---|
| 1 | `MobileRuntimeReady` → `mobile_runtime_ready` | Setup / T0Core | Simulator/emulator boots headless, debug app installs and launches, health endpoint/log line responds. Replaces SSH bootstrap for mobile guests. | yes |
| 2 | `MobileEnroll` → `mobile_enroll` | Live / T1Role | Token minted by admin/anchor; delivered via §2.2 transport; app consumes; **server-side ledger row exists** (the ledger is the evidence, not the app's UI). | yes (ledger check is server-side) |
| 3 | `MobileMeshJoin` → `mobile_mesh_join` | Live / T0Core | App connects to peers/anchor; membership bundle applied; node visible in gossip. | yes |
| 4 | `MobileMeshStatus` → `mobile_mesh_status` | Live / T0Core | Mobile equivalent of `MeshStatusValidation` via `DaemonProbeOp::MeshStatus` (`mod.rs:10182-10195`) — implemented as a mobile probe (app-local status query), same op semantics. | yes |
| 5 | `MobileEnrollmentReplay` → `mobile_enrollment_replay` | Live / T5NegativeControl | Re-offer the same token (fresh app state); consumption is denied; ledger shows no second row. Direct mobile-face of ENR-1/RSA-0023. | yes |
| 6 | `MobileDnsFailclosed` → `mobile_dns_failclosed` | Live / T4Security | Managed-DNS fail-closed on the phone: with tunnel up, resolver answers; with tunnel down, DNS **fails closed** (no silent plaintext fallback to the carrier/ISP resolver). Simulator/emulator may *develop* this; **pass requires a real device** because the enforcement point is the tunnel provider's routing. | develop in sim, pass on device |
| 7 | `MobileTwoHop` → `mobile_two_hop` | Live / T1Role | The mobile-face of `live_two_hop_validation`: phone's traffic traverses the mesh (client → … → exit) and is verifiably egressing at the exit. Requires PacketTunnelProvider/VpnService carrying real traffic. | **device only** |
| 8 | `MobileKillswitchLeak` → `mobile_killswitch_leak` | Live / T4Security | Tunnel torn down abruptly (kill app provider / toggle VPN off) → **no leak**: no traffic egresses outside the tunnel path. Leak evidence = on-device capture or OS state, not app self-report. | **device only** |
| 9 | `MobileRoaming` → `mobile_roaming` | Live / T2Resilience | Network transition (Wi-Fi↔cellular on Android device via adb data commands; iOS via controlled interface change) → session survives or re-establishes; replay watermarks hold. The mobile sibling of `LiveNetworkFlapValidation`. | **device only** |

Notes:

- **No `MobileMixedTopology` yet.** `live_mixed_topology_validation` requires Linux+macOS+Windows all present (`stage/mod.rs:273`); a four-OS cell is deliberately out of scope for the first cut and listed as future work (§6).
- **Chaos/soak** variants (`extended_soak`, chaos suite) for mobile are future work pending M2; a phone soak is a battery/thermal story the lab cannot yet hold.
- Stages 5 is deliberately a **negative control in the Live suite's T5 tier** — it must run even when everything else is green.

### 3.4 What "pass" means (no app self-trust)

Per the repo's evidence standard, a mobile stage's pass is **never** derived from the app's own claim:

- enrollment: server-side ledger row (`enrollment_consume.rs` semantics) + replay-audit report;
- mesh-join/status: control-plane view (gossip/anchor side) agreeing with the app's status;
- dataplane: egress observed **at the exit node** (the same evidence shape the desktop two-hop uses);
- killswitch: absence of egress observed on-device/OS-side;
- roaming: peer-side continuity observations.

This is the same "live result = stage status; no dry-run-as-pass" discipline the Roadmap specifies, extended to mobile.

---

## 4. Orchestrator slot-in (proposed mechanics)

### 4.1 Stage IDs and the compiler-enforced triad

Per the catalog contract (`stage/mod.rs:92-97`), each new stage = **one** `define_stage_catalog!` row + **one** `OrchestrationStage` impl + **one** `PlanBuilder` instantiation arm; the exhaustive match makes omission a compile error (RNQ-16 keeps `StageId::ALL` in plan order). The nine rows of §3.3 slot into the existing catalog at `stage/mod.rs:173-330`, ordered so setup (`mobile_runtime_ready`) precedes all Live mobile stages.

Each mobile stage's **plan arm** declares its platform gating, mirroring how `MacosRoleTransitionValidation` is gated on `--role-switch-platform macos` (`stage/mod.rs:247`) and `MacosRebootRecoveryValidation` on `--reboot-platform macos` (`stage/mod.rs:257`): **a mobile stage is `not_run` when no mobile node is elected**, and — critically — a *simulator-run* stage reports itself as such in its report artifact (§4.5).

### 4.2 Election selector

Mirror the existing platform-election flags (`--exit-platform/--anchor-platform/--role-switch-platform/--reboot-platform`, parsed at `rustynet-cli/src/main.rs:4478-4484`; parsing helper `parse_optional_platform` at `vm_lab/topology.rs:511-515`):

- `--mobile-platform <ios|android>` — elects the inventory's mobile guest of that platform into the **client** role for this run, and arms the `mobile_*` stages.
- MCP surface: `ai_lab_run` gains `mobile_platform` alongside `exit_platform`/`relay_platform`/… (mapping pattern at `lab_state.rs:6491-6495`).
- Run-exclusion: mobile stages join the exclusion matrix (`vm_lab/run_exclusion.rs:465-471` pattern) so a run without an elected mobile node marks them `not_run` — never `skip`-as-green.

### 4.3 Inventory & guest entries

Mobile "guests" are new inventory entries with `platform: ios|android` (enum already accepts them, `mod.rs:1894-1900`), a `driver` field (`simulator|emulator|device`), and **no** `ssh` endpoint. `BootstrapHosts`/`VerifySshReachability` skip driver-backed guests; `MobileRuntimeReady` owns their readiness (boot AVD / boot Simulator device / attach device, install debug build, health check).

### 4.4 Run-matrix columns

`documents/operations/live_lab_node_run_matrix.csv` grows two per-OS blocks on the `--node` engine's ledger, mirroring the existing `linux_/macos_/windows_` columns:

- `ios_present`, `ios_client`, then `ios_stage_mobile_runtime_ready`, `ios_stage_mobile_enroll`, `ios_stage_mobile_mesh_join`, `ios_stage_mobile_mesh_status`, `ios_stage_mobile_enrollment_replay`, `ios_stage_mobile_dns_failclosed`, `ios_stage_mobile_two_hop`, `ios_stage_mobile_killswitch_leak`, `ios_stage_mobile_roaming`;
- the identical `android_*` block.

Value vocabulary stays `pass/skip/not_run/fail`, plus a **qualifier convention**: the report artifacts (not the CSV cell) record `surface=simulator|emulator|device`. The CSV deliberately stays coarse; the artifact is the evidence (same rule as §12.3 of `AGENTS.md`: the row confirms existence/attribution, the stage's report artifact carries the claim). A `mobile_two_hop` pass recorded with `surface=simulator` would be a **contract violation**, detectable in review of the artifact bundle.

### 4.5 FAIL-LOUD contract for mobile

Extending the Roadmap's live-stage spec to mobile, each stage writes its own report artifact carrying: `surface` (simulator/emulator/device), driver versions (Xcode/simctl runtime, emulator/AVD image, adb), app build id, and the evidence block per §3.4. Rules:

1. Stage status comes **only** from the stage's own probe evidence — a booted simulator is `mobile_runtime_ready`'s business, never `mobile_mesh_join`'s.
2. A stage that cannot run its honest surface (e.g. `mobile_two_hop` with no device) is **`not_run`**, loudly, in `first_failed_stage`-visible form — not `skip`.
3. No dry-run-as-pass: `--dry-run` wiring checks never touch the ledger.

### 4.6 Source/build pipeline dependency

Mobile stages need app artifacts. Cross-compile prerequisites are tracked by `CrossCompileThenCloneDesign_2026-09-04.md` (merged at `68deffd8`); the mobile stage design consumes its outputs (iOS .app for the Simulator destination, Android APK/AAB for the emulator) and treats "artifact present + installable" as part of `mobile_runtime_ready`, failing loudly if the toolchain leg for a platform is absent.

---

## 5. Phased plan (smallest live proof first)

**M0 — boot (Setup, T0Core).** `mobile_runtime_ready` green for Simulator **and** emulator, headless, from the orchestrator, on this Mac: AVD boots with `-no-window`; Simulator device boots via `simctl`; debug app installs and launches; health line observed. DoD: stage row `pass` on the `--node` ledger with artifact; **no mesh interaction required**. Risk retire: headless-boot flakiness, artifact availability (§4.6).

**M1 — control plane (enroll + join).** `mobile_enroll`, `mobile_mesh_join`, `mobile_mesh_status`, `mobile_enrollment_replay` green in Simulator/emulator against a real Linux anchor/admin backbone (existing desktop nodes provide anchor/exit roles; the phone joins as a plain client). DoD: server-side ledger evidence for enrollment (incl. replay denial), gossip-side confirmation of membership. **This is the first genuine mobile parity evidence on the engine of record.**

**M2 — dataplane (device).** Acquire real devices (1× Android, 1× iOS; iOS requires signing/provisioning — a known non-code dependency, listed in §6). `mobile_two_hop`, `mobile_dns_failclosed` (device pass), first `mobile_killswitch_leak`. DoD: exit-side egress evidence for two-hop; fail-closed DNS behavior observed with tunnel down; leak test shows zero egress.

**M3 — resilience (device).** `mobile_roaming` (interface churn, session re-establishment), enrollment restart/reboot recovery on device; leak test under roaming transitions. DoD: T2-tier green on device.

**M4 — parity promotion.** Only now: widen `is_supported_for_platform` (+ keep `is_lab_assignable_for_platform` per §1.4), update the role×platform table (`role.rs:61-71`), append the `ios_client`/`android_client` rows to `CrossPlatformRoleParityRefresh` §1 with run-matrix citations, and update `documents/CODE_MAP.md` / `AGENTS.md`+`CLAUDE.md` mirror per §13.4/§14. DoD: the parity mandate's own wording satisfied — role proven **live** on the new OS, matrix says so with evidence links.

Each milestone lands as its own commit(s) with the full §7 gate list for touched code, and the verifying stage row in the ledger — same cadence as every prior role cell.

---

## 6. Risks, open questions, non-code dependencies

1. **iOS signing.** Real-device M2 needs an Apple developer identity + provisioning for the NetworkExtension entitlement. Non-code, operator-owned; M0/M1 (Simulator) deliberately do not need it.
2. **iOS Simulator cannot run PacketTunnelProvider** — permanent platform fact (§3.2). All tunnel-stage design assumes device lanes exist before M2 starts.
3. **Parallelism.** One Simulator + one emulator can run concurrently on this Mac (matches the ≤3 concurrent-run policy); real devices are serial lanes. The PlanBuilder should treat device lanes as exclusive resources.
4. **Mixed four-OS topology** (`live_mixed_topology_validation` analogue) deferred; requires the existing Linux+macOS+Windows cell to be green first (`stage/mod.rs:273` semantics).
5. **Simulator network is the Mac's network** — a Simulator-run leak test proves nothing; guards against confusion are the `surface` field (§4.4/§4.5) and T5 negative controls.
6. **App-side secrets** — deep-link handling and screenshots must not capture the token; extend `secrets_hygiene_gates.sh` patterns to the mobile crate when it exists.
7. **Battery/thermal soak** — mobile soak/chaos tiers deferred until a device-dock story exists.

---

## 7. References (all verified in tree at HEAD `9467599d` unless marked proposed)

- `crates/rustynet-cli/src/vm_lab/orchestrator/role.rs:12-23,27-40,61-74,75-99,105-113,130-140` — NodeRole, platform gates, fail-closed mobile rejection.
- `crates/rustynet-cli/src/vm_lab/mod.rs:1894-1954` — `VmGuestPlatform` incl. `Ios`/`Android`.
- `crates/rustynet-cli/src/vm_lab/mod.rs:10182-10284` — `DaemonProbeOp`, `DaemonProbe` trait, Linux probe dispatch.
- `crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs:30-90,92-97,99-132,134-167,173-330` — stage modules, catalog macro, suites/tiers, existing rows.
- `crates/rustynet-control/src/roles.rs:6-41,18-21,44-62` — `RoleCapability`, append-only ordering/signed pre-image.
- `rustynetd/src/enrollment_token.rs:104,1359`; `rustynetd/src/enrollment_consume.rs:9-11`; `rustynetd/src/enrollment_replay_audit.rs`; `rustynet-cli/src/main.rs:8129-8315,8181-8196,8265`; `rustynet-cli/src/ops_install_systemd.rs:56` — enrollment token, consume, ledger, replay audit, hardened token files.
- `rustynet-cli/src/main.rs:4478-4484`; `vm_lab/topology.rs:511-515`; `vm_lab/run_exclusion.rs:465-471`; `vm_lab/mod.rs:21222` (evaluator), `lab_state.rs:6491-6495` (MCP flag mapping) — selectors and MCP plumbing.
- `documents/operations/live_lab_node_run_matrix.csv` — ledger schema the `ios_*`/`android_*` blocks extend.
- `documents/operations/active/CrossPlatformRoleParityRefresh_2026-07-23.md` §0-§2 — mandate, status matrix, critical path.
- `documents/operations/active/CrossPlatformRoleParityPlan_2026-06-21.md`, `CrossPlatformRoleParityRoadmap_2026-06-22.md` — decree + FAIL-LOUD live-stage spec.
- `documents/operations/active/CrossCompileThenCloneDesign_2026-09-04.md` (merged `68deffd8`) — cross-compile pipeline the mobile artifacts depend on.
- `documents/operations/active/NodeEngineAcceptanceSpec_2026-07-23.md` §3/§9 — tier vocabulary.
- `MobileClientRustArchitecture_2026-09-04.md` — companion architecture doc (planned; engine, tunnel-provider integration, key custody).
