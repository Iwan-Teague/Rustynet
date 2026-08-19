# Live-Lab Coverage-Gap Discovery — 2026-08-19

Status: **DISCOVERY ONLY — no lab run, build, benchmark, or source change performed.**

Purpose: identify the live-lab tests Rustynet is not executing, or whose
assertions are too weak to support the quality claim being made. This is a
test-strategy report, not approval to implement a test or change a product
contract. Each recommendation needs design review and an adversarial pass
before it becomes a release gate.

Scope: active Rust `--node` orchestrator only. The active evidence source is
[`../live_lab_node_stage_results.csv`](../live_lab_node_stage_results.csv),
not the frozen bash matrix. Legacy validators are useful implementation
precedents but are not proof for the active engine until promoted into its plan
and recorded in its normalized ledger.

## 1. Method and evidence boundary

Read-only sources inspected:

- `crates/rustynet-cli/src/vm_lab/orchestrator/stage/mod.rs` — canonical
  `StageId` catalog, suite membership, and acceptance tier.
- `crates/rustynet-cli/src/live_lab_stage_registry.rs` — recorded stage
  vocabulary and optional/conditional dispatch policy.
- `crates/rustynet-cli/src/vm_lab/orchestrator/stage/{chaos,cross_network,
  live_network_flap_validation,live_mixed_topology_validation,
  mesh_status_validation,relay_validation,traffic_test_matrix}.rs` — current
  actual stage contracts and dependency graph.
- `crates/rustynet-cli/src/bin/{live_linux_network_flap_test,
  live_linux_reboot_recovery_test,live_linux_exit_handoff_test}.rs` — fault
  shape and live assertions.
- `documents/operations/LiveLabRunMatrix.md`,
  `QualityHardeningTodo_2026-07-25.md`,
  `CrossPlatformRoleParityPlan_2026-06-21.md`, and
  `LiveLabStageTriageLedgerPlan_2026-07-16.md` — project intent and prior
  measured limitations.

No conclusion below is inferred from a green umbrella row. A stage is only
called covered where the normalized active ledger contains its named outcome
and its current implementation supports the stated claim. A historical run is
not current compatibility evidence; it only shows that a scenario was once
attempted.

## 2. Current evidence snapshot

The active normalized ledger has 22,212 node-stage rows. Its newest run is
`livelab-1786908269-5510b726035e`, finished `2026-08-16T19:24:29Z`: five Linux
nodes, with 192 pass and 55 skip outcomes. That run is useful Linux regression
evidence; it says nothing about desktop parity or cross-network behavior.

| surface | active-ledger observation | interpretation |
| --- | --- | --- |
| Linux | 21,275 rows; newest `2026-08-16` | primary exercised surface |
| macOS | 752 rows; newest `2026-08-13`; newest run: 20 pass, 26 skip, 1 fail | focused evidence only; not mixed topology proof |
| Windows | 185 rows; newest `2026-07-25`; newest run: 4 pass, 45 skip, 1 fail, 1 not-proven | stale and mostly skipped |
| `live_mixed_topology_validation` | 497 skips, 0 pass, 0 fail | no active three-OS topology proof exists |
| `live_anchor` | 497 skips, 0 pass, 0 fail | no active anchor scenario proof exists |
| chaos suite | all 9 catalogued chaos stage names have 0 ledger rows | tests exist, but no active run has executed them |
| negative-control suite | all 4 catalogued T5 names have 0 ledger rows | no active deliberately-bad-input adjudication evidence |
| cross-network | NAT classification: 29 pass / 265 skip; NAT matrix and the 8 behavior stages: 0 pass | only a narrow classifier has run; path behavior has not |
| extended soak | 5 pass / 196 skip | too little evidence to claim resilience across variants |

The numbers show two different problems that must not be conflated:

1. **Scenario absent:** no recorded execution at all. Example: every chaos
   and negative-control stage.
2. **Scenario executed under a narrow oracle:** a pass proves only the
   limited assertion in that stage. Example: the network flap is not a
   relay-restart or NAT-rebinding test.

The first requires safe scheduling and prerequisites. The second requires a
new test contract and stronger evidence, not merely more repetitions.

## 3. Highest-value missing test coverage

### G1 — Mixed-platform topology is a hard prerequisite and has never run

**Evidence.** `LiveMixedTopologyValidationStage` requires Linux + macOS +
Windows concurrently, but itself depends on `live_lan_toggle_validation`.
It therefore recorded 497 skips. Every chaos and cross-network stage declares
`live_mixed_topology_validation` as its only dependency. The current active
Windows evidence also predates the latest Linux/macOS activity.

**Quality risk.** A platform-specific role or killswitch bug can pass focused
checks while the actual multi-OS membership, route, DNS, and peer-reachability
combination has never converged. The dependency also hides Linux-only fault
coverage behind unavailable desktop topology.

**Recommended test design; review before adoption.**

- Add a small, dedicated `mixed_platform_mesh_baseline` scenario that requires
  exactly one Linux, one macOS, and one Windows node. It should establish fresh
  membership, prove each ordered pair can carry a marked payload, and record
  expected peers plus per-peer freshness. It should not inherit destructive
  LAN-toggle or enrollment-restart dependencies.
- Keep `live_mixed_topology_validation` as the broad topology gate only if its
  assertion remains broader than the baseline. Do not make it the generic
  prerequisite for every Linux-capable fault test.
- Gate success on per-node, role-aware evidence: daemon identity, peer IDs,
  actual path status, and traffic. A parsed state file or an interface existing
  is not a mesh proof.

**Required disproof tests.** One missing platform, an intentionally invalid
member bundle, stale peer evidence, and a blocked ordered pair must each yield
a named fail/skip reason. A Linux-only run must still be able to execute a
Linux-specific resilience scenario when that scenario does not claim T3
cross-OS coverage.

**Do not take at face value.** Rewiring dependencies can create tests that run
against an invalid baseline. The design must distinguish ordering from a true
data prerequisite, as QH-48 already cautions.

### G2 — Chaos and negative controls exist but have zero active execution

**Evidence.** The `StageId` catalog has nine chaos stages (`clock_attack`,
`crash_recovery`, daemon fault/SIGSTOP, membership, network impairment,
privileged boundary, resource exhaustion, signed-state adversarial) and four
negative controls. None appears in the normalized ledger. `chaos.rs` and
`cross_network.rs` make each depend on the always-skipped mixed-topology
stage. Negative controls are opt-in by design.

**Quality risk.** Unit tests demonstrate a reducer or parser rejects bad input;
they do not prove the installed daemon, service manager, firewall, filesystem
permissions, telemetry, and cleanup compose correctly on a guest. Conversely,
an unexecuted test binary is not release evidence.

**Recommended test design; review before adoption.**

- Create a fault-suite planner with *capability* and *real prerequisite*
  metadata, separate from serial ordering. Examples: `tc/netem` is Linux-only;
  a signed-bundle rejection can be topology-independent; an actual three-OS
  route test is cross-platform.
- Execute one isolated fault per clean, disposable run. The artifact must
  include precondition, exact injected mutation, observed enforcement,
  recovery/cleanup result, and post-cleanup baseline recheck.
- Preserve T5 inversion semantics: a negative-control test passes only when
  the malicious/invalid operation fails for the required reason *and* the
  normal control succeeds immediately afterwards. A rejected input without a
  normal-path recheck is incomplete.

**First execution candidates.** Signed-state rejection, membership adversarial
input, privileged-helper allowlist denial, and clock rollback are high signal
and low blast radius. Network impairment and resource exhaustion need an
explicit resource budget and isolated guest before they are scheduled.

**Do not take at face value.** Never add a production unauthenticated "crash
worker" IPC/SSH command just to make a lab test easy. Fault injection must use
a reviewed test-only seam or a bounded operator-only lab mechanism.

### G3 — Cross-network behavior is essentially unproven

**Evidence.** The active plan defines NAT classification/matrix, direct and
relay remote exit, node-network switch, roaming/failback, controller switch,
traversal adversarial, remote-exit DNS, and remote-exit soak. The ledger has
29 `cross_network_nat_classification` passes, but zero passes for
`cross_network_nat_matrix` and all eight behavior scenarios. QH-48 confirms
that prior skips were caused by dependency cascade, not proof that a substrate
was unavailable.

**Quality risk.** A same-LAN handshake or even a two-hop test does not prove
NAT mapping/filtering handling, relay fallback, path re-selection, roaming, or
remote-exit DNS behavior. Treating classification as traversal proof would be
a false green.

**Recommended test design; review before adoption.**

Build a minimal cross-network progression, each with its own artifact and no
claim beyond its scenario:

1. Establish and record the selected NAT profile and both endpoint candidates.
2. Prove direct encrypted traffic under each required profile.
3. Block direct UDP on both peers, then prove relay-routed encrypted traffic
   with client-side path observation and relay counter delta.
4. Restore direct UDP and prove controlled return/failback without stale route,
   stale candidate, or plaintext leak.
5. Switch a node's simulated network while a marked TCP stream and a UDP flow
   are active; record bounded interruption and post-change ownership.

The existing `live_chaos_network_impairment_test` has loss, delay/reorder,
asymmetry, and MTU-blackhole profiles. Promote its scenarios only after the
planner can actually dispatch them on a Linux-capable topology; do not recreate
another impairment harness.

**Required disproof tests.** A requested NAT profile that was not actually
applied, a spoofed/unknown candidate, relay counters that do not move, direct
path falsely reported as relay, and cleanup failure must all fail closed.

### G4 — Network-flap coverage is direct-path, outbound-port-only

**Evidence.** `live_linux_network_flap_test` blocks client `OUTPUT` UDP with
destination port `51820`, waits 35 seconds, removes the nftables table, then
accepts recovery primarily from traffic crossing the tunnel. That is a useful
direct WireGuard blackout/recovery test. It does not block inbound traffic,
does not target an allocated relay port, and does not restart a relay, change a
NAT mapping, rebind a socket, lose STUN, or change a peer endpoint.

**Quality risk.** Current 61 network-flap passes show recovery from one
deliberate direct-path loss shape. They do not support a claim that traversal
or the shared UDP control/data lifecycle recovers from real topology changes.

**Recommended test design; review before adoption.**

Add a parameterized *transport-path fault matrix*, not several copy-pasted
scripts:

| fault | required evidence | prohibited false green |
| --- | --- | --- |
| client outbound direct-UDP blackhole | current baseline, plus raw applied-rule evidence | nft command merely returning 0 |
| client inbound blackhole / asymmetric loss | no recovered traffic until rule removal | a cached old handshake timestamp |
| direct path withdrawal | relay-routed data, client path state, relay counter delta | a relay health endpoint alone |
| relay restart after a confirmed session | bounded loss then a fresh allocation/re-registration and data | local `send_to` success / old allocation assumption |
| STUN loss while relay remains reachable | relay path remains usable; STUN re-probe separately | blocking relay on missing STUN |
| endpoint/NAT mapping change | prior route invalidated, fresh endpoint selected, data recovery | same local port interpreted as same socket instance |

For each, capture before/during/after path mode, session/overlay identifier,
transport incarnation when the backend provides one, candidate age, and a
marked application payload. The future Shared UDP transport work must first
define safe typed recovery semantics; this lab matrix must not invent those
semantics through brittle string matching.

**Do not take at face value.** A nonce echo or a parseable ACK establishes
correlation/reachability, not authenticated relay liveness. Require current
authenticated WireGuard evidence for any "trusted relay live" verdict.

### G5 — Shared-UDP worker recovery has no safe live-lab proof

**Evidence.** The current QH-54 analysis explicitly distinguishes whole-daemon
kill tests from an in-process userspace worker death. `chaos_daemon_fault`
restarts the daemon; it cannot exercise a still-running backend receiving a
worker-unavailable error. Linux/macOS deterministic backend tests exist, but
no active live stage proves post-worker-recovery firewall binding, candidate
invalidation, or relay re-registration.

**Quality risk.** A tunnel interface can be recreated while routing/firewall
posture, STUN observations, or relay state still describe the old instance.
The ordinary daemon-restart test can pass while this narrower lifecycle path
is broken.

**Recommended test design; review before adoption.**

Do **not** first expose a raw production fault command. First implement and
review the backend contract: typed `WorkerUnavailable`, explicit recovery
receipt/transition, unambiguous desired-state reconciliation policy, and a
read-only status record. Only then add a lab scenario which consumes a
reviewed diagnostic fault hook and proves:

1. baseline authoritative transport and policy posture;
2. unavailable transition, no attempted stale traversal use, and no plaintext
   egress during quarantine;
3. a new authoritative incarnation after recovery;
4. platform firewall/bypass binding reasserted before peer egress;
5. fresh STUN/relay reconciliation and a marked data-path check.

Run this on Linux and macOS separately. Windows command backend must report
unsupported rather than pretend it supplied shared-authoritative-socket proof.

**Do not take at face value.** This is blocked on product design, not merely
missing test code. A lab test must follow the authoritative recovery contract,
never define it.

### G6 — Relay live proof is split; active engine records lifecycle, not HP-3 forwarding

**Evidence.** Active `relay_validation` checks service activity, bound UDP/TCP
ports, `/healthz`, clean stop, and restart. That is lifecycle evidence. A
separate legacy-path helper, `exercise_linux_relay_forwards_frame`, is much
stronger: force relay-only path, require both clients report relay routing,
send marked traffic, require forwarding-counter delta, and check relay capture
for no plaintext marker. The Rust `StageId` catalog has no equivalent
`relay_forwards_frame` stage and the normalized active ledger has no such
recorded name.

**Quality risk.** A healthy relay service can be unable to forward a client
session, and an open UDP port cannot prove ciphertext-only forwarding.

**Recommended test design; review before adoption.**

- Promote the HP-3 semantics into an explicit active `--node` stage with a
  unique stage ID and evidence schema. Reuse the existing Linux harness where
  safe; do not duplicate its firewall/cleanup machinery.
- The stage must be distinct from relay lifecycle and use an explicit
  Linux-only capability until equivalent macOS/Windows mechanisms exist.
- Add a separate relay-restart-with-live-client-flow test under G4. Initial
  forwarding and recovery after server allocation loss are different claims.

**Required disproof tests.** Direct path remaining available, relay counter
unchanged, client path state missing, plaintext marker observed, or cleanup not
proven must fail the stage.

### G7 — Traffic matrix proves ICMP reachability and default deny, not service traffic

**Evidence.** `traffic_test_matrix` gathers mesh IPs, pings every ordered pair,
and then checks a denied TEST-NET address. The registry correctly says it
proves mesh pings, not chained exit behavior. It has no TCP stream, UDP
datagram, DNS query, MTU/fragmentation, long-lived-flow, or application
integrity assertion.

**Quality risk.** ICMP may work when the traffic Rustynet is expected to carry
does not. Conversely, overlay connection recovery can be wrong while a short
post-fault ping succeeds.

**Recommended test design; review before adoption.**

Add a small transport-neutral payload probe used by several stages:

- TCP: bidirectional, checksummed byte stream across a route change;
- UDP: sequenced datagrams with loss/reorder accounting;
- DNS: a scoped query plus expected failure for an unapproved name/path;
- MTU: a bounded payload ladder with explicit path-MTU result.

Use unique per-run markers, emit sender/receiver observations, and make each
protocol's absence `not_proven`, not implicit success. Do not fold this into
the existing ICMP stage until reporting can distinguish the claims.

### G8 — Role/NAT changes need an existing-flow and residue test

**Evidence.** `exit_handoff` observes reconvergence, route-leak posture,
selected endpoint, NAT presence, and managed DNS. `active_exit` checks for a
translated mesh conntrack entry. QH-47 separately documents that NAT rule
generation changes do not flush conntrack, so an existing flow can retain an
old translation while traffic continues.

**Quality risk.** A fresh connection after handoff can succeed while an old
connection leaks, stalls, or remains bound to a withdrawn exit.

**Recommended test design; review before adoption.**

Before a handoff/demotion, establish marked long-lived TCP and UDP flows from a
mesh client through the exit. During the transition, observe both flow result
and kernel/OS-native flow evidence. Afterwards require either controlled
continuity to the newly authorized path or a deterministic failure followed by
fresh clean reconnection; never accept traffic continuing through a demoted or
removed exit. Capture pre/post conntrack/NAT state on Linux and platform-native
equivalents where supported.

This test depends on deciding the product's intended existing-flow behavior.
It must not prescribe conntrack flushing until that contract and blast radius
are adversarially reviewed.

### G9 — Platform posture tests can green without proving a live mesh

**Evidence.** QH-39 recorded a macOS run where mesh-status returned green with
no daemon/peer proof; the current `MeshStatusValidationStage` supplies only the
local expected node ID and reports non-Linux nodes skipped. The same analysis
warns that resolver-file posture does not establish a loopback resolver is
listening or that macOS uses that resolver.

**Quality risk.** A platform parity matrix may look green while no peer is
reachable and no daemon is serving traffic.

**Recommended test design; review before adoption.**

- Before strengthening a green check, write its negative test: daemon absent,
  expected peer absent, stale state, wrong resolver, and listener absent must
  each fail with specific evidence.
- Supply expected peer set and a meaningful freshness/liveness source only
  after resolving whether persisted state age is a valid signal. Do not add an
  arbitrary timestamp threshold to a state file that is only rewritten on
  changes.
- Use OS-authoritative observation (`scutil --dns` and a loopback DNS query on
  macOS; Windows native resolver/firewall observation) plus actual cross-node
  traffic, not a portable file-shape approximation.

This is an oracle-repair item: rerunning the current test adds confidence to
the wrong claim. Repair or downgrade the claim first.

## 4. Priority order for future work

| priority | next work item | why now | first deliverable |
| --- | --- | --- | --- |
| P0 | Repair false-green platform/mesh oracle (G9) | Invalid greens corrupt every later coverage decision | negative cases + corrected artifact schema |
| P0 | Untangle true prerequisites from linear skip cascade (G1/G2/G3) | present runner hides most of the planned test surface | reviewed dependency/capability model and plan tests |
| P0 | Execute one minimal mixed-OS baseline (G1) | no active T3 evidence exists | exact three-node artifact; no destructive faults |
| P1 | Execute targeted chaos/T5 controls (G2) | high-security scenarios exist but are unmeasured | one isolated safe fault per run |
| P1 | Promote relay forwarding into active engine (G6) | lifecycle pass does not prove forwarding | HP-3 stage and ledger record |
| P1 | Cross-network direct/relay/failback progression (G3) | NAT classifier alone is not traversal proof | parameterized scenario contract |
| P1 | Transport-path faults (G4) | direct blackhole is too narrow | one unified fault-matrix harness |
| P2 | Existing-flow handoff/residue (G8) | needs product behavior decision | design + platform evidence plan |
| P2 | Shared-UDP recovery live proof (G5) | depends on unfinished recovery contract | safe status/fault design, not a raw hook |
| P2 | Protocol/MTU service probes (G7) | expands diagnostic depth after baseline truth is restored | reusable payload-probe spec |

## 5. Evidence contract for every new live scenario

Every new stage should carry the following fields. This avoids the current
failure mode where an exit code or stale status field gets mistaken for proof.

1. **Identity and environment:** run ID, deployed commit/dirty state, exact
   OS/version, node roles, network profile digest, and test capability set.
2. **Precondition:** fresh baseline traffic and the exact requirement being
   relied upon. If missing, emit `skip`, `blocked`, or `not_proven` with reason.
3. **Injection:** exact controlled mutation, target, start/end, and proof it
   took effect. Never infer a fault from a command's exit status alone.
4. **Safety oracle:** no plaintext leak/default-deny violation, no stale
   authority acceptance, and cleanup result, as applicable to that scenario.
5. **Functional oracle:** marked payload at both ends, path selection, relevant
   counter/evidence delta, and bounded recovery only where the product contract
   actually sets a bound.
6. **After-state:** route/firewall/service/authority baseline rechecked. A
   scenario which cannot prove cleanup must be fail/tainted, not a clean pass.
7. **Limits:** explicitly name what the stage does *not* prove. Example:
   unauthenticated relay reachability must never be rendered as trusted relay
   liveness.

## 6. Resource-safe discovery/implementation sequence

This discovery did not start a guest, build Rust code, run Cargo, or touch
benchmark processes. Keep later work bounded too:

1. Design/review artifact schemas and dependency changes first; static tests
   only when the benchmark window allows.
2. Run one focused scenario on disposable guests, using already-built lab
   artifacts where available. Do not launch full-suite or soak runs by default.
3. Inspect the exact stage artifact and append the active normalized ledger.
4. Record the attempted patch/disposition in the stage-triage ledger before a
   rerun. Do not convert a skip to a pass by weakening an assertion.
5. Only after a focused scenario is stable, schedule a broader platform or
   soak matrix with an explicit resource window.

## 7. Discovery conclusion

Rustynet has substantial live-lab machinery. The dominant quality gap is not
an absence of test names; it is that the active engine has not executed many of
its most valuable scenarios, and several existing green rows are narrower than
the operational conclusion readers may draw from them.

Start by making the active evidence trustworthy (G9), then make scenario
dispatch independent enough to expose real results (G1/G2/G3). The next
deep-dive should choose one P0 item—recommended: the dependency/capability
planner plus a minimal mixed-OS baseline—and adversarially review the exact
test contract before any lab run.
