# Owner Decision Digest — 2026-08-27

**What this is.** A single index of every decision that is waiting on the repo owner after the
2026-08-27 work wave. It is a *digest with pointers*, not a re-argument: each entry states the
decision, the options with their consequence, where the full reasoning lives, and the status. Read
the recommending document before answering — none of these entries is a substitute for it.

**Scope.** Decisions raised or materially changed by the 2026-08-27 wave (seven gate-green branches
plus the three already merged to `main`). Pre-existing owner/operator-gated items that were merely
re-confirmed today are listed once, without individual sections, in the appendix.

**Citation convention.** Most of today's work is still on unmerged branches. Any pointer to a file
that does not exist on `main` is cited as `branch:path` — for example
`work/d4a-signing-subflow:documents/operations/active/SignedMembershipTransitionSigningSubflowDesign_2026-08-27.md`.
Read those with `git show <branch>:<path>`.

**Status vocabulary.**

| Status | Meaning |
| --- | --- |
| `pending` | Waiting on the owner. Nothing is implemented behind it. |
| `gated-on-measurement` | The owner should not decide until a named measurement exists; deciding first risks landing a fix against the wrong cause. |
| `approved` | Decided. Listed so the decision is not re-litigated, and so its follow-on work is visible. |
| `in-progress-elsewhere` | Decided and delegated; a separate manager owns the execution. |

**Counts.** 17 entries: 13 `pending`, 1 `gated-on-measurement`, 2 `approved`, 1 `in-progress-elsewhere`.

---

## 1. D-7A — macOS privileged-helper lifetime (Option A, Option B, or both)

The daemon's entire shutdown rollback is privileged work it can only perform through the helper, but
launchd has no `After=`/`Requires=` equivalent, so nothing orders the helper's teardown after the
daemon's. Two mechanisms can enforce it, and the owner must pick one or both.

- **Option A — bounded exit-wait at all four teardown caller sites** (poll `launchctl print` until the
  daemon job is gone). Mechanical; the only option that helps `uninstall.rs` and
  `MACOS_LAUNCHD_STOP_COMMAND`, which today wait not at all. A poll alone cannot distinguish a clean
  exit from a launchd `SIGKILL` — pairing it with the §1 residue marker is what makes it sound.
- **Option B — a bounded, self-releasing rollback lease inside the privileged helper.** The only
  option that survives the reboot path, because it needs no cooperation from whoever sent the signals.
  Constrained by AGENTS.md §4: a lease must never widen what the helper will execute or for whom, must
  be bounded under launchd's kill ceiling, and must be acquirable only by the already-authorised peer.
- **Neither** — the rollback keeps failing silently on the reboot path; the §1 marker makes it visible
  but does not fix it.

Doc's recommendation: **A + B together**, A first. Neither is implemented.
Source: `work/d7-qh40-helper-order:documents/operations/active/MacOsHelperShutdownOrderingDesign_2026-08-27.md`
§3.2, deferral list §5(1).
**Status: `gated-on-measurement`** — see entry 3.

## 2. D-7B — startup disposition when a residue marker is present

The landed change records a durable marker when shutdown rollback leaves dataplane residue, and the
next start *reports* it (exit 78 + the `shutdown_rollback_residue_detected` grep token). The brief had
asked for a start that *refuses*. The owner decides which posture ships.

- **Report-only (what landed)** — residue is impossible for an operator or probe to miss, but an
  unattended reboot brings the node back up still carrying it.
- **Refuse to start** — louder, but not safer: a start applies dataplane state, it does not roll back,
  so refusal trades a residual host for a crash-looping host with the same residue (`KeepAlive = true`
  ⇒ a permanent 10 s respawn loop with no operator escape short of deleting a file).
- **Re-run the teardown at startup and refuse normal service until it succeeds** — the genuinely
  fail-closed option, because it actually clears the residue. Touches the privileged path and the
  controller lifecycle, so it belongs behind the same review as entry 1.

Doc's recommendation: the third option, recorded as the escalation and deliberately not taken
unilaterally. Changes the availability semantics of every macOS and Windows node.
Source: same doc, §1.6 and §5(2). **Status: `pending`.**

## 3. D-7C — measure the root cause before deciding entries 1 and 2

A competing hypothesis says the observed rollback failures are not an ordering problem at all: the
first rollback step failed with `truncated frame header` while the helper was **still alive**, and the
same failure appears on `bootstrap_apply_failed` and `membership_reconcile_failed` — paths with no
teardown in flight. The helper's own `--timeout-ms` default is 2000 ms, and there is a recorded live
observation of a continuous `truncated frame header` loop that stopped when it was raised to 10000 ms.
The deployed helper plist already sets 30000 ms, which is itself worth checking against whichever
build produced the ledger evidence.

- **Measure first** — re-query the QH-40 logs and re-measure launchd's actual post-`SIGTERM` kill
  ceiling on a live guest (that ceiling also bounds every wait in Option A). Then decide 1 and 2.
- **Decide now** — risks landing Option A/B against a failure caused by an I/O timeout, producing a
  green-looking change that fixes nothing. That is exactly how the previous QH-40 remedy was refuted.

Source: same doc, §3.3, §4.3, §5(3)(4). **Status: `pending` (this is the gate on entry 1).**

## 4. Anchor enrollment LAN listener — approved, delegated

`anchor.enrollment_endpoint` now has a real runtime gate, but enrollment-consume is still reachable
only over the local IPC socket; an anchor is not yet reachable from a new device on the LAN. Building
the listener is a mechanical copy of the bundle-pull listener seam and needs no new wire format or
crypto — but it adds a network-exposed pre-authentication parser, which per the bundle-pull precedent
requires an owner decision plus an independent adversarial review, not a defect-ticket patch.

The owner approved it on that basis and delegated execution to a separate manager; work is under way
(commit `1d2ad071`, "add the anchor enrollment-consume listener (D-3 §7.1)"). **No owner action is
pending here** — it is listed so it is not mistaken for an open item.

Follow-on, auto-sequenced rather than owner-gated: §7(2) promotes the startup coherence gate (§4c) to a
hard `DaemonError` once the listener ships *and* the Linux/macOS/Windows install templates provision
the endpoint on anchors. Doing it earlier would brick every anchor.
Source: `documents/operations/active/AnchorEnrollmentEndpointEnforcementDesign_2026-08-27.md` §7.
**Status: `in-progress-elsewhere`.**

## 5. T-D1 — wire `relay_forwards_frame` in as a `--node` stage

The HP-3 relay-forwarding validator exists and is honest (`vm_lab/mod.rs:13841`) but has no `StageId`,
so it dispatches nowhere and the column is `not_run` on 178 of 178 runs. Wiring it in is not a
mechanics question — it adds a stage to the **default** `Live` plan, changing what every profile runs,
and mid-run it injects an nft block and restarts two daemons on lab guests.

- **Wire it in** — HP-3 finally provable on the engine of record; default plan grows, every profile
  changes, plan-count assertions (`plan.rs:456-530`) need updating, and the run-safety risk is real.
- **Leave parked** — the column stays permanently `not_run`; HP-3 remains unproven on any engine.
- **Delete** — explicitly not recommended: Rustynet would have zero proof a relay forwards a frame at
  all, or that it does so blind.

Doc's recommendation: **yes, wire it in** — "the largest looks-done-but-isn't gap".
Source: `work/linux-stage-triage:documents/operations/active/NeverDispatchedLinuxStagesTriage_2026-08-27.md`
§1d, §6 (D-1). **Status: `pending`.**

## 6. T-D2 — re-parent the chaos stages, and enable the offline three first

`linux_stage_chaos` is `not_run` 178/178 behind two independent gates: `--enable-chaos-suite` was never
passed, and all nine `chaos_*` stages hard-depend on `LiveMixedTopologyValidation`, which is tri-OS-only
and 0-for-178. Flipping the flag today yields nine cascade-skips, not nine dispatches. The fix is one
line at `crates/rustynet-cli/src/vm_lab/orchestrator/stage/chaos.rs:48-50` (dependency
`LiveMixedTopologyValidation` → `TrafficTestMatrix`), but the owner also decides whether real fault
injection — OOM, SIGSTOP, clock rollback, network impairment — should reach lab guests at all.

- **Re-parent only** — tri-OS coupling gone, chaos becomes dispatchable on Linux-only topologies; zero
  change to current runs, since chaos is out of the default plan.
- **Re-parent and enable the three `ChaosTargets::Offline` stages first** (`chaos.rs:101,115,129`) —
  converts a permanently `not_run` column into real T4 evidence with zero risk to lab nodes, because
  those three contact no guest.
- **Do nothing** — the B6.2 deferral expiry will be met by a no-op.

Doc's recommendation: **yes, starting with the three offline stages** (lowest blast radius).
Source: same triage doc §2d, §6 (D-2). **Status: `pending`.**

## 7. T-D3 — prove membership-file custody on `--node`

Minting and distribution of signed membership are proven, but the `600 rustynetd:rustynetd`
mode/ownership of `membership.snapshot` / `.log` / `.watermark` is proven **nowhere** — a
`SecurityMinimumBar`-adjacent at-rest custody claim with no live evidence on any OS.

- **Option 1 — fold the three-file custody assertion into the already-dispatching
  `key_custody_validation` Linux contract.** Cheapest: one new assertion, no new plan row, no
  plan-count churn. Can turn a currently-green stage red on real guests.
- **Option 2 — a dedicated `MembershipGenesisValidation` stage** (`@ Setup / T0Core`). Cleaner ledger
  story, but adds a stage to the default plan and changes every profile.
- **Delete** — do not: it would leave the custody claim unproven and untracked.

Doc's recommendation: **option 1**.
Source: same triage doc §3d, §6 (D-3). **Status: `pending`.**

## 8. T-D4 — correct the B1.6 signed disposition

B1 of `BashRetirementDispositions_2026-08-22.md` is defined as *ledger-dialect false gaps* — the
capability is `--node`-proven under the column named. B1.6 does not fit: `linux_stage_membership`
proves minting and distribution, while `linux_membership_genesis` asserted file mode/ownership custody
and snapshot readability. Those are different claims, so a real gap is filed as a dialect artefact, and
the existing owner sign-off (APPROVED 2026-08-26) rests on that mis-statement.

- **Re-file B1.6 out of B1 into B6** (residual Linux cells), carrying the entry 7 disposition — the gap
  is tracked honestly; doc-only blast radius, but it re-opens one signed disposition.
- **Keep the sign-off and write the custody claim off explicitly** — records the loss deliberately
  rather than by accident.
- **Leave as-is** — the false equivalence keeps propagating into
  `BashRetirementGapEnumeration_2026-08-22.md` and the retirement program doc.

Doc's recommendation: **re-file**. Deliberately not edited by the triage author — these are signed
dispositions and the correction is the owner's.
Source: same triage doc §4.1, §6 (D-4). **Status: `pending`.**

## 9. D-4a §8.1 — where the signing sub-flow driver lives

The pure step sequencer landed; the automated driver that executes it did not. The split-station trust
model holds either way, so this is a packaging choice, not a trust-model choice.

- **An admin-station one-shot CLI verb** — a new shipped operator verb, usable in production
  immediately, and a new supported surface to maintain.
- **Live-lab-stage automation only, to start** — no new operator surface; the automation is proven in
  the lab before it becomes a product verb.

No recommendation stated.
Source: `work/d4a-signing-subflow:documents/operations/active/SignedMembershipTransitionSigningSubflowDesign_2026-08-27.md`
§8 item 1. **Status: `pending`.**

## 10. D-4a §8.2 — confirm quorum > 1 stays manual

When `MembershipState.quorum_threshold > 1`, does the sub-flow terminate at a partially-signed artifact
and print the merge chain, as `enrollment admit` already does (`main.rs:8385`)?

- **Confirm manual** — the sub-flow stops after its own signature and prints the exact
  `sign-update --merge-from` chain. This is what §2 already designs to.
- **Reject** — would require automating multi-approver signature collection, which §2 declares out of
  scope for D-4a entirely.

Doc's implicit recommendation: confirm.
Source: same doc, §8 item 2. **Status: `pending`.**

## 11. D-4a §8.3 — what "deployed and healthy" must verify

This is invariant I-1's teeth: a published capability must never precede a running, healthy service.
The design deliberately did **not** encode a `VerifyServiceHealthy` step, because a wrong guess would
bake into the step vocabulary; the meaning currently lives in `DeployService`'s doc contract.

- **Unit active** — cheapest and weakest: the service manager says running, which says nothing about
  function.
- **Port bound** — catches bind and config failure; still no functional proof.
- **Self-probe** — the strongest I-1 guarantee; most work, and needs per-service protocol knowledge for
  `relay` / `nas` / `llm`.

No recommendation stated. Explicitly blocking: nothing can encode the step until this is answered.
Source: same doc, §8 item 3 (cross-referenced from §7). **Status: `pending`.**

## 12. D-4a §8.4 — the remove-path availability window

After undeploy/retract but before the revocation publishes, the capability is still published while
nothing serves it. This is safe for security — nothing is running, and exit peers fail closed via route
retract on the next reconcile (`role_cli.rs:662-668`) — but peers may keep selecting a dead relay or
exit until the publish lands.

- **Accept and document the window** — no new steps, matches the strict AGENTS.md §10.7 ordering; a
  brief availability hole on removes.
- **Add a drain / re-issue-assignments step before undeploy, for `serves_exit` specifically** — closes
  the hole for exits at the cost of an extra step and coupling assignment-bundle re-issue into the
  sub-flow.

Doc's recommendation: **accept and document** (marked "recommended, matches §10.7").
Source: same doc, §8 item 4. **Status: `pending`.**

## 13. D-4a §8.5 — TTL on the signed checkpoint artifact

The sign→publish signed artifact is the sub-flow's one resumable checkpoint, and its lifetime is what
bounds a resumed run.

- **Use the default record TTL** (`expires_at_unix` as normally set) — no new policy; a longer resume
  window, and a longer-lived signed capability artifact sitting on the admin station.
- **A tighter transition-specific TTL** — smaller exposure window for an unpublished signed
  capability; more re-runs from emit when an operator is slow.

No recommendation stated.
Source: same doc, §8 item 5. **Status: `pending`.**

## 14. D-4a §8.6 — should `role set` auto-emit the unsigned record

Today `role set` prints follow-up instructions (`role_cli.rs:750-760`) telling the operator to emit,
sign and apply the capability update by hand.

- **Emit the unsigned `SetNodeCapabilities` record as a real artifact** — better operator UX, no manual
  `propose-set-capabilities` step; changes the audit story and changes the behaviour of an
  already-shipped verb.
- **Keep the follow-up text** — no regression risk to a shipped verb; the manual chain persists.

No recommendation; the doc characterises it as "cheap, but changes a shipped verb".
Source: same doc, §8 item 6. **Status: `pending`.**

## 15. D-4a — the driver's default apply/publish behaviour (latent, not in §8)

§7 keeps two driver defaults deliberately unencoded, and they land on the same step vocabulary §8
governs, so they should be answered in the same review rather than discovered during implementation.

- **Auto-apply on the signing station whenever quorum is met** (the `enrollment admit --apply` shape) —
  the doc's stated likely default; fewer operator steps, one less place to stall a transition.
- **Never auto-apply; always hand back a signed artifact** — the operator explicitly performs the
  publish; slower, but the publish is always a deliberate act.
- **Publish target** (local files vs `--daemon`) is called deployment-specific and needs a default.

Source: same doc, §7. **Status: `pending`.**

## 16. CN-4 prerequisite — tighten the CLI onto `NatProfileId`

`NatProfileId` is a validated newtype closed to the five known §D5.1 profile names, but
`--cross-network-nat-profiles` still parses with shape-only validation, so an unknown profile name
reaches the substrate as a free string. CN-1 kept it that way deliberately so the seam changed no
behaviour; tightening it is a separate, deliberate behavioural change, and it is a prerequisite for
CN-4's `apply_nat_profile` / `NatModifiers` work.

The owner has approved the tightening. It is recorded here so it is not re-argued, and so it is not
started before CN-4: landing it earlier would reject profile strings that today pass, with no
`apply_nat_profile` yet to justify the stricter contract.
Source: `crates/rustynet-cli/src/vm_lab/orchestrator/stage/cross_network/substrate.rs` (the
`NatProfileId` doc comment) and `documents/operations/active/CrossNetworkSubstrateIntegrationSpec_2026-06-21.md`
§0.4 CN-1/CN-4 rows. **Status: `approved`, sequenced behind CN-4.**

## 17. Blind relay — identity-free token/hello v2, no v1 fallback

The `blind_relay` design replaces the identity-bearing relay token/hello v1 for this role with an
identity-free, proof-of-possession token/hello v2. A blind relay accepts v2 only: there is no v1
fallback, no translation, and no dual-mode listener; tokens are reissued from current signed state
rather than converted.

That architectural selection is **approved** — it is the §0 executive decision record, and the
no-fallback shape is what makes the blindness property falsifiable (BR-C04).

What is **not** decided, and still blocks implementation: §16 items 1–6 remain OPEN — the exact
canonical encoding and framing for fleet/token/hello v2 (item 1), the proof-of-possession suite (2),
replay persistence (3), public privacy profiles (4), operational retention (5), and performance
acceptance (6). Until 1–6 are resolved the role stays design-only and must not be advertised by
production signed state.
Source: `documents/operations/active/BlindRelayRoleDesign_2026-08-27.md` §0, §7.3, §16.
**Status: `approved` (architecture) with §16.1–.6 open.**

---

## Appendix — related items that are not owner decisions

Listed so a reader does not go looking for them above.

- **QH-04 distribution gaps.** The daemon-side atomicity defect is FIXED on `work/qh04-atomicity`.
  Three *distribution* gaps are explicitly out of its scope and still unassigned: the
  `ops assignment-refresh` timer path, the remote-pull path's uncross-bound `traversal_url` /
  `assignment_url` watermarks, and membership revocation landing before the matching re-mint. These
  need an owner *assignment*, not an owner decision.
  (`work/qh04-atomicity:documents/operations/active/QualityHardeningTodo_2026-07-25.md`, QH-04.)
- **CN-5 tail.** `netns_daemon_path.sh` plus the dead `cross_network_daemon_path` registry entry —
  recorded as out of CN-5's original scope in the CN-5 row of
  `CrossNetworkSubstrateIntegrationSpec_2026-06-21.md` §0.4, and tracked as TRACKC-FIX-1.
- **Triage §4.3.** `BashRetirementDispositions_2026-08-22.md` B6.2 records chaos as *deferred* when the
  code state is *blocked*. A follow-on doc edit gated on entry 6, not a separate decision.
- **Pre-existing operator-gated items, re-confirmed today** in
  `work/qh54-firewalld-rebind:documents/operations/active/RepoStateAssessmentAndNextSteps_2026-08-19.md`:
  QH-26 (unreviewed WIP commits on the trust path + the DA-01 TLS decision) and QH-28 (the Windows
  installer minting a self-signed cert into `LocalMachine\Root` — do not fix autonomously). Both
  predate this wave; neither is new.
