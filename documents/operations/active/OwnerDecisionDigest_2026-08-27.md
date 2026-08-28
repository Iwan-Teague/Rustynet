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
| `physical` | Waiting on the operator at a console or host — unreachable remotely; no repo work unblocks it. |

**Counts.** 17 entries: 13 `pending`, 1 `gated-on-measurement`, 2 `approved`, 1 `in-progress-elsewhere`.
Addendum 2026-08-28: 6 entries (18–23) — 3 `pending`, 1 `approved`→`done`, 1 `physical`, 1 `gated-on-measurement` (with entry 3 `approved`) — plus in-place dated corrections to entries 1–3.
Addendum 2026-08-28 (2): entry 24 — MAC-DNS `approved` → `done`, one residual VPN-service-scope sub-decision noted.

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
**UPDATE 2026-08-28:** re-scoped by the measurement (entry 23) — Option A targets only the completion
race plus the two no-wait Rust sites; every wait bounded strictly under the measured 5 s kill ceiling;
still `gated-on-measurement`, now on §8.5(4)'s two named measurements only.

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
**UPDATE 2026-08-28:** the §1.6 question stands (entry 23); note the residue marker's checker has a
macOS fail-open path defect — see entry 23's fourth bullet.

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
**UPDATE 2026-08-28:** the measurement now exists — see entry 23. **Status: `approved` (measurement
done); the gate on entry 1 is lifted and re-scoped.**

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
§0.4 CN-1/CN-4 rows.

**LANDED 2026-08-27 with CN-4** on `work/cn4-substrates`. `CrossNetworkOptions::nat_profiles` and
`required_nat_profiles` are `Vec<NatProfileId>`; `--cross-network-nat-profiles` and
`--cross-network-required-nat-profiles` reject any name outside the five with a parse-time error that
lists the vocabulary. `--cross-network-impairment-profile` is deliberately untouched (it is a netem
name, not a NAT profile). The sequencing condition was met: `apply_nat_profile` landed in the same
change. **Status: `approved` → `done`.**

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

## Addendum — 2026-08-28 wave

Same rules as above: a digest with pointers, not a re-argument. Entries 18–23 are new; entries 1–3
carry in-place dated corrections above.

### 18. CN-6 — no qualifying cross-network topology exists for Tier B (vxlan)

Measured in run `livelab-1787908428-6d9224cfd954` (`LiveValidation_2026-08-28.md` §12):
`--cross-network-substrate vxlan` on the five-guest `192.168.64.x` UTM fleet provisions nothing and
dispatches none of the eight CN-3 validators — `plan_overlay` returns `Ok(None)` below two underlay
/24s (`substrate.rs:754-756`), and the scenarios additionally require `entry`/`aux` roles plus
client/exit on distinct /24s **judged on the management plane** (`cross_network.rs:514-520`,
`944-949`). The vxlan substrate cannot manufacture the cross-network condition it exists to provide,
and probing (2026-08-28) found no fleet with two genuinely routable /24s: UTM Shared NAT is
one-directional (lenovo→mac 100% loss), `192.168.121.0/24` is unreachable from both hosts, and
`192.168.65.0/24` is macOS-only with its bridge down.

- **(a) Fix the physical path** — bridge the participating UTM guests onto the real LAN (including
  the lenovo reverse path) so two routable /24s exist. Real 2-LAN proof; an operator network change
  outside the repo, and QH-41's vmnet-vs-QEMU backend split still stands.
- **(b) Accept netns-only proof** — record Tier B's contract as "overlay an already-2-LAN fleet"
  (spec §0.6 option b). Honest and zero-code; CN-3 stays unproven on any real cross-network
  substrate, forever.
- **(c) Treat gates (1)/(3) as defects** — Tier B should synthesize the separate LANs, as the shell
  tier `vxlan_tier_b.sh` did. CN-3 becomes provable on the existing five guests; real code work in
  the substrate/scenario gate.

Source: `CrossNetworkSubstrateIntegrationSpec_2026-06-21.md` §0.6. **Status: `pending`.**

### 19. MAC-D1 — macOS anchor cell blocked: the posture gate is circular as written

Both mac cells were elected live on `--node` for the first time and neither earns a green. The
anchor blocker: `role.rs:68-70` gates Anchor/Admin/Relay to Linux pending "a green run", but
`anchor_validation` gates its runtime substages on that same predicate and only reaches `Passed`
with no runtime skip — the green run required to lift the gate can never be produced by the stage
the gate controls. The intended route exists but is a second, independent switch: the macOS anchor
validators (`live_lab_stage_registry.rs:1151,1158,1168`) dispatch only under `--anchor-platform
macos`, and `live_anchor` needs a run without `--skip-linux-live-suite` (which drops 4 of the 5
harvest stages).

- **Promote via the macOS validator set** — run anchor election + `--anchor-platform macos` + the
  full Linux live suite; the green evidence then lifts `role.rs`. Costs the full suite per attempt,
  and the driver's `macos_anchor` target first needs its missing backbone call fixed
  (`ai_agent.rs:1885-1892` — every run through it dies in preflight).
- **Re-design the promotion rule** — let the gate be lifted by evidence the gated stage cannot
  produce (e.g. grade a runtime-skip as promotable once the macOS validators pass). Code work in
  `role.rs`/`anchor_validation.rs`; the fail-closed default itself stays.

Source: `MacCellsHarvest_2026-08-28.md` §2.2–§2.3. **Status: `resolved (code)
2026-08-28` — option (b) applied as a mechanical decoupling, no owner decision
needed.** The gate itself is correct posture policy (not stale, not forced
open); the defect was `anchor_validation` consulting it for its runtime gate —
the only stage still doing so, its siblings already keying on per-capability
predicates (`relay_lab_runtime_implemented`, `active_exit_runtime_implemented`).
The fix applies the same pattern: new `anchor_lab_runtime_implemented`
(Linux + macOS; Windows pending Phase 8) plus a pure `runtime_coverage`
decision that grades a macOS anchor's bundle-pull runtime as
`DelegatedToMacosValidators` (recorded under `runtime_delegated_nodes`, not a
skip) **only** when `--anchor-platform macos` is elected in the same run
(`OrchestrationContext::macos_anchor_validators_elected`, run-local, reloads
`false` on resume = fail-closed), and as a reported skip otherwise.
Fail-closed negatives are pinned by unit tests
(`runtime_coverage_macos_without_validators_is_reported_skip`,
`runtime_coverage_windows_is_reported_skip`); the combined
role-election + validator-set + full-Live-suite run (§5) now has a producible
green, and `role.rs`'s Anchor/macOS arm lifts on THAT archived evidence (kept
Linux-only until then, strictest-secure-default; evidence path documented in
its doc comment). Disposition details:
`MacCellsHarvest_2026-08-28.md` §2.2.

### 20. MAC-D2 — macOS exit cell blocked: membership-owner adapter reads the wrong path, without privilege

The exit cell fails before any exit stage: `membership_init` → "membership owner public key not
found". Two defects, either alone fatal: the macOS path constant points at
`/usr/local/var/rustynet/membership/membership.owner.key.pub` (`macos_install.rs:27-28`), which
holds no key, while a valid one sits at the Linux-conventional `/etc/rustynet/
membership.owner.key.pub`; and the read is a bare `cat` (`macos_membership.rs:29-34`) where the
Linux twin uses `sudo -n` with a fallback — so a permission error and an absent file both surface
as the same empty string. Consequence: macOS cannot hold any membership-owner role (`exit`, and
`blind_exit` under the same topology shape) on `--node` until fixed.

The fix is mechanical (correct the path constant; escalate with `sudo -n`). The open question this
run cannot answer: does a fresh macOS install seed an owner key at all — the found file is a July
leftover? Owner approves the fix and the seeding question's answer before the cell is re-run.

**DONE 2026-08-28.** Seeding question answered from code: yes — the macOS genesis
(`ops e2e-bootstrap-host` → `execute_ops_e2e_bootstrap_macos` → `rustynetd membership init
--owner-signing-key /usr/local/etc/rustynet/membership.owner.key`) writes the pubkey at
`/usr/local/etc/rustynet/membership.owner.key.pub`; the Jul 9 `/etc/rustynet/...` file is a
leftover. Fixed accordingly: `MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH` now equals
`{MACOS_OWNER_SIGNING_KEY_PATH}.pub` (pinned by test to the genesis constant), and the read uses
`sudo -n` with fail-loud classification — absent-file, unreadable/permission, and empty-output
produce distinct non-empty errors instead of one silent empty string. Adapter tests + scoped
gates green; macOS exit cell unblocked for live re-run (lab task, pending). See
`MacCellsHarvest_2026-08-28.md` §4.2 disposition.

Source: `MacCellsHarvest_2026-08-28.md` §4.1–§4.2. **Status: `done` (fix landed 2026-08-28; cell re-run pending).**

### 21. W-FIX-1/2/3 — Windows bootstrap triage: dispositions

`WindowsNodeBootstrapTriageVerdict_2026-08-28.md` verdict: the Windows `--node` bootstrap failure
is a code defect (hard dependency on the opt-in WinGet Configuration feature, enabled by no repo
code — `Bootstrap-RustyNetWindows.ps1:1130`) plus guest drift. All three code fixes are landed;
recorded so they are not re-argued.

- **W-FIX-1 — landed 2026-08-28** (§9.1): the bootstrap enables the feature itself and fails closed
  with a named error. §3's open question answered: the bash era's 66 passes are an **always-gap**
  (`winget configure` is a cold-guest path never taken on a pre-baked toolchain), not a regression
  (§9.2).
- **W-FIX-2 — landed 2026-08-28** (§9.3): the SSH adapter error seam decodes CLIXML and appends the
  readable record, so front-truncation can no longer eat it. §5(3) (PowerShell points at the
  invocation, not the cause) is guest-side and untouched.
- **W-FIX-3 — done 2026-08-28** (§7.3, `work/wfix-3`): a `run_scoped` StageSpec flag stops
  run-scoped `preflight`/cross-network stages poisoning the per-OS
  `*_stage_bootstrap`/`*_stage_cross_network` columns. Forward-only; no historical rows rewritten.

**No owner action pending. Status: `approved` → `done`.**

### 22. W-FIX-4 / W-FIX-5 — operator-physical prerequisites (no remote path exists)

- **W-FIX-4 — `windows-utm-1` guest remediation; UTM console access required.** No remote
  management path exists at all (RPC/SMB up; SSH, WinRM, RDP closed; no QEMU guest agent — §6). At
  the console (§7.1): restore `sshd` + its firewall rule, `winget configure --enable`,
  `w32tm /resync`; then re-run the minimal topology (`debian-headless-2:exit` +
  `windows-utm-1:client`) for the first `windows_stage_bootstrap=pass` row in `--node` history.
- **W-FIX-5 — restore the `ubuntu-kvm-1` host.** Both endpoints time out on TCP/22 (tailnet
  `100.117.1.47`, LAN `172.23.56.5`). Without it, failure #5's inner cause stays unclosable (§4)
  and `windows-x86-1` (the CP-3 WinNAT candidate) stays out of the pool.

Source: `WindowsNodeBootstrapTriageVerdict_2026-08-28.md` §4, §6, §7.1–§7.2.
**Status: `physical` — operator at the console/host; no repo work unblocks either.**

### 23. QH-40 measurement verdict — the D-7 re-scope (updates entries 1–3)

Entry 3 asked for the measurement before deciding entries 1 and 2; it now exists
(`MacOsHelperShutdownOrderingDesign_2026-08-27.md` §8, live on `macos-utm-1`).

- **Kill ceiling settled: 5 s** (launchd default on all rustynet services, §8.1). Every Option A
  wait and any Option B lease bound must sit strictly under it; the refuted plan's 30 s bound is
  measured unreachable.
- **Competing hypothesis resolved** (§8.2): the I/O-timeout mechanism is refuted (live 60 s idle
  probe — every timeout path returns a well-formed error frame). The `truncated frame header`
  observations attribute to the oversized-response drop, fixed 2026-08-25 (`64774bdd`). The
  `Connection refused` tail stays consistent with the §2 completion race — that race plus the two
  no-wait Rust sites is now **Option A's only target**; do not land it as "the fix for the
  truncated-frame failures".
- **Timeout asymmetry fixed 2026-08-28** (§8.7, `work/helper-timeout-mismatch`): client default
  2000→3000 ms derived from the server value; install-time rejection on mismatch.
- **Still gated before final sign-off** (§8.5(4)): the deferred §8.3 reload-ordering matrix and one
  induced residue-marker firing. The marker has since fired organically on macOS (harvest §3.3) —
  but its checker has a macOS fail-open defect (`DEFAULT_STATE_PATH` inherits the Linux path,
  harvest §3.4) that must be fixed for the report posture to mean anything on macOS.
- **Entry 2's §1.6 residue-refuse question stands**, unchanged by the measurement.

**Entry 3: `approved` (measurement done). Entry 1: still `gated-on-measurement`, now on §8.5(4)'s
two named measurements only.**

---

### 24. MAC-DNS — macOS DNS fail-closed enforcement mechanism (M1 selected)

**Decision.** Close the macOS DNS leak — the OS keeps resolving through 1.1.1.1/8.8.8.8
while RustyNet advertises loopback-only DNS, so the QH-39 `scutil --dns` green was never
backed by enforced state. The owner selected **M1** — `networksetup -setdnsservers` per
network service — over M2 (undocumented `scutil` dynamic-store overrides) and M3 (a new
loopback `:53` listener, rejected). Full reasoning:
`MacosDnsFailclosedEnforcementGap_2026-08-28.md` §4–§5.

**Status: `approved` → `done` (2026-08-28, same-day implementation).** Privileged
`NetworkSetup` program (fixed `/usr/sbin/networksetup`, argv-only allowlist),
enforcement + reconcile re-assertion in `MacosCommandSystem`
(`apply/assert/rollback_dns_protection`), session-scoped backup, teardown ordered
SC-restore BEFORE pf-anchor unload (§10.7), and the QH-40-shaped startup-recovery guard
(restores the backup on a stranded start; refuses loudly naming the manual fix when the
backup is lost).

**One residual sub-decision stays with the owner (gap doc §5 item 2):** M1 applies the
loopback pin to ALL enabled network services — including any VPN/utun service that
manages its own resolver; nothing is special-cased silently. If a VPN service proves to
need its own resolver, the owner can exclude named services via configuration later.

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
