# GLM Manager Log — 2026-09-05

Operating log for the GLM manager session on branch
`ai-edit/edit-1788631826676-82735-0` (worktree
`state/edit-worktrees/edit-1788631826676-82735-0`, base `3aedcfff`).
Records what ran, verdicts with run ids, decisions taken, decisions
deferred to the owner, and next steps. Security-relevant code changes are
out of this manager's write scope and appear here only as proposed diffs
for human review.

## 17:45–18:20 — handover, run #5 monitored to completion

Run #5 (`livelab-1788631948-3aedcfff9a75`, commit `3aedcfff`, clean) was
launched from the MAIN tree by the previous manager (pid 78346, report
`state/live-lab-macos-client-stun2-20260905-175914` in the main tree) and
monitored to completion without intervention.

Verdict, taken from the stage artifacts (stages.tsv + per-stage logs),
never the CSV column alone:

- `collect_pubkeys` **pass** — first time in this series. The
  `--linux-backend linux-wireguard-userspace-shared` pin closed run #4's
  kernel-backend stall: every node gathered reflexive candidates and the
  flag → STUN gather → `SRRLX_SPEC` pipeline is proven live end to end.
- `key_custody_validation` **pass**; 51 stage rows pass; skips all
  legitimate (relay stages: no relay node in topology; cross-network NAT
  matrix; ipv6_leak runtime skip).
- `traffic_test_matrix` **fail** — all four cross-vmnet legs 100% loss in
  both directions (macos-utm-1↔debian-headless-4 100.124.191.164,
  macos-utm-1↔debian-headless-2 100.80.169.183, both Linux→mac legs
  100.64.181.171); mac default-deny probe INCONCLUSIVE (fails closed).

Assessment: the remaining failure is CP-1 (host/lab topology split across
two isolated vmnet nets) — owner-deferred, not a rustynet defect. The next
lever is daemon-side traversal work consuming `SRRLX_SPEC`/srflx when
building mac↔Linux peer paths, not more lab plumbing. No lab-side fix in
this manager's scope.

Ledger note: the run was launched from the main tree, so its run-matrix
row and any triage stub landed in the MAIN tree's
`documents/operations/live_lab_node_run_matrix.csv` /
`live_lab_node_stage_results.csv` / `live_lab_stage_triage.jsonl`. The
worktree branch does not carry them (recorded, not fabricated).

Docs updated on this branch: `MacosCrossNetworkTrafficBlocker_2026-09-03.md`
§7 Run #5 paragraph appended; `CrossPlatformRoleParityRefresh_2026-07-23.md`
client row updated with run #5 and anchor row CORRECTED (the
port-mapping-authority failure was QH-68, a validator identity bug fixed in
`874a9aaa` — the earlier "same family as the exit-cell membership gap"
claim was wrong and is retracted).

Decisions deferred to owner (unchanged, do not take):

1. CP-1 bridged-NIC/profile re-attach (host change).
2. QH-69-default — whether `--linux-backend` should have a default or the
   backend should be recorded per run-matrix row.
3. QH-66 Option D — owner signing key custody (F1 disclosure stands: sole
   owner signing key sits on the blind_exit host).

Next: commit docs, then macOS anchor re-proof from this worktree
(`--source-mode local-head` deploys branch HEAD, hence commit first),
then relay frame-forwarding opt-in cell (QH-64).

## 18:20–18:55 — anchor re-proof run 1: all stages pass, finalization blocked by verifier bug; fixed

Launched the QH-68 re-proof from this worktree (commit `fb61cf9d`'s tree):
report `state/live-lab-macos-anchor-portmap-20260905-181715`, topology
macos-utm-1:anchor / debian-headless-4:exit / debian-headless-2:client,
`--skip-linux-live-suite --linux-backend linux-wireguard-userspace-shared`,
pid 84428.

Stage verdicts (stages.tsv + stage logs): **20 pass / 0 fail / 2 skip**
(admin_issue, blind_exit — both legitimate role-absence skips). In
particular all four anchor stages pass:
`deploy_macos_anchor_profile`, `validate_macos_anchor_bundle_pull`,
`anchor_validation`, and — the QH-68 re-proof target —
`validate_macos_anchor_port_mapping_authority` **PASS**. The fix in
`874a9aaa` is now live-proven.

BUT evidence finalization failed, so no run-matrix row was appended:
`Rust --node evidence finalization failed: recorded plan integrity check
failed: recorded plan does not match the independently-derived expected
plan ... unexpected added stages: [deploy_macos_anchor_profile,
validate_macos_anchor_bundle_pull,
validate_macos_anchor_port_mapping_authority]`.

Root cause (read from code, not guessed): the anti-shrink verifier
`verify_recorded_plan_not_shrunk` (resolved_plan.rs) rebuilt the expected
plan with `.with_anchor_platform_macos(selectors.anchor_platform ==
"macos")` — the raw flag only. On `--node` runs the recorded selector is
ALWAYS empty (native.rs records `anchor_platform: String::new()`; "bash-only
platform election selectors remain inactive"), while the runner's election
is OR(flag, Anchor-assigned-to-macOS-entry) via
`anchor_platform_macos_elected` (native.rs:1196, added by `451f9730`).
Every faithful `--node <mac>:anchor` fast-path run therefore under-derives
the expected plan and is rejected as having "added" the three anchor
stages.

Fix applied (lab tooling, rustynet-cli — no verdict/trust code):

1. `ManifestNodeAssignment` gains `#[serde(default)] platform: String`
   (live_lab_stage_manifest.rs), filled at manifest-write time from the
   inventory entry (native.rs now maps over `node_entries`, which carries
   the platform). Empty/absent platform reads as not-macos.
2. `verify_recorded_plan_not_shrunk` re-derives the election by calling the
   SAME `anchor_platform_macos_elected` fn the runner used (now `pub(crate)`,
   body unchanged), over the manifest's recorded node assignments;
   unparseable role → `NodeRole::Custom` (never Anchor → no election);
   unparseable platform → None (no election). Every failure path bends
   toward the stricter no-election plan.
3. Tests: `verify_honors_a_node_assigned_macos_anchor_on_the_fast_path`
   (the regression — passes now, failed pre-fix),
   `verify_fails_closed_for_a_platform_less_legacy_anchor_assignment`
   (legacy platform-less manifest must NOT elect; mismatch names "added" +
   "macos_anchor"), `verify_rejects_a_fabricated_anchor_election_without_an_assignment`.
   Existing anti-shrink tests unchanged and green. Scoped gates: fmt,
   clippy -D warnings, resolved_plan tests 17/17.

Security review: the mandatory adversarial review (ai_read, glm-5.3) was
attempted TWICE with the full diff; both calls timed out (MCP -32001).
Recorded here per the max-2-retries rule; will retry when the provider
answers. My own adversarial analysis in the interim: the change does not
move the trust boundary in kind — the manifest already records raw CLI
selectors authored by the runner, and the gate's purpose is to catch
selection↔recording divergence, not to authenticate inputs; a runner that
falsely wanted the anchor stages in its expected plan could always have
claimed `--anchor-platform macos` pre-fix. No new growth power, all
degenerate inputs fail toward no-election, full-digest comparison and
dropped/added naming unchanged.

Next: commit, rebuild the vm-lab binary, relaunch the re-proof with a
fresh report dir so the matrix row actually lands.

## 19:00–19:35 — anchor re-proof run 2: GREEN, row recorded

Relaunched after the verifier fix (same recipe, fresh report dir
`state/live-lab-macos-anchor-portmap2-20260905-190047`, pid 94413,
deploying branch HEAD `1eb6e800` via `--source-mode local-head`).

Verdict (stages.tsv + stage logs + matrix row cross-check):
`livelab-1788635706-1eb6e800c4cf`, commit `1eb6e800`, clean —
**20 pass / 0 fail / 2 skip** (admin_issue, blind_exit: role-absence
skips). All four anchor stages pass; QH-68 re-proof target
`validate_macos_anchor_port_mapping_authority` passes against the
daemon-reported identity `macos-utm-1-bootstrap`. Run-matrix row appended
IN THE WORKTREE ledger (run launched from the worktree):
`macos_anchor=pass`, `macos_stage_anchor=pass`,
`macos_anchor_node_id=macos-utm-1-bootstrap`,
`overall_result=partial` — partial is the fast-path semantic (stages
outside the elected cell are `not_run` by design under
`--skip-linux-live-suite`), not a failure.

The plan-integrity fix is thereby live-proven too: finalization succeeded
and the row landed.

Third attempt at the glm-5.3 adversarial review of the verifier fix also
timed out (MCP -32001) — provider unavailable this hour; standing note
above stands (own analysis recorded; no invariant weakened).

macOS cell status after this run: client 🟡 (CP-1 owner-deferred), admin 🟢,
relay lifecycle 🟢, **anchor 🟢**, exit 🟢 (blind_exit posture; F1 owner),
blind_exit 🟢, relay frame-forwarding ⬛ (opt-in, never run live).

Next: relay frame-forwarding opt-in cell (QH-64-aware:
`--node macos-utm-1:relay --node debian-headless-4:exit
--node debian-headless-2:client --enable-relay-forwarding-validation
--skip-linux-live-suite` + common flags). Disruptive by design; if
`gossip_accepted_total=0` / `restrict_permanent` symptoms appear, that is
QH-64 evidence, not a new defect.

## 19:20–20:10 — successor manager (edit-1788642144227-82735-2): relay attempt 1 = setup-only (HP-3 skip-trap); glm-5.3 adversarial review APPROVE

Handover processing. The predecessor's relay launch
(`state/live-lab-macos-relay-fwd-20260905-191701` in the OLD worktree,
pid 591) had already exited cleanly by the time this manager read the log:
`orchestration/orchestrate_result.json` exists, run
`livelab-1788636568-2a7cbf6ac22e`, commit `2a7cbf6a` (the predecessor's
timed-out checkpoint HEAD, an ancestor of this branch), clean.

Verdict (from `state/stages.tsv` + stage logs + the appended ledger row,
never the CSV column alone): **setup-only — 16 pass / 0 fail / 3 skip**
(anchor_validation, admin_issue, blind_exit: role-absence skips),
`overall_result=partial` (fast-path `not_run` semantics). **The relay
frame-forwarding stage was never planned.** Root cause, read from code:
the stage is `StageSuite::Disruptive` and the plan gate is
`!skip_live_suite && enable_relay_forwarding_validation`
(`crates/rustynet-cli/src/vm_lab/orchestrator/plan.rs:372`, with the
regression test `skip_live_suite_drops_relay_forwarding_validation_too`
at plan.rs:845), and `native.rs:743` records the selector as
`enable_relay_forwarding_validation && !skip_live_suite` — the launch
recipe combined `--enable-relay-forwarding-validation` with
`--skip-linux-live-suite`, so the opt-in was dropped BY DESIGN (same
contract as chaos/negative-control; the recorded manifest confirms
`relay_forwarding_validation:false`). Not a defect; a launch-recipe
trap. QH-64 symptoms therefore never came into play (no restarts
happened).

Ledger carry: the run-matrix row (line 314) and the 46 stage-results
rows (lines 43295–43340) were appended uncommitted in the OLD worktree;
copied line-exact into this branch's
`documents/operations/live_lab_node_run_matrix.csv` /
`live_lab_node_stage_results.csv` via python (all 47 lines verified to
reference the report dir before appending). No triage stub was created
for this run (grep of the old worktree's `live_lab_stage_triage.jsonl`
for the report dir: zero matches), so there is no stub to fill.

glm-5.3 adversarial review of the verifier fix `1eb6e800` — RETRY
SUCCEEDED via the stdio driver
(`scripts/mcp/drive_ai_agent.py --tool ai_agent`, provider glm, model
glm-5.3, grounding itself with its own git/read tools after four MCP
-32001/-style failures): **VERDICT APPROVE.** All five attack attempts
fail: (a) anti-shrink bypass — the election disjunction only ever
ENLARGES the expected plan; the pre-fix runner could already shrink via
the raw selector, so the trust boundary is unmoved and the dangerous
direction is strictly reduced; (b) no self-election path — the manifest
platform field is copied from the operator-controlled inventory at
write time (`native.rs:320-336`), unknown alias is a hard error;
(c) degenerate inputs all bend strict (unparseable role →
`NodeRole::Custom` ≠ `Anchor` → no election; unparseable/absent
platform → `None`/`""` → parse fails → no election); (d) the digest
gate `verify_recorded_matches_expected` (`resolved_plan.rs:274-308`) is
untouched by the commit; (e) `""` vs `"linux"` both converge on the
identical no-election plan. Two OPTIONAL non-blocking hardening notes:
reject duplicate aliases in `ManifestNodeAssignment` at manifest-write
time (kills the last-wins HashMap ambiguity), and pin
`VmGuestPlatform::parse("") → Err` in a unit test. Reviewer's stated
limits: did not run cargo, did not read the `parse` sources directly
(enum-inequality inferred from the committed regression tests).
Operational consequence noted by the reviewer: legacy pre-fix manifests
with legitimately-elected anchors now fail verification loudly —
intended fail-closed direction. Disposition: APPROVE recorded; the two
optional hardenings are lab-tooling-only and queued behind the relay
cell (they harden, they do not fix a defect).

Docs updated on this branch: Refresh §1 relay (frame-forwarding) row
now records attempt 1 with run id, the skip-trap root cause with
file:line, and the corrected launch recipe (NO
`--skip-linux-live-suite`).

macOS cell status unchanged otherwise: client 🟡 (CP-1 owner-deferred),
admin 🟢, relay lifecycle 🟢, anchor 🟢, exit 🟢, blind_exit 🟢, relay
frame-forwarding ⬛→ attempt-1 evidence recorded, still never run.

Next: relaunch the relay cell from THIS worktree without
`--skip-linux-live-suite` (`--node macos-utm-1:relay --node
debian-headless-4:exit --node debian-headless-2:client
--enable-relay-forwarding-validation --linux-backend
linux-wireguard-userspace-shared --source-mode local-head`), expect the
full Live suite to run (longer), QH-64-aware monitoring, fill any triage
stub before the next launch.

## 21:33 — relay attempt 2 launched from THIS worktree (correct recipe)

Relaunched the relay frame-forwarding cell without the trap flag:
`--node macos-utm-1:relay --node debian-headless-4:exit --node
debian-headless-2:client --enable-relay-forwarding-validation
--skip-soak --linux-backend linux-wireguard-userspace-shared
--source-mode local-head --trust-inventory-ready --known-hosts-file
~/.ssh/known_hosts`, report `state/live-lab-macos-relay-fwd2-20260905-213253`,
pid 12879, deploying branch HEAD `0a118d10` (docs-only on top of
`2a7cbf6a`). First launch died immediately on a missing required flag
(`--known-hosts-file is required when --node flags are present`) —
relaunched with it; report dir wiped and reused. The recorded manifest
now shows `relay_forwarding_validation:true` — the stage IS planned this
time. `--skip-soak` keeps the Soak suite out (StageSuite::Soak would
otherwise run for hours); the full Live suite runs, so expect
role-switch/two-hop/managed-dns/relay-lifecycle stages alongside the
Disruptive relay-forwarding stage. QH-64 watch active.

## 22:30 — successor manager (edit-1788646982493-23815-0): attempt 2 verdict — relay cell STILL not exercised; macOS deploy-adapter defect identified; checkpoint fix in progress

Handover processing. Attempt 2 ended at 21:50 UTC (15m 33s) in the
PREDECESSOR's worktree (read-only for this manager): run
`rust-1788644094`, commit `0a118d10`, clean, report
`state/live-lab-macos-relay-fwd2-20260905-213253` (absolute:
`/Users/iwan/Desktop/Rustynet/state/edit-worktrees/edit-1788642144227-82735-2/state/live-lab-macos-relay-fwd2-20260905-213253`).

Verdict from `run_summary.json` + `failure_digest.md` + stage logs:
**66 planned, 23 pass / 2 fail / 41 skip, overall fail.** The relay
frame-forwarding stage WAS planned (selectors
`relay_forwarding_validation:true`) but NEVER RAN:

1. `deploy_relay_service` **FAIL** on macos-utm-1: `remote command
   failed (exit Some(1)): sh: line 0: cd: /Users/mac/Rustynet: No such
   file or directory`. Root cause (read from code,
   `macos_install.rs:1270` pre-fix): the macOS adapter built
   `sudo -n env RN_SRC=… sh -c 'cd "$RN_SRC" && rustynet ops
   install-macos-relay'` with `RN_SRC` = configured workdir else
   `$HOME/Rustynet` — assuming a source checkout on the guest that a
   `--node` bootstrap never materializes (bootstrap installs from the
   shipped archive; the inventory `rustynet_src_dir` is not a live
   checkout). Lab-tooling defect, NOT a rustynet daemon defect. The
   earlier relay-lifecycle green row (`livelab-1784497253`) predates
   the `--node` engine. `relay_validation` and
   `relay_forwards_frame_validation` skipped as failed-dependency — the
   cell is still ⬛.
2. `traffic_test_matrix` **FAIL** — same CP-1 cross-vmnet 100% loss
   pattern as run #5 (all four mac↔Linux legs, default-deny
   INCONCLUSIVE failing closed). Owner-deferred; not chased. Its
   cascade skips (role_switch → … → live_two_hop → cross_network_*)
   account for most of the 41 skips.

Ledger state, verified with quote-aware greps of BOTH worktrees' CSVs
and the triage jsonl: **NO run-matrix row, NO stage-results rows, NO
triage stub exist for `rust-1788644094` anywhere** — evidence
finalization itself failed (job wrapper reported transient_failure 70),
so nothing was appended to port. Recorded here; nothing fabricated. The
handover's assumption that rows landed uncommitted in the predecessor
worktree was checked and is FALSE (clean tree, zero grep matches for
the run id and report dir).

macOS cell status: client 🟡 (CP-1 owner-deferred), admin 🟢, relay
lifecycle 🟢, anchor 🟢, exit 🟢, blind_exit 🟢, relay frame-forwarding
⬛ (two attempts, both pre-exercise).

Fix in flight: the automatic checkpoint `25e885d9` (from the timed-out
predecessor, already on this branch) carries a WIP fix —
`deploy_relay_service` drops the `workdir` param, uploads the reviewed
`scripts/launchd/com.rustynet.relay.plist` from the orchestrator's
workspace to `/tmp`, and runs `ops install-macos-relay` from a
`mktemp -d` staging cwd so no guest source root is needed (same proven
shape as the quarantined `exercise_macos_relay_lifecycle_live`). This
manager verifies/completes it (compile, unit tests, scoped gates,
binary rebuild) before relaunching attempt 3.

## 23:30 — deploy fix completed + glm-5.3 adversarial review APPROVE

Completed the checkpoint's WIP fix on this branch (commit `98664b0e` +
hardening follow-up):

1. Extracted `reviewed_relay_plist_bytes(ws_root)` — fail-closed read
   of the reviewed plist from the orchestrator workspace (missing →
   Err, never a fallback). Unit tests:
   `reviewed_relay_plist_fails_closed_when_missing`,
   `reviewed_relay_plist_returns_exact_workspace_bytes`.
2. `deploy_relay_service(conn)` (workdir param dropped): scp the
   reviewed plist to a per-run /tmp drop path, root script stages it in
   a `mktemp -d` tree and runs `ops install-macos-relay` from there;
   `rc=$?; cleanup; exit $rc`. `install-macos-relay`'s
   `read_source_plist` verified to have NO embedded fallback (Err on
   missing file outside dry-run).
3. Adversarial review (ai_read, glm-5.3, two rounds): round 1 caught
   real design issues at the fixed `/tmp` drop names — symlink
   pre-planting (scp follows a planted symlink and clobbers a victim),
   pre-created-attacker-file swap before the root read (arbitrary
   launchd plist = root persistence; attacker-chosen verifier key =
   relay trusts attacker-signed assignment state), concurrent
   collision, and the empty-`$T` rm concern. Fix: BOTH drop paths
   (verifier key and plist) now carry a per-run `unique_suffix()`
   (u128 pid+counter+time) formatted by Rust into the scp destination
   and interpolated as a literal — never a shell-active string.
   Round-2 verdict on the actual diff: **APPROVE**, angles (a)–(f) all
   resolved: same-uid swap remains structurally possible but is moot
   under passwordless `sudo -n` (same-uid compromise = root; nothing
   left to defend); `rc=$?` captures the whole `&&` chain; scp rc
   gated in Rust; empty-$T unreachable past the first `&&`; no new
   secret handling. One non-blocking hardening applied: verifier-drop
   cleanup moved to the rc-capture shape so a failed `install` still
   removes the drop file. Remaining optional (NOT applied): hash-pin
   the reviewed plist at review time; pipe bytes over stdin instead of
   /tmp. Scoped gates: fmt clean, clippy `-D warnings --locked` clean,
   `macos_install` tests 84/84, `deploy_relay` tests 9/9.

Ledger note: the 36 empty-patch triage stubs in
`live_lab_stage_triage.jsonl` predate this series (latest 2026-07-25)
with no surviving run artifacts to ground patches — left for the
owner, not fabricated.

Next: rebuild the vm-lab binary, relaunch relay attempt 3 from this
worktree (`--source-mode local-head` on the new commit).

## 00:05 — relay attempt 3 launched (fix deployed)

Rebuilt `rustynet-cli` (vm-lab binary, target-pinned debug, contains
the staged-plist deploy path — verified by `rn-relay-reviewed-` string
present in the binary). All three nodes verified UP+reachable first
(macos-utm-1 192.168.65.101, debian-headless-4 192.168.64.10,
debian-headless-2 192.168.64.4, TCP/22 open).

Launched attempt 3: `--node macos-utm-1:relay --node
debian-headless-4:exit --node debian-headless-2:client
--enable-relay-forwarding-validation --skip-soak --linux-backend
linux-wireguard-userspace-shared --source-mode local-head
--trust-inventory-ready --ssh-identity-file ~/.ssh/id_ed25519
--known-hosts-file ~/.ssh/known_hosts`, report
`state/live-lab-macos-relay-fwd3-20260906-000522`, pid 31921,
deploying branch HEAD `6e3bb383`. (First try exited bad_args 64 —
`--ssh-identity-file` is required; relaunched with it.) Resolved plan
verified from `state/resolved_plan.json`: 66 stages,
`deploy_relay_service` AND `relay_forwards_frame_validation` both
planned, selectors `relay_forwarding_validation:true`,
`skip_linux_live_suite:false`, `soak_suite:false`. QH-64 watch active.

## Successor session (2026-09-06, worktree edit-1788651195477-40131-0)

This session continues the chain from checkpoint `f094cc1b` (which
carried the attempt-3 evidence rows, both filled triage stubs, and the
readiness-wait fix into this branch).

### Attempt 3 verdict (recorded from stage artifacts)

Run `livelab-1788650472-ef1c5ed0ec20` (report
`state/live-lab-macos-relay-fwd3-20260906-000522` in the predecessor
worktree, source archive commit `6e3bb383`, clean): 66 stages, 24 pass /
2 fail / 40 skip, overall fail, first_failed_stage `relay_validation`.

- `deploy_relay_service` PASS on macos-utm-1 — FIRST time on macOS. The
  staged-plist deploy fix (98664b0e + 6e3bb383) works.
- `relay_validation` FAIL: during-run UDP :4500 not bound, TCP :4501 not
  bound, `/healthz` unreachable. Triage (stub already filled on this
  branch, independently reconfirmed): startup race — validation captured
  its snapshot in the same second the deploy kickstart returned;
  post-run guest state proves the service healthy (launchd running,
  UDP 127.0.0.1:4500 + TCP 127.0.0.1:4501 LISTEN, `/healthz` ok). Remedy
  `wait_until_ready` (30s/1s poll) is in `role_validation/relay.rs` on
  this branch; 126 scoped relay tests green under pinned 1.88.0.
- `relay_forwards_frame_validation` SKIPPED (failed dependency).
- `traffic_test_matrix` FAIL: CP-1 cross-vmnet 100% loss, unchanged
  (stub filled). Skip-cascade took role_switch/two_hop/etc., as in
  attempt 2.

### CP-1 elevated to a structural blocker for the frame-forwarding cell

New evidence gathered live this session: from debian-headless-2
(192.168.64.4), the macOS guest 192.168.65.101 is unreachable at the
LAN level entirely — ICMP 100% loss AND TCP/22 connection timeout. This
is not a mesh/WireGuard symptom: no Linux peer can send any packet to
the macOS guest's LAN address. Since the HP-3 frame-forwarding proof
requires two Linux peers to direct UDP frames at the relay's LAN bind
(provisioned as `<relay_lan_ip>:4500`), `relay_forwards_frame_validation`
with a macOS relay is structurally impossible under the current lab
topology. Additionally the stage carries an explicit fail-closed
`adapter.platform() != Linux` gate (`relay_forwards_frame_validation.rs`,
"probe is Linux-only (nft + systemd unit restarts)"), and
`select_relay_forward_test_topology` elects only Linux relay_capable
nodes — a macOS-relay port of the probe would be moot until CP-1 is
resolved anyway. Porting the probe to macOS is therefore NOT attempted;
CP-1 (bridged-NIC/host topology change) stays the owner decision it has
been recorded as since attempt 2, now with LAN-level evidence.

Note for honesty: `linux_relay_forwards_frame` has itself never passed
on any OS (matrix tally: 313 not_run / 1 skip), so the forwarding stage
is unproven even where it is implementable.

### Attempt 4 (relay_validation goal) — launched and concluded

Launched from THIS worktree at 23:52:48Z (pid 43705, report
`state/live-lab-macos-relay-fwd4-20260906-005210`, `--source-mode
local-head` deploying `04c85129`, 66 planned stages verified from
`resolved_plan.json` with `relay_forwards_frame_validation` enabled).
Results (from stage artifacts, `state/stages.tsv` + per-stage logs):

- `deploy_relay_service` PASS (00:05:05–00:05:16Z).
- **`relay_validation` PASS (00:05:16–00:05:21Z) — the macOS relay
  lifecycle is now proven on the `--node` engine** (run
  `livelab-1788653310-04c85129bb4f`, commit `04c85129`, clean). The
  readiness-wait fix is live-verified: the during-run capture now finds
  UDP :4500 + TCP :4501 bound and `/healthz` ok, the stop/restart
  lifecycle assertions hold, and the matrix column
  `macos_stage_relay_service_lifecycle=pass` agrees with the stage
  artifact.
- `relay_forwards_frame_validation` FAIL exactly as predicted, fail-closed
  before touching any host: "relay node macos-utm-1 is Macos; the
  relay-frame-forwarding probe is Linux-only (nft + systemd unit
  restarts)" (`logs/relay_forwards_frame_validation.log`). This is the
  durable in-ledger evidence that the cell is blocked, not skipped.
- `traffic_test_matrix` FAIL (CP-1, as in every prior run; stub filled
  "none: owner-deferred"). Skip cascade followed; tally 26 pass /
  2 fail / 38 skip. Ledger row + 170 stage rows appended to
  `documents/operations/live_lab_node_run_matrix.csv` /
  `live_lab_node_stage_results.csv` in THIS worktree and verified.

## Session close (2026-09-06)

Cell status after this session: macOS relay **lifecycle GREEN on the
engine of record**; macOS relay **frame-forwarding BLOCKED** by (a) the
HP-3 probe being Linux-only by construction and (b) CP-1 cross-vmnet
unreachability (now evidenced at the LAN level: ICMP + TCP/22 dead
between vmnets). A macOS probe port is moot until CP-1 lands. No
rustynet-relay production code was modified this session; the only code
change on this branch remains the predecessor's readiness wait in
`role_validation/relay.rs` (lab validation harness).

Owner decisions outstanding (not mine to make), with evidence pointers:

- **CP-1** — re-pin lab guests to one vmnet / enable host forwarding
  between bridge100 and the macOS vmnet. Blocks: macOS↔any cross-node
  dataplane stage (`traffic_test_matrix`, `cross_os_*`,
  `relay_forwards_frame_validation` with a macOS relay, two_hop).
  Evidence: attempt-3/4 `traffic_test_matrix.log`, live LAN probe
  (debian-headless-2 → 192.168.65.101 ICMP 100% / TCP/22 timeout),
  `MacosCrossNetworkTrafficBlocker_2026-09-03.md`.
- **QH-66 Option D** — owner signing-key custody (unchanged).
- **QH-69** — `--linux-backend` default vs per-row recording
  (unchanged).
- Optional (queued by predecessor, not applied): hash-pin the reviewed
  relay plist / stdin-pipe bytes; `ManifestNodeAssignment`
  duplicate-alias rejection; `VmGuestPlatform::parse("")` pin.

## Closing pass (2026-09-06, worktree edit-1788655036704-53137-0, branch ai-edit/edit-1788655036704-53137-0)

No lab runs this session — closing work only.

**Ledger verification (attempt-4 port, already landed in `325cbae2`).**
Re-verified in THIS worktree with a quote-aware reader:
`live_lab_node_run_matrix.csv` carries exactly one attempt-4 row (run
`livelab-1788653310-04c85129bb4f`, start 2026-09-05T23:52:48Z, end
2026-09-06T00:08:30Z, commit `04c85129bb4f4b5d3a3a00d2a91b496406e0fddb`,
branch `ai-edit/edit-1788651195477-40131-0`, clean);
`live_lab_node_stage_results.csv` carries the 170 attempt-4 stage rows;
no duplicates. The three triage stubs from this series
(`live_lab_stage_triage.jsonl` lines 213–215:
`livelab-1788650472-ef1c5ed0ec20::relay_validation` readiness-race
remedy, `livelab-1788650472-ef1c5ed0ec20::traffic_test_matrix` CP-1, and
`livelab-1788653310-04c85129bb4f::traffic_test_matrix` "none: CP-1
cross-vmnet substrate gap, owner-deferred") all carry non-empty `patch`
text. Per the ledger's own schema
(`crates/rustynet-cli/src/live_lab_stage_triage.rs`, lines 16–22 and
`StageTriageRecord::is_unfilled`), a filled `patch` is the ONLY fill
marker — there is deliberately no patch-commit field (the row's own
commit is the patch commit) — so no `live-lab-record-stage-patch` call
is needed or possible for them.

**Docs synced this pass.**
`CrossPlatformRoleParityRefresh_2026-07-23.md` relay rows (lifecycle +
frame-forwarding) were already current with attempt 4 (landed in
`325cbae2`); re-read, no further edit. QH-68 is recorded FIXED and QH-69
FIXED(flag)/OPEN(default) in `QualityHardeningTodo_2026-07-25.md` — both
dispositions final, no edit. Added §8 to
`MacosCrossNetworkTrafficBlocker_2026-09-03.md` pointing at attempt 4 as
the newest CP-1 confirming run. AGENTS.md/CLAUDE.md untouched.

**Final macOS cell status (engine of record = Rust `--node`; evidence =
stage artifacts, not matrix columns):**

| Cell | Status | Proving run (commit, clean) |
| --- | --- | --- |
| client | 🟡 CP-1-deferred — STUN/orchestrator half proven live (run #5 `livelab-1788631948-3aedcfff9a75`, `3aedcfff`), `traffic_test_matrix` cross-vmnet legs still 100% loss | `livelab-1788631948-3aedcfff9a75` |
| admin | 🟢 `macos_admin=pass` | `livelab-1784501586` (`537e1901`) |
| relay (lifecycle) | 🟢 `deploy_relay_service` + `relay_validation` PASS | `livelab-1788653310-04c85129bb4f` (`04c85129`) |
| relay (frame-forwarding) | ⬛ structurally Linux-only probe (platform gate, `relay_forwards_frame_validation.rs`) AND CP-1-blocked; durable fail-closed record in the attempt-4 ledger row | `livelab-1788653310-04c85129bb4f` (`04c85129`) |
| anchor | 🟢 all four anchor stages incl. QH-68 re-proof | `livelab-1788635706-1eb6e800c4cf` (`1eb6e800`) |
| exit | 🟢 baseline chain green on the blind_exit posture (QH-67 fix); admin-posture `Exit` preset stays N/A-by-decree | `livelab-1788628164-40e7409ff2a4` (`40e7409f`) |
| blind_exit | 🟢 first election + pass | `livelab-1788172934687-17194-11` (`7bdcfe60`) |
| role-transition | ⬛ never run on `--node` for macOS (unchanged, out of this push's scope) | — |

**Owner decisions outstanding (not the manager's), with evidence
pointers** — unchanged from the session-close section above: **CP-1**
(re-pin to one vmnet / host forwarding between bridge100 and the macOS
vmnet; evidence: attempt-3/4 `traffic_test_matrix.log`, LAN probe
ICMP 100% + TCP/22 timeout, `MacosCrossNetworkTrafficBlocker_2026-09-03.md`
§5–§8); **QH-66 Option D** (owner signing-key custody, evidenced by
`owner_signing_key_present=true` in `logs/membership_init.log` of
`livelab-1788625551-504605015758`); **QH-69** (`--linux-backend` default
vs per-row backend recording; `QualityHardeningTodo_2026-07-25.md`).

**Gates (pinned 1.88.0, `target-pinned`):** `cargo fmt --all
-- --check` PASS; `cargo clippy -p rustynet-cli --all-targets
--all-features -- -D warnings` PASS (2m12s, zero warnings) —
`rustynet-cli` is the only crate this branch touches (readiness wait in
`vm_lab/orchestrator/role_validation/relay.rs`).

**Branch is NOT merged.** `ai-edit/edit-1788655036704-53137-0` (head
carries this closing commit) holds the full manager-chain work; review
and merge into `main` is the owner's step, per the delegated-edit
contract. Nothing was pushed.

closing pass complete




---

## 2026-09-06 (session 2) — Linux relay frame-forwarding push (HP-3, target #1)

Context: macOS role cells closed in the prior section; owner says keep
going. Target order per handoff: (1) Linux `relay_forwards_frame_validation`
(NEVER passed on any OS), (2) macOS role-transition, (3) macOS reboot
recovery, (4) Windows role cells.

### Topology resolution (read the code before launching)

`select_relay_forward_test_topology` (`vm_lab/mod.rs:13839`) elects from
the INVENTORY, not the run assignments: relay = the only
`relay_capable=true` Linux entry — **fedora-x86-1** — and the stage
(`relay_forwards_frame_validation.rs:140`) FAILS unless the assigned relay
== the elected relay. Peers = non-relay, non-exit-capable Linux entries
ranked by `lab_role` `aux`/`extra` then alias → sender **debian-headless-2**
(receiver **debian-headless-4**). All three must be IN the run mesh (probe
restarts sender+receiver daemons and asserts relay-routed status on both).

Elected run topology: `fedora-x86-1:relay linux-x86-exit-1:exit
debian-headless-2:client debian-headless-4:client`, full flag recipe per
attempt-2 line 252-259 + `--enable-relay-forwarding-validation --skip-soak`.

### Blocker found + fixed: tailnet ACL denies this Mac → 192.168.121.0/24

First launches failed the OS-version probe on `linux-x86-exit-1`
("refusing Linux-umbrella evidence"), and the failure was NOT transient:
from this Mac, TCP to 192.168.121.26/.227:22 gets **RST** and ICMP is
100% blackholed, while `virsh list` (all 4 KVM guests running),
`domifaddr` (IPs correct), and host→guest SSH from ubuntu-kvm-1 itself
all pass. `tailscale status --json` shows ubuntu-kvm-1 advertising
`192.168.121.0/24` and the Mac holding the utun4 route — RST+blackhole
with a working far side is the tailnet-ACL-deny signature. That is an
OWNER-level tailnet ACL change; not mine to make.

Workaround (landed on this branch, commit `caa11fdc`): the adapter SSH
transport passes `-F /dev/null`, so `~/.ssh/config` ProxyJump can never
apply there. Added env-gated, CIDR-scoped jump to the shared ssh/scp
hardening: `RUSTYNET_LAB_PROXYJUMP=<user@host>` + required companion
`RUSTYNET_LAB_PROXYJUMP_CIDRS=192.168.121.0/24` appends one
`-o ProxyJump=` — jump hop inherits the pinned identity + known_hosts
(verified live: lab key authorizes `ubuntu-server@100.117.1.47`, whose
key is pinned in `known_hosts_lab`). Fail-closed on half-configured or
malformed env; unit tests for the whole matrix; fmt+clippy clean. Also
added a `~/.ssh/config` block for 192.168.121.* (supervisor lenovo-guest
pattern) — that covers the legacy helper paths that DO read ssh_config.

### Run 5 (Linux relay) — IN FLIGHT at writing

Dry-run green: 4 nodes, 66 planned stages. Launched (pid 85569, nohup —
note macOS has no setsid):
`state/live-lab-linux-relay-fwd1-20260906-082801-r2`, commit `caa11fdc`
clean, env ProxyJump pair set. QH-64 watch active (the probe restarts
sender+receiver daemons mid-run; `RestrictionMode::Permanent` /
`gossip_accepted_total=0` = QH-64 evidence, not new defects). Result
append: next section.

## 2026-09-06 (session 3) — run 5 (Linux relay fwd, attempt 1) verdict + stable-topology retry

Successor manager (worktree `edit-1788682024523-99861-0`, branch
`ai-edit/edit-1788682024523-99861-0`, base = timed-out checkpoint `d731826a`
which already carries run 5's ledger rows and the ProxyJump commits
`caa11fdc`/`9c709139`).

### Run 5 verdict (from stage artifacts, report
`state/live-lab-linux-relay-fwd1-20260906-082801-r2` in worktree
`edit-1788678035879-79896-0`; ledger id `livelab-1788681040-caa11fdc1fc8`,
commit `caa11fdc`, clean, 07:29–07:50Z, 4 nodes
debian-headless-2:client / debian-headless-4:client / fedora-x86-1:relay /
linux-x86-exit-1:exit)

- `deploy_relay_service` **pass** and `relay_validation` **pass** on
  fedora-x86-1 — first `--node`-engine Linux relay-service lifecycle proof in
  this series (the macOS lifecycle proof landed earlier as
  `livelab-1788653310-04c85129bb4f`).
- `relay_forwards_frame_validation` **fail — but NOT a probe/platform
  failure**: `fedora-x86-1: relay provisioning on fedora-x86-1 failed: remote
  command exited with status 255: ssh: connect to host 192.168.121.227 port 22:
  Connection refused`. fedora-x86-1 dropped sshd mid-run (known ubuntu-kvm
  guest flakiness); bootstrap_hosts had reached all four nodes minutes earlier
  in the same run with the ProxyJump pair active, and the watchdog re-probe
  shows the port answering again. The frame-forwarding probe was never
  exercised. Triage stub amended to record this root cause (the previous patch
  text misattributed it to the tailnet ACL, which the jump hop already
  solves).
- `traffic_test_matrix` **fail**: ALL 121.x↔64.x legs 100% loss both
  directions (fedora-x86-1↔both Debians, linux-x86-exit-1↔both Debians). New
  environment evidence: the two subnets are underlay-partitioned (121.x =
  libvirt NAT behind ubuntu-kvm-1, tailnet-ACL-blocked from this Mac; 64.x =
  local UTM shared net). 64.x↔64.x legs passed. Consequence for topology
  design: relay, sender, AND receiver for the frame-forwarding probe must sit
  on ONE mutually-reachable subnet — lenovo (192.168.0.x, bridged) cannot
  serve: 64.x→0.x works (NAT egress) but 0.x→64.x is unrouted, and both the
  receiver→relay UDP flow and any relay-on-lenovo forwarding direction need
  that dead path.
- Ledger port: the checkpoint `d731826a` already committed run 5's row + 224
  stage rows; verified byte-identical to the report artifacts (0 field diffs)
  and both new triage stubs are now filled (run 5's amended; the 08:03Z
  relaunch stub `livelab-1788681822-9c709139ad16::prepare_source_archive` was
  the clean-worktree gate tripping on the then-uncommitted rows — launch
  hygiene, no code defect).

### Retry topology (avoids fedora-x86-1 entirely; read from
`select_relay_forward_test_topology` at `vm_lab/mod.rs:13840`)

Election is inventory-driven: relay = first `relay_capable=true` Linux entry
in entries order; peers = Linux, non-relay, non-`exit_capable=true`, ranked by
lab_role aux(0)/extra(1)/other(2) then alias. fedora-x86-1 is currently the
only `relay_capable` Linux entry, and the stage fails unless the assigned
relay == the elected relay — so avoiding fedora REQUIRES an inventory change.
Worktree-only inventory edits (never merged without owner review; documented
here):

1. `debian-headless-4.relay_capable: false → true` — elects the stable local
   Debian as relay (entries order puts it ahead of fedora-x86-1).
2. `debian-lan-11.exit_capable: (absent) → true` — exclusion hack only:
   debian-lan-11 is a physical device with no mesh_ip/controller; without an
   exclusion it sorts in as receiver and the stage fails at topology
   formation ("peer debian-lan-11 has no mesh_ip recorded"). exit_capable is
   the minimal lever that excludes it from peer candidates.
3. No lab_role edits needed: with dh4 as relay, rank-2 alias order elects
   sender=debian-headless-2 and receiver=fedora-utm-1 (a local UTM Linux
   guest on the same utm-shared 192.168.64.0/24 — verified below before
   launch).

Run recipe: `--node debian-headless-4:relay --node debian-headless-2:client
--node fedora-utm-1:client --enable-relay-forwarding-validation --skip-soak
--linux-backend linux-wireguard-userspace-shared --source-mode local-head
--trust-inventory-ready --ssh-identity-file ~/.ssh/rustynet_lab_ed25519
--known-hosts-file ~/.ssh/known_hosts_lab --collect-artifacts-on-failure`,
fresh report dir, NO ProxyJump env (all-local topology). Per-node SSH
preflight with the lab key immediately before launch; abort on any miss.
QH-64 watch active (probe restarts sender+receiver daemons mid-run).

## 2026-09-06 run fwd3 (retry of relay-forward proof on 975d9bbb)
- Worktree HEAD = 975d9bbb (relay-forward role-assignment election fix), clean.
- Rebuild: cargo build -p rustynet-cli --features vm-lab @ target-pinned, OK (1m56s).
- Preflight SSH: debian@192.168.64.10=dh4 OK, debian@192.168.64.4=dh2 OK, fedora@192.168.64.103=fedora-utm-1 OK (inventory ssh_target 192.168.65.10 and live_ip 192.168.64.20 both stale/dead; 64.103 live).
- First launch attempt died instantly: worktree had no state/ dir → zsh redirect failure. mkdir state, relaunched.
- RD=state/live-lab-linux-relay-fwd3-20260906-112215 pid 65322, flags: --node dh4:relay dh2:client fedora-utm-1:client --enable-relay-forwarding-validation --skip-soak --linux-backend linux-wireguard-userspace-shared --source-mode local-head --trust-inventory-ready --collect-artifacts-on-failure. Log: state/live-lab-linux-relay-fwd3-20260906-112215.log

## 2026-09-06 runs fwd3–fwd5b (relay-forward proof, commit 975d9bbb)
- fwd3 (state/live-lab-linux-relay-fwd3-20260906-112215, pid 65322) DIED early:
  fedora-utm-1 OS-version probe degraded to 'linux' placeholder after 3 SSH
  retries (evidence.rs validate_collected_os_version fails loud, exit 70
  transient_failure). Manual probe with identical key/known-hosts works
  ("Fedora Linux 44 (Server Edition) (aarch64)") — transient, no defect.
- fwd4 (state/live-lab-linux-relay-fwd4-20260906-112854, pid 66518) ran further,
  FAILED preflight: "lab requires exactly 1 Exit node, found 0" — the retry
  recipe in the session-3 section was written against the inventory-driven
  election era and never included an Exit; preflight invariant applies to every
  --node run (preflight.rs:377-385 counts role assignments, not capability
  flags). All other stages cascade-skipped; run-matrix row + 166 stage rows +
  triage stub appended by the finalizer (uncommitted).
- All inventory exit nodes unreachable from this Mac (libvirt 121.x tailnet
  ACL-blocked — SSH to fedora-x86-1 192.168.121.227 times out; lenovo 0.x
  unrouted). Local UTM 64.x candidates: rocky-utm-1 (linux, 192.168.64.105,
  key-auth OK, Rocky 10.2).
- Commit 1a59ab6f: rocky-utm-1 exit_capable true + fedora-utm-1 live-IP refresh
  (sanctioned --update-inventory-live-ips; my first python edit mangled
  em-dashes to \u2014 — redone with ensure_ascii=False, then restored the
  sanctioned fedora refresh the git checkout had reverted). exit_capable flag
  ALSO excludes rocky from relay-forward peer election (aux rank 0 would
  otherwise elect the exit node as sender — select_relay_forward_test_topology_
  for_run filters exit_capable==Some(true)).
- fwd5 (113905) refused at launch gate: fwd4's preflight stub had no recorded
  remedy (enforce_launch_gate, no bypass by design). Recorded remedy via
  `ops live-lab-record-stage-patch --stub-id livelab-1788694287-8edbc55259c3::
  preflight` (topology fix, commit 1a59ab6f).
- fwd5b LAUNCHED 11:41:47Z: RD=state/live-lab-linux-relay-fwd5b-20260906-114147
  pid 69402, 4 nodes dh4:relay dh2:client fedora-utm-1:client rocky-utm-1:exit,
  same flags + --enable-relay-forwarding-validation. Election expectation:
  sender=debian-headless-2, receiver=fedora-utm-utm-1... precisely:
  sender=dh2 (client→rank2, alias order), receiver=fedora-utm-1. QH-64 watch
  active. Polling; verdict from logs/relay_forwards_frame_validation.log +
  stages.tsv only.
