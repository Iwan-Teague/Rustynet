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
