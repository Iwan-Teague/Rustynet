# Owner decisions — 2026-09-07 (post macOS/relay parity push)

Decisions taken by the owner on 2026-09-07 after the 2026-09-06/07 GLM manager
sessions (see `GlmManagerLog_2026-09-05.md`, `GlmManagerLog_2026-09-06_code.md`).
Each item names the plan document that carries the design and the ledger entry
that tracks it. Security posture is the tie-breaker throughout: no decision below
lengthens a TTL, weakens a validator, or downgrades a fail-closed path.

| # | Decision | Chosen | Owner rationale (security-first) | Plan / tracking |
| --- | --- | --- | --- | --- |
| 1 | rustynetd macOS boot recovery does not re-pin the Ethernet DNS service to loopback nor retire the QH-40 residue marker (proven by run `state/live-lab-macos-reboot-20260907-050612`) | **Fix now in rustynetd** (human/Claude-implemented; daemon code stays out of GLM workers) | A DNS leak window on every macOS reboot is a fail-closed gap on a shipped path; the reboot cell already exists to prove the fix | `MacosDnsBackupRebootSurvivalPlan_2026-09-02.md` addendum; reboot cell attempt 4 |
| 2 | Relay frame-forwarding blocked on stale signed traversal/dns_zone bundles after `live_reboot_recovery` | **Both**: lab re-mints/redistributes before the stage (or reorders it) AND a product design for authority pre-expiry re-mint with client refresh; TTL stays 120 s | The daemon is right to refuse stale state; a fleet must survive losing its minting authority only by failing closed, never by trusting old bundles | new `TraversalBundleFreshnessPlan_2026-09-07.md`; QH entry to follow |
| 3 | QH-74: orchestrator ledger paths bound to the build worktree | **Runtime resolution** from the inventory path / cwd, compile-time path only as an explicit fallback, with a pinning test | Evidence integrity — the ledgers are what the parity mandate rests on | QH-74; new `LedgerRuntimeRootResolutionPlan_2026-09-07.md` |
| 4 | CP-1 host pf override persistence | **launchd LaunchDaemon** that reloads `scripts/vm_lab/cross_vmnet_pf_override.pf` at boot (no `/etc/pf.conf` edit; removable by deleting one plist; owner installs with sudo) | Opens only routed traffic between the two private lab /24s; least invasive persistent form | `MacosCrossNetworkTrafficBlocker_2026-09-03.md` §9; `scripts/launchd/` |
| 5 | QH-70: `mesh_status_validation` false-green | **Stage-side**: require live-handshake evidence from daemon status; daemon untouched | A validator that passes with every tunnel dead is worse than none | `MeshStatusVacuousPassPlan_2026-08-13.md` addendum; QH-70 |
| 6 | Windows stream | **Deferred** (ubuntu-kvm-1 stays offline this session); when resumed: wired Ethernet + monitoring, and DNS fail-closed self-heal in the daemon rather than validator retries | Not decided today | `WindowsDnsFailclosedIpv6FlakeDiagnosis_2026-09-05.md` |
| 7 | Review process for GLM branches | **Always reviewed before merge**; the reviewer may be another GLM agent (flash acceptable) plus a mechanical path allowlist for edit jobs | 2026-09-07 reviews found three blockers the branch's own review had marked fixed | new `DelegatedEditPathGuardPlan_2026-09-07.md`; §12.6 of AGENTS.md/CLAUDE.md |
| 8 | Small fixes | **Do all**: reword the `rustynet-control` doc comment that trips the backend-boundary gate on `main`; fold the manager-driver fixes (`OPENCODE_DISABLE_MODELS_FETCH` when models.dev is unreachable, longer launch timeout) into `scripts/mcp/drive_ai_agent.py`; live-prove the corrected pf-anchor flush before QH-73 is called fixed | Keeps CI honest and stops the next session rediscovering the OpenCode boot hang | this commit; QH-73 |

Execution model from here: GLM flash drafts each plan (grounded, read-only), GLM
edit jobs implement the lab-tooling items (2-lab, 3, 4, 5, 7, 8) under the
path guard, and the daemon/trust-state items (1, 2-product) are implemented by
the owner or a Claude session and then GLM-flash-reviewed. Every branch gets an
independent review before it reaches `main`.

## D6 (2026-09-10, REVISED after run #4) — forward clock jump poisons the anti-rollback watermark

**What the lab measured** (lenovo-bot, `chaos_clock_attack` jump-forward leg, +90 days via
libfaketime on `rustynetd.service`, exit guest journal):

1. Under the faked clock the daemon starts (`daemon_started_under_fault=true`) and, within
   seconds, runs a *pre-expiry signed-state refresh* — "signed state refresh completed
   (reason=preexpiry)" — i.e. it mints/accepts state stamped with the future clock and
   advances its traversal watermark to that time.
2. Every reconcile then fails: "traversal authority requires valid signed traversal state:
   traversal bundle is stale" (the real bundle is older than the now-future watermark);
   after `RUSTYNET_MAX_RECONCILE_FAILURES=5` (five seconds at the 1 s reconcile interval)
   the node is **PERMANENTLY restricted** (`restrict_permanent`, `daemon.rs:11170`).
3. The restriction is in-memory, so the bin's teardown restart clears it — but the
   future-dated watermark is on disk, so the fresh process fails reconcile the same way
   and re-enters permanent restriction within five seconds, **under the real clock**
   (journal 20:44–20:45, forty consecutive "already PERMANENTLY restricted" lines).
   Consequences seen in the same run: epoch reads 0, no `rustynet0` interface (backend
   not running) so `chaos_network_impairment` failed "Cannot find device", and the
   crash-recovery loop recovered the process in 10 s but the mesh never re-converged.

So the daemon is fail-closed (good) but a *transient* forward clock error becomes a
*permanent* outage that survives restarts and needs an operator to reset the watermark.
The chaos stage's own criterion (`future_state_rejected && epoch_not_regressed`) says the
intended behaviour is the opposite: **reject** state dated in the future, keep the epoch.

**Owner decision needed (trust-state; manager will implement, GLM reviews):**
- (a) *Refuse to mint or accept a refresh whose timestamp is ahead of the last-good
  watermark by more than the configured max-age / a skew bound* — the watermark can only
  advance by a bounded step per refresh, so a clock jump cannot move it 90 days. The node
  stays recoverable-restricted (not permanent) while its clock is wrong and heals when the
  clock is corrected. Recommended.
- (b) Keep today's behaviour and document the operator watermark-reset procedure as the
  recovery path (an availability cost the chaos suite will keep flagging).

Lab-side, independent of the decision: `chaos_clock_attack` now runs LAST in the chaos
plan so a poisoned node cannot cascade into the other stages (`plan.rs`), and the clock
bin records `daemon_started_under_fault`.

Decision: ______
