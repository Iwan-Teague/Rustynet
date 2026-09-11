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

## D6 (2026-09-10, FINAL after run #5) — expired self-state permanently restricts a node in five seconds

**The lab bug (fixed `f75514d8`, no decision needed):** the managed-DNS, LAN-toggle,
exit-handoff, two-hop and cross-network scenario bins re-issue traversal bundles
mid-run with only `NODES_SPEC`/`ALLOW_SPEC`, and the issuer defaulted a missing
`TRAVERSAL_TTL_SECS` to **120 s** — silently replacing the 24-hour bundles Setup had
distributed. Two minutes after `live_managed_dns_validation` every node in the fleet held
an expired traversal bundle; any daemon *restart* after that (every restart-based chaos
stage, the crash loop, the clock stage's teardown) started with "traversal bundle is
stale", failed reconcile five times in five seconds, and was permanently restricted.
The earlier "clock-jump poisons the watermark" reading was wrong: the watermark on disk
was real-time; the bundle had simply expired. The issuer now refuses an env without a
TTL and every writer pins 24 h.

**What remains a product question:** the sequence the lab exposed is real for any
deployment — if a node's traversal bundle expires (authority down for longer than the
TTL, long suspend, a long crash loop) a fresh daemon start is **PERMANENTLY** restricted
within `RUSTYNET_MAX_RECONCILE_FAILURES × reconcile interval` (5 × 1 s), and
`complete_verified_signed_refresh` refuses to lift a permanent restriction even after
a later refresh brings a fresh bundle (`daemon.rs:6197`). Fail-closed, but it turns a
recoverable freshness gap into an operator-only outage.

- (a) Treat *staleness of otherwise-valid signed state* as RECOVERABLE (never promote to
  permanent on `Stale`; keep permanent for signature/replay/policy failures), and let a
  verified refresh clear a recoverable restriction — the node heals as soon as fresh
  state arrives. Recommended; matches §3 ("fail closed when state is stale") without
  the permanence.
- (b) Keep today's behaviour and document the operator reset.

Decision: ______

*Addendum 2026-09-11:* the clock-attack leg itself does not show poisoning — under a +90-day clock the daemon refuses to start at trust preflight ("trust evidence is stale", exit 65) and boots cleanly once the clock is restored. D6 stands on the expired-traversal-bundle episode only (an expired bundle at start → permanent restriction a later verified refresh cannot lift).
