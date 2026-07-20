# Security Audit, A4 Attestation Fix, and Main Consolidation (2026-07-21)

**Status: the security work described here is complete and merged to `main` (`f4190ab`). The
branch-consolidation work is complete — every real branch in the repo has been either merged or
confirmed already present on `main`. Several adjacent items were deliberately left open; see §7.**

## 1) Purpose

This is the session-level wrap-up tying together several pieces of work that each have their own
detailed doc, plus the branch-consolidation pass ("get everything on main") that has no dedicated
doc elsewhere. Read this first for the overall shape; follow the links below for the technical
depth on any one piece.

## 2) Security audit (A1–A5)

A five-finding security audit was run against the repo. Four fixed with tests, one corrected via
documentation, one (A4) substantial enough to need its own design/implementation/review cycle
(§3).

- **A1 — a revoked peer's WireGuard tunnel was never torn down in production.**
  `apply_revocation()` existed and was unit-tested, but no production caller ever invoked it.
  Fixed: wired into `handle_membership_apply`'s IPC apply path, fails closed (names the affected
  node) if teardown errors. Proof:
  `membership_apply_via_ipc_revokes_managed_peer_and_tears_down_tunnel` and
  `membership_apply_via_ipc_revocation_teardown_failure_returns_err` (commit `684f91b`).
- **A2 — `SecurityMinimumBar.md` falsely claimed "TLS 1.3 enforced for control-plane APIs"** with
  no TLS library anywhere in the workspace, backed by a self-asserted `tls13_valid` field
  hardcoded to `true` at issuance. Fixed: the field and all its plumbing removed from
  `TrustEvidenceRecord`/`SignedTrustVerificationReport`, trust-evidence payload version bumped
  2→3, and the doc corrected to describe what's actually enforced (WireGuard/Noise transport
  encryption for mesh traffic, signed-state verification for anything fetched outside the tunnel)
  (commits `c2e3512`, `0877fa6`).
- **A3 — the backend-boundary-leakage gate was failing.** 15 incidental WireGuard-specific
  mentions in backend-agnostic crates (`rustynet-crypto`, `rustynet-control`,
  `rustynet-backend-api`) reworded to backend-neutral language;
  `RotationError::WgApplyFailed` renamed `BackendApplyFailed`. `scripts/ci/check_backend_boundary_leakage.sh`
  now passes (commit `1d4d343`).
- **A4 — the anchor bundle-pull client never re-verified signatures after fetching.** The
  substantial one — see §3.
- **A5 — a malformed request on the admin IPC socket killed the whole daemon.** The accept loop's
  read-side disposition changed from fatal to log-and-continue, matching an existing write-side
  precedent.

**Part B** (a fresh audit hunting the same bug shape — `apply_*`/`enforce_*`/`revoke_*`/etc. call
sites, unverified-fetched-state consumption — elsewhere in the codebase) was explicitly descoped
per operator instruction partway through the session and never attempted. Not an oversight —
recorded here so it reads as a deliberate scope cut, not a dropped ball.

## 3) A4: membership head attestation — design, implementation, adversarial review

A4 needed more than a quick fix: the obvious remedy ("reuse `apply_signed_update`") doesn't
actually work architecturally, because that pipeline authenticates a chain of signed *deltas*
against an already-trusted prior state, and the anchor bundle-pull endpoint hands a *bare*
snapshot to a device with no prior state at all. Handled as its own cycle:

1. An independent design pass (read-only, no code) investigated the actual trust model, found
   the system already mandates an out-of-band pinned owner key (`SecurityMinimumBar.md` §6.B)
   that was never consumed at runtime, and recommended a "membership head attestation" — a
   quorum-signed record binding `(network_id, epoch, state_root, attested_at)`, minted in the
   same signing session as every membership update, verified client-side before any disk write.
2. Implemented essentially as designed, including rotation grace (a revoked-former-owner pin is
   still honored if a current active owner co-signs).
3. **Three independent adversarial reviewers**, run in parallel, each told to try to defeat the
   implementation rather than summarize it. 20 of 21 checks held up clean under direct code
   tracing, live PoCs, and reproduced test runs. One real defect found and fixed in this session:
   quorum was counted by signer *slot* (`approver_id`) rather than distinct signing *key* —
   closed at `MembershipState::validate()`, which turned out to reach further than intended (it
   blocks the vulnerable roster shape from ever producing a state root anywhere in the crate, not
   just at the final check, and closes the identical pre-existing gap in the regular
   membership-update quorum path as a side effect). One real defect found and **not** fixed
   inline — the stale-cache rollback vector, handled separately (§4).

Full trail — rejected design alternatives, every reviewer's per-check verdict, the quorum-bug
fix, all named tests: [`AnchorBundlePullAttestationSecurityReview_2026-07-20.md`](./AnchorBundlePullAttestationSecurityReview_2026-07-20.md).

Merged to `main` via `e1d2a8b` (attestation feature + review) and `3c1ae84`
(quorum-uniqueness fix, folded into the same fast-forward).

## 4) Rollback-vector fix

The adversarial review surfaced a real gap distinct from the quorum bug: epoch-regression
protection was derived fresh from `--output` on every `anchor pull-bundle` invocation, so a
brand-new device (the primary bootstrap scenario) or one whose local cache had simply aged past
the freshness window skipped the check entirely — a holder of an old, already-revoked signing key
could mint a freshly-timestamped attestation over a superseded epoch and it would pass every other
check clean.

Investigated separately, and the investigation surfaced its own good news: `rustynetd` already
shipped and unit-tested a `MembershipWatermark` mechanism (persistent, monotonic,
trust-on-first-use) for its own daemon bootstrap/apply paths — it had simply never been wired into
`anchor pull-bundle`. Fixed by relocating that mechanism into `rustynet_control::membership` and
having `anchor pull-bundle` consult and advance the exact same on-disk watermark file the daemon
already maintains, independent of `--output`. Three new tests prove the TOFU case, the exact
vulnerability's closure, and the honest residual limit (deleting the watermark's own storage, not
just `--output`, is a real, acknowledged TOFU-reset boundary — pinned by test, not hidden).

Full investigation, prior-art survey (TUF's version-watermark/freshness split; why
Certificate-Transparency-style equivocation defenses are a separate, harder, unaddressed problem),
and design rationale: [`AnchorBundlePullRollbackWatermarkInvestigation_2026-07-20.md`](./AnchorBundlePullRollbackWatermarkInvestigation_2026-07-20.md).
`SecurityMinimumBar.md` control 2 updated to reflect the closure.

Merged to `main` via `e0cc8e5` (fix) and `f4190ab` (doc status updates).

## 5) Dataplane fix: macOS full-tunnel exit underlay blackhole

Separate from the security-audit chain: live-lab-verified root cause of 100% WireGuard handshake
failure for any macOS node in full-tunnel exit mode. The exit-mode transition installed the
split-default routes (`0.0.0.0/1` + `128.0.0.0/1`) but never installed the per-peer `/32` endpoint
bypass route, so the node's own handshake packets to the exit peer's real endpoint were captured
by the tunnel routes and never reached `en0`. Two compounding defects: the privileged-helper argv
allowlist rejected the per-endpoint route-probe schema (so the on-link/off-link check always
failed in production, silently, while unit tests with no allowlist passed clean), and the
resulting error was swallowed as `Err(_) => Ok(false)`, classifying every endpoint as on-link.
Fixed: allowlist the read-only probe schema, fail closed on probe error instead of swallowing it.

Rebased onto current `main` (its original base was 36 commits behind by the time of this
consolidation), re-verified with the full gate suite post-rebase, merged via `1a786dc`.

## 6) Main consolidation ("get everything on main")

Separate from the security work: a pass to ensure no branch in the repo sat ahead of `main` with
unmerged, unreviewed work. Every branch and worktree in the repo was enumerated and disposed of:

**Merged this session** (beyond §2–§5 above):
- `feat/triage-auto-inject-prior-attempts` — genuinely new (auto-surfaces prior triage attempts
  when a `--node` live-lab stage fails, reading the existing triage ledger). Reviewed
  independently, rebased conflict-free, all gates clean, not superseded by anything on `main`.
  Merged via `e30bbdf`.

**Confirmed already on `main`, nothing to merge** (each independently reviewed — full diff read,
rebased to confirm zero delta, full gate suite re-run):
- `damascus` — a single test-hygiene commit, already an ancestor of `main`.
- `claude/hp3-relay-forwarding` (HP-3 real relay packet-forwarding proof: frame/byte counters,
  a new live-lab validator, a genuine cleanup-on-every-exit-path bug fix) — all 5 commits
  byte-identical ancestors of `main`, already merged with further relay work stacked on top.
- `claude/todo-file-review-kpkyar` (vm-lab SSH retry/hardening refactor) — turned out to be an
  old snapshot of `main` from 2026-07-11 rather than a diverged branch; `main` continued 269
  commits past this exact point.
- `integration/all-fixes-2026-07-15` and the **five** standalone fix branches it bundles
  (`fix/phase10-test-harness-framed-protocol-v2`, `fix/rustynetd-iproute2-6-19-fib-table`,
  `fix/ubuntu-wg-private-key-apparmor`, and a fifth not originally in scope,
  `fix/privileged-helper-ipv6-route-show`) — every one of the four logical fixes confirmed
  **byte-identical** to what's already on `main` via `git patch-id` (not just similar-looking
  diffs), having landed earlier through the same `damascus` branch merge.

**Deleted — no recoverable content** (operator-approved, 2026-07-21): three `.claude/worktrees/`
directories with no live git history —
- `fable-wireformat` — its `.git` pointer referenced a path on a different machine/sandbox
  entirely (`/sessions/kind-eager-cannon/mnt/Rustynet/...`); every file at an identical
  initial-checkout timestamp, meaning no edits were ever made here.
- `lab-main` and `role-transitions-anchor` — git had already pruned their
  `.git/worktrees/<name>/` metadata, so their last-known commit/branch is unrecoverable locally;
  no matching branch ref exists anywhere (local or remote). The repo does hold 1141
  dangling/unreachable commit objects from its overall history, but isolating which (if any)
  belonged to these two specific worktrees inside that haystack was judged not worth the search
  without a more specific lead than approximate creation dates (`.git` file mtimes: `lab-main`
  ≈2026-06-21, `role-transitions-anchor` ≈2026-07-01).

**Not deleted, still redundant housekeeping** (flagged, not acted on — operator has not asked for
this cleanup): the five stale `fix/*`/`integration/*` branches above, this session's own
`ai-edit/edit-*` worktree chain (superseded once absorbed into `main` via `security/a4-membership-head-attestation`
and `ai-edit/edit-1784559006480-92435-0`), the two local tracking branches created for review
(`claude-hp3-relay-forwarding`, `claude-todo-file-review-kpkyar`), and the still-broken local
`hp3-relay-forwarding` worktree (its branch content is confirmed on `main`; only the local
worktree checkout itself is broken).

## 7) Explicitly open — not forgotten, out of scope for this pass

- **Part B** of the original security audit (§2) — never attempted, by instruction.
- **Adjacent bearer-token gap**: `anchor pull-bundle` still authenticates the *client* with a
  static, long-lived bearer token rather than the single-use enrollment token `Requirements.md`
  specifies. Tracked in `SecurityMinimumBar.md` control 2 as a separately-scoped gap — bundle
  *authenticity* no longer depends on it (that's what §3/§4 closed), only roster
  *confidentiality* does.
- **Live-lab proof**: none of the work in §2–§5 has been run through the live lab. All of it is
  unit/integration-tested; the anchor role's live pass criterion (`AnchorNodeRoleDesign_2026-05-21.md`
  §5.2 Track B) remains an actual VM-lab exercise nobody has run yet.
- **Doc-sync nit**: `SecurityAuditLedger_2026-06-18.md` still names `wait_for_remote_socket` as
  dead code needing "fix or delete" — it was deleted as part of the already-merged
  `todo-file-review-kpkyar` content; the ledger note itself was never marked resolved. Trivial,
  non-blocking.
- **Branch housekeeping** listed at the end of §6 — deletion offered, not performed.

## 8) Final state

`main` at `f4190ab`, in sync with `origin/main`, full gate suite (fmt, workspace clippy, full
workspace test — zero failures, `cargo audit`, `cargo deny`) green at every merge point in this
session. Commit sequence for this session's work, oldest first: `1d4d343` (A3) → `684f91b`/
`8635443` (A1) → `c2e3512`/`0877fa6` (A2) → `42901a0` → `bba9983`/`f5d528f`/`3e41ea6`/`a5675a4`
(A4 feature) → `e1d2a8b` (A4 docs) → `3c1ae84` (quorum fix) → `1a786dc` (macOS dataplane fix) →
`e30bbdf` (triage-auto-inject) → `3c248e3` (rollback investigation doc) → `e0cc8e5` (rollback fix)
→ `f4190ab` (rollback doc status).
