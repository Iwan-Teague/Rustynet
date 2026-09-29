# Linux live-lab security stages: plan (2026-09-29)

**Status.** Owner-approved direction (2026-09-29: "should we add more linux live lab stages to ensure the project is secure? If you think so, implement them"). This record says which stages are added, why these and not others, and the bar each must meet. Implementation goes through fleet lanes, each with an independent review before landing and a live run before any pass is counted.

## Why more stages, and why these

The coverage gap audit (`LiveLabCoverageGapAudit_2026-09-27.md`, section 7) ranked eleven proposals. Since it was written:
- **Rank 1 is done on Linux.** Both built-but-never-run negative controls (killswitch bypass, enrollment-token replay) now pass live on katana (katana-u15 onward).
- **Ranks 6 and 11 (HP-3)** wait on owner decisions (`HP3RelayForwardProvisioning_2026-09-28.md`).
- **Ranks 2, 3 and 4** are macOS work, blocked on CP-1.
- **Rank 8 (performance floor)** is a release gate, not a security control.
- **Rank 9 (nas/llm)** needs production enforcement wired first (SecurityMinimumBar §6.E records E1, E3 and E4 as not wired). A stage today could only witness E2.
- **Rank 10 (cross-network)** is lab plumbing, not code.

What is left for Linux, and still unwitnessed, falls into two classes.
- **Trust-root changes on a live mesh.** Owner-key rotation and node revocation are exercised only in-process: the chaos membership binary runs against a synthetic network and records its live remainder as `skipped` (`crates/rustynet-cli/src/bin/live_chaos_membership_adversarial_test.rs:16-25`). So the audit's "LIVE" for revocation propagation (row 26) overstates it. SignedMembership-kind role transitions have no live witness on any OS (row 23).
- **Pre-authentication surfaces attacked over the wire.** The only rate-limit witness is the relay auditing itself (`live_hello_limiter_flood_validation` runs `rustynet-relay hello-limiter-audit` on the relay host). No stage attacks a live socket from another machine.

An independent review of the first draft of this plan (recorded below) reordered the stages and corrected three claims.

## The four stages, in order

### S1. `live_owner_key_rotation_validation`: rotation and revocation propagation (SecurityMinimumBar §3.2; Requirements §12)

On a live mesh, use the product's own path: `rustynet membership propose-rotate-approver` (`crates/rustynet-cli/src/main.rs:5995`; signed operation `RotateApprover`, `crates/rustynet-control/src/membership.rs:568`). Rotate in a new owner key (active) and revoke the old one, then sign and distribute the update through the product's distribution path.
- **Must hold:** after the rotation, every node rejects a membership update signed only by the old key, and rejects a replay of a pre-rotation update. The product's rotation grace (an old key accepted only when co-signed by an active owner, `membership.rs:1734-1740`) is asserted as designed, not treated as a failure.
- **Positive control:** a valid update signed with the new key is applied on every node within a stated bound, and observed state changes (the epoch advances on every node).
- **Revocation, same stage:** revoke a node through the product path, and prove that every peer drops it within a stated bound (no handshake, traffic denied), and that the revoked node cannot rejoin with its old state.
- Stop and report only if distributing the update to live nodes has no product path. Do not build one in the harness.

### S2. SignedMembership role transitions, live (SecurityMinimumBar §6.D; audit row 23)

Drive the SignedMembership-kind transitions that the role planner defines (for example admin to exit, and exit to admin) through the public `rustynet role set` surface on a live node. Assert what CLAUDE.md §10.7 requires: side effects happen in the required order (a service is deployed before its capability is advertised, and exit NAT is torn down before the capability is removed, with no residue); the transition appends its audit-log entry; and a transition the planner blocks is refused. This stage starts with a design lane, because the exit-demotion residue stage (and its restore, lane b41) already drives part of this walk, and the new stage must not duplicate it.

### S3. `live_enrollment_listener_abuse_validation` (SecurityMinimumBar §3.3 and §6.C)

The anchor enrollment listener enforces a 256-byte request line, a 2 s read budget and a 5 s write budget (`crates/rustynetd/src/daemon.rs:285-296`). It has no connection-count limit: it accepts one connection per poll, inline in the daemon event loop (`daemon.rs:2163-2205`), so slow clients stall the loop.
- **Parser attacks** (malformed and oversized frames, invalid-token consumes) run over loopback on the anchor, as the replay control does. **Peer-side attacks** cover the TLS handshake and slow clients only, unless allow-LAN plus a lab TLS identity is an explicitly scoped opt-in.
- Slow clients are capped at 5, and every attack is bounded in size and duration.
- **Must hold:** the daemon survives with the same PID; its IPC `status` answers within a stated bound during and after the attack; the consumed-token ledger gains no row.
- **Positive control:** a genuine token minted after the attack is accepted exactly once, and the ledger gains exactly that one row.
- The listener exposes no serve counters, and journald can rate-limit its lines, so no verdict rests on a count of journal lines.
- Because this stage uses the anchor listener host, re-run `live_anchor` (31 days stale in the audit) in the same topology.

### S4. `live_relay_preauth_flood_validation` (SecurityMinimumBar §3.3)

From a peer node (never the relay host), flood the live relay with pre-authentication hellos above the per-source-IP rate (50 per second). Do not attempt the 4096-source cap: the limiter keys on source IP, and a full table refuses new sources by design (`crates/rustynet-relay/src/main.rs:1665`, `:1696-1700`), which one peer cannot reach without spoofing.
- **Must hold:** the relay keeps the same PID (its unit restarts on failure, so the PID check matters); `pre_auth_hellos_refused_total` rises (read over SSH from the loopback-only `/metrics`), with a stated allowance for UDP loss or a paced flood; `active_sessions` does not rise.
- **Positive control:** a second, non-flooding node sends at most 10 unsigned hellos during the flood. The relay journal shows `session rejected from <probe_ip>` for them (the post-limiter path) and no `rate limited from <probe_ip>` line, while the flood source does show the rate-limited line. A rate-limit reply and a bad-token reply are the same generic reject on the wire (`main.rs:1869`, `:1925-1930`), so the verdict reads the relay's journal, not the reply bytes.

## The bar every stage meets

- **Fail closed.** A stage that is elected never skips silently. A missing topology, tool or artifact fails the stage, or is a reported skip that carries its own artifact.
- **No vacuous passes.** Each verdict reads the node's own evidence (status lines, metrics, ledger contents, PIDs), and each stage has a positive control, so a stage that attacked nothing, or a target that was already dead, cannot pass (`LiveLabCoverageGapAudit_2026-09-27.md` section 5).
- **Witness on pass** (QH-83): a pass writes its evidence line and artifact, and a failed write fails the stage.
- **Behavioural tests** that fail against a plausible wrong implementation.
- **Placement.** The floods are disruptive, so they are opt-in, like the negative-control suite. They run after the core live suite and restore anything they change.
- **Bounded attacks.** Every attack is bounded in size and duration, and afterwards the target's liveness is proved by an IPC or protocol round trip, not by `systemctl is-active`.
- **A breach is a product finding.** If the product fails a verdict, the lane stops and reports it. A verdict is never loosened to make the product pass.
- **No count-delta verdicts on journal lines or on anything the product legitimately purges.** Diff contents instead.
- **Scope.** Harness code only (`crates/rustynet-cli`, feature `vm-lab`). No product change, no new dependency (ADR-027), no C.
- **Gates.** Each lane runs the Linux leg (clippy, tests) on the lab box; landing runs the full gate set.

## Order

S1 and S3 first, in parallel; S2 starts with its design lane; S4 last (the relay already has an on-node limiter audit and unit tests). Each stage needs a live run on katana before its pass is counted.

## Review

An independent Claude reviewer found the first draft SOUND WITH CORRECTIONS. All corrections are applied above, and the manager spot-checked the cited code (the rotation CLI and `RotateApprover`, the generic reject, the listener budgets, and the chaos binary's scope note):
- Owner-key rotation has a product path, so the first draft's stop condition would have fired wrongly.
- Revocation propagation is not witnessed live either, so it joins S1.
- SignedMembership role transitions outrank the relay flood, so they become S2.
- The first draft's relay positive control could not be distinguished on the wire, and its source-cap goal was unreachable and contradicted the positive control.
- The enrollment listener has no connection limit and runs inline, so slow clients are capped and parser attacks stay on loopback.
- The bar gains bounded attacks, liveness by round trip, product findings reported rather than papered over, and no count-delta verdicts.
