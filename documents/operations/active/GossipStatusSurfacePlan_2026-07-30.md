# Gossip status surface — make the gossip data plane observable

**Status:** plan, revision 2 — corrected after adversarial review (premise upheld, nine corrections folded in). Implements item **7** of
`I4EnforcementFlipPlan_2026-07-30.md` §4, which the adversarial review called a
**ship-blocker, not a nice-to-have**.
**Precedence:** CLAUDE.md §3/§4. This change is **read-only observability** — it
adds no enforcement, no trust decision, and no new state.

---

## 1. Why this first

Every other item in the I4 scope is a trust-sensitive change to a path that
programs endpoints. This one is not: it exposes counters that already exist.
That makes it the only item in that list which is **safe to build before the
design questions are settled**, and it is a prerequisite for diagnosing the
others.

Concretely: the gossip node maintains `accepted_count` (`gossip_runtime.rs:245`)
and `rejected_counts` (`:242`, bumped at `:727`) — including the
`origin_rate_limited` counter landed in `021c1ef0`. **Neither has a production
reader.** Grep returns only tests. So today:

- A node whose gossip is being rate-limited looks identical to a healthy one.
- A node rejecting every bundle as `revoked_source`, `unknown_source`,
  `epoch_outside_window` or `stale` looks identical to a node receiving nothing.
- Whether the transport ever bound is invisible.

The lab consequence is concrete: `xnet2`'s `fedora-x86-1` sat in
`restriction_mode=Permanent` and the *traversal* alarm surfaced the reason. Had
the fault been in gossip instead, there would have been nothing to read.

## 2. Scope

Extend the **`IpcCommand::Status` line** (`daemon.rs:7872`) — the surface
`rustynet status` prints and the live-lab validators parse. Do **not** extend the
`netcheck:` log line (`daemon.rs:6088`); it is already 70+ fields and is a log,
not a queryable surface.

### 2.1 Fields

All derived from state that already exists. Names follow the existing
`snake_case` `key=value` convention.

| Field | Source | Meaning |
| --- | --- | --- |
| `gossip_state` | **reuse `gossip_mint_attached()` (`daemon.rs:5606-5608`)** — its doc says any second predicate must mirror it exactly; do not fork it | `unconfigured` / `attached_pending_transport` / `active` |
| `gossip_accepted_total` | `accepted_count` | bundles accepted since start |
| `gossip_rejected_total` | sum of `rejected_counts` | bundles rejected since start |
| `gossip_reject_reasons` | `rejected_counts` | compact **`kind=count`** list, `,`-joined, sorted by kind for determinism; `none` when empty. **NOT `kind:count`** — see §4.4 |
| `gossip_peers_registered` | `peers.len()` | peers the node may accept from |
| `gossip_local_epoch` | **accessor `local_membership_epoch()` (`gossip_runtime.rs:356`)** — the field is deliberately private so the monotonic setter is the only mutation path | the I2 epoch bound; `none` before first verified commit |
| `gossip_minted_total` | `minted_count` (`gossip_runtime.rs:246`) | bundles this node has broadcast — the outbound half, equally unreadable today. A node that accepts but never mints is broken and would otherwise look healthy |
| `gossip_transport_error` | the bind-failure branch (`daemon.rs:5499`) | `none`, or the last bind error — see below |

**The middle state has two causes, and revision 1 modelled only one.** The
transport binds inside `sync_gossip_data_plane` (`daemon.rs:5493-5505`) and a
bind failure (EADDRINUSE on a restart race) is logged and retried — leaving
node=`Some`, transport=`None` **with membership already committed**. Calling that
`awaiting_membership` would mislabel exactly the persistent fault this surface
exists to expose, and would contradict the sibling field: because
`set_local_membership_epoch` runs at `:5492`, *before* the bind, the pair
`gossip_local_epoch=<n>` + `awaiting_membership` is logically impossible.
Hence the neutral `attached_pending_transport` plus a separate
`gossip_transport_error`.

Platform note: the transport is `#[cfg(unix)]` and `validate_daemon_config`
rejects a gossip secret on non-unix (`daemon.rs:11346-11358`), so on Windows
`gossip_state` is permanently `unconfigured`. Worth stating given the parity
mandate.

### 2.2 Privacy constraint — binding

`daemon.rs:8334-8337` states the retention policy: an ingest string **MUST NOT**
include the bundle's candidate list, only the 8-byte source prefix and the error
variant name.

This plan is stricter and simpler: **no addresses and no node ids at all.**
Counts, state names, and reject-reason *kinds* only. `rejected_counts` is keyed
by `&'static str` kind (`gossip_runtime.rs:727`), never by peer, so this is
satisfied by construction rather than by remembering to redact.

## 3. Non-goals, stated so they are not smuggled in

- **No enforcement change.** Nothing about what is accepted, programmed, or
  rejected changes. If this commit alters a trust decision, it is wrong.
- **No new state.** Only reads existing fields. No counters added, no
  persistence, no watermark interaction.
- **Not the I4 three-state disposition.** That design is withdrawn; this surface
  must not presume it returns.

## 4. Risks

1. **The status line is parsed by tooling.** Live-lab validators split on
   whitespace and `=`. Appending fields is safe; **reordering or renaming
   existing ones is not.** Append only.
2. **`gossip_reject_reasons` is unbounded in principle.** Kinds are a closed set
   of `&'static str` literals, so in practice it is bounded by the number of
   error variants — but the formatter must not assume a maximum.
3. **Field-count drift.** Some validators assert an expected field count. Adding
   six fields could trip such a check; a test asserting the new fields are
   present is the mitigation, plus a grep for count-based assertions before
   landing.

## 5. Test plan — each with the mutation that must make it fail

| Test | Mutation that must make it fail |
| --- | --- |
| `status_reports_gossip_unconfigured_when_no_signing_secret` | report `active` when the node is absent — the "is it even on?" question answered wrongly |
| `status_reports_gossip_awaiting_membership_before_transport_binds` | collapse `awaiting_membership` into `active` |
| `status_reports_gossip_accept_and_reject_totals` | hardcode zeros |
| `status_reports_reject_reasons_including_rate_limited` | omit `rejected_counts` — the `021c1ef0` limiter stays invisible |
| `status_reject_reasons_are_deterministically_ordered` | iterate the `HashMap` directly — flaky output, unparseable by tooling |
| `status_gossip_fields_contain_no_addresses_or_node_ids` | interpolate a peer id or endpoint — **the §2.2 privacy pin** |
| `status_line_appends_gossip_fields_without_reordering_existing_ones` | insert mid-line — breaks the validators in §4.1 |

## 6. Acceptance

`rustynet status` on a lab guest reports `gossip_state`, and on a node with
gossip configured the accept/reject totals move under real traffic. A
rate-limited origin is visible as a non-zero `origin_rate_limited` in
`gossip_reject_reasons` — the specific thing that is invisible today.
