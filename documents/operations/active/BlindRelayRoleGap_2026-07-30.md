# UNBUILT ROLE — `blind_relay` — raised 2026-07-30

**Status: NOT STARTED. Not designed, not specced, not written.** Raised by the
operator so it is not lost; this file exists to be found later, not to design
the thing.

## What is here today

Nothing. Verified 2026-07-30: a case-insensitive search for `blind_relay` /
`blind-relay` / "blind relay" across `crates/` and `documents/` returns **zero
hits**. This is a genuinely new role, not a partially-built one.

The nearest existing thing — and the obvious model — is `blind_exit`:

- `RoleCapability::BlindExit` (`crates/rustynet-control/src/roles.rs:10`), parsed
  from `blind_exit` / `blind-exit` (`:57`), rendered `blind_exit` (`:38`).
- Reducer-enforced invariants: `BlindExit` requires `ExitServer`, and
  `BlindExit` may **not** be combined with `Anchor` or any anchor sub-capability
  (`rustynet-control/src/membership.rs`, `validate_membership_node_capabilities`).
- Irreversible by design: a `blind_exit` transition requires a factory reset
  (CLAUDE.md §10.7), which is why a `--roles blind_exit` typo at admit is filed
  as ENR-06.
- Dataplane + verifier: `rustynetd/src/linux_blind_exit.rs`,
  `macos_blind_exit.rs`, and the `linux_blind_exit_dataplane` live-lab stage.

## Why it is being recorded rather than started

The role's *meaning* has not been defined. "Blind" for the exit role means the
exit cannot associate traffic with the originating node. What the equivalent
property is for a **relay** — and whether it is the same property, a weaker one,
or a different one entirely — is an open design question, not an implementation
detail. Guessing it here would be worse than leaving it blank.

## What must be decided before any code

1. **The privacy property, stated precisely.** What must a `blind_relay` be
   unable to learn or correlate? Frame it as a property an adversary cannot
   violate, not as a list of fields to omit.
2. **Relationship to `RelayHost` / `EntryRelay`.** Is `blind_relay` a
   *modifier* on an existing relay capability (as `BlindExit` modifies
   `ExitServer`, requiring it), or a distinct capability? The `BlindExit`
   precedent argues for a modifier with a required base.
3. **Reducer invariants.** Which combinations must be refused? `BlindExit`'s
   anchor-exclusion exists because an anchor sees control-plane state that
   defeats blindness; the same question applies here and probably has the same
   answer.
4. **Reversibility.** `blind_exit` is irreversible and needs a factory reset.
   Is `blind_relay` the same? If yes, it inherits ENR-06's typo hazard and needs
   the same confirmation gate.
5. **Session-token interaction — the sharpest one.** Relay forwarding is
   authorized by `RelaySessionToken`, which names an explicit
   `node_id`/`peer_node_id` **pair** (`rustynet-control/src/lib.rs:1691-1701`),
   and the relay verifies only the signature
   (`rustynet-relay/src/transport.rs:395`). **A relay therefore already learns
   exactly which two nodes a session is between.** Any blindness property has to
   confront that directly — it may require changing the token shape, which is a
   signed wire format and therefore expensive to change later. **This is the
   reason to decide the design before more relay work lands, not after.**

## Scope estimate

Unknown, deliberately. By analogy with `blind_exit` it touches: the role enum
and parser, membership reducer invariants, role-transition side-effects
(CLAUDE.md §10.7), a platform dataplane path per OS, a verifier, a live-lab
stage, and the cross-platform parity matrix. That analogy is a floor, not an
estimate — item 5 above could make it materially larger.

## Where this must not get lost

- Indexed in `documents/operations/active/README.md`.
- Belongs in the release-blocking completeness mandate
  (`CrossPlatformRoleParityPlan_2026-07-21.md`) once the role is defined: that
  document requires **every node role + capability** to be live-proven on macOS
  and Windows as well as Linux, so a new role widens that matrix by a row per OS.
  It is deliberately **not** added there yet — adding an undefined role to a
  completeness matrix would make the matrix lie about what is outstanding.
