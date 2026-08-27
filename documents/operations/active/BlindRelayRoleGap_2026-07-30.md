# UNBUILT ROLE — `blind_relay` — raised 2026-07-30

**Status: DESIGN PROPOSED; NOT ACCEPTED OR IMPLEMENTED.** The detailed design is
[BlindRelayRoleDesign_2026-08-27.md](./BlindRelayRoleDesign_2026-08-27.md).
This gap record remains the origin/history of the request; the design document
is authoritative for proposed semantics and explicitly marks unresolved choices.

## What is here today

No implementation. The original 2026-07-30 search found zero hits. Re-verified
before the design was written on 2026-08-27: a case-insensitive search for
`blind_relay` / `blind-relay` / "blind relay" found seven hits, all prose in
this gap record and its active index entry, and no implementation hit in
`crates/`, `scripts/`, or `third_party/`. This is a genuinely new role, not a
partially-built one.

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

## Why implementation remains unstarted

The proposed design now defines "blind" narrowly as concealment of stable
Rustynet endpoint identities from the relay, while explicitly admitting that a
single relay sees both socket legs and traffic metadata. Implementation remains
gated on acceptance, protocol/encoding and proof-of-possession choices,
security review, per-OS enforcement paths, and named verification. The role
must not be inferred from this historical gap summary; use the linked design.

## What must be decided before any code

1. **Privacy property:** proposed as relay-host concealment of stable Rustynet
   endpoint identities, not concealment of IP/timing/volume or the unavoidable
   same-circuit leg association.
2. **Capability relationship:** proposed `BlindRelay` modifier requiring
   `RelayHost`, plus a dedicated local primary/preset to avoid admin co-location.
3. **Reducer invariants:** proposed exact set `{RelayHost, BlindRelay}`; every
   other present or future capability is denied unless a reviewed amendment
   changes the allowlist.
4. **Reversibility:** proposed reversible through mandatory drain, stop, purge,
   residue verification, and signed transition ordering; not factory reset,
   avoiding an unsupported ENR-06-style irreversible typo hazard.
5. **Session-token interaction — the sharpest one:** token/hello v1 names and
   repeats the explicit `node_id`/`peer_node_id` pair. The proposed role therefore
   requires identity-free, opaque per-circuit/per-leg, proof-of-possession v2
   authorization and rejects v1 without fallback. The old statement that the
   relay "verifies only the signature" is stale: current transport also checks
   TTL/freshness/future date, self-pair, replay, hello/token/relay/scope bindings,
   and capacity. It still delegates membership/pair policy to the signed issuer.

## Scope estimate

Large and intentionally unestimated until the OPEN protocol choices are closed.
The surface includes role/capability enums and parsers, exact membership reducer,
preset/local-role and transition side effects, signed fleet v2, token/hello v2,
issuer and client changes, relay runtime/state/telemetry, one hardened platform
path plus verifier per OS, adversarial live-lab stages, migration/anti-rollback,
and eventually cross-platform parity rows. See the design's §14 dependency order.

## Where this must not get lost

- Indexed in `documents/operations/active/README.md`.
- Belongs in the release-blocking completeness mandate
  (`CrossPlatformRoleParityPlan_2026-06-21.md`) once the design is accepted: that
  document requires **every node role + capability** to be live-proven on macOS
  and Windows as well as Linux, so a new role widens that matrix by a row per OS.
  It is deliberately **not** added there yet — adding an unaccepted role to a
  completeness matrix would make the matrix lie about what is outstanding.
