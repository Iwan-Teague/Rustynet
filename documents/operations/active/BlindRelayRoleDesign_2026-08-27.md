# `blind_relay` role design — identity-blind single-hop relay

**Status:** DESIGN ONLY — proposed 2026-08-27; not yet accepted, implemented,
or live-proven. No code, schema, platform claim, evidence date, or release claim is
created by this document.

**Decision owner:** Rustynet security/architecture maintainers.

**Implementation gate:** Do not implement the role until the open protocol
choices in §16 are resolved, this design is security-reviewed, and the signed
wire-format change is approved. Do not add `blind_relay` to
`CrossPlatformRoleParityPlan_2026-06-21.md` until that acceptance occurs.

## 0. Executive decision record

This design gives “blind” one narrow, falsifiable meaning:

> A `blind_relay` does not receive stable Rustynet endpoint identities or
> membership records in its session protocol and cannot derive the Rustynet
> identity pair from Rustynet artifacts available on the relay host. It still
> sees, and must associate, the two network legs of each circuit. It also sees
> source IP addresses, ports, timing, packet sizes, volume, and duration.

The selected architecture is:

1. Add an append-only signed `BlindRelay` **modifier capability** that requires
   `RelayHost`.
2. Expose a distinct user-facing `blind_relay` preset and dedicated local
   `BlindRelay` primary/daemon role. It is not an `Admin` node with another
   checkbox.
3. Permit exactly the signed capability set `{RelayHost, BlindRelay}`. Exclude
   client, entry-relay, exit, blind-exit, anchor, anchor sub-capabilities, and
   application-service capabilities.
4. Make transitions reversible, but only through an ordered privacy-boundary
   reinitialization that drains circuits, stops service, purges ephemeral
   state, verifies residue absence, and then changes signed membership.
   Failure leaves the relay stopped and the old role authoritative.
5. Replace identity-bearing relay token/hello v1 for this role with an
   identity-free, proof-of-possession token/hello v2. A blind relay accepts v2
   only. There is no v1 fallback, translation, or dual-mode listener.
6. Keep authorization at the control-plane issuer: it validates the exact
   active endpoint pair under signed policy, then atomically mints two opaque,
   per-circuit leg authorizations. The relay validates those capabilities but
   never receives the endpoint identities used to authorize them.
7. Use one hardened runtime per OS, a dedicated service identity, aggregate-only
   telemetry, bounded state, persistent anti-rollback state, explicit verifiers,
   and adversarial live-lab proof before any OS is called supported.

This is **identity-pair concealment**, not traffic-flow anonymity. A single
forwarding relay necessarily knows which two observed socket legs belong to the
same circuit. Hiding that association requires a different split-trust,
multi-relay design and is a non-goal here.

## 1. Authority, repository facts, and correction to the gap record

### 1.1 Governing documents

This proposal follows the repository precedence order:

1. `documents/Requirements.md`;
2. `documents/SecurityMinimumBar.md`;
3. active role/taxonomy and operating documents.

The design therefore assumes signed state is verified before use, unknown or
stale state is denied, replay and rollback are rejected, security-sensitive
transitions are auditable, cryptography is taken from reviewed primitives, and
the backend boundary stays unchanged.

### 1.2 Current implementation facts re-verified 2026-08-27

- Before this design was added, a case-insensitive repository search found
  seven `blind_relay`/`blind-relay`/“blind relay” hits, all prose in the gap
  record and its active index entry. There was no implementation hit in
  `crates/`, `scripts/`, or `third_party/`.
- `RoleCapability` is defined in
  `crates/rustynet-control/src/roles.rs:6`. Its derived order contributes to a
  signed canonical preimage; new variants must append, never reorder existing
  variants.
- Membership capability validation is called from signed membership validation
  at `crates/rustynet-control/src/membership.rs:251`; the central reducer is
  `validate_membership_node_capabilities` at `:2626`.
- Presets and local primary roles are separate axes in
  `crates/rustynet-control/src/role_presets.rs:34` and `:134`. The daemon mirrors
  the local role at `crates/rustynetd/src/daemon.rs:1503`.
- The current `RelaySessionToken` at
  `crates/rustynet-control/src/lib.rs:1751` signs plaintext `node_id` and
  `peer_node_id`. Its v1 canonical payload explicitly says that changing the
  format is breaking (`:1945` at the time of this review).
- The current `RelayHello` also repeats those identities, and the relay stores
  and indexes them while pairing reciprocal sessions
  (`crates/rustynet-relay/src/transport.rs:153`, `:332-375`). Token v1 therefore
  cannot satisfy this design's privacy property.
- The signed relay-fleet descriptor at
  `crates/rustynet-control/src/lib.rs:1516` carries endpoint, region, priority,
  capacity, and enabled state, but no protocol or privacy-mode capability. Its
  accepted signed wire version is 1.
- The daemon already has a persistent relay-fleet watermark path
  (`crates/rustynetd/src/daemon.rs:273`). The migration should extend that
  mechanism rather than invent an unrelated rollback store.

### 1.3 Correction: “the relay verifies only the signature” is stale

The 2026-07-30 gap record accurately identified the plaintext identity leak but
overstated the relay's missing checks. Current
`crates/rustynet-relay/src/transport.rs:382` also enforces the hello rate limit,
TTL, expiry, future-dating, self-pair rejection, replay nonce, constant-time
hello/token field bindings, relay binding, exact scope, global capacity, and
per-node capacity. Replay-store or clock failure rejects the hello.

What remains true is narrower: the relay does not independently evaluate
membership or pair policy. It trusts the signed token issuer to have done so.
Token v2 preserves that trust boundary because giving membership identities to
the blind relay would defeat the privacy goal. It strengthens the relay-side
authorization with an identity-free audience, scope, epoch, pair structure,
proof of possession, freshness, replay prevention, and fixed privacy profile.

## 2. Goals, non-goals, and terminology

### 2.1 Goals

- Conceal stable Rustynet node identities and the Rustynet identity pair from a
  relay operator, a compromised relay service, and a later forensic inspection
  of relay-owned state.
- Preserve the existing ciphertext-only forwarding boundary. A relay must not
  terminate WireGuard or receive inner packet plaintext.
- Keep exact pair authorization default-deny at the signed control plane without
  disclosing that pair to the relay.
- Make every protocol, reducer, transition, operating-system, and observability
  failure state explicit and fail closed.
- Avoid bearer-token theft, replay, downgrade, ambiguous parsing, mixed-mode
  fallback, role co-location, and unbounded resource consumption.
- Give users an honest, comprehensible status surface and predictable transition
  behavior.
- Preserve ordinary relay v1 during a bounded mixed-fleet migration without
  representing it as blind.

### 2.2 Non-goals

- Hiding the relay's own public identity or network endpoint.
- Hiding client source IP addresses, source ports, address family, coarse
  geography, connection timing, packet length, packet count, volume, duration,
  loss, or availability.
- Preventing the relay from knowing that two socket legs are paired in one
  circuit. Forwarding requires that short-lived association.
- Defeating an observer that combines relay traffic with endpoint traffic,
  ISP records, distinctive timing/volume, or external IP-to-person data.
- Protecting identity if the control-plane issuer or either endpoint is
  compromised or colludes with the relay.
- Providing anonymity against global passive observation, website fingerprinting,
  traffic confirmation, intersection attacks, or denial of service.
- Creating a new VPN, onion-routing, anonymous-credential, or cryptographic
  protocol. A stronger two-relay profile is separate future work.
- Erasing facts already learned by a node while it previously operated as a
  normal relay, or erasing external logs/backups not controlled by Rustynet.
- Claiming that memory scanning proves absence in all executions. Schema proof,
  dataflow review, negative tests, canaries, and live inspection are combined;
  none is presented as magical proof.

### 2.3 Terms

- **Stable Rustynet identity:** node ID, membership record, WireGuard public key,
  gossip identity, enrollment identity, hostname/label, or another identifier
  intended to persist across circuits.
- **Circuit:** one authorized, short-lived forwarding relationship between two
  endpoint legs through one relay.
- **Leg:** one endpoint-to-relay half of a circuit.
- **Opaque handle:** CSPRNG-generated value with no encoded identity and no reuse
  across circuits.
- **Privacy epoch:** signed, monotonically increasing generation that binds the
  blind protocol posture and prevents rollback to a weaker accepted profile.
- **Residue:** token, handle, address mapping, packet metadata, replay state,
  log, crash dump, spool entry, or configuration left after its allowed lifetime
  or a role transition.

## 3. Privacy contract and threat model

### 3.1 Named adversary

The primary adversary is **R**, the operator of the selected `blind_relay`, or
an attacker with root/administrator access to that relay host. R may inspect:

- relay process memory and crash artifacts;
- relay-owned files, journals, event logs, metrics, and audit records;
- relay configuration and service-manager state;
- all token and hello bytes delivered to the relay;
- all ciphertext frames and their network tuples, timing, size, and direction;
- state retained after restart or role transition.

R may modify or restart the relay and may send malformed, replayed, downgraded,
or resource-exhausting protocol inputs. R does **not** control the signed
control-plane issuer, an endpoint, the pinned issuer verification key, or the
reviewed cryptographic primitives. R may have outside information, but the core
property below deliberately separates protocol identity concealment from what
IP/timing side information can reveal.

### 3.2 Falsifiable privacy property BR-P1

For every accepted blind circuit between endpoints A and B:

1. No relay-consumed wire schema, relay runtime object, relay index key,
   relay-owned persistent artifact, default log, metric label, or audit field
   contains a stable Rustynet identity for A or B, a membership record for A or
   B, or a deterministic transform of one.
2. The only protocol join between the legs is a fresh random circuit handle and
   complementary leg slots. Leg and circuit handles are never reused across
   circuits and are not derivable from endpoint identities.
3. Given Rustynet-created artifacts available only on the relay host, R has no
   deterministic mapping from either leg or the circuit to A's or B's stable
   Rustynet identity. The token issuer's authorization database is not a relay
   artifact.
4. Cross-circuit equality of protocol fields does not reveal that the same
   Rustynet endpoint participated twice, except for public fleet/profile fields
   shared by the anonymity set and unavoidable network metadata.

BR-P1 is falsified by one stable identity in a relay schema/artifact, one
identity-derived handle, one reused endpoint handle, one default per-circuit
telemetry label, or one successful protocol downgrade that restores v1 identity
fields. Tests can plant unique identity canaries and inspect capture, memory,
filesystem, journal, crash, and telemetry surfaces; schema/dataflow review must
also prove that such fields have no relay-side source.

### 3.3 Explicit residual observation BR-R1

R necessarily observes two source socket tuples and associates them for the
life of one circuit. R also observes traffic timing, direction, sizes, counts,
volume, and duration. These may identify or correlate users using external
knowledge even when BR-P1 holds. Product text must state this; it must never say
“anonymous,” “untraceable,” or “the relay cannot tell who is communicating.”

The accurate user phrase is:

> Identity-blind relay: Rustynet node IDs are hidden from the relay. The relay
> still sees both network connections and traffic metadata.

### 3.4 Why single-hop is the boundary

A relay cannot forward a packet without selecting the other leg, so eliminating
same-circuit leg association at one relay is architecturally impossible. A
stronger property would split knowledge between independently operated hops:
one hop sees the incoming address but not the final outgoing leg, while another
sees the outgoing leg but not the incoming address. That requires an explicit
non-collusion assumption, separate connections/contexts, new routing and abuse
controls, and different performance/availability analysis. It is not silently
smuggled into this role.

This separation follows the architectural lesson in the Privacy Pass and
privacy-partitioning standards: unlinkability depends on context separation and
non-collusion, while IP and timing can partition the anonymity set. See RFC 9576
and RFC 9614 in §18.

## 4. Role model: modifier in signed state, dedicated local execution role

### 4.1 Signed capability decision

Append `RoleCapability::BlindRelay` after all existing variants. Its stable text
is `blind_relay`; the parser may accept `blind-relay` as an input alias, while
canonical serialization emits only `blind_relay`.

`BlindRelay` is a **modifier**, not a standalone forwarding capability:

```text
BlindRelay => requires RelayHost
```

This mirrors the useful part of the `BlindExit => ExitServer` precedent. Policy
queries can ask “can relay?” using `RelayHost` and “under which posture?” using
`BlindRelay`, without inventing two unrelated service capability families.

The variant must append because `RoleCapability`'s derived ordering feeds signed
membership canonicalization. Existing variants are never reordered. Parser,
renderer, canonical-order fixtures, unknown-value rejection, and signed
preimage fixtures change together.

### 4.2 User-facing and local execution decision

Add:

- `RolePreset::BlindRelay` with stable text `blind_relay`;
- `PrimaryRole::BlindRelay` in `rustynet-control`;
- matching `NodeRole::BlindRelay` in `rustynetd`;
- preset capability `Capability::BlindRelay` alongside `ServesRelay`;
- composition: primary `BlindRelay`, capabilities
  `[ServesRelay, BlindRelay]`;
- membership projection: exactly `[RelayHost, BlindRelay]`.

The signed concept remains a modifier, but the local execution role is distinct.
Running blind relay under the unrestricted `Admin` primary would co-locate broad
IPC, membership, anchor, route-management, and operational surfaces with the
service that is meant not to receive identity state. A dedicated primary gives
the daemon a small command allowlist and lets startup reject identity-bearing
configuration before the relay is spawned.

### 4.3 Entry relay is different

`EntryRelay` describes a client-side traversal/entry function and currently
requires `Client`. It is not the base for this role. Combining `EntryRelay` with
`BlindRelay` would make the same host both an endpoint-side participant and an
identity-blind forwarding service, collapsing the boundary. The reducer rejects
the combination.

## 5. Reducer invariants and signed-state semantics

### 5.1 Exact accepted capability set

For an active member carrying `BlindRelay`, the canonical set must be exactly:

```text
{ RelayHost, BlindRelay }
```

The reducer rejects `BlindRelay`:

- without `RelayHost`;
- with `Client` or `EntryRelay`;
- with `ExitServer` or `BlindExit`;
- with `Anchor`;
- with any anchor sub-capability, including gossip seed, bundle pull,
  enrollment endpoint, relay co-location, port-mapping authority, or pinned
  port-mapping preference;
- with `ServesNas` or `ServesLlm`;
- with any future capability unless that combination receives an explicit
  design amendment and a negative-test update.

“Reject future capability by default” matters. A list of currently forbidden
values would silently become permissive when a new capability is appended.
Validation should compare the full canonical set to the exact allowlist.

### 5.2 Where validation must happen

The invariant is enforced independently at:

1. signed membership construction and state validation;
2. membership reducer transition validation before commit;
3. daemon local-role/membership alignment before any relay service start;
4. assignment/application paths before local side effects;
5. relay fleet publication before advertising the node as blind;
6. startup/restart reconciliation before opening a listener.

A permissive warning is forbidden. In particular, the existing `BlindExit`
warn-and-continue exception in `validate_node_role_membership_alignment` is not
a precedent for `BlindRelay`. Missing `RelayHost` or `BlindRelay`, an extra
capability, missing local role, stale membership, or failed verification keeps
the listener closed.

### 5.3 Revocation and deactivation

Revocation, suspension, or removal makes the relay ineligible immediately at
the signed-state consumer. The control plane stops minting token pairs and
removes/disables the descriptor in the next signed fleet generation. The relay
must also stop accepting new circuits when its locally verified membership no
longer authorizes the exact role. Existing circuits are dropped, not allowed to
run until token expiry, because role authorization has been withdrawn.

If the relay cannot refresh signed membership or fleet state before freshness
expires, it closes admission and drains/drops existing circuits according to a
short fixed grace bounded by the already-issued token expiry. For explicit
revocation there is no grace.

## 6. Reversibility and role-transition state machine

### 6.1 Decision: reversible, but privacy-boundary reinitialization is mandatory

`blind_relay` is **not** factory-reset-irreversible. Unlike `blind_exit`, its
property is enforced by the current session protocol, isolated runtime, and
absence of identity-bearing inputs. Changing away from it does not require a
fresh node identity to preserve the truth of past blind epochs.

Factory reset would add the ENR-06 typo hazard without closing an identified
privacy gap. However, role entry and exit materially change the privacy posture,
so both require:

- owner-authorized signed membership change;
- typed user acknowledgement showing the before/after disclosure model;
- a new random privacy epoch/circuit namespace at entry;
- ordered service teardown/deploy and residue verification;
- an audit event containing role, direction, result, signed state generation,
  software version, and aggregate residue verdict, but no session handles or
  endpoint identities learned during blind operation.

### 6.2 Entering `blind_relay`

State sequence:

```text
NormalRole
  -> EnterRequested
  -> NormalRelayUnadvertised
  -> NormalRelayStopped
  -> IdentityBearingRelayStatePurged
  -> BlindRuntimeInstalledAndVerified
  -> SignedBlindCapabilityCommitted
  -> BlindDescriptorPublished
  -> BlindServing
```

Ordering rules:

1. Stop issuing normal-relay tokens and publish a signed normal-relay disable.
2. Drain for a bounded operator-visible period; at deadline forcibly drop every
   remaining normal circuit.
3. Close listeners and stop the normal service before signed blind capability
   becomes effective.
4. Purge v1 tokens, identity-keyed session indexes, spools, logs, crash dumps,
   replay state, and normal-relay configuration under Rustynet's control.
5. Install the dedicated service identity, firewall, storage, logging, resource
   limits, v2-only binary/configuration, and fresh privacy epoch.
6. Run the local platform verifier. It must prove the normal listener is absent,
   only the v2 blind listener is enabled, identity-bearing inputs are not
   mounted/readable, and required isolation is active.
7. Commit/apply the signed exact capability set.
8. Publish the signed v2 blind fleet descriptor only after membership and local
   verifier both pass.
9. Open admission only after re-reading and verifying all authoritative state.

Any failure at steps 1-9 leaves both relay listeners closed and prevents blind
advertisement. If the signed capability has already committed, the node remains
authorized-but-unavailable until repaired; it must never start a normal relay as
fallback.

### 6.3 Leaving `blind_relay`

State sequence:

```text
BlindServing
  -> BlindUnadvertised
  -> BlindDraining
  -> BlindStopped
  -> BlindEphemeralStatePurgedAndVerified
  -> SignedTargetRoleCommitted
  -> TargetRuntimeInstalledAndVerified
  -> TargetServing
```

Rules:

1. Disable the blind descriptor and stop new token issuance first.
2. Drain until the shorter of operator deadline or token expiry; then drop all
   circuits.
3. Close listeners and stop the service.
4. Purge circuit/leg handles, address mappings, proof-of-possession material,
   replay store, temporary telemetry, crash material, and privacy-epoch secrets.
5. Verify zero live sockets/processes, no blind firewall rule, no session state,
   and no relay-owned transient artifact beyond allowed aggregate audit data.
6. Only then remove `BlindRelay`/`RelayHost` or commit the exact target role.
7. Install and verify the target runtime before advertising target capability.

If teardown or purge verification fails, the signed blind role remains
authoritative, the relay stays off, and the transition reports a repairable
blocked state. It must not proceed to the target role. This is reversible
without pretending failed cleanup succeeded.

### 6.4 Crash and restart semantics

Every transition step is recorded in a crash-safe local journal containing no
session identity or opaque handles. Restart resumes toward the safest state:

- before blind advertisement: both relay modes off;
- during blind service teardown: blind admission off, finish purge;
- after blind signed-state removal but before target verification: both off;
- unknown/corrupt journal: both off, require signed-state reconciliation and a
  full residue verifier pass;
- missing secure persistence: role unavailable, never reconstruct a weaker
  privacy epoch from defaults.

## 7. Relay authorization protocol v2

### 7.1 Explicit token confrontation

This design selects prompt option **(b): change the token shape**.

- Keeping v1 unchanged cannot work: it signs `node_id` and `peer_node_id` and
  the hello repeats both.
- A mere transport wrapper cannot work: the relay must verify the signed v1
  contents and would still learn the pair.
- Calling the weaker property “blind” would be misleading because the stable
  identity pair is the sharp disclosure this role exists to remove.

The change is a new, versioned signed wire protocol. It does not mutate v1 in
place.

### 7.2 Authorization split

The control plane knows A and B because it must evaluate active membership and
signed pair policy. The blind relay does not need those identities. The issuer:

1. authenticates each requester over the existing secure control path;
2. verifies A and B are distinct, active, authorized to communicate, and
   eligible for the requested relay/profile;
3. verifies the selected descriptor is a current signed `blind_relay` and the
   clients support the required protocol/epoch;
4. atomically mints one two-leg authorization, or none;
5. delivers each leg token only to its intended endpoint over an authenticated,
   encrypted, endpoint-bound channel;
6. records policy/audit data at the control plane under its existing retention
   rules, never copies it into relay telemetry.

The relay validates the issuer signature and token capabilities. Independent
relay-side membership evaluation is deliberately impossible because it would
require the identity mapping BR-P1 forbids. A compromised issuer is outside the
privacy adversary but remains a security incident governed by existing signing
key and audit controls.

### 7.3 Proposed token v2 semantic fields

Names below are semantic; exact encoding remains an approval item in §16.

```text
BlindRelayLegTokenV2 {
  version = 2
  token_kind = "blind_relay_leg"
  audience_relay_id
  scope = "forward_ciphertext_only_blind"
  privacy_epoch
  circuit_handle        // fresh 256-bit CSPRNG value, shared by exactly 2 legs
  leg_handle            // fresh 256-bit CSPRNG value, unique to this leg
  leg_slot              // exactly 0 or 1
  presenter_public_key  // fresh per-circuit proof-of-possession key
  issued_at
  expires_at
  nonce                 // fresh per-token replay nonce
  profile_id            // coarse public, fleet-wide limits; no user tier
  issuer_key_id
  signature
}
```

Forbidden fields include node ID, peer node ID, WireGuard/gossip/enrollment
public key, membership index, hostname, account/user label, policy rule ID,
source/destination network, stable endpoint pseudonym, or an identity-derived
hash. Hashing a stable identity is not anonymization.

Constraints:

- `circuit_handle`, both `leg_handle`s, nonces, and presenter keys are generated
  with the repository-approved CSPRNG and never reused.
- Exactly two tokens share a circuit handle; they have different leg handles,
  complementary slots, the same relay audience, privacy epoch, scope, profile,
  and expiry window.
- TTL remains at most the current 120-second admission-token ceiling unless a
  separate review tightens it. Circuit lifetime is independently bounded and
  never extended by accepting an old token again.
- `profile_id` selects one small public set of uniform limits. Per-customer or
  per-node quota values would fingerprint users and are forbidden.
- Exact canonical parsing rejects duplicate, unknown, omitted, reordered where
  canonical order matters, overlong, invalid UTF-8, noncanonical numeric, and
  trailing fields before signature verification/application.
- Debug formatting redacts tokens and handles. Error messages use closed reason
  classes and never echo signed contents.

### 7.4 Proof of possession, not bearer authorization

Each endpoint creates a fresh presenter key for the circuit. The control-plane
request binds its public key into that leg's signed token. After inexpensive
source-address validation, the endpoint proves possession by signing a
domain-separated canonical transcript containing the token digest, relay
challenge/cookie, circuit handle, leg handle, slot, privacy epoch, and client
nonce. The relay verifies the signature against `presenter_public_key`.

This follows the standard proof-of-possession token pattern represented by the
`cnf` claim in RFC 8747; it does not require adopting CWT as the encoding. The
exact transcript, algorithm suite, key validation, and library must be selected
in security review. No handwritten signature scheme, custom curve operation,
or ad-hoc key derivation is allowed.

An endpoint never reuses the presenter key across circuits. Token delivery and
endpoint storage must prevent the peer from receiving the other endpoint's
token. Proof of possession limits a stolen token's usefulness; it does not hide
the source IP used to present it.

### 7.5 Hello v2 and admission order

`BlindRelayHelloV2` contains only the version, the leg token, a fresh client
nonce, a relay address-validation artifact, and the proof-of-possession
signature. It contains no separate node/peer identity.

Admission performs cheap checks before expensive/stateful ones:

1. bounded datagram/frame and exact v2 envelope parse;
2. per-source coarse pre-auth rate limit;
3. stateless source-address validation using a reviewed, rotating-key mechanism
   patterned after QUIC Retry; no session allocation yet;
4. issuer key ID allowlist and strict token signature verification;
5. version, kind, audience, scope, privacy epoch, profile, slot, and canonical
   field checks;
6. usable-clock, not-before/future-date, expiry, and TTL checks;
7. proof-of-possession transcript verification;
8. durable replay-store availability and nonce/leg replay rejection;
9. global, per-source-prefix, waiting-leg, and profile resource limits;
10. atomic nonce commit and bounded waiting-leg allocation.

Address validation is an anti-amplification/resource measure, not identity
authentication. The design should reuse a reviewed implementation or primitive;
it must not improvise cryptography. QUIC's warning also applies: validation
tokens must be short-lived and must not become stable linkability cookies.

### 7.6 Circuit pairing and forwarding

The relay maintains a bounded map keyed by `(privacy_epoch, circuit_handle)`:

```text
Absent -> Waiting(slot 0 | slot 1) -> Paired -> Draining -> Closed
                                \-> Quarantined/Closed on mismatch
```

- The first valid leg creates `Waiting` with its random leg handle, observed
  tuple, expiry, profile, and presenter key digest.
- A second leg pairs only if it has the same circuit handle, complementary slot,
  distinct leg handle/presenter key, and exactly matching signed public fields.
- A duplicate slot, third leg, mismatched profile/epoch/expiry/scope, self-same
  leg, replay, or state race closes/quarantines the attempted circuit and
  forwards nothing.
- Before pairing, data frames are dropped; no buffering of endpoint payloads.
- After pairing, only bounded ciphertext frames move byte-for-byte between the
  two bound tuples. The relay never parses inner packets and never originates
  endpoint payload.
- Tuple rebinding is denied by default. If mobility is later required, it needs
  a fresh address-validation exchange plus proof of the same presenter key and
  an explicit anti-hijack review; it is not inferred from packet arrival.
- Expiry, idle timeout, byte/packet ceiling, proof failure, replay-store failure,
  clock failure, resource pressure, role loss, or verifier failure closes the
  circuit.

The relay knows the paired tuples for this circuit. It stores no stable
Rustynet identifiers because none enter the protocol.

### 7.7 State and telemetry minimization

Allowed live per-leg state is limited to random handles, slot, observed/bound
tuple, public profile, monotonic timers, bounded counters, expiry, and the
presenter key/digest needed for the circuit. It exists in memory only, except
for the minimum replay data needed across restart.

Persistent replay entries are keyed by a one-way digest of
`(version, privacy_epoch, nonce, leg_handle)` using an approved primitive and a
rotating local key only if the reviewed replay-store design requires it. Raw
handles must not appear in ordinary logs. Rotation cannot shorten replay
retention below token validity plus allowed skew.

Default observability is aggregate by relay, protocol version, coarse rejection
class, and public profile. Forbidden labels/events include source IP, exact
prefix, circuit/leg/token/nonce, presenter key, or high-cardinality timestamp.
Packet capture and verbose per-circuit debugging are disabled in production and
require a time-bounded, owner-approved incident mode whose UI explicitly says it
weakens metadata privacy. Even incident mode cannot reveal stable Rustynet IDs
because the relay never receives them.

## 8. Version negotiation, mixed fleet, replay, and anti-rollback

### 8.1 Versioned artifacts

The migration changes three signed/wire surfaces, each with an unambiguous
leading version and separate canonical serializer/parser:

1. relay fleet bundle v2;
2. blind relay leg token v2;
3. relay hello/control envelope v2.

Fleet v2 descriptors add at least:

```text
relay_mode = normal | identity_blind
hello_versions
token_versions
minimum_privacy_epoch
profile_ids
```

The fleet bundle also adds a monotonic signed `generation` and binds its schema
version. A v1 descriptor can describe only a normal relay. Absence of a mode,
protocol list, or epoch never means blind by inference.

### 8.2 Negotiation rules

- A privacy-required client selects only a verified, fresh descriptor with
  `relay_mode=identity_blind`, hello/token v2, an accepted profile, and an epoch
  at or above its persisted minimum.
- A `blind_relay` listener accepts exactly hello/token v2 and the configured
  current privacy epoch window. It rejects v1 and unknown versions before
  session allocation.
- No version is negotiated inside an unauthenticated “best common version” that
  an attacker can strip. The client's selection is bound to the signed fleet
  descriptor; the token binds the chosen version/mode/epoch and relay audience.
- Privacy-required mode never falls back to a normal relay, token v1, a lower
  epoch, or “direct” if the user/policy requires relay privacy. It reports
  unavailable.
- A normal-relay request may continue using v1 during migration, but UI and
  policy must never label that session blind.
- A physical blind-role node exposes no normal-relay listener or descriptor.
  Separate port numbers alone are not sufficient isolation; role exclusivity is
  enforced in signed state and process configuration.

### 8.3 Mixed-fleet rollout

1. **Prepare:** implement parsers/verifiers, v2 issuer path, persistent
   watermarks, endpoint PoP, blind runtime, negative tests, and disabled-by-default
   platform paths. Continue publishing only v1 normal fleet.
2. **Dual publication:** publish distinct signed v1-normal and v2-capable fleet
   artifacts at distinct authenticated paths/content types. Updated clients can
   consume both; old clients continue to consume v1. Blind descriptors appear
   only in v2.
3. **Canary:** enable one non-production blind relay and v2 issuer for explicit
   test policy. Privacy-required clients have no fallback. Prove protocol and
   residue gates.
4. **Fleet expansion:** enable accepted OS cells gradually. Normal v1 relays
   remain available for clients not requesting blind service.
5. **Deprecation:** after an explicit compatibility window and fleet telemetry,
   stop issuing new v1 normal tokens. Drain v1 sessions. Remove v1 publication
   only by a separately approved release decision.

There is no v1-to-v2 token translation. Tokens are reissued from current signed
policy. A v1 session is drained as v1; it does not become blind mid-session.

### 8.4 Persistent anti-rollback and anti-fork rules

Extend the existing relay-fleet watermark mechanism to persist atomically:

- highest accepted fleet schema version;
- highest signed fleet generation;
- digest for that generation (same generation, different digest = fork);
- highest accepted privacy epoch per relay identity;
- minimum accepted hello/token version for privacy-required mode;
- issuer key generation/key IDs required by current signed policy.

Acceptance rules:

- lower version, generation, or privacy epoch: reject;
- same generation with different canonical digest: reject and surface incident;
- missing/corrupt/unreadable watermark after prior initialization: blind service
  unavailable; do not TOFU-reset silently;
- newer unknown schema/version: reject, not partially parse;
- atomic persistence failure: do not apply or advertise the newer state;
- clock unavailable or signed fleet stale/future-dated: no blind selection or
  admission.

Factory reset or explicit security-state reset is the only watermark reset
boundary. It requires typed owner confirmation and fresh signed bootstrap. A
software downgrade that cannot understand the persisted minimum cannot run the
blind service.

### 8.5 Replay namespaces and cutover

Replay keys include protocol version and privacy epoch. v1 and v2 never share a
namespace. A v2 replay entry survives process restart for at least token TTL,
allowed clock skew, and persistence margin. The issuer also refuses duplicate
mint request IDs and never repeats handles/nonces after retry; an idempotent
retry returns the same encrypted endpoint delivery or a closed error, not a
second ambiguous token pair.

During epoch rotation, the relay may accept the immediately previous epoch only
for already-issued tokens until their short maximum expiry, never for new token
issuance. The signed descriptor identifies the current minimum. Once the grace
window closes, persisted minimum advances and cannot roll back.

## 9. Fail-closed runtime behavior

| Condition | Required behavior |
|---|---|
| Local role and signed capabilities differ | Listener closed; descriptor disabled; reconcile error. |
| Capability set has any extra or missing value | Reject signed state/application; service off. |
| Membership missing, invalid, stale, suspended, or revoked | Stop admission; explicit revocation drops circuits; no fallback. |
| Fleet signature/freshness/version/epoch invalid | Client does not select; relay does not advertise/start from it. |
| Token/hello version is v1 or unknown | Reject before allocation. |
| Token signature, audience, scope, slot, profile, or epoch invalid | Reject; generic bounded error; no state. |
| Clock unavailable or outside permitted skew | Reject admission; close when expiry cannot be evaluated safely. |
| CSPRNG unavailable | Issuer mints nothing; relay allocates no handle/session. |
| Proof of possession or address validation fails | Reject; no pairing or forwarding. |
| Replay store unavailable/corrupt/full | Reject new admission; alert; never run memory-only fail-open. |
| Waiting pair is duplicate/mismatched/third leg | Drop/quarantine circuit; forward nothing. |
| Circuit is unpaired or state is unknown | Drop frames. |
| Tuple changes without reviewed rebinding proof | Drop; retain original tuple until close. |
| Frame over limit or malformed | Drop/close according to fixed profile; never parse inner plaintext. |
| Global/per-source/waiting/session bound reached | Reject before expensive allocation where possible. |
| Platform firewall/sandbox/verifier fails | Service off; OS cell remains unsupported. |
| Transition drain/purge/residue check fails | Both relay modes off; do not commit next role. |
| Audit sink unavailable | Security transition does not commit; packet forwarding audit stays aggregate and bounded. |
| Unknown configuration field or permissive default | Refuse configuration/startup. |

## 10. Platform paths and isolation floor

No OS is supported merely because common Rust code compiles. Each path owns
service installation, listener/firewall policy, privilege separation, secret
storage, crash behavior, log policy, residue cleanup, and an independent local
verifier. Mobile platforms are ineligible relay hosts.

### 10.1 Common floor

- Dedicated unprivileged service identity, not the admin daemon identity.
- Minimal read-only executable/config mounts and a private state directory.
- No access to membership bundles, node identity keys, WireGuard private/public
  configuration beyond the minimum encrypted-frame transport boundary, gossip
  state, enrollment state, DNS state, or other sibling-service directories.
- Privileged helper restricted to an exact blind-relay operation allowlist; no
  general shell or arbitrary firewall command.
- Only declared UDP control/data listeners. Default-deny inbound and no
  management IPC beyond health/stop/status aggregates.
- Memory/process/core-dump restrictions appropriate to the OS.
- Bounded file sizes, descriptor counts, sockets, memory, CPU, waiting legs,
  sessions, per-prefix work, and telemetry cardinality.
- Secure atomic replay/watermark persistence and restrictive permissions.
- Aggregate logs with fixed reason codes. No identity, source-address, handle,
  or token interpolation.
- Independent verifier returns a typed pass/fail report; unknown is fail.

### 10.2 Linux path

Proposed surface: a dedicated `systemd` unit and user, hardened unit sandbox,
`nftables` rules/sets owned through a narrow privileged helper, cgroup v2 limits,
private runtime/state directories, core-dump disablement, and journald field
allowlist.

The verifier must inspect the effective unit properties, process UID/GID,
capability bounding set, namespaces/protect flags, open descriptors, listening
sockets, nftables ownership/rules, cgroup limits, directory modes/ownership,
core-dump posture, log schema, binary/config digest, replay/watermark health,
and absence of mounted/readable identity state. A text configuration file alone
is not proof; effective kernel/service state is.

### 10.3 macOS path

Proposed surface: a dedicated `launchd` daemon/user, PF anchor with exact
listener policy, restrictive filesystem ACL/mode, Keychain only for host-local
secrets that require persistence, crash-report/core policy, unified-log privacy
fields, and a reviewed sandbox profile where deployable on supported macOS.

The verifier must inspect the effective launchd job identity/configuration,
process credentials/open files, PF anchor/rules, listening sockets, directory
permissions, Keychain item ACL, crash policy, effective log output, binary/config
digest, replay/watermark health, and absence of identity-state access. If the
required sandbox/isolation cannot be made enforceable on a target macOS version,
that cell is unsupported rather than weakened.

### 10.4 Windows path

Proposed surface: a dedicated Windows Service SID and restricted service account,
WFP rules scoped to the service/app identity, filesystem ACLs, restricted token
and job-object resource limits, DPAPI-protected host-local persistent secrets,
WER dump restrictions, and ETW/Event Log allowlisted fields.

The verifier must inspect SCM configuration/effective identity, service SID and
token privileges, WFP filters, sockets, job limits, ACLs, DPAPI-bound state,
WER policy, emitted event fields, binary/config digest, replay/watermark health,
and absence of identity-state access. Firewall rule existence without effective
service scoping is not a pass.

## 11. Security controls: planned enforcement and required verification

Nothing in this table is claimed implemented. “Enforcement” is the required
implementation location/mechanism; “verification” is the proof that must exist
and fail when the enforcement is removed.

| ID | Control | Planned enforcement | Required verification |
|---|---|---|---|
| BR-C01 | Exact role composition | Membership reducer compares full canonical set to `{RelayHost, BlindRelay}`; daemon repeats alignment before service start. | Table-driven unit/mutation tests for every present capability and an unknown/future-capability fixture; daemon startup negatives for missing/extra/stale state. |
| BR-C02 | No admin/anchor/endpoint co-location | Dedicated primary role and restricted IPC; reducer rejects client, entry, exit, anchor, anchor sub-capabilities, NAS, and LLM. | Preset-table completeness, every transition row, IPC allowlist negatives, live process/open-file inspection. |
| BR-C03 | Verify signed state before apply | Existing pinned-key membership/fleet verification precedes local side effects and advertisement. | Bad key/signature, canonical mutation, stale/future state, suspended/revoked member, and apply-order mutation tests. |
| BR-C04 | Identity-free relay schema | v2 token/hello/session structs have no stable identity fields; exact parser rejects extensions; relay crate has no membership identity input. | Compile/schema snapshot, dependency/dataflow audit, identity-canary packet/memory/disk/log/telemetry live stage, mutation inserting a canary-bearing field. |
| BR-C05 | Pair policy remains default-deny | Issuer verifies two distinct active members and signed pair policy before atomic mint; no token on uncertainty. | Issuer tests for unknown/suspended/revoked/self/denied/stale policy and atomic failure; live denied pair obtains zero usable leg. |
| BR-C06 | Endpoint-bound token | Fresh per-circuit presenter key signed into token; domain-separated proof checked after address validation. | Wrong key, missing proof, altered transcript, cross-circuit proof, copied peer token, replayed challenge, malformed key, and library negative vectors. |
| BR-C07 | Relay audience and least scope | Token signature binds relay ID, kind, scope, epoch, profile, and version; exact comparisons at admission. | Wrong relay/kind/scope/epoch/profile/version mutations each reject before allocation. |
| BR-C08 | No downgrade | Blind descriptor says v2/identity-blind; blind listener rejects v1; privacy-required client has no normal/direct fallback. | Active downgrade proxy strips/changes offers; v1 token/hello to blind port; old/new mixed-fleet matrix; configuration fallback mutation. |
| BR-C09 | Fleet anti-rollback/fork | Atomic persistent watermark for schema, generation, digest, per-relay epoch, and minimum versions. | Lower generation/epoch, same-generation different digest, deleted/corrupt/unwritable watermark, software downgrade, crash-at-write fault injection. |
| BR-C10 | Freshness and clock safety | Signed bounded TTL, future-date check, usable-clock gate, monotonic circuit timers. | Expired, too-long, future-dated, boundary-skew, clock unavailable/backward/forward jump live tests. |
| BR-C11 | Replay prevention | Durable version/epoch-namespaced nonce+leg store; insert atomically before accepted allocation. | Same token, same nonce/different handle, same handle/different nonce, restart replay, epoch overlap, full/corrupt/unwritable store, concurrent duplicate. |
| BR-C12 | Exactly two complementary legs | Atomic circuit map state machine; complement/matching-field checks; no pre-pair buffering. | Duplicate slot, third leg, mismatched profile/expiry/epoch, same leg/key, races in both arrival orders, data-before-pair. |
| BR-C13 | Tuple anti-hijack | Bind accepted leg to observed validated tuple; no implicit rebinding. | Packet/hello from changed IP/port, spoofed source where lab permits, delayed old tuple, race during pairing. |
| BR-C14 | Ciphertext-only forwarding | Relay treats bounded payload as opaque bytes and has no WireGuard/private inner parser or destination routing logic. | Byte-for-byte random frame forwarding; malformed inner packets forwarded opaquely; code/dependency boundary gate; plaintext canary absent from relay-generated artifacts. |
| BR-C15 | Bounded resource use | Size caps, cheap pre-auth source validation/rate limit, fixed maps/timeouts, global/per-prefix/waiting/session/byte/packet limits, cgroup/job limits. | Oversize/burst/hash-flood/waiting-leg exhaustion, slow-loris equivalent, signature-CPU pressure, memory/FD/CPU ceiling, recovery after pressure. |
| BR-C16 | Privacy-preserving observability | Fixed aggregate metrics/log schemas; no high-cardinality labels or raw tokens/tuples/handles; debug gated and bounded. | Golden log/metric schema, forbidden-field lint, planted canaries, high-cardinality budget, incident-mode expiry/restart behavior. |
| BR-C17 | Minimal retention and cleanup | In-memory circuit state, bounded durable replay minimum, explicit purge on expiry/transition, crash-dump restrictions. | Expiry/restart/kill-9/power-loss/role-switch residue scan on all OSes; retention-bound timing checks. |
| BR-C18 | Correct transition ordering | Typed transition state machine: unadvertise/stop/purge/verify before capability/target service changes; crash-safe journal. | Fault injection before/after every step, restart convergence, old/new listener mutual exclusion, signed-state and fleet ordering assertions. |
| BR-C19 | Platform isolation | Dedicated service identity, firewall, filesystem boundary, secret protection, dump/log policy, resource limits per §10. | OS verifier plus adversarial escape/read/listen tests and effective-state inspection; config-text-only evidence fails. |
| BR-C20 | Revocation | Issuer stops mint; fleet disables; relay observes signed role loss and drops admission/circuits. | Live revoke during waiting and paired states, stale-bundle substitution, offline relay freshness expiry, no token-after-revoke. |
| BR-C21 | Safe randomness | Approved OS CSPRNG for every handle, nonce, presenter key, and epoch secret; error propagation only. | Injected RNG failure at issuer/client/relay; duplicate detector/property test; no zero/deterministic fallback. |
| BR-C22 | Canonical parsing | Separate v2 exact serializer/parser with bounded lengths, field allowlist, duplicate rejection, and signed round trip. | Fuzz/property/mutation corpus: duplicate, missing, unknown, reordered, overlong, noncanonical, control character, trailing data, version confusion. |
| BR-C23 | Key lifecycle | Pinned issuer key IDs, overlap bounded by signed key generation, no unknown key fetch/fallback; service-local rotating cookie/replay key policy. | Unknown/removed/wrong key, overlap edge, rollback, rotation crash, expired old key, deletion/corruption fail-closed tests. |
| BR-C24 | Honest user claim | UI/API uses the exact BR-P1/BR-R1 language and displays mode/version/epoch/verification state. | Snapshot/copy tests reject forbidden “anonymous/untraceable” terms; live UI shows metadata warning and no silent fallback. |

## 12. User experience and operational efficiency

### 12.1 Setup and status

The role wizard presents `blind_relay` as a single preset, not a collection of
expert toggles. Before confirmation it shows:

- “Hides Rustynet node IDs from this relay”;
- “Does not hide IP addresses or traffic timing/volume”;
- “This device cannot simultaneously be an admin, anchor, client, exit, NAS, or
  LLM host”;
- ports, estimated bandwidth, resource ceiling, and platform support status;
- that leaving the role is allowed but performs a drain and privacy-state purge.

Typed confirmation should be specific, for example
`ENABLE IDENTITY-BLIND RELAY`, not a generic yes/no. This is not because entry
is irreversible; it is because the operator is accepting a public service and a
precise residual privacy boundary.

Status has closed states, not optimistic booleans:

```text
unconfigured | preparing | verified_offline | serving | draining |
blocked_signed_state | blocked_platform_verifier | blocked_watermark |
blocked_clock | blocked_resource | transition_repair_required
```

Serving status displays descriptor generation, protocol v2, privacy epoch,
public profile, aggregate active/waiting counts, capacity, last signed refresh,
and verifier age. It never displays endpoint tuples or handles.

Client UI distinguishes:

- `identity-blind relay active`;
- `identity-blind relay unavailable — traffic not sent`;
- `normal relay active — node IDs visible to relay`.

There is no silent substitution between them.

### 12.2 Performance and availability design

- O(1)-average random-handle maps with hard capacity and expiry-wheel/timer-queue
  cleanup; no scans proportional to total fleet membership on packet path.
- Pair policy and identity lookup occur at the control plane, not the relay hot
  path.
- Stateless address validation and rate limiting precede Ed25519 verification;
  no session state before all authorization checks.
- One token pair per short admission; proactive refresh is bounded and jittered
  to avoid synchronized issuer/relay load.
- Data forwarding stays zero-identity and ciphertext-byte-oriented. Buffer pool,
  frame size, queue depth, and backpressure are bounded.
- Aggregate metrics preserve capacity planning without high-cardinality labels.
- Privacy mode has an explicit performance budget measured against normal relay:
  hello p50/p95/p99 latency, issuer latency, first-packet latency, sustained
  throughput, CPU per accepted/rejected hello, memory per waiting/paired circuit,
  packet loss under load, and recovery time after exhaustion.

Numeric budgets are intentionally OPEN until current relay baselines are
measured on the supported hardware/OS matrix. Invented targets would not be an
engineering commitment. Acceptance must set budgets before implementation is
declared production-ready.

## 13. Verification program and live-lab floor

### 13.1 Static and unit proof

Required suites:

- enum/parser/render/canonical-order and signed-preimage fixtures;
- exact capability reducer and every preset transition row/column;
- local-role/membership/assignment alignment and IPC allowlist;
- v2 canonical token/fleet/hello round trips and malformed-input fuzzing;
- issuer atomic pair authorization and endpoint-specific delivery;
- proof-of-possession transcript vectors;
- token freshness/replay/epoch/version/audience/scope/profile negatives;
- circuit state-machine model/property tests including concurrency races;
- resource-bound and allocation-order tests;
- telemetry forbidden-field/schema tests;
- transition step fault injection and crash journal recovery;
- OS policy builders and independent effective-state verifier tests.

Each high-value security test needs a mutation/reversion obligation: removing
the enforcement must make the test fail. A green test that never reaches the
control does not count.

### 13.2 New live-lab stages

Stage names are proposed; they must be registered through the repository's
single stage vocabulary rather than duplicated ad hoc.

1. **`blind_relay_role_contract`** — admit exact role; reject every forbidden
   combination; verify local primary, restricted IPC, signed-state alignment,
   advertisement ordering, and no normal listener.
2. **`blind_relay_identity_privacy`** — connect two canary endpoints through a
   real relay; forward random encrypted frames; inspect packet captures, process
   arguments/environment, readable files, memory/core material where the OS lab
   safely permits, service logs, audit, metrics, replay/watermark state, and
   post-close residue. Unique stable identity canaries must be absent. Report
   paired socket/timing visibility as expected residual evidence, not failure.
3. **`blind_relay_protocol_negatives`** — v1/unknown versions, malformed
   canonical fields, wrong relay/scope/epoch/profile/slot/key, missing/altered
   proof, stale/future/long token, replay before/after restart, duplicate/third
   leg, tuple change, and unpaired data all fail closed.
4. **`blind_relay_resource_limits`** — oversize input, pre-auth flood,
   signature load, waiting-leg exhaustion, capacity, FD/memory/CPU ceilings,
   replay-store pressure/failure, and recovery without bypass.
5. **`blind_relay_transition_residue`** — normal-to-blind and blind-to-every
   allowed target; forced drain deadline; kill-9/power interruption at each
   phase; restart convergence; watermark/replay/log/crash residue; mutual
   exclusion of normal and blind listeners.
6. **`blind_relay_revocation`** — revoke during waiting/paired circuits, stale
   signed-state substitution, offline freshness expiry, and proof that no new
   token/session/forwarding survives.
7. **`blind_relay_platform_verifier`** — effective service identity, firewall,
   filesystem, dump/log, resource, socket, binary/config, and secret-store state
   for Linux, macOS, and Windows.

Every stage must emit run-scoped artifacts with source commit, binary digest,
OS/version, descriptor generation, privacy epoch, verifier output, and exact
test conclusion. Sensitive tuple/handle artifacts remain in access-controlled,
time-bounded lab evidence and must not be normalized into production logging.
Dry run, config text, unit tests, or another OS do not count as live proof.

### 13.3 Cross-platform parity timing

Do **not** edit the role parity plan yet. This document is a proposed definition,
not accepted architecture. After security/architecture acceptance and stage
registration:

1. add the new primary role and modifier capability to the authoritative parity
   vocabulary;
2. add Linux, macOS, and Windows implementation and live-proof cells;
3. mark all cells unimplemented/unproven initially;
4. turn a cell green only after its OS-specific verifier and all applicable live
   stages pass on that OS;
5. widen release completeness so the new rows are release-blocking.

## 14. Implementation surface and dependency order

This is a design inventory, not authorization to write code.

1. **Freeze semantics:** approve BR-P1/BR-R1, role exclusivity, transition
   reversibility, protocol standard/library, encoding, transcript, profiles,
   retention, and performance budgets.
2. **Signed taxonomy:** append membership capability/parser/renderer; exact
   reducer; membership transitions; signed canonical fixtures.
3. **Preset/local role:** preset, primary role, daemon role, assignment mapping,
   restricted IPC, platform eligibility, transition matrix and side effects.
4. **Fleet v2:** signed schema, strict parser/verifier, dual publication,
   signed mode/version/epoch/profile, extended persistent watermark.
5. **Issuer/client v2:** atomic pair authorization, endpoint-bound delivery,
   presenter-key generation/storage/erasure, no-fallback selection, client state
   and UX.
6. **Relay protocol/runtime v2:** strict envelope/token/PoP, address validation,
   replay store, circuit state machine, bounded forwarding, aggregate telemetry,
   v1 refusal.
7. **Transition engine:** ordered deploy/unadvertise/drain/stop/purge/verify,
   crash-safe journal, residue report, audits.
8. **Per-OS paths:** Linux, macOS, and Windows service/firewall/storage/logging/
   resource policy plus independent verifier.
9. **Tests and gates:** unit/property/fuzz/mutation, dependency/privacy schema
   gate, new live stage registry, artifacts, cross-platform parity rows after
   design acceptance.
10. **Canary rollout:** non-production, one accepted OS at a time, adversarial
    review after evidence, then explicit production decision.

Likely files include, without claiming exact final placement:

- `crates/rustynet-control/src/roles.rs`;
- `crates/rustynet-control/src/membership.rs`;
- `crates/rustynet-control/src/role_presets.rs`;
- `crates/rustynet-control/src/lib.rs` or a narrowed relay-protocol module;
- `crates/rustynetd/src/daemon.rs` and `relay_client.rs`;
- `crates/rustynet-relay/src/transport.rs` and its wire entrypoint;
- CLI/wizard/install/transition surfaces;
- one platform module and verifier path per OS;
- live-lab stage registry/orchestrator binaries and parity documents.

The protocol and privacy-critical structs should move into a small,
backend-agnostic module with strict ownership boundaries rather than growing one
large general control file. This remains subject to CODE_MAP/maintainer review.

## 15. Rollout, rollback, and incident behavior

### 15.1 Rollout gates

Production enablement requires all of:

- approved threat model and protocol choices;
- independent cryptographic/protocol review;
- exact control table implemented with named verification;
- fuzz/property/mutation gates green;
- privacy identity-canary stage green;
- transition/residue/restart stage green;
- platform verifier and resource stage green on the target OS;
- mixed-fleet downgrade/rollback stage green;
- operator runbook and user disclosure reviewed;
- parity plan rows registered and accurately marked.

### 15.2 Safe rollback

Software rollback may disable blind service, but may never re-enable v1 on a
blind descriptor or reduce persisted minimum versions/epochs. If a release must
be rolled back to software that lacks v2, the node becomes unavailable as a
blind relay. It is not automatically converted to normal relay.

An operator may explicitly transition to normal relay only through §6.3,
including unadvertise, drain, purge, signed role change, normal runtime install,
verification, and honest UI disclosure. Past blind circuits retain their
original BR-P1 claim; future normal circuits do not inherit it.

### 15.3 Incident mode

On suspected issuer compromise, fleet rollback/fork, role misalignment,
identity-canary hit, token replay anomaly, residue failure, or platform verifier
failure:

1. stop blind token issuance and publish signed relay disable/revocation;
2. close admission and circuits;
3. preserve only access-controlled incident artifacts necessary for analysis;
4. rotate affected issuer/service keys and advance privacy epoch/generation;
5. inspect whether stable identities entered relay artifacts;
6. do not restore service until the root cause, retention impact, and user
   disclosure decision are complete.

Failing the privacy canary is a security incident, not a telemetry warning.

## 16. OPEN decisions required before implementation

1. **OPEN: Encoding and framing:** select the exact reviewed, bounded canonical
   representation for fleet v2, token v2, and hello v2. The decision must include
   duplicate/unknown-field behavior and cross-language test vectors.
2. **OPEN: Proof-of-possession suite:** select the established signature algorithm and
   library, canonical transcript, key validation, challenge/address-validation
   mechanism, and key-erasure boundary. Security review required; no custom
   cryptography.
3. **OPEN: Replay persistence:** choose the minimum durable representation and local
   key-rotation scheme that survives restart without creating a stable telemetry
   identifier or weakening retention.
4. **OPEN: Public privacy profiles:** set fixed TTL, circuit lifetime, idle, bytes,
   packets, frame, and resource limits after baseline measurement. Avoid
   user-specific fingerprinting.
5. **OPEN: Operational retention:** approve exact aggregate audit/metric retention and
   the incident-mode capture policy for each OS/legal environment.
6. **OPEN: Performance acceptance:** measure the normal-relay baseline and approve
   p95/p99 handshake, throughput, CPU, memory, loss, and recovery budgets.
7. **OPEN: Stronger privacy:** decide separately whether a future two-relay,
   independently operated split-trust profile is wanted. It must not delay or
   inflate claims for this single-hop role.

Until items 1-6 are resolved, `blind_relay` remains design-only and must not be
advertised by production signed state.

> 2026-08-28: proposed selections for items 1-3, measurement plans for items 4
> and 6, and a retention proposal for item 5 now exist in
> `BlindRelayProtocolSelection_2026-08-28.md`, composed from in-tree primitives
> with file:line evidence. They remain PROPOSED pending security review and
> owner approval; this §16 list stays authoritative until that review, and
> item 7 remains a separate open decision.

## 17. Design acceptance checklist

Architecture/security reviewers should accept only if every answer is “yes”:

- Is BR-P1 falsifiable and BR-R1 prominent?
- Is the adversary explicit, including compromised relay-host access?
- Does the design avoid claiming IP/timing/flow anonymity?
- Is the same-circuit leg association admitted as unavoidable?
- Is `BlindRelay` a modifier requiring `RelayHost`, with a dedicated local role?
- Does signed state allow exactly `{RelayHost, BlindRelay}` and reject future
  co-capabilities by default?
- Is reversibility justified without inheriting the ENR-06 factory-reset hazard?
- Are transition ordering, crash recovery, residue verification, and failure
  states explicit?
- Does token/hello v2 eliminate stable identities instead of hashing them?
- Are the two legs endpoint-bound with fresh proof-of-possession keys?
- Are negotiation, mixed fleet, replay namespaces, downgrade, anti-rollback,
  anti-fork, and software rollback fully fail closed?
- Does every security control name enforcement and verification?
- Are Linux, macOS, and Windows paths independently enforced and verified?
- Is the UI honest and free of silent fallback?
- Are the remaining protocol choices clearly OPEN rather than fabricated?
- Is parity-plan modification deferred until acceptance?

## 18. References

- `documents/Requirements.md`
- `documents/SecurityMinimumBar.md`
- `documents/operations/active/BlindRelayRoleGap_2026-07-30.md`
- `documents/operations/active/NodeRoleTaxonomy_2026-05-21.md`
- `documents/operations/active/NodeRoleTaxonomyExtension_2026-06-11.md`
- `documents/CODE_MAP.md`
- [RFC 9576 — The Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html)
- [RFC 9614 — Partitioning as an Architecture for Privacy](https://www.rfc-editor.org/rfc/rfc9614.html)
- [RFC 8747 — Proof-of-Possession Key Semantics for CWTs](https://www.rfc-editor.org/rfc/rfc8747.html)
- [RFC 9000 — QUIC Transport, address validation](https://www.rfc-editor.org/rfc/rfc9000.html)
