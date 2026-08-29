# RustyDNS × Rustynet Tandem Integration Design (2026-08-27)

**Status:** design freeze candidate; design only; no implementation is present.

**Governing decree:**
[`RustydnsExitIntegrationDecree_2026-08-25.md`](./RustydnsExitIntegrationDecree_2026-08-25.md).

**Decision summary:** Rustynet owns a signed, default-off, per-exit DNS service
assignment and every client/OS dataplane mutation. RustyDNS owns DNS policy,
encrypted upstream resolution, privacy, and a local authenticated readiness
contract. The clean path preserves client-side Rustynet ownership of
`.rustynet` and sends non-mesh questions to the selected exit's RustyDNS
listener through a platform-specific managed resolver adaptor. The catch-all
path redirects selected clients' UDP and TCP port 53 traffic at the exit before
ordinary forwarding/NAT. A readiness failure changes the exit
to an observable containment state; it never restores ordinary plaintext DNS.
`blind_exit` is incompatible. Windows managed handoff is in scope, but Windows
transparent redirect is an explicit, release-blocking implementation and
live-proof gap; it must never silently degrade to managed-only operation.

This document uses **MUST**, **MUST NOT**, **SHOULD**, and **MAY** normatively.
An implementation is not conformant until the cross-repository contract and
the applicable real-node stages below pass.

## 1. Why this needs an explicit design

An exit forwards client packets through its routing and NAT dataplane. Those
packets do not traverse a resolver merely because a resolver process happens to
run on the exit host. RustyDNS therefore benefits an exiting client only when
Rustynet deliberately selects it as the client's managed resolver, or when the
exit deliberately diverts that client's plain DNS traffic to it.

The two paths solve different problems:

1. **Managed handoff** is the normal, explainable path. The Rustynet client
   keeps ownership of managed `.rustynet` answers and sends only non-mesh DNS
   to a signed resolver endpoint on its selected exit.
2. **Transparent port-53 redirect** contains applications that ignore OS DNS
   settings and send UDP or TCP DNS to a hard-coded address. The exit rewrites
   those packets to the same RustyDNS endpoint while preserving their mesh
   source identity.

Neither path can generically intercept encrypted DNS. Blocking TCP/UDP port 853
can contain conventional DoT and much DoQ. A known-DoH destination feed can
block only the endpoints represented by that feed. It cannot discover every
DoH service, cannot safely distinguish DoH from unrelated HTTPS on shared
addresses, and MUST NOT be described as complete encrypted-DNS interception.

## 2. Inputs, current facts, and scope boundary

This design was produced after the required reading order in `AGENTS.md`, plus
`documents/Requirements.md`, `documents/SecurityMinimumBar.md`, the governing
decree, `MagicDnsSignedZoneSchema_2026-03-09.md`,
`ManagedDnsMultiClientPlan_2026-08-13.md`, and `CODE_MAP.md`. The listed DNS,
NAT, killswitch, and lifecycle sources were inspected in Rustynet, and the
RustyDNS repository guidance, integration documents, architecture, operator
endpoints, configuration, identity, authority, resolver, and daemon health
paths were inspected.

The starting facts are important:

- A case-insensitive search for `rustydns` or `rusty_dns` in Rustynet's
  `crates/`, `scripts/`, and `third_party/` has zero hits. Rustynet integration
  implementation is therefore **zero**, not partial.
- The only pre-design Rustynet references are the decree and its operations
  index entry.
- Rustynet's managed-DNS and DNS-fail-closed live stages pass on Linux and
  macOS. This design extends those controls; it does not replace or weaken
  them.
- The current signed-zone v1 parser accepts `A`/`mesh_ipv4` records, not an
  advertised IPv6 resolver endpoint. Tandem v1 therefore uses the exit's exact
  signed mesh IPv4 address and contains selected IPv6 DNS-bypass transport.
- Rustynet's local resolver currently binds loopback `127.0.0.1:53535`, serves
  the signed mesh zone, and refuses other names. Linux owns local host DNS with
  an nftables output redirect; macOS uses a scoped resolver for `.rustynet` and
  has no equivalent local port-53 redirect; Windows verification expects
  loopback resolver ownership and a root NRPT rule.
- Existing exit-DNS evidence checks prove off-tunnel port-53 blocking, an
  active blocked-path probe, and tunnel hostname resolution. They do not prove
  a RustyDNS handoff or forwarded-packet redirect.
- Exit NAT lifecycle code proves forwarding/NAT activation and teardown, but
  the lifecycle evidence producers are not themselves tandem enforcement.
- RustyDNS defaults DNS service to `127.0.0.53:53`. Its configuration warns,
  rather than rejects, a wildcard `0.0.0.0` listener. Tandem mode therefore
  needs a stronger exact-bind profile.
- RustyDNS `/health` becomes healthy when configured DNS listeners are bound.
  It does not prove encrypted upstream reachability, fresh blocklists, DNSSEC,
  ECS stripping, fail-closed configuration, or tandem namespace isolation. It
  is insufficient as the activation oracle.
- RustyDNS parses NodeId-keyed policy, but runtime matching is not wired; only
  IP-keyed policy currently applies. Tandem identity integration is real work.
- RustyDNS can verify the existing signed Rustynet zone bundle. Its current
  in-process anti-rollback watermark resets on restart, while Rustynet's zone
  consumer has a persisted digest-bearing watermark. The tandem control plane
  MUST use Rustynet's signed-state/replay posture and must not treat the
  RustyDNS zone loader as an activation authority.

### 2.1 In scope

- A first-class `dns` service kind and signed per-exit tandem policy.
- Managed handoff for clients assigned to that exit.
- Transparent UDP/TCP port-53 redirect for selected clients.
- Optional TCP/UDP 853 and signed known-DoH endpoint blocking.
- Local authenticated RustyDNS readiness, identity handoff, fail-closed
  lifecycle, OS-specific application and residue verification.
- Linux, macOS, and Windows behavior, including honest platform limiters.
- Rust `--node` live-lab stages, evidence, operator status, and standalone
  regression proof.

### 2.2 Out of scope

- Moving `.rustynet` authority into RustyDNS.
- Inspecting DNS payloads in Rustynet.
- TLS interception, certificate installation, SNI inspection, QUIC decryption,
  or a claim to block arbitrary DoH.
- Automatically installing or upgrading RustyDNS.
- Sharing private keys, raw query logs, or RustyDNS configuration secrets.
- Serving tandem DNS from `blind_exit`.
- Shipping a Windows redirect based on an unproven WinNAT or WFP assumption.

## 3. Frozen security and product invariants

1. Tandem is default OFF. Only valid, fresh, replay-protected signed network
   state may enable it.
2. The activation unit is a named exit and an explicit client selector. Local
   discovery, a running process, a DNS response, DHCP, or unsigned API data may
   veto readiness but may never grant capability.
3. A selected client MUST be assigned to the same exit referenced by the DNS
   policy. A resolver cannot be selected independently of its egress path.
4. The clean and redirect paths use an exact signed exit mesh address. Wildcard
   listeners, LAN addresses, public addresses, and loopback addresses are not
   valid advertised endpoints.
5. Rustynet remains authoritative for `.rustynet`. A tandem RustyDNS listener
   MUST refuse that suffix without forwarding it upstream.
6. UDP and TCP port 53 have identical scope and failure behavior. UDP-only DNS
   is non-conformant because truncation and large answers require TCP.
7. When signed state says ON and readiness is false, stale, unauthenticated, or
   incompatible, selected DNS is contained. No system resolver fallback and no
   direct port-53 egress is installed.
8. No tandem exception may make the existing default-deny terminator
   unreachable. Resolver upstream egress is limited to the RustyDNS service
   identity and exact configured encrypted-upstream endpoints.
9. Rule ownership is generation-scoped and disjoint from ordinary exit NAT,
   base killswitch, and local protected-DNS ownership. Toggle-off, demotion,
   revocation, crash recovery, and reboot reconcile desired signed state
   against observed OS state and verify residue.
10. `blind_exit` and `serves_dns` are mutually exclusive. A resolver observes
    client addresses and query streams, so it cannot satisfy origin blindness.
11. RustyDNS and Rustynet remain independently installable, startable,
    upgradeable, observable, and testable when tandem is OFF.
12. Rustynet never logs raw QNAMEs. RustyDNS retains its privacy contract:
    no raw QNAME at info-or-higher, anonymized client address by default,
    memory-only query history by default, bounded retention, and loopback-only
    diagnostics.

## 4. Threat model

### 4.1 Protected assets

- Query confidentiality and the absence of off-tunnel plaintext DNS.
- Correct `.rustynet` namespace answers and non-disclosure of unrelated mesh
  records.
- Signed role, exit, scope, and resolver assignment integrity.
- Killswitch reachability and exit-NAT containment.
- Client-to-identity binding for policy and audit.
- Resolver configuration, blocklist, upstream, and health integrity.
- Clean teardown without a stale redirect, pass rule, resolver assignment, NAT
  state, or service egress exception.

### 4.2 Adversaries and failures considered

- An untrusted mesh peer spoofing another selected peer's source address.
- A malicious application hard-coding UDP/TCP DNS, DoT, DoQ, or DoH.
- A malicious or compromised LAN host reaching a broadly bound resolver.
- Replay, expiry, rollback, clock rollback, or cross-network substitution of a
  tandem policy.
- A crashed, wedged, stale, misconfigured, or impersonated RustyDNS process.
- A compromised unprivileged daemon attempting to inject arbitrary nftables,
  PF, WFP, route, or service rules through a privileged helper.
- Partial apply, daemon crash between steps, reboot, role demotion, exit change,
  client roaming, and stale connection-tracking/PF/WFP state.
- A malicious or stale DoH feed causing excessive collateral blocking.
- DNS amplification and resource exhaustion against RustyDNS.
- A user believing that “known DoH blocked” means “all encrypted DNS blocked.”

### 4.3 Trust boundary

The signed Rustynet control plane grants the DNS service role and client scope.
The local OS authenticates the Rustynet↔RustyDNS readiness/identity channel.
RustyDNS answers questions and reports current health; it does not grant itself
a Rustynet capability. Rustynet enforces network scope; RustyDNS applies DNS
policy. The privileged helper accepts typed, bounded specifications and
re-renders reviewed rules. Neither repository trusts free-form rule text,
client-supplied NodeId metadata, HTTP health from the mesh, or process-name
matching as an authorization mechanism.

## 5. Product model and signed control-plane contract

### 5.1 Toggle semantics

The user-facing switch is a signed network change, not a machine-local boolean:

- `OFF`: no client is assigned the tandem endpoint; no tandem redirect,
  bypass block, endpoint pass, or upstream service exception exists.
- `ON / managed`: selected clients receive managed handoff only.
- `ON / managed+redirect`: selected clients receive managed handoff and the
  exit diverts their UDP/TCP port-53 traffic.
- `ON / contained`: desired state is ON but a trust, readiness, apply, or
  verification condition failed. Selected DNS is deliberately unavailable and
  the reason is shown.
- `DRAINING`: a signed disable or scope removal is propagating. New handoffs are
  gone, existing leases are bounded, and tandem enforcement is not removed
  until the deactivation barrier in section 10 passes.
- `ERROR / residue`: desired state is OFF but owned state remains, or desired
  state is ON but observed ownership is ambiguous. Further enabling is refused.

An operator may issue a local **contain now** safety veto. It can only move ON
to contained and cannot create an OFF data path, expand scope, or enable the
service. Normal enable/disable requires authorized signing and quorum/owner
rules already governing Rustynet policy.

### 5.2 Non-authorizing `TandemDnsPrepareIntentV1`

Deploy-before-sign needs an authenticated preparation instruction without
prematurely granting a network capability. The controller therefore issues a
short-lived, signed `TandemDnsPrepareIntentV1` that binds network, request,
exit, proposed service instance/profile digest, proposed mode/scope digest,
membership epoch, freshness, and nonce. It is authorization to prepare local
contained state and run canaries only. Clients ignore it, it cannot advertise a
resolver, and the exit firewall keeps client endpoint admission closed. It uses
the same signer/quorum, strict decoding, replay, and audit rules as other
security-sensitive control operations. Expiry removes prepared-only state after
residue proof.

The active capability and enabled policy below are signed only after the
controller verifies the exit's prepared receipt. Thus a valid prepare intent is
necessary for mutation but never sufficient for client use.

### 5.3 `ServiceCapabilityV1`

The D13 hosting-role pattern is extended with `ServiceKind::Dns`, stable wire
string `dns`, sibling binary name `rustydnsd`, and a signed `ServesDns`
capability. The capability record is signed through Rustynet's existing
membership/control update envelope and binds:

| Field | Rule |
|---|---|
| `schema_version` | Exactly `1`; unknown versions fail closed. |
| `network_id` | Must equal the active network. |
| `service_kind` | Exactly `dns`. |
| `service_node_id` | Must equal the exit NodeId and signed assignment subject. |
| `service_instance_id` | Opaque 128-bit identifier generated at deployment; never a secret. |
| `mesh_address` | V1: exact signed mesh IPv4 address currently assigned to the exit; no LAN/public/loopback inference. |
| `dns_port` | Exactly `53` in v1. |
| `transports` | Exactly `{udp,tcp}`; neither may be absent. |
| `protocol_min`, `protocol_max` | Supported tandem contract range. V1 requires intersection containing `1`. |
| `profile_digest` | SHA-256 of canonical non-secret tandem security settings. |
| `generated_at`, `expires_at`, `nonce` | Existing freshness and replay fields. |
| `membership_epoch` | Must equal the reducer's accepted membership epoch. |

The capability is advertised only after deploy-before-sign ordering succeeds:
RustyDNS profile validated, local readiness authenticated, both DNS transports
functionally probed, and containment rules staged. Removal/revocation is signed
before local service teardown.

`profile_digest` is SHA-256 over a strict canonical public profile: protocol
version, exact listener, namespace guard, fail-closed/ECS/DNSSEC requirements,
encrypted-upstream transport and endpoint/bootstrap tuples, blocklist source
identities/pins/freshness policy, rate/resource limits, and fixed canary IDs. It
excludes credentials, private keys, filesystem paths, and mutable health
timestamps. RustyDNS computes it from effective validated configuration, not
from a caller-supplied digest string.

### 5.4 `TandemDnsPolicyV1`

The signed network policy references, but does not duplicate, the capability:

| Field | Rule |
|---|---|
| `schema_version` | Exactly `1`. |
| `network_id` | Cross-network substitution guard. |
| `policy_id` | Stable opaque identifier. |
| `generation` | Strictly increasing for this `policy_id`; persisted digest-bearing watermark. |
| `previous_payload_digest` | Must equal the last accepted canonical policy digest (all-zero only for creation), serializing updates and tombstones. |
| `enabled` | Explicit boolean; `false` is the signed tombstone/drain instruction and never inferred from local absence. |
| `exit_node_id` | Must have current `exit` and `dns` capability; `blind_exit` is forbidden. |
| `service_instance_id` | Must equal the capability. |
| `mode` | `managed` or `managed_redirect`; no implicit fallback between them. |
| `scope` | `all_clients_using_exit` or a sorted, deduplicated, bounded list of explicit NodeIds. |
| `block_port_853` | Default `false`; when true covers TCP and UDP, and the UI says DoT/DoQ. |
| `known_doh_feed` | Optional `{feed_id, generation, digest, expires_at}`; absence means no known-DoH block. |
| `generated_at`, `expires_at`, `nonce` | Freshness/replay tuple; expiry while ON produces containment. |
| `membership_epoch` | Must match the capability and current accepted membership state. |

`all_clients_using_exit` is evaluated against each client's signed exit
assignment, not against a CIDR wildcard. The reducer emits a deterministic,
sorted explicit endpoint/client set to each affected node. Unknown fields,
duplicate NodeIds, a client assigned to another exit, an address outside the
signed mesh assignment, a stale generation, digest mismatch, incompatible
protocol range, and role conflict all reject the update without OS mutation.

Policy and service-instance scope is one `network_id`. A physical host serving
multiple Rustynet networks uses independent instance IDs, exact per-network
mesh listeners, identity snapshots, generations, native source sets, readiness,
and audit. No client, cache-policy identity, or endpoint admission crosses the
network boundary, and `all_clients_using_exit` means all assigned clients in
that named network only.

For `enabled=false`, the reducer authenticates the policy chain, predecessor,
network, signer/quorum, generation, freshness, and named prior service instance,
then removes access; it does not require that service to remain currently
capable. Disable is published before capability revocation. Capability removal
is signed only after the exit's residue-verified removal receipt, so a service
revocation cannot strand an unprocessable active policy.

The signed object determines **who may use which service and which containment
options apply**. It deliberately does not contain local file paths, interface
names, process UIDs, PF anchor names, WFP identifiers, readiness socket paths,
or native command text. Those are host-derived, validated enforcement details.

### 5.5 Client assignment and lease

Each selected client reducer derives a `ManagedDnsAssignmentV1` from the
accepted policy and capability. It binds the client NodeId, selected exit
NodeId, resolver mesh address, both transports, policy generation, and an
expiry no later than the parent policy/capability expiry. The client accepts it
only if its active signed exit is the same exit.

The platform adaptor continues to route the signed `.rustynet` zone to the
local Rustynet resolver. On Linux and Windows, that local resolver also forwards
every other suffix to the assigned RustyDNS endpoint through the tunnel,
sourcing the flow from the client's authenticated mesh address. On macOS, the
scoped `.rustynet` resolver remains local while the OS default DNS service is
the exact exit mesh endpoint, also routed through the tunnel. Neither form may
copy the entire mesh zone to RustyDNS, use the system's pre-tunnel resolver as
fallback, or send an unqualified name off mesh before applying the existing
search-suffix and leak-prevention rules.

Assignment expiry while the parent policy remains desired ON is containment,
not fallback. Assignment removal caused by signed OFF restores the ordinary
Rustynet DNS posture after the deactivation barrier.

> **Disposition (2026-08-29, tandem phase 2 / D-6b):** the control-plane
> resolver-assignment decision is wired in
> `crates/rustynet-control/src/managed_dns_handoff.rs`
> (`managed_dns_handoff_decision`): `Active` plus proven scope, exit
> assignment, readiness, and a mesh-range-contained endpoint hands out the
> RustyDNS mesh IP; every failing predicate contains with its §11 reason and
> nothing falls back to a non-tandem resolver; signed OFF, prepare-only
> phases, draining, and unselected NodeIds produce no assignment. The
> resolver mesh address is **not** carried in signed wire format yet — that
> carriage is an owner/security-gated decision (same class as blind-relay
> §16 and phase-1 notes §3.2), so the endpoint is an abstract typed input.
> Details, flagged sub-decisions, and verification:
> `RustydnsTandemPhase2Notes_2026-08-29.md`.

### 5.6 Identity snapshot contract

RustyDNS cannot trust an EDNS option, source header, QNAME, reverse DNS, or
client-provided NodeId. Rustynet already authenticates tunnel peers and owns the
signed mesh-address assignment, so it exports a minimal local
`PeerIdentitySnapshotV1` over the authenticated local channel:

- protocol version, network ID, membership epoch, policy generation, and
  source signed-state digest;
- only selected `{mesh_address, node_id}` mappings for this service instance;
- generated monotonic timestamp and expiry bounded by the signed policy;
- no endpoint history, public address, display name, tags, or unrelated peers.

RustyDNS atomically swaps the complete snapshot. Unknown, duplicate, expired,
or conflicting mappings are refused. Queries from an unmapped source fail
closed. This wires the NodeId policy path that RustyDNS currently parses but
does not match at runtime. IP-keyed policy may remain available in standalone
RustyDNS, but tandem authorization is never based on a manually maintained IP
table.

The network firewall remains the primary admission control. The snapshot lets
RustyDNS select per-node policy and produce privacy-safe counters; it does not
replace tunnel peer/source enforcement.

## 6. Cross-product runtime contract

### 6.1 Local authenticated channel

Rustynet and RustyDNS communicate only on a local OS-authenticated endpoint:

- Linux and macOS: a Unix-domain bounded stream socket (`SOCK_SEQPACKET` where
  supported) in a root-owned, non-symlink directory, mode `0660`, with platform
  peer credentials checked against exact service UIDs/groups.
- Windows: a named pipe with an ACL limited to the Rustynet and RustyDNS service
  SIDs, with the server verifying the connecting token.

The path/pipe is host configuration, not signed network state. Both sides use
bounded length-prefixed messages, fixed maximum counts and sizes, timeouts, and
strict schemas. Symlinks, world-writable parents, unknown fields, oversized
frames, protocol downgrade, duplicate keys, and unexpected peer credentials
fail closed. The channel carries no private key or raw query.

The requester supplies a fresh 256-bit challenge. Every response echoes that
challenge and includes `service_instance_id` and a per-boot random `boot_id`.
OS peer authentication, a fresh connection, and the challenge prevent a stale
HTTP body or unrelated local process from serving as readiness. This is local
authentication, not a new cryptographic trust root.

### 6.2 `TandemDnsReadinessV1`

RustyDNS returns these bounded, non-secret fields:

| Field | Ready requirement |
|---|---|
| `protocol_min`, `protocol_max` | Intersects the signed capability at v1. |
| `challenge`, `service_instance_id`, `boot_id` | Exact expected values; current connection. |
| `profile_digest` | Equals the signed capability digest. |
| `listeners` | Exact mesh address, port 53, UDP and TCP successfully bound; no wildcard tandem bind. |
| `namespace_guard` | `.rustynet` is locally refused and never sent upstream. |
| `fail_closed` | `true`. |
| `strip_ecs` | `true`. |
| `dnssec_validate` | `true` for tandem upstream answers. |
| `upstream_transport` | Only reviewed DoH, DoQ, or ODoH; plaintext is forbidden. |
| `upstream_probe_age_ms` | Successful encrypted active probe within the configured bounded readiness window. |
| `blocklist_generation`, `blocklist_digest` | A non-empty accepted snapshot from the source/pin profile; no in-boot generation regression. |
| `blocklist_age_ms` | Within the signed/local maximum; stale or never-loaded is not ready. |
| `identity_generation` | Equals the Rustynet snapshot generation. |
| `ready`, `reason_codes` | `ready` only when every mandatory predicate holds; reasons are a closed enum. |

RustyDNS's existing `/health` remains useful for standalone listener liveness,
but Rustynet MUST NOT use it for tandem activation. The tandem readiness probe
must exercise the real policy pipeline. RustyDNS performs a fixed, privacy-safe
encrypted upstream canary (for example a DNSSEC-valid root metadata query) and
records only result and monotonic age. Rustynet additionally sends fixed UDP and
TCP queries to a locally configured `.invalid` block canary through the exact
mesh listener and verifies the configured block response. The canary name is
not client data and is never accepted from network control state.

No single boolean is sufficient. Listener-only health, process existence,
open-port checks, cached success older than the readiness window, or a response
from a wildcard/LAN listener fails activation.

### 6.3 Resolver listener and upstream egress profile

Tandem RustyDNS MUST bind the exact signed exit mesh address on UDP/TCP 53. It
MUST NOT bind `0.0.0.0`, `::`, a LAN address, or a public address for this
profile. The host firewall accepts the endpoint only from the tunnel interface
and selected signed source mappings.

The tandem listener has a namespace guard before authority, blocklist, and
recursive resolution: `.rustynet` and its descendants are refused locally and
never forwarded. If the operator also wants RustyDNS's standalone signed-zone
consumer for host-local use, it uses a separate loopback-only listener/profile.
A global RustyDNS authority view MUST NOT be exposed to forwarded tandem
clients. RustyDNS currently has one broad pipeline, so listener-specific
namespace isolation is a RustyDNS implementation gap, not an assumption.

RustyDNS upstream bootstrap must not recurse through the managed resolver it is
serving. Each configured encrypted upstream therefore has a hostname for TLS
verification plus bounded bootstrap IPs managed by RustyDNS configuration,
with ordinary certificate verification and TLS 1.3 retained. Host firewall
exceptions are generated from the currently accepted endpoint set and admit
only the RustyDNS service identity to the exact protocol/address/port tuples.
No generic UID-to-Internet or port-443 pass is permitted. Endpoint rotation is
staged under containment: resolve/validate, install the new bounded set, prove
encrypted readiness, switch, then remove the old set and state.

### 6.4 Ownership matrix

| Concern | Rustynet owns | RustyDNS owns | Shared/frozen boundary |
|---|---|---|---|
| Capability and toggle | Signed service capability, policy reducer, client assignment | Reports supported protocol/profile only | IDs, versions, digest semantics |
| Client OS DNS | Local stub, `.rustynet`, resolver state, no-fallback behavior | None | Exact exit mesh endpoint |
| Exit admission/redirect | Peer/source ACL, DNAT/rdr/WFP, bypass blocks, lifecycle | Exact listener | Selected NodeId/address snapshot |
| DNS policy | No QNAME inspection | Authority guard, blocklist, schedules, rate limits, cache | Fixed canaries and reason codes |
| Upstream privacy | Process-specific firewall exception and capture proof | DoH/DoQ/ODoH, TLS verification, DNSSEC, ECS stripping, fail closed | Exact endpoint set/digest |
| Health | Authenticates, probes, gates rules, contains failure, shows status | Computes truthful readiness | Local channel and `ReadinessV1` |
| Privilege | Typed helper specs and native mutation | Service sandbox/capabilities | No free-form commands or rule text |
| Logs/metrics | State transitions and aggregate counters; no QNAME | Privacy-safe DNS metrics/logs | Correlation by opaque policy/service generation only |

Neither side writes the other's configuration or state directory. Each side
may be upgraded first within the advertised protocol range. An unsupported
version leaves signed desired state visible as `ON / contained: incompatible`
without mutating an existing safe dataplane.

## 7. Data-plane design

### 7.1 Clean managed path

```text
application
  -> client OS resolver
       -> .rustynet: Rustynet local signed-zone resolver
       -> other names:
            Linux/Windows -> Rustynet local forwarding resolver
            macOS         -> exact exit endpoint as managed default resolver
       -> exit mesh IP:53 across authenticated tunnel
  -> RustyDNS tandem listener
  -> authority guard -> per-NodeId policy -> blocklist/cache
  -> encrypted DNS upstream with ECS stripped and DNSSEC validation
```

The Linux/Windows client-side forwarder, or the macOS system resolver's direct
socket, retains source affinity: its upstream flow is routed through the tunnel
and uses the client's mesh address. Rustynet exit ACL and the local identity
snapshot bind that address to the authenticated NodeId.
RustyDNS may cache and coalesce requests, but response IDs, transport semantics,
truncation, TTL bounds, negative caching, and per-client rate limits remain
correct. TCP fallback is tested, not inferred.

### 7.2 Transparent port-53 path

```text
selected client -> tunnel -> exit pre-forward translation
  UDP/TCP dport 53, any destination
  -> exact exit mesh IP:53
  -> local RustyDNS listener
  -> reverse state restores the application's expected source tuple
```

Translation occurs before ordinary exit forwarding and source NAT. Matching is
limited to the tunnel interface plus an explicit generation-scoped selected
source set. The client's mesh source address is preserved into RustyDNS. A
parallel filter containment rule drops selected port-53 forwarding that is not
translated to the local endpoint. Thus deleting or failing to install the
translation does not create a plaintext escape while desired state is ON.

Redirect does not inspect the QNAME and is deterministic for UDP/TCP 53. It
does not affect non-selected peers, LAN traffic, host processes, another exit,
or traffic after signed OFF.

In v1 the local resolver and redirected flows use the signed IPv4 mesh
endpoint. Queries for AAAA records are normal DNS payloads and remain supported
over that transport. Selected IPv6 UDP/TCP port 53 and optional IPv6 853/known-
DoH bypass traffic are blocked unless a later protocol version supplies and
live-proves an exact signed IPv6 service endpoint and symmetric redirect. IPv6
is never allowed merely because the v1 redirect is IPv4-only.

### 7.3 Encrypted-DNS bypass options

`block_port_853=true` installs source-scoped blocks for TCP and UDP 853 before
general forward allows. The product labels this **DoT/DoQ port block**, not
encrypted-DNS interception.

A known-DoH feed is optional, default OFF, signed/versioned, digest-checked,
freshness-bounded, size-bounded, and replay-protected. Its prefixes are compiled
into generation-scoped destination sets. Rules block selected clients to those
destinations on TCP and UDP 443. Feed application is atomic; expiry while the
feature remains signed ON contains according to policy and exposes a reason,
rather than retaining an unbounded stale feed. The UI warns that shared CDN
addresses can block unrelated HTTPS and that unknown/private DoH endpoints will
remain reachable. Domain lists, TLS SNI guessing, and opportunistic packet
inspection are not accepted substitutes.

The feed artifact has a strict `KnownDohFeedV1` envelope: schema version,
publisher key ID, feed ID, strictly increasing generation, generated/expiry
times, nonce, bounded sorted unique IPv4/IPv6 prefixes, canonical payload
digest, and publisher signature. The exit accepts it only when the network
owner's signed policy names the exact feed ID/generation/digest and the
publisher key is locally trusted for this purpose. V1 rejects mesh, loopback,
link-local, multicast, unspecified, default-route, and prefixes broader than
the reviewed minimum specificity; cardinality and encoded bytes are bounded.
The control plane distributes the verified artifact so an exit need not fetch
an unsigned live list during activation. Publisher trust alone cannot enable a
feed, and network-owner policy alone cannot substitute different feed content.

When an enabled bypass control cannot be enforced—feed expiry, corrupt set,
missing 853/DoH rule, or precedence drift—the exit blocks the selected sources'
new forwarding to the physical egress interface, while retaining mesh/control
reachability. Merely containing port 53 would leave the failed DoH promise open.
This deliberately disruptive behavior is shown during enable confirmation and
status. Recovery requires a verified feed/rules generation or a newer signed
policy that disables the optional control; a local process cannot downgrade it.

## 8. Interaction with managed zone, killswitch, and exit NAT

The client Rustynet resolver is the sole `.rustynet` authority in tandem v1.
It applies the existing signed-zone schema, persisted anti-rollback watermark,
subject/assignment checks, record bounds, TTL bounds, and least-knowledge
projection. A client never receives an exit-wide or network-wide zone merely
because RustyDNS serves the exit.

Tandem rules are additive to the base DNS-fail-closed and killswitch posture.
They MUST NOT replace the current `block drop out quick all`/policy-drop
terminator, widen a tunnel or physical-interface pass, or make a broad
`accept`/`pass quick` precede the terminator. The RustyDNS upstream exception is
narrowly identified by service identity **and** destination endpoint; a port
alone is insufficient.

The redirected client packet terminates locally after destination translation,
so it does not traverse the ordinary exit masquerade/postrouting step. The
separate RustyDNS upstream request is host-originated and can leave only through
its service-identity exception. Ordinary forwarded non-DNS traffic continues
through existing exit forwarding and NAT. Translation, filter, and NAT state
are separately named and verified so evidence cannot confuse a present exit NAT
with a present tandem redirect.

Every supported OS gains a precedence evaluator that renders expected state,
reads live normalized state, and proves:

- selected DNS reaches only the exact local endpoint while healthy;
- selected direct port 53 cannot reach the physical interface;
- resolver upstream exceptions precede the terminal drop but are exact;
- optional 853/known-DoH blocks precede any relevant forward allow;
- ordinary exit NAT remains source-scoped and does not translate host-local or
  unrelated traffic; and
- the default-deny terminator remains reachable for general egress.

Presence-only substring checks are insufficient.

## 9. OS-specific enforcement and verification

All native mutations cross Rustynet's privileged boundary as typed, bounded
specifications. The privileged side revalidates fields and renders native
rules; it never accepts a shell command, executable path, free-form nft/PF/WFP
rule, or daemon-authored root rules file. Each OS backend has pure render and
normalize/evaluate functions, unit negative tests, an atomic apply path, and a
live read-back path.

### 9.1 Linux

**Achievability:** managed handoff and transparent redirect are achievable with
nftables, subject to real-node proof. The current helper admits only the local
loopback output redirect used by protected mode; tandem prerouting shapes are
not implemented and require new typed helper forms.

On a Linux **client**, the existing loopback DNS ownership remains: OS resolver
state points only to loopback, the generation-scoped nft output rule sends
loopback port 53 to the Rustynet resolver on `127.0.0.1:53535`, and that resolver
keeps `.rustynet` local while forwarding other names to the signed exit
endpoint. NetworkManager/systemd-resolved precedence and every active resolver
source are normalized/read back. The current environment assertion that a
loopback resolver is advertised is replaced by real UDP/TCP socket and query
proof. Disable re-derives the ordinary signed Rustynet DNS state; it does not
blindly restore a captured LAN resolver.

The Linux generation owns these logically separate objects:

- `inet rustynet_tdns_filter_g<N>`: selected IPv4/IPv6 source sets, endpoint
  input admission, direct port-53 containment, optional 853/known-DoH blocks,
  and exact RustyDNS upstream output exceptions;
- `ip rustynet_tdns_nat4_g<N>` and, when IPv6 exit service is supported,
  `ip6 rustynet_tdns_nat6_g<N>`: prerouting destination translation only; and
- the root-owned `TandemAppliedStateV1` journal tying names to the signed policy
  generation and digest.

The destination-translation chain uses `hook prerouting priority dstnat`. It
matches the Rustynet tunnel input interface, an explicit selected source set,
UDP/TCP destination port 53, and rewrites to the exact exit mesh address and
port 53. It does **not** use the existing `linux_dns_protect` output redirect,
which is for host-loopback DNS and never sees forwarded packets. It also does
not use an address-free nft `redirect`, because prerouting redirect would
encourage a wildcard listener. Exact DNAT keeps the advertised endpoint and
listener binding identical.

The filter rules accept direct managed queries and post-DNAT redirected queries
only when all of these match: tunnel input, selected source, exact service
address, UDP/TCP 53, active policy generation, and an atomic `service_ready`
verdict. The next rule drops selected source traffic to any other port-53
destination. When readiness fails, the verdict changes to drop in one nft
transaction while the direct containment rule remains. Source anti-spoofing in
the base WireGuard/peer dataplane is a prerequisite; the evaluator rejects a
source set broader than the signed explicit assignments.

When an enabled 853/known-DoH control is unready, a separate high-priority
verdict drops selected tunnel input forwarded to the physical egress interface.
It does not block mesh/control recovery traffic and cannot be bypassed by the
ordinary exit forward allow.

RustyDNS upstream egress is an output-chain exception keyed by the dedicated
service UID or cgroup plus exact destination address, transport, and port. The
service identity match and destination match are both mandatory. It precedes
the default-deny output terminator but cannot admit another UID, client-forwarded
traffic, an arbitrary destination on 443, or plaintext port 53. Endpoint-set
updates use a replace/swap transaction and bounded cardinality.

Apply ordering is: stage the new empty/contained filter objects; install the
exact service egress set; prove local readiness; atomically load translation,
ready admission, and bypass rules; read back all three tables; then mark the
generation prepared. The old generation remains until the new generation
passes. A failed read-back removes the new translation, retains or restores the
contained filter generation, and refuses capability publication.

Linux verification MUST include:

- normalized `nft -j list ruleset` structural comparison, including hook,
  priority, policy, set elements, UID/cgroup, endpoints, and verdict order;
- a precedence evaluator proving the selected port-53 drop remains reachable
  if the translation table is flushed;
- socket-owner/read-back proof of exact UDP and TCP binds and absence of a
  wildcard/LAN bind;
- UDP and TCP hard-coded resolver probes plus physical-interface packet capture
  proving no port-53 egress;
- encrypted-upstream capture proving only configured endpoints and no ECS;
- tamper tests deleting translation, widening a source set, replacing the UID,
  adding a broad 443 pass, and moving a pass above containment; and
- toggle-off/restart proof that no `rustynet_tdns_*` table, set, state, endpoint
  exception, journal generation, or client resolver assignment remains.

The existing `linux_dns_failclosed` and `linux_exit_dns_failclosed` stages stay
mandatory. Tandem evidence is additive and may not turn their current pass into
a waiver.

### 9.2 macOS

**Achievability:** managed handoff and PF `rdr` are designable, but transparent
redirect requires a new reviewed translation-spec kind, root-anchor wiring,
state cleanup, and real-node proof. Current `MacosPfLoadSpec` supports
killswitch, blind-exit, and ordinary exit-NAT rules; its exit-NAT variant
intentionally permits only `nat`, not `rdr`. The gap must be implemented rather
than bypassed with a daemon-authored PF file.

On a macOS **client**, `/etc/resolver/rustynet` continues to route only the
managed suffix to the loopback Rustynet resolver on port 53535. Tandem adds the
exact exit mesh address as the sole managed default DNS server through reviewed
SystemConfiguration/NetworkExtension APIs, not a best-effort
`/etc/resolv.conf` write. The endpoint route must use the Rustynet tunnel and
source mesh address. Application and verification read the effective resolver
graph with `scutil --dns`, cover every active network service and IPv4/IPv6
fallback source, and reject any competing default resolver. Disable restores
the re-derived ordinary Rustynet resolver graph after signed drain; a stale
hotel/LAN snapshot is not blindly replayed.

The macOS generation owns:

- a fixed parent/typed child tandem translation anchor, logically
  `com.rustynet/dns`, containing only reviewed `rdr` forms;
- generation-scoped tandem filter fields rendered through the same typed
  privileged helper path as the existing killswitch anchor;
- exact PF source tables or bounded inline rules derived from selected signed
  assignments; and
- a root-owned applied-state journal and tandem-labeled states.

The reviewed translation form is equivalent to:

```text
rdr on <tunnel> inet[6] proto { udp tcp } \
    from <selected-source> to any port 53 \
    -> <signed-exit-mesh-address> port 53
```

It is not accepted as free-form text. The helper derives anchor names and
renders only exact interface, address-family, source, target, and port fields.
It verifies the child anchor is actually referenced by the active root ruleset;
a populated but unreachable leaf anchor fails.

PF translation precedes filtering. The tandem filter therefore first passes
selected tunnel input whose translated destination is the exact local resolver
endpoint, then blocks selected tunnel input to every other UDP/TCP port-53
destination. The backend must live-prove whether macOS `pfctl -s rules` exposes
the translated tuple exactly as assumed; if not, a reviewed PF tag/state design
must carry the translation decision into filtering. This is a proof condition,
not permission to add a broad `pass in`.

Optional TCP/UDP 853 and known-DoH destination blocks precede the existing
tunnel-wide pass. RustyDNS encrypted-upstream egress is a PF `pass out quick`
restricted simultaneously to the RustyDNS service user, exact physical
interface, address family, upstream address, protocol, and port. The current
precedence evaluator treats a specific port or address as narrow; tandem extends
it to prove all resolver exception dimensions. `pass out quick on <physical>
all`, `pass ... port 443` without service user and destination, and any
`route-to`, `reply-to`, or `dup-to` remain escapes.

An enabled bypass-control failure installs a higher-precedence PF block for
selected mesh sources leaving the physical interface, while preserving
mesh/control recovery. It is evaluated before ordinary exit passes and is part
of the typed expected ruleset, not an ad hoc emergency rule.

The existing terminal `block drop out quick all` remains the last filter rule.
The ordinary `com.rustynet/nat` source-scoped exit-NAT anchor is not reused for
DNS and still contains only `nat` rules. A locally terminated redirected query
does not match that exit masquerade; the separate RustyDNS upstream flow uses
the exact service exception.

PF state can outlive a rule change. Every contain, endpoint rotation, scope
removal, and toggle-off transition kills only states bearing the tandem label or
exact old source/endpoint tuple through a typed helper operation. A generic PF
flush is forbidden. Removal order is translation/filter state, tandem child
anchor content/reference, endpoint exception, and applied journal, with live
proof after each safety-sensitive boundary.

macOS verification MUST include:

- root and child anchor reachability, normalized `pfctl` translation and filter
  read-back, exact ordering, and existing killswitch precedence evaluation;
- `pfctl -s state` proof that no disallowed old tandem state remains;
- UDP/TCP direct managed and hard-coded redirect probes from a real tunnel peer;
- simultaneous capture on tunnel and physical interfaces proving original
  port-53 destinations never leave and upstream DNS is encrypted;
- a translation-anchor flush tamper while the filter containment rule remains,
  proving silence rather than plaintext fallback;
- root-anchor omission, broad physical pass, wrong service user, stale source
  table, old PF state, and `rdr` target tamper negatives; and
- toggle-off, daemon restart, role demotion, and reboot residue proof for the
  child anchor, references, tables, states, tandem default-DNS service state,
  and journal, while the base `.rustynet` scoped resolver remains correct.

Existing `macos_dns_failclosed`, `macos_exit_dns_failclosed`, exit-NAT lifecycle,
and killswitch-precedence gates remain mandatory. The current macOS
`/etc/resolv.conf` write is best-effort and the scoped `/etc/resolver/rustynet`
owns only `.rustynet`; neither is evidence that general tandem handoff works.

### 9.3 Windows

**Achievability:** managed handoff is in scope using the Rustynet local resolver,
the tunnel, an exact RustyDNS listener, and WFP admission. Transparent redirect
is **not currently proven achievable by the Rustynet backend** and is a
release-blocking parity gap for `managed_redirect`.

On a Windows **client**, the existing root NRPT/loopback ownership remains the
default-DNS path. The Rustynet loopback listener on port 53 keeps `.rustynet`
local and forwards other names to the signed exit endpoint through the tunnel.
All active interface DNS lists, IPv4 and IPv6 sibling state, NRPT root rule,
route/source address, and RA-derived resolver paths are read back. An off-loopback
or competing resolver contains activation. Disable re-derives the ordinary
signed Rustynet DNS/NRPT state and removes only tandem-owned additions.

WinNAT's existing `New-NetNat` object provides ordinary source NAT for an
internal prefix. It is not evidence that arbitrary forwarded outbound UDP/TCP
port-53 traffic can be redirected into a local user-mode resolver while
preserving source identity and reverse state. `netsh interface portproxy` is
TCP-only and is not acceptable. WFP blocking filters are not equivalent to WFP
redirection. A safe Windows redirect likely requires a reviewed WFP callout at
the correct forwarding/packet layers, with a signed driver and a narrowly
defined user-mode control surface, or another Microsoft-supported primitive
that passes live source-identity and state tests. This design does not select an
unproven primitive.

Consequently:

- `mode=managed` MAY become Windows-supported after its complete stages pass.
- `mode=managed_redirect` MUST be rejected before mutation with
  `PLATFORM_REDIRECT_UNSUPPORTED` until the exact primitive, privilege boundary,
  crash behavior, IPv4/IPv6 behavior, and live evidence are reviewed.
- A network-wide `managed_redirect` policy cannot claim three-OS parity while
  Windows rejects it. Product UI must show the incompatible clients/exits before
  signing.
- It is forbidden to silently run managed-only under a signed
  `managed_redirect` policy.

For managed mode, WFP filters admit UDP/TCP 53 to the exact WireGuard adapter
address only from selected authenticated mesh sources and only to the RustyDNS
service AppId/service SID. All other access to that listener is blocked. Exact
encrypted-upstream WFP permits require RustyDNS AppId/service SID plus endpoint,
protocol, port, direction, and interface. Existing loopback DNS and root NRPT
ownership remain the client-host protection; they do not affect packets merely
forwarded by a Windows exit.

If an enabled Windows 853/known-DoH rule set is incomplete or stale, a
higher-weight WFP block contains selected sources' forwarding to the physical
egress interface while leaving authenticated mesh/control recovery reachable.

If a redirect callout is later approved, it must preserve the source mapping,
handle UDP and TCP symmetrically, run before WinNAT source translation, retain an
independent direct-port-53 containment filter, expose typed atomic generation
replace/remove operations, and have a fail-safe behavior when its service dies.
WFP filter IDs/provider/sublayer GUIDs and callout state become owned residue.

Windows verification MUST include:

- WFP provider/sublayer/filter enumeration by stable IDs, weights, conditions,
  AppId/service SID, interface, source set, destination, protocol, and port;
- exact UDP/TCP listener and adapter binding, with LAN/public negatives;
- managed client queries, encrypted physical capture, ECS absence, NodeId
  mapping, and RustyDNS failure containment;
- ordinary `Get-NetNat`/forwarding lifecycle proof remaining correct and
  separate from tandem filter evidence;
- service SID/AppId tamper, broad 443 permit, NRPT removal, stale identity,
  and role-conflict negatives; and
- toggle-off/restart/reboot proof that no tandem WFP object, endpoint exception,
  client assignment, NRPT addition, pipe ACL, or journal state remains.

## 10. Transactional lifecycle and recovery

### 10.1 Persistent state machine

Each node persists a small root-owned, atomic `TandemAppliedStateV1` containing
only policy/service IDs and digests, generation, phase, derived native object
IDs, RustyDNS boot/profile identity, and maximum client-assignment expiry. It
contains no QNAME, blocklist content, client public address, or key. The file is
opened without following symlinks, size/mode/owner checked, fsynced with its
parent, and replaced atomically. Native OS state remains the source of observed
truth; the journal tells reconciliation what Rustynet intended to own.

The phases are `off`, `preparing_contained`, `prepared`, `active`,
`runtime_contained`, `draining`, `removing`, and `residue_error`. A transition
is complete only after live read-back and a durable journal update. Startup
recomputes desired state from verified signed control data, enumerates native
state, and reduces the pair; it never trusts a journal phase alone.

### 10.2 Enable: deploy before signed use

1. Validate the signed prepare intent's signature/quorum, schema, time, network,
   membership epoch, generation/digest watermark, exit assignment, proposed
   service role, scope digest, OS mode support, and `blind_exit`
   incompatibility. No mutation occurs on a reducer rejection, and a prepare
   intent grants no client access.
2. Validate the local RustyDNS profile and authenticated channel. Install only
   generation-scoped client containment and the exact process/upstream egress
   set. Client endpoint admission remains closed.
3. Supply the bounded identity snapshot. Challenge the current RustyDNS boot,
   validate all readiness predicates, run fixed UDP/TCP block canaries, and
   confirm physical capture policy.
4. Atomically install endpoint admission, port-53 translation when requested,
   optional bypass blocks, and ready verdict. Read back normalized state and
   run the precedence evaluator.
5. The exit signs a bounded prepared receipt containing network, policy
   generation/digest, service instance/profile digest, boot ID, OS backend, and
   observed-state digest. It carries no health detail or query data.
6. Only after the network authority verifies the receipt does it sign/publish
   the active capability/policy used by clients. This is D13's
   deploy-before-signed-bundle ordering and closes unordered distribution: the
   exit dataplane is safe before a client can accept the handoff.
7. Clients validate the active state, install the local forwarding assignment,
   read back OS resolver state, and report privacy-safe application status.

If any step fails, the new generation remains contained, its activation receipt
is not emitted, the prior good generation stays active when compatible, and the
operator gets a stable reason. A first enable has no prior good generation, so
DNS remains under the ordinary Rustynet posture and the policy is not activated.

### 10.3 Runtime health failure

Rustynet polls the local authenticated readiness contract with bounded jitter
and deadline, and independently samples the fixed UDP/TCP canaries. A closed
reason enum prevents error-text injection. Any mandatory failure atomically
changes endpoint admission to drop while leaving selected direct-port-53
containment in force. Existing tandem states are killed narrowly. Clients see
timeouts/SERVFAIL and `ON / contained`; they never receive a pre-tunnel resolver
or an unsigned fallback.

Recovery requires the same current-boot challenge, fresh identity generation,
fresh policy/blocklist/upstream proof, both transport canaries, native read-back,
and a configurable success hysteresis. A single successful packet cannot reopen
the path. Failure hysteresis may reduce flapping but MUST NOT extend a signed
expiry, blocklist freshness limit, identity expiry, or upstream-readiness hard
deadline.

### 10.4 Signed toggle-off and scope removal

1. The authority publishes a higher-generation signed policy with
   `enabled=false` or a reduced scope. Clients remove affected forward
   assignments first and restore the ordinary Rustynet DNS posture. They never
   restore a captured hotel/LAN resolver while protected mode remains active.
2. The exit enters `draining`. It keeps RustyDNS endpoint service and existing
   containment available until all online affected clients acknowledge the
   removal or the maximum signed assignment lease expires. Offline clients are
   bounded by that expiry; no unbounded acknowledgement wait exists.
3. The exit kills tandem connection/PF/WFP state, atomically removes redirect
   and optional bypass rules for the removed scope, then removes endpoint
   admission and exact RustyDNS upstream exceptions that no remaining policy
   uses. An independently operated RustyDNS process may keep running; Rustynet
   does not stop it merely because tandem is OFF.
4. The backend reads native state and proves the owned generation absent. It
   removes the journal only after that proof and emits a signed removal receipt.
   Any leftover object produces `ERROR / residue`, keeps the narrowest safe
   containment available, and blocks re-enable.

The operator cannot bypass the drain with an implicit timeout or process kill.
An emergency `contain now` remains available, but it causes outage rather than
fallback. Clock rollback, an untrusted wall clock, or inability to establish
lease expiry holds containment and requires time recovery/operator repair.

### 10.5 Crash, restart, reboot, and role changes

- **RustyDNS crash:** redirect/admission changes to or remains drop; direct
  port-53 containment and base killswitch persist. RustyDNS upstream exception
  is inert because it is service-identity scoped and is removed after the
  failure grace/read-back.
- **Rustynet daemon crash:** native rules persist. No health success is invented.
  On restart, observed-state reconciliation happens before any ready verdict is
  reopened. A stale RustyDNS boot ID forces fresh challenge/canaries.
- **Privileged helper crash:** no partially decoded spec is applied. Atomic
  native transactions either install a verified generation or leave the prior
  safe generation. The daemon reports contained.
- **Host reboot:** services start with client endpoint admission contained.
  Signed state, journal, native state, RustyDNS current boot, identity snapshot,
  and canaries are reconciled before opening. Persistent WFP/native objects are
  enumerated even when the journal is missing.
- **Exit demotion/revocation or client exit change:** treated as a signed scope
  removal. Service admission cannot outlive exit capability. A client cannot
  keep an assignment to a non-selected exit.
- **`blind_exit` transition:** the signed reducer rejects the combination before
  planning any service deploy or OS operation. Becoming `blind_exit` requires
  the existing destructive re-enrollment flow and tandem residue proof first.
- **Firewall/rule tamper:** drift causes containment. Automatic repair uses the
  last accepted signed generation only; it never broadens scope from observed
  state.

## 11. Failure semantics and operator-visible reasons

| Failure | Enforced behavior | Operator/client signal |
|---|---|---|
| Invalid/replayed/expired signed policy | Reject before mutation; current safe generation remains or contains at expiry | `SIGNED_POLICY_INVALID`, `REPLAY`, `SIGNED_POLICY_EXPIRED` |
| Exit/service/assignment mismatch | Reject before mutation | `ASSIGNMENT_MISMATCH` |
| `blind_exit` conflict | Reject before lifecycle planning | `BLIND_EXIT_CONFLICT` |
| Unsupported OS mode | Reject before mutation; no downgrade | `PLATFORM_REDIRECT_UNSUPPORTED` |
| Local channel auth/version failure | Endpoint admission drop | `LOCAL_AUTH_FAILED`, `PROTOCOL_INCOMPATIBLE` |
| RustyDNS absent/crashed/new boot | Endpoint admission drop; direct 53 contained | `RUSTYDNS_UNREACHABLE`, `BOOT_CHANGED` |
| UDP or TCP listener/canary failure | Both transports contained | `LISTENER_UNREADY`, `CANARY_FAILED` |
| Blocklist missing/stale/wrong digest | Contained | `BLOCKLIST_UNREADY` |
| Encrypted upstream/DNSSEC/ECS/fail-closed mismatch | Contained | `UPSTREAM_UNREADY`, `PROFILE_MISMATCH` |
| Identity snapshot stale/unknown source | Affected client refused; systemic mismatch contains generation | `IDENTITY_STALE`, `UNKNOWN_CLIENT` |
| Known-DoH feed or enabled bypass rule stale/missing | Selected new physical egress contained; mesh/control remains; never silently drops the control | `DOH_FEED_STALE`, `BYPASS_RULE_DRIFT` |
| Native apply/read-back/precedence drift | Retain/restore containment; no activation receipt | `RULE_APPLY_FAILED`, `RULE_DRIFT` |
| Toggle-off residue | Re-enable blocked; safe narrow containment retained | `RESIDUE` with object class, never raw command output |
| Control-plane partition before expiry | Last valid state continues | `CONTROL_STALE_WARNING` |
| Control-plane partition at expiry | Contained | `SIGNED_POLICY_EXPIRED` |
| Untrusted clock/rollback | Contained; no lease expiry inference | `CLOCK_UNTRUSTED` |

State changes emit privacy-safe audit events containing timestamp, NodeId only
where already authorized, policy/service opaque IDs, generation/digests,
previous/new state, reason code, OS backend, and evidence manifest ID. They omit
QNAME, response content, client public address, blocklist entries, upstream
credentials, socket challenge, and free-form peer input.

## 12. Security controls: enforcement and verification

This table is normative. A control without both an enforcement owner and an
independent verification path is incomplete.

| ID | Control | Enforcement | Verification and negative proof |
|---|---|---|---|
| TDNS-01 | Signed, fresh, replay-protected default-off activation | Rustynet control reducer; persisted generation/nonce/payload-digest watermark; exact network and epoch binding | Canonical fixture tests; bad signer/quorum, bit flip, stale generation, reused nonce with different digest, cross-network, future/expired time, and restart rollback tests; zero native calls asserted |
| TDNS-02 | Exit and client scope binding | Reducer joins policy, capability, signed exit assignments, and explicit peer/address set | Property tests across reordered membership; wrong exit, unassigned client, duplicate NodeId/address, CIDR widening, and client-roam tests; live unselected-peer denial |
| TDNS-03 | `blind_exit` incompatibility | Membership/capability validator and transition planner reject `serves_dns` plus `blind_exit` | Unit transition matrix, signed snapshot negative, `--node` live no-mutation proof, and pre/post native-state digest equality |
| TDNS-04 | Exact listener and admission | RustyDNS exact mesh bind; Rustynet tunnel/source/endpoint firewall; unknown sources fail closed | UDP/TCP socket enumeration; LAN/public/unselected probes; wildcard bind/profile negative; source-spoof negative and identity mismatch counter |
| TDNS-05 | Local authenticated readiness | UDS peer credentials/named-pipe ACL and token; fresh challenge, boot/service/profile binding; bounded protocol | Wrong UID/SID, stale response, replayed challenge, wrong boot/instance, malformed/oversized frame, version downgrade, symlink/ACL tests; existing HTTP `/health` deliberately insufficient test |
| TDNS-06 | Truthful DNS readiness | RustyDNS compound readiness plus UDP/TCP fixed block canaries and encrypted upstream/DNSSEC probe | Kill listener transport separately; empty/stale blocklist; upstream blackhole; DNSSEC failure; ECS/profile toggle; cached-age expiry; ensure each moves ready to contained |
| TDNS-07 | `.rustynet` single authority and least knowledge | Client Rustynet signed-zone resolver; RustyDNS tandem namespace guard before recursion; scoped identity export | Query managed records through client; query same suffix directly at tandem endpoint and require local refusal; physical capture proves no suffix leak; unrelated record/name negative |
| TDNS-08 | Deterministic plain-DNS containment | OS prerouting DNAT/PF rdr/future WFP redirect plus independent selected forward drop; UDP/TCP symmetry | Hard-coded UDP and TCP probes; flush redirect while leaving filter; physical capture must show zero port 53; wrong target/source/interface/order negatives |
| TDNS-09 | No generic encrypted-DNS claim | Optional 853 blocks and signed known-DoH IP sets only; UI/CLI semantics fixed | Port 853 TCP/UDP probes; listed and unlisted DoH probes; shared-CDN warning snapshot; docs/status test never emits “all encrypted DNS blocked” |
| TDNS-10 | DoH feed integrity and bounded collateral | Signed generation/digest/expiry, bounded prefixes, atomic swap, default OFF; selected physical-egress containment on required-control failure | Signature/replay/expiry/oversize/private-broad-prefix policy tests; listed destination blocked, unlisted reachable while healthy; feed/rule failure blocks selected physical egress; old set absent after rotation/off |
| TDNS-11 | Killswitch and NAT precedence | Typed native renderers; exact upstream service exception; base terminator retained; translation before ordinary NAT | Structural normalized evaluator, tamper-reorder/widen tests, existing OS precedence stages, simultaneous tunnel/physical capture, NAT source-scope proof |
| TDNS-12 | Privileged-boundary least authority | Helper accepts only typed bounded tandem specs and re-renders rules/derives owned names | Unknown/cross-kind/extra/oversized token tests; free-form rule, shell metacharacter, foreign table/anchor/GUID, arbitrary executable/path, broad flush, and daemon-authored root file rejected |
| TDNS-13 | Transactional apply and rollback | Generation replacement, contained prepare, durable journal, native read-back, prior-good retention | Fault injection at every mutation/journal boundary; process kill/restart; old/new generation ambiguity must contain; no activation receipt on partial apply |
| TDNS-14 | Toggle-off and crash residue | Signed tombstone/drain, bounded client leases, typed state kill, native enumeration, removal receipt | Repeated ON/OFF, scope shrink, exit change, Rustynet/RustyDNS/helper kill, reboot, demotion; assert no assignment/table/anchor/state/filter/exception/journal residue |
| TDNS-15 | Encrypted upstream only | RustyDNS DoH/DoQ/ODoH, TLS certificate verification, DNSSEC, ECS stripping, fail closed; exact service egress endpoints | Physical pcap contains no UDP/TCP 53 and only configured encrypted endpoints; invalid certificate, plaintext config, ECS, upstream loss, and endpoint rotation negatives |
| TDNS-16 | Privacy-safe identity, logs, and evidence | Authenticated address→NodeId snapshot; RustyDNS anonymization/query-log defaults; Rustynet aggregate-only audit; synthetic lab names | Log/metric/artifact scanners for raw QNAME, public client IP, key/secret patterns; NodeId self-assertion rejected; retention/restart tests; evidence permissions verified |
| TDNS-17 | Resource and amplification bounds | RustyDNS per-source/NodeId rate limits, query/packet/TCP/time bounds, cache and request coalescing; bounded control messages/sets | Flood, slow TCP, oversized DNS/control frame, high-cardinality peer/feed, cache stampede, cancellation, and memory/FD plateau tests; recovery after load |
| TDNS-18 | Standalone independence | Feature-gated/adaptor lifecycle only when signed tandem enabled; no shared write ownership or runtime discovery dependency | Rustynet full suites without RustyDNS installed; RustyDNS full suites without Rustynet; install/start/upgrade/offline tests; no integration IPC/file touched while OFF |
| TDNS-19 | Honest platform capability | Mode-specific platform capability gate; no fallback from `managed_redirect` to `managed` | Windows pre-mutation refusal with native-state digest unchanged; support-matrix/CLI tests; release ledger cannot translate unsupported into pass |
| TDNS-20 | Observable failure without sensitive detail | Closed reason codes, state machine, aggregate metrics, bounded local status | Snapshot/golden tests for every failure; error-injection cannot add raw peer text; alert fires on contained/residue; client message remains actionable |

## 13. User and operator experience

The feature should feel like one product without hiding the security boundary.
Illustrative CLI shape (exact command naming may follow existing CLI
conventions, but semantics are frozen):

```text
rustynet dns tandem enable \
  --exit <node-id> \
  --mode managed \
  --scope all-clients-using-exit

rustynet dns tandem enable \
  --exit <node-id> \
  --mode managed+redirect \
  --scope-file <explicit-node-ids> \
  --block-dot-doq

rustynet dns tandem status --exit <node-id>
rustynet dns tandem contain --exit <node-id>
rustynet dns tandem disable --exit <node-id>
```

Enable preflight reports, before requesting signatures:

- exit role, OS, mesh address, service/protocol/profile compatibility;
- whether the chosen mode is supported on every affected platform;
- selected client count and any client assigned to another exit;
- exact RustyDNS readiness predicates, without querying raw user names;
- expected signed policy expiry/assignment drain bound; and
- optional bypass effects. Enabling known-DoH blocking requires an additional
  explicit confirmation showing feed identity, freshness, prefix count, and the
  shared-hosting collateral warning.

No process auto-discovery turns tandem ON. Detection MAY offer a setup hint:
“RustyDNS found locally; validate tandem profile,” but capability publication
still follows the signed workflow. The setup wizard tests UDP and TCP, exact
bind, block canary, encrypted upstream, DNSSEC, ECS stripping, namespace guard,
identity channel, and OS readiness. It gives remediation tied to stable reason
codes rather than “DNS failed.”

Status is a compact state summary:

```text
Tandem DNS       ON / healthy
Exit             exit-a (linux, 100.64.0.7)
Mode             managed + port-53 redirect
Scope            12 clients using this exit
RustyDNS         boot 8f…; profile matches; UDP/TCP ready
Policy           generation 42; expires in 47m
Blocklist        generation 918; fresh 3m
Upstream         DoQ; last encrypted probe 12s
Bypass control   853 blocked; known-DoH OFF
Enforcement      nft generation 42 verified; no drift
```

Contained status leads with impact and remedy:

```text
Tandem DNS       ON / contained
Impact           Selected clients have no external DNS; plaintext fallback is blocked
Reason           BLOCKLIST_UNREADY (last accepted snapshot expired 2m ago)
Next             Repair RustyDNS blocklist refresh, then run `rustynet dns tandem check`
Safety           Port 53 remains contained; .rustynet stays locally available
```

Client UI distinguishes `.rustynet` availability from external DNS. It may say
“Secure DNS at exit unavailable; external names are paused to prevent a DNS
leak,” and MUST NOT recommend changing to `8.8.8.8`. Scope additions/removals,
feed changes, containment, and disable are auditable signed operations. Status
is available locally when the control plane is unreachable.

## 14. Verification strategy

### 14.1 Rust unit, property, integration, and fault tests

All new production logic and all real-hardware stage control are Rust. Shell
wrappers may only invoke an already reviewed Rust entry point and cannot contain
the test logic.

Required Rust test groups:

1. Strict canonical encode/decode and cross-repository golden fixtures for
   `ServiceCapabilityV1`, `TandemDnsPolicyV1`, `ManagedDnsAssignmentV1`,
   `PeerIdentitySnapshotV1`, `TandemDnsReadinessV1`, receipts, and journal.
2. Signature/quorum, replay watermark, expiry, clock, membership epoch, scope,
   address assignment, role conflict, protocol range, and policy-generation
   properties.
3. State-machine model tests covering every event in every phase, idempotence,
   duplicate delivery, reorder, prior-good retention, and crash at every durable
   boundary.
4. Pure native render/normalize/evaluate tests with malicious widening,
   ordering, foreign ownership, unknown field, cardinality, Unicode/control
   character, and cross-family cases.
5. Privileged-helper request-schema positive and exhaustive near-miss negative
   tests. Direct/root and helper IPC paths must enforce the same schema.
6. Authenticated local-channel credential/ACL, challenge replay, boot change,
   timeout, truncation, oversized frame, slow peer, cancellation, and protocol
   negotiation tests.
7. Resolver behavior tests for `.rustynet` guard, NodeId mapping, UDP/TCP,
   truncation fallback, block policy, cache separation, ECS stripping, DNSSEC,
   upstream failure, endpoint rotation, and no plaintext fallback.
8. Privacy scans across logs, metrics, status, receipts, manifests, and failure
   strings; synthetic QNAME/public-IP/secret markers must not escape the
   permitted test sink.
9. Standalone, packaging, startup, upgrade, and feature-OFF tests in both
   repositories.

Each repository carries identical v1 wire fixtures plus a manifest of fixture
digests. CI in both repositories parses the other-product fixtures as opaque
contract vectors; no runtime crate or source checkout dependency is introduced.
An intentional wire change requires a new version and fixtures, not an in-place
edit.

### 14.2 RustyDNS compose e2e

The RustyDNS repository owns a Compose-based integration e2e, orchestrated by a
Rust test binary. It contains an exit namespace/host with RustyDNS, a Rustynet
client, a controlled encrypted DNS upstream, and capture points on the client
tunnel and exit physical side. It proves:

- clean managed query is blocked/allowed per deterministic test policy;
- `.rustynet` is answered client-side and never reaches RustyDNS/upstream;
- hard-coded UDP and TCP DNS are redirected and policy-applied;
- upstream exchange uses the selected encrypted transport, validates DNSSEC,
  contains ECS, and sends no plaintext port 53;
- RustyDNS stop, upstream stop, blocklist expiry, identity expiry, invalid
  readiness, and translation deletion fail closed;
- signed OFF drains and restores ordinary standalone behavior without residue;
  and
- RustyDNS-alone and Rustynet-alone Compose profiles still work.

The Compose lane is necessary but not platform evidence. It cannot close the
macOS PF or Windows WFP cells.

### 14.3 Rust `--node` live-lab stages

The only accepted real-hardware path is the existing Rust `--node` engine. The
feature adds these focused stages for each applicable OS exit and a real peer:

| Stage | Required proof |
|---|---|
| `rustydns_tandem_preflight` | Clean OFF baseline; signed assignments; exact versions/profile; RustyDNS exact binds; no tandem native residue; clocks trusted |
| `rustydns_tandem_managed` | Client OS→local stub→tunnel→exit RustyDNS for UDP/TCP; block and allow canaries; NodeId mapping; `.rustynet` local; roaming-route equivalent; no physical port 53 |
| `rustydns_tandem_redirect` | Hard-coded distinct resolver destinations over UDP/TCP become local RustyDNS queries; original destinations absent on physical capture; unselected peer unaffected; translation-flush containment negative |
| `rustydns_tandem_bypass_blocks` | TCP/UDP 853 blocked when selected; signed listed DoH endpoints blocked; unlisted endpoint behavior proves bounded claim; OFF case restores reachability |
| `rustydns_tandem_failclosed` | Kill RustyDNS; break one listener; stale blocklist/identity/policy/feed; blackhole upstream; corrupt readiness; remove/widen/reorder native rule; every case observable and leak-silent |
| `rustydns_tandem_lifecycle` | Repeated ON/OFF, scope add/remove, exit roam/change, endpoint rotation, RustyDNS/Rustynet/helper restart, abrupt kill, role demotion, and reboot; native/client/journal residue zero |
| `rustydns_tandem_blind_exit_denied` | Signed conflicting role/policy rejected before mutation; native-state digest and service inventory unchanged |
| `rustydns_tandem_standalone` | Rustynet exit with no RustyDNS and RustyDNS with no Rustynet; existing managed-DNS, DNS-fail-closed, exit-NAT, and killswitch stages still pass |
| `rustydns_tandem_capacity` | 1/64/maximum-supported selected peers; cache cold/warm, UDP/TCP mix, churn, failure recovery, CPU/RSS/FD/latency/throughput evidence |

Linux and macOS require every base and redirect stage. Windows may pass managed
and standalone stages independently, but `rustydns_tandem_redirect` remains a
release-blocking **not proven** cell until an approved implementation passes; a
pre-mutation unsupported refusal is a correct safety result, not parity proof.

Each network proof captures concurrently at the client tunnel, exit tunnel,
and exit physical interface with synthetic reserved test names only. The stage
actively attempts UDP and TCP direct DNS to a controlled off-tunnel target and
fails if it did not attempt the path. Silence without an attempted probe is not
proof. An allowed synthetic query proves the resolver path remains usable so a
blanket outage cannot pass the block test.

### 14.4 Evidence and ledger contract

Each stage emits a schema-versioned manifest with repository commits, binary
digests, OS/build, node roles, sanitized opaque IDs, signed policy/service
generation and payload digests, RustyDNS profile/boot/blocklist generations,
native observed-state digest, exact subcheck booleans, monotonic timestamps,
artifact hashes, and overall result. Failure records the closed reason code and
the failed predicate. Secrets and live user QNAMEs are prohibited.

Artifacts include sanitized signed fixtures, readiness predicate report,
normalized native state, socket/service ownership, probe transcripts, synthetic
pcaps or derived capture reports, state-machine timeline, performance samples,
and residue report. Raw synthetic pcaps are permission-restricted and retained
only under the lab artifact policy. The Rust stage validates artifact schema and
hashes before writing the standard `--node` ledger row; an external script may
not manufacture a pass.

The stage results and run-matrix columns remain `not_run` until real evidence
exists. Implementation PRs must not prefill pass values. Existing
`managed_dns`, `dns_failclosed_check`, exit-DNS-fail-closed, NAT lifecycle, and
killswitch-precedence rows must continue passing in the same run.

## 15. Efficiency, scale, and reliability budgets

Tandem adds one local client stub hop already present in managed DNS, one tunnel
hop already selected for exit traffic, and a resolver policy/cache step. It must
avoid per-query control-plane calls, disk writes, subprocesses, locks shared by
all clients, and copies of the whole mesh zone.

Implementation requirements:

- immutable/atomically swapped policy, identity, blocklist, endpoint, and native
  generation snapshots on query paths;
- O(1) mesh-address/NodeId and exact-domain policy lookup, bounded suffix work,
  cache key separation by policy dimensions, and request coalescing;
- bounded UDP packet, TCP connection/query, control-frame, client, policy,
  endpoint, feed-prefix, cache, log, and evidence cardinalities;
- monotonic deadlines, cancellation propagation, bounded connect/query/reload
  timeouts, and jittered health/reconcile polls;
- no full native ruleset rewrite on each query or health poll; only generation
  changes or atomic ready-verdict changes mutate the dataplane;
- no synchronous blocklist fetch or zone parse on the DNS query path; and
- graceful overload that rate-limits/refuses and remains fail closed rather
  than queueing unbounded work.

Before release, the live capacity stage establishes platform baselines on the
same hardware. At minimum it reports p50/p95/p99 cold and warm latency,
successful queries/s, cache hit/coalescing ratios, CPU, RSS, allocation/FD/socket
plateaus, rule-apply time, health-containment time, and recovery time for 1, 64,
and the supported maximum peer count. Release gates are:

- zero plaintext port-53 packets and zero out-of-scope admissions at every load;
- no unbounded growth after a sustained load plus idle/GC interval;
- tandem idle control work below 5% of one core on the lowest supported node;
- steady-state resolver throughput no more than 10% below RustyDNS standalone
  with the same DNS policy and upstream on the same node;
- warm-cache p95 added latency no greater than 5 ms or 10% over the comparable
  RustyDNS-through-tunnel baseline, whichever allowance is larger; and
- containment completes within one configured health deadline and never later
  than the shortest signed freshness deadline.

If a platform cannot meet a budget, the evidence and revised budget require
explicit review; the implementation may not silently increase timeouts or
reduce security probes.

## 16. Repository ownership and implementation work map

### 16.1 Rustynet repository

Rustynet implementation work includes:

- add `Dns` to `rustynet-control::role_presets::ServiceKind`, add the signed
  service-hosting capability, lifecycle mapping, transition planning, and
  membership validation that inherits the existing service-hosting versus
  `blind_exit` prohibition;
- implement the strict signed capability/policy/assignment schemas, persisted
  digest-bearing anti-rollback state, deterministic reducer, prepared/removal
  receipts, and contract fixtures;
- extend the local resolver from mesh-only refusal to signed per-exit forwarding
  while retaining `.rustynet` authority and fail-closed behavior;
- implement the authenticated readiness/identity client and privacy-safe status;
- add a tandem lifecycle/reconcile module rather than folding cross-product
  state ambiguously into local `linux_dns_protect`;
- add typed Linux nftables, macOS PF, and Windows WFP helper specs, renderers,
  evaluators, fault injection, state cleanup, and applied journal;
- integrate ordering with `phase10`, daemon startup/reconcile, exit NAT,
  killswitch, role transition, shutdown, protected DNS, and endpoint rotation;
- expose signed toggle/preflight/status/contain/disable through CLI and existing
  control surfaces with authorization, CSRF/MFA/audit requirements matching
  other security-sensitive network changes; and
- implement Rust unit/integration tests, Rust `--node` stages, manifests,
  ledger columns, docs, and support-matrix truth.

The existing evidence-producer files inspected for this design remain useful
verification inputs, but implementation belongs in reviewed runtime apply paths
and the privileged boundary. A report generator is not an enforcement owner.

### 16.2 RustyDNS repository

RustyDNS implementation work, to be performed in that repository under its own
review, includes:

- a tandem profile with exact mesh UDP/TCP bind validation and wildcard/LAN
  rejection;
- listener-specific `.rustynet` refusal before recursive resolution, allowing a
  separate loopback standalone authority profile if desired;
- the OS-authenticated bounded local readiness/identity server and v1 contract
  fixtures;
- truthful compound readiness for listener, namespace, fail-closed, ECS,
  DNSSEC, encrypted upstream, blocklist freshness/digest, identity generation,
  and fixed canaries;
- runtime NodeId matching from the authenticated Rustynet snapshot, replacing
  the current tandem-inadequate manually keyed client-IP policy path;
- secure encrypted-upstream bootstrap/rotation that cannot recurse through the
  resolver it serves, while retaining certificate verification and TLS 1.3;
- service sandbox/UID/SID definitions usable by exact Rustynet firewall rules,
  bounded metrics/reasons, and privacy regression tests; and
- the Rust-orchestrated Compose e2e and standalone regressions.

RustyDNS does not need Rustynet to start in standalone mode, and Rustynet does
not vendor, link, discover, or require a RustyDNS binary when tandem is OFF.

### 16.3 Frozen cross-repository artifacts

The shared contract consists only of this versioned semantic specification,
canonical fixtures and their digest manifest, closed enums, fixed canaries,
and the evidence schemas. Each repository implements and tests its side. There
is no shared writable directory, database, log, key, native-rule file, or
runtime library. Cross-repository CI may fetch/version the public fixtures, but
release packages remain standalone.

## 17. Rollout and release gates

1. **Contract freeze:** ratify v1 schemas, fixtures, reason codes, canaries,
   limits, ownership, and downgrade rules in both repositories.
2. **RustyDNS readiness/identity profile:** land exact bind, namespace guard,
   NodeId mapping, truthful readiness, upstream bootstrap, privacy tests, and
   Compose e2e while Rustynet toggle remains unavailable.
3. **Linux managed and redirect:** implement typed nftables and lifecycle; pass
   all unit/fault/Compose/Linux `--node` stages plus existing DNS/NAT/killswitch
   stages. Keep user toggle behind an experimental signed capability.
4. **macOS managed and redirect:** implement typed PF rdr/root wiring, filter
   precedence, exact upstream user rule, state cleanup; pass all macOS stages.
5. **Windows managed:** implement exact listener/WFP/service identity path and
   pass managed/failure/lifecycle/standalone stages. Do not advertise redirect.
6. **Windows redirect:** select and security-review a supported primitive,
   implement its signed-driver/privilege/lifecycle contract, and pass redirect,
   tamper, reboot, and capacity stages. Until then, three-OS redirect parity is
   blocked.
7. **General availability:** default may change only by a separate decree after
   multi-run stability. This design keeps default OFF even after first proof.

No phase may waive an earlier security stage. A feature flag can hide unproven
work; it cannot turn `not_run`, skipped, simulated, or unsupported into pass.

## 18. Definition of done

The decree is satisfied only when all of the following are true:

- `dns` is a first-class signed service kind with deploy-before-sign ordering,
  per-exit toggle, explicit scope, strict replay/freshness, and `blind_exit`
  rejection.
- Managed handoff preserves Rustynet `.rustynet` ownership and gives selected
  clients RustyDNS blocking, encrypted upstream, DNSSEC, and ECS stripping on
  Linux, macOS, and Windows.
- Transparent UDP/TCP port-53 redirect is implemented and real-node-proven on
  Linux, macOS, and Windows, or the product explicitly remains pre-GA for that
  mode. Managed-only Windows behavior cannot satisfy redirect parity.
- RustyDNS absence, crash, stale blocklist/identity/policy/feed, upstream loss,
  protocol mismatch, rule drift, and partial apply all produce observable
  containment with zero plaintext DNS fallback.
- Optional 853/known-DoH controls are described and tested within their honest
  limits; no arbitrary-DoH claim appears.
- Every security control in section 12 has unit/negative and applicable live
  evidence, and every native mutation crosses a typed least-authority boundary.
- Toggle-off, scope change, role demotion, exit change, crash, restart, and
  reboot prove zero owned residue across client state, native rules/states,
  service exceptions, IPC/identity state, and journal.
- RustyDNS-alone and Rustynet-alone install/start/upgrade/functional suites pass
  with no cross-product dependency.
- Existing managed-DNS, DNS-fail-closed, exit-DNS-fail-closed, NAT lifecycle,
  killswitch precedence, and platform suites remain green.
- Compose e2e and every applicable Rust `--node` ledger cell carry validated,
  hashed, privacy-safe evidence; no hand-edited pass is accepted.

## 19. Empirical blockers, not open semantics

The intended semantics and ownership are frozen above. Three implementation
questions require evidence rather than design-by-assumption:

1. **OPEN: macOS PF tuple/tag behavior.** macOS must live-prove the post-`rdr`
   tuple/tag behavior used by its exact
   filter and root-anchor reachability. Failure requires a reviewed narrow PF
   design, not a broad pass.
2. **OPEN: Windows transparent redirect primitive.** Windows needs an approved
   transparent forwarding redirect primitive with
   UDP/TCP, source identity, fail-safe lifecycle, signed distribution, and real
   hardware proof. WinNAT presence alone does not answer this.
3. **OPEN: RustyDNS upstream bootstrap.** RustyDNS needs an encrypted-upstream
   bootstrap/rotation mechanism that does
   not loop through itself and can be expressed as exact service firewall
   endpoints without weakening TLS hostname verification.

Each blocker fails closed and is visible in the support matrix. None permits a
silent fallback, a wildcard listener, generic physical-interface egress, or a
claim of parity before evidence exists.
