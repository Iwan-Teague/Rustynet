# Anchor Enrollment-Endpoint Enforcement: Design and Implementation (2026-08-27)

- Date: 2026-08-27
- Status: active — design + first enforcement point landed on `work/d3-anchor-enrollment`; the LAN listener half is an owner decision (§7) and is NOT implemented here.
  - **Correction 2026-08-27 (`work/enrollment-listener`):** the owner sanctioned the listener build as a phase-1 change; §7 item 1 has landed there (pending the independent adversarial review pass the bundle-pull precedent requires before LAN exposure is used in anger). See the dated notes in §7.
- Owner: Rustynet
- Parent doc: [`AnchorNodeRoleDesign_2026-05-21.md`](./AnchorNodeRoleDesign_2026-05-21.md) §4 (`anchor.enrollment_endpoint`), §5.2, §8.
- Precedent followed: [`AnchorBundlePullAttestationSecurityReview_2026-07-20.md`](./AnchorBundlePullAttestationSecurityReview_2026-07-20.md) and the bundle-pull enforcement code it produced.
- Defect ID: **D-3 — `anchor.enrollment_endpoint` has zero runtime enforcement.**

---

## 1) The defect, verified against the code

`RoleCapability::AnchorEnrollmentEndpoint` (`crates/rustynet-control/src/roles.rs:15`) is
parsed (`:67`), rendered (`:43`), classified as an anchor sub-capability (`:90`), and shipped
in `ANCHOR_CAPABILITIES` (`:109`) so every anchor and admin node advertises it in signed
membership. A full-repository search for that variant before this change returned **only**
declarative sites: the enum itself, the `role_presets` mirror, the lab's expected-capability
tables, and one membership-validation combination test. There was no site anywhere that read
the capability and changed runtime behaviour because of it.

Contrast the three sibling anchor sub-capabilities:

| Capability | Runtime surface before this change |
|---|---|
| `anchor.bundle_pull` | `bind_anchor_bundle_pull_listener` / `poll_anchor_bundle_pull_once` / `handle_anchor_bundle_pull_stream` (`crates/rustynetd/src/daemon.rs`), with a per-request re-read of signed membership at `daemon.rs:1323` that refuses to serve once the capability is revoked. Live-proven on Linux anchors by `anchor_validation`. |
| `anchor.gossip_seed` | `gossip_runtime` seed selection. |
| `anchor.port_mapping_authoritative` | `crates/rustynetd/src/anchor_port_mapping_status.rs` + the Pin-then-Seniority comparator. |
| `anchor.enrollment_endpoint` | **none.** |

The second half of the defect is worse than "an unenforced claim", and is the reason this is
a live security finding rather than a tidiness one:

> `DaemonRuntime::handle_enrollment_consume` (`crates/rustynetd/src/daemon.rs:8763`) accepted
> an `IpcCommand::EnrollmentConsume` on **any** node whose daemon has an enrollment secret and
> ledger path configured — which, per `ops_install_systemd.rs` and
> `adapter/macos_install.rs`, is **every installed node**, client and anchor alike. A valid
> bearer token redeemed against a plain client daemon consumed the token from that node's
> single-use ledger and registered the enrollee as a gossip push peer on that node.

So the capability was not merely unenforced in the "claimed but not provided" direction; the
service it names was being provided by nodes that never claimed it. `AGENTS.md` §3
("default-deny policy is mandatory across ACL, routes, and trust-sensitive flows") is not
satisfied by a trust-sensitive verb that is open on every node in the mesh.

---

## 2) Design question 1 — what does the endpoint actually serve?

`AnchorNodeRoleDesign_2026-05-21.md` §4 defines it as:

> a token-gated LAN-loopback endpoint that accepts `EnrollmentConsume` requests from new
> devices on the same LAN (or, optionally, from any peer with a valid token)

and §5 records that "the IPC path already exists; just needs LAN exposure gated by token".

Concretely, the *service* is one operation, already implemented and hardened:
`enrollment_consume::consume_and_register_peer` — verify the enrollment token's HMAC tag and
expiry, burn it in the single-use ledger (durably, before any peer registration), then register
the enrollee's verifying key and push address in the local gossip routing table under
`PushAddressPolicy::Strict`.

It does **not** serve, and must never serve:

- membership admission (`enrollment admit`), which signs a `MembershipUpdateRecord` with the
  membership owner key — that stays with the owner, per `SecurityMinimumBar.md` §6.C's
  "an anchor is not a trust authority";
- the signed membership bundle itself — that is `anchor.bundle_pull`, a separate capability
  with its own listener and its own head attestation.

The capability therefore has a precise runtime meaning, and it is testable today without any
new wire format: **"this node is authorised to accept `EnrollmentConsume`."**

## 3) Design question 2 — what does a peer verify before trusting it?

Two verifications, in this order, and neither of them trusts the anchor:

1. **Capability, from signed state.** The peer resolves the anchor's entry in the signed
   membership snapshot it already holds and requires `anchor.enrollment_endpoint` on an
   `Active` node. This is exactly the `snapshot_bytes_have_bundle_pull_capability` pattern
   (`crates/rustynet-control/src/membership.rs:1205`), generalised by this change into
   `snapshot_bytes_have_capability`. A capability advertised over gossip, over a discovery
   response, or in an operator's notes is not evidence; only the quorum-signed roster is.
2. **Nothing else, because there is nothing else to trust.** The bearer credential in this
   flow is the enrollment token's HMAC tag, and the secret that mints it is the *network's*,
   not the anchor's to vouch for. A hostile anchor that holds the capability can already
   burn a token and register a bad push address — that is a revocation problem, handled by
   the membership-revoke path, not something a peer-side handshake can detect. This is why
   the endpoint deliberately does **not** get a channel-authentication scheme (see §5).

The corollary matters for the client side: a first-contact device with no signed snapshot
**cannot** verify step 1, and must therefore pull and verify a bundle first
(`anchor pull-bundle`, which since `e1d2a8b`/`e0cc8e5` verifies a membership head attestation
against the §6.B out-of-band owner pin) before it may treat any node as an enrollment
endpoint. Bundle-pull first, enrollment second — never the reverse.

## 4) Design question 3 — fail-closed behaviour when the capability is claimed but the listener is absent

`AGENTS.md` §3 requires failing closed when trust state is missing, invalid, stale, or
unavailable, and §2 requires the strictest secure practical default with the choice documented.
The choice made here, stated as three separate rules because they fail closed in different
directions:

**(a) Serve-side, per request — the enforcement point that landed.**
`handle_enrollment_consume` now re-reads the local signed membership snapshot on **every**
request and refuses unless the local node is `Active` and holds
`anchor.enrollment_endpoint`. Refusal covers all of: snapshot file missing, unreadable, a
symlink, oversized, malformed, digest mismatch, local node absent from the roster, local node
not `Active`, and capability absent or since-revoked. There is no cached "we were an anchor at
startup" answer, so a revocation takes effect at the next request rather than the next restart
— identical to the bundle-pull gate's per-request re-read, and chosen for the same reason.

**(b) Claim-side, at request time.** A node that advertises the capability but has no
enrollment subsystem configured (`enrollment_secret_path` / `enrollment_ledger_path` unset)
already returns an error and consumes nothing. That is fail-closed and is retained unchanged.

**(c) Claim-side, at startup — deliberately NOT a process abort.** The obvious stricter rule
is "if the local signed roster grants `anchor.enrollment_endpoint` and no endpoint is
provisioned, refuse to start". It is rejected for now, and the rejection is the interesting
part of this design:

- The anchor and admin presets advertise the capability on **every** OS
  (`orchestrator/role.rs:262`, `roles::anchor_role_capabilities`). A start-time abort would
  brick every anchor whose install template does not provision an endpoint — which is every
  anchor, since the LAN listener does not exist yet. A control that cannot be enabled without
  taking the fleet down is not the strictest *practical* default; it is an outage.
- The failure mode a start-time abort defends against — a peer trusting an advertised endpoint
  that is not listening — is a **liveness** failure, not a trust failure. The peer's enrollment
  attempt fails to connect and it must not fall back to an unverified path. Rule (a) already
  guarantees that no *unauthorised* node answers.

The strictest practical default is therefore: **advertising is not serving, and serving
requires the signed claim.** A claimed-but-absent endpoint is a connection failure the client
must treat as a hard enrollment failure, never as a licence to enrol elsewhere unverified.
Promoting (c) to a hard startup gate becomes correct — and should be done — at the moment the
listener ships and the install templates provision it on anchors. That is recorded in §7 as a
blocking follow-up, not as an optional nicety.

## 5) Design question 4 — does it need its own signed attestation, like `bundle_pull` has?

**No.** The bundle-pull attestation exists to solve a problem this endpoint does not have, and
adding one here would import a trust-authority shape that `SecurityMinimumBar.md` §6.C
forbids.

Bundle-pull is a **read** of authoritative state by a party that has not yet got any: the
client cannot judge the bytes it is handed, so the *state* must carry its own quorum
signature (`MembershipHeadAttestation`) and the client verifies that against the out-of-band
owner pin. Without it the anchor's word is the only evidence, which is precisely the audit
finding A4 closed.

Enrollment-consume is a **write** requested by a party that already holds the network's
bearer credential:

- The thing being authenticated is the *token*, and it is already authenticated — HMAC tag
  over the network's enrollment secret, verified by `verify_and_consume_token`, with expiry
  and a durable single-use ledger. There is no unauthenticated payload for an attestation to
  cover.
- An attestation would have to be minted *by the anchor* to be about the anchor, and
  `AnchorBundlePullAttestationSecurityReview_2026-07-20.md` §3 already recorded and rejected
  exactly that shape twice: "a compromised anchor … can mint a token committing to its own
  forged root", and channel authentication "authenticates the *anchor* rather than the
  *state*, which again makes the anchor a trust authority".
- The authorisation question that *is* real — "may this node accept enrolments at all?" — is
  already answered by quorum-signed state: the capability in the membership roster, which the
  approver set signed. Enforcing that (§4a) reuses the existing signature chain rather than
  adding a second one. **No new crypto, no new wire format**, per `AGENTS.md` §3.

The one place a signature-shaped question survives is the LAN-exposed listener of §7: exposing
the verb beyond loopback puts an unauthenticated pre-token parser on the LAN. The mitigation
there is transport shape and the existing token gate (bind loopback by default, explicit
`--allow-lan` opt-in, strict length/time budgets), copied from bundle-pull's listener — not a
new attestation.

---

## 6) What landed

Enforcement point (`AGENTS.md` §4 requirement 1):

- `crates/rustynet-control/src/membership.rs` — new
  `snapshot_bytes_have_capability(bytes, node_id, capability)`: parses the snapshot,
  validates it, and returns `true` only for an **`Active`** node holding the capability.
  Fails closed (`false`) on every parse, digest, size or lookup failure.
  `snapshot_bytes_have_bundle_pull_capability` is reimplemented as a thin wrapper over it, so
  the bundle-pull gate inherits the `Active`-status requirement it previously lacked (a
  revoked anchor could still serve bundles; it can no longer).
- `crates/rustynetd/src/daemon.rs` — new
  `require_local_signed_capability(snapshot_path, local_node_id, capability)`, which reads the
  snapshot through the existing symlink-refusing, size-bounded
  `open_anchor_state_file` seam and returns `DaemonError::State` on any failure; called as the
  **first** statement of `handle_enrollment_consume`, before the secret is touched, before the
  ledger lock is taken, and before any token bytes are parsed. Its IPC-facing message is a
  single fixed string (`"enrollment endpoint capability not held"`), preserving the handler's
  fixed-vocabulary rule; the capability set is public signed state, so this discloses nothing
  the roster does not.
- `crates/rustynet-cli/src/vm_lab/orchestrator/role.rs` — the lab `Exit` role (Linux and
  Windows) and the `Entry` role now advertise `anchor.enrollment_endpoint`. The exit is the
  membership owner and the admin-owner node an enrollee's token is redeemed against; the entry
  is required by
  `entry_grant_covers_serving_as_the_clients_exit` to cover the Linux exit grant in full and
  runs the same admin-owner daemon role. Both already advertised `Anchor` + `RelayHost`, so the
  combination is legal under `validate_membership_node_capabilities`. Without this the new gate
  would refuse the very flow the lab exercises — this makes the declarative claim match the
  runtime fact rather than papering over the gate.

  Note, found while checking that coupling: the Linux enrollment-restart harness
  (`crates/rustynet-cli/src/bin/live_linux_enrollment_restart_test.rs`) drives its scenario
  through four `rustynet ops` subcommands that **do not exist** in the CLI's `OpsCommand`
  parser (`generate-enrollment-token`, `consume-enrollment-token`, `show-node-id`,
  `verify-membership`), each behind `capture_root_allow_failure`, so the stage degrades to
  `enrollment_outcome=rolled_back` instead of failing. That stage therefore never reaches
  `handle_enrollment_consume` today and cannot be regressed by this gate — but it also proves
  nothing. Tracked separately; it is not a D-3 defect.

Verification methods (`AGENTS.md` §4 requirement 2) — negative tests first:

11 tests in total — 6 in `crates/rustynetd/src/daemon.rs`, 5 in
`crates/rustynet-control/src/membership.rs`. All but two are negative cases.

| Test | Proves |
|---|---|
| `enrollment_consume_refused_when_capability_absent` (daemon.rs) | **the fail-closed path**: a running daemon whose signed roster does not grant `anchor.enrollment_endpoint` refuses `EnrollmentConsume` outright — refused, not tolerated. The roster used is the full anchor set *minus* the endpoint capability, so the refusal cannot be explained away as "it is not an anchor". |
| `enrollment_consume_capability_gate_precedes_subsystem_and_token_checks` (daemon.rs) | positive control: the only difference is the capability, and with it the same call reaches the *next* check instead. Proves the gate is a discriminator, not a blanket refusal, and that it runs ahead of any token handling. |
| `require_local_signed_capability_refuses_when_capability_absent` (daemon.rs) | the gate itself, plus its non-vacuity (a capability the node *does* hold passes the same call). |
| `require_local_signed_capability_refuses_when_snapshot_missing` (daemon.rs) | trust state unavailable ⇒ refusal (§3 fail-closed). |
| `require_local_signed_capability_refuses_revoked_local_node` (daemon.rs) | a since-revoked node is refused even though its roster row still lists the capability. |
| `require_local_signed_capability_accepts_capability_holder` (daemon.rs) | an active holder passes. |
| `snapshot_bytes_have_capability_accepts_active_holder` / `_discriminates_between_capabilities` / `_refuses_revoked_node_that_still_lists_it` / `_refuses_unknown_node_and_malformed_input` / `_refuses_digest_tampered_snapshot` (membership.rs) | library-layer coverage: per-capability discrimination (holding `gossip_seed` grants neither `enrollment_endpoint` nor `bundle_pull`), unknown node, empty/non-utf8/structurally-broken bytes, digest tampering, and the revoked-node case — which also asserts the tightening reaches the pre-existing bundle-pull gate. |

---

## 7) What is NOT done, and what unblocks it

1. **The LAN-exposed listener does not exist.**
   **Landed 2026-08-27 (`work/enrollment-listener`).** What shipped, in
   `crates/rustynetd/src/daemon.rs`, modeled on the bundle-pull seam exactly as sketched here:
   - `bind_anchor_enrollment_listener` / `poll_anchor_enrollment_once` /
     `handle_anchor_enrollment_stream`, portable (`std::net`) and polled by BOTH the Unix and
     Windows daemon main loops. Opt-in: the listener binds only when
     `--anchor-enrollment-addr` / `RUSTYNET_ANCHOR_ENROLLMENT_ADDR` is set (no default
     address), loopback-only unless the explicit `--anchor-enrollment-allow-lan` /
     `RUSTYNET_ANCHOR_ENROLLMENT_ALLOW_LAN` opt-in.
   - It serves EXACTLY one verb: the existing `enrollment consume <token> <pubkey-b64>
     <addr:port>` wire encoding from `ipc.rs`, dispatched into the existing
     `handle_enrollment_consume` → `enrollment_consume::consume_and_register_peer` path under
     `PushAddressPolicy::Strict`. Every other line — including `status`, `gossip push`,
     `membership apply`, and remote-op envelopes — is refused default-deny with one fixed
     string. No new wire format, no new crypto, no attestation (§5 held).
   - Pre-authentication hardening mirrors bundle-pull: accept-time capability re-read before
     any client byte is parsed, one request line under a 256-byte byte-at-a-time cap
     (`MAX_ANCHOR_ENROLLMENT_REQUEST_LINE_BYTES`) and a 2s wall-clock read budget, 2s socket
     timeouts, deadline-bounded response writes, fixed-vocabulary `OK …`/`ERR …` responses.
     Two deliberate tightenings beyond the precedent: an EOF-truncated request line is refused
     outright (bundle-pull tolerates one for compatibility), and inside
     `handle_enrollment_consume` every payload parse now precedes the enrollment ledger lock,
     so invalid-consume floods never contend on the single-use ledger.
   - Per the bundle-pull review's rule for network-exposed pre-authentication parsers, the
     independent adversarial review pass remains REQUIRED before any deployment sets
     `--anchor-enrollment-allow-lan`; loopback-only operation does not wait on it.
     **Update 2026-08-27, same branch:** that review pass is complete — see
     [`AnchorEnrollmentListenerSecurityReview_2026-08-27.md`](./AnchorEnrollmentListenerSecurityReview_2026-08-27.md),
     verdict PASS with no MEDIUM-or-above finding (five accepted INFO/LOW residuals recorded
     there, including the F2 fixed-string hardening follow-up for the `{err}`-bearing
     secret/ledger arms).
2. **Startup coherence gate (§4c)** — promote to a hard `DaemonError` once (1) ships and the
   Linux/macOS/Windows install templates provision the endpoint on anchors. Until then it
   would brick anchors.
   **Update 2026-08-27 (`work/enrollment-listener`):** the listener-open half is implemented
   as designed: `bind_anchor_enrollment_listener` refuses to open (no optimistic bind) unless
   the local quorum-signed snapshot shows `anchor.enrollment_endpoint` on an **Active** row —
   missing/symlinked/oversized/malformed snapshot and unprovisioned enrollment subsystem all
   refuse at startup. The per-request re-read inside `handle_enrollment_consume` is kept
   unchanged as the revocation mechanism (listener-open = startup coherence; per-request =
   revocation; both exist, verified by
   `anchor_enrollment_revoked_capability_refused_per_request_while_listener_stays_bound`).
   The remaining §4(c) promotion — "capability advertised but no endpoint provisioned ⇒
   refuse to start" — still waits on the install templates provisioning the endpoint on
   anchors, exactly as stated above.
3. **`anchor_validation`'s reported skip.** `anchor_validation.rs` `:43`/`:256` hard-coded
   `reported_skipped_runtime_dependent=[enrollment_endpoint]` with the reason "pending a
   trust-model decision — enrollment admit signs a membership update with the owner signing
   key". That reason is **partly mis-stated**: it describes `enrollment admit`, which the
   endpoint does not serve (§2). `enrollment consume` needs no owner key. The accurate blocker
   for the *positive* substage is (1) — there is no listener to probe. The note is updated to
   say so, and the *negative* substage is unblocked today (§8).
   **Update 2026-08-27 (`work/enrollment-listener`):** with (1) landed, the positive substage
   is no longer design-blocked — DESIGN sketch only, no stage code written here. What it
   needs from the listener: the admin/exit lab roles already advertise the capability (§6);
   the stage additionally provisions `--anchor-enrollment-addr 127.0.0.1:51823` (51823 is the
   suggested convention, one above bundle-pull's 51822 — any free port works, discovered from
   the daemon argv, there is no default) plus the existing `--enrollment-secret` /
   `--enrollment-ledger` flags on the serving node, mints a token against the co-located
   secret, then drives one TCP line `enrollment consume <token> <pubkey-b64> <addr:port>\n`
   and asserts the `OK enrollment accepted node=…` response, the durable ledger burn, and a
   replay refusal. LAN-crossing cells additionally require `--anchor-enrollment-allow-lan
   true`, which stays gated on the adversarial review pass noted in (1). The
   `anchor_validation.rs` reported-skip reason text is NOT edited on this branch (live-lab
   stage files are out of scope here); it should change to "positive substage pending
   live-lab stage implementation against the landed listener" when that stage lands.

## 8) Live-lab stage shape (sketch only — not run, no lab access in this task)

A negative substage is exercisable now and needs neither a listener nor an owner key:

- `enrollment_endpoint_denied_without_capability` — on a **client** node (no anchor
  sub-capabilities in signed membership), invoke `rustynet enrollment consume` with a
  syntactically valid but bogus token over the local IPC socket. Expect the fixed capability
  refusal, and assert the *distinguishing* fact: the message is the capability refusal, **not**
  `"enrollment token rejected"` — proving the gate short-circuited ahead of token verification
  rather than the token merely being bad. Assert the client's enrollment ledger is unchanged.
- Per-OS cells: the substage is argv-only over the existing `RemoteShellHost` seam, so it needs
  only the per-OS `rustynet` binary path and IPC socket/pipe path that
  `AnchorRuntimeParams::for_platform` already resolves — Linux and macOS via the unix socket,
  Windows via the named pipe (`windows_ipc.rs`). Unlike the bundle-pull substages it needs no
  token provisioning, so it should not inherit their `is_supported_for_platform` skip and can
  run on all three OSes in the same wave.
- The positive substage (`enrollment_endpoint_admits_new_device`) stays reported-skipped until
  §7(1) lands; it will additionally need the enrollment secret co-located with a mint on the
  admin node and an `aux` enrollee, i.e. the shape
  `live_enrollment_restart_validation` already builds.

## 9) Cross-references to update when §7(1) lands

- `AnchorNodeRoleDesign_2026-05-21.md` §5 (enrollment row), §8 (security-control table).
- `SecurityMinimumBar.md` — add the enrollment-endpoint authorisation control alongside
  control 2 (bundle-pull head attestation).
- `AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md` Track A, enrollment sub-stage.

**Note 2026-08-27 (`work/enrollment-listener`):** §7(1) has landed on that branch; the three
documents above still carry their pre-listener text and are deliberately NOT edited there
(they are shared with in-flight branches). Update them when this branch merges.
