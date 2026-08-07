# I4 — traversal enforcement: what it needs, and why it cannot ship yet

**DESIGN ONLY. NOT APPROVED. NO PRODUCTION CODE PROPOSED AS WRITTEN.** Revision 7, after
five rounds of adversarial review.

**Read §0.0000 first** — it refutes revision 6's own surviving recommendation (item 2,
"make the command backends honest") before any code was written, and narrows what is
left of it.

**Then read §0.000.** It closes item 6 (endpoint attribution) as unachievable with
this observation surface, reframes §0.01 as a deliberate architectural decision rather
than a defect, records a live allowlist defect that breaks traversal probing on
enforced Linux and macOS nodes at HEAD, and adds a hard prohibition: a
`wg show <iface> dump` allowlist arm would expose the interface private key.

Then read §0 onward for the earlier rounds: the second review refuted four of revision
2's corrections including its headline recommendation, and the third refuted **all
three steps of the chain revision 3 proposed in its place** (§0.0, §9.1). The sections
below carry their retractions inline. Nothing here is landable as written.

A caution for whoever picks this up, because it has now held at every step: **the narrow
supporting fact was correct each time; the conclusion drawn from it was not.** Treat every
generalisation in this document as the weakest link, and re-read the code that *writes* a
signal before relying on it.

Scope: items 1–6 and 8 of `I4EnforcementFlipPlan_2026-07-30.md` §4. Item 7 (gossip
status surface) shipped earlier and is out of scope.

**Headline result: I4 cannot be completed now, and one of its two published designs
would still program an attacker-chosen endpoint.** The ordering problem the task
anticipated is real, larger than expected, and the blocking dependency is partly work
that was only *designed* today. §1 states the result; §9 states what is landable now.

## 0.0000 Revision 7 — item 2 ("make the command backends honest") is REFUTED as written

Revision 6 closed items 5 and 6 and left four recommendations. Recommendation 2 — skip the
ICE race when the backend is blocked and take the relay/fail-closed path — was designed in
full and attacked by four independent adversarial reviews plus a verifying judge on
2026-08-07, at HEAD `adeea15e`. **All four reviews returned REFUTED. No code was written.**
That is the process working: `01c20297` was written, gated, landed and reverted; this was
killed at the design stage instead.

### The load-bearing error, which is the SAME shape as the previous four

The plan's verified fact: `initiate_peer_handshake` is the inherited no-op on all three
command backends (overrides exist only at `userspace_shared/mod.rs:546`,
`userspace_shared/runtime.rs:631`, `userspace_shared_macos/mod.rs:637`,
`userspace_shared_macos/runtime.rs:672`) `[verified]`. So the race sends nothing.

**That kills only the SEND half.** The race is simultaneously a 240 ms *passive detector*:
`traversal.rs:1740-1744` is the only producer of `TraversalDecision::Direct`, and it
decides on `runtime.latest_handshake_unix()`, which on every command backend is a **live
`wg show <if> latest-handshakes` shell-out**, not a cache (`linux_command.rs:387-394`;
identical at `macos_command.rs:473-480`) `[verified]`. Deleting the race deletes the
observation — the only way one of these nodes can ever promote to Direct.

Once again: the narrow supporting fact was correct; the conclusion drawn from it was not.

### Surviving blockers, each independently re-verified by the judge

1. **B1 — the Direct arm is an observation, not a consequence of our sends.** Above.
2. **B2 — with `relay_client == None` the gate makes `PathMode::Relay` ABSORBING.** The
   gate always returns Relay (`traversal.rs:1816`); the only non-race Direct short-circuit
   cannot fire because relay candidates are excluded from `direct_candidates`
   (`daemon.rs:14891`); and the peer re-probes forever back into the gate
   (`daemon.rs:2234`). Today an observed handshake advance is the escape. The patch removes it.
3. **B3 — that same topology forces `path_live_proven=false` permanently**, and it IS
   hard-gated: relay liveness requires a relay *session* (`daemon.rs:7376-7383`), which
   cannot exist without a relay client, so `daemon.rs:7509` is false forever and
   `ops_cross_network_reports.rs:1323-1325` rejects the evidence outright.
4. **B4 — the proposed edit trips clippy** (8 parameters vs the default threshold of 7; no
   `clippy.toml` exists). Bundle the two reasons into a struct instead.
5. **B5 — the proposed test suite cannot detect its own core mutation.** Every fixture sets
   `backend_probe_blocked` by hand, so hard-coding the real daemon wiring to `false` leaves
   the whole suite green with the gate dead in production.

### What is left, and the measurement that gates it

A narrowed form survives — gate on `backend_probe_blocked && relay_endpoint.is_none()`,
where the fall-through is FailClosed→Direct rather than an absorbing Relay, and where
`relay_or_fail_closed_for_race` still performs the `latest_handshake_unix` read
(`traversal.rs:1824`, `:1834`) so the observation half is preserved. Derive the predicate
from the property actually being reasoned about (the inherited `initiate_peer_handshake`
no-op), NOT from `transport_socket_identity_blocker` — that value is filtered on unrelated
config at `daemon.rs:4143-4146`, so two identical Windows nodes take opposite branches.

**Do not implement any of it until this is measured.** The single riskiest assumption is
that `wg set <if> peer <k> endpoint <a>` emits no handshake initiation on a command
backend — i.e. that the 24 rewrites per round are pure cost. **The repo argues both ways
and settles neither**: `daemon.rs:20086-20096` records that with the no-op trigger "zero
WireGuard handshake datagrams reached the wire on any platform", while `daemon.rs:2205-2213`
states "each re-race forces a WireGuard handshake" at a measured ~6 handshakes/second on a
live cross-network path whose backend is not named.

The measurement: on ONE command-backend node, tcpdump the WireGuard UDP port across ≥30
reconcile ticks with the daemon otherwise idle, and log the destination of every handshake
initiation. If initiations reach more than the single `max_by_key(priority)` host
candidate, **abandon the patch entirely** — the storm is a working NAT search, and the
correct fix is instead to make it cheap by skipping the unconditional
`refresh_peer_endpoint_routes_and_attest` (`phase10.rs:6265`) when the bypass-destination
*set* is unchanged. Note the earlier "≥2 distinct endpoints inside one 240 ms race" framing
is unrunnable by construction (`MAX_PAIRS=24 / ROUNDS=3 / ROUND_SPACING_MS=80` at
`traversal.rs:62-64` plus WireGuard's own initiation pacing), so it would return green
regardless of the truth — measure over ≥60 s instead.

Landing evidence must include one Windows or explicit `--backend *-command` traversal run.
The Linux lab and macOS service installs both run userspace-shared
(`macos_service_hardening.rs:243-245`), so green gates on this repo's usual legs prove
nothing about the population this change affects — which is exactly the
`01c20297`→`2fdc7f70` shape.

## 0.000 Revision 6 — item 5 is not a defect, item 6 is closed, and A3.2 would have leaked the private key

A plan to fix "the ICE race emits no handshake datagrams on the command backends"
(§0.01) and to re-attempt A3.2 was written on 2026-08-07 and attacked by two
adversarial reviews before any code was written. **Both halves of that plan were
refuted.** Every claim below was re-verified by hand afterwards. The plan is not
recorded; its refutation is, because the refutation is what transfers.

### The reframing: §0.01 describes a deliberate decision, not an oversight

`poll_stun_results` returns early when the backend declares itself
non-authoritative — `crates/rustynetd/src/daemon.rs:5932-5936`:
`if self.transport_socket_identity_blocker.is_some() || …stun_servers.is_empty() { return; }`
`[verified]`. All three command backends set that blocker
(`linux_command.rs:544-547`, `macos_command.rs`, `windows_command.rs`), and the
Linux one states why: the adapter has "no authoritative packet-I/O handle or
backend-owned datagram multiplexer, so the daemon cannot safely run STUN or relay
bootstrap/refresh on the real peer-traffic transport".

**Consequence: on a command backend the race never gathers a server-reflexive
candidate at all.** It only ever holds host/LAN candidates, where NAT punching is
neither needed nor possible. No STUN, no relay bootstrap and no handshake
origination are therefore **one decision, not three omissions**, and §0.01's
finding is a symptom of it rather than an independent bug.

This also settles by reading what §0.01 proposed to settle by measurement: the
cross-network hole-punch this project has measured **cannot** have used a command
backend, because such a backend never produces a srflx candidate.

### RETRACTED — "give the command backends a handshake trigger"

The plan proposed a `nudge_peer_handshake` sending one datagram toward the peer's
overlay address. It cannot work, for reasons that are protocol-level rather than
implementation detail:

- WireGuard rate-limits initiation to one per `REKEY_TIMEOUT`, which is **5
  seconds** (`third_party/boringtun/src/noise/timers.rs:22`), and suppresses a
  repeat while one is in flight (`third_party/boringtun/src/noise/mod.rs:438-439`,
  `if self.handshake.is_in_progress() && !force_resend`) `[verified]`. Kernel
  WireGuard exposes no force-resend, and the privileged-helper allowlist grants no
  command that would provide one.
- The race fires up to 24 pairs × 3 rounds inside ~240 ms
  (`traversal.rs:62-64`). So the nudge would yield **at most one initiation for
  the entire 72-probe race**, aimed at `pairs[0]` of round 0.
- Kernel WireGuard stores **one endpoint per peer**, so 24 candidates cannot be in
  flight concurrently by construction — the "parallel race" is unachievable on a
  command backend regardless of trigger.

The failure mode this would have produced is the one this document family keeps
producing: a packet capture showing "zero became one", a proof obligation reading
as met, gates passing, and a race still 1/72 functional. It would also make a
deliberately non-authoritative backend *look* like it punched, which is precisely
what the blocker exists to prevent.

### CORRECTED — the rejection of the userspace-shared backend was wrong

The plan rejected routing traversal through userspace-shared because
`supports_roaming` is `false` there. That field has **exactly one reader in the
entire repository** — a test assertion at `crates/rustynetd/src/daemon.rs:17624`
`[verified]`. There are no production readers. The rejection therefore rested on a
field nothing consults, and it rejected the only backends that could ever
implement `handshake_endpoint`, since they are the only ones that own the socket.

### Item 6 is CLOSED: attribution and parallel racing are mutually exclusive here

The plan's replacement for A3.2 was a "confirmation round" — on observing a
handshake advance, program the reported endpoint and verify a handshake against it
specifically. It cannot fire. The confirmation runs immediately after the winning
guard, so a valid session already exists, and WireGuard will not rekey for
`REKEY_AFTER_TIME` = **120 s** (`third_party/boringtun/src/noise/timers.rs:19`)
`[verified]` — 500× the entire 240 ms race budget.

So the confirmation's causal path is *closed* while its coincidental path is
*open*: the only events that can advance the handshake during the window are ones
the confirmation did not cause — in-flight responses from the 72 earlier probes,
or the peer's own initiation, which this repo measured at ~6 handshakes/second on
a live cross-network path (`crates/rustynetd/src/daemon.rs:2220-2225`). A check
that can only ever succeed by coincidence is not proof.

**Recorded conclusion: with this observation surface, endpoint attribution and
parallel racing cannot both be had.** Serial probing would attribute for free but
trades away simultaneous-open, which is the mechanism marginal-NAT topologies
need. Item 6 is closed rather than re-scoped. What is lost is the FIS-0009
prior-store re-ranking optimisation, which is a performance feature and not a
security control; direct paths are simply unattested, and the reason variants
already say so honestly.

### CRITICAL — never add a `wg show <iface> dump` allowlist arm

`dump` prints the interface **private key** as field 0 of its first line, and
every peer's preshared key as field 1 of each peer line. This is not inference:
the reverted A3.2 commit's own parser doc says "the leading interface line carries
4 (private-key, public-key, listen-port, fwmark)" and its own test fixture is
`"priv\tpub\t51820\toff\n…"` `[verified]`.

Skipping that line in the parser does not stop it crossing the privileged-helper
boundary into an unzeroized `String` in daemon memory. The existing allowlist is
deliberately structured so the daemon only ever handles the private key **by
path** (`privileged_helper.rs`, the `["set", interface, "private-key",
private_key_path]` arm). A `dump` arm would hand it back in plaintext — a §4 and
§10.6 violation, and the most secret-dense output `wg` can produce.

**So the reverted A3.2 was worse than recorded in §0.00: alongside its two
blockers, it would have pulled the interface private key into daemon memory.** If
an endpoint read-back is ever needed, `wg show <iface> endpoints` yields
peer/endpoint pairs without key material — unverified locally (`wg` is not
installed on the dev host) and to be confirmed on a lab guest.

### LIVE DEFECT at HEAD — the endpoint-only argv is not allowlisted

`update_peer_endpoint` emits a **six**-token argv with no `allowed-ips` tail
(`crates/rustynet-backend-wireguard/src/linux_command.rs:474-484`), and `HEAD`'s
`validate_wg_args` has no matching arm — its only `endpoint` arm requires the
`allowed-ips` tail, so the six-token form hits the deny catch-all `[verified]`.
Validation is client-side, before the socket, and the production Linux/macOS
backends are hard-wired to the helper.

**So `send_probe` cannot complete its first line on an enforced Linux or macOS
node: it errors at `reconfigure_managed_peer` before `initiate_peer_handshake` is
ever reached.** This is more severe than §0.01, invalidates any measurement of
"does the race emit handshakes" taken before it is fixed, and bypasses
`relay_or_fail_closed_for_race` entirely — there is no relay fallback on this
path. The fix is written but uncommitted at time of writing.

### Also recorded, not yet fixed

- **Mixed-fleet fail-open at the proof surface.** When two or more live direct
  peers carry differing reasons, the aggregate reports the *attesting* literal, so
  one attributed peer plus one unattributed peer launders into a clean
  attestation. One line, no boundary change; see §0.0's `daemon.rs:7398` entry,
  which described the same code without naming the fail-open.
- **A loaded `?` on the winning path.** `traversal.rs`'s
  `match runtime.handshake_endpoint()?` sits inside the branch taken when the race
  has *succeeded*. It is inert only because no production implementation exists;
  the moment one does, a backend error fails the reconcile exactly when a direct
  path starts working — how A3.2 would have failed every enforced node. Make it
  fail-soft regardless of whether attribution is ever implemented.
- **Route-flush storm on the probe path.** Every endpoint reprogram calls
  `refresh_peer_endpoint_routes_and_attest` (`phase10.rs:6264-6265`) `[verified]`,
  which flushes and rebuilds routing table 51820 and re-asserts the killswitch —
  up to 72 times inside a 240 ms round budget, each momentarily blackholing the
  default route on an exit client. Unmeasured and uninstrumented.

### The recommendation this leaves

1. Commit the endpoint-only allowlist arm first; nothing else in this area is
   measurable until it lands.
2. Make the command backends honest rather than giving them a synthetic trigger:
   when the backend is blocked, skip the ICE race and take the existing
   relay/fail-closed path with a named reason. That also removes the route-flush
   storm and the misleading `traversal_probe_attempts` increments.
3. Treat real traversal on Linux/macOS as meaning the userspace-shared backend,
   which is where it already demonstrably works.
4. Fix the mixed-fleet fail-open and defuse the `?`. Both are cheap and worth more
   than item 6 was.

## 0.00 Revision 5 — A3.2 was built, landed, reviewed, and REVERTED the same night

A3.2 was implemented on 2026-08-07 (commit `01c20297`), passed all five mandatory
gates including a 10367-test suite, carried three verified mutations, and was pushed.
An adversarial review then found two blockers, both re-verified by hand, and it was
reverted in `2fdc7f70`. **Do not re-attempt it from that design.** The gates were
green and the change was still wrong, which is the point worth keeping.

**BLOCKER 1 — `wg show <iface> dump` is not on the privileged-helper allowlist, and
the failure lands on the WINNING path.** `validate_wg_args` is an exhaustive match
with a deny catch-all; the only `show` arm is
`crates/rustynetd/src/privileged_helper.rs:2068`
(`["show", interface, "latest-handshakes"] if is_interface_name(interface) => Ok(())`),
and everything else hits `:2108` `_ => Err("unsupported wg argument schema")`
`[verified]`. The production Linux and macOS backends run `wg` through
`PrivilegedCommandClient`, which validates client-side before the socket. Worse than a
plain failure: `handshake_endpoint()` is called **only after** the race has already
observed a fresh advanced handshake, so the error converts a *successful* direct path
into `TraversalProbeFailed`, which propagates with `?` through
`sync_traversal_runtime_state` into `restrict_recoverable` +
`force_fail_closed_or_restrict`. Under enforcement the node fails closed the moment a
direct path works. None of the six new tests could catch it: they all drive a
`RecordingRunner`, never the privileged-helper runner.

**BLOCKER 2 — the attribution was circular, and the new label asserted proof.**
`send_probe` reprograms the kernel peer endpoint for every pair *before* any poll, and
`DEFAULT_TRAVERSAL_PROBE_MAX_PAIRS` is 24, so at poll time `peer->endpoint` is
`pairs[23]` — written milliseconds earlier by the race itself. `wg show dump`'s
endpoint column *is* that same `peer->endpoint`, and the parser cannot distinguish
"the kernel roamed it" from "we wrote it". So the change moved the misattribution from
index 0 to index 23 while *upgrading* the reason from `IcePairRaceHandshakeUnattributed`
to `IcePairRaceHandshakeObserved`, which phase10 maps to `FreshHandshakeObserved`.
**Before: wrong endpoint, honestly flagged unattributed. After: wrong endpoint,
asserted as proof.** The atomicity argument in the commit body was a non-sequitur —
reading two columns from one line proves they were *sampled* together, not that one
*caused* the other.

**What a correct A3.2 needs, therefore:** an allowlist arm for the `dump` form; a
fail-soft call site so a backend error can never abort a winning race (treat `Err` as
unattributed, never propagate); and — the hard part — a probe loop that does not
clobber the very value it later reads. Observing between probes, or recording which
endpoint was programmed at each observation, would give real attribution; reading back
a field the loop just overwrote never can.

## 0.01 The finding that outranks A3.2: the ICE race sends nothing on the default backends

Surfaced by the same review and verified independently. `initiate_peer_handshake` has
**no override in any of the three command backends** — `linux_command.rs`,
`macos_command.rs` and `windows_command.rs` each define zero, so all three inherit the
trait default `Ok(())` at `crates/rustynet-backend-api/src/lib.rs:274-279` `[verified]`.
Only the two userspace-shared backends implement it
(`userspace_shared/mod.rs:546`, via an in-process boringtun control handle).

This is architectural, not an oversight: `linux_command.rs:546` states the adapter
"exposes configuration and handshake queries but no authoritative packet-I/O handle",
so it has nothing to send a datagram *with*.

Consequence: on `DaemonBackend::Linux` and `::Macos` — the **default** modes —
`send_probe` reprograms the peer endpoint, returns `Ok`, increments
`traversal_probe_attempts`, and emits **zero WireGuard handshake datagrams**. The ICE
pair race does not actively hole-punch on those backends; it cycles endpoints and
observes whatever handshake happens for other reasons.

**And the existing test does not catch it.** `daemon.rs:19733` is a source-text pin on
the `DaemonBackend` dispatch block, whose own comment (`:19725-19729`) claims it exists
to prevent exactly this. It cannot: the dispatch arms are all present and correct, and
the no-op is one layer *below* them. This is the §2 warning — "do not trust a
dispatch-layer pin to catch a missing backend impl" — holding true against the very
test written for it.

Recorded, not fixed: giving the command backends a real handshake trigger is a
separate design question (there is no `wg` verb for it), and it plausibly explains more
about traversal behaviour on Linux than anything in §3.

## 0.0 Revision 4 — the chain revision 3 proposed was reviewed, and all three steps failed

Revision 3 closed §9 by recommending "A3.1 + item 2, taken together, plus a proof-surface
change", and flagged that this re-scoping had not itself been reviewed. It has now been
reviewed — three independent adversarial passes with distinct lenses, every load-bearing
link re-verified by hand at commit `8ffa3a6e` — and the pattern held for a third time:
**the narrow supporting facts were correct, and the conclusion drawn from them was not.**
Details and the per-step evidence are in §9.1. The headline retractions:

**RETRACTED — "A3.1 does not cost connectivity because `ExistingFreshHandshake` covers the
steady-state peer".** The guard is structurally unreachable for a peer in relay mode.
`evaluate_traversal_probes` re-arms relay *before* it reads the incumbent endpoint
(`phase10.rs:5955-5956`); that call reprograms a `PathMode::Relay` peer to the relay
address (`phase10.rs:5868-5877`); the guard then reads the endpoint back from the backend
(`phase10.rs:5959-5962`) and requires it to be a **direct** candidate
(`phase10.rs:5969-5972`), while a relay endpoint is never in that list
(`daemon.rs:14847`, `TraversalCandidateType::Relay => return None,`) `[verified]`. So it
fires only for a peer that is *already* Direct — it is not a promotion path. Since no
production runtime implements `handshake_endpoint`, after A3.1 the race never returns
`Direct` in production: a peer that lands on relay never returns to direct, and a healthy
direct peer is permanently demoted by one stale-handshake blip. The only other
`PathMode::Direct` committer, `mark_direct_recovered` (`phase10.rs:5701`), has no
production caller — all six call sites are after the `#[cfg(test)]` at `phase10.rs:7082`
`[verified]`.

**RETRACTED — "start with item 2, since it is the producer-side hole and is independent of
attribution".** Three separate defects. (i) There is no representable "nothing programmed"
outcome, so the only closure is `Err`, and `Err` is a **node-wide egress kill**, not a
per-peer denial: `daemon.rs:4978-4983` → `force_fail_closed_or_restrict` →
`phase10.rs:5557-5559` `self.system.block_all_egress()?;` `[verified]`. (ii) It makes the
residue case strictly worse — `send_probe` reprograms the backend for every probed pair
(`phase10.rs:98-105`) and nothing reverts it, so deleting the arm's overwrite leaves
`pairs[last]`, a peer-supplied endpoint, programmed permanently `[verified]`. (iii) An
identical `.max_by_key(|candidate| candidate.priority)` survives on a path that runs no
race at all — `daemon.rs:14688-14691` in `select_runtime_traversal_endpoints`, reached
from `static_traversal_endpoint` at `daemon.rs:7016` for any peer with no probe status
(first boot, post-restart, after any status clear) `[verified]`. Item 2 relocates the hole
rather than closing it.

**RETRACTED — "the proof surface must stop treating path-mode-plus-freshness as proof".**
The *description* of `live_proven` is accurate (`daemon.rs:7461` carries no reason term),
but the remedy is a demolition. Because no production runtime implements
`handshake_endpoint`, requiring attribution makes `path_live_proven` permanently false on
every direct path fleet-wide, breaking the Windows mesh-join gate
(`scripts/bootstrap/windows/Verify-RustyNetWindowsBootstrap.ps1:756`, `:823`),
`scripts/vm_lab/netns_daemon_path.sh:475`,
`scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh:329`,
`scripts/e2e/live_linux_cross_network_failback_roaming_test.sh:355` and `:485`,
`crates/rustynet-cli/src/ops_cross_network_reports.rs:1863`,
`crates/rustynet-cli/src/bin/live_linux_mixed_topology_test.rs:196`,
`crates/rustynet-cli/src/bin/live_chaos_crash_recovery_test.rs:665`, and the §7-mandatory
unit test at `daemon.rs:24979` `[verified]`. Note the four shell and PowerShell consumers
are invisible to any `.rs` grep — the enumeration error this document family keeps making.

**CORRECTED — `daemon.rs:7398` is not a fallback.** Per `daemon.rs:7383-7399` the empty
case is unreachable in the `direct_active` arm, so the literal fires only when **two or
more** live direct peers carry *differing* reasons. It is a collapse of a heterogeneous
reason set onto one member's string, not a default. "Delete the literal" is therefore an
unspecified policy decision (mixed marker? most-pessimistic member?), and no existing test
reaches it — every `direct_active` test in the tree is single-peer and takes the
`len() == 1` branch `[verified]`. Revision 3's `:7395` claim survives: that `.unwrap_or`
is genuinely dead.

**Also recorded: `live_proven` is already treated as unreliable elsewhere in the tree.**
`crates/rustynet-cli/src/bin/live_linux_two_hop_test.rs:2052-2055` states it is
"structurally unsatisfiable on shared-transport nodes … so it must never be used as a
liveness gate" `[verified]`. Any future hardening of that field must reconcile with this
precedent rather than tighten a signal one platform class already routes around.

**What survived the third review, unrefuted.** The misattribution premise itself:
`handshake_endpoint` has no production implementation — the `SimultaneousOpenRuntime` impl
for `Phase10PeerRuntime` (`phase10.rs:95-117`) defines only `send_probe` and
`latest_handshake_unix`, so the `Ok(None)` default at `traversal.rs:714` applies to every
production race, and `pairs[0]` is credited while the backend last sat at `pairs[last]`
`[verified]`. **The bug is real. Every remedy proposed so far is what fails.**

## 0. Revision 3 — what the second review retracted

Revision 2's corrections were themselves reviewed, and four were wrong. Continuing the
pattern this document family has shown at every step: **the narrow fact held, the
conclusion drawn from it did not.** Retractions are kept, not deleted.

**RETRACTED — the rejection of A3.1 (§3) rested on a false consequence.** Revision 2
claimed deleting the attribution fallback would make the race never return `Direct` and
so remove direct connectivity fleet-wide. The first half is right — `pairs[0]` is the
only route to `Direct` *inside* `execute_ice_pair_race`. The consequence is wrong at the
**caller**: `evaluate_traversal_probes` returns `Direct` without entering the race at all
(`phase10.rs:5979-5981`, `ExistingFreshHandshake`), and the race's `FailClosed` is
converted by the caller into a programmed Direct path (`phase10.rs:6122`, `:6125`)
`[verified]`. So connectivity would not be lost.

What A3.1 would actually do is different and worse: it reroutes every unattributed race
into the one arm where the **raw sender-supplied `priority` integer** selects the
endpoint — `.max_by_key(|candidate| candidate.priority)` at `phase10.rs:6113` — the very
channel §3.1 notes is closed on the race path. **A3.1 is therefore viable only together
with item 2** (closing the FailClosed arm), which §10 already lists. That pairing is a
coherent option revision 2 never evaluated, and it is stronger than A3.3.

**RETRACTED — A3.3 does not achieve its stated goal.** Revision 2 claimed it would mean
"no consumer can mistake an unattributed handshake for endpoint proof". The proof surface
is **reason-blind**: `live_proven: live_peer_count == programmed_peer_count &&
programmed_peer_count > 0` (`daemon.rs:7461`), computed from path mode and freshness
`[verified]`. After A3.3 an unattributed Direct endpoint still reports
`path_live_proven=true`. Worse, A3.3 *creates* a mixed-reason fleet, and the aggregator
hard-codes the literal for that case — `.unwrap_or("fresh_handshake_observed")` and
`else { "fresh_handshake_observed".to_owned() }` (`daemon.rs:7395`, `:7398`) `[verified]`
— so a fleet where **no** peer has the new reason would still print
`path_reason=fresh_handshake_observed`. A3.3 is also not observable-neutral: it breaks
named in-tree assertions at `daemon.rs:24967` and `:24984` `[agent]`. Any real fix must
change the proof surface, not only the reason.

**RETRACTED — §7's "the two conditions agree by construction" is false.** Statuses exist
only for peers already programmed (`managed_peer_ids()`, `daemon.rs:6473`), while the
reconcile path runs the authority call on the **new** peer vector
(`daemon.rs:9323`) with the controller already `DataplaneApplied` `[verified]`. A newly
added peer therefore has no status, the gated deny fires, and because the loop has no
per-peer skip one new peer fails the whole vector into `restrict_recoverable` +
`promote_to_permanent_if_over_limit`. The cold-start cycle is not closed — it is
**relocated to every membership change**. A correct design needs a per-peer skip for
never-yet-programmed peers, not a global state gate.

**RETRACTED — §3.4 overstated its own contingency.** Revision 2 said the finding collapses
if the handshake counter can only advance from the endpoint just probed. It does not:
`send_probe` reprograms the backend endpoint for **every** pair before any poll
(`phase10.rs:102-108`), so the endpoint "just probed" at poll time is `pairs[last]` while
`pairs[0]` is credited. Misattribution follows from the send loop alone and **needs no
roaming**. Revision 2's own §3.2 said this and §3.4 contradicted it. So §9's triage order
("settle the empirical question first") was wrong — it is no longer load-bearing. Related
nuance revision 2 missed: `supports_roaming: false` on the userspace-shared backends
`[agent]`.

**CORRECTED — §5.1 was too strong.** Only the **host** lanes lack a port. Both srflx
lanes carry a real port inside the signed preimage —
`out.extend_from_slice(&sa.port().to_be_bytes())` (`peer_gossip.rs:423`, `:427`,
documented `:382`) `[verified]` — and srflx is direct-eligible. So a gossiped srflx
candidate is already a signed, port-carrying, programmable endpoint, and finding C
("item 1 is a signed wire-format change") applies to the host lane only.

**CORRECTED — a `[verified]` tag with invented evidence.** Revision 2 wrote that the
`handshake_endpoint` overrides were "`tests/ice_pair_race.rs:105`, `:480`, plus three
`#[cfg(test)]` impls". Those three are impls of `SimultaneousOpenRuntime` that do **not**
override `handshake_endpoint`; I conflated trait impls with method overrides and tagged it
verified. The conclusion — no production override — is right and in fact stronger than
stated, but the evidence as written was wrong.

Also noted by review and accepted: A3.2 is **plausible** rather than impossible on the
userspace-shared backend, which already has the source address at inbound demux
(`find_node_id_by_endpoint`) but does not propagate it to the handshake record `[agent]`.
It still requires widening a signature inside `crates/rustynet-backend-wireguard`, which
this work must not touch.

**Net effect on the recommendation.** §9's "land A3.3" is withdrawn. The candidate that
survives review is **A3.1 + item 2 together**, and it needs a proof-surface change as
well, per the A3.3 retraction. Nothing in this document is landable without that
re-scoping, and none of it can be mutation-verified on this host.

## 0a. Evidence provenance

- `[verified]` — I read the cited line myself this session at commit `9859126c`.
- `[computed]` — established by independent calculation.
- `[agent]` — reported by an investigating sub-agent, not re-read by me.
- `[open]` — could not be established; recorded as a question.

Line numbers in both predecessor plans have **drifted**; every citation below was
re-located by symbol. Where a predecessor's number is wrong I give both.

## 1. The result, up front

Three findings, in descending order of consequence.

**A. The corrected definition of "attested" is itself unsound.** The withdrawn plan's
fix — accept only `reason ∈ {ExistingFreshHandshake, FreshHandshakeObserved}` — does not
hold, because in production the race cannot attribute a handshake to an endpoint and
credits `pairs[0]` by default. `FreshHandshakeObserved` therefore does not mean "this
endpoint answered". §3.

My first mechanism for A was **wrong and has been corrected** (§3.1): sender-supplied
`priority` is discarded and recomputed on the race path. The harm survives via a class
ladder in which a public victim IP outranks a legitimate RFC1918 candidate, made worse by
foundation dedupe (only one remote address per lane is probed, §3.2). One empirical
question could still collapse the whole finding, and it cannot be settled on this host
(§3.4).

**B. The approved parent plan's precondition for I4 is unmet.**
`TraversalSelfSustenancePlan_2026-07-23.md` §6 requires return-routability active
*before* enforcement programs from gossip, and §I3 marked that satisfied by
inheritance from `traversal_probe_statuses`, "which already attests reachability"
(§I3 lines 292-295, 317-325). It does not attest. So the guard §6 demands has never
existed. §2.

**C. Item 1 is a signed wire-format change, not plumbing**, and is transitively
blocked on unimplemented work. §5, §6.

## 2. "A probe status means the endpoint was proven" is still false — and worse than recorded

Verified first, as the task required. `crates/rustynetd/src/phase10.rs:6109-6131`, the
`TraversalDecision::FailClosed` arm, reached when the race is exhausted and nothing
answered:

```rust
let endpoint = evaluation.direct_candidates.iter()
    .max_by_key(|candidate| candidate.priority)
    .map(|candidate| candidate.endpoint).ok_or_else(...)?;
self.commit_verified_traversal_path_for_peer(node_id, PathMode::Direct)?;
self.configure_traversal_paths(node_id, Some(endpoint), None)?;
self.reconfigure_managed_peer(node_id, endpoint, PathMode::Direct)?;
Ok(TraversalProbeReport {
    decision: TraversalProbeDecision::Direct,
    reason: TraversalProbeReason::DirectProbeExhaustedUnprovenDirect, ... })
```

All `[verified]`. Still true. Two additions to the record:

- The predecessor's excerpt **omits `commit_verified_traversal_path_for_peer`**. A
  function with **`verified`** in its name is called on the branch where nothing
  answered. That is the predecessor's own §5 lesson occurring one line deeper than the
  predecessor records it. (It is a path-mode transition that clears
  `pending_path_mode`/`pending_since`, `phase10.rs:5786-5800` — misnamed, but it does
  **not** persist proof, so it cannot serve item 5.) `[verified]`
- `TraversalProbeDecision` is `Direct | Relay` (`phase10.rs:250-254`), so no consumer
  can distinguish this from success. `[verified]`

`priority` is sender-supplied: `TraversalCandidate { candidate_type, endpoint,
relay_id, priority: u32 }` at `daemon.rs:2100-2106`, parsed from the signed bundle
section. `[verified]`

### 2.1 Freshness is per-peer; only endpoint coupling makes the good arms sound

`traversal_handshake_is_fresh(&self, value: Option<u64>, now_unix)`
(`daemon.rs:6944-6948`) takes a bare timestamp, sourced from
`backend.peer_latest_handshake_unix(node_id)` — **node_id only, no endpoint**
(`phase10.rs:5924`, `:5963`). `[verified]` So freshness alone proves a peer is
reachable *somewhere*.

The two attesting arms are nonetheless sound, but for a reason the predecessor never
states:

- `ExistingFreshHandshake` (`phase10.rs:5964-5986`) requires `!incumbent_demoted`
  **and** `direct_candidates.iter().any(|c| c.endpoint == current_endpoint)` **and**
  freshness, returning `selected_endpoint: current_endpoint` where `current_endpoint =
  backend.current_peer_endpoint(node_id)`. WireGuard sets a peer's endpoint from an
  *authenticated* source, so this is genuine return-routability. `[verified]`
- `FreshHandshakeObserved` derives from `TraversalDecision::Direct { endpoint }`
  (`phase10.rs:6070-6085`) — the race's own endpoint. `[verified]` **But see §3.**

**Design consequence.** Any rule that keeps the reason check and drops the endpoint
coupling silently reopens S3. The invariant is *endpoint attribution*, not freshness.

### 2.2 Two more ways a status exists with nothing proven

- **Non-due probes clone the status forward.** `daemon.rs:6630-6644` `[verified]`:
  ```rust
  if let Some(endpoint) = current_endpoint { retained.selected_endpoint = endpoint; }
  retained.latest_handshake_unix = latest_handshake_unix.or(retained.latest_handshake_unix);
  ```
  `current_endpoint` is read from `self.controller.managed_peer_endpoint(...)` — what is
  **programmed** `[agent]`. So `selected_endpoint` tracks what is programmed while
  `decision`/`reason`/`attempts` ride forward from an arbitrarily old pass. The
  predecessor cited `:6446-6459`; that range is now the hints/clear block.
- **The handshake stamp is sticky.** `.or(...)` means once `Some`, the field never
  returns to `None` `[verified]`. A peer dead for days keeps a non-`None` stamp; only
  the freshness *comparison* ages it out, never the field. Any design reading the field
  rather than comparing it inherits a permanently-populated value.
- **Key presence carries almost no information**: the map is rebuilt wholesale each
  pass and eleven distinct error paths `clear()` it entirely `[agent]`. A key means
  only "this peer was managed on the last pass that completed", all-or-nothing across
  peers — not a per-peer proof record.

Additionally, `saturating_sub` makes a **future-dated** timestamp permanently fresh:
`now_unix.saturating_sub(timestamp) <= window` yields 0 when `timestamp > now_unix`
`[verified]`. Default window 30 s
(`DEFAULT_TRAVERSAL_PROBE_HANDSHAKE_FRESHNESS_SECS`, `daemon.rs:310`) `[verified]`.

## 3. The corrected "attested" rule is exploitable — endpoint attribution is the real gap

This is finding A, and it is the reason item 3 cannot ship alone.

1. Production uses the **parallel ICE-pair race**. `phase10.rs:6036-6053` builds
   `Phase10PeerRuntime` and calls `engine.execute_ice_pair_race(...)`; the comment at
   `:6042-6044` says "production probe path now uses the parallel ICE-pair race instead
   of the older serial `execute_simultaneous_open`". `[verified]`
2. `Phase10PeerRuntime` implements `SimultaneousOpenRuntime` at `phase10.rs:95-96`.
   `[verified]`
3. **`handshake_endpoint` appears nowhere in phase10.rs**, so the trait default applies:
   `fn handshake_endpoint(&mut self) -> Result<Option<SocketEndpoint>, TraversalError> {
   Ok(None) }` (`traversal.rs:714-716`), whose own doc says the default is for "runtimes
   that don't track per-endpoint state". Every override in the tree is test-only
   (`tests/ice_pair_race.rs:105`, `:480`, plus three `#[cfg(test)]` impls). `[verified]`
4. So the race always takes the fallback (`traversal.rs:1725-1730`) `[verified]`:
   ```rust
   let winning_endpoint = match runtime.handshake_endpoint()? {
       Some(endpoint) => endpoint,
       None => crate::ice_priority::socket_addr_to_socket_endpoint(pairs[0].remote.addr),
   };
   ```
5. The trigger is only that a **per-peer** counter advanced —
   `handshake_advanced(observed_latest, latest) && handshake_is_fresh(...)`
   (`traversal.rs:1722-1723`) `[verified]`. The counter resolves to
   `wg show <if> latest-handshakes` keyed by **public key only**
   (`rustynet-backend-wireguard/src/linux_command.rs:387-396`) `[agent]` — nothing in the
   chain is endpoint-aware.

### 3.1 Correction — my first mechanism for this was wrong

An adversarial review refuted the mechanism I originally gave, and it was right. I had
claimed `pairs[0]` is reachable by setting a large sender-supplied `priority`. **It is
not, on the race path.** `prioritize_traversal_candidates` recomputes priority locally:

```rust
priority: ice_priority(kind, addr.ip()),   // ice_priority.rs:284
```

It reads only `candidate.source` and `candidate.endpoint`; **`candidate.priority` is
never read** `[verified]`. The functions that do consume the sender's integer
(`score_pair`, `score_candidate`) are reached only from `plan_direct_probes` /
`plan_remote_probes`, which the race does not call `[agent]`.

So the raw integer is **not** the channel. Recording the error rather than deleting it,
because "the sender's priority field drives selection" is the intuitive reading and the
next person will reach for it too. Where the sender's integer **is** load-bearing is the
FailClosed arm's `.max_by_key(|candidate| candidate.priority)` (§2) — a different arm,
a different reason code.

### 3.2 The harm survives through a coarser channel, and is worse in two ways

What a remote candidate controls is a **class ladder**, not an integer: `type_pref` from
`source` plus `local_pref` from family and scope (`ice_priority.rs:73-88`, `136-144`).
Concretely Host+Global-v4 = 2 122 317 823 versus Host+Private-v4 = 2 118 123 519
`[agent]`. **A globally-routable victim IP declared `Host` outranks a legitimate RFC1918
host candidate in the same lane** — and a victim IP is by definition globally routable.
Pair priority is monotonic non-decreasing in the remote candidate's priority
(`pair_priority`, `ice_priority.rs:149-155`) `[agent]`, so position 0 stays reachable by
choosing `source: Host` with a global address.

Two facts the review surfaced make this worse, not better:

- **Foundation dedupe probes exactly one remote address per lane.**
  `let key = (l.foundation.clone(), r.foundation.clone()); if seen_foundations.contains(&key) { continue; }`
  (`ice_priority.rs:334-338`), with remote foundation `{prefix}-{kind}-{family}`
  (`:280`) `[verified]`. So an injected candidate that wins its (kind, family) lane means
  **the legitimate endpoint is never probed at all**.
- **Probing already programs every candidate it touches.** `send_probe` calls
  `reconfigure_managed_peer(&self.node_id, endpoint, PathMode::Direct)` before
  `initiate_peer_handshake` (`phase10.rs:102-108`) `[verified]`. Attacker-nominated
  endpoints are therefore installed into the backend **transiently today**, ahead of any
  handshake evidence. The corrected-attested rule's incremental exposure is
  **persistence of that programming**, not first-time programming — which is a smaller
  delta than my original framing implied, and a larger pre-existing exposure.

Timing confirms the misattribution is structural, and refines it: the loop fires the
whole round before polling (`traversal.rs:1706-1721`) `[agent]`, with defaults
`MAX_PAIRS = 24`, `ROUNDS = 3`, `ROUND_SPACING_MS = 80` `[agent]`, so multi-pair is the
normal case. Because `send_probe` rewrites the endpoint per pair, the endpoint actually
installed at poll time is `pairs[last]` while the endpoint *credited* is `pairs[0]` —
the two need not even be the same candidate.

### 3.3 Preconditions, stated honestly

The attack is more constrained than my first framing implied `[agent]`: candidates must
arrive in an **authority-signed** traversal bundle, so this is not an off-path network
attacker; the race must be reached (`probe_due`, a validated signed coordination
schedule, non-empty direct candidates, and the incumbent-fresh-handshake short-circuit
must not fire); `pairs.len() > 1`; and the candidate must win its lane on class.
`traversal_prior_rerank` is off by default `[agent]`, so `pairs[0]` is the pure RFC 8445
top pair.

Whether the signing authority ever ingests peer-self-reported candidates — i.e. whether
the adversary is an ordinary mesh member or requires authority compromise — is `[open]`
and sits outside this crate. **That question sets the severity**, and it should be
answered before this is triaged.

### 3.4 The one empirical question that could collapse this

Everything above rests on the per-peer counter being able to advance for a reason other
than the endpoint just probed. That follows from WireGuard roaming semantics and the
backend advertising `supports_roaming: true` `[agent]`, but **no in-repo code proves it**
and no test was run — cargo is unusable on this host (§11). **If `latest-handshakes` can
only advance from the endpoint just probed, link 5 collapses and this whole finding goes
with it.** It must be settled empirically before any code is written against §3.

Note the existing mitigations do **not** cover this: `validate_traversal_candidate_ip`
(`daemon.rs:14635-14683`) rejects only unspecified/loopback/multicast/link-local/broadcast
for Host, and *requires* a global unicast address for ServerReflexive, so a public victim
IP is admissible as either type; `reject_unreachable_candidates` accepts
`Global | Private` for the same reason; and there is no validation at all between the
race result and programming `[agent]`. An anti-mitigation: `race_outcome_classes`
records the misattributed endpoint's class as a **win** in the persistent prior store
`[agent]`, so the mistake is already being learned across sessions.

**This is the third time a guard in this area would have shipped the harm it
targeted** — the co-location gate, revision 1's attested rule, and now the corrected
attested rule. The shared cause is unchanged: a signal trusted for its name.

**Therefore item 3 must be paired with attribution.** Three options, and the obvious one
is a trap:

- **A3.1 — delete the fallback so an unattributable handshake is not `Direct`. DO NOT DO
  THIS.** I proposed it first and it is wrong. Because `handshake_endpoint()` returns
  `None` *unconditionally* in production (§3, link 3), **every** race outcome is
  unattributable, so denying on `None` would make `execute_ice_pair_race` never return
  `Direct` at all. Every peer would fall to relay or fail closed: a fleet-wide loss of
  direct connectivity. The absence of attribution is total, not occasional — which is
  precisely why the fallback was written.
- **A3.2 — implement `handshake_endpoint` for `Phase10PeerRuntime`.** The correct fix,
  and it needs a backend that can report which endpoint completed the last handshake.
  The command backend cannot: `current_peer_endpoint` returns the **cached configured**
  value rather than a read-back from `wg`
  (`rustynet-backend-wireguard/src/linux_command.rs:489-495`) `[agent]`. Whether any
  backend can is `[open]`, and the code lives in `crates/rustynet-backend-wireguard`,
  which this work must not touch.
- **A3.3 — separate the report from the predicate (landable, §9).** Leave the race's
  behaviour exactly as it is, and stop *calling* its output proof: introduce a distinct
  reason for "a handshake advanced but was not attributed to this endpoint", and exclude
  that reason from the §4 attested predicate. Connectivity is unchanged because
  programming still happens on the same branch; what changes is that no consumer can
  mistake an unattributed handshake for endpoint proof.

## 4. What "attested" must mean operationally

Given §2.1 and §3, the operational definition is:

> A peer P is **attested at endpoint E at time T** iff a WireGuard handshake completed
> with P **and was attributed to E** by a mechanism the sender cannot influence, within
> the freshness window ending at T.

Which code writes that signal today: `phase10.rs:5979` (`ExistingFreshHandshake`,
attribution via `current_peer_endpoint` — an authenticated source, sound) and
`phase10.rs:6079` (`FreshHandshakeObserved`, attribution via the race — **unsound until
§3 is fixed**). Nothing else writes a signal that could bear this meaning. The four
non-attesting arms — `NoDirectCandidatesRelayArmed`, `CoordinationRequiredRelayArmed`,
`DirectProbeExhaustedRelayArmed`, `DirectProbeExhaustedUnprovenDirect` — must never
satisfy it `[agent, arms enumerated]`.

A `Relay` decision attests the relay, not the peer; that distinction is already correct
in the predecessor and is preserved here.

## 5. Item 1 — wiring gossip candidates into an index

**No gossip→traversal path exists.** Established by enumerating both ends rather than
one grep `[agent]`, and spot-verified by me:

- `build_verified_traversal_index` (`daemon.rs:7086`, predecessor said `:6902`) and
  `traversal_direct_probe_candidates` (`daemon.rs:14837`, predecessor said `:14648`)
  both read `self.traversal_hints`, whose sole writer loads a **signed local custody
  file**; the network fetcher is inert (`traversal_url: None`) `[agent]`.
- `applied_endpoints`' doc comment claims "Read by the connect path". Its only non-test
  reader is the self-audit module `[agent]` — another signal trusted for its name.
- The would-be bridge, `ice_priority::prioritize_candidate_set`, whose module header
  advertises "a remote peer's **gossiped** `CandidateSet`", has **zero callers outside
  its own file** `[verified]`.
- The ingest result is discarded at `daemon.rs:5646` (predecessor said `:5587`); a
  *second* call site (`daemon.rs:8527→8539`) does bind the summary but reads only
  `source_node_id` and `sequence` for a log string `[agent]` — the "fourth caller used a
  helper" hazard again.

### 5.1 Gossip cannot express a programmable endpoint today

**Host candidates carry no port, and the signature covers that absence.**
`signing_preimage` emits 16 address bytes plus a literal zero port per host candidate
(`peer_gossip.rs:414`, `:418`), documented at `:380-381` as "2 bytes port=0 padding"
`[verified]`. Port 0 is then hard-rejected in three places: `traversal.rs:358`,
`traversal.rs:1807`, `daemon.rs:14372` `[verified]`.

So item 1 requires **either** a versioned signed wire-format change to carry host ports
— the mixed-fleet migration class the predecessor's §2.3 already flagged, where an old
daemon rejects a new-format bundle whole — **or** a global assumption that every peer
listens on `DEFAULT_WG_LISTEN_PORT = 51820`, which is false for any peer with a
non-default `wg_listen_port`. No per-peer listen port exists in gossip, `PeerConfig`, or
membership `[agent]`.

Two further gaps: **the relay lane is inexpressible** over gossip (four lanes, the
preimage covers exactly those four), so gossip candidates can never satisfy the relay
half of `select_runtime_traversal_endpoints` `[agent]`; and **`priority` must be
invented**, which matters because it drives three `max_by_key` sites — and if every
synthesized value in a class is equal, `max_by_key` silently becomes last-wins on
iteration order `[agent]`.

Naming hazard for implementers: there are **two** distinct `TraversalCandidate` types —
`traversal.rs:35` (public, imported as `ProbeTraversalCandidate` at `daemon.rs:73`) and
a private one at `daemon.rs:2100` `[verified]`.

## 6. Item 1 is transitively blocked on today's gossip identity work

Gossip keys peers on `[u8; 32]` (the Ed25519 verifying key); the traversal index keys on
`NodeId` (a String). Nothing retains a reverse map, so a gossip candidate cannot be
*filed* under the right index key without building one from verified membership
`[agent]`.

That map requires membership's `node_pubkey_hex` to hold the peer's **gossip verifying
key**. It does not: it holds a WireGuard key or raw CSPRNG bytes. That is
`GossipMembershipIdentityAlignment_2026-08-05.md` — committed today as **design only**,
unimplemented, and itself blocked on a missing export primitive and a platform blocker
(Windows cannot hold a gossip identity; macOS never mints one).

**So items 1–2 sit behind unimplemented design work, exactly as the task suspected.**

## 7. Item 4 — denying without deadlocking, and where the fail-open actually is

The predecessor's §2.1 fail-open is precisely located. `apply_traversal_authority_to_peers`
(`daemon.rs:6958-6962`, `&self`) ends `[verified]`:

```rust
if let Some(status) = self.traversal_probe_statuses.get(&peer.node_id) {
    peer.endpoint = status.selected_endpoint;
} else {
    peer.endpoint = self.static_traversal_endpoint(bundle, &peer.node_id)?;
}
```

The `else` branch is the control-plane endpoint. So "hold this peer" keeps the
control-plane endpoint — the accept-via-either fail-open §6 forbids.

**Cold start works *because of* that fallback**, and the deadlock is real
`[agent, links individually cited]`: `sync_traversal_runtime_state` returns early unless
state is `DataplaneApplied | ExitActive` (`daemon.rs:6441-6447`); the controller starts
at `Init` (`phase10.rs:5132`); the unique first entry to the started set is
`apply_dataplane_generation` (`phase10.rs:5322`/`:5327`, the two competing
`transition_to` sites being behind `ensure_started`); and that runs only after the
authority call returns `Ok` (`daemon.rs:7728→7747`, `9323→9352`). Turning the `else`
into a deny closes the cycle — and `promote_to_permanent_if_over_limit`
(`daemon.rs:9332`) escalates it to a **permanent** restriction.

**Resolution (recommended).** Gate the deny on the same condition link 1 uses: deny only
when `self.controller.state()` is already `DataplaneApplied | ExitActive` — i.e. only
when a status *could* have existed — and keep the static fallback for the pre-started
generation. The two conditions then agree by construction and steady state is not
weakened. The trust posture conceded is explicit and bounded: for one generation the
endpoint is *authority-verified* (signature over a custody bundle) but not
*reachability-proven*. That concession must be stated in the plan of record, because it
is exactly the kind of thing that later gets misread as proof.

`apply_traversal_authority_to_peers` takes `&self` and therefore **cannot** record or
expire attestation state `[verified]`; the writing must happen in
`sync_traversal_runtime_state`, which is `&mut self`.

## 8. Item 5 — persistent attestation state does not exist and must be built

Nothing records "when this peer was last proven reachable" `[agent, swept]`. The closest
candidate is `PeerTraversalPrior` (`peer_traversal_prior.rs:89-95`) — persisted as
atomic JSON at `0o600` — but its fields are `last_success_class` (**which** class, never
**when**), `per_class` Beta posteriors, and `updated_at_unix`, which is bumped on failure
paths too `[verified]`. It is also explicitly fail-open on load and persist failure
`[agent]`. Reusing it would repeat this area's characteristic error: adopting a store
because its name suggests proof.

Everything else is in-memory only and documented as such (`flap_breakers`,
`quality_tracker`, `keepalive_estimators`) `[agent]`, and `live_proven` is derived at
read time, never stored `[agent]`.

So item 5 requires **new** state: per-peer `(endpoint, last_attributed_handshake_unix)`,
written only by the §4-conforming arms, cleared on revocation, and persisted with the
same atomic-rename + `0o600` discipline as `PeerPriorStore`. It must be **fail-closed on
load failure** — the opposite of `PeerPriorStore` — because an unreadable attestation
store must not read as "attested". The hold bound is then `now - last_attributed <=
bound`, which satisfies item 5's requirement that a peer which stops gossiping ages out
even though no new candidate expires.

## 9. Item 8, and what is landable now

**Item 8.** `GossipCandidateScopingPlan_2026-07-30.md` §2 fixes two operator-selectable
modes, **`repush` default**, `index` opt-in `[verified]`. The mode changes what "missing
from the index" means, and neither reading is "unreachable":

- `repush`: R indexes what it receives, and upstreams filter. Missing = **nobody
  forwarded it yet** — a convergence delay the doc itself acknowledges ("a permitted pair
  may need more gossip rounds"). Fail-closed on missing converts slow convergence into an
  outage, **in the default posture**.
- `index`: missing **conflates** "no ACL right to P" (deny is correct) with "P never
  gossiped" (deny is a liveness bug).

So I4's deny rule must distinguish absent-because-unscoped from
absent-because-unconverged. That distinction does not exist today and is new work. The
same document also requires `index` mode to be "loud in status output, not silent".

**Nothing is landable as written.** Revision 2 recommended A3.3 here; §0 retracts that on
two grounds — the proof surface (`live_proven`) is reason-blind, so A3.3 would not stop an
unattributed endpoint reporting as proven, and A3.3 creates the mixed-reason case whose
aggregate literal is hard-coded, so it would misreport. It also breaks named in-tree
assertions, contrary to the "observable-neutral" claim.

**The candidate that survives both reviews is A3.1 + item 2, taken together**, plus a
proof-surface change:

1. **Item 2** — stop the `FailClosed` arm programming the max-priority candidate. Must come
   first, because A3.1 alone reroutes unattributed races into exactly that arm, where the
   raw sender-supplied `priority` integer selects the endpoint (`phase10.rs:6113`).
2. **A3.1** — an unattributed handshake is not a `Direct` decision. Safe once item 2 has
   closed the arm it would otherwise fall into, and it does **not** cost direct
   connectivity: `ExistingFreshHandshake` returns `Direct` without entering the race
   (`phase10.rs:5979-5981`), which covers the steady-state peer.
3. **Proof surface** — `live_proven`/`path_live_proven` must stop treating
   path-mode-plus-freshness as proof (`daemon.rs:7461`), and the hard-coded
   `"fresh_handshake_observed"` aggregate fallback (`daemon.rs:7395`, `:7398`) must go.
   Without this, items 1 and 2 leave the strongest proof-named surface still lying.

**RETRACTED IN REVISION 4 — all three steps above were refuted. Do not build this chain.**
The caveat that follows was correct, and the review it asked for has now happened. See
§0.0 for the headline retractions and §9.1 for the per-step evidence. The three numbered
steps above are kept only because the retraction is the transferable part.

This re-scoping has **not itself been reviewed**, and on this document's record that
matters: every previously unreviewed recommendation here has been refuted. It should be
attacked before it is built.

## 9.1 What the third review established, per step

Three independent adversarial reviews (lenses: connectivity/reachability,
attacker-chosen endpoint, proof surface and mutation-provability) on 2026-08-06, each
required to cite `file:line` with quoted line text and told that an endorsement is a
failed review. Every load-bearing link below was then re-verified by hand at `8ffa3a6e`;
claims that did not survive that re-verification are recorded at the end.

**Step 1 — close the fail-closed arm (`phase10.rs:6109-6131`). UNSAFE.** The arm is
reachable only when no relay endpoint exists — `relay_or_fail_closed_for_race` returns
`Relay` first whenever one is available (`traversal.rs:1768`), so step 1 targets exactly
the relay-less topologies, including the same-LAN and hole-punched cross-network meshes
this project has already proven. No non-`Direct`/`Relay` outcome is representable
(`phase10.rs:251`, `phase10.rs:301`), so the only closure is `Err`, which is node-wide
(§0.0). It also converts an overwritten bad endpoint into an unoverwritten one, and leaves
`daemon.rs:14691` untouched.

**Step 2 — A3.1. UNSAFE.** Its stated safety net is unreachable for relay peers, so it
eliminates the only production promotion path to direct (§0.0). One reviewer traced the
demotion concretely: a peer already Direct whose handshake goes stale re-races
immediately (`daemon.rs:2229-2231`, `if was_fresh_when_last_evaluated { return true; }` —
the reviewer cited `:2222-2224`, which is the explanatory comment, not the branch), the
race now declines to return `Direct`, the caller
commits `PathMode::Relay` (`phase10.rs:6085-6087`), and the peer is thereafter pinned.

**Step 3 — proof surface. UNSAFE ONLY IN COMBINATION, and not landable as scoped.** Sound
in isolation as a description; as a change it goes permanently false fleet-wide and breaks
eight named consumers plus one mandatory unit test (§0.0). A second, wider hole it does
not close was surfaced during the review and is recorded here because no item in the
handoff cites it: the `FailClosed` arm installs `PathMode::Direct` to the highest-priority
candidate that was **never probed** (`phase10.rs:6109-6127`), so a later fresh handshake
makes the surface emit `path_reason=direct_probe_exhausted_unproven_direct` together with
`path_live_proven=true` — "unproven" and "proven" on one line.

**Reviewer claims that did not survive re-verification, recorded so they are not
inherited.** One review reported that
`crates/rustynetd/tests/ice_pair_race.rs:391` is the `#[test]` attribute with the function
at `:392`, and presented this as a correction to the handoff. It is wrong: `grep -n` puts
`fn ice_race_falls_back_to_top_priority_when_runtime_lacks_endpoint_attribution()` at
**`:391`** exactly, with `#[test]` at `:390`. Its substantive observation — that the test
discards the reason via `TraversalDecision::Direct { endpoint, .. }` at `:435-437` and so
proves nothing about reasons today — is correct, but it is not a refutation of the
handoff, which already asked for that assertion to be *added*. The same review's
enumeration of `path_live_proven` consumers was also an undercount: it found the
PowerShell gate but missed the four shell consumers listed in §0.0.

Two constraints hold regardless. It cannot be mutation-verified on this host (cargo wedges
under Gatekeeper saturation, §11), and by the standing rule a behaviour change that cannot
be shown to fail a specific test does not ship. And item 4's deny needs a **per-peer skip**
for never-yet-programmed peers, not the global state gate §7 proposed (§0).

**Triage order** once a working build host exists: start with item 2, since it is the
producer-side hole and is independent of attribution. §3.4's empirical question is **no
longer a prerequisite** — §0 retracts that framing; misattribution follows from the send
loop without any roaming assumption.

**Not landable, and why:** items 1–2 (signed wire change + the unimplemented gossip
identity work, §5–§6); item 3 alone (unsound without A3.1, §3); items 4–5 (depend on §3
for the signal and on new persistent state, §7–§8); item 6 (same signal); item 8 (needs
the scoping modes built).

## 10. §6 invariants touched

| Change | §6 invariant | Effect |
| --- | --- | --- |
| A3.3 separate report from predicate | "Never program a self-asserted endpoint that has not passed return-routability (S3)" | Does **not** restore it — programming is unchanged (§3.2). It stops an unattributed handshake being promoted to proof, which is what §6 needs before I4 consumes the signal |
| A3.2 real attribution (blocked) | same | Would restore it properly; needs a backend change this work must not make |
| Item 2 close the FailClosed arm | same | Restores it on the producer side |
| Item 4 gated deny | "Fail closed on missing/stale/unverifiable … exclusive precedence, each side fails closed independently" | Moves toward it; concedes one authority-verified generation at cold start (§7) — must be recorded, not silent |
| Item 5 persistent attestation | "No widening of the 120 s / 300 s TTLs" | New bound must sit inside existing TTLs, not extend them |
| Item 1 wire change | "No guard-free programming window (I3 before I4)" | Cannot be satisfied until §3 lands, since the guard §6 names never existed (§2) |
| Item 8 mode reconciliation | "no fail-open path" | `repush`-default missing≠unreachable must not become accept-anyway |

## 11. Could not establish

- **The load-bearing one (§3.4): whether `latest-handshakes` can advance for a reason
  other than the endpoint just probed.** A negative answer collapses §3 entirely. It
  follows from roaming semantics and `supports_roaming: true` `[agent]`, but no in-repo
  code proves it and no test could be run. Settle this before writing code against §3.
- Whether the backend can report which endpoint completed the last handshake, i.e.
  whether A3.2 is implementable. The command backend demonstrably cannot
  (`current_peer_endpoint` returns the cached configured value) `[agent]`; the
  userspace-shared backend is unaudited. Either way it lives in
  `crates/rustynet-backend-wireguard`, which this work must not touch.
- Whether the signing authority ingests peer-self-reported candidates, which determines
  whether §3's adversary is an ordinary member or requires authority compromise — i.e.
  it sets the severity (§3.3).
- A worst-case staleness bound for the §2.2 clone-forward path; it depends on
  `traversal_probe_due_decision` interacting with the flap breaker and reprobe interval
  `[agent, explicitly not derived]`.
- Whether an out-of-tree signing authority mints traversal bundles from observed gossip.
  No in-repo writer does `[agent]`.
- ~~The `max_reconcile_failures` threshold governing §7's escalation to permanent
  restriction~~ **RESOLVED: `DEFAULT_MAX_RECONCILE_FAILURES = 5`, `daemon.rs:338`
  `[verified]`.**
- Nothing here was compiled or tested: cargo is unusable on this host (macOS Gatekeeper
  saturation wedges test-binary exec for hours). Every claim is static reading.
  **Re-measured 2026-08-06, and the diagnosis is now precise rather than inferred.** With
  all ten UTM guests stopped, zero swap in use and a warm build (`Finished` in 0.61 s):
  `cargo --version` returns in 0.027 s and `cargo fmt --all -- --check` **passes in
  3.7 s**, so cargo itself is healthy. What is wedged is specifically **test-binary
  execution** — a full `cargo nextest run --workspace --all-targets --all-features
  --locked --retries 0` was killed at **68 minutes with no `Summary` line**, and the same
  command narrowed by `-E 'test(=…)'` to a **single** test was killed at **10 minutes**
  without completing. The signature: binaries turned over in seconds for the first ~30
  minutes, then the tail stalled with every test binary at **0.0 % CPU in state `S`** for
  3–16 minutes each while `syspolicyd` accumulated 227 minutes of CPU, with zero swap in
  use — Gatekeeper validating each freshly built unsigned binary on exec, not memory
  thrashing. Note also that the killed run left a 209-byte log with no summary and zero
  FAIL lines, which reads exactly like a clean run; it was not one.
- **CORRECTION — "cargo is unusable here" is too strong, and the first version of this
  entry drew exactly the wrong conclusion from the right measurement.** The tax was then
  measured directly rather than inferred, by running one **prebuilt** test binary with no
  cargo involved:

  | Exec of `target/debug/deps/ice_pair_race-<hash>` | Wall clock | CPU |
  | --- | --- | --- |
  | 1st | **25.559 s** | 0.00 s user, 0.00 s system |
  | 2nd | **0.007 s** | 0.00 s |
  | 3rd | **0.005 s** | 0.00 s |

  Twenty-five seconds of pure blocking to start a binary that then does 0.00 s of work —
  and **the validation is cached per binary**, so the tax is paid **once per freshly built
  binary**, not once per exec. That reframes everything: the workspace has ~155 test
  binaries, so a cold suite pays roughly 155 × 25 s ≈ 65 minutes of pure Gatekeeper
  latency *before* the tests themselves cost anything — which is precisely where the run
  above was when it was killed at 68 minutes. It was not wedged; it was finishing paying.
  It also explains why `-E 'test(=…)'` did not help: nextest must exec every binary with
  `--list` to resolve the filter, so a single-test selection still pays the full listing
  tax.

  So on this host: `cargo fmt` (3.7 s) and single-binary verbs such as
  `ops check-secrets-hygiene` (1 min, PASS) are fine; a full gate is slow but **not
  impossible**; and targeted mutation verification is cheap once the binary exists,
  because re-running it costs milliseconds. **Do not record this host as unable to build.
  Record it as one where the first exec of each new test binary costs ~25 s.**
