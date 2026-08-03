# Gossip status surface — make the gossip data plane observable

**Status:** **IMPLEMENTED** — `001c23b1` (surface + 11 fields + 17 tests) and
`ab8e47e4` (defects found by the implementation review). Revision 5 of the plan;
four adversarial reviews in total. Revision 3's central decision was refuted and
revision 4's justification for reversing it was refuted in turn. What survives is
the *conclusion* (fields go on `status`) with a **different and honest reason**.
Implements item **7** of `I4EnforcementFlipPlan_2026-07-30.md` §4, which the
adversarial review called a **ship-blocker, not a nice-to-have**.

**Live-lab acceptance is UNMET, and the reason is stronger than a missing run.**
§6's acceptance ("the totals move under real traffic; a rate-limited origin is
visible") cannot be satisfied by **any configuration currently in this repo**.
`build_gossip_node` (`daemon.rs:4036`) returns `None` unless both
`RUSTYNET_GOSSIP_SIGNING_SECRET` and `RUSTYNET_GOSSIP_SIGNING_SECRET_PASSPHRASE`
are set (note: **no `_PATH` suffix** — the Rust constant is named
`GOSSIP_SIGNING_SECRET_PATH_ENV` but its value is not, and copying the identifier
name would set a variable the daemon never reads), and
**nothing sets them** — not a systemd unit, not a launchd plist, not a bootstrap
script, not an orchestrator stage. Only the CLI argument parser
(`main.rs:2978`, `:2992`) reads those fields at all. (`--gossip-watermark` *is*
passed by the installers, which makes the subsystem look wired when it is not.)

So on every shipped and lab node today `gossip_node` is `None`,
`drain_gossip_inbound` early-returns, the socket is never bound, and all eleven
fields render their unconfigured constants — a fixed 290 B. A live run right now
would append a row reading `gossip_state=unconfigured` and prove nothing about
the counters.

`documents/operations/live_lab_node_run_matrix.csv` ends 2026-07-29 at commit
`8a2d613644ea` and references none of these commits. Per CLAUDE.md §9 this scope
is complete in code and gates but **not live-proven**, and proving it requires
first wiring the signing secret into a deployment path. Outstanding work, not a
claimed result.

**Line numbers are as of `b3870a19`.** They shift whenever the file does — this
work alone moved `daemon.rs` by ~700 lines, which invalidated every citation an
earlier revision had made. Treat the **symbol names** as authoritative and the
numbers as a hint; if one does not land, grep the symbol.

**Precedence:** CLAUDE.md §3/§4. This change is **read-only observability** — it
adds no enforcement and no trust decision. It adds three new non-trust diagnostic
counters; §2.4 declares them rather than claiming otherwise.

---

## 1. Why this first

Every other item in the I4 scope is a trust-sensitive change to a path that
programs endpoints. This one is not: it exposes counters that already exist.
That makes it the only item in that list which is **safe to build before the
design questions are settled**, and it is a prerequisite for diagnosing the
others.

Concretely: the gossip node maintains `accepted_count` (`gossip_runtime.rs:245`),
`minted_count` (`:246`) and `rejected_counts` (`:242`, bumped at `:751`) —
including the `origin_rate_limited` counter landed in `021c1ef0`. **None has a
production reader** (repo-wide, they are read only by
`crates/rustynetd/tests/gossip_three_peer_mesh.rs`). So today, six distinct
failures are indistinguishable from a healthy node:

1. Gossip is being **rate-limited** — the `021c1ef0` limiter is invisible.
2. Every bundle is **rejected** (`revoked_source`, `unknown_source`,
   `epoch_outside_window`, `timestamp_outside_window`) — identical to receiving
   nothing.
3. The **transport never bound**.
4. Every **outbound push fails** — both the mint broadcast and the epidemic
   re-push (§2.3).
5. Inbound datagrams **fail to decode**, aborting the drain, counted nowhere
   (§2.3).
6. The node's **gossip identity does not match its membership pubkey**, so every
   peer rejects its mints (§2.3).

The lab consequence is concrete: `xnet2`'s `fedora-x86-1` sat in
`restriction_mode=Permanent` and the *traversal* alarm surfaced the reason. Had
the fault been in gossip instead, there would have been nothing to read.

## 2. Scope — the fields go on `status`

Extend the **`IpcCommand::Status`** response line (`daemon.rs:8040`).

### 2.1 The surface question, and the rule that actually decides it

Revision 3 moved these fields to `netcheck`; revision 4 moved them back to
`status`. Both used a rule neither surface satisfies.

**Neither `status` nor `netcheck` is side-effect-free.** Both call
`refresh_traversal_hint_state` (`daemon.rs:4922`) — `Status` with
`force_reprobe=false` (`:7919`), `Netcheck` with `true` (`:8146`) — and that
parameter is threaded to **exactly one** place, `sync_traversal_runtime_state`
at `:4978`. Everything before it is identical for both. So **`rustynet status`
also**:

- reads the watermark and bundle set from disk (`:4930`, `:4940`);
- **writes** the traversal anti-replay watermark to disk (`persist_traversal_watermark`, `:4949`);
- bumps `traversal_hint_generation` (`:4929`);
- on a `sync_traversal_runtime_state` error in enforced mode, calls
  `restrict_recoverable` + `force_fail_closed_or_restrict` (`:4981-4982`).

Revision 4 asserted status was "the cheap surface". It is cheap**er**, not cheap.
A qualifier the reviews did *not* establish, and which matters: the four
`traversal_probe_statuses.clear()` sites that would make a subsequent pass re-race
every peer (`:4936`, `:4953`, `:4966`, `:4975`, feeding the
`existing_status == None ⇒ due` branch at `:2178-2180`) are all in
`refresh_traversal_hint_state`'s **error and missing branches**, not its happy
path. So `status` triggers an ICE re-race only when traversal state is *already*
broken — real, but not the routine cost `netcheck` pays unconditionally.

**The rule that actually decides it** is not "is the surface pure" — none is —
but: *does this change increase the frequency or cost of a side-effecting call?*

- **`status`: no.** It is already the primary operator command and is already
  polled by every live-lab validator. Adding fields to an existing response adds
  **zero** new calls, at zero new cost. The marginal risk is nil.
- **`netcheck`: yes.** It would have driven gossip-cadence polling onto the
  unconditional path — `traversal_probe_due_decision` short-circuits
  `if force_reprobe { return true }` (`:2175`), forcing every peer through
  `execute_ice_pair_race` (`phase10.rs:6053`): up to 24 pairs × 3 rounds, each
  followed by an 80 ms `std::thread::sleep` (`phase10.rs:121-127`), on a daemon
  loop whose own comment warns a stall takes down "DNS drain, reconcile, **and
  gossip**" (`daemon.rs:15499`). Polling gossip health would have stalled the
  gossip plane being measured.

Revision 3's other three arguments were also false and are recorded so they are
not re-derived: the "structural twins live on netcheck" claim was wrong — they
live on **both**, and **57 of netcheck's 72 keys are duplicated onto `status`**,
making duplication the precedent and netcheck-only the deviation; the `--json`
argument (§6.1) argues for fixing `status --json`, not for relocating a
diagnostic away from it; and the Windows-cap argument cannot discriminate, since
gossip is unix-only (§2.5) and the suffix is fixed on Windows either way.

**Conceded, because the rule is satisfied narrowly.** It is true of the diff —
this change adds no call — but these fields exist so that operators and validators
*will* poll `status` to watch gossip health, and `Status` is side-effecting. The
rule is therefore answered on the diff rather than on the intent. The honest
disposition: the correct home is the side-effect-free read path named below, and
`status` is where the fields go *until that exists*.

**That both read commands mutate state is a real defect — it is just not this
plan's defect.** Logged as §6.6/§6.7, with the proper remedy named there: a
genuinely side-effect-free read path, which would also be the right home for a
future high-frequency gossip poll. Building it here would be scope creep into a
trust-sensitive refactor, and would leave the far larger `status` hazard unfixed
anyway.

No authorization change is needed: `IpcCommand::Status` is permitted for every
role in `NodeRole::allows_command` (`daemon.rs:1416-1440`). (Revision 3 called
these "foreign-uid allow lists" — wrong. Peer-credential authorization is
**uniform across every command**; see `authorize_local_peer`, `daemon.rs:15740-15752`.)

### 2.2 Implementation shape — one named argument, not eleven positional ones

The status `format!` already takes **84 positional `{}`** plus 2 `{:?}` for 86
fields. The fields are therefore built by a helper returning one pre-formatted
string, and the format string gains exactly **one named capture** appended at the
end:

```rust
let gossip_suffix = self.gossip_status_suffix();   // " gossip_state=… gossip_…"
format!("… membership_active_nodes={}{gossip_suffix}", …)
```

Verified mechanics: a named capture mixes freely with 84 positional arguments and
consumes no positional slot; the helper returns an owned `String` bound before the
`format!`, so there is no borrow conflict with the immutable `self` borrows
around it.

The justification is **transposition, not miscount** — revision 4 had this wrong.
A miscount is a hard compile error in both directions (`N positional arguments in
format string, but there are M arguments` / `argument never used`). Only a
*transposition at the correct count* is silent, and that is the hazard eleven more
positional arguments would add. The helper also makes every new field unit-testable
in isolation, without constructing a status line.

### 2.3 Fields

Eleven fields, appended in this order.

| Field | Source | Meaning |
| --- | --- | --- |
| `gossip_state` | `gossip_mint_attached()` (`daemon.rs:5659`) + `gossip_node.is_some()` | `unconfigured` / `attached_pending_transport` / `active` |
| `gossip_accepted_total` | `accepted_count` | bundles accepted since start |
| `gossip_minted_total` | `minted_count` (`gossip_runtime.rs:246`) | bundles **minted** — signed and watermark-committed. **Not delivery-confirmed** |
| `gossip_push_failures_total` | **new counter** — both push loops (§2.4) | outbound pushes that failed |
| `gossip_recv_errors_total` | **new counter** (§2.4) | inbound datagrams that failed to decode |
| `gossip_rejected_total` | sum of `rejected_counts` | bundles rejected since start |
| `gossip_reject_reasons` | `rejected_counts` | **`kind=count`** list, `,`-joined, sorted by kind; `none` when empty. **NOT `kind:count`** — §4.1 |
| `gossip_peers_registered` | `peers.len()` (`gossip_runtime.rs:203`, `pub`) | peers the node may accept from |
| `gossip_local_epoch` | accessor `local_membership_epoch()` (`gossip_runtime.rs:375`) — the field is private so the monotonic setter stays the only mutation path | the I2 epoch bound; `none` before first verified commit |
| `gossip_identity_mismatch` | **computed fresh** (§2.4) | `true` / `false` / **`unknown`** |
| `gossip_transport_error` | **new field** (§2.4) | `none`, or the last bind error, sanitised and capped |

**`gossip_minted_total` alone is a lie, and revision 3 shipped it as a truth.**
`minted_count` is incremented at `gossip_runtime.rs:453` — **before** the
broadcast loop at `:439-450`, and unconditionally of push success. So a node whose
every push fails shows a healthy, rising `gossip_minted_total`. Revision 3
justified the field as exposing exactly that failure; it does the opposite.

**`gossip_push_failures_total` must cover both push loops.** There are two, and
revision 4 instrumented one:
- mint broadcast — `gossip_runtime.rs:456-472`, warn at `:443`;
- epidemic re-push — `gossip_runtime.rs:529-545`, warn `gossip_repush_failed` at
  `:513`.

On a node acting as an epidemic relay, re-push is the **dominant** outbound path.
Counting only mints would leave §1's fourth failure unsolved on exactly the nodes
where it matters most. Both sites bump the same counter, so the field name stays
honest.

**`gossip_recv_errors_total` closes §1's fifth failure.** `drain_gossip_inbound`
(`daemon.rs:5614-5648`) handles a transport-level decode failure as
`Err(err) => { log::warn!("gossip_recv_error reason={err}"); break; }` — counted
nowhere. Note the rejection counters *are* reached on the UDP path (they live
inside `ingest_inbound_bundle`); it is specifically the **pre-decode** failures
that vanish. A peer emitting malformed datagrams therefore produces
`accepted=0, rejected=0, reasons=none` — indistinguishable from silence. (The
`break` also aborts the rest of that drain pass; the loop is already bounded at
`MAX_DRAIN_PER_ITERATION = 16`, so this is a stall, not an unbounded DoS. Fixing
the `break` is an enforcement change — logged §6.8, not done here. Counting it is
observability, and is done here.)

**`gossip_identity_mismatch` is computed fresh and is three-valued — it does NOT
reuse the existing latch.** A node whose membership pubkey ≠ its gossip verifying
key has its mints rejected by every peer, and the daemon already detects this
(`daemon.rs:5568-5582`). But `gossip_identity_mismatch_warned` (`:3844`) is a
**one-shot warn latch**: its complete write set is declaration `:3844`, init
`false` `:4291`, set `true` `:5534` — **nothing ever clears it**, and `:5526`
short-circuits on it (`if !self.gossip_identity_mismatch_warned && …`), so once
true the check stops running entirely. Surfacing it directly would ship a field
that reads `true` forever after a mismatch is *repaired*, violating in the same
table the clear-on-recovery rule this plan imposes on `gossip_transport_error`.

It also fails **open**: the condition only detects a mismatch when the local node
id is found in `membership_state.nodes`. Absent local entry, `membership_state`
`None` (early return `:5518`), or `gossip_node` `None` (`:5515`) all yield
"no mismatch" — indistinguishable from a verified match. Reporting `false` there
is a default-allow read on a trust-adjacent signal (CLAUDE.md §10.4).

So the field is derived at status time from the same two inputs, and reports
**`unknown`** whenever the comparison could not be made. Absence of evidence is
never rendered as evidence of absence. The latch is left untouched — its
warn-once behaviour is correct for a log.

**`gossip_rejected_total` is kept despite being derivable** from the reason list.
It is one number an alert can threshold without parsing a variable-length value,
and it stays correct if the list is ever bounded. 24 bytes for that is worth it.

**`gossip_state` needs two predicates.** `gossip_mint_attached()` is
`gossip_node.is_some() && gossip_transport.is_some()` — two states. Three require
also asking `gossip_node.is_some()`. That is not the fork its doc-comment warns
against: `gossip_mint_attached()` remains the sole authority for `active`, and the
extra check only splits the remaining `false` case. Verified total over reachable
states: node=`None` + transport=`Some` is unreachable — both writers set the pair
together (`:5457-5458`) or set transport strictly downstream of the
`gossip_node.as_mut()` early return (`:5515` → `:5493`), and nothing assigns
`None` back.

**The middle state has two causes, and revision 1 modelled only one.** The
transport binds inside `sync_gossip_data_plane` (`daemon.rs:5530-5548`); a bind
failure (EADDRINUSE on a restart race) is logged and retried, leaving node=`Some`,
transport=`None` **with membership already committed**. Calling that
`awaiting_membership` would mislabel exactly the persistent fault this surface
exists to expose, and contradicts the sibling field: `set_local_membership_epoch`
runs at `:5528`, *before* the bind. Hence the neutral `attached_pending_transport`
plus a separate `gossip_transport_error`.

**Two honest limits, stated so they are not over-read:**

- `attached_pending_transport` also covers the *awaiting-membership* cause
  (`sync_gossip_data_plane` returns at `:5518` before any bind is attempted), where
  `gossip_transport_error` is legitimately `none`. That combination is diagnosable
  via `gossip_local_epoch=none`, but it is not self-describing.
- `active` means "bound once", not "healthy". `daemon.rs:5530` gates the bind on
  `gossip_transport.is_none()` and nothing re-binds or health-checks an attached
  socket, so a transport that dies later reads `active` indefinitely. §1's third
  failure is answered; "is the transport *still* working" is not, and this plan
  does not claim it is. Logged §6.9.

### 2.4 The new state, declared

| New state | Where | Written | Cleared |
| --- | --- | --- | --- |
| `pub push_failed_count: u64` | `GossipNode` | both push loops, `gossip_runtime.rs:464` and `:513` | never (monotonic) |
| `gossip_recv_errors: u64` | daemon runtime | drain error branch, `daemon.rs:5644` | never (monotonic) |
| `gossip_transport_error: Option<String>` | daemon runtime | bind-failure branch, `daemon.rs:5543` | **on successful bind**, so a resolved fault does not read as live |

`push_failed_count` is `pub` — `gossip_runtime` and `daemon` are sibling modules,
so a private field would be unreadable from the status surface. This matches its
siblings `accepted_count` / `minted_count` (`:245-246`); the accessor treatment is
reserved for `local_membership_epoch`, which is private *specifically* to keep the
monotonic setter the only mutation path.

Adding a field to `GossipNode` is **not** a wire-format change: `persist_watermark`
(`gossip_runtime.rs:718-726`) serialises a separate
`GossipWatermark { local_sequence, seen }`. Nothing serialises `GossipNode`.

Clear-on-bind is reachable: the `gossip_transport.is_none()` gate at `:5493` does
not make the bind one-shot — `sync_gossip_data_plane` re-runs at four signed-state
commit seams (`:5069`, `:7765`, `:8838`, `:9403`), so a failed bind is retried and
the `Ok` branch at `:5532-5534` runs.

Revision 2's §3 claimed "no new state". That was untrue; the honest framing is
narrower: **no new *trust* state.** These values are never consulted by any
decision — no policy, no ACL, no acceptance path reads them; never persisted;
write-only from their branch, read-only by one surface. The one free-form string is
sanitised via `sanitize_netcheck_value` (`daemon.rs:15769`) and capped at 64 bytes.
That function maps every character outside `[A-Za-z0-9_\-:./+]` to `_` — including
**whitespace and `=`** — so it can neither forge a `key=value` token nor split into
extra whitespace tokens. Its output is pure ASCII, so a `.chars().take(64)` cap is
byte-exact and cannot panic on a char boundary.

Omitting `gossip_transport_error` was the alternative, rejected because
`attached_pending_transport` with no reason is undiagnosable, and an operator who
cannot tell "port in use" from "permission denied" at 2am has been handed a correct
control that is a bad control.

### 2.5 Platform: gossip is structurally unix-only

The `#[cfg(not(unix))]` `GossipTransport::bind` stub **always** returns
`Unsupported` (`gossip_transport.rs:232-236`), and `validate_daemon_config` rejects
a configured gossip secret on non-unix (`daemon.rs:11544-11552`) — and its only
production caller (`:10120`, in `run_daemon`) runs *before* the only production
`DaemonRuntime::new` (`:10135`), where `build_gossip_node` (`:4285`) runs. Every
other `DaemonRuntime::new` is `#[cfg(test)]`. So on Windows `gossip_state` is
permanently `unconfigured`, every counter `0`, and the suffix is a **provably fixed
290 B**.

Fields are emitted **unconditionally**, not `cfg`-gated, so the schema is uniform
and an absent key cannot be confused with an old daemon. Cost stated in §4.3.

### 2.6 Privacy constraint — binding

`daemon.rs:8524-8527` states the retention policy: an ingest string **MUST NOT**
include the bundle's candidate list, only the 8-byte source prefix and the error
variant name.

This plan is stricter: **no addresses and no node ids at all.** `rejected_counts`
is `HashMap<&'static str, u64>` (`gossip_runtime.rs:242`) and `bump_reject_counter`
takes `kind: &'static str` (`:726`), which **structurally excludes** formatted peer
data — including `GossipError::UnreachableCandidate { addr: String }`
(`peer_gossip.rs:224`), whose `addr` is dropped by the mapper at `:917`.
`peers.len()` is a count. `local_membership_epoch()` returns the value `status`
already publishes as `membership_epoch=`. The one free-form value,
`gossip_transport_error`, is a local `io::Error` from binding a local socket — no
peer identity — sanitised and truncated regardless.

## 3. Non-goals, stated so they are not smuggled in

- **No enforcement change.** Nothing about what is accepted, programmed, or
  rejected changes. If this commit alters a trust decision, it is wrong.
- **No new trust state.** Three new diagnostic counters (§2.4), fully declared.
- **No change to the identity-mismatch warn latch** — read fresh instead (§2.3).
- ~~**No fix for the `break` in `drain_gossip_inbound`** — that is an enforcement
  change.~~ **Reversed during implementation, deliberately and on the record.**
  The implementation review showed the `break` does not merely defer a fix — it
  makes the *new counter's units wrong*: incrementing at most once per drain pass,
  which runs once per main-loop iteration against an idle sleep of up to 25 ms, so
  the counter saturates near the loop rate and a flood renders like a trickle. A
  counter that stops growing with the attack is worse than no counter. On
  inspection the `break` is also not an enforcement change: no trust decision
  moves, and the pass is already bounded by `MAX_DRAIN_PER_ITERATION = 16`, so
  `continue` cannot spin. It also removes a stall where one malformed datagram
  delays every legitimate bundle behind it. Changed to `continue` in `ab8e47e4`,
  with `status_counts_every_malformed_datagram_not_just_one_per_drain` pinning it.
  Recorded here rather than quietly widened.
- **No fix for `status --json`** (§6.1). Repairing it means giving the status line
  a `prefix:`, breaking every whitespace parser and 18,000+ captured lines.
- **No re-bind or transport health check** (§6.9).
- **Not the I4 three-state disposition.** Withdrawn; this surface must not presume
  it returns.

## 4. Risks

### 4.1 Formatting and parser compatibility

- **Append only.** Consumers split on whitespace and `strip_prefix("key=")`
  (`extract_inline_field`, `ops_cross_network_reports.rs:370-376`; the PowerShell
  reader anchors with `(^|\s)`, `Verify-RustyNetWindowsBootstrap.ps1:481`).
- **One named argument, not eleven positional ones** — §2.2.
- **`kind=count`, never `kind:count`.** A colon inside a value is what breaks
  `status --json` (§6.1). Note `gossip_reject_reasons` will be the **first
  schema-designed status value containing `=`** — the `iface=ips` precedent
  (`local_host_candidates`) is on the **netcheck** line, not status, and revision 4
  cited it wrongly. This is safe rather than precedented: `extract_inline_field`'s
  `strip_prefix` requires the token to *start* with `key=` and is inert to a
  nested `=`.

**Deleted from revision 2: "field-count drift."** Verified a non-risk — no test,
validator, script or parser asserts a token or field count on either line. The only
`fields.len() != expected` sites parse **signed bundle wire formats**
(`daemon.rs:13394`, `:14322`, `:14460`; `main.rs:16657`;
`rustynet-dns-zone/src/lib.rs:403`). Repo-wide there is exactly one
`split_whitespace().count()`, in `rustynet-llm-gateway/src/engine.rs:250`.

### 4.2 Substring shadowing — a real hazard that already bites

Some consumers test raw substrings rather than parsed tokens:
`contains("state=FailClosed")` (`ops_live_lab_orchestrator.rs:2979`, `:2981`,
`:2999`) and `contains("state=ExitActive")` (`live_linux_two_hop_test.rs:1210`). A
field whose **name ends with an existing field's name** shadows it.

Not hypothetical: the status schema already has **six** such collisions (five
`*_state=` keys shadow `state=`; `serving_exit_node=` shadows `exit_node=`), and
`daemon.rs:28536`'s `assert!(status.message.contains("state="))` is **vacuous
today**.

Of the eleven proposed names, exactly one collides: `gossip_state` ⊃ `state`. Its
closed value set — `unconfigured` / `attached_pending_transport` / `active` — makes
neither live needle a substring today, but it is one value away, and the failure
direction is the dangerous one: a shadowed `contains` flips a live-lab verdict
red→**green**. A test pins the vocabulary (§5).

### 4.3 Response size

`MAX_WINDOWS_DAEMON_CONTROL_MESSAGE_BYTES = 4096` (`windows_ipc.rs:589`) bounds the
**response**, and exceeding it is a hard error that **never truncates**: the server
refuses at `rustynet-windows-native/src/lib.rs:777-782`, before
`write_pipe_message`. The daemon pipe thread only `log::warn!`s
(`daemon.rs:10419-10422`), so the client sees an opaque 5-second timeout
(`main.rs:17198`). Unix has **no response cap** (`ipc.rs:311` bounds only the
request; the Unix client uses an unbounded `read_line`, `main.rs:17180-17184`). The
wire adds `ok|` and `\n` (`ipc.rs:176`), so the Windows budget is **4092 B**.

Measured:

| Surface | Static skeleton | Fields | Longest real capture |
| --- | --- | --- | --- |
| `status` | 2178 B | 86 | **3433 B** — `artifacts/live_lab/20260410T003016Z_5node_utm_retry32_full/state/parallel-validate_baseline_runtime/results.tsv` |
| `netcheck` | 1927 B | 72 | **2825 B** — `artifacts/live_lab/20260410T122500Z_5node_live_lab/diagnostics_validate_baseline_runtime/vm_lab_status.json` |

This plan's suffix, recomputed for all eleven fields (revision 4 understated this
by 30% because it costed nine):

- **Windows: a provably fixed 290 B** — gossip cannot run there (§2.5), so every
  counter is `0`, both strings `none`, state `unconfigured`, mismatch `unknown`.
  Worst real status 3433 + 290 = **3723 B against 4092**. Fits.
- **Unix worst case ≈ 1125 B**: `gossip_reject_reasons` with all 16 kinds (§4.4) at
  `u64::MAX` is 284 B of names + 16×(1+20) + 15 commas + 22 B key + 1 space =
  **658 B**; the other ten at maximum width, with the 64-byte cap on
  `gossip_transport_error`, are **467 B**. Unix has no cap, so this bounds nothing
  but is stated to keep the line honest. Typical (0 reject kinds, small counts):
  **~290 B**.

**The honest cost.** Status carries `managed_peer_endpoints` (`daemon.rs:5906`), a
`+`-joined list **linear in mesh size** at ~33 B/peer, reaching the 4092 B Windows
cliff at roughly **40 peers today**. The fixed 290 B suffix costs **8.8 peers**,
moving the cliff to **~31**. Accepted because (a) both figures are far above the
current 7-node lab, (b) the cliff is a pre-existing defect needing a real bound
rather than an 8-peer workaround (§6.3), and (c) `cfg`-gating to buy those peers
would make the schema platform-dependent and an absent key ambiguous with an old
daemon. Stated so it can be attacked rather than discovered.

### 4.4 The reject-kind vocabulary is 16, not 12

Anyone sizing this by grepping `GossipError` gets 12 and misses the counter this
plan exists to expose. `error_kind()` (`gossip_runtime.rs:973-987`) is an
exhaustive 12-arm match with no `_` arm; four kinds are **ad-hoc literals** at call
sites:

| Kind | Site |
| --- | --- |
| `oversized` | `gossip_runtime.rs:494` |
| `self_origin` | `:549` |
| `membership_epoch_unknown` | `:559` |
| **`origin_rate_limited`** | `:611` — the `021c1ef0` limiter |

All `bump_reject_counter` sites are `:472, :480, :549, :559, :578, :595, :611`;
`:480`/`:578` pass `error_kind(&err)`, and `:595`'s `revoked_source` is already one
of the 12. No other code writes `rejected_counts`. `transport_error_kind`
(`:925-932`) feeds only the `gossip_repush_failed` log and never the counter.

## 5. Test plan — each with the mutation that must make it fail

Gossip tests in this file are `#[cfg(unix)]` (`daemon.rs:25956`); this family
follows. Helper: `build_runtime_with_custom_relay` (`daemon.rs:18824`), which
configures no gossip secret and so yields `unconfigured` directly. Other states use
the hand-assignment pattern the existing tests already use (`:25802` sets
`gossip_bind_addr`; `:25811`/`:25879` assign `gossip_node`). The bind-failure state
is reached by setting `gossip_bind_addr` to an unbindable address before
`sync_gossip_data_plane`.

| Test | Mutation that must make it fail |
| --- | --- |
| `status_reports_gossip_unconfigured_when_no_signing_secret` | report `active` when the node is absent |
| `status_reports_attached_pending_transport_when_bind_failed` | collapse the middle state into `active` — the §2.3 bind-failure case |
| `status_reports_transport_error_and_clears_it_on_successful_bind` | leave the stale error set after recovery |
| `status_reports_gossip_accept_mint_and_reject_totals` | hardcode zeros |
| `status_counts_push_failures_from_both_mint_and_repush` | instrument only the mint loop — leaves relays blind (§2.3) |
| `status_counts_inbound_decode_errors` | drop the drain-error counter — malformed traffic reads as silence |
| `status_reports_identity_mismatch_as_unknown_when_uncheckable` | report `false` when membership or the node is absent — **the §2.3 fail-open** |
| `status_reports_identity_mismatch_true_and_false_from_live_inputs` | read the sticky latch instead of computing fresh — a repaired mismatch reads `true` forever |
| `status_reject_reasons_include_origin_rate_limited` | omit `rejected_counts` — the `021c1ef0` limiter stays invisible |
| `status_reject_reasons_are_deterministically_ordered` | iterate the `HashMap` directly — flaky, unparseable output |
| `status_gossip_tokens_contain_no_addresses_or_node_ids` | interpolate a peer id or endpoint — **the §2.6 privacy pin** |
| `status_gossip_state_vocabulary_cannot_shadow_existing_needles` | widen the value set so `state=FailClosed`/`state=ExitActive` becomes a substring (§4.2) |
| `status_gossip_transport_error_is_sanitised_and_capped` | emit the raw `io::Error` — whitespace/`=` forges tokens |
| `status_gossip_suffix_is_290_bytes_when_unconfigured` | let the Windows-reachable suffix grow past its fixed budget (§4.3) |
| `status_appends_gossip_fields_without_reordering_existing_ones` | insert mid-line — breaks the §4.1 parsers |
| *(in `gossip_runtime.rs`)* `every_reject_kind_is_reachable_and_renders` | add a kind at a call site with no test reaching it |

### 5.1 What actually shipped, and where it diverges

**18 tests** (15 in `daemon.rs`, 3 in `gossip_runtime.rs`), not the 15+1 planned. Divergences, stated rather than smoothed over:

- Plan listed one `status_counts_push_failures_from_both_mint_and_repush`. Shipped
  as **two** tests in `gossip_runtime.rs`, where the loops live:
  `push_failures_are_counted_on_the_mint_path` and
  `..._on_the_repush_path`. Strictly stronger — dropping either counter now fails
  a distinct test (mutation-verified both ways).
- Plan listed `every_reject_kind_is_reachable_and_renders`. Shipped as
  `every_error_kind_is_listed_in_the_published_vocabulary`, which is **a weaker
  property than the name it replaced**: it proves the published vocabulary cannot
  drift from `GossipError`, not that every kind is reachable at runtime. The first
  version of it was the tautology §5 said it had removed — a hand-maintained
  variant array that a new enum variant would not have broken. `ab8e47e4` added a
  compile-time exhaustiveness guard beside the array so a new variant now fails the
  build there (verified: dropping one arm yields `error[E0004]`). The four ad-hoc
  literals still have no such guard; a brand-new literal at a new call site would
  escape. That residual gap is stated in the code, not just here.
- Added `status_counts_every_malformed_datagram_not_just_one_per_drain` (pins the
  `continue`, §3) and the totals test now also samples `gossip_peers_registered`
  and `gossip_local_epoch`.

**Three shipped tests did not deliver their stated guarantee and were fixed in
`ab8e47e4`.** Worth recording because each *read* as coverage:

1. The totals test set `gossip_rejected_total` and `gossip_recv_errors_total` both
   to `6`, so transposing those two interpolations passed every assertion — in the
   one test standing between a transposition and a silently wrong line, guarding
   the exact hazard §2.2's design exists to prevent. Values are now pairwise
   distinct, and the test asserts its own distinctness so the guard cannot rot.
2. `assert_eq!(seen.len(), 3)` was vacuous — `seen` is pushed to unconditionally,
   so a run where the bind failed would report `attached_pending_transport` twice
   and still pass with `active` unexercised. Now asserts the exact sequence.
3. The privacy pin never populated `gossip_transport_error` — the only free-form
   value in the block, hence the only one that could carry an address. It exercised
   everything except the thing at risk. It now forces a real bind failure and
   asserts the local bind address does not appear.

### 5.2 Mutation verification — the record, not the claim

Every behaviour above was verified by breaking it and confirming the **specific**
test failed, then restoring. Recorded in full because a bare count is exactly the
kind of unauditable assertion this plan spent a commit removing from its own
citations.

| # | Mutation applied | Caught by |
| --- | --- | --- |
| M1 | `gossip_identity_mismatch_state` returns `false` instead of `unknown` on the no-node early return | `status_reports_identity_mismatch_as_unknown_when_uncheckable` |
| M2 | read the sticky `gossip_identity_mismatch_warned` latch instead of computing fresh | `status_reports_identity_mismatch_true_and_false_from_live_inputs` |
| M3 | drop `gossip_transport_error = None` on successful bind | `status_reports_transport_error_and_clears_it_on_successful_bind` |
| M4 | emit the raw `io::Error` unsanitised | `status_gossip_transport_error_is_sanitised_and_capped` |
| M5 | drop `sort_unstable_by_key` on the reject-reason list | `status_reject_reasons_are_deterministically_ordered` |
| M6 | drop the epidemic re-push counter, keep the mint one | `push_failures_are_counted_on_the_repush_path` |
| M7 | collapse `attached_pending_transport` into `active` | `status_reports_attached_pending_transport_when_bind_failed` |
| M8 | drop the inbound decode-error counter | `status_counts_inbound_decode_errors` |
| M9 | render a peer's port in place of `peers.len()` | `status_gossip_tokens_contain_no_addresses_or_node_ids` |
| M10 | interpolate the gossip block mid-line instead of appending | `status_appends_gossip_fields_without_reordering_existing_ones` |
| M11 | hardcode accepted/minted/push counters to zero | `status_reports_gossip_accept_mint_and_reject_totals` |
| M12 | remove `origin_rate_limited` from `ALL_GOSSIP_REJECT_KINDS` | `every_error_kind_is_listed_in_the_published_vocabulary` |
| M13 | drop the mint-path push counter | `push_failures_are_counted_on_the_mint_path` |
| M14 | revert `continue` to `break` in the drain error arm | `status_counts_every_malformed_datagram_not_just_one_per_drain` |
| M16 | transpose `{recv_errors}` and `{rejected}` in the format string | `status_reports_gossip_accept_mint_and_reject_totals` |
| M18 | interpolate the bind address into `gossip_transport_error` | `status_gossip_tokens_contain_no_addresses_or_node_ids` |
| M19 | make two sampled values equal | same test's pairwise-distinctness guard |
| M20 | drop one arm from the exhaustive mirror | **build failure**, `error[E0004]` |
| M21 | drop the clear in `attach_gossip_runtime` | `attach_gossip_runtime_clears_a_stale_transport_error` |
| M22 | mirror returns a kind string that disagrees with `error_kind` | `every_error_kind_is_listed_in_the_published_vocabulary` |

Two guards are structural rather than assertion-based: M19 trips the distinctness
check with its own message, and M20 is a compile error. M15 and M17 were planned
and superseded (folded into M19 and M16); the numbering is the order applied and is
left as-is so the record matches what happened rather than being tidied afterwards.

**M16 and M18 are why this table exists.** Both were first run with the fixes
*uncommitted*, so the `git checkout -- <file>` that restored each mutation also
reverted the fixes, and both mutations then "passed" against the previous
revision's weaker tests. The false green was caught only because two passes were
implausible. This is CLAUDE.md §5.1 rule 3 exactly — commit before you experiment —
and it is recorded here because the failure mode is a green result that means
nothing.

**Two revisions' test defects, fixed.** Revision 2's
`status_gossip_fields_contain_no_addresses_or_node_ids` was unpassable as worded —
it asserted over the whole line, which legitimately contains `node_id=`, endpoints
and candidate addresses; it must extract only the `gossip_*` tokens. Revision 4's
`status_reject_reasons_cover_all_sixteen_kinds` could not catch its own stated
mutation: `gossip_reject_reasons` renders `rejected_counts` generically, so a new
kind is surfaced automatically the first time it is bumped and no code path omits
one. Comparing two hardcoded lists is a tautology. The property genuinely worth
testing — that each of the 16 is *reachable* — belongs in `gossip_runtime.rs`, and
is listed there.

## 6. Acceptance

`rustynet status` on a lab guest reports `gossip_state`, and on a node with gossip
configured the accept/mint/reject totals move under real traffic. A rate-limited
origin is visible as a non-zero `origin_rate_limited` in `gossip_reject_reasons` —
the specific thing that is invisible today.

**No `--json` acceptance criterion**, because `status --json` does not render at all
(§6.1) — revision 3's criterion asserting it would have been unpassable.

**Defects found while writing this plan, logged not fixed here:**

1. **`rustynet status --json` never renders.** `command_supports_json_render`
   (`main.rs:1875`) admits `Status`, but `render_key_value_line_as_json` (`:1890`)
   requires a `prefix:` and the status line has none, so `split_once(':')` lands
   inside the first colon-bearing value. Every invocation falls back to raw text with
   a shape-drift preamble (`main.rs:1779`). Downstream,
   `scripts/e2e/live_linux_path_handoff_under_load_test.sh:175` pipes it into
   `json.load()` and silently yields `unknown` via `|| echo unknown`; that script also
   reads `local_rustynet_ip` (`:186`), and
   `vm_lab/orchestrator/adapter/linux_traffic.rs:749` / `macos_traffic.rs:513` read
   `mesh_ip`/`wg_ip` — none of which exist on the line. Dead lookups returning a
   default that reads as success.
2. **Five status values bypass `sanitize_netcheck_value`** and can carry whitespace,
   inflating the line and injecting fake tokens: `bootstrap_error` (`daemon.rs:8058`),
   `last_reconcile_error` (`:8063`), `port_forward_error` (`:8161`), `node_id`
   (`:8041`), `exit_node` (`:8045`). A real capture shows `bootstrap_error` at 304 B
   carrying 36 extra whitespace tokens, taking that line from 86 to 158 tokens.

   **This change gave that gap a new consequence, stated here rather than left
   implied.** Those five values are emitted *before* the gossip block, and every
   consumer takes the FIRST matching token — `extract_inline_field`
   (`ops_cross_network_reports.rs:370-376`) uses `find_map`, the test helper uses
   `.find`. Before this change a forged `gossip_*` token meant nothing; now it is
   a health verdict live-lab validators read, and the forgery would win.
   `status_appends_gossip_fields_without_reordering_existing_ones` proves
   suffix-ness only for a clean line. Sanitising those five values is the fix. It
   is a pre-existing whole-line defect and is deliberately not bundled into a
   read-only observability change — but it is more urgent now than when it was
   merely cosmetic.
3. **The status line has no provable size bound** and reaches the 4092 B Windows cliff
   at ~40 peers (§4.3) — a hard failure surfacing as an opaque timeout.
4. **`daemon.rs:28536`'s `contains("state=")` assertion is vacuous** (§4.2).
5. **`vm_lab/mod.rs:15550`** greps `generation=[0-9]+` unanchored; any future
   `*_generation=` field breaks the macOS killswitch-anchor lookup.
6. **Both `Status` and `Netcheck` mutate state on a read** (§2.1): disk read, a
   **watermark write**, and a reachable `force_fail_closed_or_restrict`. Observation
   changes state, and during an incident a diagnostic poll nudges the node toward
   fail-closed. The remedy is a genuinely side-effect-free read path — also the right
   home for a future high-frequency gossip poll.
7. **`IpcCommand::is_mutating()` (`ipc.rs:99-114`) omits both `Status` and
   `Netcheck`**, despite §6.6. `is_mutating()` gates the restricted-safe-mode refusal
   at `daemon.rs:7717`, so these commands run — writing the anti-replay watermark and
   able to escalate restriction — **while the daemon is already in restricted-safe
   mode**.
8. **`drain_gossip_inbound` `break`s the drain pass on a decode error**
   (`daemon.rs:5644`), so one malformed datagram stalls the remaining bundles until
   the next loop iteration. Bounded by `MAX_DRAIN_PER_ITERATION = 16`, so a stall
   rather than a DoS — but `continue` is almost certainly the correct handling.
9. **Nothing re-binds or health-checks an attached gossip transport** (§2.3). A
   socket that dies after a successful bind reads `active` forever.
10. **`gossip_identity_mismatch_warned` is a sticky latch that is never cleared and
    whose check short-circuits on itself** (`daemon.rs:5568`, `:5534`), so a repaired
    mismatch is never re-detected and never re-warned. Correct for warn-once logging,
    wrong as state — which is why §2.3 computes the field fresh instead.
11. **`local_host_candidates` shadows `host_candidates` on the netcheck line** — the
    same collision class as §4.2.
12. **The gossip socket binds every interface, and the module doc says it does
    not.** `gossip_transport.rs:3-12` states each peer "binds a dedicated UDP socket
    **on the rustynet0 mesh interface**", and builds a security argument on it:
    because that interface "only carries traffic that has already traversed the WG
    tunnel, the bundle datagrams ride inside an encrypted-and-authenticated channel
    for free". The daemon binds
    `SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), RUSTYNET_GOSSIP_PORT)`
    (`daemon.rs:4315-4318`) — **`0.0.0.0:51821`, every interface** — and no nft/pf
    rule scopes that port anywhere in the repo. The Ed25519 signature still gates
    *acceptance*, so this is **not a trust bypass**; but the decode path, the
    per-origin rate limiter and `gossip_recv_errors_total` are reachable
    **off-tunnel** by any host that can reach UDP/51821. This is the same failure
    this thread keeps producing: a document asserting a property the code that
    writes it contradicts. It is also exactly the condition under which the
    `break`-vs-`continue` saturation (§3) mattered.
13. **`gossip_push_failures_total` cannot see a peer that is simply down.**
    `push_bundle` wraps `UdpSocket::send_to`, where `Ok` means handed to the kernel,
    not delivered. §1's fourth failure is therefore **partially** closed: locally
    detectable failures (address-family mismatch, killswitch `EPERM`, no route) are
    counted; loss in flight is not, and `0` is not separable from "nothing was
    pushed". Closing it properly needs an acknowledged-delivery or
    attempted/succeeded pair, which is a protocol change, not an observability one.
14. **`ALL_GOSSIP_REJECT_KINDS` has no production reader.** `gossip_reject_reasons`
    renders only kinds that have fired, so an operator still cannot distinguish
    "this kind has never happened" from "this kind does not exist" without reading
    the source.

15. **A truncated netcheck line records a cross-network run as a PASS.** Found while
    auditing the status line's consumers; not a gossip defect, recorded here because
    this is the active defect ledger and it is the same false-green class CLAUDE.md
    §12.3 warns about. `ops_cross_network_reports.rs:1873-1913` gates a pass verdict
    on five fields — `traversal_alarm_state`, `traversal_alarm_reason`,
    `dns_alarm_state`, `dns_alarm_reason`, `traversal_error` — each with
    `.as_deref().is_some_and(...)`, so an **absent** field satisfies the gate. The
    verdict is `problems.is_empty()`.

    Why that is reachable: `path_mode` is netcheck field **1** and is mandatory
    (`ok_or_else` at `:391`), but those five are fields **59, 60, 61, 62 and 68**. A
    line truncated anywhere after the mandatory prefix clears it and then passes
    every alarm gate by absence, recording a pass on evidence carrying no alarm
    state at all. The file's own convention two blocks up is the correct shape —
    `transport_socket_identity_local_addr` uses `is_none_or`, treating absence as a
    problem.

    Note when fixing: `traversal_error` is on **netcheck only**, not `status`, while
    the CLI flag is named `--path-status-line`. Requiring its presence correctly
    rejects a status line, so the message must say so or the next person meets a
    confusing failure instead of a confusing pass. The three shipped callers pass
    `"$client_netcheck"`, so requiring presence breaks none of them.

These are pre-existing (except 13 and 14, which are stated limits of what shipped),
out of scope for a read-only observability change, and must not be silently bundled
into it.
