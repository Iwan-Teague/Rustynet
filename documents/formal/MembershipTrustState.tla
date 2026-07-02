------------------------- MODULE MembershipTrustState -------------------------
(***************************************************************************)
(* Formal model of the Rustynet membership trust-state apply pipeline:    *)
(*                                                                         *)
(*   crates/rustynet-control/src/membership.rs                             *)
(*     apply_signed_update            (:693-737)                           *)
(*     reduce_membership_state        (:1141-1253, node-roster arms)       *)
(*     MembershipReplayCache::observe (:552-562)                           *)
(*                                                                         *)
(* Scope (FIS-0019, 2026-07-02): the core reducer + epoch chain +          *)
(* prev/new state-root checks + anti-replay watermark — the slice where    *)
(* the historical RSA-0009 bug lived. Signature verification is an         *)
(* abstract boolean oracle (record field `verified`); the approver-quorum  *)
(* arithmetic, RotateApprover/SetQuorum operations, the key-rotation /     *)
(* epoch-tagged-bundle subsystem (verify_epoch_tagged_bundle — currently   *)
(* unwired in production), gossip transport, and enrollment are OUT of     *)
(* scope, per the findings doc.                                            *)
(*                                                                         *)
(* Faithfulness notes (real -> model):                                     *)
(*  - state_root_hex = SHA-256(canonical_payload(state)) where the         *)
(*    payload covers the FULL state content (epoch, every node's status/   *)
(*    caps/key/joined_at/updated_at, approvers, quorum). Model: the root   *)
(*    IS the state tuple itself (hashing is injective modulo collisions,   *)
(*    which we abstract away). RemoveNode's model arm normalizes the       *)
(*    removed slot to canonical "absent" values — the analog of the node's *)
(*    fields vanishing from the real canonical payload.                    *)
(*  - The RSA-0009 bug: the reducer stamped unix_now() into the affected   *)
(*    node's updated_at instead of the signed record.created_at_unix, so   *)
(*    the producer's new_state_root (computed at mint time T1) never       *)
(*    matched the applier's re-derivation (at T2 /= T1). Only the FOUR     *)
(*    stamping arms were affected (SetNodeCapabilities / RevokeNode /      *)
(*    RestoreNode / RotateNodeKey); AddNode carries its fields inside the  *)
(*    signed record and RemoveNode stamps nothing. CONSTANT BuggyReducer   *)
(*    = TRUE reintroduces exactly that bug in the applier's re-derivation. *)
(*  - Guard order is the real one: validate / payload-shape / network(*) / *)
(*    expiry / clock-skew / prev-root / epoch-chain / signature-oracle /   *)
(*    reduce+validate / new-root equality / replay-observe LAST.           *)
(*    (*) network_id: the model has a single network; the mismatch guard   *)
(*    is therefore vacuous and omitted (disclosed in the findings doc).    *)
(*  - MembershipReplayCache = seen update-id set + max-epoch watermark;    *)
(*    observe() checks BOTH before mutating EITHER, and runs only after    *)
(*    every other guard passed (membership.rs:734) — so any rejection      *)
(*    leaves the cache untouched (property CacheIntactOnReject).           *)
(*  - validate() richness in scope: "active node must have >= 1            *)
(*    capability" (validate_membership_node_capabilities, :1699-1704) —    *)
(*    included because it can reject a reduced state (e.g. RestoreNode on  *)
(*    a node whose caps were emptied while revoked). The capability-       *)
(*    pairing rules (blind_exit etc.) are excluded from this slice.        *)
(*                                                                         *)
(* Companion files: MembershipTrustState.cfg (TLC config, correct          *)
(* reducer), and membership_trust_state_explorer.py (an exhaustive BFS     *)
(* surrogate used where TLC itself is unavailable; mirrors this module     *)
(* transition-for-transition).                                             *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
  NodeIds,      \* abstract node identities, e.g. {"a", "b"}
  Keys,         \* abstract node pubkeys, e.g. {"k1", "k2"}
  Caps,         \* abstract capability atoms, e.g. {"c1"}
  UpdateIds,    \* abstract update_id space, e.g. {"u1", "u2"}
  MaxTime,      \* wall-clock horizon (abstract seconds), e.g. 3
  MaxEpoch,     \* epoch horizon, e.g. 2
  ClockSkew,    \* MEMBERSHIP_CLOCK_SKEW_SECS analog (real: 90), e.g. 1
  UpdateTtl,    \* expires_at - created_at for honest mints, e.g. 2
  BuggyReducer  \* TRUE = reintroduce the RSA-0009 wall-clock stamping bug

ASSUME BuggyReducer \in BOOLEAN
ASSUME ClockSkew \in Nat /\ UpdateTtl \in Nat \ {0}

Timestamps == 1..MaxTime
OpNames == {"add", "setcaps", "remove", "revoke", "restore", "rotatekey"}
NoKey == CHOOSE k \in Keys : TRUE   \* canonical key value for absent slots

VARIABLES
  epoch,          \* MembershipState.epoch
  status,         \* [NodeIds -> {"absent","active","revoked"}]
  caps,           \* [NodeIds -> SUBSET Caps]
  key,            \* [NodeIds -> Keys]
  updated,        \* [NodeIds -> 0..MaxTime]  (updated_at_unix; 0 = never)
  seenIds,        \* MembershipReplayCache.seen_update_ids
  maxEpochSeen,   \* MembershipReplayCache.max_epoch
  now,            \* applier wall clock (now_unix)
  pending,        \* the update presented for application, or NoPending
  log,            \* Seq of accepted-update summaries (history, for invariants)
  acceptedRecs,   \* full accepted records (adversary replay source)
  honestRootMismatch \* count of HONEST records rejected NewStateRootMismatch

vars == <<epoch, status, caps, key, updated, seenIds, maxEpochSeen, now,
          pending, log, acceptedRecs, honestRootMismatch>>

NoPending == [kind |-> "none"]

(***************************************************************************)
(* State root abstraction.  Root of a state = the state content itself.   *)
(***************************************************************************)
RootOf(e, st, cp, ky, up) == <<e, st, cp, ky, up>>
CurrentRoot == RootOf(epoch, status, caps, key, updated)

(***************************************************************************)
(* reduce_membership_state — preconditions (incl. the in-scope validate() *)
(* rule "active => caps nonempty") and the reduced roster, stamped at t.  *)
(***************************************************************************)
ReduceOk(op, tgt, argCaps) ==
  CASE op = "add"       -> status[tgt] = "absent" /\ argCaps # {}
    [] op = "setcaps"   -> status[tgt] # "absent"
                           /\ (status[tgt] = "active" => argCaps # {})
    [] op = "remove"    -> status[tgt] # "absent"
    [] op = "revoke"    -> status[tgt] = "active"
    [] op = "restore"   -> status[tgt] = "revoked" /\ caps[tgt] # {}
    [] op = "rotatekey" -> status[tgt] # "absent"

RStatus(op, tgt) ==
  CASE op = "add"       -> [status EXCEPT ![tgt] = "active"]
    [] op = "setcaps"   -> status
    [] op = "remove"    -> [status EXCEPT ![tgt] = "absent"]
    [] op = "revoke"    -> [status EXCEPT ![tgt] = "revoked"]
    [] op = "restore"   -> [status EXCEPT ![tgt] = "active"]
    [] op = "rotatekey" -> status

RCaps(op, tgt, argCaps) ==
  CASE op = "add"       -> [caps EXCEPT ![tgt] = argCaps]
    [] op = "setcaps"   -> [caps EXCEPT ![tgt] = argCaps]
    [] op = "remove"    -> [caps EXCEPT ![tgt] = {}]
    [] op \in {"revoke", "restore", "rotatekey"} -> caps

RKey(op, tgt, argKey) ==
  CASE op = "add"       -> [key EXCEPT ![tgt] = argKey]
    [] op = "rotatekey" -> [key EXCEPT ![tgt] = argKey]
    [] op = "remove"    -> [key EXCEPT ![tgt] = NoKey]
    [] op \in {"setcaps", "revoke", "restore"} -> key

\* Which arms stamp updated_at with the reducer's timestamp argument.
\* AddNode carries its fields inside the signed record (modeled as stamping
\* with the record's own createdAt on BOTH sides — hence never divergent);
\* RemoveNode normalizes the slot. The four stamping arms are the RSA-0009
\* blast radius.
RUpdated(op, tgt, recCreatedAt, stampT) ==
  CASE op = "add"       -> [updated EXCEPT ![tgt] = recCreatedAt]
    [] op = "remove"    -> [updated EXCEPT ![tgt] = 0]
    [] op \in {"setcaps", "revoke", "restore", "rotatekey"}
                        -> [updated EXCEPT ![tgt] = stampT]

(***************************************************************************)
(* Producer side (preview_next_state): always stamps with the record's    *)
(* own created_at (the fixed, post-RSA-0009 behavior — the producer        *)
(* computes new_state_root from its own reduce at mint time).              *)
(***************************************************************************)
ProducerRoot(op, tgt, argCaps, argKey, createdAt, epochNew) ==
  RootOf(epochNew,
         RStatus(op, tgt),
         RCaps(op, tgt, argCaps),
         RKey(op, tgt, argKey),
         RUpdated(op, tgt, createdAt, createdAt))

(***************************************************************************)
(* Applier side re-derivation (apply_signed_update step 9): the FIXED     *)
(* reducer stamps record.created_at_unix; the BUGGY (RSA-0009) reducer     *)
(* stamps the applier's wall clock `now`.                                  *)
(***************************************************************************)
ApplierStamp(createdAt) == IF BuggyReducer THEN now ELSE createdAt
ApplierRoot(op, tgt, argCaps, argKey, createdAt, epochNew) ==
  RootOf(epochNew,
         RStatus(op, tgt),
         RCaps(op, tgt, argCaps),
         RKey(op, tgt, argKey),
         RUpdated(op, tgt, createdAt, ApplierStamp(createdAt)))

(***************************************************************************)
(* Record constructor for honest mints.                                    *)
(***************************************************************************)
HonestRecord(id, op, tgt, argCaps, argKey) ==
  [kind      |-> "rec",
   id        |-> id,
   op        |-> op,
   tgt       |-> tgt,
   argCaps   |-> argCaps,
   argKey    |-> argKey,
   createdAt |-> now,
   expiresAt |-> now + UpdateTtl,
   prevRoot  |-> CurrentRoot,
   newRoot   |-> ProducerRoot(op, tgt, argCaps, argKey, now, epoch + 1),
   epochPrev |-> epoch,
   epochNew  |-> epoch + 1,
   verified  |-> TRUE,
   honest    |-> TRUE]

(***************************************************************************)
(* Actions                                                                 *)
(***************************************************************************)
Init ==
  /\ \E seed \in NodeIds :
       /\ status  = [n \in NodeIds |-> IF n = seed THEN "active" ELSE "absent"]
       /\ caps    = [n \in NodeIds |-> IF n = seed THEN {CHOOSE c \in Caps : TRUE} ELSE {}]
       /\ key     = [n \in NodeIds |-> NoKey]
       /\ updated = [n \in NodeIds |-> 0]
  /\ epoch = 0
  /\ seenIds = {}
  /\ maxEpochSeen = 0
  /\ now = 1
  /\ pending = NoPending
  /\ log = <<>>
  /\ acceptedRecs = {}
  /\ honestRootMismatch = 0

Tick ==
  /\ now < MaxTime
  /\ now' = now + 1
  /\ UNCHANGED <<epoch, status, caps, key, updated, seenIds, maxEpochSeen,
                 pending, log, acceptedRecs, honestRootMismatch>>

MintHonest ==
  /\ pending = NoPending
  /\ epoch < MaxEpoch
  /\ \E id \in UpdateIds \ seenIds :
     \E op \in OpNames :
     \E tgt \in NodeIds :
     \E argCaps \in SUBSET Caps :
     \E argKey \in Keys :
       /\ ReduceOk(op, tgt, argCaps)
       /\ pending' = HonestRecord(id, op, tgt, argCaps, argKey)
  /\ UNCHANGED <<epoch, status, caps, key, updated, seenIds, maxEpochSeen,
                 now, log, acceptedRecs, honestRootMismatch>>

\* Adversary shape 1: an honest-shaped record whose signature does not verify.
MintUnsigned ==
  /\ pending = NoPending
  /\ epoch < MaxEpoch
  /\ \E id \in UpdateIds \ seenIds :
     \E op \in OpNames :
     \E tgt \in NodeIds :
     \E argCaps \in SUBSET Caps :
     \E argKey \in Keys :
       /\ ReduceOk(op, tgt, argCaps)
       /\ pending' = [HonestRecord(id, op, tgt, argCaps, argKey)
                        EXCEPT !.verified = FALSE, !.honest = FALSE]
  /\ UNCHANGED <<epoch, status, caps, key, updated, seenIds, maxEpochSeen,
                 now, log, acceptedRecs, honestRootMismatch>>

\* Adversary shape 2: replay of a genuinely accepted (validly signed) record.
MintReplay ==
  /\ pending = NoPending
  /\ \E rec \in acceptedRecs :
       pending' = [rec EXCEPT !.honest = FALSE]
  /\ UNCHANGED <<epoch, status, caps, key, updated, seenIds, maxEpochSeen,
                 now, log, acceptedRecs, honestRootMismatch>>

\* Adversary shape 3: payload-consistent epoch skip (epoch_prev = epoch+1,
\* epoch_new = epoch+2) — passes canonical_payload's "+1" self-check but must
\* fail the state-level epoch-chain guard (and the prev-root guard).
MintEpochSkip ==
  /\ pending = NoPending
  /\ epoch + 2 <= MaxEpoch
  /\ \E id \in UpdateIds \ seenIds :
     \E op \in OpNames :
     \E tgt \in NodeIds :
     \E argCaps \in SUBSET Caps :
     \E argKey \in Keys :
       /\ ReduceOk(op, tgt, argCaps)
       /\ pending' = [HonestRecord(id, op, tgt, argCaps, argKey)
                        EXCEPT !.epochPrev = epoch + 1,
                               !.epochNew  = epoch + 2,
                               !.newRoot   = ProducerRoot(op, tgt, argCaps,
                                                          argKey, now, epoch + 2),
                               !.honest    = FALSE]
  /\ UNCHANGED <<epoch, status, caps, key, updated, seenIds, maxEpochSeen,
                 now, log, acceptedRecs, honestRootMismatch>>

(***************************************************************************)
(* apply_signed_update — the guard chain, in the real order.               *)
(* Any rejection: pending is dropped, EVERYTHING else unchanged            *)
(* (in particular the replay cache — observe() runs last, :734).           *)
(***************************************************************************)
RejectableReasonExists(r) ==
  \/ ~(r.epochNew = r.epochPrev + 1 /\ r.createdAt < r.expiresAt)   \* payload self-check (:421-430)
  \/ now > r.expiresAt                                              \* Expired (:707)
  \/ r.createdAt > now + ClockSkew                                  \* FutureDated (:710)
  \/ r.prevRoot # CurrentRoot                                       \* PrevStateRootMismatch (:713)
  \/ r.epochPrev # epoch \/ r.epochNew # epoch + 1                  \* epoch chain (:716)
  \/ ~r.verified                                                    \* signature oracle (:722)
  \/ ~ReduceOk(r.op, r.tgt, r.argCaps)                              \* reduce/validate (:727-729)
  \/ ApplierRoot(r.op, r.tgt, r.argCaps, r.argKey,
                 r.createdAt, r.epochNew) # r.newRoot               \* NewStateRootMismatch (:730-733)
  \/ r.id \in seenIds \/ r.epochNew <= maxEpochSeen                 \* observe() (:552-562, :734)

\* The specific reason "the recomputed root differed" fired FIRST among the
\* guards (i.e. every earlier guard passed) — needed to attribute honest
\* rejections to the RSA-0009 mechanism and nothing else.
RootMismatchFiredFirst(r) ==
  /\ r.epochNew = r.epochPrev + 1 /\ r.createdAt < r.expiresAt
  /\ now <= r.expiresAt
  /\ r.createdAt <= now + ClockSkew
  /\ r.prevRoot = CurrentRoot
  /\ r.epochPrev = epoch /\ r.epochNew = epoch + 1
  /\ r.verified
  /\ ReduceOk(r.op, r.tgt, r.argCaps)
  /\ ApplierRoot(r.op, r.tgt, r.argCaps, r.argKey,
                 r.createdAt, r.epochNew) # r.newRoot

ApplyReject ==
  /\ pending.kind = "rec"
  /\ RejectableReasonExists(pending)
  /\ pending' = NoPending
  /\ honestRootMismatch' =
       IF pending.honest /\ RootMismatchFiredFirst(pending)
       THEN honestRootMismatch + 1
       ELSE honestRootMismatch
  /\ UNCHANGED <<epoch, status, caps, key, updated, seenIds, maxEpochSeen,
                 now, log, acceptedRecs>>

ApplyAccept ==
  /\ pending.kind = "rec"
  /\ ~RejectableReasonExists(pending)
  /\ LET r == pending IN
       /\ epoch'   = r.epochNew
       /\ status'  = RStatus(r.op, r.tgt)
       /\ caps'    = RCaps(r.op, r.tgt, r.argCaps)
       /\ key'     = RKey(r.op, r.tgt, r.argKey)
       /\ updated' = RUpdated(r.op, r.tgt, r.createdAt, ApplierStamp(r.createdAt))
       /\ seenIds' = seenIds \union {r.id}
       /\ maxEpochSeen' = r.epochNew
       /\ log'     = Append(log, [id |-> r.id, prevRoot |-> r.prevRoot,
                                  epochPrev |-> r.epochPrev,
                                  epochNew |-> r.epochNew])
       /\ acceptedRecs' = acceptedRecs \union {r}
       /\ pending' = NoPending
  /\ UNCHANGED <<now, honestRootMismatch>>

Next == Tick \/ MintHonest \/ MintUnsigned \/ MintReplay \/ MintEpochSkip
        \/ ApplyReject \/ ApplyAccept

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety properties                                                       *)
(***************************************************************************)

\* P1 — epoch chain linearity: every accepted update advanced the epoch by
\* exactly 1, and consecutive acceptances chain (no skip, no rollback).
\* Corresponds to apply_signed_update_rejects_epoch_chain_break +
\* replay_and_rollback_are_rejected.
InvLogEpochsChain ==
  \A i \in 1..Len(log) :
    /\ log[i].epochNew = log[i].epochPrev + 1
    /\ (i > 1 => log[i].epochPrev = log[i-1].epochNew)

\* P2 — no update_id is ever accepted twice. Corresponds to
\* replay_and_rollback_are_rejected.
InvNoDoubleAccept ==
  \A i, j \in 1..Len(log) : i # j => log[i].id # log[j].id

\* P3 — RSA-0009: an honest, fresh, correctly-chained, validly-signed record
\* is NEVER rejected because the applier's re-derived root diverged from the
\* producer's. Under BuggyReducer = TRUE this invariant is violated on any
\* Tick-then-Apply interleaving that touches a stamping arm. New — not
\* directly encoded by any existing Rust test (the closest are the four
\* op-application success tests, which pass trivially because producer and
\* applier share one process AND one wall-clock second in-test).
InvHonestNeverRootMismatch == honestRootMismatch = 0

\* P4 — chain/fork integrity: each base state (identified by its root) is
\* extended by at most one accepted update — no divergent fork from a shared
\* parent. Corresponds to the prev_state_root guard and
\* replay_and_rollback_are_rejected's second half.
InvNoForkPerRoot ==
  \A i, j \in 1..Len(log) : i # j => log[i].prevRoot # log[j].prevRoot

\* P5 — cache/state coupling: the replay watermark tracks exactly the
\* accepted-epoch frontier (observe() is called only on success, last).
\* Corresponds to replay_cache_not_updated_on_failed_update.
InvCacheCoupling ==
  IF log = <<>>
  THEN maxEpochSeen = 0 /\ epoch = 0
  ELSE maxEpochSeen = epoch /\ epoch = log[Len(log)].epochNew

\* P2b/P5b as an action property: any rejection leaves the replay cache
\* byte-identical (checked as a temporal property).
RejectLeavesCacheIntact ==
  [][ (pending # NoPending /\ pending' = NoPending /\ log' = log)
        => (seenIds' = seenIds /\ maxEpochSeen' = maxEpochSeen) ]_vars

\* Epoch never decreases across ANY step.
EpochNeverDecreases == [][ epoch' >= epoch ]_vars

================================================================================
