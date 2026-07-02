#!/usr/bin/env python3
"""Exhaustive BFS surrogate for MembershipTrustState.tla (FIS-0019).

TLC (tla2tools.jar) was unreachable from the authoring sandbox (network
allowlist blocked github releases / Maven Central / nightly.tlapl.us), so
this script mirrors the TLA+ module's transition system EXACTLY — same
constants as MembershipTrustState.cfg, same guard order, same invariants —
and exhaustively enumerates the reachable bounded state space.

Usage:
    python3 membership_trust_state_explorer.py correct   # BuggyReducer=FALSE
    python3 membership_trust_state_explorer.py buggy     # BuggyReducer=TRUE

Expected: `correct` reports all invariants hold over the full reachable
space; `buggy` reports an InvHonestNeverRootMismatch violation with a
minimal Mint -> Tick -> Apply counterexample trace (the RSA-0009 bug).

This is a verification AID pending a real TLC run — the .tla module is the
canonical spec. Keep the two in lockstep if either changes.
"""
import sys
from collections import deque

# Constants — mirror MembershipTrustState.cfg
NODES = ("a", "b")
KEYS = ("k1", "k2")
CAP_SUBSETS = (frozenset(), frozenset({"c1"}))  # SUBSET Caps for Caps={"c1"}
NONEMPTY_CAPS = tuple(c for c in CAP_SUBSETS if c)
UPDATE_IDS = ("u1", "u2")
MAX_TIME = 3
MAX_EPOCH = 2
CLOCK_SKEW = 1
UPDATE_TTL = 2
NO_KEY = KEYS[0]
OPS = ("add", "setcaps", "remove", "revoke", "restore", "rotatekey")
STAMPING_OPS = {"setcaps", "revoke", "restore", "rotatekey"}

# State tuple layout:
# (epoch, status, caps, key, updated, seenIds, maxEpochSeen, now, pending,
#  log, acceptedRecs, honestRootMismatch)
# roster components are tuples indexed by NODES order; pending/None or record
# tuple; log tuple of (id, prevRoot, epochPrev, epochNew); acceptedRecs
# frozenset of records.
# Record tuple: (id, op, tgt, argCaps, argKey, createdAt, expiresAt,
#                prevRoot, newRoot, epochPrev, epochNew, verified, honest)

def idx(n):
    return NODES.index(n)

def root_of(epoch, status, caps, key, updated):
    return (epoch, status, caps, key, updated)

def reduce_ok(status, caps, op, tgt, arg_caps):
    s = status[idx(tgt)]
    if op == "add":
        return s == "absent" and len(arg_caps) > 0
    if op == "setcaps":
        return s != "absent" and (s != "active" or len(arg_caps) > 0)
    if op == "remove":
        return s != "absent"
    if op == "revoke":
        return s == "active"
    if op == "restore":
        return s == "revoked" and len(caps[idx(tgt)]) > 0
    if op == "rotatekey":
        return s != "absent"
    raise AssertionError(op)

def reduced(status, caps, key, updated, op, tgt, arg_caps, arg_key,
            created_at, stamp_t):
    i = idx(tgt)
    st, cp, ky, up = list(status), list(caps), list(key), list(updated)
    if op == "add":
        st[i], cp[i], ky[i], up[i] = "active", arg_caps, arg_key, created_at
    elif op == "setcaps":
        cp[i], up[i] = arg_caps, stamp_t
    elif op == "remove":
        st[i], cp[i], ky[i], up[i] = "absent", frozenset(), NO_KEY, 0
    elif op == "revoke":
        st[i], up[i] = "revoked", stamp_t
    elif op == "restore":
        st[i], up[i] = "active", stamp_t
    elif op == "rotatekey":
        ky[i], up[i] = arg_key, stamp_t
    return tuple(st), tuple(cp), tuple(ky), tuple(up)

def initial_states():
    out = []
    for seed in NODES:
        status = tuple("active" if n == seed else "absent" for n in NODES)
        caps = tuple(NONEMPTY_CAPS[0] if n == seed else frozenset()
                     for n in NODES)
        key = tuple(NO_KEY for _ in NODES)
        updated = tuple(0 for _ in NODES)
        out.append((0, status, caps, key, updated, frozenset(), 0, 1, None,
                    (), frozenset(), 0))
    return out

def mint_records(state, honest=True, unsigned=False, epoch_skip=False):
    (epoch, status, caps, key, updated, seen, _me, now, pending,
     _log, _acc, _hrm) = state
    if pending is not None:
        return
    ep_new_off = 2 if epoch_skip else 1
    if epoch + ep_new_off > MAX_EPOCH:
        return
    prev_root = root_of(epoch, status, caps, key, updated)
    for uid in UPDATE_IDS:
        if uid in seen:
            continue
        for op in OPS:
            for tgt in NODES:
                arg_caps_opts = CAP_SUBSETS if op in ("setcaps",) else (
                    NONEMPTY_CAPS if op == "add" else (frozenset(),))
                arg_key_opts = KEYS if op in ("add", "rotatekey") else (NO_KEY,)
                for ac in arg_caps_opts:
                    for ak in arg_key_opts:
                        if not reduce_ok(status, caps, op, tgt, ac):
                            continue
                        ep_prev = epoch + (1 if epoch_skip else 0)
                        ep_new = ep_prev + 1
                        n_st, n_cp, n_ky, n_up = reduced(
                            status, caps, key, updated, op, tgt, ac, ak,
                            now, now)  # producer stamps createdAt (= now)
                        new_root = root_of(ep_new, n_st, n_cp, n_ky, n_up)
                        yield (uid, op, tgt, ac, ak, now, now + UPDATE_TTL,
                               prev_root, new_root, ep_prev, ep_new,
                               not unsigned, honest)

def guards_reject(state, rec, buggy):
    """Returns (rejected: bool, root_mismatch_fired_first: bool)."""
    (epoch, status, caps, key, updated, seen, max_e, now, _p, _log, _acc,
     _hrm) = state
    (uid, op, tgt, ac, ak, created, expires, prev_root, new_root, ep_prev,
     ep_new, verified, _honest) = rec
    if not (ep_new == ep_prev + 1 and created < expires):
        return True, False
    if now > expires:
        return True, False
    if created > now + CLOCK_SKEW:
        return True, False
    if prev_root != root_of(epoch, status, caps, key, updated):
        return True, False
    if ep_prev != epoch or ep_new != epoch + 1:
        return True, False
    if not verified:
        return True, False
    if not reduce_ok(status, caps, op, tgt, ac):
        return True, False
    stamp = now if buggy else created
    n_st, n_cp, n_ky, n_up = reduced(status, caps, key, updated, op, tgt,
                                     ac, ak, created, stamp)
    if root_of(ep_new, n_st, n_cp, n_ky, n_up) != new_root:
        return True, True  # NewStateRootMismatch fired first
    if uid in seen or ep_new <= max_e:
        return True, False
    return False, False

def successors(state, buggy):
    (epoch, status, caps, key, updated, seen, max_e, now, pending, log, acc,
     hrm) = state
    # Tick
    if now < MAX_TIME:
        yield ("Tick", (epoch, status, caps, key, updated, seen, max_e,
                        now + 1, pending, log, acc, hrm))
    # Mints
    if pending is None:
        for rec in mint_records(state, honest=True):
            yield ("MintHonest", state[:8] + (rec,) + state[9:])
        for rec in mint_records(state, honest=False, unsigned=True):
            yield ("MintUnsigned", state[:8] + (rec,) + state[9:])
        for rec in acc:
            replay = rec[:12] + (False,)
            yield ("MintReplay", state[:8] + (replay,) + state[9:])
        for rec in mint_records(state, honest=False, epoch_skip=True):
            yield ("MintEpochSkip", state[:8] + (rec,) + state[9:])
    # Apply
    if pending is not None:
        rec = pending
        rejected, rmff = guards_reject(state, rec, buggy)
        if rejected:
            hrm2 = hrm + 1 if (rec[12] and rmff) else hrm
            yield ("ApplyReject", (epoch, status, caps, key, updated, seen,
                                   max_e, now, None, log, acc, hrm2))
        else:
            (uid, op, tgt, ac, ak, created, _exp, prev_root, _new_root,
             ep_prev, ep_new, _v, _h) = rec
            stamp = now if buggy else created
            n_st, n_cp, n_ky, n_up = reduced(status, caps, key, updated, op,
                                             tgt, ac, ak, created, stamp)
            yield ("ApplyAccept",
                   (ep_new, n_st, n_cp, n_ky, n_up,
                    seen | {uid}, ep_new, now, None,
                    log + ((uid, prev_root, ep_prev, ep_new),),
                    acc | {rec}, hrm))

def check_invariants(state):
    (epoch, _st, _cp, _ky, _up, _seen, max_e, _now, _p, log, _acc,
     hrm) = state
    errs = []
    for i, entry in enumerate(log):
        if entry[3] != entry[2] + 1:
            errs.append("InvLogEpochsChain(+1)")
        if i > 0 and entry[2] != log[i - 1][3]:
            errs.append("InvLogEpochsChain(link)")
    ids = [e[0] for e in log]
    if len(ids) != len(set(ids)):
        errs.append("InvNoDoubleAccept")
    if hrm != 0:
        errs.append("InvHonestNeverRootMismatch")
    roots = [e[1] for e in log]
    if len(roots) != len(set(roots)):
        errs.append("InvNoForkPerRoot")
    if not log and not (max_e == 0 and epoch == 0):
        errs.append("InvCacheCoupling")
    if log and not (max_e == epoch and epoch == log[-1][3]):
        errs.append("InvCacheCoupling")
    return errs

def check_action_props(pre, action, post):
    errs = []
    if post[0] < pre[0]:
        errs.append("EpochNeverDecreases")
    if action == "ApplyReject":
        if post[5] != pre[5] or post[6] != pre[6]:
            errs.append("RejectLeavesCacheIntact")
    return errs

def trace(parents, state):
    steps = []
    while state in parents and parents[state] is not None:
        prev, action = parents[state]
        steps.append((action, state))
        state = prev
    steps.reverse()
    return steps

def main():
    buggy = len(sys.argv) > 1 and sys.argv[1] == "buggy"
    frontier = deque()
    parents = {}
    for s in initial_states():
        frontier.append(s)
        parents[s] = None
    explored = 0
    transitions = 0
    accepted_applies = 0
    violation = None
    while frontier:
        state = frontier.popleft()
        explored += 1
        errs = check_invariants(state)
        if errs:
            violation = (errs, state)
            break
        for action, nxt in successors(state, buggy):
            transitions += 1
            if action == "ApplyAccept":
                accepted_applies += 1
            aerrs = check_action_props(state, action, nxt)
            if aerrs:
                violation = (aerrs, nxt)
                parents.setdefault(nxt, (state, action))
                break
            if nxt not in parents:
                parents[nxt] = (state, action)
                frontier.append(nxt)
        if violation:
            break
    mode = "BUGGY (RSA-0009 reintroduced)" if buggy else "CORRECT"
    print(f"mode={mode}")
    print(f"states_explored={explored} transitions={transitions} "
          f"apply_accept_transitions={accepted_applies}")
    if violation:
        errs, vstate = violation
        print(f"VIOLATION: {sorted(set(errs))}")
        print("counterexample trace (action -> key state fields):")
        for action, s in trace(parents, vstate):
            print(f"  {action}: epoch={s[0]} now={s[7]} "
                  f"pending={'yes' if s[8] else 'no'} log_len={len(s[9])} "
                  f"honestRootMismatch={s[11]}")
        sys.exit(1)
    print("ALL INVARIANTS HOLD over the full reachable bounded state space.")

if __name__ == "__main__":
    main()
