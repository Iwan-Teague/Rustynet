# W5.6 Flip Dispositions (NodeEngineAcceptanceSpec §6.1) — 2026-07-24

**Named disposition ledger** for the W5.6 default-flip (bash → `--node`). Per
`NodeEngineAcceptanceSpec_2026-07-23.md` §6.1, a red/skipped in-scope cell may be
dispositioned out of the flip gate only under: (a) recorded in a named ledger
(this file), (b) owner sign-off per item with a stated reason, (c) an expiry /
re-review date, (d) T4-security items are NOT dispositionable below owner level,
and (e) the deferral is mirrored into the acceptance spec's list. Each item below
satisfies (a)–(e).

The flip is gated by **G1 (engine-adjudication trust)**, not G2 (parity
attainment) — §1. The unifying principle for every disposition here: the `--node`
engine **correctly adjudicated** each item (it reported the red/skip loudly and
truthfully — no false-green), which is exactly what G1 tests. None of these is an
engine-trust failure; each is a product/tooling gap the engine correctly surfaced.

## Flip evidence baseline (for context)

- Flip-candidate commit: `a414ceb` (clean tree, dirty-check fixes `65b9368`+`a414ceb`).
- §5.4 stability: **5-of-5** clean runs at `a414ceb` (`anchor_validation` 5-of-5,
  the flake-recorded stage; every other T0/T1 stage 5-of-5). Each run
  independently **A2-verified VALID** (§4.8). T0 (14 stages) + T1 (19 stages) all
  GREEN except the dispositioned items below.
- G3 enumeration-diff precondition: satisfied (`G3EnumerationDiff_2026-07-23.md`).

## Dispositions

### D1 — `live_two_hop_validation` (T1 client capability): validator-tooling gap
- **Status in the flip runs:** SKIPPED in the standard 5-node topology (correct,
  role-gated — needs an `entry` role + a second client, absent by design); FAILED
  in a dedicated two-hop topology (`exit/client/entry/aux/extra`) on a **tooling
  bug**, not the dataplane.
- **Root cause (verified):** `two_hop`'s known-hosts-file mode pre-check calls
  `ops check-local-file-mode`, which is `#[cfg(feature = "vm-lab")]`-gated. The
  helper `run_cargo_ops` (`crates/rustynet-cli/src/bin/live_lab_bin_support/mod.rs:755`)
  invokes `cargo run -p rustynet-cli` **without `--features vm-lab`**, so the
  subcommand is not compiled into the binary it runs → `unknown ops subcommand:
  check-local-file-mode`. The stage failed **before reaching any two-hop routing**.
- **Why it does not block the flip (G1):** the engine reported the failure loudly
  and correctly (a hard RED with a precise error) — no false-green. G1 tests
  whether the engine can be believed; a validator-scaffolding bug it *correctly
  surfaces* is orthogonal to engine trust. The client's *managed-tunnel* T1 path
  (traffic_test_matrix, live_managed_dns) is GREEN 5-of-5.
- **Owner sign-off:** APPROVED 2026-07-24 (owner chose "disposition two_hop, flip
  now" over a ~4h full re-prove).
- **UPDATE 2026-07-24 (tooling fixed → real root cause GROUNDED, and a prior
  mislabel corrected).** The `run_cargo_ops` `--features vm-lab` fix landed
  (`553f92d`, post-flip G2 item). With it, the two-hop topology re-run got *past*
  the pre-check and exercised the actual dataplane proof, which fails as
  `end_to_end_reachable=false per_hop_ttl_decrement=none`.
  - **CORRECTION:** an earlier draft of this update called it "the client↔client
    WireGuard-transport gap." That is **wrong**, grounded out as follows:
    - **Client↔client direct mesh reachability WORKS on the engine of record.**
      `traffic_test_matrix` (`stage/traffic_test_matrix.rs:101-160`) is a genuine
      full cross-node mesh probe (skips self L118; errors on any unreachable pair)
      and it **PASSED** in the two-hop run, which had **three clients**
      (debian-2 + fedora-aux + ubuntu-extra) — so every client↔client pair reached
      each other directly. The 2026-07-15 "client↔client 100% loss" finding is
      **stale / since-fixed**, not a current bug.
    - **Not a lab-no-internet artifact either:** the exit guest reaches `1.1.1.1`
      at baseline (0% loss, via the UTM Shared gateway `192.168.64.1`).
  - **Actual root cause (narrower):** the **two-hop EXIT-CHAIN internet route**
    (`client → entry(=client's exit) → final-exit → NAT → internet`) does not
    complete. The client reaches the *final exit's mesh IP* (two-hop TTL reply 64)
    but `1.1.1.1` via the chained NAT is unreachable, and the baseline (entry) TTL
    probe returned None. So this is a **two-hop exit-chaining / forwarding** gap
    (entry-as-intermediate forwarding to a second exit + chained NAT), a **product**
    gap of the same class as D3 `network_flap`. The engine adjudicates it correctly
    (loud, detailed RED, no false-green), so G1 engine-trust is unaffected.
- **UPDATE 2026-07-25 — root cause GROUNDED to a test-harness atomicity gap; the
  2026-07-24 "exit-chain forwarding gap" label is CORRECTED to *unproven*.**
  - **What actually fails.** The `entry` daemon **fails closed and tears down
    `rustynet0`** before the data-plane probes run. Journal at the probe instant:
    `traversal authority rejected reconcile apply: snapshot contains unmanaged peers:
    fedora-utm-1-bootstrap,ubuntu-utm-1-bootstrap` (×5) →
    `restrict_permanent: reconcile failure threshold exceeded: 5` →
    `disconnect cleanup complete … interface_present=false`. This is **correct
    fail-closed behaviour, not the bug.**
  - **Mechanism (source-grounded).** The daemon's managed peer set comes from the
    **assignment** bundle (`envelope.bundle.peers`, `daemon.rs:8919`; parallel site
    `:7414`) — *not* from membership. `apply_traversal_authority_to_peers`
    (`daemon.rs:6693-6755`) requires **exact set equality** between that peer set and
    the traversal bundle's target index, failing closed in both directions:
    `missing` = expected−indexed (`:6724-6729`), `extra` = indexed−expected →
    `"snapshot contains unmanaged peers"` (`:6730-6739`); the same pair is enforced in
    the probe path (`:6207-6230`). Each rejection increments `reconcile_failures` and
    calls `promote_to_permanent_if_over_limit` (`:8976-8987`, `:9250-9257`);
    `DEFAULT_MAX_RECONCILE_FAILURES = 5` (`:338`). A traversal bundle for source `S`
    holds exactly one hint per ALLOW pair `S→T` (`ops_e2e.rs:3544-3583`), so the
    index ≡ `S`'s ALLOW targets; installing one **overwrites** the file and drops the
    watermark (`live_linux_two_hop_test.rs:1443-1475`) and the loader rejects mixed
    snapshots (`daemon.rs:13596-13605`), so bundles never union.
  - **Why the entry saw a mismatch.** `two_hop` narrows the inherited 5-node mesh to
    its 4-node chain by rewriting **both** sides from the same `NODES_SPEC`/
    `ALLOW_SPEC` (`:191-224`) but **non-atomically and assignment-first**: assignment
    bundles install at `:322-350`, while traversal is only *issued* at `:418` and
    installed at `:479-507` (an on-guest issuance plus five `scp` captures in
    between). Inside that window the daemon holds the **narrow** assignment
    (entry peers `{client, final_exit}`) against the **setup's full-mesh** traversal
    index (targets including `fedora` + `ubuntu`) → `extra_peers = {fedora, ubuntu}`,
    which is the observed error string **with the observed node list**.
  - **THE INVARIANT, AND THE PRODUCTION EXPOSURE (corrected 2026-07-25 — an earlier
    draft of this entry got the protecting mechanism wrong; recorded here because the
    wrong version is the more comforting one).**
    - **The invariant:** a running daemon must never observe the assignment peer set
      and the traversal target index unequal. Both directions fail closed and five
      consecutive rejections latch a permanent restriction, so the two artifacts are
      semantically **one atomic pair**.
    - **What does NOT protect production.** `ops refresh-assignment` does re-mint
      **both** halves from the single `/etc/rustynet/assignment-refresh.env`
      (`refresh_local_traversal_bundle_from_specs`, `main.rs:14345`, called before the
      assignment-TTL short-circuit), which is genuinely atomic — **but that path is
      off by default and unavailable to ordinary nodes.**
      `RUSTYNET_ASSIGNMENT_AUTO_REFRESH` defaults to `"false"` at runtime
      (`main.rs:9443`) and in the installer (`ops_install_systemd.rs:237`), and the
      lab's own e2e env sets it `"false"` (`ops_e2e.rs:644`), so the 60 s timer is a
      **no-op** unless explicitly enabled. It is also a local **minter**, not a
      fetcher: it requires the mesh assignment signing secret on the node
      (`validate_root_owned_encrypted_signing_file` guards
      `/etc/rustynet/assignment.signing.secret` immediately before the call), which a
      normal production node is not expected to hold — putting it on every node is
      exactly the key-custody expansion `TraversalSelfSustenancePlan` §3 uses to
      reject Design B. So the atomicity guarantee applies **only** to the opt-in
      self-minting configuration. `two_hop` is one such node set: its
      `write_assignment_refresh_env` sets `AUTO_REFRESH=true`
      (`live_lab_bin_support/mod.rs:733`), turning self-minting **on** mid-stage for
      the four chain nodes, which setup had left off.
    - **What actually holds on a default node:** *neither* half is autonomously
      re-minted, so both change only when an external pusher installs them. The
      invariant is therefore **not structurally enforced in general** — it rests on
      the pusher's ordering.
    - **⇒ PRODUCTION IS EXPOSED IN PRINCIPLE, and this should not be papered over by
      the test fix.** Any flow that **changes** a node's peer/target set (an ACL
      narrowing, a membership or capability change) and pushes the two halves as
      separate steps while the daemon is reconciling reproduces exactly this failure:
      fail-closed ×5 → permanent restriction → tunnel torn down. The race requires a
      set *change*; it does not bite at lab setup only because both halves are
      full-mesh there and the sets are already equal. Note the lab orchestrator itself
      distributes them as two separate stages (`distribute_assignments`,
      `distribute_traversal`) — the product's own tooling exhibits the vulnerable
      pattern.
    - **The window is far tighter than a human-paced push.** Reconcile runs at
      `DEFAULT_RECONCILE_INTERVAL_MS = 1000` (`daemon.rs:337`) against a threshold of 5,
      so roughly **five seconds** of observed set inequality is enough to latch the
      permanent restriction and tear the tunnel down — where this test needed tens of
      seconds only because its swap is that slow. A later successful apply does clear
      the restriction, so it self-heals, but the tunnel is down in the meantime.
    - **Routed, not fixed here** (outside the `two_hop` partition): someone must
      decide whether the pusher is required to co-distribute both halves atomically,
      whether the daemon should consume a single combined artifact, or whether the
      set-equality check should be evaluated against a staged pair. Cross-referenced
      from `TraversalSelfSustenancePlan_2026-07-23.md`, whose I4 dual-path precedence
      must preserve the same property.
    - The `two_hop` fix below is therefore **conformance to the invariant on the one
      node set this test controls** — not evidence that the product is safe.
  - **The per-hop TTL constant was always WRONG, and the ALLOW spec made the
    measurement NON-DETERMINISTIC.** `EXPECTED_PER_HOP_TTL_DECREMENT = 2` (exact `==`)
    arrived with `b162be02` (2026-06-25).
    - **The corrected value is DERIVED AND PRE-REGISTERED — not retro-verified**
      (wording corrected 2026-07-26; an earlier draft claimed retro-verification, which
      overstates it). Two archived reports at `c66887a8c` (2026-06-27) do record
      **`baseline_reply_ttl=64, two_hop_reply_ttl=63, per_hop_ttl_decrement=1,
      ok=false`** — `state/3os-postseed-c66887a/live_linux_two_hop_report.json` and
      `state/winadmin-legacy-c66887a/live_linux_two_hop_report.json` — so `2` was
      demonstrably unattainable and the direction of the change is well supported. But
      those measurements come from a **peer topology that this same change altered**
      (the client still had its own `client|final_exit` peer and route), and the new
      single-path topology **has never yielded a two-hop TTL at all**. So the value `1`
      rests on the derivation plus a pre-registered prediction, with the old-topology
      reports as corroboration, not as verification of the new topology.
    - **The oracle's SHAPE is the real strengthening, independent of the value.**
      `baseline == 64 && delta == 1` forces `two_hop == 63` exactly, which correctly
      rejects both a direct reply (64) and a double-forward (62). Keeping the comparison
      exact and adding the absolute-baseline assertion is what makes it bind; only the
      *number* awaits a measurement on this topology.
    - **A retracted claim, kept visible.** An earlier draft of this entry asserted the
      assertion was "unsatisfiable because `client|final_exit` gave the client a
      direct tunnel, so the probe measured a 1-hop reply". **That is FALSIFIED** by the
      `c66887a8c` pair above: with the pair present the probe measured a genuine
      two-hop reply path (delta 1). The pair does not force a direct reply.
    - **The defensible reason to strip the pair is DETERMINISM.** With
      `client|final_exit` present the measured delta is not stable across runs: **1**
      at `c66887a8c` (2026-06-27), **0** at `050743825` (run #10, baseline 64 /
      two-hop 64), and **−1** at `f9388393` (run #11, baseline −1 because the entry had
      torn itself down). A stability gate cannot stand on an oracle whose input
      depends on which of two available paths the traffic happens to take. Removing the
      pair leaves exactly one path. **The post-strip delta had never been measured
      before 2026-07-25** (see the run below).
    - *Search trap for the next person:* older reports are named
      **`live_linux_two_hop_report.json`**, current ones **`live_two_hop_report.json`**.
      Searching only the current name silently misses every pre-July measurement — it
      is how the `c66887a8c` evidence was missed on the first pass.
- **Derivation of the correct decrement (written before measurement; the
  justification for changing the constant).** WireGuard is an encapsulating **link**,
  not a router: encapsulation does not decrement the inner TTL, only *forwarding*
  does, and a node that **originates** a packet (including an ICMP echo *reply*)
  stamps the initial TTL (64 on Linux). So the client-observed reply TTL depends on
  the **reply path only** = 64 − (forwarding hops on the return path).
  - *baseline* (client → entry mesh IP): the entry originates the reply, the client is
    a direct peer → **0** return forwards → **64**.
  - *two-hop* (client → final-exit mesh IP, with `client|final_exit` stripped): the
    request matches the client's `0.0.0.0/0` via the entry; the entry forwards it and
    **masquerades** the hairpin, so the final exit's reply is addressed to the
    **entry** (a direct peer, 0 forwards) and the entry then un-NATs and forwards it
    to the client → **1** return forward → **63**.
  - **⇒ expected `per_hop_ttl_decrement = 1`.**
  - **Why the in-code `2` is simply wrong (not merely model-dependent).** `2` requires
    **two** intermediate forwarders on the reply path, and this topology has exactly
    one (the entry). The final exit never *forwards* the reply — it *originates* it.
    So `2` is unreachable under either a masquerading or a pure-routing hairpin, and
    the author additionally mis-modelled the baseline as already carrying a decrement
    (hence the unit tests' 63/61 at `:2540-2560`).
  - **What the hairpin masquerade actually buys is DELIVERABILITY, not the hop
    count** — and it is why stripping the ALLOW pair is safe. Verified chain:
    `relay_with_upstream = exit_mode == FullTunnel && serve_exit_node`
    (`phase10.rs:5063-5064`) → `set_relay_forwarding` (`:1914`) → nft
    `iifname rustynet0 oifname rustynet0 masquerade` (`:2285-2299`). Without that
    SNAT the final exit would have **no route back** to the client once
    `client|final_exit` is removed (its peers carry only `entry/32` and
    `second_client/32`), so the reply would not return at all.
  - **Falsifiable predictions for the verifying run:** `baseline_reply_ttl = 64` (a
    measured 63 falsifies the origination rule → stop and report),
    `two_hop_reply_ttl = 63`, `per_hop_ttl_decrement = 1`. A measured **2** would mean
    an **additional, unexpected forwarding hop on the reply path** — a genuine
    data-plane finding bearing on the forwarding question below, not a reason to keep
    the constant at 2.
- **VERIFYING RUN 2026-07-25 — the fence is PROVEN; the residual question is
  narrowed but OPEN.** Run `livelab-1784993329-f9388393729d`
  (`state/live-lab-ll-1784992427041-36819-0`, diagnostic-grade: the fix was
  working-tree state, so the row records `f9388393` + `dirty:worktree`). A2 evidence
  verifier: **`VALID (not a pass)`**, §4.1/§4.2/§4.5/§4.6 all PASS.
  - **The traversal race is DEAD.** **Zero** occurrences of `unmanaged peers`,
    `missing signed traversal state`, or `reconcile failure threshold exceeded` on the
    entry across the whole run; the only journal matches were benign no-op
    `disconnect cleanup complete` lines. Entry timeline through the stage:
    `peers=4` → (fence stops the daemon) `iface=absent` → **`iface=up peers=2`** (the
    correctly narrowed set) and it stayed up. The entry **never fail-closed and never
    tore down**, versus a permanent restriction in run #11. Linux stages went
    **19 pass → 29 pass**, with `two_hop` the only red.
  - **`baseline_reply_ttl = 64` — the pre-registered prediction, confirmed.** This also
    refutes the original constant's implicit "baseline 63" model by measurement.
  - **`two_hop_reply_ttl = −1` (no reply); `end_to_end_reachable = false`.** The
    pre-registered 63 was NOT met, so per the derivation discipline neither the
    derivation nor the constant was adjusted to fit.
  - **What is NOT yet established.** The stage ended ~12 s after the entry's daemon
    came up cold, and `peers=2` is *config*, not *liveness*. Two readings remain open:
    (a) **warm-up** — the entry↔final tunnel had not finished handshaking when the
    probe fired, making the `−1` an artifact of the fence's own cold restart; or
    (b) a **genuine forwarding regression** on the entry→final leg, which would be a
    regression rather than a never-worked gap, since `c66887a8c` measured 63 on that
    same leg. `baseline=64` proves handshakes were not uniformly blocked, but
    client↔entry and entry↔final are different pairs with different transport
    identities (the entry runs the non-shared kernel backend; client and final are
    shared-transport), so they need not converge together. **The run's captures cannot
    decide it** — the stage log was clipped past the entry's status block and the
    journal does not record per-peer handshake ages at that verbosity.
  - **Instrument added to decide it** (not a workaround): `await_two_hop_path_ready`
    polls **actual ICMP reachability** over the two-hop path, bounded to 90 s, before
    measuring, and records `path_readiness_{probe_attempted,became_reachable,attempts,
    waited_secs}` in the report. It is fail-closed — it only ever *delays* the
    measurement, never skips or softens it, so if the path stays unreachable the probes
    still run and still fail. The next run therefore discriminates: *became reachable
    after N attempts* ⇒ reading (a), warm-up; *never reachable across every attempt
    over 90 s* ⇒ reading (b), a real forwarding regression. Liveness is deliberately
    tested by round trip and never by `path_live_proven`, which is structurally
    unsatisfiable on shared-transport nodes.
- **★ SECOND VERIFYING RUN 2026-07-25 — the open question is CLOSED: the entry→final
  forwarding leg is genuinely broken, and it is a REGRESSION.** Run
  `livelab-1784995467-f9388393729d`
  (`state/live-lab-ll-1784994471871-36819-1`, `f9388393` + `dirty:worktree`,
  diagnostic-grade). A2: **`VALID (not a pass)`**, exit 2, §4.1/§4.2/§4.5/§4.6 PASS.
  Stages again **29 pass / 16 skip / 1 fail**, `two_hop` the only red, and
  **zero** fence-critical journal lines (the fence now holds across two consecutive
  runs).
  - **Readiness gate verdict — branch (b).** `path_readiness_became_reachable=false`
    after **14 attempts over 95 s**. The two-hop path never carried a single packet in
    a sustained hundred-second window.
  - **Warm-up is DEFINITIVELY EXCLUDED by the per-peer handshake and byte counters.**
    Sampled on the entry every 10 s through the stage, after the fence's cold restart
    both peers were continuously handshaked and actively moving data:
    ```
    16:02:18  client:hs_age=3s  rx=507    tx=92     final:hs_age=2s  rx=180   tx=92
    16:03:20  client:hs_age=1s  rx=22467  tx=13228  final:hs_age=0s  rx=14800 tx=7808
    16:04:11  client:hs_age=1s  rx=54451  tx=31984  final:hs_age=0s  rx=43204 tx=22496
    ```
    `hs_age` stayed at 0–3 s for **both** peers and both byte counters climbed
    monotonically into the tens of kilobytes. So the entry↔final tunnel was up, fresh
    and functional for the entire readiness window — the `-1` is not a cold-start
    artifact of the fence. (The climbing entry↔final counters do not by themselves
    prove *forwarded* traffic: the entry also runs its own full tunnel through the
    final exit, so its own egress crosses that link. They prove the link works, which
    is what refutes warm-up.)
  - **`baseline_reply_ttl = 64` again** — the pre-registered baseline now holds across
    two independent runs, so the origination rule and the corrected constant are on
    firm ground even though the two-hop half cannot yet be measured.
  - **`MATCHES PRE-REGISTRATION = false`** (`two_hop_reply_ttl=-1`,
    `per_hop_ttl_decrement=-1`, `end_to_end_reachable=false`). Neither the derivation
    nor the constant was adjusted to fit — the derived value stands unmeasured on its
    two-hop half until forwarding is repaired.
  - **⇒ This is a REGRESSION, not a never-worked gap:** `c66887a8c` (2026-06-27)
    measured `64 / 63 / delta 1` on this same leg. Next step is a **static** narrowing
    of `c66887a8c..HEAD` across `crates/rustynetd/src/phase10.rs`,
    `crates/rustynetd/src/daemon.rs`, `crates/rustynet-backend-wireguard/` and
    `third_party/rustynet-tun/`, with `fef40bb` (FIS-0027 MTU-at-bring-up, already a
    proven flap regression on NetworkManager/networkd distros — and the entry is rocky)
    and `8f957f5` (2026-07-20, the 17-branch efficiency-catalog merge carrying
    dataplane perf changes) as the first two suspects. Live runs are for confirming a
    specific suspect, not for bisecting a month of commits at ~40 min each.
  - The 2026-07-24 claim that exit-chain forwarding was the "actual root cause"
    remains **not evidenced**, and is now further undercut: the traversal teardown
    alone accounted for run #11's reds, and the forwarding leg has still never been
    measured under stable, warm conditions.
- **★ `ip_forward` REFUTED as the 2026-07-25 cause (2026-07-25, third run).** Recorded
  because it was the leading suspect and the refutation came from the probe armed to
  confirm it. Entry samples inside the two_hop window
  (`state/live-lab-ll-1785004213271-36819-2`):
  ```
  18:43:06  iface=up      ip_forward=1  ForwDatagrams=54  hairpin_rules=0
  18:43:16  iface=absent  ip_forward=0  ForwDatagrams=54   <- the FENCE, not a defect
  18:43:37  iface=up      ip_forward=1  ForwDatagrams=54  hairpin_rules=0
  18:43:47  iface=up      ip_forward=1  ForwDatagrams=56  hairpin_rules=2
  18:45:19  iface=up      ip_forward=1  ForwDatagrams=94  hairpin_rules=2
  ```
  `ip_forward=1` for the entire post-restart window, both hairpin rules installed, and
  the kernel actively forwarding. So `696b8c52`/`9c425f5b` are **cleared** as the cause.
  - **RETRACTED 2026-07-26 — the `ForwDatagrams` arithmetic does NOT localise the
    break, and it was wrongly called "the decisive datum".** The claim was: readiness
    sent 14 × `ping -c 3` = 42 requests while `ForwDatagrams` moved 54 → 94 = 40, so
    ~42 ≈ requests-only and "nothing returns". Three independent reasons it fails:
    1. `IPSTATS_MIB_OUTFORWDATAGRAMS` increments in `ip_forward_finish`, which the
       kernel reaches **through** `NF_INET_FORWARD` — so a reply dropped by the entry's
       own forward chain is **never counted**. ~42 is therefore equally consistent with
       "replies never arrived", "arrived and were dropped in FORWARD", and "arrived but
       conntrack failed to reverse the SNAT so they were delivered locally".
    2. The client is a **FullTunnel** client of the entry, so *every* packet it emits
       for any reason (resolver retries, chrony) is forwarded in both directions —
       ~20 background packets accounts for the entire delta.
    3. Requests-only actually predicts **48** (42 readiness + 3 end-to-end + 3 TTL),
       above the observed 40–46, so the fit was never tight.
    The lesson is narrower than the claim: counter arithmetic can bound magnitudes but
    cannot localise a drop across a netfilter hook that sits *upstream* of the counter.
  - **RETRACTED 2026-07-26 — "the full hairpin round trip worked at `c66887a8c`" is
    FALSE, and with it the entire regression framing.** `end_to_end_probe_target` is
    `TWO_HOP_PUBLIC_PROBE_TARGET = "1.1.1.1"` (`live_linux_two_hop_test.rs:1923`, call
    site `:1139`) — **not** the final exit's mesh IP. Both `c66887a8c` archives already
    record **`end_to_end_reachable: false`** (verified directly in
    `state/3os-postseed-c66887a/` and `state/winadmin-legacy-c66887a/`). So
    internet-through-the-chain has failed **continuously since at least 2026-06-27**.
    - The only observable that changed is the **mesh-IP TTL probe** (63 → no reply), and
      it changed in the same commit that removed the client's own peering with the
      final exit. So there is **no regression window**, and the commit-range hunt over
      `c66887a8c..HEAD` (including the `ip_forward`, MTU, perf-merge and iproute2
      suspects) was searching a window in which nothing relevant broke.
    - **Corrected hypothesis: ONE long-standing defect, not two.** Partition the probes
      by whether the entry must forward *on the client's behalf*: client → entry mesh IP
      **works** (the entry answers locally); client → final-exit mesh IP **fails** (it
      worked only while the client had its own peer and route); client → `1.1.1.1`
      **fails, and failed at `c66887a8c` too**. Everything terminating at the entry
      succeeds; everything requiring the entry to forward for the client fails. The
      `client|final_exit` pair was **masking a long-standing exit-serving forward
      defect**, and stripping it (change (C)) removed the mask — turning a green
      sub-probe red without altering any daemon behaviour.
    - Within that, the **request** leg is the more likely silent-drop point than the
      return leg: without an effective hairpin SNAT the request reaches the final exit
      with inner `src = client` mesh IP, against an entry peer whose `AllowedIPs` is
      `entry/32`, so WireGuard cryptokey routing drops it **after decryption**, silently
      and with no ICMP — and invisibly to `tcpdump -ni rustynet0` at the final exit.
  - `hairpin_rules=2` proves the rules **exist**, not that the masquerade is
    **effective**: that rule is built without a `counter`, so it cannot be counted
    directly, which is why the decisive observation must be made at the **final exit**
    rather than by more entry-side counting.
- **★ COVERAGE LOST BY THE FENCE — the `extra_peers` fail-closed direction is no longer
  exercised anywhere.** Before the fence, this stage inadvertently drove the
  `extra_peers` branch of `apply_traversal_authority_to_peers`
  (`daemon.rs:6730-6739`, "snapshot contains unmanaged peers") end-to-end every run —
  that is precisely the teardown the fence now prevents. The fence is right, but the
  coverage was real and is now gone.
  - **Asymmetric unit coverage:** the `missing` direction *is* pinned — a runtime test
    asserts `"missing signed traversal state for managed peers: node-relay"`
    (`daemon.rs:26328`, inside the multi-peer traversal-authority snapshot test around
    `:26317-26339`). There is **no equivalent assertion for `extra_peers`**, so that
    branch now has neither live nor unit coverage.
  - **Spec for the test to add** (deliberately specced rather than half-built): mirror
    the existing multi-peer snapshot test, but construct the traversal index as a
    **strict superset** of the assignment peer set — index `{peer_a, peer_b}` against a
    bundle whose `peers` is `{peer_a}` — then assert the reconcile fails closed with
    `"snapshot contains unmanaged peers"` naming `peer_b`, and that
    `restriction_mode`/`reconcile_failures` advance. Both directions then have a pinned
    negative test, and neither depends on a live stage accidentally producing the
    condition.
  - Worth doing precisely *because* the live path no longer produces it: a fail-closed
    branch whose only historical proof was an accident of a broken test topology is one
    refactor away from silently becoming fail-open.
- **★ METHOD FINDING — an automated verdict must model the instrument's own
  perturbation.** The pre-registered decision tree printed
  *"ip_forward TOGGLED 1→0 → a clear site fired after apply"*, which is **wrong**: the
  `1→0` is the atomicity fence stopping `rustynetd`, visible as `iface=absent` on the
  very same samples. The tree could not distinguish *"the system did X"* from *"the
  harness did X to the system"*, and it would have sent the next reader to the wrong
  commits with an authoritative-looking verdict. This is the analysis-layer twin of the
  observer effect avoided in the measurement layer (reading `/proc/net/snmp` instead of
  instrumenting nft rules, precisely so diagnosing a firewall-adjacent fault would not
  make the firewall part of the experiment). **Rule: any pre-registered classifier must
  either exclude the windows in which the harness itself mutates the system, or carry an
  explicit branch for them.** Related: the probe survived stage-log truncation only
  because it was deliberately placed in a host-side capture outside the test binary's
  stdout — designing around QH-09 is what preserved it.
- **★ STANDING FRAGILITY FINDING — `net.ipv4.ip_forward` has one setter, seven
  clear sites, and the clears discard their result.** Recorded independently of
  whether it proves to be the 2026-07-25 forwarding regression, because it is a latent
  race in a **security-relevant** sysctl either way.
  - **Asymmetry.** `ip_forward` is enabled at exactly one place —
    `set_ipv4_forwarding(true)` from `apply_nat_forwarding`
    (`crates/rustynetd/src/phase10.rs:1603` / `:1685-1700`, reached via the
    `exit_mode == FullTunnel || serve_exit_node` gate at `:5227`) — and cleared at
    **seven**: `:1720`, `:2233`, `:2262`, `:2282`, `:2307`, `:2344`, and unconditionally
    in `rollback_nat_forwarding` (`:2354-2393`). A single set-once against seven
    clears is racy by construction, regardless of today's bug.
  - **The clears are `let _ = self.restore_ipv4_forwarding();`** — error paths that
    mutate a security-relevant sysctl **and discard whether the mutation succeeded**.
    That is bad in both directions: a failed restore silently leaves forwarding
    **enabled** after demotion (the residue leak that `696b8c52`/`9c425f5b` exist to
    close), and a successful one silently leaves it **disabled** mid-service (the
    forwarding symptom under investigation). Neither outcome is reported.
  - **Diagnosability cost, measured.** The daemon logs none of these operations at
    default verbosity: the entry's journal for a whole failing two_hop window contained
    zero `nat|forward|sysctl|masquerade` lines, so the sysctl transition is invisible
    and had to be observed out-of-band from `/proc`. An error path that silently
    toggles forwarding should at minimum log the trigger and the restore outcome.
  - **Fix shape (constraint, not yet a proposal).** Any repair must **converge** the
    required state — assert `ip_forward=1` on every reconcile while the node
    legitimately serves as an exit, and keep restoring it on demotion — rather than
    relax the clears. "Set it on and stop clearing it" is explicitly rejected: it would
    trade this forwarding defect for the demotion-residue release-blocker those two
    commits closed. Whatever lands must state how demotion residue stays closed.
- **HARNESS FINDING — stage-log truncation is a DISCOVERABILITY defect, not evidence
  loss. (Corrected 2026-07-26; an earlier version of this entry claimed the clip
  "destroyed the decisive evidence" — that was WRONG and is retained here as the
  correction, because it is the more alarming version and would otherwise be
  re-derived.)**
  - **What is true:** the stage record's inline copy is clipped to
    `STAGE_FAILURE_STREAM_BUDGET = 4000` chars
    (`vm_lab/orchestrator/stage/mod.rs:307`, formatter `:333-360`, disclosure test
    `:427`), so `logs/live_two_hop_validation.log` held 4,288 of 14,818 bytes.
  - **What is FALSE:** that the lost bytes were unrecoverable. The stage passes
    `--log-path` to the test binary, which writes its **own complete log** to
    `<report_dir>/live_two_hop.log` — verified at 13,583 bytes for
    `state/live-lab-ll-1785006873254-36819-3`, containing every section *and* the
    per-node status blocks. **The full evidence was there the whole time; the wrong
    file was read.** A sidecar spill was queued as the fix — it is largely redundant,
    because the sidecar already exists.
  - **Also note the tail-keeping is deliberate and correct** for its intended case: a
    failing CLI dumps ~11.5 KB of usage text and prints the real error last, so
    clipping the head would hide the one useful line (`:339-345`). Do not "fix" that.
  - **The real, much smaller defect:** the clip disclosure does not name the complete
    artifact. A reader who sees `…(clipped 10818 of 14818 bytes; tail follows)` has no
    indication that an unclipped `live_two_hop.log` sits beside it, which cost a full
    diagnostic cycle and produced the false finding above. Minimal fix: have the
    disclosure point at the full-log artifact when the stage has one (the caller
    already holds `log_path_str`; the formatter is pure and does not, so the pointer
    belongs at the call site or as an added optional parameter).
- **★ RUN-4 ENTRY STATUS — settles two open questions from evidence already on disk
  (2026-07-26).** From the complete `live_two_hop.log` of
  `state/live-lab-ll-1785006873254-36819-3`:
  ```
  node_role=admin state=ExitActive serving_exit_node=true
  exit_node=debian-headless-4-bootstrap
  managed_peer_endpoints=debian-headless-2-bootstrap/192.168.64.4:51820
                        +debian-headless-4-bootstrap/192.168.64.10:51820
  path_live_proven=true path_live_peer_count=2 path_programmed_peer_count=2
  traversal_peer_count=2 restriction_mode=None reconcile_failures=0
  last_reconcile_error=none
  ```
  - **The fence is confirmed again from the daemon's own view:** `restriction_mode=None`,
    `reconcile_failures=0`, no reconcile error — no fail-closed, no teardown.
  - **BOTH entry tunnels were LIVE-PROVEN** (`path_live_peer_count=2`), including the
    one to the final exit. `path_live_proven` is meaningful here precisely because the
    entry runs the non-shared kernel backend, the case where that signal *is*
    satisfiable.
  - **⇒ Run 4's `aips=[]` on the final exit was an INSTRUMENTATION ARTIFACT**, not an
    empty peer set: a live proven handshake with the final exit is impossible if the
    final exit held no peer for the entry. The "final exit had no peers" candidate is
    **refuted**, and the earlier refusal to name a branch from that reading was
    correct.
  - So the picture is now: entry healthy, correctly narrowed to 2 peers, both tunnels
    live-proven, `ip_forward=1`, hairpin rules present, ~42 requests forwarded — and
    **nothing returns**. The open question is narrowed to the return leg at or beyond
    the final exit.
  `scripts/e2e/live_linux_two_hop_test.sh` has been a two-line
  `exec cargo run … --bin live_linux_two_hop_test` wrapper since `4f9689d9`, so the
  bash engine and the `--node` engine run **identical** two-hop logic and the
  identical ALLOW spec. `live_lab_run_matrix.csv` records **56** linux `two_hop`
  passes, of which **exactly 52 predate `b162be02`** — i.e. they ran with **no
  end-to-end and no per-hop assertion at all** and proved control-plane wiring only,
  never two-hop forwarding. The remaining 4 all sit in runs whose *first* failure was
  an earlier stage (`active_exit` ×1, `exit_demotion_residue_validation` ×2,
  `exit_dns_failclosed_validation` ×1), so they are recording artifacts rather than
  executions. **No archive row is a genuine two-hop forwarding proof**, so the archive
  must not be read as showing a capability the `--node` engine lacks. General lesson:
  *a ledger row is only as strong as the assertion in force when it was recorded.*
- **Fix (test-side only).** All in
  `crates/rustynet-cli/src/bin/live_linux_two_hop_test.rs`:
  - **(A) atomicity fence — LIVE-PROVEN 2026-07-25.** Quiesce the
    `rustynetd-assignment-refresh.timer`, its service, and `rustynetd` on the four
    chain nodes across the artifact swap, so no reconcile can observe a half-swapped
    pair; `enforce_host` then brings each daemon up cold on the completed pair.
    Deliberately a **fence rather than a re-ordering**: staging every artifact before
    every install would only shrink the inconsistent window, whereas quiescing
    eliminates it and also covers the dns-zone bundle. Made exception-safe by a
    `Drop`-based guard (`BundleSwapFence`) because the swap spans a long run of
    fallible SSH steps — without it any `?` would abort leaving four guests with the
    daemon and timer stopped *by the test*, which both confounds post-mortems and
    trips later stages on "timer is active". The traversal installer also gained the
    same `retry_root` treatment the dns-zone installer already had, since it is the
    flakiest step inside the quiesce window.
  - **(B)** subsumed into (A) — see above; do not re-add issue-then-install staging.
  - **(C)** strip `client|final_exit` + `final_exit|client` from `ALLOW_SPEC` so the
    client has exactly one peer and the per-hop probe has exactly one available path,
    and correct the constant to the derived **1**, keeping the comparison exact
    (`==`). Also assert the **absolute baseline** (`EXPECTED_BASELINE_REPLY_TTL = 64`),
    not merely the delta: a delta check alone accepts `(63, 62)` identically to
    `(64, 63)` even though a forwarded baseline is topologically impossible, so
    without it the derivation does not bind.
  - **Readiness gate** (`await_two_hop_path_ready`) — bounded, fail-closed, recorded
    in the report; see the verifying-run entry above for why it exists and what it
    discriminates.
  - **No daemon change:** set equality, the failure threshold, the managed-peer
    definition, and signature/freshness/anti-replay validation are all untouched — the
    fix removes an invalid intermediate state rather than teaching the daemon to
    tolerate one (§13.2).
- **Expiry / re-review:** prove `two_hop` GREEN in a real `--node` run as a
  **G2/release** item, then re-judge the forwarding question above.
  - **★ Acceptance MUST read the two_hop REPORT, because the ledger cell is a proven
    FALSE-GREEN.** Require `live_two_hop_report.json` to show `status = pass` **and** a
    `dataplane` block with `end_to_end_reachable = true`, `baseline_reply_ttl = 64`,
    `per_hop_ttl_decrement = 1`, and `per_hop_ttl_decrement_ok = true`.
    - **The `linux_stage_two_hop` column cannot be trusted for this stage.**
      Quote-aware parse of `live_lab_node_run_matrix.csv` (108 rows):
      **`pass 43 | skip 22 | fail 34 | not_run 9`**. Against the per-stage ledger
      (`live_lab_node_stage_results.csv`, 15,432 rows) those 43 passes are not
      two-hop proofs:
      ```
      live_two_hop_validation:  skip 263 | fail 116 | pass 0   ← has NEVER passed
      traffic_test_matrix:      pass 260 | skip 75 | not_proven 34 | fail 10
      ```
    - **Root cause is a ledger-code defect, not prose.** Three distinct stage names
      alias onto the same column in `crates/rustynet-cli/src/live_lab_run_matrix.rs`:
      `"traffic_test_matrix" => Some("two_hop")` (`:3744`),
      `"live_two_hop" => Some("two_hop")` (`:3747`), and
      `"live_two_hop_validation" => Some("two_hop")` (`:3770`). So
      `linux_stage_two_hop = pass` reports **"the mesh pinged"**
      (`traffic_test_matrix`) while the chained-exit proof was skipped or failed.
    - **The repo already knows this exact failure class and fixed only half of it.**
      `live_lab_run_matrix.rs:~426-433` documents the bash-era symptom —
      "`linux_stage_two_hop` showed 52 passes while the `--node` engine had never once
      passed two-hop" — and resolved it by splitting the *ledgers* per engine. The
      **stage aliasing was left in place**, which reintroduces the same false-green
      *within* the `--node` ledger.
    - **This is load-bearing beyond this disposition:** `CLAUDE.md` / `AGENTS.md`
      (~line 418) instruct every agent to use the run-matrix cell as their acceptance
      criterion, so any agent trusting `linux_stage_two_hop = pass` concludes two-hop
      works when it never has. The engine's `NO-VERDICT` guard
      (`vm_lab/mod.rs:6295-6296`) does **not** help here: it correctly handles the
      *absence* of results and does nothing when the cell affirmatively says `pass`.
    - *Analysis note:* the distribution above requires a **quote-aware** CSV parse.
      Every data row contains commas inside quoted fields, so `awk -F,` shifts the
      stage block and reads the wrong column — that mistake produced a spurious
      "no pass rows at all" reading during this investigation.
  - The verifying run must be at a **committed SHA from a clean tree**; the 2026-07-25
    run is diagnostic-grade only (`dirty:worktree`).
  - NOT a permanent exemption; NOT a flip blocker (G1 = engine-trust, satisfied).

### D2 — T5 negative controls `negative_control_planted_residue` + `negative_control_daemon_kill_mid_stage`: live proof COMPLETE (2026-07-24)
- **RESOLVED 2026-07-24 (D2 satisfied):** the two controls' `execute()` bodies now
  inject the live fault and adjudicate RED-for-the-right-reason (fable-reviewed build
  + adversarial code review; plan `LiveT5NegativeControlProofPlan_2026-07-24.md`).
  Proven live in run `state/live-lab-d2-negctl-1784908669`: both control rows `pass`
  in `stages.tsv`; residue → clean-assert `Err` naming `rustynet_planted`, then torn
  down and verified absent; daemon-kill → the daemon-socket probe failed `Connection
  refused (os error 111)` under the SIGKILL, daemon restarted `active`. A2 independent
  verifier: **VALID** (§4.1/4.2/4.5/4.6 all PASS), exit 2. All four T5 fault classes
  now prove RED-for-the-right-reason.
- **Prior status (history):** built as opt-in T5 stages (A3a, `1b9e2c0`) with unit-tested pure
  adjudication logic, but `execute()` returns `Skipped` pending a live-guest fault
  injection (the deferred half of A3-finish per the CompletionBrief). The other
  two T5 fault classes — `negative_control_signed_bundle_rejection` and
  `negative_control_wrong_node_substitution` — are fully built, unit-tested, and
  exercised in-pipeline (see the T5 verification run recorded alongside this flip).
- **Why it does not block the flip (G1):** two of the four T5 fault classes are
  proven end-to-end (adjudicate RED-for-the-right-reason); the engine's ability to
  correctly report a real red is additionally demonstrated live by
  `live_network_flap_validation` correctly-RED across all 5 stability runs, each
  A2-verified VALID (exit-2 valid-non-pass, not INVALID). This is a **T5-tier**
  item, not T4-security, so it is dispositionable.
- **Owner sign-off:** APPROVED 2026-07-24 (part of the "flip now" decision).
- **Expiry / re-review:** implement the live residue/daemon-kill injection and
  prove RED-for-the-right-reason on a real guest as a G2 follow-on.

### D3 — `live_network_flap_validation` (T2 resilience): correctly-adjudicated-RED
- Already the acceptance spec's standing treatment (§6 / review B6): the daemon
  fails closed ~120 s after setup because nothing re-issues the signed
  traversal-authority bundle — a **real production self-sustenance gap** tracked in
  `TraversalSelfSustenancePlan_2026-07-23.md`. Correctly-RED satisfies G1; GREEN is
  required for G2. Restated here for completeness; the fix is the traversal track.

## What is NOT dispositioned (green on the engine of record)

T0 core (bootstrap, membership, distribute-{membership,assignments,traversal,dns},
enforce/validate baseline, traffic, cleanup) and T1 roles (anchor, admin, relay,
exit + its NAT/handoff/dns-failclosed/demotion-residue, blind_exit dataplane where
applicable, key-custody, service-hardening, runtime-acls, authenticode, ipv6-leak,
security-audit, mesh-status, managed-dns) are all GREEN 5-of-5, A2-verified. The
`--node` engine is trusted (G1) on this basis.

## Mirror

Mirrored into `NodeEngineAcceptanceSpec_2026-07-23.md` §6.1 (deferred-with-reason
list) per rule (e). These dispositions gate the W5.6 flip only; G2 (release) still
requires D1/D2 resolved and D3 green.
