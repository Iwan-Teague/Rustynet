# Gossip secret provisioning — how to make the gossip data plane actually run

**Status:** **INVESTIGATION + DESIGN, NOT APPROVED, NOT IMPLEMENTED.** A 13-agent
read-only workflow investigated the problem, produced three designs from different
angles, judged them, and then attacked the winner from three lenses. **All three
lenses returned NEEDS_CHANGES, with five ship-blockers.** One of them would have
bricked every existing node. No code should be written against this document until
§4's blockers are resolved and §5's operator decisions are made.

**Provenance and trust level.** Everything below carries file:line citations from
the agents that produced it. Claims marked `[verified]` were then checked
personally against the code; the rest remain **agent-reported and should be
re-verified before being relied on** — this session repeatedly produced confident,
well-cited claims that were wrong, including three designs refuted after review and
one factual error that reached a pushed commit (§1.1).

**Verified personally so far:** §1.1 (the env var name), §4.2 (in substance),
§4.3 (as a *conditional* hazard, not a live one), §4.4 (fully), §4.5 (fully). The
remaining blocker, §4.1, rests on the shipped systemd unit carrying no gossip
config today — also verified: `scripts/systemd/rustynetd.service` passes
`--gossip-watermark` and nothing else gossip-related.

---

## 1. The problem

The gossip data plane is **dormant on every shipped and lab node**. `build_gossip_node`
returns `Ok(None)` unless both gossip config fields are set, and **nothing in the
repository sets them** — no systemd unit, no launchd plist, no bootstrap script, no
orchestrator stage. Consequence: the transport never binds, no bundle is ever
minted or accepted, and the status surface shipped in `001c23b1` reports a fixed
290 B of `unconfigured` constants everywhere.

This is why `GossipStatusSurfacePlan_2026-07-30.md`'s live-lab acceptance is
unmeetable: a live run today appends `gossip_state=unconfigured` and proves nothing.

### 1.1 The env var name is a trap `[verified]`

The Rust constant is **named** `GOSSIP_SIGNING_SECRET_PATH_ENV`, but its **value**
is `"RUSTYNET_GOSSIP_SIGNING_SECRET"` — **no `_PATH` suffix**. Its sibling is
`RUSTYNET_GOSSIP_SIGNING_SECRET_PASSPHRASE`.

I copied the identifier's shape into the status-surface plan and into a memory
file, publishing `RUSTYNET_GOSSIP_SIGNING_SECRET_PATH` — a variable the daemon
never reads. Anyone following that doc would set it, see no change, and conclude
gossip was broken rather than unset. Corrected everywhere; recorded here because
the failure is silent in exactly the way this whole thread keeps rediscovering.

### 1.2 What the loader actually does — the configured path is never opened

Agent-reported, high-confidence, and materially different from what "point the
daemon at a key file" suggests:

- The configured path is used only to derive (i) a custody **directory** = its
  parent, and (ii) a **key id** = `wg-private-` + first 8 bytes of SHA-256 of the
  path string, as hex.
- Bytes come from the OS store (`secret-tool` on Linux, Keychain on macOS) or, on
  Linux only, from `<parent>/wg-private-<16hex>.enc`.
- macOS and Windows use `RequireOsSecureStore`, so the encrypted-file fallback does
  not exist there.
- Encrypted-file format v1: `[version:1][salt:16][nonce:24][ct_len:4 BE][ct]`,
  Argon2id → XChaCha20-Poly1305, AAD `b"RNET" || version`.
- Permissions are **equality** checks, not masks: parent dir exactly `0700`, file
  exactly `0600`, both owned by the effective uid, neither a symlink.

**Two gaps worth carrying forward:**
1. A validly-encrypted but *semantically wrong* secret is never rejected — the only
   content check is emptiness, and HKDF absorbs arbitrary bytes into a valid key.
   So provisioning the wrong blob yields a working daemon with a wrong identity.
2. The configured **passphrase path is inert on unix**: `read_passphrase_file`
   resolves the passphrase from the WireGuard credential env var / Keychain
   instead. A design that "just sets the passphrase path" does nothing.

### 1.3 Other traps found

- `gossip_watermark_path` is **optional and independent**. `None` means gossip runs
  purely in memory and anti-replay state **does not survive restart**. The
  installers pass `--gossip-watermark` already, which is what makes the subsystem
  look provisioned when it is not.
- An **empty** CLI flag value sets the field to `None` — silently disabling gossip
  rather than erroring.
- The `#[cfg(not(unix))]` "unix-only" rejection is **order-shadowed on Windows** by
  the Windows path validator, so the existing platform-gate test's assertion
  (`error contains "unix-only"` for `/tmp/...` paths) cannot hold on Windows.
  That is a pre-existing defect in an existing test, not in this work.

## 1.4 NEW EVIDENCE (2026-08-04) — a working provisioning precedent exists

The design round below ranked **enrollment-first** first and **provisioning-parity**
second, partly on the grounds that parity "adds no new enforcement". That ranking
was made without the following fact, which materially weakens it.

**The systemd installer already provisions a daemon secret — just not this one.**
`crates/rustynet-cli/src/ops_install_systemd.rs` defines
`ENROLLMENT_SECRET_PATH = "/var/lib/rustynet/keys/enrollment.secret"` (`:38`),
generates it as exactly 32 raw bytes for admin nodes (`:830-843`), and the service
template already points `--enrollment-secret` at it (`:818`). A test pins that the
install path matches the daemon's default (`:2955-2961`).

In the same file, `grep -c GOSSIP_SIGNING_SECRET` returns **0**.

So the installer knows how to mint, permission and wire a daemon secret. It simply
never learned to do it for gossip. That makes provisioning-parity a
**fill-in-the-template** change rather than a novel design, and it is the argument
the original ranking lacked.

**Correction to the security ledger:** `AdversarialSecurityRemediation_2026-07-29.md`
lists **ENR-12** as "the daemon never provisions the enrollment secret,
contradicting the module doc". The installer evidence above says the enrollment
secret **is** provisioned. That row is stale or wrong and should be re-checked
before anyone acts on it.

### 1.5 Consequence — a phased split that removes two of the three blockers

The three operator decisions in §5 were all attached to the *enforcement* half of
enrollment-first. Splitting provisioning from enforcement defers two of them:

- **Phase 1 — provision only.** Mint and wire the gossip secret exactly as the
  enrollment secret is wired. No enforcement, no admission validation, no
  membership migration, no recovery verb. Gossip *runs*. This needs only §5.1
  (passphrase separation), and even that can default to parity-with-enrollment
  with the residual stated.
- **Phase 2 — enforcement, informed by Phase 1 data.** §5.2 asks whether existing
  membership entries get migrated. **That question is currently unanswerable
  because nobody can see the answer.** Once Phase 1 lands, the
  `gossip_identity_mismatch` field shipped in `001c23b1` reports, per node,
  whether membership publishes the node's real gossip verifying key — `true`,
  `false`, or `unknown`. The observability built for this subsystem becomes the
  instrument that decides its own enforcement policy.

§4's five ship-blockers were all raised against enrollment-first. §4.1 (the fleet
brick) and §4.4 (the decoy existence check) apply to **any** design and remain
mandatory. §4.2, §4.3 and §4.5 are specific to the enrollment/admission half and
fall out of Phase 1 scope entirely.

## 2. Direction chosen: enrollment-first

Of three designs — **enrollment-first**, **provisioning-parity**, **lab-first** —
the judge ranked enrollment-first first, on one argument that matters:

The failure this work exists to eliminate is *an operator putting the wrong blob in
`node_pubkey_hex`*, which makes every peer reject that node's mints. Only
enrollment-first attacks that at the point a real node's key enters membership,
rather than leaving the invariant to operator discipline.

**But §4.2 shows the central premise of that ranking is false**, so the direction
is provisional.

## 3. Mandatory grafts from the losing designs

The judge required these regardless of which design proceeds:

1. **From provisioning-parity — do NOT put an inline default or an `ExecStartPre`
   file test in the shipped systemd unit.** Use conditional pair-emit instead. This
   is the fleet-brick fix (§4.1).
2. **From provisioning-parity** — add key-custody verifier entries
   (`linux_key_custody.rs`, `macos_key_custody.rs`). The winner had **no
   verification method at all** for its new custody object, which CLAUDE.md §4
   forbids.
3. **From provisioning-parity** — explicit `set_owner_mode_if_exists(...0o600)` for
   the gossip secret beside the WireGuard block in `ops_install_systemd.rs`.
4. **From lab-first** — land mint + publish + read-back **with enforcement OFF**
   first, and prove it on two guests via a per-node systemd drop-in, not the shipped
   unit.
5. **From lab-first** — its evidence stage: sample `rustynet status` twice at least
   35 s apart (`GOSSIP_REMINT_INTERVAL_SECS = 30`) and require `gossip_minted_total`
   to increase. This is the only concrete acceptance artifact any design produced.
6. **From lab-first — a validator warning that applies to the surface I already
   shipped:** `gossip_identity_mismatch` is **three-valued**. Any validator written
   as `!= "true"` reads `unknown` — absence of evidence — as a pass. Pin the
   expected value explicitly.
7. **Against the winner** — drop its proposed cached `gossip_identity_verified: bool`.
   `gossip_identity_mismatch_state` already computes this live, and deliberately
   does not read the sticky latch.

## 4. Ship-blockers — all five must be resolved before code

### 4.1 Fleet brick

The winner adds `Environment=RUSTYNET_GOSSIP_SIGNING_SECRET=...` plus
`ExecStartPre=/usr/bin/test -f ${...}` to the **shipped** unit. Every existing node
has no gossip key, so every existing node would fail to start. Graft 3.1 replaces
it. **This is the single most valuable output of the whole exercise.**

### 4.2 "admit is the only place a key enters membership" is false `[verified]`

Other production writers of `node_pubkey_hex` are ungated. Verified two directly —
`parser.required("--node-pubkey")` flows straight into a membership operation at
`rustynet-cli/src/main.rs:5881-5892` and again at `:6056-6071`, both distinct from
the admit path at `:8399`. The agent reported four; two is already enough to void
the claim. The
legacy operator-typed `--pubkey` path also survives, and the proof-of-possession
flow is **opt-in** (`--request-file` is mutually exclusive with `--pubkey`). So the
correctness-by-construction claim the ranking rests on does not hold.

### 4.3 The enrollee would author its own capabilities `[verified as conditional]`

**This is a hazard the proposed design would create, not a live defect** — a
distinction worth keeping, because the two call for different urgency. Verified:
capabilities are derived directly from roles
(`capabilities: enrollee_capabilities_from_roles(&ctx.roles)?`,
`rustynet-control/src/enrollment.rs:178`), but today `ctx.roles` comes from the
**operator's** `--roles` (`config.roles`, `rustynet-cli/src/main.rs:8401`), and the
function's own doc calls them "the operator's `--roles` tokens" (`:209`). Under the
proposed `--request-file`, roles would instead come from a file the **enrollee**
wrote and signed with its own key, and roles are the capability grant. This would let a joining node
choose its own privileges. Any PoP design must take identity from the request and
**capabilities from the admitting operator**.

### 4.4 Existence checks test a decoy `[verified]`

Every "is it provisioned" check in the design tests the **configured path**, which
the loader never opens. Verified directly: `decrypt_private_key`
(`key_material.rs:521-542`) uses that path only to build a custody manager from its
**parent** and a key id `wg-private-<sha256(path_string)[0..8] hex>`
(`key_custody_key_id`, `:779-788`), then calls `manager.load_private_key(&key_id)`.
The path is a **naming input, not a file that is read**. The gate can read true while the object the daemon
actually needs is absent — and because the daemon aborts startup on a custody
failure, that is a **whole-node outage, not a gossip outage**.

### 4.5 Linux production never gets a secret `[verified]`

The proposed Linux mint sits inside `ops e2e-bootstrap-host`, behind the
**default-off `vm-lab` feature** — verified: `#[cfg(feature = "vm-lab")]` sits
directly above the `"e2e-bootstrap-host"` parse arm
(`crates/rustynet-cli/src/main.rs:5645-5646`), so the verb does not exist in a
default build. So production Linux nodes would receive a unit
demanding a file that nothing mints. Combined with §4.1 this is the fleet brick
twice over. Relatedly, the Linux path passes `--force`, which is reportedly
*mandatory for decryptability* there yet **silently rotates the identity** of an
already-admitted node.

## 5. Operator decisions required

These are not engineering calls and should not be made by an agent:

1. **Passphrase separation.** `build_gossip_node`'s own doc justifies deriving a
   gossip sub-key so that a compromised daemon cannot recover the node's identity
   secret — yet every design ends with the gossip secret under the **same
   passphrase** as the WireGuard identity, which defeats that rationale. Accept, or
   fund a second passphrase and its custody?
2. **Existing membership entries.** Every current snapshot publishes a
   **non-gossip** value in `node_pubkey_hex` (the lab fills the WireGuard key;
   genesis fills raw seed bytes). Enforcing agreement would mark every existing
   node `identity_unverified` with **no self-heal path** — `ops init-membership`
   early-returns when the files exist. Migrate, or enforce only for new nodes?
3. **Recovery ergonomics.** The proposed `key show-gossip-pubkey` verb reportedly
   cannot run on a deployed Linux node, because the plaintext passphrase it needs no
   longer exists on the host. If operators need a recovery verb, it needs a
   different mechanism.

## 6. Unresolved / not verifiable read-only

- systemd `EnvironmentFile` vs `Environment` precedence — nothing in the repo
  asserts which wins. Must be settled empirically before relying on either.
- Whether the mint/read-back/derive round-trip test can run green in CI: the
  sibling tests are `#[cfg(not(target_os = "macos"))]` and depend on a credential
  path.
- macOS bootstrap passes `--force` to `key init` so a partial install can be
  re-run; copying that to the gossip mint would rotate identity on every re-run.

## 7. Recommended next step

**Do not implement.** Resolve §5.1 and §5.2 with the operator first — both change
the shape of the work — then re-run the design round with §4's blockers as
constraints rather than discoveries. The cheapest useful increment that is *not*
blocked is graft 3.4: mint + read-back with enforcement off, proven on two lab
guests via a drop-in, which produces the evidence everything else is currently
asserting without.
