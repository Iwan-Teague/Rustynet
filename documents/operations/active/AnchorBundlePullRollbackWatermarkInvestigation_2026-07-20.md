# Investigation: Anchor Bundle-Pull Stale-Cache Rollback (§6 of AnchorBundlePullAttestationSecurityReview_2026-07-20.md)

**Status: IMPLEMENTED (2026-07-20, commit `e0cc8e5`, merged to `main`).** The recommended
Candidate A design below (§4) was accepted and built essentially as specified: `MembershipWatermark`
and its load/persist/replay-check functions moved from `rustynetd::daemon` into
`rustynet_control::membership`, and `anchor pull-bundle` now consults and advances the same
on-disk watermark file the daemon's own bootstrap/apply paths already maintain. Three tests
(`pull_bundle_accepts_first_ever_pull_with_no_watermark_and_establishes_one`,
`pull_bundle_rejects_epoch_regression_on_brand_new_device_after_first_watermark_established`,
`pull_bundle_watermark_survives_output_deletion_but_not_watermark_deletion`) in
`crates/rustynet-cli/src/main.rs` prove the TOFU case, the exact vulnerability's closure, and the
honest residual limit from §5 respectively. Full gate suite (fmt, workspace clippy, full workspace
test, audit, deny) passed before merge. `SecurityMinimumBar.md` control 2 updated accordingly. The
rest of this document is kept as-written — the investigation and design reasoning that led to the
fix, useful for anyone auditing the decision later — rather than rewritten in past tense.

All line numbers below are from the `security/a4-membership-head-attestation` implementation
(now merged to `main`, commit `1a786dc`) and were read directly against the code, not taken
on faith from the review document that first surfaced this gap.

## 1) Confirming exploitability precisely

The description in [AnchorBundlePullAttestationSecurityReview_2026-07-20.md](./AnchorBundlePullAttestationSecurityReview_2026-07-20.md)
§6 is accurate. This investigation traced every function it names, plus one more that turns
out to matter as much as any of them: `MembershipCommand::Attest` (the `membership attest`
re-mint verb).

**The three functions that matter, and what they do and don't check:**

- `head_attestation_canonical_payload(network_id, epoch, state_root_hex, attested_at_unix)`
  (`crates/rustynet-control/src/membership.rs:824-837`) is a pure formatter. It takes `epoch`
  and `attested_at_unix` as independent, caller-supplied `u64` values with **no relationship
  enforced between them**.
- `sign_head_attestation(...)` (`membership.rs:843-872`) signs whatever
  `head_attestation_canonical_payload` produces. It validates `approver_id` non-empty,
  `network_id` well-formed, and `state_root_hex` is a valid 32-byte hex digest — nothing that
  binds `attested_at_unix` to the real historical moment `epoch` was current.
- `verify_attested_snapshot(bytes, pinned_owner_pubkey_hex, now_unix, prior_identity,
  max_age_secs)` (`membership.rs:1214-1382`) is the sole enforcement point, and its 9 checks
  are exactly as documented: structural parse/digest (1), attestation presence (2),
  attestation-identity-matches-offered-state (3), every signature verifies against the
  *offered state's own* approver set (4), pin-is-Owner-and-actually-signed with rotation
  grace (5), quorum among the *offered state's* active approvers (6), freshness of
  `attested_at_unix` vs `now_unix` (7), not future-dated (8), and **only if
  `prior_identity: Option<&(u64,String)>` is `Some`**, epoch-non-regression / same-epoch-fork
  detection (9, `membership.rs:1364-1379`). Every one of checks 3-8 is evaluated entirely
  *within the offered snapshot's own self-consistent world* — an old, internally-valid roster
  passes all of them on its own terms. Check 9 is the only one that reaches outside that
  world, and it is the only one gated on an optional parameter.

**The `prior_identity` derivation is exactly as described, confirmed at
`crates/rustynet-cli/src/main.rs:7572-7584`:**

```rust
let local_verified_identity: Option<(u64, String)> =
    std::fs::read(&output_path).ok().and_then(|bytes| {
        let state = verify_attested_snapshot(
            &bytes, &pinned_owner_pubkey_hex, now_unix, None, max_attestation_age_secs,
        ).ok()?;
        ...
    });
```

`None` is passed as `prior_identity` even for this *local* re-verification — there is no
persistent state anywhere in this function; `local_verified_identity` is entirely a function
of what currently sits at `--output` plus the clock. This value then becomes `prior_identity`
for the real verification of the pulled bundle at `main.rs:7652-7661`. Any of three triggers
collapses it to `None` via `.ok()`: no file at `output_path`, an existing file whose
attestation is stale by check 7 (`AttestationStale`), or the file being absent because it was
deleted. All three produce byte-identical downstream behavior: `verify_attested_snapshot` runs
with `prior_identity = None`, and check 9 never executes.

**The temporal-binding gap, sharpened.** The one place in the whole system that *does* bind a
timestamp to real historical contemporaneity is `apply_signed_update`
(`membership.rs:924-929`): `now_unix > record.expires_at_unix` and
`record.created_at_unix > now_unix + skew`, checked at the moment an update is originally
applied. When an update is applied normally (`sign-update`/`apply-update`, enrollment `admit`,
`membership init` genesis, daemon `add-peer`), `head_attestation_from_signed_update`
(`membership.rs:880-908`) sets `attested_at_unix: record.created_at_unix` — so under normal
operation the attestation timestamp really is contemporaneous with the epoch, because it
inherited that binding from the original apply-time check.

**`membership attest` breaks that inheritance entirely.** This verb (`main.rs:7980-8044`,
parsed at `main.rs:5936-5947`) is a standalone re-mint: it loads *whatever local snapshot+log
the caller points `--paths` at* (`load_current_membership_state`), and calls
`sign_head_attestation` with `attested_at = attested_at_unix.unwrap_or(now_unix)` — a
**freshly-defaulted "now" timestamp**, completely decoupled from `apply_signed_update`'s
expiry/future-date machinery. It performs no check that the loaded state's epoch is the
mesh's current epoch, and no check that the signing key is *currently* an active approver
anywhere except inside `verify_attested_snapshot` at verification time (which, as shown,
evaluates against the *offered* state's own roster).

**Concrete attack scenario, using real command/function names:**

1. At real epoch 3, `owner-1` (key `K_old`) is a legitimate `Active`/`Owner` approver. Any
   node that pulled or was provisioned with that state — including `owner-1` itself — has a
   faithful, unmodified local copy of the epoch-3 snapshot+log.
2. Later, at real epoch 5, the mesh owner rotates `owner-1` out (`K_old` → `Revoked`), for
   cause. Revocation is a roster-status flag; it does not invalidate `K_old` as an ed25519
   key.
3. The holder of `K_old` runs, entirely on their own machine, against their own retained
   epoch-3 files: `rustynet membership attest --snapshot <old-epoch3-snapshot> --log
   <old-epoch3-log> --approver-id owner-1 --signing-key <K_old-priv> ...`. This produces a
   snapshot file that is **fully self-consistent**: `attestation.epoch=3`,
   `attestation.state_root_hex` = the real epoch-3 root, `attestation.attested_at_unix` =
   right now, signed by `K_old`, over a roster where `K_old` genuinely is `Active`/`Owner`.
   No forgery of any hash, signature, or roster entry is required — every byte is a faithful
   replay of real, once-valid history.
4. This blob is served to a victim device's `anchor pull-bundle` request.
5. On the victim device, `prior_identity` is `None` — either because this is its first-ever
   pull (the primary use case), or because its cached `--output` attestation aged past
   `max_attestation_age_secs` (default 604800s). The victim's out-of-band §6.B pin is
   `K_old` — entirely plausible, since pins are sticky, manually delivered, and never
   auto-refresh on rotation.
6. `verify_attested_snapshot` runs all 9 checks. Checks 3-8 pass on their own terms. Check
   5's pin logic finds `pinned_active_owner = true` **directly** — `K_old` is Active Owner
   *in the offered epoch-3 roster* — so the rotation-grace branch never even triggers (no
   rotation-grace codepath is needed for this attack). Check 9 is skipped. Result: `Ok(state)`,
   and the bytes are written to disk.
7. The victim device now trusts an epoch-3 view of the mesh: any node/approver revoked
   between epoch 3 and the real present (including `K_old` itself) reads as still-active on
   this device; anything added after epoch 3 is invisible to it.

## 2) What "fixed" requires — first-ever vs. stale-vs-reset

**These two cases are structurally identical from the code's point of view, and that identity
is itself the important fact.** Whether `prior_identity` collapsed to `None` because no file
ever existed, because the file exists but its attestation aged out, or because the file was
deleted, `verify_attested_snapshot` cannot — and, sourcing only `--output`-derived state,
never could — distinguish them. Any fix that continues to derive its floor from `--output`
inherits the same conflation. The fix must stop deriving the anti-rollback floor from
`--output` at all, and instead track it in **separate, persistent state whose only write
condition is "verification just succeeded"** — never touched by attestation staleness, and
not collocated with the artifact an operator might reasonably delete to "reset the cache."

With that separation, the two cases *do* need different — and already well-precedented —
treatment:

- **Genuinely first-ever pull (the watermark file has never existed):** there is nothing to
  regress *against*. This is TOFU (trust-on-first-use), the same trust model
  `SecurityMinimumBar.md` §6.B already codifies for the owner-key pin itself. The correct
  behavior is to accept based on checks 1-8 alone (as today) and then **immediately persist
  the newly-established floor** so every subsequent invocation is protected. This is not a
  new idea in this codebase — see §3, it's exactly what `rustynetd`'s own bootstrap path
  already does.
- **A watermark existed and is now stale/missing:** if "stale/missing" means the
  *attestation* aged out but the watermark file survives, nothing changes — freshness and
  rollback-floor are orthogonal and the floor should be consulted regardless of attestation
  age. If "missing" means the *watermark file itself* is gone, the honest answer is: **code
  cannot tell the difference between "operator did a deliberate, audited factory reset" and
  "attacker with local write access deleted the file to force a TOFU re-bootstrap."** This is
  a real limit (§5), not something a cleverer file format fixes.

## 3) Prior art

**External, general-knowledge (not verified against this repo — standard descriptions of
these systems):**

- **TUF (The Update Framework)** solves precisely this failure class with two *orthogonal*
  mechanisms, and the fact that they're orthogonal is the load-bearing lesson here: (1) every
  role's metadata carries a monotonic **version number**, and a compliant client is required
  to **persist the highest version number it has ever trusted** and refuse anything lower —
  TUF's explicit "rollback attack" mitigation; (2) a separate, short-TTL **timestamp role**
  provides freshness — the "freeze attack" mitigation. Rustynet's `verify_attested_snapshot`
  has built (2) (`attested_at_unix` + `max_age_secs`) but never built the persistent-version-
  watermark half of (1) for the bundle-pull path — which is exactly why a *freshly re-signed*
  old epoch defeats it: freshness alone was never designed to catch this, in TUF's own model
  either.
- TUF is also explicit that its threat model does **not** protect a client's very first
  update if the attacker controls the repository before that first contact — the textbook,
  acknowledged limit of any TOFU-rooted trust model, not a defect specific to this design.
- **Certificate Transparency (RFC 6962) / SUNDR fork-consistency / CONIKS gossip** solve a
  different, and strictly harder, problem: **equivocation across multiple honest
  observers**, not just a single device's own monotonicity. A local watermark can only ever
  protect a device against *regressing relative to what that device itself has already
  seen*; it structurally cannot help a device's first-ever observation, no matter how it's
  implemented. Gossip/witness protocols address that only by requiring corroboration from
  other parties.

**Verified against this repo's code — the most important finding of this investigation:**

The codebase already contains, and has already shipped and tested, a mechanism that is
structurally exactly the fix this gap needs — for a sibling problem, not this one.
`rustynetd`'s own membership-bootstrap path maintains a persistent, monotonic watermark:

- `MembershipWatermark { epoch, state_root }` (`crates/rustynetd/src/daemon.rs:2559`),
  persisted at `DEFAULT_MEMBERSHIP_WATERMARK_PATH` = `/var/lib/rustynet/membership.watermark`
  (Linux; Windows equivalent via `DEFAULT_WINDOWS_MEMBERSHIP_WATERMARK_PATH`,
  `daemon.rs:199-201`).
- `membership_watermark_is_replay(incoming, previous)` (`daemon.rs:12444-12450`): "strictly
  older epoch → replay; same epoch, different root → replay (fork); same epoch same root →
  idempotent OK; strictly newer → OK" — the *exact same rule* `verify_attested_snapshot`'s
  check 9 implements inline, duplicated rather than shared.
- `load_membership_watermark`/`persist_membership_watermark` (`daemon.rs:12452-12527`):
  plain-text `version=1\nepoch=..\nstate_root=..\n`, atomic temp+fsync+rename write, `0700`
  parent-directory permissions.
- Consulted at **daemon startup** in `load_verified_membership` (`daemon.rs:4165-4225`):
  `previous = load_membership_watermark(...)`; if `None` (no prior file — first boot), the
  check is skipped and the fresh watermark is persisted (exactly the TOFU-then-remember
  pattern §2 argues for); if `Some`, `membership_watermark_is_replay` gates acceptance.
- Also **bumped on every daemon-applied membership update** in `handle_membership_apply`
  (`daemon.rs:8106-8197`, watermark persist at `8191-8197`) — so this file already tracks the
  daemon's high-water mark across *both* bootstrap loads and live gossip-driven applies.

This is not a hypothetical parallel — it is the identical property (`epoch`/`state_root`
monotonicity, anti-fork, anti-rollback, TOFU-on-absence) already implemented, already
unit-tested (`membership_watermark_replay_detector_pins_full_ordering_matrix`,
`daemon.rs:20054-20130`), and already shipped in production code, just scoped to
`rustynetd`'s own snapshot bootstrap and never wired into `rustynet-cli`'s
`anchor pull-bundle`, which instead re-derives its floor from `--output` every time (§1).

**`FableForkConsistentMembershipTransparency_2026-07-01.md` — assessed.** This is a
superset-ambition, unimplemented (status: "SPECULATIVE R&D — UNSCHEDULED"), multi-phase
proposal targeting **cross-node equivocation** (§0, §1.1 of that doc: two internally-valid
forks routed to disjoint honest node sets, which no local check — including a local
watermark — can ever detect on its own). Its Layer 1 (Merkle history tree, §2.1) and Layer 2
(Signed Tree Head + gossip fork detection, §2.2) would, as a byproduct, *also* close the
stale-cache-rollback gap investigated here, and arguably more completely — but only once
gossip transport is wired, which the document's own build path (§6) sequences as Phase 3
(large effort, explicitly requires a report-only bake before enforcement) after Phase 1-2. It
does **not** close the pure first-contact case either — the document's own §9.4 states
plainly it "does not defend against a fully compromised admin quorum... nothing short of a
fundamentally different trust model does," and a device's first-ever contact with zero
witnesses has the same irreducible exposure under Fable's design as under a plain watermark.

**Assessment: related but should be a separate, sequenced track, not a blocker on this fix.**
The stale-cache-rollback gap is small, local, and immediately closeable using a mechanism
this repo already has and has already proven in production. FableFork is a large,
unscheduled, multi-phase R&D program solving a broader problem this specific finding is not
about. The one thing worth doing *now*, for future compatibility rather than as a dependency:
shape the watermark record so it is a natural degenerate case of "last-verified STH" (`epoch`
~ `tree_size`, `state_root` ~ `root_hash`) — which `MembershipWatermark`'s existing two-field
shape already is — so that if/when Phase 1-2 of FableFork ships, the persisted watermark can
be superseded by (or grow into) an STH-based check without a storage-format migration.

## 4) Candidate approaches for this codebase

### Candidate A (recommended) — extract and reuse `MembershipWatermark`, decoupled from `--output`

Move `MembershipWatermark`, `membership_watermark_is_replay`, `load_membership_watermark`,
`persist_membership_watermark` out of `rustynetd/src/daemon.rs` into `rustynet-control` (the
domain/trust-state crate per `CLAUDE.md` §11.2; not a boundary violation —
`membership.rs` already does equivalent file I/O for snapshots/logs). Wire
`AnchorCommand::PullBundle` to consult and advance this shared watermark, ideally reusing the
**same file** the daemon already writes, not a new one:

- On every pull, before verification: `prior_identity = load_membership_watermark(watermark_path)`
  — independent of `--output`'s existence, staleness, or content.
- On successful `verify_attested_snapshot`: persist the new `(epoch, state_root)` to the
  watermark unconditionally.
- Fresh install: watermark absent → `prior_identity = None` → check 9 skipped exactly once
  (the irreducible TOFU moment, §5), then immediately remembered.
- Reset device: only a wipe of the watermark's own storage location resets trust — not a
  wipe/reset of `--output` alone. This is the concrete difference from today and from
  Candidate B.
- Sharing the exact file the daemon already maintains is a genuine win, not just
  convenience: it means the floor tracks *every* way this device's membership view can
  validly advance — anchor pulls **and** ordinary gossip-driven daemon applies (which already
  bump it) — so a pull-bundle run after the daemon has advanced via gossip correctly refuses
  to accept anything below what gossip already established, and vice versa.
- Trade-off to flag explicitly: `rustynet-cli` and `rustynetd` must have consistent
  read/write access to this path (today `0700`-permissioned, presumably root/service-account
  owned) — an explicit operational assumption, since `anchor pull-bundle` may run as part of
  pre-daemon provisioning.
- FIS-0020 `have`/`UNCHANGED` interaction: keep `have_identity` (the `have <epoch> <root>`
  hint) derived from `--output` as today — that's genuinely "do I have usable bytes on disk"
  — but source `prior_identity` (the check-9 floor) from the watermark independently. These
  are different questions; conflating them is part of today's bug.
- Multi-anchor: the watermark is anchor-agnostic by construction (keyed on the device's own
  trust state, not on which anchor served it) — correct, since anchors are trust-inert per
  `SecurityMinimumBar.md` §6.C.
- Local-filesystem-integrity assumption: yes, this design assumes an attacker who can write
  to the watermark's directory can defeat it (delete it → TOFU reset). **That assumption is
  not new** — it is the exact assumption the daemon's own `membership.watermark`,
  `rustynetd.trust.watermark`, and `rustynetd.assignment.watermark` already make today, all
  stored the same way (plaintext, directory-permission-only, no per-file signing). This
  design extends the existing bar to a path that currently has none at all.

### Candidate B — co-located sibling file next to `--output` (e.g. `<output>.watermark`)

Simpler to wire (no new system path, no daemon-crate dependency), and closes the
first-invocation and aged-cache triggers just as well as Candidate A. But it does **not**
close the third trigger — an attacker or confused operator who deletes/resets `--output`'s
directory most plausibly deletes the sibling watermark in the same action, reproducing
precisely the vulnerability being fixed for exactly the trigger the review calls out.

### Candidate C — OS-secure-custody storage (Keychain/DPAPI), mirroring §6.C's enrollment-secret pattern

Considered and not recommended. The threat this watermark defends against is **integrity**
(can the floor be tampered with or erased), not **confidentiality** — `epoch` and
`state_root_hex` are public values already visible in every snapshot. Keychain-class storage
is the codebase's established tool for confidentiality-sensitive material; reaching for it
here would be inconsistent with every other watermark in the codebase (all plain-file +
directory-permission) for a value that isn't secret, and doesn't address the actual gap in
this design space, which is *location and persistence*, not *encryption*.

## 5) Recommendation and honest residual risk

**Recommend Candidate A**: extract the daemon's existing `MembershipWatermark` machinery into
`rustynet-control`, and have `AnchorCommand::PullBundle` consult and advance it as
`prior_identity`, independent of `--output`.

**This does not make the control airtight, and it would be dishonest to present it that
way.** The residual risk is structural, not an implementation shortfall:

1. **The first-ever pull is, and will always be, irreducibly TOFU.** A device with genuinely
   zero prior state has nothing to check a newly-offered epoch against. Any attacker
   positioned to answer that very first `anchor pull-bundle` request has the same window this
   gap describes today, indefinitely. No local-watermark design of any shape closes this;
   only cross-device corroboration (FableFork's gossip/witness layers) or a stronger
   out-of-band pin (e.g. pinning an expected minimum epoch or roster thumbprint alongside the
   §6.B owner key, at delivery time) can narrow it, and both are separate, heavier tracks.
2. **A device offline/uninstalled for long enough, or whose watermark storage is wiped
   (attacker or operator) before its next pull, degrades back to case 1.** Intentional and
   correct for a genuine factory reset; exploitable if an attacker can force it. Candidate A
   raises the bar for forcing it to "write access to the same protected system path the
   daemon's own trust state already lives in," not "delete one file the user already knows
   how to delete" — a real improvement, not a fictional one.
3. **A compromised-key holder who is never detected/revoked is out of scope for this fix
   entirely** — this closes stale-epoch resurrection *after* a legitimate revocation is on
   record; it does nothing for a still-undetected key compromise, same as every mechanism
   discussed here including FableFork's own explicit self-assessment.

State this plainly wherever this gets tracked per `SecurityMinimumBar.md` §2's High-control
risk-acceptance requirement: the fix converts "any new or cache-aged device is unconditionally
exposed" into "a device is exposed only on its genuine first contact, or if an attacker can
defeat the same local-filesystem-integrity assumption every other trust watermark in this
codebase already relies on" — a materially smaller, already-precedented, and explicitly
bounded residual, not zero.

## 6) Concrete integration points

**Files/functions to change:**

- `crates/rustynetd/src/daemon.rs`: extract `MembershipWatermark` (2559),
  `membership_watermark_is_replay` (12444-12450), `load_membership_watermark`
  (12452-12485), `persist_membership_watermark` (12487-…), and the
  `DEFAULT_MEMBERSHIP_WATERMARK_PATH`/`DEFAULT_WINDOWS_MEMBERSHIP_WATERMARK_PATH` constants
  (199-201) — move to `crates/rustynet-control/src/membership.rs` (or a new
  `rustynet-control::membership_watermark` submodule), re-exported for `rustynetd` to keep
  using unchanged at its two call sites (`daemon.rs:4197-4205`, `daemon.rs:8195-8197`).
- `crates/rustynet-cli/src/main.rs`: `AnchorCommand::PullBundle` struct (433-445) gains a
  `watermark_path: PathBuf` field (default `DEFAULT_MEMBERSHIP_WATERMARK_PATH`, override flag
  mirroring `--owner-key-pub`'s pattern at 6154-6156); the `execute_anchor` handler
  (7540-7670) replaces the `local_verified_identity` derivation (7572-7584) — currently
  reused for both `have_identity` and the check-9 floor — with two independent reads:
  `have_identity` keeps deriving from `--output` unchanged, and a new
  `rollback_floor = load_membership_watermark(&watermark_path)` feeds `prior_identity` at the
  `verify_attested_snapshot` call (7652-7661). On success, persist the new
  `(epoch, state_root)` to `watermark_path` immediately after the write at 7662.
- No change needed to `verify_attested_snapshot` itself (`membership.rs:1214-1382`) — its
  `prior_identity` parameter and check 9 are already exactly the right shape; only the
  caller's derivation of that parameter changes.

**Storage format:** reuse the existing plaintext `version=1\nepoch=<u64>\nstate_root=<hex>\n`,
atomic temp+fsync+rename, parent directory `0700` — identical to
`persist_membership_watermark`'s current implementation, just relocated. No new format to
design or review.

**Test plan** (one enforcement point → the `prior_identity`-derivation change at `main.rs`
around 7572-7661 — plus one verification test per fail-closed case, matching the existing
`pull_bundle_*` naming convention at `main.rs:23425-23557` and the
`verify_attested_snapshot_rejects_*` convention at `membership.rs:4573-4644`):

- `pull_bundle_rejects_epoch_regression_on_brand_new_device_after_first_watermark_established`
  — pull epoch 5 successfully (establishes watermark), delete `--output` (simulate "new
  device"/cache reset), attempt to pull a validly-attested-but-old epoch-3 bundle from a
  different served response; must fail with `EpochRegression`, matching the exact scenario
  in §1.
- `pull_bundle_rejects_epoch_regression_when_local_output_attestation_is_stale` — establish
  watermark at epoch 5, age the `--output` file's attestation past
  `max_attestation_age_secs` without touching the watermark, attempt an old-epoch pull; must
  still fail (proves the fix is decoupled from `--output` freshness, the exact bug being
  closed).
- `pull_bundle_accepts_first_ever_pull_with_no_watermark_and_establishes_one` — no
  `--output`, no watermark file; a validly-attested current-epoch bundle is accepted (TOFU
  case, §2); assert the watermark file now exists with the correct `(epoch, state_root)`.
- `pull_bundle_watermark_survives_output_deletion_but_not_watermark_deletion` — establish
  watermark + `--output`; delete only `--output`; old-epoch pull still rejected. Then
  additionally delete the watermark file; old-epoch pull is now accepted (documents, rather
  than hides, the residual TOFU-on-full-reset limit from §5 — a negative test that pins the
  *known* boundary rather than pretending it doesn't exist).
- `pull_bundle_watermark_rejects_same_epoch_different_root_as_fork` — mirrors
  `verify_attested_snapshot_rejects_epoch_regression_against_prior_identity`'s
  `ForkDetected` half but through the watermark-sourced `prior_identity`, not a
  directly-constructed one.
- Extend `scripts/ci/membership_gates.sh` (currently scoped to `-p rustynet-control` +
  `-p rustynet-policy`) to also run `cargo test -p rustynet-cli pull_bundle` so the CLI-side
  watermark tests are part of the same gate.

### Critical files for implementation

- `crates/rustynet-control/src/membership.rs` (`verify_attested_snapshot`,
  `sign_head_attestation`, `head_attestation_canonical_payload`; destination for the
  extracted `MembershipWatermark` primitive)
- `crates/rustynet-cli/src/main.rs` (`AnchorCommand::PullBundle` struct and handler;
  `MembershipCommand::Attest`, the concrete re-mint path used in the attack scenario)
- `crates/rustynetd/src/daemon.rs` (source location of `MembershipWatermark`/
  `load_membership_watermark`/`persist_membership_watermark`/
  `membership_watermark_is_replay` to extract; `load_verified_membership` and
  `handle_membership_apply` as the reference pattern)
- `documents/SecurityMinimumBar.md` (§6.B trust-anchor pin, §2 High-control
  risk-acceptance requirement this finding is tracked against)
- `documents/operations/active/FableForkConsistentMembershipTransparency_2026-07-01.md`
  (adjacent, superset-ambition proposal — assessed as a separate, sequenced track, not a
  dependency)
