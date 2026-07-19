# Efficiency & Advanced-Technique Opportunity Catalog — 2026-07-19

> **STATUS: RESEARCH CATALOG — UNSCHEDULED, NOT A PLAN.** Every finding below is "here is a real,
> code-grounded inefficiency and here are several established technique families that could address
> it" — never "the fix is X." This document does not select a solution, does not commit to an
> implementation, and does not modify the live-lab acceptance matrix or any active execution ledger.
> It is a research handoff: **the next agent's job is to design the actual fix**, choosing among the
> candidate approaches (or a different one it comes up with) by reasoning about tradeoffs itself, not
> by following a recommendation made here. See "How to use this document" below before acting on
> anything in it.

## 0) Provenance and verification method

Produced by an 11-area, 24-agent grounded-research workflow (Claude Sonnet 5, 2026-07-19): 2 survey
agents first read `PlatformImprovementBacklog_2026-05-14.md` and `FullRepoAnalysis_2026-05-24.md` in
full to build a dedup list; then 11 "hunt" agents each independently read real code in one subsystem
(no two agents shared a subsystem) and produced findings with file:line citations, multiple candidate
technique families per finding, and explicit constraint notes; then 11 independent "verify" agents
adversarially re-read the actual cited files, re-derived the claims from scratch, and either
**CONFIRMED**, flagged **NEEDS_REVISION** (real error, corrected below), or would have **REJECTED**
(none were — every finding survived, though two needed factual correction). Total: 905 tool calls,
~3.4M tokens of subagent work. This document folds every verify-stage correction directly into the
finding text below rather than presenting the original (partly wrong) claim — where a correction was
material, it is called out explicitly.

Two findings were materially corrected by their verify pass:
- **ENR-2** originally claimed no automated bundle-distribution client exists anywhere in the repo.
  This was **false** — `rustynet anchor pull-bundle` / `AnchorCommand::PullBundle`
  (`crates/rustynet-cli/src/main.rs:7482-7569`) is a complete, tested, wired client. The finding below
  reflects the corrected picture: the client exists and works, but performs **no signature
  re-verification** after fetching the bundle — it trusts the anchor's disk state.
- **RLY-2** originally claimed no repository document states relay-side privacy as a goal, based on a
  grep that missed a hit. This was **false** — `CrossNetworkRemoteExitNodePlan_2026-03-16.md` §5.3.1,
  titled *"Architectural Principle: Zero-Knowledge Relay,"* already states this as a design goal for a
  **different, unimplemented** transport design. The finding below reflects this and asks the next
  agent to reconcile the two designs rather than treating RLY-2 as green-field.

No finding in this document proposes custom cryptography, a hand-rolled protocol, or a WireGuard-type
leak into a transport-agnostic domain crate. Every crypto-adjacent candidate technique family names its
own audit-status caveat explicitly rather than asserting safety it can't back up — several are flagged
as **blocked today** under CLAUDE.md §3's audited-crate-only rule and are recorded for the record, not
as green-lit options.

## 1) How to use this document

This catalog exists so a later agent does not have to rediscover these problems from scratch — the
research (reading the code, tracing the call graphs, checking what's already been tried elsewhere in
the repo, checking what the requirements docs actually say) is done and verified. What is **not** done,
deliberately:

- **No finding here has a chosen fix.** Each one lists multiple genuinely different candidate technique
  families, each with its own real tradeoff, several with an explicit "here is why this might be the
  wrong call" caveat. Pick one, combine ideas, or propose a fifth approach nobody here thought of — the
  point is that the choice requires judgment about the project as a whole, not that it requires more
  research.
- **Work at the level of rigor already modeled in `FableIntelligentSystemsProposals_2026-07-01.md`**
  (the FIS-0001..0008 proposals cross-referenced throughout this doc) if you move a finding from
  "documented opportunity" to "proposed change": ground every current-code claim yourself (code drifts —
  re-verify line numbers before trusting them), name real prior art, run an independent adversarial
  check before committing, and do an explicit constraint check against CLAUDE.md §3/§4/§8 for whatever
  you choose. That bar — not the bar of "does it compile" — is what "MIT-level" execution means here.
- **Security-sensitive findings need sign-off, not just code review.** Several findings below touch
  trust-state verification, anti-replay protection, or key custody (§13.2 of CLAUDE.md). Treat those
  exactly as seriously as any other change to that code: SecurityMinimumBar.md review, no
  unwrap()/expect(), the secrets-hygiene and backend-boundary gates, one enforcement point + one
  verification test per control (§4).
- **Not every finding is worth fixing.** Several are explicitly scale-gated (the finding says so) —
  real mechanisms whose benefit doesn't clear its cost at Rustynet's stated 2-50 node target. One
  (`WIN-1`) is reported specifically because it's *already done right*, so nobody re-investigates it.
  Treat "this is real but not worth it right now" as a legitimate, first-class conclusion.
- **This is a catalog, not a queue.** Nothing here is ordered by priority. Decide priority yourself
  based on what the project needs right now — a fresh read of the current active ledgers
  (`CrossPlatformRoleParityRoadmap_2026-06-22.md`, `RustynetDataplaneExecutionPlan_2026-05-18.md`, etc.)
  will tell you more about what's urgent than this document can.

## 2) At a glance

| ID | Finding | Area | Kind |
|----|---------|------|------|
| SEC-1 | WireGuard runtime-key custody pipeline (Argon2id+OS-store+atomic rewrite) re-run from scratch on every reconcile-triggered apply | Key custody | Redundant expensive work |
| SEC-2 | No Ed25519 batch verification anywhere; membership-quorum and gossip-ingestion loops verify one signature at a time | Key custody / crypto | Missed established technique |
| ACL-1 | `PolicySet`/`ContextualPolicySet` use an unindexed `Vec<Rule>` linear first-match-wins scan | Policy engine | Algorithmic complexity |
| ACL-2 | `evaluate_with_membership` checks the costlier membership predicate before the cheap selector predicate, on every rule | Policy engine | Wasted-work ordering |
| ACL-3 | No decision caching anywhere in `rustynet-policy`; bundle-issuance node-pair evaluation is O(N×tags²×R), fully recomputed every call | Policy engine | Missing incremental recompute |
| MEM-1 | Every membership apply re-serializes+re-hashes the entire roster (O(N)); `apply_signed_update` does this redundantly ~2x | Trust-state | Algorithmic complexity + redundancy |
| MEM-2 | No partial/incremental verification path exists — bootstrap, reconnect, and single-fact queries all require full-roster download+reverify | Trust-state | Missing succinct-proof capability |
| ENR-1 | Membership-admission cost scales with total historical operations, not roster size; log is never compacted, hashed twice redundantly | Trust-state / enrollment | Unbounded growth + redundancy |
| ENR-2 | *(corrected)* Bundle-pull client exists and works, but performs no signature re-verification after fetch — trusts anchor's disk state | Trust-state / enrollment | Assurance/cost asymmetry |
| ENR-3 | Enrollment token itself is lean and identity-free; the flat, un-compartmentalized full-roster disclosure is the real (undocumented-as-goal) privacy question | Enrollment / privacy | Disclosure-scope, not perf |
| SER-1 | Tier-1 "zero-clone canonical builder" fix landed only in `membership.rs`; the identical anti-pattern is unfixed in 7+ other builders, worst-case O(N²) at full-mesh scale | Serialization | Incomplete rollout of known fix |
| SER-2 | Membership audit log hex-encodes an already-hex-embedded envelope a second time purely to hash it; full log rewritten on every single append (O(n²) cumulative) | Serialization | Redundant work + unbounded growth |
| SER-3 | Hex-nesting to embed canonical payloads inside line-oriented envelopes doubles at-rest/on-wire bytes for every signed bundle | Serialization | Bytes-on-wire, tension w/ hardening plan |
| NAT-1 | ICE pair race's "fire all pairs concurrently" loop is actually serial expensive OS-mutation syscalls/subprocess spawns, not cheap datagram sends | NAT traversal | Mislabeled concurrency |
| NAT-2 | Round-timing structure gives the final round's probes zero observation window; fixed 80ms budget, not RTT-adaptive | NAT traversal | Timing/architecture bug |
| NAT-3 | Third (authoritative-transport) STUN gathering path is genuinely serial-sum latency; two independent STUN wire-format implementations have already drifted in retry robustness | NAT traversal | Serial I/O + code duplication |
| RLY-1 | Rate limiter's `HashMap<String,_>` forces a heap allocation on every forwarded relay frame via `entry()`'s owned-key requirement | Relay | Allocation on hot path |
| RLY-2 | *(corrected)* Relay usage accounting is aggregate-only (nothing to make private yet); an unimplemented "Zero-Knowledge Relay" design already exists elsewhere and needs reconciling | Relay / privacy | Missing feature + doc conflict |
| RLY-3 | One UDP socket + one tokio task per relay session vs. QUIC-datagram multiplexing — real tradeoff, but FD ceiling isn't reached at target scale | Relay | Scale-gated architecture question |
| CCY-1 | No locks because there's no concurrency: the whole control plane is one cooperative single-thread loop; a missing write-timeout on the admin IPC socket can stall DNS/gossip/reconcile unboundedly | Concurrency | Availability hazard |
| CCY-2 | `reconcile()` unconditionally reloads+reverifies+re-persists trust/membership state every tick regardless of change | Concurrency | Redundant expensive work |
| CCY-3 | `GossipNode` owns canonical state; `DaemonRuntime` keeps a manually-resynced shadow copy — correctness-risk, not (currently) a perf issue | Concurrency | Architecture hygiene |
| BLD-1 | Low-level crates fan out into the two heaviest crates; xtask's `--affected` is one-hop only, silently under-scopes ≥2-hop dependents like `rustynet-cli` | Build/dev-loop | Tooling gap + graph shape |
| BLD-2 | No cargo-nextest; ~101 test binaries run one-at-a-time; test stage is the dominant, measured gate cost (up to 65 min cold) | Build/dev-loop | Missing established tool |
| BLD-3 | `check` and `clippy` run as two fully serial full-workspace passes costing near-identical wall time each — ~21.5 min combined before tests even start | Build/dev-loop | Redundant cache-miss work |
| CLI-1 | Daemon startup fully parses+verifies+replays every signed-state bundle type twice — once in a discarded preflight pass, once for real | Startup | Redundant expensive work |
| CLI-2 | `rustynet-cli` shells out for build-time-fixed facts (`rustc --version`) on every invocation; zero memoization anywhere in the crate | Startup | Unnecessary subprocess spawn |
| CLI-3 | Network-interface enumeration independently implemented 3x; `diagnostics` composes 6 external-process probes strictly sequentially (measured ~40x baseline) | Startup | Duplication + missing concurrency |
| WIN-1 | *(not a finding)* The one raw WFP FFI call site is already correctly transaction-batched | Windows | Confirmed-sound baseline |
| WIN-2 | Windows peer/route apply is subprocess-per-item + full-config DPAPI-re-encrypt-per-mutation — O(N) spawns, O(N²) total DPAPI bytes for one logical generation apply | Windows | Algorithmic complexity |
| WIN-3 | llm-gateway/nas streaming is already granular (not the feared buffer-then-forward); neither sets `TCP_NODELAY`; llm-gateway's real inference backend doesn't exist yet so pooling can't be graded | Windows / service-hosting | Mixed: one real gap, one N/A-for-now |

## 3) Already covered elsewhere — do not re-propose

Cross-referenced throughout; listed once here for completeness. Do not treat these as fresh ground:

- **FIS-0001..0008** (`FableIntelligentSystemsProposals_2026-07-01.md`): post-handshake path-quality
  EWMA scoring (FIS-0001); TLA+ formal verification of the membership state machine — correctness, not
  perf (FIS-0002); Plumtree epidemic gossip for peer-endpoint-candidate dissemination only, explicitly
  *not* the membership bundle itself (FIS-0003); loss/RTT congestion signal → relay preference (FIS-0004);
  MCDA role-placement scoring (FIS-0005); SPRT/CUSUM flake classifier for live-lab evidence (FIS-0006);
  load-aware relay selection + DRR fairness (FIS-0007); multi-instance service routing for nas/llm
  (FIS-0008).
- **`DataplanePerfBacklog_2026-06-12.md`**: landed — engine scratch-buffer reuse, worker zero-timeout
  poll, relay zero-copy forward + paired-session-id cache, control-plane Tier-1 hex/clone/parse pass
  (hex-via-nibble-LUT + zero-clone canonical builders, **landed only in `membership.rs`** — see SER-1),
  release build-profile LTO/codegen-units tuning. Scheduled remaining: P1 engine outcome-sink copy
  removal, P2 relay await-based recv + lock-contention reduction, P3 macOS utun readv/writev framing, P4
  endpoint→peer reverse-index at >10 peers. Explicitly rejected: shrinking the relay recv buffer below
  64KiB.
- **`FullRepoAnalysis_2026-05-24.md`** (efficiency-relevant items only, not the doc's full security/doc
  scope): `relay_client.rs` hot-path allocations (error-string-per-signing-failure, `NodeId` clone per
  session, double `to_owned()`); `key_rotation.rs:342` digest-computation clones instead of
  serialize+hash; workspace has only one benchmark file, no perf-regression guard on several
  signature/parse paths; `Arc<dyn RelaySessionTokenIssuer>` vtable dispatch overhead (minor); relay
  `allocate_port()` holds an `RwLock` across `UdpSocket::bind().await`, serializing port allocation;
  synchronous Ed25519 verify inline in the relay's async transport path; `daemon.rs`'s `http_get_raw()`
  reads a full HTTP response via `read_to_end` before the size bound applies, needs `.take()`.
- **`SerializationFormatHardeningPlan_2026-03-25.md`**: locked decision to keep signed control-plane
  bundles as canonical text (not binary/CBOR/postcard) — SER-1/SER-2/SER-3 must be read against this;
  SER-3 in particular flags a direct tension.
- **`PlatformImprovementBacklog_2026-05-14.md`**: surveyed in full; contains no efficiency/performance
  items (it's security-drift verifiers + a correctness-focused typed-JSON-schema migration) — zero
  overlap with this catalog.

---

## 4) Key custody & secrets storage (`rustynet-crypto`, `rustynet-local-security`, `rustynetd::key_material`)

### SEC-1: Runtime-key custody pipeline (Argon2id KDF + OS-store round trip + atomic disk rewrite) re-run from scratch on every reconcile-triggered apply, never memoized

**Current behavior.** `prepare_runtime_wireguard_key_material` (`crates/rustynetd/src/daemon.rs:10403-10446`)
has no cache: whenever a kernel-WireGuard backend mode requires it
(`requires_runtime_wireguard_key_material()`, daemon.rs:857-865; `decrypts_runtime_key_in_memory()`
false for those modes, daemon.rs:893-895), it unconditionally calls `decrypt_private_key()`
(`key_material.rs:521-542`) then `write_runtime_private_key()` (an `OpenOptions::create_new` +
`write_all` + `sync_all` + `rename` atomic write, `key_material.rs:790-795`) — even when the encrypted
blob, passphrase, and resulting plaintext are byte-identical to the previous call. `decrypt_private_key`
chains: `read_passphrase_file` → `key_custody_manager` (wraps `PlatformOsSecureStore`,
`key_material.rs:583-601`) → `KeyCustodyManager::load_private_key` (`rustynet-crypto/src/lib.rs:427-447`),
which tries the OS secure store first (`secret-tool` subprocess spawn on Linux with no daemon/keyring
typically available on a headless server or Pi, `lib.rs:904-949`; `/usr/bin/security` subprocess
fallback on macOS, `lib.rs:752-773`) and on `OsStoreUnavailable` falls back to
`read_encrypted_key_file` (`lib.rs:1573-1583`): `validate_key_custody_permissions` (2× `symlink_metadata`
+ 2× `metadata` syscalls, `lib.rs:1680-1721`) + `fs::read` + `decrypt_private_key_envelope`
(`lib.rs:1357-1408`), which runs `Argon2::default().hash_password_into` (`lib.rs:1362-1364`) —
Argon2 0.5.3's `Default` is `DEFAULT_M_COST=19*1024` KiB, `DEFAULT_T_COST=2`, `DEFAULT_P_COST=1`
(verified directly against the vendored crate source, `argon2-0.5.3/src/params.rs:42,52,61`), i.e. a
deliberately memory-hard, non-trivial-latency KDF pass by design. The call sites inside `reconcile()`
are gated at `daemon.rs:8529-8534` (`DataplaneState::FailClosed || RestrictionMode::Recoverable ||
assignment_changed || membership_changed || local_route_reconcile_pending`) feeding
`ensure_runtime_private_key_material()` (`daemon.rs:8341`, called from `reconcile()` at `daemon.rs:8593`
and from `bootstrap()` at `daemon.rs:7143`, the latter startup-only and fine). `reconcile()` runs on a
fixed 1000ms timer (`DEFAULT_RECONCILE_INTERVAL_MS`, `daemon.rs:322`).

**Why it's a bottleneck.** Any sustained `FailClosed`/`Recoverable` condition (set by
`restrict_recoverable`/`restrict_permanent`, `daemon.rs:8841/8849`, cleared only on a fully successful
apply, `daemon.rs:8690`) re-enters the trigger block on *every* reconcile tick, so the full pipeline
(subprocess spawn or Argon2id + 4 stat syscalls + AEAD decrypt + fsync'd atomic rewrite) repeats once
per second for as long as the node stays stuck recovering from an *unrelated* failure — the key material
itself never changed. Outside a failure loop, `membership_changed`/`assignment_changed` fire on any
mesh-wide epoch bump, coupling a deliberately-slow KDF to unrelated dataplane-apply triggers instead of
to "did the encrypted key or passphrase actually change."

**Impact.** Argon2id at these defaults is on the order of tens-to-low-hundreds of ms on typical
server/desktop CPUs, expected to cost meaningfully more on ARM SBC-class hardware (no hard number
measured against real Pi hardware — qualitative, not benchmarked). A node stuck in `Recoverable` for
minutes (a plausible live-lab failure-loop scenario) pays this roughly once per second for the whole
duration.

**Scale relevance.** Matters most at the Raspberry-Pi-class anchor end of the 2-50 node target — Argon2id's
memory-hardness and constrained CPU compound — and during any prolonged failure/recovery condition
regardless of mesh size.

**Candidate technique families (pick none, one, several, or something else):**
- In-process memoization of the derived plaintext runtime key (a `Zeroizing<Vec<u8>>` field +
  invalidation on the encrypted blob's mtime/hash, cleared on rotation) — near-zero cost on repeat
  triggers; tradeoff: keeps plaintext key material resident in memory longer, the exact exposure-vs-cost
  tradeoff this document leaves open, not resolved.
- Extend the exact `OnceLock`-memoization idiom already used in this same file for a different check
  (`WINDOWS_DPAPI_STARTUP_SELF_TEST: OnceLock<Result<(), String>>`, `key_material.rs:77`, consumed at
  `key_material.rs:401-405`, itself `#[cfg(windows)]`-only today) to the decrypt-and-write step generally
  — same idiom, wider scope; tradeoff: a stale cache surviving an out-of-band rotation needs an explicit
  invalidation signal.
- Dirty-check before paying the KDF cost: compare the on-disk blob's content hash against what would be
  produced before re-deriving — avoids caching secret material at all, but still repeats the cheap I/O
  read+hash every trigger and doesn't help the OS-store subprocess-spawn cost.
- Decouple `ensure_runtime_private_key_material()` from the generic `reconcile()` retry loop by giving it
  its own success/failure state that's checked, not re-executed, on ordinary reconcile re-entry — narrows
  the trigger surface without touching the crypto path; adds another piece of daemon state to keep
  consistent with `restriction_mode`/`bootstrap_error`.

**Constraints.** Any caching must not weaken the mandatory fail-closed startup permission check (§4) —
`validate_key_custody_permissions` etc. must still run at least once per process lifetime before the key
is trusted; a cache should skip only *re-derivation*, never initial verification. No unwrap/expect may be
introduced (§3/§10.2). `OsSecureStore` must stay backend-agnostic (§8) — no platform special-casing
inside `rustynet-control`/`rustynet-policy`.

---

### SEC-2: No Ed25519 batch verification anywhere; two concrete verify-in-a-loop sites confirmed

**Current behavior.** `ed25519-dalek = "2"` is declared in 7 consuming crates with no `batch` feature
enabled anywhere in the workspace (confirmed by grepping every `Cargo.toml`). The vendored crate
(`ed25519-dalek-2.2.0/Cargo.toml:76-80`) shows `batch = ["alloc", "merlin", "rand_core"]`, off by
default, implementing `verify_batch` over independent (message, signature, key) triples via one
multiscalar multiplication. **Site A — membership quorum:** `verify_membership_signatures`
(`crates/rustynet-control/src/membership.rs:1013-1054`) loops
`for signature in &signed_update.approver_signatures` (line 1032) calling
`verifying_key.verify_strict(payload, &signature_obj)` (lines 1044-1046) individually, where every
signature is over the *identical* payload — the textbook batching case. This runs from
`apply_signed_update` (`membership.rs:722`), itself called once per historical log entry inside
`replay_membership_snapshot_and_log`'s loop (`membership.rs:932-944`) whenever a node's local snapshot
lags the log — invoked from `load_verified_membership` on every `reconcile()` tick.
**Site B — gossip-bundle ingestion:** `drain_gossip_inbound` (`daemon.rs:5174-5205`,
`MAX_DRAIN_PER_ITERATION=16`) routes each of up to 16 inbound bundles per main-loop iteration through
`accept_bundle_with_now` → a single `verify_strict` call per bundle (`peer_gossip.rs:411-412`) —
heterogeneous messages and heterogeneous keys, which `verify_batch`'s per-item API still supports.

**Why it's a bottleneck.** Each `verify_strict` call pays two full variable-time scalar multiplications
serially; batch verification amortizes the dominant multiscalar-multiplication across all N items in one
pass. Site A's cost scales with `signer_ids.len()` (bounded by `quorum_threshold`) *times* the number of
historical log entries replayed before a lagging node's snapshot catches up — it can spike to
O(total-historical-ops × quorum_threshold) sequential verifications on a behind node, repeated every
reconcile tick until caught up. Site B recurs on every main-loop pass under active gossip traffic.

**Impact/scale.** `quorum_threshold` is a small governance-committee size independent of mesh size (test
default 2; validated only `<= active_approvers`), so Site A's steady-state per-call N is small — the
batching win is modest there in steady state and material specifically in the catch-up-replay
amplification case. Site B's up-to-16-per-iteration batch size, recurring every main-loop pass under
active gossip at the upper end of 2-50 nodes, is close to where published Ed25519 batch-verification
benchmarks show consistent wins over serial verification.

**Candidate technique families:**
- `ed25519_dalek::verify_batch` (audited, already-vendored, gated behind the existing `batch` feature)
  at Site A across one update's `approver_signatures` — tradeoff: batch failure reports only that *some*
  signature is invalid, not which, so a fail-closed caller needs a single-verify fallback to attribute
  the bad signature for `SignerNotAuthorized`/`SignatureInvalid`, doubling worst-case cost on the
  (presumably rare) failure branch.
- `verify_batch` at Site B across the up-to-16 collected bundles before dispatch — tradeoff: requires
  restructuring the drain loop from immediate per-bundle ingestion to collect-then-verify-then-apply,
  changing today's early-exit-on-first-bad-bundle behavior; needs the same single-verify fallback.
- Precompute/cache each approver's `VerifyingKey::from_bytes` decompression once per membership-state
  generation instead of per verification call — a smaller, additive optimization independent of
  batching, since `verify_membership_signatures` currently re-parses `approver.approver_pubkey_hex`
  fresh every call (`membership.rs:1040`).
- Attack the O(historical-log-length) amplification directly (advance/checkpoint the local snapshot more
  aggressively so `entries` beyond it stays small) — reduces *how often* N grows large without touching
  the verification primitive; a legitimate alternative to batching for Site A specifically.

**Constraints.** `verify_batch` is the crate's own audited implementation, not hand-rolled — adopting it
doesn't violate §3, but changing feature flags needs a `cargo audit`/`cargo deny` pass (§7) since `batch`
pulls in `merlin` and `rand_core` as new transitive deps. Batch verification's multiscalar multiplication
is variable-time by design — standard for public-signature verification, no secret key material
involved, so no conflict with constant-time expectations (which apply to secret-dependent operations).
Any restructuring must preserve default-deny/fail-closed: a batch that fails must still result in zero
updates applied, matching today's one-bad-signature-rejects-the-whole-update behavior.

---

## 5) ACL / policy evaluation engine (`rustynet-policy`)

### ACL-1: `PolicySet`/`ContextualPolicySet` use an unindexed `Vec<Rule>` linear first-match-wins scan

**Current behavior.** The entire rule store is `pub rules: Vec<PolicyRule>`
(`crates/rustynet-policy/src/lib.rs:125-128`) and `Vec<ContextualPolicyRule>` (`lib.rs:194-197`). All
four decision entry points — `PolicySet::evaluate` (131-150), `PolicySet::evaluate_with_membership`
(152-182), `ContextualPolicySet::evaluate` (200-222), `ContextualPolicySet::evaluate_with_membership`
(224-257) — are `for rule in &self.rules { .. if matches { return } }` loops returning `Decision::Deny`
only after falling off the end. `selector_matches` (`lib.rs:382-384`) is a plain
`rule_value == "*" || rule_value == candidate` string comparison — no CIDR/prefix matching, no
set/hash lookup, no compiled structure; a route literal like `"100.64.0.2/32"` is compared only for
exact equality (confirmed by the `literal_route_destinations_do_not_require_membership_resolution`
test, `lib.rs:809-834`) — the crate does not support real CIDR matching today at all.

**Why it's a bottleneck.** Every decision costs O(R) string comparisons worst case — specifically the
default-deny path (no rule matches) and any request whose matching rule sits near the end, both exactly
the security-relevant cases where an attacker/misconfigured peer walks the *entire* rule list.
Architecturally identical to a legacy iptables-style linear chain.

**Impact/scale.** At the 2-50 node target the observed rule counts are small and hand-authored (the
daemon's baked-in default policy is a single rule, `daemon.rs:3902-3910`) — the crate's own O(R) cost is
negligible in absolute terms today. Where this compounds is in callers that multiply the per-call cost by
node-pair combinatorics (see ACL-3); a rule set that grows through many per-tag/per-group rules is the
scenario where this finding becomes concretely worth revisiting. No benchmark exists for this crate (the
workspace has only one benchmark file total, per `FullRepoAnalysis`).

**Candidate technique families:**
- Hash/set-indexed exact-match rules (nftables named-set style): index by `(src, dst)` into a
  `HashMap<(String,String), Vec<RuleIdx>>` plus a wildcard bucket checked once — O(1) average for exact
  lookups; needs a rebuild or incremental update on every `rules` change, and only helps exact-match
  selectors (which is all this crate supports today).
- Decision-diagram/BDD-style rule compilation (Header Space Analysis / OpenFlow classifier compilers) —
  much higher implementation/verification complexity; **no mature audited off-the-shelf Rust crate for
  ACL-specific BDD compilation exists today**, so this would be materially custom code sitting in a
  default-deny security path — a real correctness-risk/review-burden concern independent of it not being
  "custom cryptography."
- Trie-based longest-prefix-match structures — relevant only if the selector language grows real
  CIDR/range matching, which it explicitly does not have today; adopting a trie would be introducing a
  capability, not accelerating an existing one.
- Cheapest-predicate-first reordering inside the existing linear scan — no new data structure, see ACL-2.
- Decision memoization keyed on the normalized request tuple, invalidated on a policy/membership
  generation counter — only pays off if the same tuple recurs many times between policy changes.

**Constraints.** Any indexing/compilation scheme must preserve default-deny and first-match-wins
semantics exactly (no reordering that changes which rule "wins" for overlapping selectors);
`rustynet-policy` is transport-agnostic (§8/§10.3) so no backend-specific type may leak in. A
rebuild-on-change index must never silently serve stale (over-permissive) results mid-rebuild (§3/§4).

---

### ACL-2: `evaluate_with_membership` checks the costlier membership predicate before the cheap selector predicate, on every rule

**Current behavior.** In both `PolicySet::evaluate_with_membership` (152-182) and
`ContextualPolicySet::evaluate_with_membership` (224-257), the per-rule loop order is: (1)
`membership_rule_allowed(...)` — a `HashMap` lookup into `MembershipDirectory::selector_members` plus an
`.iter().all(...)` scan over the selector's member list (`lib.rs:420-426`) — *then* (2)
`selector_matches(&rule.src, &request.src)`, the O(1) check that determines whether the rule is even
relevant. The expensive check runs unconditionally for every rule before the cheap check that would
usually `continue` past irrelevant rules immediately.

**Why it's a bottleneck.** Wasted-work ordering independent of ACL-1's algorithm class — remains
wasteful even after adopting a smarter indexing scheme unless the reorder is also applied. Every rule
*other* than the matching one pays a full membership resolution before being skipped a moment later.

**Candidate technique families:**
- Simple predicate reordering: run `selector_matches` (cheap) first, call `membership_rule_allowed`
  (costlier) only for rules that already passed selector/protocol/context filters — pure code-order
  change, no new data structure or dependency.
- Short-circuit via a combined predicate function inlining both checks, avoiding a second function-call
  boundary per rule.
- Precomputed per-selector membership-validity cache (`HashMap<&str, bool>` populated once per
  `evaluate()` call, refreshed on `MembershipDirectory` generation change) so repeated selectors across
  many rules (e.g. many rules sharing `dst="tag:servers"`) resolve once instead of once per rule.

**Constraints.** Reordering must not change which check causes the deny (functionally equivalent either
order — both must pass to reach the action). The M5 revocation-precedence design intent (`lib.rs:836-838`,
"revocation denies before rule evaluation" for the *request's own* src/dst) is a separate, already-early
check unaffected by this finding, which targets only the per-*rule*-selector membership check.

**Scale relevance.** Matters most where ACL-1 starts to bite — larger rule sets and/or larger selector
groups, since group iteration is O(group size), not O(1). On a Pi-class anchor this ordering issue turns
what should be a cheap early-exit into a HashMap probe plus a linear group scan for every irrelevant
rule.

---

### ACL-3: No decision caching anywhere; bundle-issuance node-pair evaluation is O(N×tags²×R), fully recomputed from scratch every call

**Current behavior.** `rustynet-policy` has zero cache/memoization state (confirmed by reading the full
crate). Every production call site — `daemon.rs::policy_gate_auto_tunnel` (4246-4309),
`phase10.rs::set_exit_node`/`::ensure_lan_route_allowed` (5389-5421, 5449-5492),
`service_exposure.rs::evaluate_service_access` ("the single admission point," 459-462) — re-derives its
`Decision` fresh, but all are control-plane / session-granularity events, not per-packet. The one place
evaluation is genuinely combinatorial: `rustynet-control::policy_allows_node_pair` (`lib.rs:3422-3454`)
loops `selectors_for_node(source) × selectors_for_node(destination) × [Any, Udp, Tcp]` — up to
`(2+tags)² × 3` calls into `PolicySet::evaluate()` per node pair, short-circuiting only on first Allow.
Invoked once per candidate peer inside `signed_auto_tunnel_bundle` (`lib.rs:2554-2631`), which for a
single node's bundle lists *every* current node, recomputes `deterministic_tunnel_assignments` for the
*whole mesh*, and calls `policy_allows_node_pair` once per peer candidate. `ControlPlaneCore`
(`lib.rs:2234-2257`) has no pair-eligibility cache and no per-node "dirty since last bundle" tracking.

**Why it's a bottleneck.** Every call to `signed_auto_tunnel_bundle` for one node redoes O(N) node-pair
evaluations from cold, each up to `(2+tags)² × 3` calls into ACL-1's O(R) scan — up to
O(N × tags² × R) work to (re)issue a single node's bundle, none of it reused from the previous call even
when only one other node's status changed. There is no way to ask "which edges changed" short of
recomputing all of them.

**Impact/scale.** This is the most scale-relevant of the three ACL findings: node-pair combinatorics are
O(N²) worst case (regenerating every node's bundle after any membership change), and unlike ACL-1/ACL-2
this cost is paid synchronously as part of bundle issuance/signing — exactly the kind of operation that
blocks a control-plane critical section on constrained anchor hardware. At N=50 with a handful of tags
per node this is on the order of tens of thousands of string comparisons — not catastrophic on a modern
CPU, but the least-amortized of the three findings.

**Candidate technique families:**
- Per-mesh N×N reachability bitset precomputed once and updated incrementally — updates touching only
  the changed node's row/column recompute in O(N) instead of the full O(N²) matrix; requires an explicit
  "which rows are dirty" invalidation tied to membership/policy generation numbers.
- Decision cache keyed on `(source selector-set, destination selector-set, protocol)` with LRU or
  generation-stamped eviction — cheap to add, pays off only if the same node pairs recur across many
  `signed_auto_tunnel_bundle` calls between policy changes (plausible but unmeasured).
- Batch/columnar evaluation: precompute per-rule applicable-selector sets once per bundle-generation pass
  and intersect, turning repeated O(R) scans into fewer set operations — reduces constant factor without
  changing the underlying data structure.
- Incremental/differential bundle regeneration keyed on a membership diff: track the previous
  membership snapshot's per-pair decisions and re-run `policy_allows_node_pair` only for pairs where at
  least one endpoint's status/tags or the rule set changed — the only family here that addresses "full
  rebuild vs. incremental recompute" rather than just speeding up the rebuild; a control-plane design
  change, not a data-structure swap.

**Constraints.** Any cache/precomputed structure must fail closed on staleness (§3/§4): a cached Allow
must never be served past a membership revocation or policy rollback without invalidation first — a
stronger requirement than a typical ACL cache, needing explicit generation-counter/watermark tie-in to
the existing signed/replay-watermark machinery rather than a time-based TTL cache.

---

## 6) Membership/trust-state verification cost and succinct-proof opportunity (`rustynet-control::membership`)

*Distinct from FIS-0002 (a TLA+ correctness proposal, not performance) and from FIS-0003 (peer-endpoint-
candidate gossip only, explicitly excludes the membership bundle itself — "a possible future phase-4
extension only, never designed").*

### MEM-1: Every membership apply re-serializes and re-hashes the ENTIRE roster (O(N)); `apply_signed_update` performs this full pass redundantly ~2x per single-field change

**Current behavior.** `MembershipState.nodes`/`.approver_set` are plain `Vec`s with no id-indexed
structure (`membership.rs:159-168`; grep confirms no `HashMap`/`BTreeMap` keyed by `node_id` anywhere).
`canonical_payload()` (`246-305`) calls `self.validate()` (which hex-decodes every node/approver pubkey,
`171-244`), sorts *all* node/approver references (O(N log N)), and serializes every field of every
record. `state_root_hex()` (`307-310`) is `sha256(canonical_payload())`. `apply_signed_update`
(`693-737`) calls, per single-operation apply: `state.validate()` (699) THEN `state.state_root_hex()`
(713, which internally calls `canonical_payload()` → `validate()` **again** — a second full validate of
the same old state), then `reduce_membership_state` (727), which does `state.clone()` — a full deep clone
of every node/approver field (`1160`) — to mutate exactly one node found via an O(N) linear
`.iter_mut().find()` scan, then `next.validate()` (729) THEN `next.state_root_hex()` (730, which again
internally re-validates). Net: **4 full O(N) validate passes (2 redundant), 2 full O(N log N)
sort+serialize passes, 2 full SHA-256 hashes, 1 full O(N+M) deep clone — to apply one single-field
mutation to one node.**

**Why it's a bottleneck.** The state root is a flat hash of the fully-concatenated, fully-sorted roster
with no incremental/authenticated-data-structure representation, so there's no way to update or verify
it without touching every record every time, regardless of delta size. On top of that architectural O(N)
floor, the call graph invokes validate+canonicalize on both pre- and post-image state twice each
(directly, then again inside `state_root_hex()`) — roughly 2x the constant factor even the O(N)
architecture strictly requires.

**Measured impact.** Directly measured on this checkout: `cargo build --release -p rustynet-control
--example perfprobe_membership` + `/usr/bin/time -l` at N=50 nodes gives **107,690 ns/op, 1,598
allocations/op, 162,468 bytes/op** for one `canonical_payload()` + `state_root_hex()` + decode round
trip. Consistent with the already-landed Tier-1 baseline (177→117 µs/op, `DataplanePerfBacklog §1.6`) —
that pass's constant-factor win is visible but the O(N) shape is unchanged. Inferred (not separately
profiled): since `apply_signed_update` performs this shape roughly twice plus one full O(N+M) deep
clone, a single one-field change costs on the order of ~150-250 µs CPU and several hundred KB of
transient allocation churn purely from full-roster re-canonicalization.

**Scale relevance.** Sub-millisecond in isolation at 2-50 nodes, but paid in full on *every* membership
operation, multiplied by pending-log-entry count on reconnect (see ENR-1) — matters most on Pi-class
anchors and near the snapshot format's own stated aspirational headroom ("several hundred nodes",
`membership.rs:28-30`).

**Candidate technique families:**
- Algorithmic redundancy elimination (no structural change): compute `canonical_payload`/`validate` once
  per side and reuse it instead of calling `state_root_hex()` (which re-derives internally) after
  already calling `validate()` explicitly — halves the validate/serialize passes with zero architecture
  change. Not addressed by the landed Tier-1 pass, which reduced per-call cost but not call *count*.
- Id-indexed roster (`HashMap<NodeId, usize>` or `BTreeMap` alongside/instead of the `Vec`) — turns
  linear `.find()`/`.retain()` into O(1)/O(log N), can support structural sharing (`im`/`rpds`-style)
  so `reduce_membership_state` copies only the touched entry — tradeoff: touches the canonical-payload
  sort/serialize logic and wire format, both pinned by determinism/round-trip tests and signature
  verification (a protocol-version bump, not a drop-in swap).
- Merkle tree / sparse Merkle tree over the node/approver set — see MEM-2, where it's explored in depth
  (this affects both apply-cost and verification-cost, so the full writeup lives there).
- Succinct/zk-verified transition proofs — out of scope for *this specific* redundancy (a much heavier
  lift for what is fundamentally an O(N)-vs-O(log N) engineering problem, not a verification-opacity
  problem); see MEM-2.

**Constraints.** Must preserve the anti-replay/rollback contract (§4) — `apply_signed_update`'s
prev/new-root and epoch-chain checks (`713-732`) are the actual defense and must continue to gate every
apply unambiguously. Pure transport-agnostic control-plane logic (§8) — no WireGuard types involved.

---

### MEM-2: No partial/incremental verification path exists — bootstrap, reconnect, and single-fact queries all require full-roster download-and-reverify; the only existing bandwidth optimization is binary all-or-nothing

**Current behavior.** Three call sites confirm no partial-proof mechanism exists. (1)
`load_verified_membership` (`daemon.rs:4138-4176`): bootstrap/reconnect loads a full snapshot + whatever
local log entries exist, then `replay_membership_snapshot_and_log` (`membership.rs:920-946`) loops
`apply_signed_update` once per entry — O(L×N) work to catch up L pending operations, each paying MEM-1's
full O(N) cost. The owner's log is deliberately *not* shipped to client nodes over the network
(`daemon.rs:4145-4154`) — a freshly-enrolled client gets snapshot-only (one O(N) verify), but a
reconnecting node with a stale *local* log replays through however many entries it already holds. (2) The
network distribution path (`anchor.bundle_pull`, `daemon.rs:1004-1062`) is strictly binary:
`write_anchor_bundle_pull_response_with_have` compares `(epoch, state_root)` — on exact match replies
`UNCHANGED` (cheap), but on *any* mismatch, even a single node's status flip, sends the entire current
bundle (`OK {len}` + full bytes), which the receiver must fully parse+validate+hash. No delta/diff
format exists. (3) `snapshot_bytes_have_bundle_pull_capability` (`membership.rs:789-805`) — answering
"does node X hold capability Y" — fully decodes and validates every node in the snapshot just to look up
one node's capability list.

**Why it's a bottleneck.** The flat-hash state root (MEM-1) has no companion inclusion-proof mechanism,
so "prove the current state" and "prove one fact about the current state" both degrade to "transmit and
fully re-verify the whole roster." Every consumer — a reconnecting node, a mobile client, an internal
capability lookup — goes through the same O(N) path regardless of how small the actual fact/delta is.

**Bandwidth reality check (be honest about this).** Estimated ~250-300 bytes/node encoding
(`canonical_payload`'s field template, `membership.rs:270-286`) → ~15 KB full bundle at N=50, trivial
even on a poor cellular link and well under the 1 MiB `MAX_MEMBERSHIP_SNAPSHOT_BYTES` comment's
realistic ceiling. **Raw byte count alone is a weak justification for succinct proofs at the stated
target scale.** The stronger, better-evidenced motivations are (a) the CPU/allocation cost from MEM-1
recurring on every apply and multiplied by L on reconnect-replay, mattering more on Pi-class anchors, and
(b) the architectural oddity that a single-fact query requires a full-roster parse. The case for the
heavier techniques below gets meaningfully stronger only if node counts grow well past 50, per-node data
grows substantially, or this log/snapshot pattern gets reused for a much larger authenticated-state use
case — none of which are true today.

**Candidate technique families:**
- **Merkle tree / sparse Merkle tree (SMT) state commitment**: represent the roster as an SMT keyed by
  `node_id`; the state root becomes the tree root instead of a flat-concat hash. A bandwidth/CPU-constrained
  verifier (mobile client, Pi-class anchor) could verify one claim via an O(log N) inclusion proof
  (~6 hash comparisons at N=50; ~16-17 even at the format's `MAX_MEMBERSHIP_NODE_COUNT=65,536` ceiling)
  instead of downloading/parsing the full roster; writer-side, single-node updates become O(log N) root
  recomputation. This composes the *same* `sha2::Sha256` already imported (`membership.rs:15`) into a
  tree shape rather than a flat digest — no new cryptographic primitive, satisfying the audited-crate
  constraint comfortably. The engineering risk is tree-indexing/data-structure correctness (ordinary,
  unit-testable Rust), not a cryptographic-primitive risk. Genuine cost: a real wire-format and
  persistence-format change with a migration story for existing deployments.
- **zk-SNARK/STARK succinct state-transition proof**: a proof that "new_state_root correctly follows from
  prev_state_root via N validly-signed operations," verifiable in O(1)/constant size regardless of N —
  strictly stronger than a Merkle proof (which only proves one leaf under an *assumed*-honest root, not
  that the root itself was reached validly). The heaviest-weight candidate; its value proposition is
  narrow and only pays for itself if the verifier is specifically constrained enough that O(N) replay is
  itself the problem — at the stated 2-50 node ceiling that's a modest, sub-millisecond, tens-of-KB cost.
  Mature Rust proving ecosystems exist and are used in production (arkworks, halo2 — used in Zcash
  Orchard — winterfell for STARKs, risc0 as a general-purpose zkVM), but **none are "audited" in the same
  conservative sense as this repo's existing crypto deps** (ed25519-dalek, sha2, chacha20poly1305).
  Critically: using an audited *proving backend* does not by itself make a deployment safe — the actual
  proof statement has to be expressed as a circuit specific to Rustynet's membership semantics, and
  circuit under-constraint bugs are a well-documented real-world zk vulnerability class independent of
  library audit status — effectively bespoke cryptographic protocol design on top of the library. **This
  is a real, named blocker under CLAUDE.md §3 ("no custom cryptography/protocol invention"), not a
  glossed-over caveat** — flag it explicitly if this path is pursued.
- **Delta/diff bundle-pull protocol extension** (no new cryptography, protocol-only): extend the
  `have (epoch, root)` handshake so the server can answer with just the log entries between the client's
  known epoch and current — generalizing `replay_membership_snapshot_and_log`'s already-existing *local*
  catch-up mechanism to the *network* path. The client still does O(L) `apply_signed_update` calls (still
  paying MEM-1's O(N) per entry — does not fix the CPU-side problem), but avoids re-transmitting and
  re-verifying the unchanged N-minus-few records' worth of network bytes. Cheapest engineering lift of
  the three (reuses existing signed-update/log primitives verbatim); weakest fit for the "succinct
  verification" half of the ask since per-op cost is still O(N).
- **Verkle trees / vector-commitment state commitments** (mentioned for completeness, not as a good fit):
  Ethereum's proposed Merkle-Patricia successor, smaller proofs via KZG/IPA polynomial commitments.
  Research-grade Rust support exists but carries the same audited-crate caveat as the zk family — KZG/IPA
  is a materially heavier primitive than SHA-256 Merkle hashing and far less mature/reviewed in Rust than
  either the sha2-Merkle or zk-proving options. A further-out option, not near-term.

**Constraints.** Must preserve the fail-closed anti-rollback contract: `apply_signed_update`'s prev/new
root and epoch-chain checks (§4) are the actual replay/rollback defense and must continue to exist as a
single, unambiguous root every node agrees on — a redesign changes *how* that root is computed and what
can be proven about it, not *whether* a global root gates every apply; must never create a state where
two "partial" verifications of the same claimed root can disagree. Any zk-circuit approach must be
reviewed against §3's custom-cryptography ban — a genuine open question for the reader to resolve, not a
rubber-stamp "use library X."

**Cross-reference (found during verification, not in the original hunt scope).**
`documents/operations/active/FableForkConsistentMembershipTransparency_2026-07-01.md` already proposes an
RFC-6962-style append-only Merkle history tree over the membership **log** (keyed by log position, for
fork-consistency/equivocation detection) — a structurally different tree solving a different problem than
MEM-2's proposed sparse-Merkle-tree-over-the-*roster* (verification cost, not fork detection), so not a
duplicate, but the two would likely share Merkle-proof infrastructure and should be cross-referenced by
whoever designs either.

---

## 7) Enrollment-token flow cost and anonymous-credential opportunity (`rustynet-control`, `rustynetd`, `rustynet-cli`)

### ENR-1: Membership-admission cost scales with total historical mesh operations, not roster size — the log is never compacted and is redundantly re-hashed multiple times per enrollment

**Current behavior.** Every enrollment reaching the membership layer (`rustynet enrollment admit` via
`load_current_membership_state`, `rustynet-cli/src/main.rs:15292-15308`, and the daemon's
`MembershipApply` IPC handler, `daemon.rs:8031-8093`) loads the *entire* historical membership log via
`load_membership_log` (`membership.rs:851-918`) before applying one new delta.
`append_membership_log_entry` (`822-849`) never truncates or compacts — always loads every existing
entry and re-persists the full set via `persist_membership_log` (`971-986`); no
`prune`/`truncate`/`compact` function exists anywhere in the file. One single admission pays **four
separate full linear passes**: (1) `load_membership_log`'s per-entry raw-hex hash check (`892-914`); (2)
`verify_membership_log_chain`, called both at the end of `load_membership_log` (916) *and* inside
`persist_membership_log` (975), independently re-deriving the **same** `entry_hash` via a **second,
different derivation** (`entry.signed_update.canonical_envelope()`, a full re-serialization, not reuse of
the hex already validated in pass 1); (3) `replay_membership_snapshot_and_log`'s skip-loop over every
entry (calls `apply_signed_update` zero times under normal single-writer operation, but still iterates
every entry); (4) `handle_membership_apply` re-walks all `entries` a second time purely to seed a fresh
`MembershipReplayCache` (`daemon.rs:8062-8072`), rebuilding a `seen_update_ids: HashSet<String>` holding
every update_id ever issued — duplicate protection `apply_signed_update` already gets for free from its
own strict `epoch_prev == state.epoch` chain check.

**Why it's a bottleneck.** The persisted `membership_snapshot` file (`739-750`) is already a valid
checkpoint of the fully-reduced current state, but nothing in the codebase ever uses it to shrink or
replace the log — every pass above is O(total historical operations) work performed synchronously on
the hot path of a single new enrollment, even though only the delta and current epoch matter to the
admission decision. Two of the four passes compute the identical SHA256 digest of the identical logical
content via two different derivations, every load.

**Impact/scale.** Not raw-latency-critical at N≤50 roster size in absolute terms (sub-second SHA256/parse
work at a few hundred entries of churn), but the cost axis is *total historical operation count, not
current node count*, and grows without bound as long as the mesh operates (routine key rotation, role
changes, revokes/re-admits). Matters at the top of the 2-50 node range and, more importantly, *over time*
regardless of node count — most acute on Pi-class anchors doing this synchronously and on
occasionally-connected mobile clients reconciling after a long gap.

**Candidate technique families:**
- Raft/etcd-style log compaction: truncate entries already covered by the last durable snapshot, keeping
  only the tail needed for crash recovery — needs an explicit decision about where the discarded
  fine-grained audit trail is archived, since the repo's security posture cares about auditability.
- Checkpoint pointer instead of full replay: persist the last-verified `(index, entry_hash)` alongside
  the snapshot so replay can skip straight to unverified entries — adds a second small state file to keep
  consistent with the snapshot.
- Batch Ed25519 verification (SEC-2's unused `batch` feature) for the case where several epochs genuinely
  need sequential replay (a long-offline mobile client or Pi-class anchor catching up) — helps the
  K-signatures-per-update case more cleanly than cross-epoch batching, which the strict epoch-chain design
  serializes anyway.
- In-memory hash-chain caching scoped to daemon-process lifetime: verify the full chain once at boot,
  then only verify newly-appended entries for the rest of that process's life — reintroduces an
  in-memory/on-disk consistency assumption needing re-validation after any external log mutation.
- Replace `seen_update_ids: HashSet<String>` (rebuilt by full scan every call) with persisting only
  `max_epoch` plus a small bounded recent-id window, relying on already-enforced epoch monotonicity for
  the bulk of replay protection — a narrower window changes the replay-detection guarantee for very-out-
  of-order redelivery, needing a security review, not just a perf one.

**Constraints.** Must preserve default-deny/fail-closed on missing or corrupt state (§3/§4) and must not
weaken anti-replay/rollback protection (§4) — the current design gets strong replay protection
essentially "for free" from full-history scanning, so any compaction scheme must prove it keeps the same
guarantee, not just go faster. Must also preserve the append-only signed audit trail the repo cares about
elsewhere — discarding history outright is not free even off the hot path.

---

### ENR-2: *(corrected)* An automated bundle-pull client already exists and works — but performs no signature re-verification after fetch, and the bulk-distribution path itself drops from quorum-signature verification to a plain digest + shared bearer token

**Correction to the original finding.** The initial hunt claimed no client-side puller exists anywhere
in the repo. This is **false**, caught by the verify pass: `rustynet anchor pull-bundle`
(`AnchorCommand::PullBundle`, `rustynet-cli/src/main.rs`: struct at 431, CLI verb at 6095, full impl at
7482-7569, unit tests at 21530+) is a complete, tested, wired desktop/CLI client — it connects over TCP
to the anchor's bundle-pull listener, sends the token, and writes the returned bundle to disk. The
finding below reflects this corrected picture.

**Current behavior.** The only two ways a `SignedMembershipUpdate` gets applied are `EnrollmentConsume`/
`MembershipApply`, both purely local IPC commands (`daemon.rs:7764-7777, 7914-7985, 8031-8093`) — there
is no network transport that *broadcasts* a membership delta to other nodes. Distributing one admission
to an N-node mesh requires either operator-driven re-application of the identical `signed_update_wire`
against each node's IPC, or the bulk mechanism: anchor bundle-pull (`daemon.rs:945-1330`), which serves
the flattened current `MembershipState` file protected by only a plain `digest=sha256(...)`
self-consistency checksum — **not a signature**. Server-side gating is a single shared bearer token
(`constant_time_ascii_eq`) plus a capability-revocation check — no per-request quorum-signature
re-verification. `PullBundle` (confirmed at `main.rs:7482-7569`) performs **no signature re-verification
after fetch** — it writes the fetched bytes straight to `output_path`. `documents/Requirements.md:43`
states *"Anchor-mediated bootstrap does not bypass signature verification — it is a faster path to the
same signed state new devices would otherwise obtain via gossip convergence"* — a real, currently-live
discrepancy against what the client code as read actually does with the fetched bytes.

**Why it's a bottleneck.** An assurance/cost asymmetry rather than a raw CPU bottleneck: the
cryptographically strong path (`apply_signed_update`, quorum Ed25519 + ENR-1's full-history replay cost)
has no automated way to reach more than one node's local IPC at a time, while the cheap, already-automated
path (bearer-token compare, O(1), *and* a working client) that reaches many nodes carries no re-derivable
signature evidence in what's actually transmitted or checked on receipt.

**Candidate technique families:**
- Attach the terminal `SignedMembershipUpdate` (or the short log suffix since the last checkpoint) to the
  bundle-pull response so `PullBundle` can independently re-verify quorum signatures instead of trusting
  the anchor's disk state — tradeoff: larger response, inherits ENR-1's log-replay cost unless paired
  with a compaction fix.
- Aggregate/threshold signatures (e.g. BLS aggregate over the quorum set, verified as one pairing check
  instead of K separate Ed25519 verifies) — audited-in-practice crates exist via the Ethereum
  consensus-client ecosystem (`blst`/`bls12_381`), but **this is a real scheme migration away from the
  existing per-approver Ed25519 design, not a drop-in change**, and BLS pairing verification is well
  known to only beat K individual Ed25519 verifies when K is large (tens-to-hundreds of signers, as in
  Ethereum validator sets) — at this repo's likely small quorum thresholds, K separate Ed25519 verifies
  are almost certainly *cheaper* than one pairing check. This family's usual motivation ("cheap enough to
  automate everywhere") needs the datacenter-scale caveat made explicit before being pursued.
- A dedicated membership-delta propagation channel over the mesh's existing gossip transport, distinct
  from and complementary to the peer-endpoint-candidate gossip FIS-0003 scoped out of covering this —
  needs its own anti-replay/ordering semantics respecting the strict sequential epoch chain
  `apply_signed_update` enforces.
- Push-based replication from the admitting node to every currently-known peer at admit time, rather than
  leaving fan-out to operator discipline or periodic pull polling — requires the admitting node to already
  have live reachability to the rest of the mesh, not always true for occasionally-connected members.

**Constraints.** Default-deny (§3) means any "fast path" must not quietly become the *default* trust
boundary for the mesh. Stays within `rustynet-control` (transport-agnostic) with backend-specific
delivery left to `rustynetd`/`rustynet-cli` (§8/§10.3). An aggregate-signature scheme is a
cryptographic-primitive decision requiring an audited crate, never a hand-rolled aggregate scheme (§3).

---

### ENR-3: The enrollment token itself is already appropriately lean and identity-free; the real disclosure question is the fully flat, un-compartmentalized trust roster every full member receives — and privacy-preserving/anonymous enrollment is not a stated Rustynet requirement today

**Current behavior.** Token mint is one CSPRNG draw plus one HMAC-SHA256 over a 32-byte random key
(`enrollment_token.rs:220-235, 255-286`) — no KDF stretching, correctly so since the key is already
high-entropy random material, not a password. Verify+consume is one HMAC recompute plus a
constant-time compare, and — contrary to what might be assumed — involves **zero network round-trips**:
both `rustynet enrollment admit` and the daemon's `EnrollmentConsume` IPC command are purely
local-machine operations (CLI args / local IPC socket). The token deliberately carries no identity, per
the module's own design comment and confirmed in the `EnrollmentToken` struct — good privacy hygiene
already in place. Once redeemed, though, the delta's canonical payload embeds the new node's full
Ed25519 pubkey, human-readable `owner` string, and role/capability list in **plaintext**
(`membership.rs:456-471`), and `Requirements.md:46-47` confirms `owner` is intentional required node
metadata, not an oversight. `MembershipState` is one flat `Vec<MembershipNode>` with **no per-viewer
filtering anywhere** — every full mesh member that applies or bundle-pulls the current state learns
every other member's owner name, role, capabilities, and pubkey, regardless of whether the two nodes
will ever route through each other.

**Honest scope check.** Grepping `Requirements.md`/`SecurityMinimumBar.md` for privacy/anonymity/
selective-disclosure terms in an enrollment context returns nothing on-topic (the sole tangential hits
are about log-retention policy and an unrelated Phase-8 "privacy maturity" mention). Requirements.md
explicitly requires `owner` as node metadata. **The honest read: full-roster disclosure to every member
is a deliberate, documented design choice, and anonymity/selective-disclosure between mesh members is
not a stated Rustynet goal today** — anyone pursuing the technique families below is proposing a
genuinely new privacy posture, not closing a documented gap. Rustynet also has no third-party
coordination server or CA ("no accounts, no SaaS-mediated identity, no third-party trust," module doc) —
so the classic anonymous-credential threat model (hide identity from an untrusted issuer/relay) has no
natural target here; the realistic question is member-to-member visibility within an already-mutually-
trusted roster, narrower and different from the usual anonymous-credential use case.

**Candidate technique families:**
- Blind signatures (RSA-blind per RFC 9474, or EC blind sig, Privacy-Pass lineage) so an issuer signs a
  token without linking it to redemption — the Rust crate `blind-rsa-signatures` (jedisct1) implements
  RFC 9474 and is real/maintained, but **no confirmed independent third-party security audit was found**
  as of this pass — treat maturity as unconfirmed, not "audited."
- BBS+/anonymous-credential schemes for selective attribute disclosure and unlinkable multi-show — Rust
  crates exist (`bbs`, `bbs_plus`, `signature_bbs_plus` from the docknetwork/Hyperledger DID ecosystem)
  and are used in real Verifiable-Credential deployments, but **likewise no confirmed independent audit**;
  would also introduce a new BLS12-381 dependency and trust-setup considerations alongside the existing
  Ed25519 scheme.
- zk-SNARK-based selective disclosure ("prove I am an active member with role=X without revealing which
  node") — **the clearest blocker of the three under this repo's audited-crate-only constraint**: the
  Rust ecosystem (arkworks, halo2, bellman) is real and active, but arkworks' own docs explicitly
  disclaim it as an academic proof-of-concept "not ready for production use," and existing audits (e.g.
  Trail of Bits on Axiom's Halo2 circuits) cover a specific application's hand-authored circuit, not a
  general reusable "prove membership" library. A Rustynet-specific circuit would mean hand-designing a
  new cryptographic protocol on top of a disclaimed-non-production library — in direct tension with both
  "no custom cryptography" and "audited crate only."
- Group/ring signatures ("signed by *some* quorum approver" without revealing which) — addresses
  approver-anonymity rather than enrollee-anonymity; no mature, clearly-audited Rust crate surfaced in
  this pass, likely also a blocker today.

**Constraints.** Since this is not a stated requirement, the first decision for whoever picks this up is
a **product decision** (does Rustynet want this posture at all), not an engineering one. Whatever is
chosen must still satisfy the no-custom-cryptography rule (§3) — every option above needs its audit
status re-verified at implementation time, since crate maturity changes and this is a July-2026 snapshot,
not a cryptographic review of the crates' own source.

---

## 8) Canonical serialization/wire-format efficiency across signed-state crates

### SER-1: The Tier-1 "zero-clone canonical builder" fix landed only in `membership.rs`; the identical anti-pattern is unfixed in 7+ other builders, with the auto-tunnel assignment builder as the highest-impact unfixed site

**Current behavior.** `DataplanePerfBacklog §1.6` documents two landed wins (commit `9719922`): hex via
nibble LUT and zero-clone canonical builders, credited in its own changelog to "membership, role_audit,
dns-zone, gossip_runtime." Reading the actual code: `membership.rs`'s three canonical builders were
genuinely rewritten to use `writeln!` into one pre-sized buffer with explanatory comments confirming a
deliberate perf pass — **that is the full extent of the landed fix.** The same `push_str(&format!(...))`
per-field pattern (a throwaway heap `String` per field, copied a second time into an *unsized*
`String::new()` accumulator — strictly worse than the pre-fix `membership.rs` pattern, since it's also
missing the pre-sizing) is still live, unfixed, in: `rustynet-dns-zone/src/lib.rs::serialize_dns_zone_payload`
(596-638, 8 `format!` calls per DNS record) — despite that **same file's own `hex_bytes` already being
migrated to the nibble-LUT form one function away and stopping there**; `rustynet-control/src/lib.rs`'s
`serialize_auto_tunnel_payload` (3747-3805, ~11 fixed fields + 5 `format!` calls per peer + 3 per route),
the endpoint-hint payload builder (~3850-3931, 6 `format!` calls per candidate), the relay-fleet payload
builder (4002-4030, 7 `format!` calls per relay), `serialize_traversal_coordination_payload`
(4256-4311); `key_rotation.rs::VerifierArchive::canonical_payload` (205-227) and
`PerEpochReplayWatermark::canonical_payload` (338-347); `rustynetd/src/key_rotation.rs::
LocalKeyRotationLedger::canonical_payload` (192-221, persisted every rotation event and re-derived every
load). Separately, `rustynet-control/src/lib.rs` still carries its **own un-migrated hex encoder** —
`hex_bytes` (3612-3618) does `hex.push_str(&format!("{byte:02x}"))` per byte, the exact anti-pattern
Tier-1 claims to have fixed — called ~25 times across the file for every public key, signature, HMAC, and
nonce in every bundle type it builds, including inside the per-peer loop of `serialize_auto_tunnel_payload`.

**Why it's a bottleneck.** `serialize_auto_tunnel_payload` is structurally the worst case: invoked once
**per target node**, and each call's inner loop serializes every peer the target is allowed to reach — a
full-mesh assignment refresh is O(N) peers-per-node × N nodes = **O(N²) peer-field serializations in
aggregate**, each peer costing 5 `format!`+`push_str` calls plus one `hex_bytes` call (32-64 more
`format!` calls) for the peer's public key.

**Impact/scale.** Direct in-repo precedent: the `perfprobe_membership` benchmark showed the same class of
fix cut canonicalization wall-time 34%, allocation count 63%, bytes/op 41% at N=50. The unfixed sites
aren't benchmarked, but the mechanism is identical, and `serialize_auto_tunnel_payload`'s O(N²) fan-out at
full-mesh scale makes it plausibly the single largest unfixed allocation source in the control-plane
canonicalization surface — larger in aggregate than `membership.rs`'s own pre-fix cost, which triggered
the original Tier-1 pass. Matters most at the upper end of 2-50 nodes (where auto-tunnel assignment's
O(N²) cost is heaviest), on Pi-class anchors issuing/verifying these bundles, and recurs at least every
few minutes per node (TTL-driven refresh cycles).

**Candidate technique families:**
- Mechanical port of the `membership.rs` Tier-1 pattern (single `writeln!`-into-one-pre-sized-buffer,
  sort-by-reference) to the remaining builders — lowest risk, byte-identical output, but 7+ separate call
  sites to touch and re-pin with round-trip/determinism tests each.
- Extract one shared "canonical key=value writer" helper (a small builder wrapping a `String` +
  `writeln!` with pre-sizing heuristics) used by all these builders — removes duplication and reduces the
  chance a future builder reintroduces the anti-pattern, at the cost of a new small shared abstraction
  every signed-bundle crate must depend on or vendor.
- Migrate the still-unfixed `hex_bytes` in `rustynet-control/src/lib.rs` to the same nibble-LUT technique
  already proven in `membership.rs`/`dns-zone` — trivial, isolated, no format change, directly closes the
  gap between what Tier-1's changelog claims and what actually exists in the file building the
  highest-call-volume bundle.
- A CI lint (a small grep-style gate, similar in spirit to `scripts/ci/check_backend_boundary_leakage.sh`)
  flagging new `push_str(&format!(` occurrences under `rustynet-control`/`rustynet-dns-zone` — stops the
  pattern being reintroduced or left half-migrated the way it was here; process fix, doesn't address
  existing debt.

**Constraints.** Pure allocation/CPU efficiency change, byte-identical canonical UTF-8 output — no touch
to §3/§8 backend-boundary rules, and does not conflict with `SerializationFormatHardeningPlan §8.1`'s
explicit "do not replace" decision for signed control-plane bundles (that plan is silent on
*construction-cost* efficiency for the format it mandates keeping). No unwrap/expect concerns. A
shared-helper option should be weighed against that plan's §10, which already proposes a shared
`crates/rustynet-serialization/` for a related-but-distinct purpose (typed CBOR/postcard artifact
envelopes) — the plan doesn't currently scope a canonical-text-writer helper either way; worth surfacing
to whoever designs the fix rather than assuming.

---

### SER-2: Membership audit-log append hex-encodes an already-hex-embedding envelope a second time purely to feed a hash function that doesn't care about text representation, and rewrites the entire on-disk log on every single append

**Current behavior.** `append_membership_log_entry` (`membership.rs:822-849`) computes
`encoded_update = signed_update.canonical_envelope()?` — which **already** hex-encodes the inner update
record's payload into a `payload_hex=...` field to safely nest multi-line canonical text inside the outer
line-oriented envelope. The caller then hex-encodes **this entire envelope a second time**
(`encoded_update_hex = hex_encode(encoded_update.as_bytes())`), concatenates it with `index|previous_hash|`
into `entry_material`, and feeds that straight to `sha256_hex(...)` to produce `entry_hash`. `entry_material`
is never stored or reparsed — it's discarded on the next line, existing solely as SHA256 input.
Separately, the same function calls `persist_membership_log(path, &entries)` after `entries` was just
loaded in full — `persist_membership_log` re-derives `canonical_envelope()` + `hex_encode()` +
`push_str(&format!(...))` for **every** entry in the log, not just the newly-appended one, and writes the
whole rebuilt file via atomic rename.

**Why it's a bottleneck.** SHA256 operates on raw bytes and has no notion of "ambiguous delimiters" —
hex-encoding `encoded_update` before hashing doubles the byte length of that string and pays a full extra
allocation+copy pass for a transformation whose only observable effect is changed hash-input bytes; the
anti-ambiguity goal (a raw envelope containing a literal `|` colliding with the field separator) can be
achieved by hashing components independently and combining digests, or an unambiguous length-prefixed
join, without touching every byte of the roster-shaped envelope. Compounding this, `persist_membership_log`
turns every accepted mutation into an O(n) operation over the full log, making cumulative write cost
**O(n²) over a mesh's operational lifetime** instead of true O(1) append — and this happens on the same
code path as the double-hex-encode, so the two effects compound on every `AddNode`/`RemoveNode`/
`RevokeNode`/`RotateNodeKey`/`RotateApprover`/`SetQuorum` operation.

**Impact/scale.** The double-hex-encode is a fixed ~2x-of-envelope-size waste per accepted update
(bounded, small per call). The O(n) full-log-rewrite is the more consequential piece: proportional to
total historical log length, recurring on every future update — a long-lived mesh with many accumulated
operations sees rewrite cost grow roughly linearly with history length on every single new operation, i.e.
O(n²) cumulative. Relevant across the whole 2-50 node range but the O(n²) mechanism specifically matters
more to long-lived meshes than to large-N meshes at a point in time — most noticeable on an anchor that's
been running a long operational period.

**Candidate technique families:**
- Hash `encoded_update.as_bytes()` directly with unambiguous binary framing (length-prefix each field
  before hashing, or hash `index`/`previous_hash`/`encoded_update` as separate digest inputs combined via
  a domain-separated chained hash) instead of hex-encoding the whole envelope first — removes one full
  allocation+copy pass per accepted update, no format change to what's persisted.
- True append-only log file: open in append mode, write only the new entry's line(s), maintain a
  separately-cached "last entry hash" in memory or a small sidecar rather than reloading and
  re-serializing the whole file every write — turns O(n) per-append into O(1), but changes the
  crash-recovery/atomicity story (the current design gets atomicity "for free" from rewrite-and-rename)
  and needs its own fsync/torn-write analysis before adoption.
- Periodic checkpoint + append-only tail: persist a full snapshot only every K entries, append-only the
  deltas since the last checkpoint — a middle ground keeping most of the current atomic-rewrite simplicity
  for the checkpoint while removing per-entry O(n) cost otherwise, at the cost of a more complex recovery
  path (checkpoint + replay tail).
- A dedicated Merkle/hash-chain library crate for the chain-hash construction itself instead of hand-
  rolling the `index|previous_hash|payload` concatenation — could simplify chain-hash correctness
  reasoning, but is a larger structural change to a security-relevant integrity mechanism, needing its own
  review against §3's "no custom cryptography" rule (the crate would need to be established/audited; the
  chaining *logic* is not itself a cryptographic primitive so this is likely in-bounds, but the later
  designer should confirm explicitly).

**Constraints.** The chain-hash/audit-log integrity mechanism is trust-sensitive (§4: anti-replay/rollback
protection, append-only audit-log entries per §10.7) — any change needs its own enforcement-point +
verification-test pair (§4) and must preserve fail-closed behavior on a corrupted/truncated log. The
O(1)-append candidate specifically trades away "atomic rewrite is inherently crash-safe" and needs
explicit justification that the replacement preserves the same crash-recovery guarantee.

---

### SER-3: Hex-nesting to embed multi-line canonical-text payloads inside outer line-oriented envelopes doubles the at-rest and on-wire byte size of every signed bundle — unaddressed by Tier-1 or by FIS-0003's gossip scope

**Current behavior.** Several signed-bundle envelopes nest one canonical-text payload inside another
line-oriented structure by hex-encoding the inner payload first: `persist_membership_snapshot`
(`739-750`) writes `state_hex={hex_encode(state_payload.as_bytes())}` as one snapshot line;
`canonical_envelope` writes `payload_hex={hex_encode(payload.as_bytes())}` so the update record's own
multi-line canonical payload can be embedded as a single line inside the outer envelope. This hex-wrapping
is structurally necessary given the current line-oriented-parser design (the inner payload contains
embedded newlines from its own `writeln!` calls; the outer envelope is itself parsed line-by-line) — but
hex is the most byte-expensive way to achieve it: it doubles the byte count of the *entire* inner payload
regardless of how much content is actually "unsafe" (contains a literal newline or `=`), because every
byte, not just unsafe ones, goes through the 2x hex expansion.

**Why it's a bottleneck.** For a canonical payload of size B (which scales with roster size —
`canonical_payload`'s own capacity estimate implies multi-KB payloads at even modest node counts), the
hex-embedding step produces a 2B-byte field, permanently baked into both the on-disk snapshot (fsync'd,
read back on every daemon start/reconcile) and, for envelope types that travel over the network, the
actual wire payload transferred. A pure 2x multiplier on bytes stored/transferred for the affected
fields, additive to SER-1/SER-2's allocation-count inefficiencies — a bytes-on-the-wire/disk cost, not a
CPU-cycles cost, that persists even after SER-1's allocation fixes land (those fixes preserve byte-
identical output by design).

**Impact/scale.** Explicitly relevant to two constrained-endpoint classes: occasionally-connected mobile
clients paying real per-byte cellular cost on every TTL-driven bundle refresh, and Pi-class anchors where
even a 2x reduction in parse/hex-decode work on a constrained CPU is proportionally larger than on a
desktop-class node. Explicitly out of FIS-0003's scope — that proposal covers only peer-endpoint-candidate
gossip bandwidth and its own scope note says the membership bundle's bandwidth profile is a "possible
future phase-4 extension only, never designed." Not independently measured against real fetch/transfer
telemetry — a real, code-confirmed mechanism, but its absolute bandwidth impact in bytes/month for a given
mesh should be quantified against actual bundle-fetch cadence before prioritizing.

**Candidate technique families:**
- Replace full hex-embedding with a minimal escaping scheme for the specific characters actually unsafe
  in the outer line-oriented format (embedded `\n` and the field-separator character only) — keeps the
  envelope as canonical UTF-8 text (compliant with the hardening plan's "signed control state: canonical
  text bundles only" policy) while approaching ~1x rather than ~2x expansion for typical content; adds
  escaping/unescaping logic needing the same round-trip/determinism-test rigor the hex approach already
  has.
- Restructure the envelope to use explicit length-prefixed framing for the nested sub-block (still text/
  canonical: `payload_len=<N>\npayload=<N raw bytes>` rather than a hex-string line) — avoids the 2x
  blowup entirely with no character-level escaping or hex expansion needed, but is a bigger structural
  change to the envelope grammar than a drop-in escaping helper, and needs reconciling against the outer
  parser's strictly-line-oriented parsing assumptions.
- Compress the resulting envelope before it hits disk/wire, orthogonal to the encoding scheme — would
  recover much of the 2x hex overhead (hex output is highly compressible) plus additional gains from the
  underlying text's own redundancy, but adds a new dependency and a compress/decompress step to every
  trust-boundary parse, needing its own bounded-decompression-size hardening (decompression bombs) to
  stay consistent with §4's bounded-decode requirement.
- Base64/Ascii85 as lower-expansion alternatives to hex for the same "embed arbitrary bytes as text"
  problem (base64 ~1.33x vs. hex's 2x) — a smaller, purely mechanical improvement within the same
  "stay as text" constraint.

**Constraints — direct tension with an existing locked decision.** `SerializationFormatHardeningPlan
§8.1` says "do not replace" the signed control-plane bundle format, and §15's post-migration policy states
"signed control state: canonical text bundles only." Any candidate that would turn these bundles (or the
nested sub-payload) into a binary/non-text representation — including zero-copy formats like `rkyv`, or
the plan's own CBOR/postcard recommendations (explicitly scoped to *other* boundaries — privileged IPC,
discovery/report artifacts — and explicitly excluded from the signed-bundle boundary) — would conflict
with that decision's stated rationale (human-reviewable for incident response, simple parser surface,
already aligned with watermark/signature handling). **This tension is flagged, not resolved**: whoever
designs the actual fix must decide whether the bytes-on-the-wire savings justify revisiting a deliberate
decision, or whether only the escaping/length-prefix families (which stay within "canonical text bundles
only") are in-bounds. The compression candidate carries the same tension implicitly (compressed bytes
aren't canonical UTF-8 text) even though the hardening plan doesn't name compression individually.

---

## 9) Pre-establishment NAT traversal / ICE candidate-gathering efficiency (`rustynetd::traversal.rs`, `stun_client.rs`)

*All three findings here are about connection-establishment **latency** — first-connection and reconnect-
after-roam responsiveness — a genuinely different "speed" dimension than the steady-state packet-forwarding
hot path `DataplanePerfBacklog` covers, and distinct from FIS-0001's post-establishment path-quality
re-scoring.*

### NAT-1: The ICE pair race's "fire ALL pairs concurrently" loop is actually a serial loop of expensive OS-mutation syscalls/process-spawns, not cheap datagram sends

**Current behavior.** `execute_ice_pair_race` (`traversal.rs:1860-2002`) builds a prioritized candidate-
pair list once (correctly outside the round loop), then for each of `simultaneous_open_rounds` (default
3) rounds, loops `for pair in &pairs { runtime.send_probe(...) }` over up to `max_probe_pairs` (default
24) pairs. The doc comment frames this as "fire ALL pairs of this round concurrently... each probe is one
outbound datagram." In production, `send_probe` (`Phase10PeerRuntime::send_probe`, `phase10.rs:98-109`)
calls `reconfigure_managed_peer(...)` **before** sending anything — which calls
`backend.update_peer_endpoint(...)` and then, unless the endpoint already matches (near-impossible across
distinct candidate pairs), `refresh_peer_endpoint_routes_and_attest()`, which unconditionally does
`rollback_routes()` + `apply_peer_endpoint_bypass_routes(&peers)` over **all** `self.managed_peers.values()`
(not just the probed peer) + `apply_routes(...)` + `assert_exit_policy(...)`. On Linux:
`update_peer_endpoint` spawns an external `wg set <iface> peer <pubkey> endpoint <ip:port>` process;
`apply_peer_endpoint_bypass_routes` spawns, per *unique* peer endpoint across the whole managed-peer set,
one `ip route get` plus one bypass-route-add call; `apply_routes` spawns one `ip route replace ... table
51820` per route plus one call per fail-closed-SSH-allow CIDR; `rollback_routes` spawns `ip route flush
table 51820`. All routed through the privileged-helper IPC client per the repo's argv-only privileged-
boundary hardening pattern. macOS shows the identical pattern. **Windows is worse per-call**:
`update_peer_endpoint` calls `apply_peer_runtime` (spawns `wg.exe set ...`) **and**
`sync_persistent_config()`, which re-renders the full peer config, DPAPI-encrypts it, and does an atomic
file write — on every single endpoint change (see WIN-2 for the full mechanism). By contrast, the
userspace-shared (boringtun) backend's `update_peer_endpoint` is an in-process call with no process spawn
— so this cost is backend-specific, but the command-line backends are the ones in use on Windows (no
userspace-shared backend exists there) and are the documented default on macOS.

**Why it's a bottleneck.** WireGuard peer objects have exactly one active endpoint at a time — there's no
"send N independent probes and listen for whichever replies" primitive at this layer. So "probing pair 2"
after "pair 1" is not appending a second in-flight datagram; it's rewriting the single peer's endpoint
(external process spawn) and, because the route-refresh step is unconditional and mesh-wide rather than
scoped to just the endpoint that changed, redoing a full route-table rollback+reapply touching every
*other* managed peer's bypass route too — synchronously, in a plain `for` loop with no `tokio::join`/
`spawn_blocking` fan-out. Round N's total wall-clock cost before the code even checks for a handshake is
proportional to (pairs-in-round) × (external command invocations per candidate switch, itself scaled by
total managed-peer count via the mesh-wide route refresh) — O(pairs × total_mesh_size) privileged
external-process invocations per round, not O(pairs) cheap sends.

**Impact/scale.** With defaults (24 pairs, 3 rounds) a single peer's traversal negotiation can trigger up
to 72 endpoint-rewrite events; each that actually changes the current endpoint (the common case) fans out
into ≥2 additional external route commands per unique peer endpoint across the *entire* managed-peer set,
plus a table flush and full reapply. Directly scales with mesh size within 2-50 nodes: a node near 49
peers pays a route-refresh cost during *every* candidate probe of *every* peer's traversal race, not just
its own. Exercised on both first-connection and reconnect-after-roam, worse on Pi-class anchors where
fork/exec and IPC round-trips are proportionally more expensive.

**Candidate technique families:**
- Coalesce the mesh-wide route refresh out of the per-candidate-switch hot path — recompute/apply the
  route table once per race (or only when the *set* of expected routes actually changes) instead of on
  every single reconfigure call; requires carefully re-deriving which parts of the refresh are genuinely
  endpoint-dependent vs. one-time-per-race, and must not create a fail-closed gap.
- Replace repeated single-purpose `ip`/`wg` CLI invocations with a single batched/atomic apply where the
  tool supports it (`wg syncconf` applies a whole peer-config diff in one invocation instead of many
  `wg set` calls; Linux route mutations could move to batched rtnetlink messages via an audited crate
  like `rtnetlink`/`netlink-packet-route` behind the existing `System` trait) — real engineering lift,
  Linux-specific, doesn't help macOS/Windows without separate platform work, and moves further from the
  "argv-only exec, no shell construction" simplicity the current design values for auditability.
- Diff-based route apply: the code already tracks "expected" route sets — a mutation could be skipped
  when the computed target state already matches the last-applied state, converting most of the 72
  per-race refreshes into no-ops — adds cache/staleness-tracking complexity to a security-sensitive
  fail-closed path, with a real risk of a stale-route TOCTOU window if the cache diverges from actual
  kernel state under a crash/restart.
- Decouple "trying a candidate" from "committing a candidate": probe reachability on a lightweight local
  socket that is *not* the configured WireGuard peer endpoint (ICE connectivity-check style), only paying
  the reconfigure cost once for the winning pair — WireGuard's Noise handshake state is tied to the
  interface/peer object, so a pre-check needs its own out-of-band liveness signal rather than a real WG
  handshake, and needs care not to introduce a new trust decision.
- Move probing work preferentially onto the userspace-shared backend (already in-process, no spawn) for
  platforms where it's available (Linux/macOS) — doesn't help Windows at all, and reprioritizing which
  backend is "default" is a larger project decision beyond this probe loop.

**Constraints.** Must preserve the `Backend` trait boundary (§8/§10.3) — no candidate here requires
leaking a WireGuard type into a domain crate. Must preserve "argv-only exec for helpers, no shell
construction with untrusted values" (§4) — any batching must stay argv-based. Must not weaken default-
deny/fail-closed route application (§3/§4) — any diff-based skip-if-unchanged optimization needs a
negative test proving it cannot leave a stale/missing route in a trust-sensitive state.

---

### NAT-2: Round-timing structure gives the final round's own probes zero observation window; every round's effective RTT budget is a fixed 80ms constant, not adaptive to the actual path

**Current behavior.** In `execute_ice_pair_race`'s round loop, each iteration: (1) waits `round_delay -
elapsed` (`round_spacing_ms × round`, default 80ms), (2) sends all pairs for that round, (3) immediately
calls `runtime.latest_handshake_unix()` with **zero further wait**. Because step 3 happens instantly after
step 2's sends, a round's check is really evaluating the *previous* round's probes (which had exactly one
`round_spacing_ms` of wall-clock time during the *next* iteration's wait). The final round (index 2 by
default) is sent and checked with zero wait window; if that check finds nothing, the loop simply ends and
falls straight into `relay_or_fail_closed_for_race` **without ever giving that last round's just-sent
probes a chance to be observed** within this function call.

**Why it's a bottleneck.** Architectural/timing issue independent of NAT-1's process-spawn cost — even
with instant, free probe sends, the round structure (a) wastes one full round of probing (up to
`max_probe_pairs` datagrams) whose outcome the function commits a decision without ever checking, and (b)
bounds every *other* round's effective observation window to exactly `round_spacing_ms` regardless of
actual path RTT, so any path where RTT + WireGuard Noise handshake completion exceeds 80ms will
systematically fail to observe a real success before falling back to relay/fail-closed.

**Impact/scale.** Total genuinely-observed probing time is bounded to `(simultaneous_open_rounds-1) ×
round_spacing_ms` = 160ms with defaults, regardless of how many rounds/pairs are configured (arithmetic
consequence of documented defaults, not independently benchmarked). Matters most for the occasionally-
connected/cross-network/cellular scenarios the dataplane execution plan targets (higher, more variable
RTT than same-LAN lab topology, where sub-5ms RTT makes 80ms generous) — largely invisible in the LAN
live-lab environment this repo currently proves stages against, which is exactly why it could persist
unnoticed.

**Candidate technique families:**
- Give the final round a genuine post-send observation wait (one more `round_spacing_ms`, or a
  measured/estimated RTT) before falling to relay/fail-closed — adds fixed latency specifically to the
  guaranteed-failure case (paths with truly no direct route now take longer to declare that).
- Make `round_spacing_ms` adaptive to an observed or estimated RTT (e.g. derived from STUN response
  round-trip time already measured during candidate gathering) instead of a fixed constant — needs new
  plumbing from gathering into engine config; STUN-server RTT is not guaranteed representative of the
  actual peer-to-peer path RTT.
- Poll handshake state at a finer sub-interval between sends (every 10-20ms) rather than only once per
  round boundary, so a fast responder is detected sooner without waiting a full `round_spacing_ms` — more
  calls to `latest_handshake_unix()` (cheap on command backends, a state read not a process spawn), but
  adds polling complexity and needs a bounded polling budget.

**Constraints.** Must preserve the fail-closed default (§3/§4): a decision must still resolve to Relay or
FailClosed rather than hang indefinitely, and must not weaken `handshake_is_fresh`'s freshness/trust
check.

---

### NAT-3: STUN candidate gathering is well-optimized on the raw-socket path; a second, genuinely serial STUN path exists in production for the shared/authoritative transport, and the two independent STUN implementations have already silently diverged in retry robustness

**Current behavior.** Three STUN gathering code paths exist, not one. **(1)**
`CandidateGatherer::query_stun_servers_batched` (`traversal.rs:296-413`, doc-labeled FIS-0011) fires
every server's binding request up front with its own transaction id, runs a single receive loop demuxing
by source+tx-id until a shared deadline, **with** a per-server RTO-doubling retransmit ladder
(`STUN_INITIAL_RTO=250ms`, `STUN_MAX_REQUEST_ATTEMPTS=3`) tolerating one lost datagram per server. **(2)**
`StunClient::gather_mapped_endpoints_batched` (`stun_client.rs:122-194`, doc-labeled FIS-0018)
independently reimplements the same fire-all-then-collect-by-deadline pattern (its own hand-written STUN
wire-format implementation, separate from traversal.rs's) but with **no retransmit ladder at all** — each
server is queried exactly once; one dropped datagram silently drops that server's candidate for the whole
gather cycle. **(3)** `StunClient::gather_mapped_endpoints_with_round_trip`
(`stun_client.rs:198-240`), used in production by `daemon.rs::poll_stun_results` whenever the backend
exposes `authoritative_transport_round_trip` (the userspace-shared/boringtun path, needed so the returned
srflx candidate reflects the NAT mapping of the *same* socket that will carry peer traffic), is explicitly
**sequential by design**: `for server in &self.servers { round_trip(...) }`, with the code's own comment
stating "the authoritative round-trip transport is a hard singleton (queries must stay sequential),"
mitigated only via budget-slicing (`per_server_slice` = total timeout / server count), not true
concurrency.

**Why it's a bottleneck.** For path (3), a slow-but-eventually-responsive first STUN server consumes up to
its full timeout/N slice before the second server is even attempted — true serial-sum latency rather than
the max-of-N latency the batched paths achieve. Separately, paths (1) and (2) are two independently
maintained reimplementations of the identical idea that have already drifted apart in a way that matters
for correctness-under-loss, not just style: (2) has no loss tolerance where (1) does.

**Impact/scale.** With defaults (2000ms timeout, e.g. 3 configured STUN servers), `per_server_slice` ≈
666ms for path (3); a slow-first-server case adds up to ~666ms of pure serial wait before the second
server is even tried, versus near-zero added latency for the same scenario under the batched design (an
arithmetic consequence of documented defaults, not a live measurement). Affects the userspace-shared/
boringtun backend specifically and repeats on a periodic poll timer, so a single persistently slow or
unreachable configured STUN server becomes a recurring, compounding latency tax rather than a one-time
cost. The raw-socket batched paths (1)/(2) already meet the "send probes to multiple candidates
concurrently" bar — no further work obviously needed there.

**Candidate technique families:**
- True concurrent multiplexing over the single authoritative transport by transaction id, mirroring the
  raw-socket batched design (fire all N requests through the one round-trip channel, demux replies by
  tx-id as they arrive under one shared deadline) — feasible only if the underlying worker channel can be
  extended from one-request-one-response to fan-out/fan-in; needs verification against the actual
  userspace-shared worker API, real engineering lift.
- Reorder servers by recent observed latency/health so the first server tried is usually the fast one,
  without changing the sequential structure — needs a small persistent per-server health/latency cache;
  doesn't fix the worst case, only improves the common case.
- Give the sequential path a short RTO+retry ladder per server (mirroring FIS-0011's approach) instead of
  one large timeout/N wait, so a genuinely dead server is detected and skipped faster than its full slice
  — still fundamentally serial-sum latency, just with a smaller constant.
- Consolidate the two independent batched STUN wire-format implementations into one shared implementation
  so retry/robustness behavior cannot silently diverge again — a correctness/maintainability fix more
  than a speed fix, but grounded directly in the observed drift; worth flagging alongside the concurrency
  finding since a later agent fixing STUN gathering should not fix only one of the two copies.

**Constraints.** This is a pure network-I/O/RTT and transport-singleton-ownership problem — no
cryptographic or exotic-data-structure technique fits it, and none is forced in here. Any fix to the
singleton transport's concurrency must preserve the property that the returned srflx candidate reflects
the exact socket used for peer traffic (the whole reason path (3) exists rather than always using the
raw-socket path).

---

## 10) Relay-fleet accounting efficiency and privacy-preserving usage accounting (`rustynet-relay`)

*FIS-0007 already covers **which** relay a session picks (load-aware selection) and per-session fairness
(DRR) — none of the three findings here restate that.*

### RLY-1: The rate limiter's `HashMap<String,_>` forces a heap allocation on every forwarded relay frame via `entry()`'s owned-key requirement

**Current behavior.** `RateLimiter { buckets: HashMap<String, TokenBucket>, .. }`
(`rate_limit.rs:8-14`). `check_packet` is `self.buckets.entry(node_id.to_owned()).or_insert_with(...)` —
`HashMap::entry` takes its key by value, so `node_id: &str` must be converted to an owned `String` (heap
alloc + memcpy) *before* the lookup can even run, on every call, whether or not the bucket already
exists. The sole call site is inside `RelayTransport::forward_packet`, the per-datagram relay hot path
invoked once per forwarded UDP frame. `DataplanePerfBacklog §1.5` already identified this as "the
relay's single remaining alloc/op" from a fixed-work probe but explicitly left the fix unproposed — that
probe uses a 1-byte node_id, which is why its measured `alloc_bytes_per_op` reads ≈1B; real node_id
strings (unbounded length, only validated as non-empty+unique) will allocate more bytes per call, though
the dominant cost of a small heap allocation is typically allocator-call/lock overhead, not the copy
itself. Two lower-frequency sites share the identical pattern: the per-cleanup-tick pruning path
(`active_nodes: HashSet<String> = self.sessions.values().map(|s| s.node_id.clone()).collect()`) and the
per-hello linear node-session-count check.

**Why it's a bottleneck.** In a relay whose own perf pass got everything else in the forward loop down to
a ~156ns/frame, zero-syscall, zero-copy steady state, this is the one call that still touches the global
allocator every frame — allocator contention (especially under multiple concurrent `spawn_forward_task`
tasks hitting it through the shared `transport.write().await` lock) turns into both added per-frame
latency and allocator-lock contention distinct from the already-tracked P2 backlog item (which is about
the recv-loop poll+lock, not this allocation).

**Candidate technique families:**
- Two-phase get-then-insert (std-only, zero new dependency): `if let Some(bucket) =
  self.buckets.get_mut(node_id) { .. } else { insert with node_id.to_owned() }` — `get_mut` accepts a
  borrowed `&str` key via `Borrow<str>`, so the hot (existing-node) path does zero allocation; only the
  cold (first-frame-for-a-new-node) path pays the owned-key cost, once per distinct node_id rather than
  once per frame. Smallest possible diff, no new supply-chain surface.
- `hashbrown`'s raw-entry API (`raw_entry_mut()`) used directly instead of std's `HashMap` — same benefit
  as the two-phase pattern as a library primitive; `hashbrown` is already resolved twice in this
  workspace's `Cargo.lock` transitively, so promoting it to a direct dependency isn't a brand-new unvetted
  crate. Caveat: raw-entry has historically been an experimental/unstable-surface API even within
  standalone `hashbrown` — verify API stability against the pinned version before relying on it long-term.
- Interned `Copy` handle assigned once at session-establishment, mirroring an existing precedent in this
  exact file (`RelaySession.paired_session_id: Option<SessionId>`, a `Copy [u8;16]` cached specifically to
  avoid rebuilding an owned pairing key on every frame): assign a small `Copy` node-handle (e.g. `u32`)
  once in `handle_hello` via a `HashMap<String,u32>` interning table, store it on `RelaySession`, key
  `RateLimiter`'s buckets by the handle. Most invasive option (touches `RelaySession`, hello handling,
  bucket lifecycle/pruning), but removes the allocation on 100% of frames including the first for a
  brand-new node_id. **Must stay keyed by the interned `node_id`, not `SessionId`**, or it silently
  changes the token bucket from shared-per-node (today, up to `max_sessions_per_node`=8 sessions share
  one bucket) to fragmented-per-session — a real security-adjacent semantic risk if implemented carelessly.
- `Arc<str>` for `RelaySession.node_id`/`peer_node_id` (and the rate-limiter/pair-index keys) instead of
  `String`, populated once at hello-time; `check_packet` clones an `Arc` (atomic refcount bump, not a
  heap alloc+copy). Smallest behavioral diff of the four but widest textual diff — `node_id`/
  `peer_node_id` are compared at roughly a dozen sites across `transport.rs` that would all need the type
  change threaded through.

**Constraints.** None of these touch the security-relevant token-bucket math itself
(`TokenBucket::check_and_consume`/`refill`) — pure data-structure/allocation changes. The interned-Copy-
handle family is the one with a real semantic-preservation caveat, spelled out above. Any fix should
carry through to the two adjacent String-keyed sites for consistency, though those aren't hot-path-critical
themselves.

**Impact/scale.** Matters at any relay pps level, including a single home-server relay serving one
2-8-session mesh member — the cost is per-frame, not per-session-count. More likely to be perf-visible on
the Pi-class anchor/relay hardware this project explicitly targets than on a beefy dev host, since
allocator overhead is proportionally larger on constrained CPUs.

---

### RLY-2: *(corrected)* Relay usage accounting is aggregate-only today (nothing to make private yet); an unimplemented "Zero-Knowledge Relay" design already exists elsewhere in the repo and needs reconciling, not rediscovering

**Correction to the original finding.** The initial hunt claimed a documents-wide grep for privacy/
anonymity/ZK terms in relay context returned zero hits. This was **false**, caught by the verify pass:
`documents/operations/active/CrossNetworkRemoteExitNodePlan_2026-03-16.md` §5.3.1, titled *"Architectural
Principle: Zero-Knowledge Relay,"* states the relay operator "cannot correlate flows beyond session
lifetime" as an explicit design goal — directly on-topic and squarely inside the search terms the
original finding claimed returned nothing. This is a genuine index-level source-of-truth document
(indexed in both `documents/README.md` and `documents/operations/active/README.md`), so it counts as
"the project has stated this as a goal somewhere," even though it describes a different, more elaborate
(nested TLS/Noise) transport design than the leaner ed25519-token scheme actually shipped.

**Current behavior.** The relay's only usage telemetry is two global atomics,
`ForwardStats { frames_forwarded_total, bytes_forwarded_total }`, incremented on every successful
forward, exposed only as workspace-wide sums via `/health` and `/metrics` — **there is no per-node_id or
per-SessionId counter anywhere.** So today the relay cannot answer "how much did node X use" at all,
privately or otherwise — the feature this section's premise assumes exists has not been built. What the
relay's session layer *does* know in plaintext, per session: `node_id`/`peer_node_id`, carried in the
ed25519-token-authenticated `RelayHello`, compared with `ConstantTimeEq` (constant-time to prevent
timing side-channels on the *comparison*, not to hide the values from the relay operator, who is the
party doing the comparing). Beyond the CrossNetworkRemoteExitNodePlan §5.3.1 hit above, the only other
stated relay privacy/trust requirement is `Requirements.md:396`: "treat relays and coordination as
untrusted for traffic *confidentiality*" — i.e. the relay must never see plaintext payload *content*
(already satisfied: "ciphertext-only: relay never sees plaintext") — a different property from hiding
*who is talking to whom and how much*. The locked architecture
(`RustynetDataplaneExecutionPlan_2026-05-18.md:35,113`) fixes the relay as a **self-hosted,
single-mesh home-server component** — "no rented VPS, no SaaS, no third party" — and
`AnchorNodeRoleDesign_2026-05-21.md:74` notes relay co-location with the anchor is "by convention," so an
anchor without relay is valid, meaning the relay can be run by a *different member of the same mesh*, not
a third party.

**Why this matters (or doesn't).** Two separate facts, not to be conflated: (1) there's no non-private
accounting to make private yet; (2) the project *has* stated a "relay operator shouldn't correlate flows"
goal, but only in one unimplemented, more elaborate design document — the shipped architecture's dominant
deployment shape (one mesh, one self-hosted relay, operator == mesh owner in the common case) weakens the
practical motivation for hiding usage from the relay's own operator in *that* common case. The one place a
privacy motivation is plausible and *now documented as a real, if unimplemented, goal*: the "relay lives
on a different peer" case — a mesh member running the shared relay could observe a *different* member's
session-level metadata even though they're in the same trust domain for membership/ACL purposes. That's a
narrower, intra-mesh, opt-in-topology scenario, not the "public/commercial relay-as-a-service operator"
framing the technique families below are usually built for — applying those tools where the underlying
threat model differs from their design target risks solving the wrong problem.

**Candidate technique families:**
- RSA blind signatures / Privacy-Pass-style unlinkable admission tokens (RFC 9474; `blind-rsa-signatures`
  crate, the same construction Cloudflare/Apple use in production Privacy Pass) — the control plane
  blind-signs a token at issuance so the relay can verify "validly issued" at redemption without linking
  redemption back to issuance. Addresses identity-*linkability at the token layer*, not volume secrecy;
  doesn't by itself let the relay avoid learning `node_id` for pairing/forwarding — the pairing mechanism
  would need a parallel redesign around anonymous credentials, a materially bigger protocol change than
  swapping a crypto primitive.
- VOPRF-based tokens (IETF Privacy Pass v1 lineage, `voprf` crate) — same threat-model target, smaller
  tokens, EC-based rather than RSA-based; **maturity/audit status not independently verified** to the same
  degree as `blind-rsa-signatures`' RFC 9474 lineage.
- Zero-knowledge range proofs (`bulletproofs` crate, dalek-cryptography, Ristretto over curve25519-dalek)
  for "this session used ≤N bytes" without revealing the exact count — the core range-proof path has had
  a real third-party security review (Quarkslab, commissioned by Tari Labs, 2019, no critical findings
  against `subtle`/`curve25519-dalek`/`bulletproofs`), unlike the R1CS/`yoloproofs` experimental surface
  of the same crate, which is explicitly unsuitable for deployment. **The only family here that addresses
  volume secrecy rather than identity linkability** — a genuinely different property. Bulletproofs
  generation/verification is millisecond-scale, not viable per-packet — would only make sense as a
  periodic (per-billing-window) batch settlement proof layered on top of ordinary per-frame forwarding.
- Pairwise pseudonymous session identifiers minted by the mesh's own control plane, no new crypto library
  (reuse the `ed25519-dalek` already a `rustynet-relay` dependency) — the control plane issues each
  pairing a rotating per-pair token the relay sees instead of the durable `node_id`, decoupling the
  relay-visible identifier from long-term identity while leaving existing rate-limit/pairing/ACL mechanics
  structurally intact. Lowest new-dependency cost, only option composing cleanly with the existing
  single-verifier-key trust model — but this only hides *identity*, not volume/timing, and (like Tor's own
  documented limits) any relay operator can still correlate two pseudonymous sessions via packet-
  count/timing side channels without cover traffic, which none of these four families provide and which
  is a materially larger, unscoped design cost.

**Constraints.** §3/§4's default-deny/fail-closed mandate structurally requires *someone* in the request
path to know who is asking before granting service — today that's the relay itself. Any scheme making the
relay unable to see `node_id` at all must relocate the identity-based admission/rate-limit decision to
token-issuance time at the control plane, leaving the relay to verify only "possession of a validly
issued, not-yet-spent credential" — a real protocol redesign needing the same scrutiny as any other
trust-sensitive workflow (§5: one enforcement point + one verification test per control). All four
families use only established libraries (no custom cryptography per §3); two of the four (VOPRF maturity;
bulletproofs' non-range-proof surface) need their exact crate/scope re-verified before any implementation
commitment. **Whoever picks this up should first read `CrossNetworkRemoteExitNodePlan §5.3` in full and
decide whether to build toward that design's stated goal, adapt it to the shipped ed25519-token
architecture, or explicitly supersede/retire it** — not treat this as green-field.

---

### RLY-3: One UDP socket + one tokio task per relay session ("allocated-port demultiplexing") vs. QUIC-datagram multiplexing — a real architectural tradeoff, but the FD-scaling problem it would solve already has a documented operational fix, and real session counts at target scale sit far below where either fix matters

**Current behavior.** The relay's module doc names the design: *"allocated-port demultiplexing... each
session gets a unique allocated port for ciphertext forwarding."* `allocate_port` binds a fresh
`UdpSocket` to a free port (default range 50,000-59,999) for every accepted session;
`spawn_forward_task` then spawns one dedicated tokio task per allocated port — the *port itself* is the
session-demux key, with zero payload parsing needed to identify the session.
`DEFAULT_MAX_TOTAL_SESSIONS: usize = 4096`. `documents/operations/Arm32BitEmbeddedSupportReference_
2026-06-23.md §10` already documents the direct consequence: *"the relay allocates one UDP socket per
active session. At the default `--max-total-sessions 4096`, approximately 4130 file descriptors are
needed. The system default `ulimit -n 1024` is insufficient"* — with an **operational fix already
specified** (`LimitNOFILE=8192` in the systemd unit, or `--max-total-sessions 32` for embedded 1-3-peer
deployments, "~60 fds needed"). `rustynet-relay/Cargo.toml` has no QUIC/TLS dependency today — the only
crypto dependency is `ed25519-dalek` for the existing `RelayHello` token scheme.

**Why this is a real tradeoff, not just a bug.** Socket+task count scales 1:1 with concurrent sessions,
so at high session counts a relay needs proportionally many FDs and OS-scheduled tasks — the documented
constraint above. This is orthogonal to the already-tracked `DataplanePerfBacklog` P2 item (about *how*
each per-port task waits, not *how many* sockets/tasks exist). A QUIC-datagram-based transport (RFC 9221;
supported by both `quinn` and AWS's `s2n-quic`, the latter additionally Kani-model-checked) would collapse
the per-session socket+port+task model into one shared UDP socket wrapped in one QUIC endpoint, with
sessions multiplexed as QUIC connections/streams — removing the FD-count and port-range-exhaustion path
entirely. **But** this moves session identification from **free** (kernel 5-tuple/port demux, which is
exactly what makes `forward_packet`'s session lookup O(1) with zero payload trust decisions) to
**CPU-costly** (every inbound datagram must go through QUIC's own connection/stream demultiplex and, since
QUIC always encrypts even the unreliable-datagram extension — it rides inside the QUIC-negotiated TLS 1.3
record layer — a full decrypt step) on the exact hot path `DataplanePerfBacklog §1.5` just got to
~156-187ns/frame with zero allocations and zero syscalls beyond the unavoidable recv/send. Relayed
payloads are already WireGuard ciphertext, so wrapping them in QUIC means **encrypting already-encrypted
bytes a second time** — real CPU cost on the Pi-class relay/anchor hardware this project targets.

**Reality check on urgency.** No FD-exhaustion has been measured as an actual incident in this repo's
live-lab evidence. The Arm32Bit doc's numbers are a documented *projection* from the default
`--max-total-sessions=4096`, not an observed failure. Real session counts at target scale are far lower:
`max_sessions_per_node` defaults to 8 and the architecture caps a mesh at 2-50 nodes, so worst-case
concurrent sessions on one relay (≈50 nodes × 8) is on the order of a few hundred — the Arm32Bit doc's own
embedded guidance already recommends `--max-total-sessions 32` for realistic 1-3-peer deployments ("~60
fds needed"), well under even the unmodified 1024 default ulimit. **This is the clearest case in this
document of a technique whose benefit is explicitly scale-gated and, on the evidence read, likely not
reached at Rustynet's actual target scale** — recorded honestly rather than manufacturing urgency: the
FD-scaling problem is real and already has a working operational mitigation; QUIC is a legitimate
technique family worth recording for the record, but adopting it trades a currently-free, already-
optimized hot path for a CPU-costlier one, to solve a resource ceiling this project's own docs show is
not currently being approached at the deployment scale the architecture is locked to.

**Candidate technique families:**
- QUIC-datagram multiplexing via `quinn` — pure-Rust, widely adopted, confirmed RFC 9221 support.
  Tradeoff: collapses N sockets/tasks to ~1, but adds a full TLS 1.3 handshake/identity substrate that
  must somehow interoperate with or replace the existing ed25519 `RelaySessionToken` scheme, and converts
  the currently-free kernel-level session demux into a per-packet application-level decrypt+demux.
- QUIC-datagram multiplexing via `s2n-quic` — AWS-authored, same RFC 9221 support, additionally uses the
  Kani model checker for memory/type/correctness properties on parts of the implementation. Same
  fundamental tradeoffs as `quinn`; choice between the two is an implementation-maturity/API-fit question
  this document doesn't resolve.
- Leave the current model in place and rely on the already-documented operational fix (raise
  `LimitNOFILE`, or cap `--max-total-sessions` to the deployment's real peer count) — zero new code, zero
  new dependency, already the specified mitigation for embedded deployments. Doesn't reduce per-session
  OS resource cost, only raises the ceiling.
- A lighter-weight application-level multiplexing scheme keeping a single shared UDP socket but
  demultiplexing sessions via an explicit `SessionId` prefix in the datagram itself (closer to the
  *control* socket's existing model) instead of pulling in a full QUIC stack — avoids the double-
  encryption/TLS-substrate problems, but reduces (doesn't eliminate) the demux-cost shift, since the
  relay would still need to read and trust-check a session identifier from packet content rather than
  getting it free from which socket the OS delivered on; also a bigger wire-format-surface change than any
  of RLY-1's options, since it changes what ciphertext-relay clients speak to the relay.

**Constraints.** §3's "WireGuard must remain an adapter behind stable backend abstractions" and "no
custom cryptography/VPN protocol invention" are not structurally violated on their face — WG ciphertext
still flows end-to-end unchanged through the relay; QUIC would only be the relay-hop carrier, using
established crates. But §3's "one hardened execution path per security-sensitive workflow, no runtime
fallback/legacy branch" is real friction: introducing QUIC's own TLS-based peer authentication alongside
the existing ed25519-signed `RelayHello` token model means either two parallel security-sensitive auth
paths (explicitly discouraged) or a full replacement of the token scheme with QUIC-native auth (raw
public keys pinned to the same ed25519 identities — plausible but a materially larger, independently-
reviewable change than anything else in this section). The locked non-goals ("no external relay host...
no DERP fleet") don't prohibit a QUIC relay-transport outright but confirm the deployment model it would
need to justify itself against is a single self-hosted home-server relay, not a multi-tenant VPS fleet.

---

## 11) Concurrency and lock architecture outside the packet-forwarding hot path (`rustynetd` control plane)

*`DataplanePerfBacklog` already covers per-packet engine/relay locking — all three findings here are
about everything else.*

### CCY-1: There are no locks because there is no concurrency — the entire control plane is one cooperative single-thread reactor loop, so any blocking call anywhere stalls every other subsystem including DNS resolution, worst case unboundedly via a missing write-timeout on the admin IPC socket

**Current behavior.** Grepping the whole `rustynetd` crate for `Mutex`/`RwLock` outside `#[cfg(test)]`
fixtures returns **zero production hits** — `DaemonRuntime` (60+ fields) is owned and mutated by exactly
one OS thread. `run_daemon` binds a nonblocking `UnixListener` and a nonblocking DNS UDP socket, then
runs a single loop that, once per pass, sequentially: checks shutdown, accepts at most one IPC connection
and handles it fully in-line including signature/ACL checks, drains all pending DNS queries, polls the
anchor-bundle-pull listener, runs `reconcile()` on the 1s cadence, then unconditionally calls
`poll_stun_results`/`maybe_refresh_port_mapping`/`maybe_preexpiry_refresh_traversal`/
`poll_endpoint_monitor_and_maybe_refresh`/`maybe_trigger_endpoint_change_refresh`/
`drain_gossip_inbound`/`maybe_run_gossip_mint` before an idle sleep capped at 25ms. `GossipTransport`
itself is a nonblocking UDP socket polled with `Duration::ZERO`, consistent with the single-thread model
rather than a dedicated gossip thread. **Concretely dangerous instance:** once an IPC connection is
accepted, a 2s read timeout is set inline but `read_command_envelope` immediately re-sets it to 5s — and
`write_response` calls `stream.write_all(...)` with **no write timeout configured anywhere** on that
Unix admin-control socket (the crate's only two `set_write_timeout` calls are on unrelated
NAT-PMP/anchor-bundle-pull TCP streams). Because DNS answering runs strictly after the accept/handle
block completes in the same pass, a slow or wedged local admin-IPC client (e.g. a CLI process that stops
reading its response) can stall Magic DNS resolution, reconcile, and gossip processing for the whole
mesh for up to the 5s read timeout on the read side, and for an **unbounded** duration on the write side.

**Why it's a bottleneck.** The single reactor thread is the de facto global lock every subsystem contends
on — except it's implicit (one instruction pointer, no lock object) rather than an explicit
Mutex/RwLock, so the task's usual "lock held across an await point" pattern can't literally occur (no
async runtime anywhere in `rustynetd` — zero `tokio::spawn`/`async fn` hits), but the functional analogue
is present and worse: a *synchronous blocking OS call* anywhere in the loop body has the identical
serializing effect a held lock would, with no compiler or runtime signal marking the hazard. `reconcile()`
additionally performs multi-stage, potentially slow work directly in this loop:
`apply_generation_stages` contains `for peer in &peers { self.backend.configure_peer(peer.clone())?; }` —
one sequential blocking backend call per peer (up to ~49 for a 50-node mesh), each resolving to either a
subprocess spawn (Windows) or a privileged-helper IPC round trip (Linux/macOS) — plus firewall/killswitch/
NAT/DNS-protection/route application stages, all synchronous, all on the same thread that must keep
answering DNS queries in real time.

**Impact/scale.** Bites immediately at N=1 (a single stalled local admin-IPC client freezes DNS answering
for everyone on the mesh's Magic DNS zone) and gets systematically worse toward the 50-node ceiling
because peer-apply is O(peers) sequential blocking calls. Disproportionately affects Pi-class anchors,
most likely to see slow subprocess-exec/privileged-helper-IPC latency under load — precisely the work
embedded in this loop. No benchmark exists for reconcile-loop latency under a stalled IPC client or a
full peer-apply sweep — the write-timeout gap is a concrete, code-verifiable availability hazard
(unbounded stall) independent of node count; the O(peers) sequential-apply cost scales with mesh size.

**Candidate technique families:**
- Message-passing/actor decomposition — split reconcile/apply, gossip, DNS responder, and admin-IPC server
  into separate OS threads (or tokio tasks if async is ever adopted), each owning its own state and
  communicating via mpsc/crossbeam channels. **This exact pattern already exists in-repo**: the Windows
  control-pipe implementation has a dedicated `rustynetd-control-pipe` thread doing the blocking pipe I/O
  and only forwarding parsed `(request_bytes, response_sender)` via `mpsc::channel` to the main loop,
  which drains it non-blockingly — but the Unix admin-socket path (the CLAUDE.md-designated "done
  reference" platform) does not use it, embedding blocking accept/read/write directly in the reactor loop
  instead. Removes head-of-line blocking structurally; costs real implementation/testing surface and
  requires re-deriving today's implicit single-writer invariants as an explicit channel protocol.
- Keep the single reactor thread, but bound every blocking call: add a write timeout to the Unix admin
  socket (mirroring the write timeouts already used elsewhere) and offload only the genuinely slow, rare
  operations (privileged-helper RPC, subprocess spawn) to a small worker-thread pool with a completion
  channel polled non-blockingly, generalizing the Windows control-pipe forwarding pattern. Much smaller
  diff, preserves the current lock-free simplicity, but the loop stays serial for anything not explicitly
  offloaded — a future blocking call added elsewhere silently reintroduces the same hazard with no
  structural guardrail.
- Sharded/finer ownership without full message-passing: split `DaemonRuntime` into a few independently-
  owned sub-runtimes (GossipRuntime, DnsResponder, IpcServer, ReconcileEngine) each on its own thread, with
  currently-shared read-heavy state (membership snapshot, DNS zone, traversal hints) republished as an
  immutable snapshot behind a single atomic pointer swap (`arc-swap` crate) — the RCU pattern for
  read-heavy state. Cleanly bounds contention to a single pointer swap per publish; requires deciding a
  staleness/consistency policy for readers observing a swap mid-reconcile, and is a materially larger
  architectural change than the other two options.
- Adopt an async runtime (tokio — already a workspace dependency via `rustynet-relay`, just not used in
  `rustynetd` today) specifically for the control plane (not the packet-forwarding hot path, which
  `DataplanePerfBacklog` already owns), using `tokio::time::timeout` for all I/O and `spawn_blocking` for
  subprocess/privileged-helper calls. Gives timeout/cancellation for free, but is the largest lift — a
  panic/cancellation-safety review surface in a codebase with zero async in `rustynetd` today, and
  reintroduces exactly the "lock held across .await" foot-gun class if not done carefully with the other
  candidates' state-ownership discipline.

**Constraints.** `unsafe_code=forbid` and "no custom cryptography/VPN protocol" are not implicated — all
options are pure Rust-std or well-established crates operating purely on control-plane scheduling. Any
decomposition must preserve fail-closed semantics (§3/§4): if subsystems move to separate threads/tasks,
the reconcile-vs-apply ordering and the trust/membership verify-before-apply sequence (§10.5) must remain
enforceable as an explicit protocol, not an accident of shared-thread ordering as it is implicitly today.
The WireGuard backend boundary (§8/§10.3) is unaffected regardless of which thread calls `configure_peer`/
`run_capture`.

---

### CCY-2: `reconcile()` unconditionally reloads, re-verifies, and re-persists trust and membership state from disk every tick regardless of whether anything changed

**Current behavior.** `reconcile()` calls `load_verified_trust()` and `load_verified_membership()`
unconditionally on every 1000ms tick, gated only by "did the timer fire," never by "did the file change."
`load_verified_trust` always: loads the previous watermark, loads+parses+verifies the trust evidence file
against the verifier key, persists the watermark back — three synchronous file operations plus a
signature verification, every second, forever. `load_verified_membership` is heavier: existence check,
snapshot load, log load, full replay against the snapshot, state-root computation, previous-watermark
load, replay check, persist a new watermark — all unconditionally, every tick. Immediately after,
`membership_directory_from_state` rebuilds a fresh `MembershipDirectory` from the just-replayed state
(iterating every node), and the controller clones+ingests it — **before the code even checks whether
`membership_changed` evaluated true or gates the expensive apply path.**

**Why it's a bottleneck.** A "reload the whole world every tick" pattern rather than a delta-apply
pattern: the watermark-comparison logic that would let the code detect "nothing changed" already exists
(`membership_watermark_is_replay`) but is currently used **only to reject a stale/replayed bundle, never
to skip the reload+reverify+rebuild work when the freshly-computed watermark matches the previous one.**
At the 2-50 node scale the data volume itself is small, so the clone/rebuild CPU cost in isolation isn't
the bottleneck — but the *disk I/O and Ed25519 verification* cost is real synchronous work repeated on the
single reactor thread (CCY-1), every second, in perpetuity, with essentially zero payoff on the
overwhelming majority of ticks where nothing changed.

**Impact/scale.** No reconcile-loop timing benchmark exists in the repo. This is about steady-state
wasted work — disk I/O + crypto verify on every one of ~86,400 ticks/day at the 1s default cadence, the
vast majority with zero state change. Matters most for Pi-class anchors (slower storage, no page-cache
headroom) and battery/data-constrained mobile clients, where an unconditional once-per-second disk-read-
plus-verify is pure background tax with no payoff on most ticks; at 2-3 node scale the absolute cost is
small but is still always-on work regardless of mesh activity.

**Candidate technique families:**
- mtime/hash-gated short-circuit: stat the trust/membership files (or reuse the watermark already
  computed) and skip the full load+parse+verify+persist-watermark round trip when nothing has changed
  since the last successful tick. Cheapest possible change, preserves fail-closed semantics if the stat
  call itself is treated as fail-closed on error; requires care that "unchanged" is judged strictly
  enough not to weaken the anti-replay guarantee.
- Filesystem watch (inotify/FSEvents/ReadDirectoryChangesW, via the `notify` crate) pushing a dirty flag
  into the loop instead of polling unconditionally every tick. Converts a guaranteed-every-second poll
  into an edge-triggered wakeup, but adds a new cross-platform dependency and a missed/coalesced-event
  failure mode that **must fail closed to a periodic-poll backstop rather than replace it outright** — an
  outright replacement would violate the fail-closed-on-missing-freshness requirement.
- Read-Copy-Update snapshot: keep the currently-verified `TrustEvidence`/`MembershipState`/
  `MembershipDirectory` behind a single `Arc`, construct+verify+swap a new `Arc` only when the watermark
  comparison indicates the underlying signed state actually advanced. Doesn't reduce the parsing/
  verification work needed when state genuinely changes, but removes the always-happens I/O+reverify tax
  on every idle tick; only pays off in combination with a reader model where other subsystems consume the
  snapshot by reference rather than by fresh reload (ties into CCY-1's decomposition candidates).

**Constraints.** Any skip-when-unchanged optimization must not weaken the signed-state-verify-before-apply
or anti-replay/rollback protections (§4/§10.5) — "unchanged" must be judged from a value that's itself
already fail-closed-verified (the watermark), never from a bare mtime check standing in for signature
freshness.

---

### CCY-3: `GossipNode` owns canonical gossip state; `DaemonRuntime` keeps a manually-resynced shadow copy — architecture-hygiene and correctness-risk, honestly not a measurable performance issue at target scale

**Current behavior.** `GossipNode` owns `gossip_sequence`, `seen_gossip_sequences: SeenSequenceState`, and
`last_minted_bundle: Option<GossipBundle>` as canonical state. `DaemonRuntime` independently declares its
own copies of the same three fields. Every call to `drain_gossip_inbound` and `maybe_run_gossip_mint` ends
with an explicit three-field copy-back — the code's own comment states the intent plainly: *"mirror the
canonical state back onto DaemonRuntime so status queries and other call sites that read these fields see
the latest values."* `drain_gossip_inbound` runs unconditionally on every loop pass (up to ~40/sec when
idle, per the 25ms sleep cap), so this mirror-copy executes at that rate.

**Why this is flagged as hygiene, not performance.** `SeenSequenceState` is `HashMap<[u8;32], u64>` keyed
one-entry-per-source-peer, so at the 2-50 node target its clone cost is at most 50 hashmap entries —
genuinely negligible CPU, verified by reading the type definition rather than assumed. **This is not a
real performance bottleneck today, and it would be dishonest to present it as one.** What it *is*: two
independent owners of the same logical state kept in sync only by a human remembering to copy back after
every mutation site, with no compiler-enforced or structural guarantee the shadow and canonical copy are
ever actually consistent — only "runs on the single reactor thread and the current call sites happen to
copy correctly." The next call site that mutates `GossipNode`'s fields directly, or a new status-read path
added between drain/mint calls, can silently read stale shadow state with nothing catching it.

**Candidate technique families:**
- Single source of truth: delete the three `DaemonRuntime` shadow fields, have every status/IPC read go
  through `self.gossip_node` directly. Since everything is single-threaded (CCY-1), there's no
  borrow-checker/lifetime obstacle to reading through — the mirroring appears to be a stylistic choice
  rather than a structural necessity. Zero runtime cost and removes the bug class outright, but is a
  mechanical refactor touching every call site currently reading the shadow fields.
- If gossip is ever moved to its own thread (per CCY-1's decomposition candidates), replace the manual
  mirror with a real publish/subscribe primitive: `GossipNode` publishes an immutable status snapshot
  behind `ArcSwap` (or `tokio::sync::watch` if async is adopted) that readers grab a cheap `Arc` clone of.
  Only pays off once gossip genuinely runs off-thread; turns today's 2-collection-clone-per-tick mirror
  into a single atomic pointer swap, at the cost of a new small dependency.
- Persistent/structural-sharing collection (`im`/`rpds` crates) for `SeenSequenceState` so "cloning" the
  dedup set is O(1) structural sharing instead of an O(peer-count) HashMap clone — named here only
  because the task explicitly calls out persistent data structures and this is the one place in scope
  whose shape matches the technique; at 2-50 entries this solves a cost measurement shows doesn't exist
  yet, and the first option above is strictly simpler and sufficient. Listed for completeness, not as a
  real recommendation at current scale.

**Constraints.** None of these touch signed-state verification or replay protection — `SeenSequenceState`/
`last_minted_bundle` are already-verified in-memory caches, not the trust boundary itself, so this is a
pure internal-architecture cleanup with no security-control interaction.

---

## 12) Workspace build-time and test-suite feedback-loop speed

*Developer/CI-facing speed, not runtime behavior — applies to every contributor on every commit
regardless of mesh size.*

### BLD-1: Low-level crates fan out into the workspace's two heaviest crates; xtask's `--affected` scoping is asymmetric with this shape — no benefit where it matters most, and a silent under-scoping gap beyond one hop

**Current behavior.** The transitive-dependent closure of `rustynet-crypto` is
`{control, nas, rustynetd, cli, relay}` — it reaches both of the two largest crates in the repo
(`rustynetd`: 85 files, 116,942 lines; `rustynet-cli`: 205,720 lines excluding its 97 `src/bin/*.rs`
binaries, and the root `Cargo.toml` itself notes `rustynet-cli` "links ~30 crates" and needs
`codegen-units=16` just to avoid linker OOM on a 2Gi lab VM). `rustynet-crypto`'s own `lib.rs` is a
single 2,704-line file with no internal module split. Separately, `rustynet-windows-native` (1,948 lines,
itself the lowest node in the graph — zero workspace deps) is depended on **inconsistently**: plain,
unconditional `[dependencies]` (not target-gated) in `rustynet-crypto`, `rustynet-backend-wireguard`, and
`rustynetd` — three crates that compile+fingerprint-check it on every platform including macOS/Linux —
while `rustynet-control` and `rustynet-relay` correctly gate it behind `[target.'cfg(windows)'.dependencies]`.
`windows-native`'s own source is not a blanket `#![cfg(windows)]` file — it has plain cross-platform
structs plus per-item `#[cfg(windows)]`/`#[cfg(not(windows))]` guards throughout, so a substantial
fraction of the file participates in non-Windows compilation, and any edit anywhere in it (including
inside Windows-only sections) still changes its source hash and invalidates Cargo's fingerprint for every
dependent. Meanwhile xtask's own `--affected` fast-path is **deliberately one-hop-only** — the code
comment ("one hop: add every workspace crate that directly depends on a directly-changed crate") and a
dedicated passing unit test (`one_hop_only_no_transitive_explosion`) confirm this is intentional, not an
oversight.

**Why it's a bottleneck.** Two compounding effects from the same root cause: (a) ordinary full or
`-p`-scoped gate runs on `rustynet-crypto`/`rustynet-windows-native` unavoidably force Cargo to relink/
re-verify the two most expensive crates regardless of how small the edit is; (b) the workspace's own
opt-in speed mechanism has a coverage gap precisely at ≥2-hop distance from a low crate — for a change to
`rustynet-windows-native`, one-hop dependents are only `{backend-wireguard, control, crypto, relay,
rustynetd}`; `rustynet-cli` is **not** a direct dependent (confirmed absent from its `Cargo.toml`) so it's
2 hops away and silently *omitted* from an `--affected`-scoped check/clippy/test run, even though
`rustynet-cli` transitively links windows-native's compiled output and is the actual shipped product
binary. A developer trusting `--affected`'s PASS on a windows-native-only change gets no signal at all
about whether the real release artifact still compiles/passes.

**Candidate technique families:**
- Extract a slim, always-empty-on-non-Windows abstract types crate consumed unconditionally + a real FFI
  crate gated fully behind `cfg(windows)` and consumed only by the few crates needing actual Win32 calls
  — shrinks non-Windows fan-out surface; more manifests to maintain, refactor risk touching a
  security-relevant platform boundary (must not violate §8/§10.3 backend-abstraction rules).
- Make windows-native's dependency edge consistently target-gated everywhere (matching
  `control`/`relay`'s existing pattern) instead of unconditional in `crypto`/`backend-wireguard`/
  `rustynetd` — removes non-Windows compile+fingerprint cost entirely for those three; any code in those
  crates referencing windows-native types outside their own cfg guards needs matching guards or a
  trait-based indirection, real diff surface in security-sensitive crates.
- Deepen `--affected` from one-hop to full transitive reverse-dependency closure (`cargo_metadata` is
  already parsed by hand in xtask) so scoped runs never silently omit a real dependent like
  `rustynet-cli` — closes the correctness gap; but for exactly the low/wide crates this finding is about,
  full closure often *is* most of the workspace, so the scoping benefit evaporates on those specific
  changes — a correctness gain, not a speed gain, for this crate class.
- `cargo-hakari`-style workspace-hack crate to pin unified third-party feature sets — addresses an
  adjacent problem (feature-unification churn across shared external deps, not internal path-dep fan-out),
  worth naming as established workspace-hygiene tooling; adds a generated/checked-in crate needing
  regeneration when dependency feature needs change.

**Constraints.** Any split of `rustynet-windows-native`/`rustynet-crypto` must preserve §8/§10.3 (no
backend-specific type leaking into transport-agnostic domain crates) and the existing
`check_backend_boundary_leakage.sh` gate. This is a developer-experience concern, so the deployment-scale
constraint doesn't bound the solution space directly — though CI/lab build hosts are themselves resource-
constrained (the 2Gi-VM `codegen-units` tuning comment).

---

### BLD-2: No cargo-nextest anywhere in the repo; the test stage is the dominant, empirically-measured gate cost and runs ~100+ separate test binaries via default `cargo test`'s one-binary-at-a-time sequential execution

**Current behavior.** Grepping the whole repo for "nextest" returns zero hits. CI and xtask both invoke
plain `cargo test --workspace --all-targets --all-features [--locked]`. The workspace has **101 separate
`[[bin]]`/`src/bin/*.rs` binary targets** (97 in `rustynet-cli/src/bin` alone), of which at least 25 in
`rustynet-cli` and all 4 in `rustynet-mcp/src/bin` contain their own `#[cfg(test)]` unit-test module,
plus 17 standalone integration-test files, plus each crate's own lib.rs unit-test harness — roughly
**6,761 `#[test]` functions total workspace-wide**. `cargo test` compiles each into its own executable
and, by default, runs discovered test binaries **one at a time in sequence** — parallelism exists only
*within* a single binary via libtest's internal thread pool, never *across* binaries — so with 100+
separate binaries the wall clock accumulates binary-by-binary regardless of idle CPU cores. Real measured
evidence from `documents/operations/gate_timings.csv` (357 rows): full-workspace `test` stage costs range
from 213-256s for small/scoped runs up to **3912s (65 min) on a clean/cold build**, matching xtask's own
doc comment ("full `--all-targets` suite is ~48-60min") and the 5400s (90 min) default timeout chosen
specifically because 3600s wasn't enough headroom. No `.cargo/config.toml` exists anywhere in the repo, so
there's also no faster linker (mold/lld), no `sccache`/`RUSTC_WRAPPER`, and no `build.jobs` tuning to
offset this at the compile stage either.

**Why it's a bottleneck.** Default `cargo test`'s binary-at-a-time scheduling turns what could be a
single parallel test-execution phase into ~100+ sequential process launches, each paying process-spawn +
dynamic-link + libtest-harness-init overhead before its own tests even start, with no ability to
interleave a slow binary's execution against a different binary's already-finished compile. Architecturally
distinct from (and additive to) the underlying compile cost — pure execution-scheduling overhead on top
of an already-built test suite.

**Candidate technique families:**
- Adopt `cargo-nextest` (de facto ecosystem standard for large multi-crate workspaces): schedules
  individual tests from *all* discovered binaries onto one global concurrent pool instead of
  binary-by-binary, plus per-test process isolation and configurable per-test retries for flaky tests —
  matches this workspace's shape well (many small binaries). Doesn't run doctests (moot here, since
  neither CI nor xtask invokes `--doc` today); is an external tool needing pinning + install-step
  maintenance; per-test process-spawn overhead can itself become the bottleneck on a suite with thousands
  of very cheap tests (6,761 here) — worth measuring rather than assuming a straightforward win.
- Reduce binary-target count directly: many of the 97 `rustynet-cli/src/bin/*` targets are live-lab/e2e
  tools gated behind the default-off `vm-lab` feature but still get built+test-harnessed under
  `--all-features` in every CI/xtask run; splitting the vm-lab-only binaries into a separate cargo
  workspace (mirroring how `gui/` and `rustynet-lab-monitor` are already excluded) would shrink the
  default gate's binary count substantially — **but this trades lab-code test coverage in the main gate
  for speed, a real product-safety tradeoff, not a free lunch**, and contradicts the documented reason
  vm-lab stays in-workspace-but-feature-gated ("CI gates run `--all-features`, so the lab code stays
  compiled and tested").
- Parallel per-crate job fan-out inside xtask itself (spawn `cargo test -p X` concurrently for
  independent crates, no new external dependency) — captures some cross-binary parallelism without
  adopting nextest; reimplements a chunk of nextest's scheduling/output-aggregation logic in-house, and
  crates sharing a dependency still serialize on that shared compile step.
- CI-level test sharding across parallel runner matrix jobs — improves CI wall-clock only (not the local
  dev inner loop this section is about, and not total compute cost, only wall-clock via more machines).

**Constraints.** Pure dev/CI tooling — no security-sensitive-path implications.

---

### BLD-3: `check` and `clippy` run as two fully serial, independent full-workspace passes that empirically cost near-identical wall time on the same commit — a real, quantified double-pay, deliberately traded for fail-fast, not an oversight

**Current behavior.** xtask builds a `stages` list in strict order [fmt, check, clippy, (test unless
`--skip-test`)], each stage's own `cargo` args always appending `--all-targets --all-features`; the loop
executes them one at a time, blocking on each `cargo` child process's exit before starting the next — no
concurrency between stages anywhere. **Empirical evidence** from `gate_timings.csv`, sampled across 8+
distinct commits with matching same-commit check/clippy rows: e.g. commit `231aa7f` (clean build) —
check=626s, clippy=665s; and across every sampled pair, clippy costs roughly as much wall time as the
check stage that ran moments before it on the identical commit — if clippy were reusing check's freshly-
populated cache it should be dramatically faster (as a same-commit warm-rerun pair on a different commit
showed dropping to 9s/11s), not comparable in magnitude. The module's own doc comment documents the
ordering as intentional: "fail-fast — a compile or lint error surfaces in minutes instead of after the
whole test suite," with `check` placed before `clippy` specifically so a cheap compile error is caught
before paying clippy's cost.

**Why it's a bottleneck.** Cargo's clippy integration sets `RUSTC_WORKSPACE_WRAPPER` to the clippy-driver
binary, which changes the fingerprint/cache key Cargo uses for every compilation unit relative to a plain
`cargo check` (no wrapper) — even though both stages are semantically "type-check the same source with
the same flags," they land in different cache buckets, so `cargo clippy` after `cargo check` cannot reuse
the other's cached artifacts and re-walks/re-type-checks the near-entirety of the
`--workspace --all-targets --all-features` dependency graph a second time. On the sampled clean-build row
the combined fmt+check+clippy pre-test cost was **1+626+665=1292s (~21.5min) before the test stage even
started**, for a total serial gate run of ~87 minutes.

**Candidate technique families:**
- Drop the standalone `check` stage and treat `clippy` (a strict superset of rustc's own diagnostics plus
  its additional lints) as the sole correctness+lint gate — eliminates one of the two ~10-11min cold
  metadata passes entirely; **reverses the documented fail-fast intent** — a plain compile error would now
  surface bundled inside clippy's slower output instead of a few minutes earlier, which the current
  design explicitly chose to avoid.
- Run `check` and `clippy` concurrently as two parallel subprocesses since neither depends on the other's
  output, only on the same unchanged source — cuts wall-clock for that portion roughly toward the slower
  of the two rather than eliminating the redundant CPU work; doubles peak CPU/memory pressure during that
  window (relevant on constrained CI runners and laptops, and directly opposed to the existing
  single-process-group-per-stage timeout/kill design, which would need rework for two concurrently-
  running, independently-killable child process groups), and still loses the current fail-fast property
  since a compile error would no longer be known before clippy's slower pass completes.
- `sccache` (`RUSTC_WRAPPER`-based shared compilation cache) — caches keyed by full compiler invocation
  including the wrapper, so it would **not** by itself close the check-vs-clippy cache-miss (different
  wrapper = different cache key = same problem persists on a truly cold cache), but would help repeat runs
  of the identical invocation (CI cache warm-started from a prior run of the same commit, or a local dev
  machine re-running the same gate twice); adds an external daemon/tool and cache-storage management
  without solving the core cross-wrapper duplication.
- Accept the current design as a considered tradeoff and only optimize the `--affected`-scoped path
  (already exists) so day-to-day iteration rarely triggers the full-workspace cold case at all, reserving
  the ~21min check+clippy pre-test cost for full/CI runs — doesn't touch the CI-side cost at all, and
  (per BLD-1) `--affected`'s one-hop scoping already provides no benefit for edits to the workspace's most
  heavily-depended-on crates.

**Constraints.** Pure dev-tooling change; the only real constraint is §7's own requirement that
fmt/check/clippy/test remain individually-invocable authoritative gate definitions — any restructuring
must not remove the ability to run each `cargo` command standalone as documented there.

---

## 13) CLI and daemon cold-start latency and resource footprint

### CLI-1: Daemon startup fully parses+cryptographically verifies (and, for membership, replays) every one of the five signed-state bundle types twice — once in a discard-only preflight pass, once for real in bootstrap

**Current behavior.** `run_daemon` calls `run_preflight_checks(&config)` **before** constructing
`DaemonRuntime` and calling `runtime.bootstrap()`. `run_preflight_checks` does five full load+verify
passes whose results are immediately discarded: trust evidence (bound with `let _ =`); the membership
snapshot+log, fully replayed via `replay_membership_snapshot_and_log` (result never bound to any variable
used later); the auto-tunnel/assignment bundle (when `auto_tunnel_enforce`); the DNS zone bundle; the
traversal bundle set. Immediately afterward, `DaemonRuntime::bootstrap()` performs the **same five loads
again**, this time keeping the result: `load_verified_trust()` reloads+reverifies; `load_verified_membership()`
reloads+replays the log again; `load_verified_auto_tunnel()`, `refresh_dns_zone_state()`,
`refresh_traversal_hint_state()` all reload+reverify. (A secondary redundancy — `state_fetcher.fetch_*()`
called twice each in `bootstrap()` — is confirmed **inert in production**: `StateFetcher::new_from_daemon`
hardcodes all four fetch URLs to `None` with the comment "hardened daemon paths only consume pinned local
custody artifacts," and those fields are only ever set to `Some(...)` in test code.)

**Why it's a bottleneck.** Each "load" is not a `stat()` check — it's a full file read plus a separate
verifier-key file read plus a full parse plus an Ed25519 (or multi-approver) signature verification. For
membership specifically, `apply_signed_update` calls `verify_membership_signatures()` once **per log
entry** inside the replay loop, so the membership replay's cost is O(number of accumulated transitions
since the last snapshot) — and that whole O(n) parse+verify pass runs **twice**, unconditionally, on
every single daemon boot.

**Impact/scale.** Not independently wall-clock-measured (would require constructing a full signed trust+
membership fixture and privileged runtime setup). The wasted half is precisely characterized by direct
code reading: 5× (file-read + verifier-key-read + parse + signature-verify), one of which additionally
repeats one Ed25519 verification per historically-accumulated log entry. Matters most on Pi-class anchors
(slower CPU for the doubled verify loop, slower storage for the doubled reads) and for "fast recovery
after a crash/restart" — a node that crash-loops or gets restarted by a supervisor pays this double cost
on every restart attempt, and unlike a brand-new node an established mesh member has real accumulated
transition history to replay twice.

**Candidate technique families:**
- Single-pass validate-and-carry: have preflight return the verified structures instead of discarding
  them, have bootstrap consume the already-verified value — couples the two phases' data lifetimes; needs
  care that the existing "scrub decrypted WG key material if preflight fails" property (called on
  preflight `Err`) is preserved exactly.
- Lightweight preflight + one real verify in bootstrap: strip preflight down to existence/permission/
  size-bound checks only, push the one full crypto verify+replay to bootstrap — **this changes preflight's
  actual documented job** (fail closed on corrupt/malicious state before committing resources), so
  weakening it is a security-posture decision requiring explicit sign-off against the fail-closed mandate,
  not a pure perf refactor.
- In-process content-addressed verification cache for the single startup call chain: hash each file's
  bytes once, memoize (digest → verified-envelope) so an identical second load in the same run resolves
  without re-parsing/re-verifying — invalidation is trivial here since nothing mutates these files between
  the two loads within one synchronous startup sequence.
- Membership log compaction/checkpointing (ties to ENR-1) so each individual replay pass is bounded
  regardless of history length — orthogonal to the double-pass issue (reduces the cost of each pass rather
  than eliminating the duplication), so multiplies the benefit of whichever de-duplication approach is
  chosen; requires a new signed "compacted snapshot" issuance step from the owner authority, adding
  trust-model surface.

**Constraints.** Must preserve fail-closed semantics precisely (§3/§4): whichever path remains "the"
verification must still run before the daemon serves/forwards traffic, and the WG key-scrub-on-preflight-
failure property must still hold. No custom cryptography implicated — pure control-flow/caching
restructuring around already-audited signature-verification calls. Cross-reference, not re-derivation: the
key-material prepare/scrub sequence around this same bootstrap path is SEC-1's territory.

---

### CLI-2: `rustynet-cli` shells out for facts fixed at compile time on every invocation of the commands that need them, with zero in-process memoization anywhere in the crate

**Current behavior.** `execute_info()` calls `rustynet_sysinfo::rustc_version()`, which on every call
spawns `Command::new("rustc").arg("--version").output()` — a full subprocess exec — to report a value
fixed for the entire lifetime of the compiled binary ("which toolchain built this exact artifact"). A
grep across `rustynet-sysinfo`/`rustynet-cli`/`rustynetd` for `OnceCell`/`LazyLock`/`once_cell`/
`lazy_static` returns **zero hits** — no memoization primitive anywhere, so every one of
`rustynet-sysinfo`'s ~90 public functions recomputes from scratch, via fresh subprocess spawn or fresh
file read, on every call.

**Measured impact.** Directly measured on a release build, warm caches, fast dev host: `rustynet version`
(no subprocess call) median ~3.9ms; `rustynet info` (one extra `rustc_version()` subprocess call) median
~16.9ms — roughly a **4x increase attributable to that single spawn**.

**Impact/scale.** The `info` command's absolute cost is minor (human/diagnostic-invoked), but it
demonstrates a module-wide pattern — dozens of leaf CLI diagnostic subcommands built the same way. For
scripted/CI-driven operator workflows invoking `rustynet <diagnostic>` repeatedly (health-check polling
across a 2-50-node mesh, or repeated calls within one script), this per-invocation tax is paid every time
with no way to amortize it even across calls milliseconds apart on the same host, and would be
proportionally worse on a slower Pi-class ARM device.

**Candidate technique families:**
- Compile-time embedding via `build.rs` (capture `rustc --version` once at build time into an `env!()`-
  sourced constant, the same mechanism `vergen`/`built` provide) — eliminates the runtime subprocess
  entirely; correct semantically since the fact *is* a build-time property, not a runtime one.
- Process-lifetime memoization (`std::sync::OnceLock`) for facts that might genuinely be read more than
  once within a single invocation — checked directly: no `execute_*` function today calls the same
  `rustynet_sysinfo::` function twice, so this technique currently has no payoff against any command that
  exists right now; it only pays off if a future command combines several `sysinfo::` calls in one
  invocation.
- Short-TTL on-disk cache shared across repeated short-lived invocations for scripted polling scenarios —
  introduces a staleness window that must be sized so it never masks a real state change; appropriate only
  for pure informational diagnostics, **never for anything trust/security-relevant**.

**Constraints.** None of these touch trust/security state. A `build.rs`-based fix must keep the existing
argv-only-exec convention (no shell string construction) and must not require network access during
build.

---

### CLI-3: Host-network-interface enumeration is independently implemented three separate times; the `diagnostics` command composes six independent external-process probes strictly sequentially with no concurrency

**Current behavior.** Three separate, separately-maintained implementations of "enumerate network
interfaces" exist in `rustynet-sysinfo`: `network_interfaces()` (Linux reads `/sys/class/net` directly,
macOS shells `ifconfig` and parses it); `iface_list()` (a **second**, independent Linux `/sys/class/net`
reader and a **second**, independent macOS `ifconfig`-invoker/parser with its own state machine); and
`diagnostics::observe_interfaces()` (a **third** `/sys/class/net` reader on Linux, a **third** `ifconfig`
parser on macOS, plus a Windows variant using `netsh interface ipv4 show interfaces`). Each returns a
differently-shaped struct for materially overlapping data. Separately, `execute_diagnostics()` calls
`observe_system_diagnostics()`, which runs `observe_interfaces`/`observe_routes`/`observe_dns`/
`observe_listening_sockets`/`observe_firewall`/`observe_service` **strictly sequentially** in one thread —
on macOS each is its own `Command::new(...).output()` (`ifconfig`/`netstat -rn`/`scutil`/`netstat -an`
or `lsof`/`pfctl -s info`/`launchctl list`), each bounded by a 3-second-per-probe timeout but with zero
concurrency between probes.

**Why it's a bottleneck.** Sequential composition of independent I/O-bound external-process calls sums
their latencies instead of taking the max — none of `DiagnosticsReport`'s six fields depends on another's
value (populated independently in one struct-literal statement), so the ordering is an artifact of how
the composing function happens to be written, not a real data dependency.

**Measured impact.** Directly measured on a release build, 10 samples: `rustynet diagnostics` median wall
time ~155-160ms versus the ~3.9ms no-op baseline — roughly **40x**, consistent with six sequential
subprocess round-trips at roughly 25ms each.

**Impact/scale.** Per-CLI-invocation and host-local (not mesh-size-proportional) — exactly the
"short-lived process invoked repeatedly by operators/scripts" scenario: a fleet health-check script
running `rustynet diagnostics` once per node across a 2-50-node mesh pays ~155ms × node-count purely in
sequential-probe overhead, expected to be higher (not lower) on Pi-class hosts where process-spawn and
external-tool startup are both slower than on a fast dev machine.

**Candidate technique families:**
- Run the independent probes concurrently (`std::thread::scope` + one thread per probe, or a small pool)
  — `CommandRunner` is already a trait-object abstraction invokable from multiple threads with no new
  `unsafe` code required; wall time collapses toward the single slowest probe instead of their sum.
- Consolidate the three independent interface-enumeration implementations into one shared internal helper
  reused by all three callers, converting to each public shape at the edges — removes triplicated
  ifconfig/sysfs parsers that can silently drift apart (they already have — the two aren't byte-identical
  in field extraction), though it doesn't by itself fix the diagnostics command's sequential-fanout
  timing (dominated by the other five probes, not interfaces alone).
- Extract more fields from a single already-invoked tool's output rather than issuing a separate tool
  call per fact where the OS tool already reports adjacent information in one pass — reduces subprocess
  *count* rather than parallelizing it; tighter coupling between the parser and one specific external
  tool's combined output format.

**Constraints.** Pure read-only diagnostics — `CommandRunner`'s allowlist explicitly enforces read-only
verbs, so no fail-closed/default-deny trust-state constraint applies; this is a latency/UX concern only.
Any concurrency introduced must preserve the existing per-probe timeout bound and stay within
`unsafe_code=forbid` (`std::thread::scope` is fully safe Rust).

---

## 14) Windows WFP/DPAPI batching and nas/llm-gateway service data-path efficiency

### WIN-1: The one raw WFP FFI call site is already correctly batched into a single transaction — not a finding, confirmed as sound

`apply_wfp_tunnel_permit`/`remove_wfp_tunnel_permit` (`rustynet-windows-native/src/lib.rs:1679-1737`) is
the **only** place in the workspace calling the WFP engine API (grep confirms no other call sites exist).
Both functions open the engine once, then wrap every mutation — filter/sublayer deletes, sublayer add, up
to two permit-filter adds — inside one `FwpmTransactionBegin0`/`FwpmTransactionCommit0` pair, aborting on
any intermediate error. This is exactly the batching pattern WFP's own documentation recommends. There is
no per-peer or per-ACL-entry WFP rule set anywhere in the repo today (only 2 filters + 1 sublayer exist,
regardless of mesh size), so there is no per-rule transaction to optimize. **Recorded here so the next
agent doesn't waste effort re-verifying or "fixing" something already correct** — and so this pattern is
the template to replicate if per-peer/per-route WFP filters are ever added in the future.

---

### WIN-2: Windows peer/route rule-set apply is a subprocess-per-item + full-config DPAPI-re-encrypt-per-mutation pattern — one layer above the (already-batched) WFP call, the real batching gap

**Current behavior.** Applying a mesh generation on Windows runs through `phase10.rs::apply_generation_stages`,
which loops `for peer in &peers { self.backend.configure_peer(peer.clone())?; }` — one
`TunnelBackend::configure_peer` call per peer, sequentially, no batch entry point. `configure_peer`
(`windows_command.rs:447-453`) calls `apply_peer_runtime` (spawns one `wg.exe set <tunnel> peer <key>
endpoint ... allowed-ips ...` subprocess per call) and then `sync_persistent_config()`, which
**re-renders the entire config text for all currently-configured peers**, DPAPI-protects that whole blob
(`dpapi_protect`), and atomically rewrites the whole config file. `update_peer_endpoint` and `remove_peer`
follow the identical per-call pattern. `apply_routes`/`set_exit_mode` each spawn one `netsh.exe` subprocess
per changed CIDR, then `rewrite_runtime_peers` re-spawns `wg.exe set` for **every** configured peer (not
just ones whose AllowedIPs actually changed), then one `sync_persistent_config()` at the end (the
file-level batching there is already correct). The `TunnelBackend` trait already has a batched
`apply_routes(&mut self, routes: Vec<Route>)` signature but has **no batched peer counterpart** —
`configure_peer` takes exactly one `PeerConfig`, structurally forcing the phase10.rs loop to call it N
times.

**Why it's a bottleneck.** Two compounding costs from the same per-item call pattern: (1) Windows process
creation for `wg.exe`/`netsh.exe` isn't free (tens of ms typically, more under AV/EDR hooking of
`CreateProcess`), spent once per peer/route rather than once per logical apply — for an N-peer generation-
apply, O(N) subprocess spawns where the WFP code (WIN-1) two lines up in the same crate already shows
O(1) is achievable for a comparable operation. (2) `sync_persistent_config` re-renders and DPAPI-
re-encrypts the **full** config text (all peers configured so far) on every single peer mutation, not
just the delta — so applying a fresh N-peer generation does N DPAPI `CryptProtectData` calls and N
full-file atomic rewrites, each processing a config blob proportional to the peer count already applied
(1, 2, 3, ..., N peers of text) — **O(N) DPAPI calls doing O(N²) total bytes of render+encrypt+write work
for what is logically one atomic membership-generation apply.**

**Impact/scale.** Windows nodes are explicitly in scope for full role parity. At a 50-peer generation
apply, 49 sequential `configure_peer` calls drive 49 subprocess spawns + 49 full-config DPAPI-encrypt-
and-rewrite cycles on every membership generation change a Windows node observes (initial join, any peer
add/remove/rotate anywhere in the mesh). Not catastrophic at 50 nodes, but meaningfully serialized latency
(subprocess spawn costs alone plausibly approach ~1s at N=49 even at a conservative ~20ms/spawn) paid
repeatedly rather than once — disproportionately affects a Windows anchor/relay node (sees generation
churn from the whole mesh) more than a rarely-reconfigured Windows client.

**Candidate technique families:**
- Add a batched `configure_peers(&mut self, peers: Vec<PeerConfig>)` to `TunnelBackend` (mirroring the
  trait's own existing `apply_routes(Vec<Route>)` shape) so the Windows adapter can defer
  `sync_persistent_config()` to one call at the end of the batch — a `Backend` trait signature change
  ripples to every backend (Linux/macOS/userspace/stub), each needing a default or explicit multi-peer
  impl even if trivial.
- Use `wg syncconf <tunnel> <config-file>` (a documented `wg(8)` primitive, present in the same
  wireguard-windows-bundled `wg.exe` already invoked here) to replace N `wg set ... peer ...` calls with
  one subprocess that diff-applies a full peer set from a config file — `syncconf`'s diff semantics (it
  *removes* peers absent from the file) differ from today's imperative per-peer `set` and need careful
  behavior-preservation; still one process spawn instead of N, not zero.
- Add a local dirty-flag + explicit flush point (call `sync_persistent_config` once at the end of
  `apply_generation_stages` instead of inside each `configure_peer`) — smallest, most localized change (no
  trait churn), but relies on every mutation call site remembering to flush, and a missed flush point
  silently leaves the on-disk config stale.
- Move `sync_persistent_config`'s DPAPI-protect + file rewrite off the synchronous per-mutation path onto
  a coalescing background writer — **not merely a perf refactor, changes a durability/security property**
  (§4 fail-closed/state-freshness): the DPAPI-protected config is what the WireGuard tunnel *service* (a
  separate LocalSystem process) reads on restart, so a write-lag window needs explicit reasoning about
  what a crash mid-lag leaves the tunnel service reading.

**Constraints.** Any trait-level change must stay within `rustynet-backend-api`'s `Backend`/
`TunnelBackend` abstraction (§8/§10.3) — no WireGuard-specific type may leak upward (the trait's actual
parameter types — `PeerConfig`, `Route`, `NodeId`, `SocketEndpoint` — are already backend-agnostic, so a
batched `configure_peers` addition doesn't leak one), and any batched entry point must still be
default-deny/fail-closed equivalent to today's per-call error propagation (an error partway through a
batch must not silently leave some peers applied and others not, mirroring the WFP code's own
abort-on-error transaction discipline one layer up). DPAPI is an OS-native, not custom, crypto primitive
— §3 not implicated by call frequency.

---

### WIN-3: llm-gateway/nas client-facing data paths are already streamed/bounded (not the feared full-buffer-before-forward pathology) — but neither daemon sets `TCP_NODELAY`, and llm-gateway's real (non-mock) inference backend doesn't exist yet, so connection-pooling can't be assessed on real traffic

**Current behavior.** llm-gateway's `stream_completion` writes each fragment to the client socket as it
arrives from the engine iterator — no accumulation of the full completion before the first byte reaches
the client. nas's `PutChunk`/`GetChunk` operate on content-addressed chunks explicitly capped at 4 MiB —
a bounded-chunk protocol by design, not an accidental whole-file buffer. **However**: a grep across both
crates for `set_nodelay`/`TCP_NODELAY`/`nodelay` returns **zero hits** — neither daemon ever calls
`TcpStream::set_nodelay(true)` on the accepted connection, so Nagle's algorithm stays enabled on every
session. `write_frame` in both daemons issues two separate `write_all` calls per frame (length-prefix,
then body) rather than one vectored/combined write. Separately, llm-gateway's `run()` validates
`--engine-endpoint` as loopback-only but **never constructs a real client from it** — it always wires
`Arc::new(MockEngine::serving(...))` regardless of the configured endpoint, and its `Cargo.toml` has no
HTTP client dependency at all — so **there is no real loopback-backend connection code in the repository
yet** to audit for pooling behavior.

**Why it's a bottleneck (where it is one).** With Nagle enabled and no explicit flush/nodelay, a small
write (a single streamed token fragment, often just a few bytes) issued while there's still unacknowledged
data on the connection can be held by the kernel rather than sent immediately, waiting to coalesce with
more data or the peer's ACK — the classic Nagle/delayed-ACK interaction. Whether this bites depends on the
gap between successive `write_frame` calls relative to path RTT: irrelevant on a fast LAN hop, real over a
higher-RTT/degraded mobile tunnel path, which the project explicitly targets, and is more consequential
for llm-gateway (a naturally chatty many-small-frames protocol) than nas (large chunk transfers already
exceed one segment, so Nagle is largely moot there). The double `write_all` per frame is a separate,
smaller cost — one extra syscall per frame, not a latency-scale concern by itself. The pooling question
for the real inference engine **can't be graded today because no real client exists**; what *is* gradable
is that the trait boundary already commits to a synchronous, blocking, pull-based `Iterator` for
`stream_completion`, which constrains what connection-reuse strategies a future real adapter can use
without either blocking an OS thread for the duration of each generation (current thread-per-connection
model) or bridging to an async client from inside a blocking call.

**Candidate technique families:**
- Call `TcpStream::set_nodelay(true)` on accept in both daemons — removes Nagle-induced coalescing delay
  for small streamed frames; **latency-vs-bandwidth tradeoff, not a free win** — more, smaller packets on
  the wire cuts against the bandwidth-conscious posture needed for occasionally-connected/mobile clients.
- Combine the length-prefix and body into one `write_all` (single copy into a scratch buffer) or a
  vectored `write_vectored`/`IoSlice` call per frame — removes one syscall and one split-segment
  opportunity per frame; vectored write avoids the extra copy, but coalescing into one TCP segment isn't
  guaranteed by the OS either way.
- For the future real engine adapter: a synchronous HTTP client with built-in keep-alive pooling (`ureq`,
  `attohttpc` — both audited-enough, mostly-pure-Rust sync HTTP crates) behind the existing sync
  `Iterator`-returning trait — minimal churn to `InferenceEngine`, but a blocking `Iterator::next()` still
  occupies one OS thread for the full duration of each in-flight generation, capping concurrency to
  thread/stack budget on a Pi-class anchor/nas host.
- Alternatively, change `InferenceEngine::stream_completion` to an async `Stream` backed by an async HTTP
  client with native connection pooling (`reqwest`/`hyper`) — decouples thread count from concurrent-
  generation count, but requires migrating the whole gateway off std `TcpListener`+thread-per-connection
  onto an async runtime, a materially larger structural change than anything else in this section, **not
  scoped further here**.
- A small fixed-size persistent connection pool (or a single long-lived connection) to the loopback
  engine, reused across client requests rather than opened fresh per request — on loopback the TCP-
  handshake cost being avoided is already tiny, so the bigger payoff of reuse is usually avoiding the
  *engine's* own per-connection setup work (context/KV-cache init), which is engine-specific
  (llama.cpp/Ollama/vLLM each behave differently here) and outside what rustynet's gateway code alone
  controls.

**Constraints.** None of these require anything beyond std/audited crates — no custom protocol or crypto
implicated. Any change to `InferenceEngine`'s trait shape is an internal engine-boundary decision inside
`rustynet-llm-gateway`, doesn't cross the WireGuard `Backend` abstraction boundary (§8/§10.3 not
implicated). Per-frame identity/authorization re-checks (the mid-stream revocation-severance property,
§4-adjacent) are load-bearing and must remain between every emitted event regardless of any framing/
pooling change — none of the candidates above touch it.

---

## 15) Closing note for whoever picks this up

Every finding above was independently grounded in real code by one agent and then independently
re-derived from scratch by a second, skeptical agent whose only job was to try to break it — find a wrong
citation, a duplicate, a constraint violation, a hidden overclaim. Two findings failed that test in a
real, substantive way (ENR-2, RLY-2) and are recorded here corrected, not silently fixed and passed along
as if the first version had been right. That's the standard to hold your own work to if you turn any of
this into an actual change: don't trust a claim — including one from a document as detailed as this one —
until you've re-derived it yourself against the current tree, because the tree has moved since
2026-07-19 and will keep moving.

Nothing here is scheduled. Nothing here is ranked. The next step is picking one finding (or a cluster of
related ones — several of the trust-state findings, MEM-1/MEM-2/SER-1/SER-2/SER-3/CLI-1, share enough
surface area that fixing them together may be more coherent than fixing them one at a time) and doing the
actual design work this document deliberately didn't do: weighing the candidate technique families
against each other for *this specific codebase's* priorities right now, writing the constraint check,
picking a build path, and proving it with the tests and gates §4/§7 of `CLAUDE.md` require. Multiple
genuinely different approaches were given for a reason — use that, don't just take the first bullet in
each list.

