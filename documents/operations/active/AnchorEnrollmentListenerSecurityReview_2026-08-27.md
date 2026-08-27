# Anchor Enrollment-Consume Listener: Independent Adversarial Security Review (2026-08-27)

**Status: review complete on branch `work/enrollment-listener`. All mandatory gates green on
the post-review tree. No unresolved MEDIUM-or-above finding. Verdict: PASS — see §7.**

This is the independent adversarial pass the bundle-pull precedent
([`AnchorBundlePullAttestationSecurityReview_2026-07-20.md`](./AnchorBundlePullAttestationSecurityReview_2026-07-20.md))
requires before any deployment sets `--anchor-enrollment-allow-lan`. It was performed by a
reviewer that did **not** write the listener, did **not** trust the phase-1 author report, and
verified every claim by reading the code and running the tests. Loopback-only operation does not
wait on this review; LAN exposure does.

## 1) Scope

The change surface is the four files this branch touches (three-dot diff
`main...work/enrollment-listener`):

- `crates/rustynetd/src/daemon.rs` — the new listener seam:
  `bind_anchor_enrollment_listener`, `handle_anchor_enrollment_stream`,
  `poll_anchor_enrollment_once`, the `read_line_bounded` `label` parameter, the reordered
  `DaemonRuntime::handle_enrollment_consume`, the `validate_anchor_enrollment_addr` gate, the two
  new `DaemonConfig` fields, and the wiring into both the Unix and Windows daemon main loops.
- `crates/rustynetd/src/main.rs` — the `--anchor-enrollment-addr` /
  `--anchor-enrollment-allow-lan` flags and their `RUSTYNET_ANCHOR_ENROLLMENT_*` env mirrors.
- `crates/rustynetd/tests/state_fetcher.rs` — two new config fields in the test fixture.
- `documents/operations/active/AnchorEnrollmentEndpointEnforcementDesign_2026-08-27.md` — the
  design §7 landing notes.

Supporting code read but not modified by this branch, and re-verified here because the listener
depends on it: `crate::ipc::parse_command`, `require_local_signed_capability`,
`rustynet_control::membership::snapshot_bytes_have_capability` / `parse_snapshot_content`,
`open_anchor_state_file`, `enrollment_consume::consume_and_register_peer` /
`finalise_consume`, `enrollment_token::acquire_ledger_lock`, and the bundle-pull seam
(`bind_anchor_bundle_pull_listener` / `handle_anchor_bundle_pull_stream`) that this listener
claims to match or exceed.

Governing standards: `AGENTS.md` §3 (fail-closed, default-deny, argv-only, no new crypto), §4
(an enforcement point **and** a verification test for every control); the design doc's §2 (serve
ONLY enrollment-consume), §4 (fail-closed rules), §5 (no new crypto/wire/attestation).

## 2) Method

- Read the full three-dot diff and every dependency listed above at the code level, not the
  report level.
- Ran the author's tests directly: `cargo test -p rustynetd --all-features --lib
  anchor_enrollment` (16 daemon tests) and `cargo test -p rustynet-control --lib
  snapshot_bytes_have_capability` (5 membership tests) — **all 21 pass**. Read each test's
  assertions against what the author claimed it proves.
- Attacked the pre-authentication parser, the verb whitelist, the authentication ordering, the
  token-burn concurrency, the capability-check TOCTOU windows, the fail-closed error branches, and
  the information-leak surface, each against the real code (details in §4).
- Wrote two additional adversarial probe tests for vectors the author's suite left implicit (exact
  byte-cap boundary; smuggled second verb). **Both pass unmodified** — they confirm the listener
  holds and are kept as regression guards.
- Re-ran the full gate suite on the post-review tree (§6).

## 3) Findings table

| # | Severity | Location | Scenario | Disposition |
|---|---|---|---|---|
| F1 | INFO | `daemon.rs:1350` (`DeadlineWriter::write`) | The write-deadline error string is hardcoded `"anchor bundle-pull response exceeded its time budget"` and is reused verbatim by the enrollment response path. | Accepted. Cosmetic: the string is a server-side `DaemonError::Io` that is logged, never sent to the client. Shared struct; no security impact. |
| F2 | LOW | `daemon.rs:9141,9147,9149` (`handle_enrollment_consume` secret/ledger load error arms) | A handful of `ERR {reason}` refusals embed `{err}` from `load_secret` / `acquire_ledger_lock` / `load_ledger`, which can contain a local filesystem path. With `--anchor-enrollment-allow-lan` set, that path is disclosed to a pre-auth LAN caller. | Accepted-with-reason. Discloses a path, never secret **material** or ledger **state** (so the design §5/§7 claim holds as written). Only reachable on mid-run corruption/permission change — bind-time provisioning already proved the secret loads and the paths are set. Matches bundle-pull, which likewise surfaces `{err}` in its `DaemonError`. Hardening recommendation in §5, not blocking. |
| F3 | LOW | `daemon.rs` main loops (`poll_anchor_enrollment_once` served inline) | The listener serves one connection per tick synchronously on the shared daemon event loop; a stalling peer holds the loop for up to the read timeout + line budget. A connection flood degrades daemon responsiveness. | Accepted. Identical design to the reviewed bundle-pull listener and strictly **less** severe than it (5 s write budget + one-line response vs bundle-pull's 30 s + 8 MiB bundle). Loopback-only by default; LAN gated behind this review. Not worsened by this branch. |
| F4 | INFO | `membership.rs:1181` (`parse_snapshot_content`) | The snapshot self-`digest` is a plain SHA-256 (no key), so it is an integrity guard against corruption, not authenticity: an attacker with local write access could recompute it. | Accepted / residual. Within the real threat model authenticity comes from the quorum-gated `apply_signed_update` write path plus local file permissions plus the symlink-refusing, size-bounded `open_anchor_state_file` reader. Local write access is already game-over. Identical to the bundle-pull gate. |
| F5 | INFO | `enrollment_consume.rs:181` (`enforce_push_address_policy`, `Strict`) | A holder of a valid enrollment token can register an arbitrary Global/Private push address (not necessarily one it controls); LAN exposure widens who can reach this token-gated verb. | Accepted / residual. Inherent to enrollment-consume (pre-existing D2.7), gated by the network's bearer token, which the design §3 explicitly treats as the trust boundary. Out of scope of the listener; noted for completeness. |

**No CRITICAL, HIGH, or MEDIUM finding was found. The listener holds.**

## 4) What was attacked, and what the code actually does

Every vector below was traced to the real code; where a test settles it, the test is named.

**Pre-auth parser abuse.** `read_line_bounded` (`daemon.rs:1286`) reads one byte at a time, pushes
to a `Vec`, and refuses the moment `bytes.len() > max_bytes` — so no allocation is ever
proportional to attacker input beyond the 256-byte cap. The cap is an exact boundary: a 256-byte
payload is accepted (then refused by the whitelist), 257 is refused by the reader before the
newline. I added `anchor_enrollment_stream_size_cap_is_exact_256_257_boundary` to lock this; it
passes. `String::from_utf8` rejects non-UTF8 (connection dropped, no response). An embedded NUL is
valid UTF-8 but not whitespace, so it fuses into a token and fails the arity/verb match rather than
panicking. The overall 2 s wall-clock budget is checked before every blocking read, and the socket
carries independent 2 s read/write timeouts, so a slow-loris or never-sending peer is bounded. **No
`unwrap`/index/parse panic exists on any hostile-input path**: `pk.copy_from_slice` is guarded by an
explicit `len() == 32` check, and `VerifyingKey::from_bytes` returns `Result`. Truncation (EOF
before newline) is refused outright (`!newline_terminated ⇒ Err`), a deliberate tightening over
bundle-pull — verified by `anchor_enrollment_stream_refuses_truncated_payload` and
`_refuses_oversized_payload_before_allocation`.

**Verb whitelist / exactly-one-operation.** The whitelist is enforced on the **parsed**
`IpcCommand` enum via an irrefutable-let-else (`daemon.rs:268`), not a string prefix. `parse_command`
(`ipc.rs:193`) matches on a fixed-arity token slice: `EnrollmentConsume` requires **exactly** five
whitespace-separated tokens, so a smuggled sixth field (a second verb) forces `IpcCommand::Unknown`
and the fixed `ERR unsupported operation` refusal — I confirmed with
`anchor_enrollment_stream_refuses_smuggled_second_verb` (carries a *valid* token plus a trailing
`status`; refused, and nothing burned). No `admit`, `bundle`, `gossip push`, `membership apply`,
`remote-op-v1`, or `status` line can reach a mutating path — `anchor_enrollment_stream_refuses_non_enrollment_verbs`
covers all of these.

**Authentication ordering.** The capability is re-read from signed state at **accept time, before a
single client byte is read** (`handle_anchor_enrollment_stream`, `daemon.rs:244`), and **again** as
the first statement of `handle_enrollment_consume` (`daemon.rs:9098`), before the secret is read,
before the ledger lock is taken, and before any token byte is parsed. This is strictly **stronger**
than bundle-pull, which checks capability only once (at accept); the enrollment double-check catches
a revocation that lands during the read window. Confirmed by
`anchor_enrollment_revoked_capability_refused_per_request_while_listener_stays_bound`.

**Token replay / burn races.** There is no intra-process concurrency to race: the enrollment poll
runs on the single daemon main-loop thread, and the local IPC path is marshalled onto that **same**
thread (the control-pipe/socket accept thread forwards `(bytes, resp_tx)` over an mpsc channel "so
DaemonRuntime stays single-threaded", `daemon.rs:10948`). One connection is accepted and served
inline per tick — fully serialized. Cross-**process** redemption of one token is guarded by
`acquire_ledger_lock`, an exclusive `flock(2)` advisory lock (`nix::fcntl::Flock`) held across the
entire load→check-consumed→register→write sequence; `finalise_consume` persists the burn to disk
**before** registering the peer. Replay after a successful burn is refused by the single-use ledger —
`anchor_enrollment_stream_refuses_replayed_token_after_successful_consume` proves the durable burn
and the replay refusal end-to-end over the real socket.

**Capability-check TOCTOU.** Two windows exist and both fail closed: (bind-open → per-request) is
covered because the per-request re-read is authoritative and a revoked node refuses at the next
request while the listener stays bound (same test as above); (accept-check → ledger-burn) is covered
because `handle_enrollment_consume` re-checks capability at its top, after the line is read, so a
revocation during the ≤2 s read window is caught before any burn.

**Fail-open under bad snapshot.** `require_local_signed_capability` opens the snapshot through
`open_anchor_state_file` (refuses symlinks and non-regular files), bounds the read to
`MAX_MEMBERSHIP_SNAPSHOT_BYTES + 1`, and delegates to `snapshot_bytes_have_capability`, which returns
`false` on non-UTF8, oversize, digest mismatch, parse/validate failure, unknown node, non-`Active`
status, or absent capability. Every `?`/error branch in the bind path and the per-request path
defaults to **deny**. The bind path creates **no socket** until all pre-bind checks pass (loopback
gate → subsystem provisioned → secret actually loads → signed capability present). Covered by
`bind_anchor_enrollment_listener_refuses_when_{capability_absent,snapshot_missing}`,
`_refuses_symlinked_snapshot`, `_refuses_unprovisioned_enrollment_subsystem`,
`_rejects_non_loopback_without_allow_lan`, and the membership-layer digest-tamper / unknown-node /
revoked-node tests.

**Information leaks / oracles.** Every token-layer verdict collapses to the single fixed string
`enrollment token rejected` (`daemon.rs:9161`), so expired vs unknown vs bad-tag are
indistinguishable — `anchor_enrollment_stream_refuses_expired_token` asserts exactly this string.
The design's required ordering (capability refusal short-circuits **ahead** of token verification) is
honored: capability is checked first at both gates, and its refusal is a fixed string
(`enrollment endpoint capability not held` in-handler, `ERR forbidden after revocation` at accept).
Because capability assignment is public quorum-signed roster state, distinguishing "has capability"
from "doesn't" discloses nothing the roster does not. The only residual disclosure is F2 (local
paths via `{err}` on mid-run I/O failure).

## 5) Fixes and hardening

No MEDIUM-or-above finding required a code fix. Two adversarial regression tests were **added** on
the branch (they pass unmodified, confirming the listener holds and guarding two properties the task
called out that the author's suite left implicit):

- `anchor_enrollment_stream_size_cap_is_exact_256_257_boundary` — pins the exact byte-cap boundary
  against a future `>`/`>=` slip.
- `anchor_enrollment_stream_refuses_smuggled_second_verb` — pins the arity-fixed whitelist against a
  variadic parse arm; asserts a valid token carried alongside a smuggled verb is **not** burned.

Non-blocking hardening recommendation (F2), for a follow-up, not applied here to keep the review
change surface to added tests only: collapse the `{err}`-bearing secret/ledger arms of
`handle_enrollment_consume` to fixed strings (e.g. `"enrollment subsystem unavailable"`) so no local
path can reach a LAN caller even on mid-run I/O failure. This is defense-in-depth beyond the design's
stated bar, which the current code already meets.

## 6) Gate evidence (post-review tree)

Run in the worktree with
`CARGO_TARGET_DIR=/Users/iwan/Desktop/Rustynet/.claude/worktrees/mgr-enrollment-listener/target`:

- `cargo fmt --all -- --check` → `FMT_EXIT=0`.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` → `Finished` clean, exit 0.
- `cargo check --workspace --all-targets --all-features` → `Finished` clean, exit 0.
- `cargo test --workspace --all-targets --all-features` → exit 0 (verbatim summary appended in the
  final review report).

The 21 control tests (16 `rustynetd` listener + enforcement, 5 `rustynet-control` capability) plus
the 2 reviewer-added probes all pass.

## 7) Author claims — verified, and where overstated

**Verified true against the code:**

- "Pre-authentication hardening mirrors bundle-pull" (accept-time capability re-read before any
  client byte; byte-at-a-time size cap before proportional allocation; 2 s line budget; 2 s socket
  timeouts; deadline-bounded writes; fixed-vocabulary `OK`/`ERR`). **True.**
- "Two deliberate tightenings beyond the precedent" — EOF-truncated line refused outright, and every
  payload parse precedes the ledger lock. **Both true** (`handle_anchor_enrollment_stream` newline
  check; the reordered `handle_enrollment_consume` parses pubkey/addr before `load_secret` +
  `acquire_ledger_lock`). I found a **third** un-advertised strengthening: the per-request capability
  re-read makes enrollment stricter than bundle-pull, which checks capability only once.
- "Serves EXACTLY one verb; every other line refused default-deny with one fixed string." **True**,
  enforced on the parsed enum, arity-fixed; confirmed by the whitelist test and my smuggle test.
- "Fail-closed bind — no optimistic bind." **True**: the socket is created only after all four
  pre-bind checks pass.
- "The capability gate runs before the secret is touched, the ledger lock is taken, and any token
  byte is parsed." **True**: it is the first statement of `handle_enrollment_consume`.
- Opt-in, disabled by default, loopback-only unless explicit `--anchor-enrollment-allow-lan`.
  **True.**
- "No new crypto, no new wire format, no attestation (§5 held)." **True** — the listener reuses the
  existing `enrollment consume` wire encoding and the existing token/ledger machinery.

**Overstated / needing a caveat:**

- Design §5/§7: responses "leak neither secret material nor ledger state." Narrowly **true as
  written** (no key material, no ledger contents), but it leaves the impression of "discloses
  nothing," whereas a few error arms surface a local **filesystem path** via `{err}` on mid-run I/O
  failure — finding F2. Low severity, gated behind allow-lan, recommended for the hardening
  follow-up.

**Not overstated:** the phase-1 note counts "11 tests" for the D-3 enforcement point; the listener
work in fact adds 16 `rustynetd` tests plus 5 `rustynet-control` tests — if anything the count is
conservative. I independently re-ran them rather than trusting the report.

**Could not break it.** Across the pre-auth parser, the verb whitelist, the authentication ordering,
the burn concurrency, the two TOCTOU windows, and the fail-closed error branches, I found no path to
admit an unauthorized operation, burn a token twice, bypass the capability gate, panic the daemon on
hostile bytes, or extract a token oracle. The two vectors I probed that the author had not explicitly
covered (exact cap boundary; smuggled second verb) both held, and their regression tests are now on
the branch.

## Final verdict

**PASS. No unresolved MEDIUM-or-above finding remains.** The residual items (F1 INFO, F2 LOW, F3 LOW,
F4 INFO, F5 INFO) are all accepted with the reasons recorded above and none blocks enabling
`--anchor-enrollment-allow-lan`. The independent adversarial pass the bundle-pull precedent requires
is satisfied.
