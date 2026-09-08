<!-- Independent senior audit of MultiAgentSecurityReview_2026-09-08.md, performed
     2026-09-08 on branch ai-edit/edit-1788861037660-84155-0 at base commit 1a7d0ce7.
     Every verdict below was reached by reading the cited code in this tree, not by
     accepting the review's assertions. Sub-claims I could not verify in reasonable
     time are marked UNVERIFIED rather than agreed. This document changes no code. -->

# Audit of the Ten-Dimension Multi-Agent Security Review (2026-09-08)

**Audited document:** `MultiAgentSecurityReview_2026-09-08.md` (317 lines, committed at `1a7d0ce7`).
**Question answered:** are the surviving findings TRUE and the conclusions SOUND — before the owner spends engineering time on them?
**Method:** re-verified 7 of the 28 surviving findings from the code (all four High, plus the three verification-layer Mediums the systemic headline rests on: M4, M8, M9). Looked for compensating controls the review might have missed, in both directions.

---

## 1. Verdict

**The review's surviving findings hold. All seven findings I re-checked from code were confirmed, with accurate bounds. My refutation rate is 0/7, against the Claude round's 12/41 (29%) at filing time — the two rounds triangulate: the refutation layer did its job, and the survivors are credible.**

The headline split — "production security core in good shape, verification machinery is not" — is justified by my own reading, and in one respect understated (H3, below). The review's own §5 coverage note is honest; it neither overclaims clean areas nor hides the static-only method.

Two nuances the owner should carry forward:

1. H4 is a High for the *evidence ledger*, not for shipped binaries — the `vm-lab` cargo feature is default-off (RNQ-17) and the stage never ships. Grading it as a product-security High would misdirect.
2. H1's Severity is correctly bounded by posture: it is not reachable in the genesis default (one Owner at quorum 1), and the physical blind_exit node still fails closed at role-alignment validation. What is rewritten is the mesh-wide signed record — which is bad enough, and is exactly what SecurityMinimumBar forbids.

---

## 2. Part 1 — the four High findings, re-verified from code

### H1 — owner-signer list omits `AddNode`/`RemoveNode` — **CONFIRMED (High)**

My own evidence, independent of the review:

- `crates/rustynet-control/src/membership.rs:463-471` — `requires_owner_signer` matches exactly `RotateApprover | SetQuorum | SetNodeCapabilities | RotateNodeKey`. No `AddNode`, no `RemoveNode`.
- `:1956-1958` — the sole enforcement point: `if signed_update.record.operation.requires_owner_signer() && !owner_signed { Err(OwnerSignatureRequired) }`. A quorum-signed `AddNode`/`RemoveNode` never needs the owner.
- `:2069-2092` — the `AddNode` reducer pushes the full node record (capabilities AND `node_pubkey_hex`, the two things the guard's own doc comment at `:449-457` names as owner-worthy), refusing only `BlindRelay`.
- `:2126-2132` — `RemoveNode` is a bare `retain`.
- `:2111-2115` — `SetNodeCapabilities` enforces blind_exit immutability. The remove-then-re-add round trip bypasses it: same `node_id` re-enters via `AddNode` with any capability set.
- CLI reachability verified: `crates/rustynet-cli/src/main.rs:5844-5867` (`propose-add`, accepts arbitrary `--capabilities`) and `:5869-5881` (`propose-remove`).
- Document basis verified: `documents/SecurityMinimumBar.md:502-505` — "Capability changes require owner signature … Local-only acceptance of capability changes is forbidden." A remove+re-add IS a capability change to an existing identity; the bar is violated in letter, not just spirit.

Bounds re-checked and accurate: genesis mints one Owner at `quorum_threshold: 1` (`crates/rustynet-control/src/enrollment.rs:311-315`), so every default quorum includes the owner; reaching a vulnerable approver set itself requires owner-signed `RotateApprover`/`SetQuorum`. The attacker is therefore a colluding authorized quorum — privileged insiders, not outsiders. The daemon-side compensator exists as claimed: `validate_node_role_membership_alignment` (`daemon.rs:2357`, branching on `is_blind_exit()` at `:2378`) keeps a locally-blind_exit node from serving anchor-carrying membership. The damage is to the signed mesh record, which every peer trusts.

**Judged split fix: correct and safe, with two additions.** Restricting owner-free `AddNode` to exactly `{Client}` and requiring the owner for privileged capabilities or a reused `node_id` matches both the threat and SecMinBar. The CLI already defaults to `Client` when `--capabilities` is omitted (`main.rs:5851-5854`), so enrollment ergonomics survive. My additions: (a) enforce the split in the **reducer**, not only at the CLI/propose layer — RSA-0009's recorded lesson is that enforcement living outside the trust boundary is not enforcement; (b) tombstoning must key on the `(node_id, node_pubkey_hex)` pair, so a removed identity cannot re-enter even via a quorum that never saw the owner — otherwise the tombstone is replayable against a later re-enrollment.

### H2 — Windows runner discards exit status — **CONFIRMED (High)**

- `crates/rustynetd/src/daemon.rs:3733-3757` — `WindowsHostWireguardRunner::run_capture` builds the return from stdout/stderr only; `output.status` is never read. The shared return struct `WireguardCommandOutput` (`linux_command.rs:71-75`) has **no status field**, so the blindness is structural, not a forgotten `if`.
- `daemon.rs:3728-3731` — `run()` is `let _ = self.run_capture(...)?`, so every mutating command inherits it.
- Sibling contrast verified: `LinuxCommandRunner::run_capture` (`linux_command.rs:105-117`) returns `Err` on `!output.status.success()`; the privileged-helper runner at `daemon.rs:3704-3722` checks `output.success()`.
- Consequence verified structurally: `windows_command.rs:500-529` — `remove_peer` runs the blind `wg set … peer … remove` at `:517-526`, then `self.peers.remove(node_id)` at `:527`, defeating the invariant its own comment at `:506-508` states. `sync_persistent_config` rewrites disk but does not restart the tunnel service, so the live tunnel keeps serving the revoked peer's allowed_ips.
- Production wiring verified: `daemon.rs:4028-4037` constructs `WindowsWireguardBackend::new(WindowsHostWireguardRunner, …)` on the `--backend windows-wireguard-nt` path.

The caution about idempotent deletes is correct: `netsh … delete` and `wireguard.exe /uninstalltunnelservice` exit non-zero when the object is already absent, so a naive status check would convert cleanup into spurious failures. The review's fix (absent-is-success handling at those exact sites) is the right shape.

Severity: High on the Windows path specifically — it is a production backend, on the platform with the least live-lab coverage, and the failure direction is "wrongly reports success." Reachability requires a real command failure (route race, service stall), which is exactly when correctness matters.

### H3 — Windows silently downgrades `blind_exit` to full NAT, then blesses it — **CONFIRMED, and slightly UNDERSTATED by the review (High)**

- `phase10.rs:6568-6581` — `WindowsCommandSystem::apply_nat_forwarding` takes `_blind_exit: bool` and drops it; when `serve_exit_node` it calls `apply_windows_exit_nat_forwarding` unconditionally.
- Linux branches correctly on the flag (`phase10.rs:3334-3349` → `apply_linux_blind_exit_locked`), as does macOS (`:5138-5165`, explicit `serve_exit_node && blind_exit` branch). Verified both.
- `assert_exit_serving` (`:6849-6878`) requires `nat_applied`, `WINDOWS_PS_ASSERT_NAT`, and forwarding enabled on both the tunnel and underlay NICs — i.e. it demands the full-NAT posture, so the stage passes *because* the posture is inverted. Verified.

Reachability — the hard part — verified end-to-end, and it is **worse than the review states**:

- Installer: `scripts/bootstrap/windows/Install-RustyNetWindowsService.ps1:11` declares `[string]$NodeRole = 'client'` with no `[ValidateSet]`, threaded into `--node-role` at `:744`/`:756` and into `RUSTYNETD_DAEMON_ARGS_JSON` at `:778`. Verified.
- Service host: `windows_service.rs:197-224` parses the env file's daemon args as a raw JSON array; `resolve_windows_backend_request` (`:285-340`) only classifies backend arguments — no role validation anywhere on this path. Verified.
- **Additional evidence the review did not cite:** the daemon's *own* startup gate also passes. `validate_node_role_backend_capabilities` (`daemon.rs:13582-13612`) rejects `BlindExit` only when the backend lacks `supports_exit_nodes`/`supports_exit_serving` — and `WindowsWireguardNt` declares both `true` (`daemon.rs:13554-13558`). So `rustynetd daemon --node-role blind_exit --backend windows-wireguard-nt` is accepted even without the env-file path. The only rejections live in the operator config layer (`rustynet-operator/src/role.rs:90-122`, `config/validate.rs:373-378`), which this path bypasses entirely.

The doc/code drift claim (`CrossPlatformRoleParityRefresh_2026-07-23.md:427` asserting a main.rs hard error that does not exist) is consistent with what I found — no such hard error exists in `rustynetd/src/main.rs`.

Severity: High. The role is irreversible by design; a silent downgrade to a *broader* posture (full masquerading NAT with underlay forwarding) that the assertion then reports as green is the worst failure direction available. Fix as proposed: fail closed on `blind_exit` in the Windows arm plus `ValidateSet` on the installer parameter — both cheap, both correct.

### H4 — `traffic_test_matrix` drops its collision guard at the deadline — **CONFIRMED (High for evidence integrity; Medium for shipped security)**

- `traffic_test_matrix.rs:66` — `if (!has_collision && !has_missing) || Instant::now() >= deadline`: at deadline the colliding map is committed regardless; `has_collision` (computed at `:63`) is never used again. Verified.
- The asymmetry is real: a *missing* IP fails closed downstream (`:121-126` pushes "no mesh IP"), but a *collision* leaves a fully populated map.
- The ping loop skips only `peer_alias == src_alias` (`:117-120`) — it never compares `peer_ip` to the source's own address, so every node ends up pinging the duplicated address. With the killswitch's loopback accept, that self-address ping succeeds, `src_reached_peer` flips true, and the default-deny probe is judged conclusive — `:206-207` returns `Passed`. Verified.
- The pass path writes no evidence artifact (capture is failure-arm only, `:209+`). Verified.

Severity, restated for the owner: nothing here ships — the stage lives under the default-off `vm-lab` feature. The victim is the live-lab evidence ledger the release gate reads, i.e. the same class as the QH-07 contamination. Spend the twenty lines (fail on collision at deadline; refuse self-IP targets; write evidence on pass) — but grade it as ledger integrity, not node security.

---

## 3. Part 2 — the systemic claim: "a claim of 'proven' is worth less than it reads"

**Judgment: JUSTIFIED — and marginally understated.** The three findings I was asked to verify as the load-bearing samples all check out from the code, and the H3 finding above adds an instance the review itself did not fully excavate (the daemon's own capability gate blessing `blind_exit` on Windows).

**M8 — vacuous named-test gate — CONFIRMED.** `run_logged_test` (`ops_ci_release_perf.rs:2040-2066`) checks only `output.status.success()` at `:2057`; its callers pass hardcoded test names with `--exact` (`probe_security_tests` at `:1247+`, `backend_tests` at `:1302+`). A `cargo test` filter matching zero tests exits 0 — the gate cannot notice a renamed or deleted test. The repo's own correct implementation exists and is unused here: `execute_ops_verify_required_test_output` (`ops_phase9.rs:4859+`) fails when `total_passed < 1`. (The further claim that these reports fold into the phase10 signed-provenance set at `ops_phase9.rs:2296`/`:4430` I verified only structurally — the report-table shape is there — so that sub-claim is UNVERIFIED in its end-to-end form, though it changes nothing about the finding.)

**M9 — blind_exit Linux proof passes on any non-empty stdout — CONFIRMED.** `blind_exit.rs:69-79` — the Linux arm runs `iptables -t nat -L POSTROUTING || nft list ruleset` and fails only on *empty* stdout; under `sudo -n` both commands always emit at least a chain header or the ever-present killswitch table, so the guard cannot fire. The probe is also semantically inverted: a correct blind_exit must carry **no** NAT translation, so listing POSTROUTING measures nothing. The macOS arm (`:80-96`) demands pf NAT rules be *present* — the same inversion. The negative test at `:190` feeds `stdout: Vec::new()`, an output the real command cannot produce, so it survives deletion of the guard. Verified.

**M4 — RSA-0008 gate is dead code — CONFIRMED.** `rustynet-control/src/lib.rs:3510` gates the revocation clause behind `is_populated()`; the only callers of `set_membership_directory` are five test-module sites (`lib.rs:8090-8177`); the three shipped issuance sites are bare `ControlPlaneCore::new` (`rustynet-cli/src/main.rs:6854`, `:6961`, `:7052`); the test at `:8063` (`rsa0008_empty_membership_directory_preserves_issuance`) pins the bypass as intended. The duplicate-status claim also checks out: `AdversarialSecurityReview_2026-07-29.md:394` already records "the RSA-0008 issuance gate **never runs**" and `:408` "rests on a gate that is in fact never active." The daemon-side compensator is real and production-wired: `check_peer_membership_active` (`phase10.rs:8846-8860`, called at `:7725`) denies Revoked/Unknown with no `is_populated` escape.

### The smallest set of changes that makes a green run mean something

Ordered by leverage per line of code:

1. **Evidence-on-pass rule.** A stage that records `Passed` must write the data artifact behind the verdict on the pass path; a stage with no evidence file is `NotProven`. One wrapper change in the stage framework closes H4's silent-green, the M9 shape, L10, and the QH-07 contamination class at the point of writing.
2. **Vacuous-filter kill.** Make `run_logged_test` parse the harness summary and require `N ≥ 1` passed — the parser already exists (`ops_phase9.rs:4859`); reuse it. This converts M8 from "gate that cannot fail" to "gate".
3. **Self-proof kill for source pins.** The meta-test the review proposes in §3.A: fail any `include_str!` pinning its own file unless sliced before `#[cfg(test)]` (the in-repo remedy at `windows_install.rs:2101` and `rustynet-crypto/src/lib.rs:2323` already demonstrates it), plus a one-time mutation sweep of the existing pins. Two of the three pinned defects were proven green with the guarded line deleted — until this lands, every "pin" test in the repo is a claim, not a check.
4. **Ledger discipline check.** A remediation entry may not be marked DONE unless `git show --stat <cited-commit>` includes the file the finding names. The PF-05 pattern (marked DONE at `8417edf1`, which never touched `phase10.rs`) silently removes live findings from every future search.
5. **Collision/self-IP guards in `traffic_test_matrix`** (the H4 fix) — included in item 1's rule, listed separately because it is the one live contamination source today.

Items 1-3 are roughly a day of work combined and are the difference between "green" and "measured."

---

## 4. Part 3 — what the ten dimensions did not reach

The review's own §5 honestly lists execution, crypto-protocol correctness, supply chain, the excluded crates, and concurrency/DoS. These are real, and I do not repeat them. What follows are gaps **beyond** that list:

1. **Hostile-input wire parsing — the internet-facing surface.** No dimension owned "a remote peer controls the bytes." The STUN client response parser (`rustynetd`'s `stun_client.rs`), ICE candidate parsing, gossip envelope decode at the transport boundary, relay frame demux in `rustynet-relay`, and DNS response handling in the loopback resolver all parse data that an on-path attacker or malicious mesh peer can shape. The panics dimension hunted panics statically and repo-wide; the fuzz targets compile but were never run. This is the highest-value next review: custom binary parsing, remotely reachable, on the least-examined paths. `rustynet-netns-probe`'s STUN wire is byte-pinned to `stun_client.rs`, so a defect there has two consumers.
2. **The CI pipeline's own trust boundary.** The review audited gate *semantics* (vacuous passes) but not the pipeline that runs them: `.github/workflows` YAML (workflow-trigger confusion, untrusted env expansion into `scripts/ci/*.sh`), and shell quoting across the gate scripts themselves. Given the review's own verdict that the verification layer is the weakest part of the repo, the layer's own supply chain is unexamined.
3. **The MCP servers and the lab robot's privileged execution.** `rustynet-mcp-lab-state` / the `vm-lab` CLI construct SSH argv to lab guests and spawn cargo/utmctl; the ai-agent server shells out to `security` and spawns `opencode serve`. This is trusted-operator tooling, but it is privileged execution with a documented stale-binary rot problem (§12.5) and no dimension covered it.
4. **The service-hosting hot paths.** `rustynet-nas` request handling and `rustynet-llm-gateway`'s tunnel-facing API got only key-flag scrutiny (L3). The NAS store TOCTOU (L9) hints at the shape; the request-parse paths are unaudited.

Review next, in order: (1) wire parsers — remote-reachable and unfuzzed; (2) CI/workflow integrity — cheap, and it hardens the exact layer this review says is weakest; (3) the service-hosting request paths.

---

## 5. Part 4 — calibration

- **Claude filing round:** 12 of 41 claims refuted (29%).
- **This audit, on survivors:** 0 of 7 re-checked findings refuted. All seven confirmed from code, with bounds holding under inspection; one (H3) *strengthened* — I found an additional reachable path the review did not cite. H4 alone took a severity regrade (evidence-integrity High, shipped-security Medium), not a refutation.
- **Implication:** the refutation layer earned its keep — what survived one adversarial pass also survived a second, independent, code-first pass. The owner should treat the surviving High/Medium set as actionable now, without a third re-verification round. The Lows I did not check (12 findings) keep their "read as genuinely low" status from the review; spot-audit them opportunistically when touched, not as a program.
- **Honesty note on where I agree:** all seven of my verdicts rest on code I read myself in this tree (every file:line in §2-§3 is my own observation). Two secondary sub-claims are marked UNVERIFIED in place (M8's provenance fold end-to-end; I also accepted the review's citation of `I4GossipImplementationHandoff` D5 on the H1 fix warning without opening that ledger, since it argues for *caution*, not for a change). Nothing in my verdicts rests on merely not contradicting the review.

---

## 6. What the owner should actually spend time on, in order

1. **H1 — the membership owner-signer gap.** Owner decision first (the split: owner-free `AddNode` limited to exactly `{Client}`; owner required for privileged capabilities or a reused `node_id`/pubkey pair; tombstoning keyed on the identity pair), then implement with the reducer as the enforcement point and the reproduction as a permanent negative test. It is the only finding at the root of trust, and the naive fix (blanket-add both arms) is a known trap.
2. **H3 — Windows `blind_exit` silent downgrade.** Fail closed in `apply_nat_forwarding`, mirror in `assert_exit_serving`, add `ValidateSet` to the installer. An hour of work protecting an irreversible role; the downgrade is blessed green today by the assertion.
3. **H2 — Windows exit-status blindness.** One struct field plus mirrored status handling with explicit absent-is-success sites for the idempotent deletes, plus the non-zero-status `remove_peer` test. Un-blinds the entire Windows backend before the next Windows lab campaign.
4. **The §3 minimal set (evidence-on-pass, vacuous-filter kill, self-proof kill for pins, ledger DONE discipline).** A day, in aggregate, that converts the evidence ledger from claims to measurements — the review's own "the finding that matters most."
5. **H4 — the collision/self-IP guards and pass-path evidence in `traffic_test_matrix`.** Twenty lines; do it inside item 4's rule rather than as a standalone.

**Drop / downgrade:** nothing in the High set is droppable. H4 should be re-labeled ledger-integrity rather than product-security. M4 needs an owner *disposition* (it is RSA-0008, already tracked) more than new code — the wiring fix is three lines at the CLI sites once the owner decides absent-directory means deny. The twelve Lows: queue items, not a program.

---

*Audit method note: this document records verdicts reached by reading code at commit `1a7d0ce7` in the isolated worktree `state/edit-worktrees/edit-1788861037660-84155-0`. No production code was modified. The audited review itself remains UNTRUSTED OUTPUT for any finding not independently verified here or elsewhere.*
