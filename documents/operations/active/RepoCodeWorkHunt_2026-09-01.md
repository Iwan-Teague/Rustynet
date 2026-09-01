# Repo Code Work Hunt — 2026-09-01

**Scope:** docs-only survey of production Rust code for genuine, offline-doable, untracked work. No `.rs` files were changed. Survey performed in worktree branch `ai-edit/edit-1788296017101-45994-16` at HEAD `233b19a0` (clean tree at survey start).

**Honest headline: the production code came back essentially clean.** After a full pass over the six hunt categories with per-hit open-and-read verification, there are no P1/P2 findings. Two P3 observations are recorded below, both low-risk. The bulk of this document is the *cleared-with-evidence* list: what was checked, what was found, and why each candidate was dismissed — so the next hunt does not re-derive these same readings. A negative result with a citable evidence trail is the deliverable here, not padding.

## Method and dedup

Every grep hit was opened and read in context before being judged; nothing was accepted on the grep line alone (a prior coverage-gap hunt misread a fail-closed test as a silent skip, so blind grep trust was off the table). Test code was separated from production code using the `#[cfg(test)]` / `#[cfg(all(test, ...))]` boundary, with a line-ordering awk pass per file — an early pass that matched only the bare `#[cfg(test)]` spelling produced false positives (117 "unwraps" in `privileged_helper.rs` that all live inside its `#[cfg(all(test, not(windows)))]` module), so all counts were re-taken with the compound-cfg-aware pattern.

The following already-tracked territory was excluded, per the dedup requirement:

- `QualityHardeningTodo_2026-07-25.md` (QH-01..QH-64): all items are tracked-open by default per the document's own status rule, except those explicitly marked FIXED/RESOLVED (QH-03, QH-04, QH-36, QH-37, QH-59, QH-63).
- `FullTodoInventory_2026-07-28.md` — the doc-by-doc catalog of `documents/operations/active/`.
- `SecurityAuditCatalogStalePathsTodo_2026-07-28.md` — the RSA-0049-class stale catalog paths (`dataplane.rs` deleted, `SecurityHardeningBacklog` moved).
- `TestQualityReview_2026-07-30.md` — gate/test-quality findings (§3–§10). This kept the hunt out of lab tooling, gate scripts, orchestrator stages, evidence ledgers, and test hermeticity, which is where the tracked open items concentrate.

Crates swept: `rustynetd`, `rustynet-control`, `rustynet-policy`, `rustynet-crypto`, `rustynet-backend-api`, `rustynet-backend-wireguard`, `rustynet-relay`, `rustynet-llm-gateway`, `rustynet-local-security`, `rustynet-dns-zone`.

## Findings (ranked)

### F-1 (P3) — LLM gateway: a granted peer with no scope entry is unrestricted by design; confirm this is the intended product semantics

- **Where:** `crates/rustynet-llm-gateway/src/enforce.rs:166-174` (`visible_models` — `scope.map(|s| s.permits_model(model)).unwrap_or(true)`), `:75` (`admit_request`) and `:125` (`record_tokens`) — all three treat `None` scope as unrestricted; `crates/rustynet-llm-gateway/src/main.rs:336` (`scope = scopes.get(node_id).cloned()` can be `None` for an admitted peer).
- **Why it matters (mildly):** a peer listed in `grants` but absent from the `scopes` file gets every model, no token quota, and no rate limit. This is *documented intended design*, not an oversight: the loader's doc comment (`main.rs:221-228`) states "a missing scopes file leaves grants unrestricted by documented design (scopes restrict, they never grant)", the malformed-scope lines fail closed (`main.rs:284-308`), and the tests codify it (`enforce.rs:197-209` `no_scope_admits_any_model_without_quota_or_rate`). Admission itself is default-deny (`main.rs:328-335` — a peer not in grants is refused outright).
- **Proposed action:** a product/security owner confirms that "grants gate admission, scopes are optional tighteners" matches the `llm` role requirement in `documents/Requirements.md`. If unbounded token spend by an granted-but-unscooped peer is unacceptable, the fix is small and offline: require a scope entry for every grant (or apply a conservative default quota when scope is absent), plus test updates.
- **Offline-fixable:** yes. **Needs adversarial review before implementation:** yes — this is an authorization-semantics change on a service-hosting role.

### F-2 (P3) — Whole-file `#![allow(dead_code)]` on two macOS backend files

- **Where:** `crates/rustynet-backend-wireguard/src/userspace_shared_macos/socket.rs:1` and `crates/rustynet-backend-wireguard/src/userspace_shared_macos/tun.rs:1`.
- **Why it matters (mildly):** a file-wide suppression hides genuinely unused helpers behind platform-conditional compilation, which is exactly where dead code accumulates unnoticed. The module itself is live (`lib.rs:10` declares it; `lib.rs:27` re-exports `MacosUserspaceSharedBackend`), so this is hygiene, not breakage. All other `dead_code` hits in the sweep were the normal per-item `#[cfg_attr(not(windows|test), allow(dead_code))]` cross-platform pattern and are fine.
- **Proposed action:** narrow the file-level attribute to the specific items that need it (they are almost certainly the non-macos-platform builds of shared code), so future unused items surface. A few spare `#[allow(dead_code)]` items in `rustynetd` (`key_material.rs:881`, `linux_killswitch_boot.rs:609`, `linux_dns_failclosed.rs:314`, `phase10.rs:5199/8229/8244/8266`) can be reviewed in the same pass.
- **Offline-fixable:** yes. **Needs adversarial review:** no.

## Cleared with evidence (so nobody re-reads these)

- **Markers (cat 1):** no `TODO`/`FIXME`/`XXX`/`HACK`/`unimplemented!(`/`todo!(` in production code anywhere in scope. The sole grep hit, `secret_log_audit.rs:1729`, is quoted fixture text inside the secret-scanning audit tool, not a marker. The remaining `unreachable!` sites are test-only closure stubs in `relay_client.rs`, an exhaustive `IpAddr::V6(_)` arm at `stun_client.rs:1182`, a test at `membership.rs:3461`, and an audit-gate string literal at `daemon.rs:19891`.
- **unwrap/expect (cat 2):** all production-path instances are either (a) length-guarded fixed-size slice conversions — `relay/main.rs:1720,1722` behind the `pos + 16 > data.len()` guard at `:1717`; `peer_gossip.rs:769-803` behind the truncation check at `:755`; (b) locally provable invariants — hex alphabet at `rustynet-control/src/membership.rs:2831` and `rustynet-dns-zone/src/lib.rs:876`, HMAC accepting any key length at `enrollment_token.rs:226`; or (c) one-shot CLI report serialization — `rustynetd/src/main.rs:283`, `:2826`, static-socket parse at `windows_killswitch_smoke.rs:476`, static default binds in `rustynet-relay/src/main.rs:193,2260`. `rustynet-policy/src/lib.rs` and all of `rustynet-control` are clean outside test modules (verified with the compound-cfg-aware pass). The style asymmetry in the relay token parser (timestamps unwrap, nonce/signature `map_err`) is cosmetic only.
- **Fail-open shapes (cat 3):** every `unwrap_or_default` / `let _ =` candidate lands in the fail-closed direction or is best-effort with the primary error still propagated: `service_exposure.rs:313` defaults to `serves_nas:false/serves_llm:false` (fail-closed); `macos_dns_failclosed.rs:385-396` defaults observability flags to `false` (fail-closed, per its own doc comment at `:400-404`); `linux_exit_dns_failclosed.rs:130,181` are evidence-capture reports, not gates; `key_rotation.rs:1068` is inside the test fault-injection helper; `peer_traversal_prior.rs:180` defaults traversal hints to empty; `rustynet-crypto/src/lib.rs:645-654` best-effort keychain unlock is followed by an error-checked `set_generic_password` and a CLI fallback; `lib.rs:697` delete-then-add keeps the add as the error surface; `windows_command.rs:448` and `linux_command.rs:552` are rollback/teardown paths where the original error is returned regardless. A discarded-result sweep (`x.ok();` / `x.is_ok();` as statements) found nothing.
- **`llm` gateway state loader** fails closed on unreadable/malformed state (`main.rs:229-236`, `:284-308`) and admission is deny-by-default — the only open design question is F-1 above.

## Honest limits of this pass

- Category 5 (doc-comment vs. behavior drift) was sampled, not exhausted: the files read end-to-end (`llm-gateway` enforce/main, relay token parse, peer gossip wire parse, service exposure, macOS DNS snapshot builders) show accurate comments, but a systematic drift audit over every module doc comment was not performed.
- No correctness-smell sweep of hot-path `.clone()` usage or comparison ordering was done beyond the files read; nothing suspicious surfaced in those.
- `rustynet-windows-native` was not included in the per-file unwrap re-count sweep.
- No gates were run (docs-only survey; no code changed), so nothing here claims to compile-or-fail — all claims are read-level observations with file:line citations.

## Suggested next steps

1. Route F-1 to a product/security decision (small doc-or-code change either way).
2. Fold F-2 into any future hygiene pass on the backend crates; it does not warrant its own change on urgency.
3. If a deeper hunt is wanted, the un-sampled areas above (systematic doc-drift audit, windows-native sweep, hot-path clone audit) are the remaining ground — everything else in these six categories is now cleared on the record.
