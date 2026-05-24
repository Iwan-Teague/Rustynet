# Rustynet Security Review (2026-05-24)

Status: active security-review ledger. Firm-grade security assessment of the
Rustynet workspace, focused on the privileged boundary and broadly across the
security-sensitive surface. Produced from six parallel domain reviews plus
first-hand verification of the load-bearing findings.

> Scope note: line numbers are indicative (captured against `main` at
> 2026-05-24) and must be re-confirmed when remediating. Findings marked
> **[verified]** were confirmed first-hand during this review; others are
> domain-review findings that should be reproduced before fix sign-off.

## 1. Methodology & scope

Six independent domain reviews were run against current `main`, each tasked to
find real, exploitable weaknesses (not style), rate severity, cite `file:line`,
give an attacker model, and propose remediation:

1. Privileged execution boundary & process exec (`privileged_helper.rs`, all `Command::new`).
2. Cryptography & key custody (`rustynet-crypto`, `rustynet-local-security`, `key_material.rs`).
3. Signed trust state, authn/authz, anti-replay/rollback (`rustynet-control` membership, `key_rotation`, `enrollment_token`, gossip, traversal, `dns-zone`).
4. Untrusted-input parsing & IPC/control surface.
5. Dataplane fail-closed / killswitch / default-deny policy & leak prevention.
6. Secret hygiene/logging, supply chain, build/config hardening, residual shell.

The prior `SecurityHardeningAudit_2026-04-28.md` was used as context; this pass
is fresh and calls out net-new findings and any regressions.

### Severity scale
- **High** — exploitable or assurance-breaking on a realistic path (remote/authenticated DoS, traffic leak, fail-open of a security control, or a control that does not actually run).
- **Medium** — meaningful weakness requiring specific conditions, or a fail-open default contradicting the stated mandate.
- **Low** — narrow / defense-in-depth / latent (no current attacker path).
- **Info** — hygiene, coverage-completeness, documented-partial.

## 2. Headline

The security-critical core is, on the whole, **strongly engineered**: the
privileged helper is a model argv-only allowlisted boundary; crypto uses vetted
primitives with Argon2id at OWASP params, fail-closed CSPRNG, and redacting
`Debug`; the signed-trust core verifies-before-mutate and consults watermarks
before accept; most network parsers are bounded and panic-free; there are no
secret leaks into logs.

The findings cluster in three places: (1) a **High remote/authenticated DoS** in
the membership decoder, (2) a set of **dataplane fail-closed / leak-prevention
gaps** where the audited module is dead code, error paths fail open, and the
Windows killswitch is materially weaker than Linux, and (3) **build/supply-chain
integrity** gaps. None are pre-auth RCE; the most urgent are the DoS and the
fail-open/leak items because they defeat the project's central fail-closed
guarantee.

### Findings tally

| Severity | Count |
|---|---|
| High | 7 |
| Medium | 9 |
| Low | 17 |
| Info | 5 |

| Domain | High | Medium | Low | Info |
|---|---|---|---|---|
| Privileged boundary | 0 | 0 | 4 | 3 |
| Crypto & key custody | 0 | 2 | 4 | 1 |
| Trust & anti-replay | 0 | 1 | 2 | 1 |
| Untrusted input & IPC | 1 | 0 | 0 | 0 |
| Dataplane fail-closed | 5 | 3 | 3 | 0 |
| Secret hygiene & supply chain | 1 | 3 | 4 | 0 |

## 3. High-severity findings

### RN-01 — Unbounded `Vec::with_capacity` from attacker-controlled count in the membership decoder (DoS) **[verified]**
- **Domain:** Untrusted input · **CWE-789 / CWE-1284 / CWE-400** · **Confidence: High**
- **Location:** `crates/rustynet-control/src/membership.rs:1203, 1230, 1276`; `parse_usize_field:1553` (bare `.parse::<usize>()`, no cap).
- **Description:** `node_count`, `approver_count`, `sig_count` are read from the text body and passed straight to `Vec::with_capacity(count)` before validation or signature checks. No upper bound and no field-count cross-check. Verified: there is no max-count constant in `membership.rs`, in direct contrast to the sibling `rustynet-dns-zone` parser which caps `record_count > MAX_RECORD_COUNT` and cross-checks `fields.len()` before allocating.
- **Impact / scenario:** `node_count=18446744073709551615` → capacity-overflow panic (process abort); `node_count=100000000` → ~13 GB request → allocation abort. Reachable two ways: (a) authenticated IPC `membership apply <b64>` (`daemon.rs:7141`) — the 4096-byte command cap is no protection since `sig_count=99999999999` is ~22 bytes, and the crash precedes signature/quorum checks; (b) an attacker-influenceable on-disk snapshot — its integrity gate is an **unkeyed SHA-256** over the payload, so a malicious `node_count` with a matching digest crashes the daemon at next decode, defeating fail-closed startup.
- **Remediation:** Add `MAX_MEMBERSHIP_NODE_COUNT` / `_APPROVER_COUNT` / `_SIG_COUNT` constants and reject oversized counts before allocation; add the `fields.len() == expected_field_count` cross-check (mirror dns-zone). Defense-in-depth: use `Vec::new()` + `push`. Add negative tests and structured seeds to the two membership fuzz targets (the count fields sit behind a `version` gate, which is why fuzzing hasn't reached them).
- **Status: FIXED 2026-05-24** — see Remediation log RL-1.

### RN-02 — The audited dataplane module (`dataplane.rs`) is dead code; its killswitch/ACL/fail-closed controls never run **[verified]**
- **Domain:** Dataplane · **CWE-1164 / CWE-684** · **Confidence: High**
- **Location:** entire `crates/rustynetd/src/dataplane.rs` (`LinuxDataplane`, `ensure_egress_allowed`, `ensure_dns_allowed`, `select_exit_node`, `ensure_lan_route_allowed`, `HandshakeFloodGuard`).
- **Description:** Verified: `LinuxDataplane` is referenced only inside `dataplane.rs`'s own `#[cfg(test)]` block (and one string in `security_audit_catalog.rs`). No production code constructs it. The live dataplane is `phase10.rs` (`Phase10Controller` + `LinuxCommandSystem`), which carries a *parallel* implementation. (Note `phase10::LinuxDataplaneMode` is a different type from `dataplane::LinuxDataplane`.)
- **Impact:** Anyone validating the killswitch by reading/testing `dataplane.rs` is validating code that does not execute; divergence from the live path (it already exists — see RN-06/RN-12) is invisible to those tests. This is an assurance failure: the control surface being reasoned about is not the one enforcing.
- **Remediation:** Either delete `dataplane.rs` (and its catalog reference) or wire the daemon through it. Point the security-audit catalog and tests at the live `phase10.rs` enforcement.

### RN-03 — Fail-open inverse: `force_fail_closed(...)` results discarded; a failed killswitch on first bootstrap leaves the host open **[verified]**
- **Domain:** Dataplane · **CWE-636 / CWE-252** · **Confidence: High**
- **Location:** `crates/rustynetd/src/daemon.rs` — 10 confirmed `let _ = …force_fail_closed(…)` sites (of 39 total call sites); `force_fail_closed`→`block_all_egress`→`ensure_failclosed_table` at `phase10.rs:4116/2146`.
- **Description:** When trust/membership/key state is missing/invalid/stale the daemon intends to fail closed, but at least 10 sites discard the `force_fail_closed` Result with `let _ =`. If `block_all_egress` fails (nft unavailable, helper socket down, transaction race) the error is swallowed and the routine `return`s. (Calibration: the original review said "every site"; the precise count of discard-on-error sites is 10 — confirm each during fix.)
- **Impact / scenario:** Mitigated when a generation killswitch table already exists (it carries `policy drop`). The dangerous case is **first bootstrap** (state `Init`): trust fails before any killswitch table was created, `ensure_failclosed_table` is the thing that would create it, it errors, the Err is dropped → no table, no `policy drop`, all host traffic egresses cleartext while the daemon believes it is restricted.
- **Remediation:** Never discard the fail-closed Result. On error, escalate hard — log error, increment a hard-fail counter, and either terminate (so the boot killswitch backstops) or retry `block_all_egress` with backoff while refusing to serve. Pair with RN-04.

### RN-04 — Bootstrap leak window: tunnel interface + routes are brought up before the killswitch is programmed
- **Domain:** Dataplane · **CWE-696 / CWE-362** · **Confidence: High**
- **Location:** `phase10.rs:3832` (`backend.start()` brings up `rustynet0`) and `:3967/3971` (route apply) precede `:3977` (`apply_firewall_killswitch`).
- **Description:** Apply order is backend-up → configure peers → apply routes → *then* killswitch. On a fresh `Init` host with no prior generation table and without the opt-in `ExecStartPre` boot killswitch, there is a window with a live tunnel + installed routes but no `policy drop`. If `apply_firewall_killswitch` fails or the process is killed in between, the host has routes but no drop policy.
- **Impact / scenario:** Default route may already point at the tunnel while non-tunnel-bound sockets/established flows egress via the physical NIC unfiltered. `linux_killswitch_boot.rs` documents exactly this shape but is opt-in.
- **Remediation:** Program the `policy drop` killswitch before `backend.start()` and route apply; make the `linux_killswitch_boot.rs` `ExecStartPre` installer mandatory in the shipped unit and refuse to start the backend if the boot killswitch table is absent (the verifier already exists — gate on it).

### RN-05 — Policy engine default-allows any selector not prefixed `node:` (revocation bypass for group/user/tag/CIDR rules) **[verified]**
- **Domain:** Dataplane/policy · **CWE-284 / CWE-280** · **Confidence: High**
- **Location:** `crates/rustynet-policy/src/lib.rs:305-313` — `selector_membership_allowed` returns `true` for any selector where `strip_prefix("node:")` is `None`.
- **Description:** Verified: the membership/revocation gate only consults membership for `node:`-prefixed selectors. `user:`/`group:`/`tag:`/raw-CIDR/`*` selectors skip the gate and proceed to rule eval. The daemon's `policy_gate_auto_tunnel` uses `src=subject` (a `user:`-style string), so the source side of every auto-tunnel decision is never membership-checked.
- **Impact / scenario:** A **revoked** node still matching a `group:`/`tag:`/`user:` allow rule is permitted — revocation is silently ineffective across the entire non-`node:` rule surface.
- **Remediation:** Resolve group/tag/user selectors to their constituent node set and deny if any required member is revoked/unknown, or forbid trust-sensitive rules whose source identity can't be mapped to a membership-checked node. Add negative tests for revoked identity expressed via each selector type.

### RN-06 — Windows killswitch allows ALL non-DNS outbound on physical LAN interfaces
- **Domain:** Dataplane (Windows) · **CWE-1188 / CWE-284** · **Confidence: High**
- **Location:** `phase10.rs:3184` → `windows_firewall_allow_interfacetype_args:5248` (`interfacetype=lan action=allow`); DNS-only block `windows_dns_block_lan_args:5266` (port 53 only).
- **Description:** The Windows killswitch sets global `blockoutbound` but then opens `interfacetype=lan` to all outbound, forcing only DNS (port 53) through the tunnel. Linux drops everything except `oifname <tunnel>` + the WG UDP port; Windows has no equivalent restriction.
- **Impact / scenario:** Full-tunnel Windows client; if WireGuard-NT default-route injection fails/flaps/tears down (roaming, adapter reset, metric flap), TCP/443, QUIC, etc. egress cleartext via the LAN NIC. Only DNS is protected. Real-traffic leak, not metadata.
- **Remediation:** Scope the Windows LAN egress allow to exactly what bootstrap needs (WG UDP to peer/relay endpoints + STUN + management), mirroring Linux's narrow allow; everything else hits the global block. Don't treat routing as the killswitch.

### RN-07 — Windows IPv6 leak: "disable IPv6" only suppresses RA; native IPv6 egress still permitted
- **Domain:** Dataplane (Windows) · **CWE-636 / CWE-284** · **Confidence: High**
- **Location:** `phase10.rs:3343` → `windows_ipv6_egress_disable_args:5301` (`routerdiscovery=disabled advertise=disabled` only).
- **Description:** Linux kills IPv6 at the stack (`disable_ipv6=1`) and uses an `inet` killswitch (drops v4+v6). Windows only turns off RA/router-discovery on the egress adapter — it does not remove existing/static/DHCPv6 addresses, doesn't block IPv6 egress, and there is no IPv6 firewall block. Combined with RN-06's allow-all LAN, any configured global IPv6 keeps egressing.
- **Impact / scenario:** Dual-stack network, host already holds a global IPv6 address; Happy-Eyeballs apps send over IPv6 straight out the LAN NIC outside the tunnel, never hitting the killswitch; DNS-over-IPv6 also bypasses the IPv4 port-53 block.
- **Remediation:** Add an explicit IPv6 outbound block (advfirewall block for non-tunnel `::/0`, or unbind IPv6 on the egress adapter), flush autoconfigured global addresses, and verify in `assert_killswitch`.

## 4. Medium-severity findings

### RN-08 — Encrypted-key envelope does not bind salt/nonce/version via AAD
- **Domain:** Crypto · **CWE-353** · **Confidence: High**
- **Location:** `rustynet-crypto/src/lib.rs:942-943, 969-970` (empty AAD); blob framing `:1097-1128` (no magic/version).
- **Description:** XChaCha20-Poly1305 authenticates only the ciphertext; the stored 16-byte salt and 24-byte nonce are not fed as AAD, and the on-disk frame has no magic/version byte (weaker than the Windows passphrase blob which has both). Tampering still fails decryption (wrong key derived), so this is not a confidentiality break — it's a versioning/algorithm-agility gap that could enable downgrade/confusion if a second format is added without an authenticated version.
- **Remediation:** Bind `MAGIC || version || salt || nonce` as AAD; add a magic+version prefix validated before decryption (match the Windows blob discipline).

### RN-09 — systemd-credential passphrase files may be group-readable, gated only by a path prefix
- **Domain:** Crypto/key custody · **CWE-732** · **Confidence: Medium**
- **Location:** `rustynetd/src/key_material.rs:140-141, 550-563`; `is_systemd_credential_path:674` (`starts_with("/run/credentials/")`).
- **Description:** For files under `/run/credentials/`, the permission mask is widened from `0o077` (owner-only) to `0o037` (permits group-read) and root ownership is accepted. The only gate is the path prefix — it does not verify the parent is the systemd-managed `0700` per-unit mount, the fs is tmpfs, or the group is a trusted gid.
- **Impact / scenario:** If the passphrase path is influenceable by a less-trusted orchestration layer, a root-owned `/run/credentials/<x>/wg_key_passphrase` at mode `0o640` with a shared group lets a process in that group read the WireGuard passphrase that gates the node private key.
- **Remediation:** Require the parent dir to be uid-0 + `0o700` and the file's group to be a reviewed gid (0 or daemon gid) before honoring the wider mask; ideally verify tmpfs.

### RN-10 — Corrupt rotation ledger silently resets to genesis instead of failing closed
- **Domain:** Trust/anti-rollback · **CWE-636 / CWE-665** · **Confidence: High**
- **Location:** `daemon.rs:8082-8105` (`load_rotation_ledger`) — on any `RotationError` it logs and returns `LocalKeyRotationLedger::genesis()` and proceeds.
- **Description:** The function's own doc comment says corrupt ledger state "must not be silently reset" and the caller should surface the error before key-bearing operations; the implementation does the opposite. A corrupt/truncated/tampered ledger resets `current_epoch` to 0, empties the verifier archive, and clears per-epoch replay watermarks. Contradicts CLAUDE.md §3/§4.
- **Impact / scenario:** Local attacker/fault that can corrupt the `.rotation_ledger` rewinds the rotation epoch on next start. Direct forgery is still blocked downstream (`verify_epoch_tagged_bundle` rejects unknown epochs), so blast radius is contained, but it's a genuine fail-open on a security-state file plus loss of the ability to verify legitimately-archived old-epoch bundles.
- **Remediation:** Make load failure fatal to bootstrap; distinguish *absent* (→ genesis, already handled) from *corrupt* (→ refuse to proceed).

### RN-11 — Default-allow when the membership directory is unpopulated
- **Domain:** Dataplane/policy · **CWE-1188 / CWE-636** · **Confidence: High**
- **Location:** `rustynet-policy/src/lib.rs:83-86` (`is_populated`) consumed at `phase10.rs:4786-4789` (empty directory → skip the gate, `Ok(())` for every peer).
- **Description:** An empty membership directory is treated as "governance not active = allow all," indistinguishable from "membership state failed to load / was wiped." Combined with RN-03 (swallowed fail-closed) this becomes a practical bypass.
- **Remediation:** Distinguish an explicit operator opt-out (`--membership-governance=disabled`) from absent/unloadable state (fail closed). Default to deny on empty unless explicitly opted out, and refuse if a snapshot path was configured but failed to load.

### RN-12 — Linux DNS leak on exit-serving nodes: broad egress `accept` precedes the DNS drop (first-terminal-verdict)
- **Domain:** Dataplane · **CWE-696** · **Confidence: Med-High**
- **Location:** `apply_nat_forwarding` inserts `oifname <egress> accept` (`phase10.rs:1980-1993`, stage `:3981`) before `apply_dns_protection` adds `dport 53 oifname != <tunnel> drop` (`:2020-2042`, stage `:3989`).
- **Description:** nftables evaluates in insertion order with terminal verdicts; on an exit/relay node the broad egress `accept` matches DNS first, so the port-53 drop never evaluates. Client nodes (no broad accept) are unaffected.
- **Remediation:** Insert DNS drop with higher precedence than the broad egress accept (positioning/priority, or exclude port 53 from the egress accept); assert ordering in `assert_exit_serving`.

### RN-13 — `HandshakeFloodGuard` unbounded source map (and the flood guard doesn't run in production)
- **Domain:** Dataplane · **CWE-401 / CWE-770** · **Confidence: High**
- **Location:** `dataplane.rs:237-246` — `source_attempts` retains timestamps but never removes empty keys; and per RN-02 this module is dead, so there is **no handshake flood guard in the live `phase10.rs` path** (relies on boringtun's own cookie/rate behavior).
- **Remediation:** If reviving `dataplane.rs`, evict empty keys + cap tracked sources. Decide whether handshake flood protection is required in the live path; if so implement it there.

### RN-14 — Workspace `unsafe_code = "forbid"` lint is dead config (no crate opts in) **[verified]**
- **Domain:** Supply chain/build · **CWE-1188** · **Confidence: High**
- **Location:** `Cargo.toml:29-30` declares `[workspace.lints.rust] unsafe_code = "forbid"`; verified no crate manifest contains `[lints] workspace = true`.
- **Description:** Cargo only applies `[workspace.lints]` to members that opt in; none do, so the compiler never enforces it. The property holds today via per-file `#![forbid(unsafe_code)]` on 13/14 crate roots (only the FFI crate `rustynet-windows-native` lacks it, as expected) plus the `ops check-no-unsafe-rust-sources` scanner — but the manifest-level control is doing nothing, and a newly-added crate without the per-file attribute could slip through.
- **Remediation:** Add `[lints]\nworkspace = true` to each member crate; let `rustynet-windows-native` locally override with a documented allow.
- **Status: FIXED 2026-05-24** — see Remediation log RL-2.

### RN-15 — CI build/test/clippy do not use `--locked` (lockfile integrity not enforced)
- **Domain:** Supply chain · **CWE-829** · **Confidence: High**
- **Location:** `.github/workflows/cross-platform-ci.yml:23-25, 47-49, 128-130` (no `--locked`); only `release-windows.yml:60` pins.
- **Description:** Without `--locked`, Cargo can silently re-resolve `Cargo.lock` to newer semver-compatible transitive versions, so CI (and `cargo audit`/`cargo deny`) run against a tree different from the committed, reviewed lockfile.
- **Remediation:** Add `--locked` to every cargo invocation in CI; add a `git diff --exit-code Cargo.lock` guard.

### RN-16 — GitHub Actions pinned to mutable tags, not commit SHAs
- **Domain:** Supply chain · **CWE-829 / CWE-494** · **Confidence: High**
- **Location:** `.github/workflows/cross-platform-ci.yml:16,40,59,86`; `release-windows.yml:49,158,185,205` (`actions/checkout@v4`, `softprops/action-gh-release@v2`).
- **Description:** Mutable refs; a compromise/re-point of those actions executes attacker code in CI — worst case the release workflow (signing/publishing artifacts).
- **Remediation:** Pin every `uses:` to a full 40-char commit SHA; enforce with `actionlint`/`zizmor`.

## 5. Low-severity findings

| ID | Domain | Title | Location | Remediation |
|---|---|---|---|---|
| RN-17 | Priv | Connect-after-validate TOCTOU on helper socket path | `privileged_helper.rs:191-199` | Re-check peer creds on the connected fd (SO_PEERCRED) instead of trusting path metadata |
| RN-18 | Priv | Helper authorizes any uid==0 peer, not just daemon uid | `privileged_helper.rs:393-394` | Drop `|| uid == 0` unless a concrete second caller needs it; gate behind a flag |
| RN-19 | Priv | Direct (helper-less) exec path skips `validate_request` | `phase10.rs:730-746` | Call `validate_request` on the direct branch too (symmetric gate) |
| RN-20 | Priv | Backend runners use PATH-resolved bare program names | `backend-wireguard/in_memory.rs:105`, `linux_command.rs:41` | Resolve via absolute validated paths or `#[cfg(test)]`-gate |
| RN-21 | Crypto | Dead algorithm-exception code (unconditional reject) | `rustynet-crypto/lib.rs:182-193` | **Intentionally not changed** — current over-rejection is already fail-closed; "fixing" it re-enables a downgrade-exception mechanism (a product decision, not a security gain). See RL note. |
| RN-22 | Crypto | Ed25519 uses non-strict `verify()` (malleability) | `rustynet-crypto/lib.rs:803`; `control` 1574/1855/2495/3157/3225 | **FIXED (RL-3)** — `verify_strict()` at all 10 sites + malleability negative test |
| RN-23 | Crypto | macOS keychain `key_id` not validated before use | `rustynet-crypto/lib.rs:460-487` | **FIXED (RL-5)** — `is_valid_key_identifier` on both keychain paths |
| RN-24 | Crypto | `SecretKey`/derived keys wiped via `fill(0)` not `zeroize` | `rustynet-crypto/lib.rs:58-62, 946/951/973/979` | **FIXED (RL-4)** — `zeroize()` on Drop + all four derived-key wipes |
| RN-25 | Trust | Coordination replay window is in-memory only | `traversal.rs:833-852` | Persist seen-nonce set (watermark spool pattern) or document per-process scope |
| RN-26 | Trust | `ConsumedTokenLedger::purge_expired` is a no-op stub | `enrollment_token.rs:386-393` | Spool `token_id+expires_at`; prune at load (needs schema change) |
| RN-27 | Dataplane | `block_all_egress` trusts single drop-rule presence | `phase10.rs:2146-2150` | Verify chain `policy drop` + no `accept` above drop, or flush+rebuild |
| RN-28 | Dataplane | `validate_policy_safety` allow-all bypassable + only on rollout path | `rustynet-policy/lib.rs:271-282` | Evaluate effective `*→*` coverage; run on `PolicySet`/`ContextualPolicySet` ingestion |
| RN-29 | Dataplane | DoH/DoT/DoQ (443/853) DNS exfil not constrained | `phase10.rs:2025/5266/2305` (port 53 only) | Rely on narrow egress allowlist (don't broadly allow 443 on egress); document Do53-only |
| RN-30 | Supply | Toolchain mismatch: `rust-toolchain.toml` 1.88 vs CI 1.85 | `rust-toolchain.toml:2` vs CI `rustup default 1.85.0` | Single source of truth; honor `rust-toolchain.toml` in CI |
| RN-31 | Supply | `deny.toml [advisories]` no explicit `yanked`/`unmaintained` | `deny.toml:1-2` | Set `yanked = "deny"`, `unmaintained = "all"` |
| RN-32 | Supply | macOS bootstrap writes temp `NOPASSWD: ALL` + `curl|bash` Homebrew | `scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh:168-173` | `trap` to remove sudoers on EXIT; scope to brew; pin/verify Homebrew installer |
| RN-33 | Crypto | `validate_key_custody_permissions` is a no-op on Windows | `rustynet-crypto/lib.rs:1180-1185` (returns `Ok`) | Wire to windows-native SDDL inspector or fail closed until implemented |

## 6. Informational

| ID | Domain | Note | Location |
|---|---|---|---|
| RN-34 | Priv | `wg ... private-key <path>` not pinned to a key dir (defense-in-depth; path is daemon-controlled today) | `privileged_helper.rs:1466-1483` |
| RN-35 | Priv | `pfctl -f <path>` rules file not pinned to daemon temp prefix | `privileged_helper.rs:1598-1601` |
| RN-36 | Priv | `--allowed-uid`/`--allowed-gid` accept arbitrary values with no sanity floor | `main.rs:278-296` |
| RN-37 | Crypto | Passphrase `Zeroizing` cloned in encrypt path (widens residency window) | `key_material.rs:493` |
| RN-38 | Supply | `secret_log_audit` scanners are name-list + 2-root scoped (coverage-completeness; whole-tree gate mitigates) | `secret_log_audit.rs:41-76` |

(Plus `bans] multiple-versions = "warn"` allowing boringtun-driven duplicate `base64`/`nix` versions — track those transitively for advisories; low priority.)

## 7. Controls correctly implemented (coverage)

The review explicitly credits these as present and correct:

- **Privileged helper:** closed-enum program allowlist, per-program argv schema allowlisting, argv-only exec (no shell), shell-metacharacter + path-traversal rejection, binary integrity validation (absolute + canonicalize + regular-file + executable + non-group/other-writable + **root-owned**), absolute hardcoded binary candidates (no PATH on the privileged path), SO_PEERCRED authn, 0660 group socket + parent-dir mode/owner + symlink/type rejection, robust framed protocol with hard size caps and panic-free bounds-checked decoders, IO + subprocess timeouts, `kill` constrained to `-TERM <pid>` `pid>1`, no key bytes in helper output. **[verified]**
- **Crypto:** vetted primitives only (ed25519-dalek 2.2, XChaCha20-Poly1305, Argon2id @ OWASP params, subtle, OS keystores); fail-closed CSPRNG (no ThreadRng fallback); fresh CSPRNG nonce+salt per envelope; all-zero key rejection; signature length + wrong-key rejection; redacting `Debug`; static secret-leak test sweep; constant-time secret compares; strict OS-store-required custody on macOS/Windows; strict Unix permission validators (symlink-aware, exact 0700/0600); atomic key writes with fsync; Windows DPAPI SDDL hardening.
- **Trust/anti-replay:** verify-before-mutate ordering in `apply_signed_update`; quorum + per-approver + owner-signature enforcement; epoch + state-root chaining; replay cache observe-last; snapshot/log digest + chain verification + bounded reads + perm checks; schema-version fail-closed; watermark consulted before signature in epoch-tagged bundle verification; HMAC enrollment tokens with constant-time compare-before-checks, single-use ledger persisted before peer registration; gossip signature-as-sole-authority with watermark-before-commit; key rotation epoch monotonicity + atomic ledger + deterministic rollback.
- **Untrusted input:** IPC envelope bounded + per-command SO_PEERCRED authz + quorum-gated mutation; `peer_gossip`, STUN, relay hello/token, NAT-PMP/PCP/UPnP, the DNS question parser, and `dns-zone` wire are all bounded, overflow-checked, and panic-free (exemplary). **[partially verified]**
- **Dataplane (Linux):** generation killswitch chain created with `policy drop` (`inet` = v4+v6), atomic generation rotation, loopback/established carve-outs, opt-in boot-time pre-protective killswitch + verifier, IPv6 disabled at the stack, client DNS leak filter, NM/resolved drift detection, default-deny policy fallthrough + first-match, multi-gate exit selection, full-tunnel-requires-protected-DNS, route-state assertions, immediate revocation; macOS pf default-drop catch-all. **[partially verified]**
- **Secret hygiene/supply chain:** no secret leaks into logs (hashed token thumbprints), `unsafe` genuinely contained (only FFI/vendored), no committed secrets, comprehensive deprecated-crypto bans in `deny.toml`, no `build.rs` anywhere (zero build-time code-exec surface), argv-only secret-bearing shell dispatch. **[verified: no build.rs, unsafe containment]**

## 8. Prioritized remediation roadmap

**P0 — fix now (exploitable / fail-open / leak):**
1. RN-01 — cap membership decoder counts (DoS; one-file fix, mirror dns-zone).
2. RN-03 + RN-04 — make `force_fail_closed` failures fatal/retried and program the killswitch before backend start / make the boot killswitch mandatory.
3. RN-06 + RN-07 — bring the Windows killswitch + IPv6 handling to Linux parity (real traffic leak today).
4. RN-05 + RN-11 — close policy default-allow paths (non-`node:` selectors bypass revocation; empty membership = allow-all).

**P1 — high-value integrity/assurance:**
5. RN-02 — resolve the dead-vs-live dataplane split so the audited control is the one that runs.
6. RN-10 — fail closed on corrupt rotation ledger.
7. RN-08, RN-22, RN-09 — authenticate/version the key envelope; `verify_strict()` everywhere; tighten the systemd-credential group-read gate.
8. RN-15, RN-16, RN-14 — CI `--locked`, SHA-pin actions, make the `unsafe` lint real.

**P2 — defense-in-depth / hygiene:**
9. RN-12, RN-27, RN-28, RN-29 — DNS-ordering on exit nodes, killswitch-tamper detection, allow-all coverage check, encrypted-DNS guidance.
10. RN-17–RN-20, RN-21, RN-23–RN-26, RN-30–RN-38 — the remaining Low/Info items.

## 9. Verification ledger (confirmed first-hand this pass)

- RN-01: `parse_usize_field` has no cap; three `with_capacity` sites; no max-count constant; dns-zone caps by contrast. **Confirmed.**
- RN-02: `LinuxDataplane` referenced only in `dataplane.rs` tests; daemon uses `phase10` types. **Confirmed.**
- RN-03: 10 `let _ = …force_fail_closed` sites (of 39 total). **Confirmed; "every site" recalibrated.**
- RN-05: `selector_membership_allowed` returns `true` for non-`node:` selectors. **Confirmed.**
- RN-14: workspace lint declared; no crate opts in via `[lints] workspace = true`; 13/14 roots carry per-file forbid. **Confirmed.**
- Privileged-boundary controls (RN-17..20 context): program enum → hardcoded absolute binary candidates → root-owned/non-writable validation; argv-only exec; SO_PEERCRED + 0660 socket. **Confirmed.**

The remaining findings are domain-review results that should be reproduced
against the cited `file:line` before fix sign-off.

## 10. Remediation log

Fixes landed on branch `claude/test-coverage-analysis-FDUBe`. Each follows the
project mandate: an enforcement point in code plus a verification test.

### RL-1 — RN-01 membership decoder count bounds **(landed)**
- **Files:** `crates/rustynet-control/src/membership.rs`.
- **Change:** Added three ceilings — `MAX_MEMBERSHIP_NODE_COUNT = 65_536`,
  `MAX_MEMBERSHIP_APPROVER_COUNT = 4_096`, `MAX_MEMBERSHIP_SIGNATURE_COUNT =
  4_096` — and a `bounded_count(label, count, max, field_total)` helper that
  rejects any count above the ceiling **or** above the parsed field total
  (every element needs ≥1 indexed field, so a legitimate count can never
  exceed `fields.len()`; and `fields.len()` is itself bounded by the 4 KiB IPC
  envelope cap / 8 MiB snapshot read cap). Wired it at all three
  `Vec::with_capacity` sites (`node_count`, `approver_count`, `sig_count`)
  before allocation, so the guard runs before any element is read and well
  before signature/quorum verification.
- **Why this shape:** the `> field_total` bound closes the hole on every
  arrival path (IPC and on-disk artifact) regardless of the ceiling, while the
  named ceilings document intent and bound the worst-case pre-allocation. This
  mirrors the existing `rustynet-dns-zone` discipline.
- **Tests added (4):** `bounded_count_rejects_over_max_and_over_field_total`
  (unit), `decode_membership_state_rejects_oversized_node_count`,
  `decode_membership_state_rejects_oversized_approver_count`,
  `decode_signed_update_rejects_oversized_sig_count` (each drives the public
  decode entry with a `…=18446744073709551615` count and asserts a graceful
  `InvalidFormat`, not an abort).
- **Verification:** `cargo fmt -p rustynet-control -- --check` clean;
  `cargo clippy -p rustynet-control --all-targets --all-features -- -D warnings`
  clean; `cargo test -p rustynet-control --lib` → 237 passed (incl. the 4 new).
- **Follow-up (not yet done):** add structured seed corpora to the
  `membership_decode_state` / `membership_decode_signed_update` fuzz targets so
  the count fields (behind the `version` gate) become reachable by the fuzzer.

### RL-2 — RN-14 make the workspace `unsafe_code` lint real **(landed)**
- **Files:** the 13 member crate `Cargo.toml`s that already carry per-file
  `#![forbid(unsafe_code)]` (`rustynet-backend-api`, `-backend-stub`,
  `-backend-userspace`, `-backend-wireguard`, `-cli`, `-control`, `-crypto`,
  `-dns-zone`, `-local-security`, `-policy`, `-relay`, `-sysinfo`, `rustynetd`).
- **Change:** appended `[lints]\nworkspace = true` so each crate inherits the
  workspace-level `unsafe_code = "forbid"`, making the compiler enforce it (not
  just the per-file attribute + the `ops check-no-unsafe-rust-sources` scanner).
- **Deliberately excluded:** `rustynet-windows-native` (legitimate Win32 FFI;
  the source scanner already allowlists it). Opting it in would force-forbid
  its required `unsafe` and break the build — so it is left without the stanza,
  matching the finding's prescribed remediation.
- **Verification:** `cargo check --workspace --all-targets --all-features`
  compiles (no `unsafe_code` violations surfaced; the workspace lint is now
  active for all 13 opted-in crates). A newly-added crate that opts into
  workspace lints now gets compiler-enforced `forbid(unsafe_code)` for free.
- **Pre-existing note:** the workspace check surfaces an unrelated
  `unused_mut` warning in `rustynetd` lib tests (not introduced here); worth a
  separate cleanup since the CI gate runs clippy `-D warnings`.

### RL-3 — RN-22 ed25519 `verify_strict` everywhere (signature malleability) **(landed)**
- **Files:** `crates/rustynet-crypto/src/lib.rs` (attestation verify),
  `crates/rustynet-control/src/lib.rs` (7 sites), `crates/rustynet-control/src/membership.rs` (2 sites).
- **Change:** replaced every `VerifyingKey::verify(...)` with
  `verify_strict(...)` (10 sites total), which enforces canonical `S` and
  rejects small-order/torsion points (RFC 8032 strict / ZIP-215), eliminating
  the ed25519 malleability class outright. Dropped the now-unused `Verifier`
  trait import from all three files.
- **Why safe for users:** honestly-produced ed25519-dalek signatures are
  always canonical, so `verify_strict` accepts every legitimate signature —
  confirmed by the full control suite (237 tests, all signature-verification
  paths) still passing unchanged. Zero UX impact.
- **Test added:** `verify_attestation_rejects_non_canonical_malleable_signature`
  (crypto) signs a payload, mauls `S := S + ℓ` (group order, little-endian,
  with carry) to produce a non-canonical-but-equation-satisfying signature,
  and asserts `verify_strict` rejects it (`AttestationVerificationFailed`)
  while the canonical signature verifies.
- **Verification:** `cargo fmt` + `clippy -p rustynet-crypto -p rustynet-control
  --all-targets --all-features -- -D warnings` clean; crypto 24 tests pass
  (incl. the new one), control 237 pass; `cargo check --workspace` compiles.

### RL-4 — RN-24 zeroize derived key material **(landed)**
- **Files:** `crates/rustynet-crypto/src/lib.rs`.
- **Change:** `SecretKey::drop` now calls `self.0.zeroize()` instead of
  `fill(0)`, and the four Argon2-derived AEAD key wipes in
  `encrypt_private_key_envelope` / `decrypt_private_key_envelope` use
  `key.zeroize()`. `zeroize()` carries a compiler/optimizer barrier so the
  clearing write cannot be elided as a dead store (which `fill(0)` permits).
  Un-gated the `zeroize::Zeroize` import (now used unconditionally via Drop).
- **Verification:** clippy clean; existing envelope round-trip + wrong-passphrase
  tests still pass.

### RL-5 — RN-23 validate macOS keychain key_id **(landed)**
- **Files:** `crates/rustynet-crypto/src/lib.rs`.
- **Change:** `store_in_macos_keychain` / `load_from_macos_keychain` now call
  `is_valid_key_identifier(key_id)` before interpolating it into the keychain
  service name, mirroring the file-fallback and Windows custody paths
  (returns `InvalidLength` on a malformed id). Defense-in-depth — the keychain
  CLI invocation is already argv-only, so this guards against keychain-namespace
  confusion, not injection. macOS-gated code; compiles on the Linux CI host but
  exercised on macOS.

### RL note — RN-21 deliberately left as-is
`AlgorithmPolicy::with_exceptions` currently rejects *all* non-empty exception
lists (the dead-guard). That over-rejection is **fail-closed** and is the more
secure state: repairing it would re-enable the time-boxed
denylisted-algorithm compatibility-exception mechanism, which is a deliberate
product/governance decision rather than a security improvement. Per the
"choose the most secure option" directive it is intentionally not changed; if
the exception mechanism is wanted, it should land as a scoped feature with its
own review (and the mis-pinned test corrected at that time).

## 11. Remediation design notes for the remaining P0s (pre-implementation)

These P0s are **behavioral/semantic** changes that carry real regression risk
(breaking legitimate traffic, or refusing to boot) or encode a policy
decision. They are scoped here so the implementer (and owner) can choose the
exact behavior before code lands — recommended to confirm direction first
rather than unilaterally change fail-closed/leak semantics.

### RN-03 / RN-04 — fail-open on `force_fail_closed` + pre-killswitch bootstrap window
- **Design choice to confirm:** on `force_fail_closed` error, **terminate** the
  process (let systemd + a *mandatory* boot killswitch backstop) vs **retry**
  `block_all_egress` with backoff while refusing to serve. Recommendation:
  terminate on the bootstrap (`Init`, no prior table) path where there is no
  `policy drop` backstop; retry-with-refuse on the steady-state path where a
  prior generation table already enforces `policy drop`.
- **Concrete steps:** (1) change the ~10 `let _ = …force_fail_closed(…)` sites
  to match on the Result and escalate; (2) make the `linux_killswitch_boot.rs`
  `ExecStartPre` installer mandatory in the shipped unit and gate
  `backend.start()` on the boot killswitch table being present; (3) reorder
  `apply_dataplane_generation` so the `policy drop` killswitch is programmed
  **before** `backend.start()` and route apply. Regression risk: a too-early
  killswitch could black-hole bootstrap traffic (control-plane fetch, STUN) —
  ensure the loopback/established/WG-port/control carve-outs are added in the
  same atomic step as the `policy drop`.
- **Tests:** simulate `block_all_egress` failure on first boot (inject an nft
  error) and assert the daemon refuses to serve / exits rather than running
  open; assert no interface-up-without-killswitch window in the apply order.

### RN-05 / RN-11 — policy default-allow (non-`node:` selectors + empty membership)
- **Policy decision to confirm:** how should revocation apply to
  `group:`/`tag:`/`user:` selectors? Recommendation: the policy compiler
  resolves each non-`node:` source selector to its constituent member node set
  at evaluation (or compile) time and denies if **any** required member is
  revoked/unknown; selectors that cannot be resolved to membership-checked
  nodes are rejected for trust-sensitive rules. For RN-11, default an empty
  membership directory to **deny** unless an explicit
  `--membership-governance=disabled` opt-out is set, and always fail closed if
  a snapshot path was configured but failed to load.
- **Regression risk:** flipping empty-directory to deny will break
  pre-governance / first-bring-up deployments that currently rely on the
  permissive default — hence the explicit opt-out flag. Confirm the deployment
  story before flipping.
- **Tests:** revoked identity expressed via each selector type is denied;
  empty directory denies unless opt-out; configured-but-unloadable snapshot
  fails closed.

### RN-06 / RN-07 — Windows killswitch + IPv6 parity with Linux
- **Design:** scope the Windows `interfacetype=lan` egress allow to exactly the
  bootstrap set (WG UDP to peer/relay endpoints + STUN + management), mirroring
  Linux's narrow `oifname <egress> udp dport <wgport> accept`; everything else
  hits the global `blockoutbound`. Add an explicit IPv6 outbound block
  (advfirewall block for non-tunnel `::/0`, or unbind IPv6 on the egress
  adapter) and flush autoconfigured global IPv6 addresses; assert both in
  `assert_killswitch`.
- **Regression risk:** narrowing the Windows allow can break management/roaming
  if the bootstrap set is under-specified — enumerate every legitimate
  bootstrap flow first. Needs a Windows lab run to validate (no Linux-CI
  coverage for the firewall rules).

### RN-10 — corrupt rotation ledger must fail closed (P1, contained)
- **Design:** in `load_rotation_ledger`, distinguish *absent* (→ `genesis()`,
  already correct) from *corrupt/unparseable* (→ propagate the error and refuse
  to enter key-bearing operation), matching the function's own doc contract.
- **Regression risk:** a genuinely-corrupt-but-recoverable ledger would now
  block boot — that is the intended fail-closed behavior, but pair it with a
  clear operator runbook entry for recovery.
- **Tests:** corrupt-digest / truncated / monotonicity-violation ledgers cause
  bootstrap refusal; absent ledger still yields genesis.
