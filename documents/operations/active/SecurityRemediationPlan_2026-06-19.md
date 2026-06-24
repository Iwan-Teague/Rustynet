# Rustynet Security Remediation Plan — 2026-06-19

Derived from the review-only audit ledger
[`SecurityAuditLedger_2026-06-18.md`](./SecurityAuditLedger_2026-06-18.md)
(73 findings, RSA-0001..RSA-0074, RSA-0062 retired). This document **sequences** the
findings into remediation waves; it does **not** change code. Each item carries the
proposed fix and the verification test that must accompany it (full observation/risk/
source live in the ledger finding entry). As fixes land, flip the finding's ledger row
`open → proposed/accepted/applied` with a dated status line (append-only).

**Release gate (SecurityMinimumBar §2):** no unmet Critical; **2 High** unmet on
reachable paths — both must be fixed or carry documented risk-acceptance before the next
security milestone.

Effort key: **S** ≤½ day · **M** ~1–2 days · **L** ≥3 days / needs design decision.

---

## Wave P0 — release-blocker class (the 2 Highs). Fix first.

| ID | File | Fix (proposed) | Verification | Eff |
|---|---|---|---|---|
| **RSA-0009** | `rustynet-control/src/membership.rs` | Make the reducer deterministic for state-root purposes — derive `updated_at_unix` from the signed record (e.g. `created_at_unix`), **or** exclude it from `canonical_payload`/`state_root`, **or** carry the new timestamp in the operation. **Owner design decision (3 options).** | Success-path `apply_signed_update` **and** `replay` tests for `RevokeNode`/`RestoreNode`/`RotateNodeKey`/`SetNodeCapabilities` asserting the signed `new_state_root` matches | **L** |
| **RSA-0063** | `scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh` | Register `trap 'rm -f "${sudoers_tmp}"' EXIT` **before** the `curl\|bash`; prefer scoping the grant to the brew command, not `NOPASSWD: ALL` | Bootstrap-failure simulation leaves no `/etc/sudoers.d/rustynet-*`; lint asserting the trap precedes the sudoers write | **S** |

> RSA-0009 is the higher-impact (revocation + key-rotation are non-functional); RSA-0063
> is the quicker win. Do RSA-0063 immediately; schedule the RSA-0009 design decision.

---

## Wave P1 — Mediums, grouped by systemic theme (fix the pattern, not just the instance)

**Theme A — non-unix key-permission no-op / at-rest ACL (Windows).**
- RSA-0002 `rustynet-crypto::validate_key_custody_permissions` non-unix branch → implement the Windows ACL check via `inspect_file_sddl`, fail closed. **M**
- RSA-0025 `rustynetd/key_material.rs` → apply a SYSTEM/Admin-only DACL at `.enc` write time (closes the read+write gap with RSA-0002). **M**
  *(One fix design covers both loci + the `windows-trust-cli` / `llm-gateway` callers.)*

**Theme B — one-time-credential / resource-bound gaps.**
- RSA-0023 enrollment ledger → wrap the read-modify-write in an OS advisory lock (mirror `resilience.rs::acquire_lock`); add the §6 concurrent-consume race test. **M** — ✅ APPLIED 2026-06-24 (acquire_ledger_lock flock spanning load→consume→write; 8-thread race test = exactly one redemption).
- RSA-0037 relay `HelloLimiter.counts` → prune on the cleanup cadence + hard-cap `len()`; flood test for bounded map. **S** — ✅ APPLIED 2026-06-24 (cap=16384 + prune_elapsed on cleanup; flood + prune tests).
- RSA-0047 MCP `run_server` → bounded `read_line` (reject oversized lines before buffering). **S** — ✅ APPLIED 2026-06-24 (read_bounded_line, 4 MiB cap, stream-drains over-cap line + resyncs; 4 tests).

**Theme C — unescaped host/config values into a shell/PowerShell/env-file.**
- RSA-0046 `rustynet-sysinfo` → replace `powershell -Command` interpolation with `-File`+`param()` or a native API (4 sites). **M**
- RSA-0059 `windows_membership.rs` → `ps_quote` (or drop) `node_id` in the throw-literal. **S** — ✅ APPLIED 2026-06-24 (pure `build_add_peer_script`; node_id ps_quoted in throw too; breakout + control-char tests).
- RSA-0068 `scripts/bootstrap/linux/rn_bootstrap.sh` → strict `^[A-Z_]+=` env parser instead of `source` (chain sink for RSA-0057). **S**
  *(RSA-0051/0057 (Low) are the same chain — fix together: validate/escape `build_bootstrap_env` output.)*

**Theme D — fail-open / assurance verification.**
- RSA-0026 `secret_log_audit` gate → enumerate the *real* secret types (derive from `Zeroizing`/zeroize), multi-line scan, extend to control/relay/crypto; meta-test. **M**
- RSA-0031 exit-NAT teardown verify (mac/win) → fail closed on `pfctl`/forwarding-capture exec error (never report `restored=true`). **S** — ✅ APPLIED 2026-06-24 (code-complete; live re-proof pending): capture-failure now reads anchor/NAT as present + forwarding NOT restored; exec-failure-injection unit tests on both OS verifiers.

**Theme E — revocation-blind issuance / consistency (mitigated downstream, fix for one-hardened-path).**
- RSA-0007 `phase10.rs` set_exit_node/ensure_lan_route_allowed → route through `evaluate_with_membership`; revoked-node negative tests. **S** — ✅ APPLIED 2026-06-24 (both gates now membership-aware; revoked exit-node + revoked-requester negative tests).
- RSA-0008 `rustynet-control` `ControlPlaneCore` → give it a signed `MembershipDirectory`, use `evaluate_with_membership` for issuance. **M**

**Theme F — destructive lab automation (the overnight driver).**
- RSA-0052 overnight live path → real branch isolation (`git checkout -B overnight/<date>`, refuse `main`) + dry-run default + never push. **M**
- RSA-0053 overnight clean → pathspec-confine `git clean` or run in a dedicated worktree. **S**

**Theme G — bootstrap supply-chain (curl|bash / unpinned downloads).**
- RSA-0064 macOS Homebrew installer → pin commit-SHA URL + verify SHA-256. **S**
- RSA-0065 Windows `rustup-init`/`vs_BuildTools` → `Get-AuthenticodeSignature` (valid+publisher) or pin SHA-256 before execute. **S**

---

## Wave P2 — Low / Info (defense-in-depth, hygiene, fuzz/test coverage)

Batch by category so each PR is coherent:
- **Fuzz coverage (RN-N6 class):** RSA-0038 (WG engine), RSA-0040 (relay hello/token + state machine), RSA-0042 (dns-zone bundle parser) → add cargo-fuzz targets, run ≥1h/commit in CI. **M total**
- **`// SAFETY:` on production FFI:** RSA-0032 (`macos_utun_helper_unsafe`), RSA-0074 (`rustynet-tun`) → add SAFETY comments; Miri where feasible. **S**
- **Crypto/consistency:** RSA-0043 (dns-zone → `verify_strict`), RSA-0001 (envelope unambiguous v0/v1 framing + legacy-decode test, RN-08), RSA-0003 (delete/fix dead `AlgorithmPolicy::with_exceptions`), RSA-0010 (relay-token `try_sign_at`). **M**
- **Permissions / secrets hygiene:** RSA-0017 (sqlite DB perms), RSA-0039 (Win backend redacting `Debug`), RSA-0016 (break-glass `ct_eq`+redacting Debug, unwired), RSA-0060 (real_wireguard harness key perms), RSA-0013/0020 (perm checks). **M**
- **Input/robustness:** RSA-0027 (structural CIDR parse, RN-N7 — ✅ APPLIED 2026-06-24), RSA-0050 (sysinfo parser bounds), RSA-0033 (helper kill scoped to owned PIDs), RSA-0055 (CSV formula injection), RSA-0054 (matrix report path confinement), RSA-0066 (e2e host-key pinning), RSA-0041 (relay reject reflection), RSA-0056/0061 (orchestrator/e2e argv hygiene), RSA-0070/0071/0072 (script robustness/gate-drift/HB-3), RSA-0058 (printf quoting). **M total**
- **Gossip hardening:** RSA-0028 (per-peer inbound rate limit, RN-N4), RSA-0029 (traversal post-restart replay), RSA-0030 (RN-09 negative test). **S**
- **Vendored hygiene:** RSA-0073 (strip/disposition boringtun dead `device/ffi/jni`). **S**

---

## Owner-decision queue (the 6 Question items — need a call before they become work)

| ID | Question for the owner |
|---|---|
| RSA-0014 | Should `emit_role_audit` fail **closed** (block the transition) when the durable audit append fails, for SignedMembership/Irreversible role changes? |
| RSA-0018 | Wire `admin.rs` `validate_privileged_command` into a real enforcement point, or document it as design-reference scaffolding (the audit catalog over-claims it)? |
| RSA-0024 | Are the §6.E `service_exposure` controller + llm-gateway `session`-token enforcement meant to ship wired for D13 nas/llm, or are they scaffold? |
| RSA-0034 | Should gossip ingest re-check current `Active`/`Revoked` status before applying a registered peer's state? (confirm registry pruning on revocation) |
| RSA-0035 | Restrict uPnP SSDP `LOCATION`/`controlURL` to the responder IP / on-link space (SSRF), or accept the LAN-trust model? |
| RSA-0045 | Implement the B.4.1 RFC1918 resolver-output answer-filter in the daemon DNS responder (DNS-rebinding-style protection)? |

---

## Applied fixes (net-new, post-audit — not from RSA-0001..0074)

- **2026-06-24 — macOS `pfctl -f` privileged-boundary (regeneration).** APPLIED
  (code-complete; live-lab pending). The macOS privileged helper previously
  accepted `pfctl -a <anchor> -f <path>` gated only by anchor/path token shape,
  so a daemon compromised to the helper's uid could author an arbitrary rules
  file (`pass out quick all`) and have the root helper load it into the
  killswitch anchor, defeating default-deny egress. Ownership/`O_NOFOLLOW`
  checks cannot fix it (the daemon legitimately authors the file). Fix:
  **regeneration** — the daemon now sends a validated STRUCTURED spec
  (`crates/rustynetd/src/macos_pf_load_spec.rs`, `MacosPfLoadSpec`) over the new
  `macos-pf-load` privileged builtin; the root helper re-renders the `pf` rule
  text from the reviewed builders, derives the anchor name itself, and owns the
  root-only temp file + `pfctl -n`/`-f`. The `-f`/`-n -f` arms are removed from
  `validate_pfctl_args`. Verification: spec roundtrip + reject (injected iface /
  bad cidr / oversized list / cross-kind) + no-false-reject cartesian sweep
  (`macos_pf_load_spec` tests) and the boundary regression
  (`validate_request_rejects_pfctl_boundary_rule_file_load`,
  `validate_pfctl_args_permits_nat_anchor_show_and_flush_but_not_load`). Mirrors
  the `DnsFailclosedFile` builtin precedent. Live-lab macOS killswitch/blind/nat
  validation on `.210` is the only remaining step. Open risk: helper+daemon must
  upgrade together (new program rejected by an old helper → fail-closed). The
  Linux `validate_nft_args` arg-level-only class is the same shape — tracked
  separately, out of scope here.

---

## Process notes
- Each fix PR: small, one logical change; add the verification test in the same PR; run
  the relevant `scripts/ci/*_gates.sh` + `cargo run -p rustynet-xtask -- gates`.
- After merge, update the finding's ledger row status (dated, append-only) and tick it here.
- Re-run `cargo audit` + `cargo deny` and the live-lab evidence path for any change that
  touches a dataplane/trust/bootstrap surface.
- All items trace to a sourced ledger finding; no new scope is introduced here.
