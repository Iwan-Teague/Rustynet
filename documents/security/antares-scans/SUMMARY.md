# Antares-1B scan campaign — summary readout (2026-07-23)

Authoritative, human-verified readout of the Antares-1B vulnerability-localization
campaign. Read this first; the 88 `antares_*.md` files are raw per-run traces (see
["how to read the corpus"](#how-to-read-the-corpus)).

## Bottom line

**0 confirmed vulnerabilities** across 88 runs (whole-repo + 13 crates × core CWE
matrix). Antares-1B *localizes* a CWE class to candidate files; it does not confirm
exploitability or propose fixes. Every "vulnerable_files" verdict is an **unverified
localization**, not a finding. The leads a human verified either (a) pointed at
already-hardened code, or (b) pointed at code that is not externally reachable.

This is a **negative result with evidence**, which is itself useful: the obvious
weakness classes were checked *at their real locations* and the code held up.

## What actually came out of it (the value)

### 1. Positive assurances (verified by hand at the flagged sites)
At every location the model flagged **and a human inspected**, the code used safe
patterns. Not a whole-codebase proof — but concrete evidence at the exact spots a
weakness would live:

- **OS command execution is shell-free.** Every exec site checked
  (`rustynetd/phase10.rs`, `rustynet-control/credential_unwrap.rs:526`,
  `rustynet-backend-wireguard/{linux,macos}_command.rs`) uses
  `Command::new(program).args([...])` — no `sh -c`, no shell string interpolation.
  Dynamic values (endpoints, interface names) are passed as typed args, not spliced
  into a shell line. → the CWE-78 leads are non-injectable.
- **Crypto keeps an explicit weak-algorithm denylist.**
  `rustynet-crypto/src/lib.rs` `is_denylisted()` rejects `Md5/Sha1/Rc4/Des/TripleDes/
  BlowfishCbc/WeakDh`; real primitives are AES-256-GCM / XChaCha20-Poly1305, RNG is
  `OsRng` (kernel CSPRNG). → the CWE-327/330 leads are the *guard*, not a defect.
- **Credentials are never hard-coded.** `rustynetd/key_material.rs` and
  `credential_unwrap.rs` load passphrases from env vars / macOS Keychain, keep
  plaintext off disk, and `zeroize` on drop. → the CWE-798 leads are correct handling.
- **Secret-log auditing exists as a dedicated control** (`rustynetd/secret_log_audit.rs`).

### 2. Marginal hardening candidates (defense-in-depth, low priority)
Genuine but minor; each needs owner judgment, none is a live bug:
- **Bound deserialized collections.** Manifest/config parsers (e.g.
  `rustynet-cli/src/live_lab_stage_manifest.rs`, serde `Vec<...>` with no cap) accept
  unbounded lengths. Inputs are operator-local today, so not exploitable — but an
  explicit size limit is cheap hardening if any such parser ever ingests remote data.
- **Allowlist the helper binary path** in `credential_unwrap.rs::run_helper_and_capture`
  (already safe; an absolute-path/allowlist assert would be belt-and-suspenders).

### 3. Operating guide for the tool itself
See [GUIDE.md](GUIDE.md) — empirically-derived envelope for when Antares-1B is worth
using. Key results from this campaign:

| Scope size | Runs | Abort | Mean inspected-ratio | Read |
|---|---|---|---|---|
| single-file crate | 18 | 3 | 0.58 | picks the lone `lib.rs` for every CWE — noise |
| small (2-10) | 34 | 9 | 0.65 | frequent aborts |
| **medium (11-40)** | 18 | 1 | **0.71** | **sweet spot** — differentiates file per CWE |
| whole-repo (498) | 18 | 1 | 0.62 | false-flags *defensive* code; do not use |

- **Use it scoped to medium, logic-heavy crates.** There it reads its way to a
  specific, plausible file per CWE and **declines inapplicable CWEs**
  (`crypto/CWE-400 → no_vulnerability_found`) instead of inventing one.
- **Do not run whole-repo** — it flags the very modules that *implement* the
  protection (crypto denylist, secret-log auditor) as if they were the flaw.
- **On-domain CWE only.** Rustynet is WireGuard/static-key; TLS CWEs (295) are N/A.
  CWE names that collide with domain vocab ("traversal" = NAT traversal) mislead it.

## How to read the corpus
- `runs.jsonl` — machine log, one line per run (verdict, files, inspected/fabricated
  counts, distraction score).
- `INDEX.md` — table of all 88 runs.
- `antares_<scope>_<CWE>_2026-07-23.md` — raw per-run trace. **Each "vulnerable_files"
  is an unverified lead.** The harness existence-checks submissions, so paths are real,
  but *real path ≠ real bug*. Treat as "a human could look here," nothing more.

## Coverage / not covered
- Covered: whole-repo + advisor, backend-{api,stub,userspace,wireguard}, cli, control,
  crypto, dns-zone, lab-monitor, llm-gateway, local-security, mcp.
- **Not run per-crate:** `rustynetd` (the main daemon), nas, netns-probe, operator,
  policy, relay, sysinfo, windows-native, xtask. The daemon's key files *were* sampled
  via the whole-repo runs and verified as false-positives/hardened, so the pattern is
  well-established; a full per-crate daemon pass was judged not worth the compute.

## Recommendation
Antares-1B is **not a bug finder** for this codebase — it produced no actionable
finding in 88 runs. Its usable value is narrow: a *scoped, medium-crate attention map*
that points a human reviewer at the right security-sensitive file, plus the
documented assurances above. For actual vulnerability discovery, use a code-grounded
review (which both finds the area **and** judges exploitability). Keep this tool for
"where should I look in crate X?", not "is crate X vulnerable?".
