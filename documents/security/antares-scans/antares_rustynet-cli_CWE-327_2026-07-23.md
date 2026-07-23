# Antares scan — `rustynet-cli` — CWE-327

**Date:** 2026-07-23  
**Scope:** `rustynet-cli` (273 first-party `.rs` files)  
**CWE:** CWE-327 — Use of a broken or risky cryptographic algorithm, or insecure use of cryptographic primitives (weak cipher/hash, misused nonce/IV, bad KDF).  
**Verdict:** `vulnerable_files`  
**Budget:** 18/30 terminal cmds, 21 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/vm_lab/network_prepare.rs` | inferred (grep-only) |

## Model reasoning

The file implements a custom SHA-256 hasher that truncates the full 256-bit digest to the first 16 hex characters (digest[..16].to_owned()). This weakens the cryptographic integrity check by returning only the first 128 bits of the hash, reducing collision resistance and making the system vulnerable to attacks that exploit the truncated hash space.

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 80
$ grep -RIn "md5\|sha1\|des\|rc4\|sha256_digest\|sha256::\|xxhash\|blake2\|crypto\|Crypto::" /workspace/repo/src | head -n 200
$ grep -RIn "md5" /workspace/repo/src
$ grep -RIn "sha1" /workspace/repo/src
$ grep -RIn "md5" /workspace/repo
$ grep -RIn "Crypto" /workspace/repo/src
$ cat src/vm_lab/orchestrator/adapter/windows_install.rs
$ grep -RIn "sha256::" /workspace/repo
$ grep -RIn "sha256_" /workspace/repo
$ grep -RIn "sha1_" /workspace/repo
$ grep -RIn "sha1::\|sha1_hex\|sha1_hex(" /workspace/repo
$ grep -RIn "sha1::" /workspace/repo
$ cat src/release_manifest.rs
$ grep -RIn "sha256_hex(" /workspace/repo/src
$ cat src/vm_lab/mod.rs | head -n 100
$ grep -RIn "sha256_hex\(" /workspace/repo
$ grep -RIn "sha256_hex(" /workspace/repo
$ cat src/vm_lab/orchestrator/role_validation/anchor.rs
$ sed -n '540,570p' src/vm_lab/orchestrator/role_validation/anchor.rs
```
