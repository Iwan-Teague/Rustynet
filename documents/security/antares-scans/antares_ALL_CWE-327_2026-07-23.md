# Antares scan — `ALL` — CWE-327

**Date:** 2026-07-23  
**Scope:** `ALL` (498 first-party `.rs` files)  
**CWE:** CWE-327 — Use of a broken or risky cryptographic algorithm, or insecure use of cryptographic primitives (weak cipher/hash, misused nonce/IV, bad KDF).  
**Verdict:** `vulnerable_files`  
**Budget:** 10/30 terminal cmds, 13 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `crates/rustynetd/src/secret_log_audit.rs` | inferred (grep-only) |
| `crates/rustynet-crypto/src/lib.rs` | inspected |

## Model reasoning

Found explicit references to MD5 (Md5) in the codebase. The secret_log_audit.rs contains a use of md_5::Md5 and related checks that mark MD5 usage as forbidden, indicating MD5 is treated as a weak/denied cryptographic algorithm. The crates/rustynet-crypto/src/lib.rs also references Md5 as a supported algorithm. MD5 is a broken cryptographic hash and should be removed from cryptographic uses per security policy, so these files contain the vulnerable cryptographic primitive usage.

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 80
$ grep -RIn "md5\|sha1\|des\|rc4\|sha0\|md4\|md5_digest\|sha1_digest\|sha256_new\|sha256_update\|sha256_final\|blake2\|blake3\|sha256::Digest\|Crypto::" /workspace/repo --include="*.rs" | head -n 200
$ grep -RIn "md5" /workspace/repo --include="*.rs" | head -n 200
$ grep -RIn "sha1" /workspace/repo --include="*.rs" | head -n 200
$ grep -RIn "sha256" /workspace/repo --include="*.rs" | head -n 200
$ grep -RIn "sha256_new\|sha256_update\|sha256_final\|sha256_digest" /workspace/repo/crates | head -n 200
$ grep -RIn "sha256_new" /workspace/repo/crates | head -n 200
$ grep -RIn "Sha1" /workspace/repo --include="*.rs" | head -n 200
$ ls crates/rustynet-crypto/src
$ cat crates/rustynet-crypto/src/lib.rs
$ grep -RIn "Md5" /workspace/repo/crates | head -n 200
```
