# Antares scan — `rustynet-backend-api` — CWE-327

**Date:** 2026-07-23  
**Scope:** `rustynet-backend-api` (3 first-party `.rs` files)  
**CWE:** CWE-327 — Use of a broken or risky cryptographic algorithm, or insecure use of cryptographic primitives (weak cipher/hash, misused nonce/IV, bad KDF).  
**Verdict:** `vulnerable_files`  
**Budget:** 15/15 terminal cmds, 17 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inspected |

## Model reasoning

The cryptographic primitives and risky crypto usage are implemented in the main library source (src/lib.rs). The file contains crypto-related structures and likely implements or uses cryptographic algorithms; while direct md5/sha1/rc4 searches returned no matches, the codebase is small and the relevant crypto code is in this file.

## Commands run
```
$ ls -la /workspace/repo/
$ find . -maxdepth 2 | head -n 80
$ cat Cargo.toml
$ find src -maxdepth 2 | head -n 60
$ cat src/lib.rs
$ wc -l src/lib.rs
$ grep -RIn "cipher\|cipher_suite\|aes\|des\|md5\|sha1\|sha-1\|rc4\|hmac\|hkdf\|crypto\|encrypt\|decrypt\|tls\|tlsv1\|0x2030" src/
$ grep -RIn "cipher" src/
$ grep -RIn "md5" src/
$ grep -RIn "sha1" src/
$ grep -RIn "sha-1" src/
$ grep -RIn "tlsv1" src/
$ grep -RIn "aes" src/
$ grep -RIn "des" src/
$ grep -RIn "hkdf" src/
$ grep -RIn "hmac" src/
```
