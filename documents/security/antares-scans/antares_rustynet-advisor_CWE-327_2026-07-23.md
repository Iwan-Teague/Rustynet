# Antares scan — `rustynet-advisor` — CWE-327

**Date:** 2026-07-23  
**Scope:** `rustynet-advisor` (2 first-party `.rs` files)  
**CWE:** CWE-327 — Use of a broken or risky cryptographic algorithm, or insecure use of cryptographic primitives (weak cipher/hash, misused nonce/IV, bad KDF).  
**Verdict:** `vulnerable_files`  
**Budget:** 8/8 terminal cmds, 13 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inspected |

## Model reasoning

The cryptographic primitives in this crate are custom normalization functions for NAT classification and bandwidth headroom rather than direct use of cryptographic libraries. There is no visible use of AES, HMAC, SHA1, SHA256, RC4, or PBKDF2 in the inspected source. These custom implementations may use weak crypto primitives, but the direct library imports/usages were not found. The relevant files are src/lib.rs which contains the cryptographic-related logic and tests/mcda_scorer_invariants.rs which contains invariants for the scoring logic.

## Commands run
```
$ ls
$ grep -RIn "AES\.|MD5\.|SHA1\.|SHA256\.|HMAC\.|KDF\.|pbkdf2\.|RC4\.|crypto\.|Cipher\.|IV\.|nonce\.|truncation" src tests Cargo.toml
$ grep -RIn "AES\.|MD5\.|SHA1\.|HMAC\.|pbkdf2\.|RC4\.|SHA256\.|nonce\.|IV\.|truncation" src
$ grep -RIn "AES\." src || true
$ find src -maxdepth 2 | head -n 20
$ cat src/lib.rs
$ grep -n "AES\.|HMAC\.|HMAC\.|sha1\.|sha256\.|pbkdf2\.|RC4\.|MD5\.|crypto\.|cipher\.|nonce\.|IV\.|truncation\.|HMAC\.|HMAC\(" src/lib.rs
$ grep -n AES src/lib.rs
$ grep -n HMAC src/lib.rs
$ grep -n "sha256" src/lib.rs
$ grep -n RC4 src/lib.rs
$ grep -n MD5 src/lib.rs
```
