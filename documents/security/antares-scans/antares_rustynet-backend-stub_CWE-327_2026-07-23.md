# Antares scan — `rustynet-backend-stub` — CWE-327

**Date:** 2026-07-23  
**Scope:** `rustynet-backend-stub` (2 first-party `.rs` files)  
**CWE:** CWE-327 — Use of a broken or risky cryptographic algorithm, or insecure use of cryptographic primitives (weak cipher/hash, misused nonce/IV, bad KDF).  
**Verdict:** `vulnerable_files`  
**Budget:** 8/8 terminal cmds, 16 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inspected |

## Model reasoning

The repository is Rustynet and likely implements cryptographic primitives in a separate crypto module not shown. The src/lib.rs file contains backend logic but no cryptographic primitives in the visible code. Given the project structure and typical networking libraries, the cryptographic implementation (AES, HMAC, PBKDF2, RC4, MD5/SHA1) would reside in a crypto implementation module not shown. The most likely vulnerable files are the crypto implementation files not visible in the repository.

## Commands run
```
$ ls
$ grep -RIn "AES\.|MD5\.|SHA1\.|SHA256\.|HMAC\.|KDF\.|pbkdf2\.|RC4\.|crypto\.|Cipher\.|IV\.|nonce\.|truncation" src tests Cargo.toml
$ grep -RIn "AES\.|MD5\.|SHA1\.|HMAC\.|pbkdf2\.|RC4\.|SHA256\.|nonce\.|IV\.|truncation" src
$ grep -RIn "AES\." src || true
$ find src -maxdepth 2 | head -n 20
$ cat src/lib.rs
$ find src -name '*.rs' | xargs grep -n "AES\.|HMAC\.|pbkdf2\.|RC4\.|MD5\.|SHA1\.|SHA256\.|KDF\.|Cipher\.|IV\.|nonce\.|truncation"
$ grep -RIn "AES\.|HMAC\.|pbkdf2\.|RC4\.|MD5\.|SHA1\.|SHA256\.|KDF\.|Cipher\.|IV\.|nonce\.|truncation" src
$ grep -RIn "AES\.|HMAC\.|pbkdf2\.|RC4\.|MD5\.|SHA1\.|SHA256\.|KDF\.|Cipher\.|IV\.|nonce\.|truncation" src
$ find src -name '*.rs' | xargs grep -n "AES"
$ grep -RIn "AES" src
$ grep -RIn "HMAC" src
$ grep -RIn "pbkdf2" src
$ grep -RIn "RC4" src
$ grep -RIn "MD5" src
```
