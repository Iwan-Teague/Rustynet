# Antares scan — `rustynet-backend-userspace` — CWE-327

**Date:** 2026-07-23  
**Scope:** `rustynet-backend-userspace` (2 first-party `.rs` files)  
**CWE:** CWE-327 — Use of a broken or risky cryptographic algorithm, or insecure use of cryptographic primitives (weak cipher/hash, misused nonce/IV, bad KDF).  
**Verdict:** `no_submission`  
**Budget:** 8/8 terminal cmds, 17 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

_None (aborted or no matching vulnerability declared)._

## Model reasoning

budget exhausted and model failed to submit within allowed post-budget turns

## Commands run
```
$ ls
$ grep -RIn "AES\.|MD5\.|SHA1\.|SHA256\.|HMAC\.|KDF\.|pbkdf2\.|RC4\.|crypto\.|Cipher\.|IV\.|nonce\.|truncation" src tests Cargo.toml
$ grep -RIn "AES\.|MD5\.|SHA1\.|HMAC\.|pbkdf2\.|RC4\.|SHA256\.|nonce\.|IV\.|truncation" src
$ grep -RIn "AES\." src || true
$ find src -maxdepth 2 | head -n 20
$ cat src/lib.rs
$ find . -maxdepth 2 | grep -E "wireguard|boringtun|backend|crypto|noise|cipher"
$ find . -maxdepth 2 | grep -E "wireguard|boringtun|noise|cipher|crypto"
$ find . -maxdepth 2 | grep wireguard
$ find src -maxdepth 1
$ find . -name '*.rs' | xargs grep -n "noise"
$ find . -name '*.rs' | grep -E "noise"
$ find . -name '*.rs' | grep boringtun
$ find . -path '*rustynet-backend*' | head -n 20
$ find . -name '*.rs' | grep -E "boringtun|noise|crypto|cipher"
```
