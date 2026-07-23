# Antares scan — `rustynet-local-security` — CWE-327

**Date:** 2026-07-23  
**Scope:** `rustynet-local-security` (1 first-party `.rs` files)  
**CWE:** CWE-327 — Use of a broken or risky cryptographic algorithm, or insecure use of cryptographic primitives (weak cipher/hash, misused nonce/IV, bad KDF).  
**Verdict:** `no_vulnerability_found`  
**Budget:** 8/8 terminal cmds, 14 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

_None (aborted or no matching vulnerability declared)._

## Model reasoning

The repository contains a socket security validation library (src/lib.rs) that performs Unix-specific permission and ownership checks using standard filesystem metadata operations (fs::metadata, file type checks, uid/gid retrieval). It does not implement or use any custom cryptographic algorithms or primitives. The code validates socket permissions and ownership but lacks cryptographic operations (no sha256/hash implementation, no crypto primitives), so there is no CWE-327 vulnerability in the codebase.

## Commands run
```
$ ls
$ grep -RIn "cipher\.|hash\.|sign\.|verify\.|rsa\.|ecdsa\.|aes\.|des\.|blake2\.|sha\.|md5\.|sha1\.|curve\.|kdf\.|nonce\.|iv\.|CTR\.|CBC\.|HMAC\.|ECDH\.|DiffieHellman" src || true
$ grep -RIn "cipher\.|hash\.|sign\.|verify\.|rsa\.|ecdsa\.|aes\.|des\.|blake2\.|sha\.|md5\.|sha1\.|curve\.|kdf\.|nonce\.|iv\.|CTR\.|CBC\.|HMAC\.|ECDH\.|DiffieHellman" src
$ grep -RIn "cipher\.|hash\.|sign\.|verify\.|rsa\.|ecdsa\.|aes\.|des\.|blake2\.|sha\.|md5\.|sha1\.|curve\.|kdf\.|nonce\.|iv\.|CTR\.|CBC\.|HMAC\.|ECDH\.|DiffieHellman" src
$ find src -maxdepth 2 | head -n 200
$ cat src/lib.rs
$ wc -l src/lib.rs
$ grep -n "sha\.|md5\.|sha1\.|blake2\.|keccak\.|ripemd\.|hmac\.|ecdsa\.|rsa\.|des\.|aes\.|sha256\.|sha512\.|sha224\.|ripemd160\.|md4\.|md5" src/lib.rs
$ grep -RIn "sha\.|md5\.|sha1\.|blake2\.|keccak\.|ripemd\.|hmac\.|ecdsa\.|rsa\.|des\.|aes\.|sha256\.|sha512\.|sha224\.|ripemd160\.|md4\.|md5" src/lib.rs
$ grep -RIn "sha" src/lib.rs
$ grep -RIn "hash\(" src/lib.rs
$ grep -RIn "sha256" src/lib.rs
$ grep -RIn "sha256" src
```
