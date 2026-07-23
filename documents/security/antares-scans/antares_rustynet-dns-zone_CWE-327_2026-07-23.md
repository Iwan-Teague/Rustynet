# Antares scan — `rustynet-dns-zone` — CWE-327

**Date:** 2026-07-23  
**Scope:** `rustynet-dns-zone` (1 first-party `.rs` files)  
**CWE:** CWE-327 — Use of a broken or risky cryptographic algorithm, or insecure use of cryptographic primitives (weak cipher/hash, misused nonce/IV, bad KDF).  
**Verdict:** `vulnerable_files`  
**Budget:** 8/8 terminal cmds, 15 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inspected |

## Model reasoning

The file uses ed25519_dalek::Signer/VerifyingKey for digital signatures, which is secure. It uses sha2::Sha256 for digest hashing, which is also secure. However, the repository may contain weak hash implementations or insecure crypto usage elsewhere. The cryptographic primitives used (ed25519, sha2) are generally secure, but I should verify for any weak hash functions (md5, sha1) or insecure crypto algorithms (DES, ECB). The file src/lib.rs contains cryptographic operations including signature verification and digest computation using secure algorithms.

## Commands run
```
$ ls
$ grep -RIn "cipher\.|hash\.|sign\.|verify\.|rsa\.|ecdsa\.|aes\.|des\.|blake2\.|sha\.|md5\.|sha1\.|curve\.|kdf\.|nonce\.|iv\.|CTR\.|CBC\.|HMAC\.|ECDH\.|DiffieHellman" src || true
$ grep -RIn "cipher\.|hash\.|sign\.|verify\.|rsa\.|ecdsa\.|aes\.|des\.|blake2\.|sha\.|md5\.|sha1\.|curve\.|kdf\.|nonce\.|iv\.|CTR\.|CBC\.|HMAC\.|ECDH\.|DiffieHellman" src
$ grep -RIn "cipher\.|hash\.|sign\.|verify\.|rsa\.|ecdsa\.|aes\.|des\.|blake2\.|sha\.|md5\.|sha1\.|curve\.|kdf\.|nonce\.|iv\.|CTR\.|CBC\.|HMAC\.|ECDH\.|DiffieHellman" src
$ find src -maxdepth 2 | head -n 200
$ cat src/lib.rs
$ grep -RIn "sha2\.|sha256\.|sha512\.|ripemd160\.|md5\.|md5digest\.|ripemd160digest\.|ed25519\.|signer\.|verifying_key\.|ed25519_dalek" src
$ cat src/lib.rs | head -n 500
$ grep -n "verify\|verify_signature\|signature\|digest\|sha256\|ed25519\|signer" src/lib.rs
$ grep -n "verify_signature" src/lib.rs
$ grep -n "verify_signature" src/lib.rs
$ cat src/lib.rs | grep -n "verify\|signature\|digest\|sha256\|ed25519\|signer"
$ head -n 500 src/lib.rs
$ wc -l src/lib.rs
```
