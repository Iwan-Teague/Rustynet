# Antares scan — `rustynet-crypto` — CWE-327

**Date:** 2026-07-23  
**Scope:** `rustynet-crypto` (1 first-party `.rs` files)  
**CWE:** CWE-327 — Use of a broken or risky cryptographic algorithm, or insecure use of cryptographic primitives (weak cipher/hash, misused nonce/IV, bad KDF).  
**Verdict:** `vulnerable_files`  
**Budget:** 8/8 terminal cmds, 18 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inspected |

## Model reasoning

The crypto algorithm enum includes CryptoAlgorithm::Md5, which maps to the MD5 cryptographic hash algorithm. MD5 is a weak cryptographic primitive (CWE-327) and should not be used for security-critical applications. The presence of Md5 in the algorithm enum indicates where the risky algorithm is implemented.

## Commands run
```
$ ls
$ grep -RIn "cipher\.|hash\.|sign\.|verify\.|rsa\.|ecdsa\.|aes\.|des\.|blake2\.|sha\.|md5\.|sha1\.|curve\.|kdf\.|nonce\.|iv\.|CTR\.|CBC\.|HMAC\.|ECDH\.|DiffieHellman" src || true
$ grep -RIn "cipher\.|hash\.|sign\.|verify\.|rsa\.|ecdsa\.|aes\.|des\.|blake2\.|sha\.|md5\.|sha1\.|curve\.|kdf\.|nonce\.|iv\.|CTR\.|CBC\.|HMAC\.|ECDH\.|DiffieHellman" src
$ grep -RIn "cipher\.|hash\.|sign\.|verify\.|rsa\.|ecdsa\.|aes\.|des\.|blake2\.|sha\.|md5\.|sha1\.|curve\.|kdf\.|nonce\.|iv\.|CTR\.|CBC\.|HMAC\.|ECDH\.|DiffieHellman" src
$ find src -maxdepth 2 | head -n 200
$ cat src/lib.rs
$ grep -n "fn .*_key\|fn .*_keypair\|fn .*_key_derive\|fn .*_encrypt\|fn .*_decrypt\|fn .*_sign\|fn .*_verify" src/lib.rs | head -n 200
$ grep -n "fn .*_key\|fn .*_keypair\|fn .*_key_derive\|fn .*_encrypt\|fn .*_decrypt\|fn .*_sign\|fn .*_verify" src/lib.rs
$ grep -n "fn .*_key\|fn .*_keypair\|fn .*_key_derive\|fn .*_encrypt\|fn .*_decrypt\|fn .*_sign\|fn .*_verify" src/lib.rs 2>&1
$ find . -name '*.rs' | xargs grep -n "cipher\.|hash\.|sign\.|verify\.|rsa\.|ecdsa\.|aes\.|des\.|blake2\.|sha\.|md5\.|sha1\.|curve\.|kdf\.|nonce\.|iv\.|CTR\.|CBC\.|HMAC\.|ECDH\.|DiffieHellman"
$ find . -name '*.rs' | head -n 20
$ grep -RIn "md5\.|md5" .
$ grep -RIn "md5" src
$ find src -name '*.rs' | xargs grep -n "md5"
$ find src -name '*.rs' | head -n 10
$ grep -RIn "Md5" src
$ sed -n '160,180p' src/lib.rs
```
