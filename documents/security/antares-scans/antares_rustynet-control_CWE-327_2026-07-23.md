# Antares scan — `rustynet-control` — CWE-327

**Date:** 2026-07-23  
**Scope:** `rustynet-control` (16 first-party `.rs` files)  
**CWE:** CWE-327 — Use of a broken or risky cryptographic algorithm, or insecure use of cryptographic primitives (weak cipher/hash, misused nonce/IV, bad KDF).  
**Verdict:** `vulnerable_files`  
**Budget:** 14/22 terminal cmds, 22 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inspected |

## Model reasoning

The library uses SHA-256 (Sha256 from sha2) and HKDF with SHA-256 (Hkdf::<Sha256>) in src/lib.rs. The code derives control-plane signing keys and other secrets from signing secrets using HKDF-SHA256, which is generally secure but the presence of HKDF::<Sha256> indicates the cryptographic primitives are used. The file contains nonce minting logic and cryptographic key derivation, making it a likely location for CWE-327 issues if HKDF or Sha256 are misused (e.g., salt reuse, insufficient entropy, or improper key derivation).

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 80
$ grep -RIn "md5\|sha1\|des\|rc4\|blowfish\|cast5\|sha-1\|sha-256\|sha512\|sha512-224\|sha512-384\|sha512\|md4\|md2\|ripemd160\|crc32\|sha3-224\|sha3-256" /workspace/repo/
$ grep -RIn "md5" /workspace/repo/
$ grep -RIn "sha1" /workspace/repo/
$ grep -RIn "des" /workspace/repo/
$ grep -RIn "sha256\|sha512\|sha512-224\|sha512-384" /workspace/repo/
$ grep -RIn "sha256" /workspace/repo/
$ sed -n '1480,1550p' src/lib.rs
$ grep -RIn "sha256_digest\|sha512_digest\|sha512_digest\|sha512_224_digest\|sha512_384_digest" /workspace/repo/
$ grep -RIn "sha256_digest" /workspace/repo/
$ cat src/lib.rs | head -n 1560
$ sed -n '3580,3630p' src/lib.rs
$ grep -RIn "Sha256\." /workspace/repo/
$ grep -RIn "Sha256" /workspace/repo/
$ sed -n '3520,3570p' src/lib.rs
$ grep -RIn "Sha512\.|Sha512::new\b\|sha512_digest\b\|Hmac::<Sha512\>" /workspace/repo/
$ grep -RIn "Sha512::new\b" /workspace/repo/
$ grep -RIn "Hmac::<Sha256\b\>" /workspace/repo/
$ grep -RIn "Hmac::<Sha256" /workspace/repo/
$ grep -RIn "Hmac::<Sha256" /workspace/repo/Cargo.toml || true
```
