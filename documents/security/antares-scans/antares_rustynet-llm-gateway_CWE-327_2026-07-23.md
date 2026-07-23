# Antares scan — `rustynet-llm-gateway` — CWE-327

**Date:** 2026-07-23  
**Scope:** `rustynet-llm-gateway` (7 first-party `.rs` files)  
**CWE:** CWE-327 — Use of a broken or risky cryptographic algorithm, or insecure use of cryptographic primitives (weak cipher/hash, misused nonce/IV, bad KDF).  
**Verdict:** `vulnerable_files`  
**Budget:** 10/15 terminal cmds, 15 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/session.rs` | inspected |

## Model reasoning

The session token implementation uses SHA-256 to create a thumbprint from a payload that includes the signed session token signature bytes. This creates a signature leak: the signature is embedded in the thumbprint, so an attacker who obtains the thumbprint can infer the signature value. The thumbprint is used for token validation and audit logging, so the embedded signature exposes the signing key/signature to attackers. This is a broken cryptographic use (embedding signature in thumbprint) which violates the principle of not leaking signatures or keys through derived identifiers.

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 80
$ grep -RIn "md5\|sha1\|des\|rc4\|blowfish\|sha256::digest\|sha256::New\|sha3::Sha256\|sha512::Digest\|sha512::Sha512\|sha512::New\|md4\|md2\|sha0" /workspace/repo/src || true
$ grep -RIn "md5" /workspace/repo/src || true
$ grep -RIn "md5" /workspace/repo/
$ grep -RIn "sha1" /workspace/repo/
$ grep -RIn "des" /workspace/repo/
$ grep -RIn "sha256" /workspace/repo/src || true
$ sed -n '1,240p' src/engine.rs
$ sed -n '1,260p' src/lib.rs
$ sed -n '1,240p' src/session.rs
$ sed -n '240,520p' src/session.rs
$ grep -RIn "SigningKey\|SigningKey::" src/ || true
$ grep -RIn "SigningKey" src/
```
