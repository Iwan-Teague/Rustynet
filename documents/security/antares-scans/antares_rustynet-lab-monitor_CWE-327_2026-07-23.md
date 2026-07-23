# Antares scan — `rustynet-lab-monitor` — CWE-327

**Date:** 2026-07-23  
**Scope:** `rustynet-lab-monitor` (34 first-party `.rs` files)  
**CWE:** CWE-327 — Use of a broken or risky cryptographic algorithm, or insecure use of cryptographic primitives (weak cipher/hash, misused nonce/IV, bad KDF).  
**Verdict:** `vulnerable_files`  
**Budget:** 20/22 terminal cmds, 22 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/data/job_watcher.rs` | inspected |

## Model reasoning

The job_watcher module scans job state directories for JSON files and deserializes them into JobState structs. The code handles deserialization errors by continuing to the next entry (returning Some(... ) => Err(_) => continue). This means malformed or invalid JSON content can be deserialized and treated as valid job state, potentially allowing unexpected behavior or misuse of the job system. The file contains the scanning and deserialization logic that is the likely location of a cryptographic algorithm misuse issue (invalid/malformed data during deserialization).

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 100
$ grep -RIn "md5\|sha1\|des\|rcrypto::blowfish\|blowfish\|sha256::Crypto::\|md4\|md5::MessageDigest::MD5\|sha1::MessageDigest::SHA1\|sha256::MessageDigest::SHA256\|sha512::MessageDigest::SHA512" /workspace/repo/ | head -n 200
$ grep -RIn "md5" /workspace/repo/
$ grep -RIn "sha1" /workspace/repo/
$ grep -RIn "des" /workspace/repo/
$ grep -RIn "md5" /workspace/repo/
$ grep -RIn "MessageDigest" /workspace/repo/
$ grep -RIn "Crypto::" /workspace/repo/src/ | head -n 200
$ ls -la src/
$ ls -la src/data/
$ cat src/data/mod.rs
$ cat src/data/job_watcher.rs
$ head -n 300 src/data/job_watcher.rs
$ tail -n 100 src/data/job_watcher.rs
$ grep -RIn "sha1" /workspace/repo/
$ grep -RIn "sha256\." /workspace/repo/src/ | head -n 200
$ grep -RIn "sha1\." /workspace/repo/src/ | head -n 200
$ grep -RIn "sha1::" /workspace/repo/src/ | head -n 200
$ grep -RIn "sha1::Crypto::" /workspace/repo/src/ | head -n 200
$ grep -RIn "sha1" /workspace/repo/fixtures/
```
