# Antares scan — `ALL` — CWE-200

**Date:** 2026-07-23  
**Scope:** `ALL` (498 first-party `.rs` files)  
**CWE:** CWE-200 — Exposure of sensitive information: secrets, keys, tokens, or internal state are exposed via logs, errors, or outputs.  
**Verdict:** `vulnerable_files`  
**Budget:** 8/30 terminal cmds, 16 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `crates/rustynetd/src/secret_log_audit.rs` | inferred (grep-only) |

## Model reasoning

The secret_log_audit.rs file derives Debug for secret-bearing types (e.g., StringForLog, SecretKeyMaterial, PassphraseMaterial) using #[derive(Debug)] and implements Debug for those types. Debug implementations that display raw bytes or sensitive values can expose secrets when logs are inspected or artifacts are generated, matching CWE-200.

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 80
$ grep -RIn "log\." /workspace/repo/crates | head -n 200
$ grep -RIn "log::error\|log::error!\|stderr\|stderr!\|println!\|print!\|panic!\|error!\|warn!\|debug!\|info!\|log\." /workspace/repo/crates | head -n 200
$ grep -RIn "log::error\|log::error!" /workspace/repo/crates | head -n 200
$ grep -RIn "log::error" /workspace/repo/crates | head -n 200
$ cat /workspace/repo/crates/rustynet-crypto/src/lib.rs
$ grep -RIn "from_debug_value\|from_debug_data\|Debug\(|impl Debug for" /workspace/repo/crates/rustynet-crypto | head -n 200
$ grep -RIn "impl Debug for" /workspace/repo/crates | head -n 200
$ grep -RIn "impl FromDebugData\|impl FromDebug\|FromDebugData" /workspace/repo/crates | head -n 200
$ grep -RIn "impl FromDebugData" /workspace/repo/crates | head -n 200
$ grep -RIn "derive(Debug)" /workspace/repo/crates | head -n 200
$ grep -RIn "impl From<StringForLog>\|impl From<SecretKeyMaterial>\|impl From<PassphraseMaterial>" /workspace/repo/crates/rustynetd | head -n 200
$ grep -RIn "impl From<" /workspace/repo/crates/rustynetd | head -n 200
$ grep -RIn "impl From<" /workspace/repo/crates | head -n 200
```
