# Antares scan — `rustynet-llm-gateway` — CWE-20

**Date:** 2026-07-23  
**Scope:** `rustynet-llm-gateway` (7 first-party `.rs` files)  
**CWE:** CWE-20 — Improper input validation: input is not validated (or is validated incorrectly) before use, allowing malformed or malicious data to alter control/data flow.  
**Verdict:** `vulnerable_files`  
**Budget:** 9/15 terminal cmds, 17 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/enforce.rs` | inspected |

## Model reasoning

src/enforce.rs implements authorization checks for LLM node access (model allow-listing, token quotas, request rates) using signed policy scopes and a BTreeMap of SignedPeer entries. It is responsible for validating attacker-influenced model names. If the code accepts arbitrary model names without canonicalization/whitelisting, an attacker can supply a malicious model name (containing newlines, control characters, or crafted separators) that alters control/data flow when the engine resolves or serves it, matching CWE-20 improper input validation.

## Commands run
```
$ ls -la /workspace/repo/
$ find /workspace/repo -maxdepth 2 | head -n 100
$ cat Cargo.toml
$ grep -R "url" -n src || true
$ grep -R "url" src || true
$ grep -R "url" src/ 2>/dev/null || true
$ grep -R "http" src || true
$ grep -R "request" src || true
$ grep -R "deserialize" src || true
$ cat src/health.rs
$ cat src/protocol.rs
$ cat src/enforce.rs
$ cat src/lib.rs
$ cat src/main.rs
$ wc -l src/enforce.rs src/lib.rs src/main.rs
```
