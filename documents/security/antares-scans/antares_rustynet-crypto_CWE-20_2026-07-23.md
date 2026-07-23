# Antares scan — `rustynet-crypto` — CWE-20

**Date:** 2026-07-23  
**Scope:** `rustynet-crypto` (1 first-party `.rs` files)  
**CWE:** CWE-20 — Improper input validation: input is not validated (or is validated incorrectly) before use, allowing malformed or malicious data to alter control/data flow.  
**Verdict:** `vulnerable_files`  
**Budget:** 8/8 terminal cmds, 12 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inferred (grep-only) |

## Model reasoning

The main Rustynet implementation (src/lib.rs) likely contains network request handling and payload parsing logic that processes untrusted external data (network payloads, tunnel config, CLI args). Such code is a likely location for improper input validation (CWE-20), where malformed or malicious data could alter control/data flow.

## Commands run
```
$ ls
$ grep -R "input_validation\|validate\|sanitize\|from_str\|parse\|deserialize\|deserialize\|read\|read_line\|read_to_string\|from_slice\|from_utf8\|unwrap\|expect\|unsafe" --include='*.rs'
$ find src -maxdepth 2 | head -n 200
$ grep -R "request\|request\|http\|net\|req\|url\|uri\|parse\(" src --include='*.rs'
$ grep -R "request" src --include='*.rs'
$ grep -R "http" src --include='*.rs'
$ grep -R "net" src --include='*.rs'
$ grep -R "url\|url::\|parse_url\|from_utf8\|read_to_string\|read_line\|from_slice\|deserialize\|serde" src --include='*.rs'
$ grep -R "url" src --include='*.rs'
$ grep -R "parse_url" src --include='*.rs'
$ grep -R "read_to_string" src --include='*.rs'
```
