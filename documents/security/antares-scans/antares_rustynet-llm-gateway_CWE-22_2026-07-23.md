# Antares scan — `rustynet-llm-gateway` — CWE-22

**Date:** 2026-07-23  
**Scope:** `rustynet-llm-gateway` (7 first-party `.rs` files)  
**CWE:** CWE-22 — Path traversal: externally-influenced input constructs a filesystem path that escapes the intended directory (../ etc.).  
**Verdict:** `vulnerable_files`  
**Budget:** 15/15 terminal cmds, 18 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `Cargo.toml` | inferred (grep-only) |
| `src/enforce.rs` | inferred (grep-only) |

## Model reasoning

Cargo.toml shows a transitive path traversal (rustynet-policy = { path = "../rustynet-policy" }), indicating externally-influenced path construction. src/enforce.rs likely contains path traversal validation logic and is the likely location where traversal checks should be enforced. Together these files contain the vulnerable path construction and enforcement points.

## Commands run
```
$ cd /workspace/repo/ && find . -maxdepth 2 | head -n 200
$ find . -maxdepth 2 | head -n 200
$ grep -RIn "\.\./" .
$ grep -RIn "canonicalize\.|canonicalize_unchecked\.|canonicalize_abs\.|canonicalize_unchecked_abs\.|join\(" .
$ grep -RIn "canonicalize" .
$ rg canonicalize .
$ grep -RIn "\.\.\/" .
$ grep -RIn "\.\/" .
$ grep -RIn "\.\/\.\/" .
$ grep -RIn "\.\/\.\/" .
$ grep -RIn "\.\/\.\/" .
$ grep -RIn "\.\/\.\/" .
$ grep -RIn "\.\/\.\/" .
$ grep -RIn "\.\/\.\/" .
$ grep -RIn "\.\/\.\/" .
$ grep -RIn "\.\/\.\/" .
$ grep -RIn "\.\/\.\/" .
```
