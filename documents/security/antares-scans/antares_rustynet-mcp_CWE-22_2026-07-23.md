# Antares scan — `rustynet-mcp` — CWE-22

**Date:** 2026-07-23  
**Scope:** `rustynet-mcp` (6 first-party `.rs` files)  
**CWE:** CWE-22 — Path traversal: externally-influenced input constructs a filesystem path that escapes the intended directory (../ etc.).  
**Verdict:** `vulnerable_files`  
**Budget:** 15/15 terminal cmds, 18 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inferred (grep-only) |
| `src/bin/repo_context.rs` | inferred (grep-only) |

## Model reasoning

The code uses read_file_capped(&self.repo_root.join(relative_path), ...) and other repo_root.join(...) usages, which construct filesystem paths from user-controlled strings. If relative_path or similar inputs are not validated/sanitized before joining with repo_root, this can enable path traversal (CWE-22). The relevant implementations are in src/lib.rs (read_file_capped) and src/bin/repo_context.rs (uses repo_root.join(...) for crates, Cargo.toml, inventory, etc.).

## Commands run
```
$ cd /workspace/repo/ && ls
$ find . -maxdepth 2 | head -n 200
$ grep -RIn "\.join\(" src | head -n 200
$ grep -RIn "\.join(" src
$ grep -RIn "read_file_capped\(" src | head -n 200
$ grep -RIn "read_file_capped" src
$ grep -RIn "\.join\(" src/lib.rs | head -n 200
$ grep -RIn "\.join(" src/lib.rs
$ grep -RIn "\.join\(" src/bin | head -n 200
$ grep -RIn "\.join(" src/bin
$ grep -RIn "\.join\(" src/bin/ | head -n 200
$ find src -maxdepth 2 | grep -E "bin|lib|context"
$ find src/bin -maxdepth 1
$ grep -RIn "\.join\(" src/bin/repo_context.rs | head -n 200
$ grep -RIn "\.join(" src/bin/repo_context.rs
$ grep -RIn "\.join\(" src/lib.rs | head -n 200
$ grep -RIn "\.join(" src/lib.rs
```
