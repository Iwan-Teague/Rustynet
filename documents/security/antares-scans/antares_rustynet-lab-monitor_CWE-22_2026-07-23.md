# Antares scan — `rustynet-lab-monitor` — CWE-22

**Date:** 2026-07-23  
**Scope:** `rustynet-lab-monitor` (34 first-party `.rs` files)  
**CWE:** CWE-22 — Path traversal: externally-influenced input constructs a filesystem path that escapes the intended directory (../ etc.).  
**Verdict:** `vulnerable_files`  
**Budget:** 15/22 terminal cmds, 23 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/app.rs` | inspected |

## Model reasoning

The resolver implementation in src/app.rs constructs a filesystem Path from an externally supplied report_dir string and uses it directly (repo_root.join(report_dir)) without canonicalization or traversal validation. The function resolve_report_dir(repo_root: &Path, report_dir: &str) -> PathBuf simply does Path::new(report_dir) and returns it (absolute if absolute, else repo_root.join(report_dir)). Callers (e.g., src/app.rs around lines ~1810) pass user-controlled strings into this resolver, so an attacker-controlled path traversal string (e.g. ../...) can escape the intended directory and be joined into absolute paths or paths outside the repository root. This matches CWE-22.

## Commands run
```
$ cd /workspace/repo/ && ls
$ find . -maxdepth 2 | head -n 200
$ grep -RIn "\.join\(" src | head -n 200
$ grep -RIn "\.join(" src
$ grep -RIn "read_json\(" src | head -n 200
$ grep -RIn "read_json" src
$ grep -RIn "report_dir\.|report_dir" src
$ grep -RIn "report_dir" src
$ grep -RIn "canonicalize\|canonicalize(" src
$ grep -RIn "canonicalize" src
$ grep -RIn "\.\.\.join\|\.\.\." src
$ grep -RIn "\.\.\." src
$ rg -n "resolve_report_dir|report_dir|\.join\(" src
$ grep -RIn "resolve_report_dir" src
$ cat src/app.rs
$ sed -n '235,260p' src/app.rs
$ grep -RIn "\.resolve\(" src
$ grep -RIn "resolve(" src
$ grep -RIn "resolve_report_dir" src
$ sed -n '1800,1850p' src/app.rs
$ grep -RIn "\.is_absolute\|\.strip_prefix\|\.prefix\|\.normalize\|\.join\(" src
$ grep -RIn "is_absolute\|strip_prefix\|prefix\|normalize\|join(" src
```
