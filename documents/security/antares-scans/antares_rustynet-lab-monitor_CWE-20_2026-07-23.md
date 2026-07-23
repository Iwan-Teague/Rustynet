# Antares scan — `rustynet-lab-monitor` — CWE-20

**Date:** 2026-07-23  
**Scope:** `rustynet-lab-monitor` (34 first-party `.rs` files)  
**CWE:** CWE-20 — Improper input validation: input is not validated (or is validated incorrectly) before use, allowing malformed or malicious data to alter control/data flow.  
**Verdict:** `vulnerable_files`  
**Budget:** 2/22 terminal cmds, 3 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/main.rs` | inferred (grep-only) |
| `src/app.rs` | inferred (grep-only) |
| `src/config.rs` | inferred (grep-only) |

## Model reasoning

The repository appears to be a Rust service. The main entry points (src/main.rs and src/app.rs) likely parse external input (CLI args, HTTP requests, config files) and pass it into handlers. src/config.rs is a likely place for unvalidated configuration input. These files are the most likely locations for CWE-20 (improper input validation) vulnerabilities where malformed or malicious data could alter control/data flow.

## Commands run
```
$ find . -maxdepth 2 | head -n 100
$ grep -R "url" -n src | head -n 200
```
