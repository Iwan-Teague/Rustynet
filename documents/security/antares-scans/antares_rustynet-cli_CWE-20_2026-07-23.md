# Antares scan — `rustynet-cli` — CWE-20

**Date:** 2026-07-23  
**Scope:** `rustynet-cli` (273 first-party `.rs` files)  
**CWE:** CWE-20 — Improper input validation: input is not validated (or is validated incorrectly) before use, allowing malformed or malicious data to alter control/data flow.  
**Verdict:** `aborted`  
**Budget:** 24/30 terminal cmds, 30 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

_None (aborted or no matching vulnerability declared)._

## Model reasoning

model produced 3 consecutive turns with no tool call

## Commands run
```
$ find . -maxdepth 2 | head -n 50
$ cat Cargo.toml
$ grep -R "url" -n src | head -n 200
$ grep -R "parse_url" -n src | head -n 200
$ grep -R "http://" -n src | head -n 200
$ grep -R "Invoke-WebRequest" -n src | head -n 200
$ cat src/vm_lab/orchestrator/role_validation/relay.rs
$ grep -R "http_url" -n src | head -n 200
$ grep -R "FromURL|parse_from_url|FromURL_try|FromURL::" -n src | head -n 200
$ grep -R "FromURL" -n src | head -n 200
$ find . -type d | grep -E "relay|service|role_validation|vm_lab"
$ find . -maxdepth 1 | grep -E "relay|service|role_validation|vm_lab"
$ find . -maxdepth 1 | head -n 200
$ ls -la src/
$ ls -la src/bin/
$ grep -R "FromURL" src/
$ grep -R "FromURL" src/*.rs | head -n 200
$ grep -R "FromURL_try" -n src/
$ grep -R "FromURL" src/live_lab_support/
$ find src/live_lab_support -type f
$ find . -name '*live_lab*' | head -n 200
$ ls -la src/bin/live_lab_support/
$ cat src/bin/live_lab_support/mod.rs
$ grep -R "url" src/bin/live_lab_support/
$ grep -R "FromStr" -n src/bin/live_lab_support/
$ grep -R "impl FromStr" -n src/bin/live_lab_support/
$ grep -R "impl FromStr" -n src/bin/live_lab_support/ | head -n 200
```
