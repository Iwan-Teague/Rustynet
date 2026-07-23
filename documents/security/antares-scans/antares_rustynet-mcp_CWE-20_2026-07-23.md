# Antares scan — `rustynet-mcp` — CWE-20

**Date:** 2026-07-23  
**Scope:** `rustynet-mcp` (6 first-party `.rs` files)  
**CWE:** CWE-20 — Improper input validation: input is not validated (or is validated incorrectly) before use, allowing malformed or malicious data to alter control/data flow.  
**Verdict:** `vulnerable_files`  
**Budget:** 13/15 terminal cmds, 17 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `src/lib.rs` | inspected |

## Model reasoning

The JSON Schema deserialization logic is implemented in src/lib.rs (functions deserialize_json_schema and json_schema_object). These functions parse user-supplied schema objects and construct validation structures without sufficient validation of the input JSON format or schema validity. Malformed or crafted schema objects could lead to incorrect validation behavior or potential deserialization issues. The function json_schema_object at line 324 constructs a schema object from properties and required fields, and the deserialize_json_schema function is responsible for deserializing JSON Schema documents. This is a likely location for CWE-20 improper input validation.

## Commands run
```
$ ls -la /workspace/repo/
$ find . -maxdepth 2 | head -n 80
$ cat Cargo.toml
$ cat src/lib.rs
$ wc -l src/lib.rs
$ grep -RIn "input_schema\|input_schema:" src/lib.rs
$ grep -RIn "input_schema" src/lib.rs
$ sed -n '1120,1200p' src/lib.rs
$ grep -RIn "deserialize_json_schema\|deserialize_json_schema(" src/lib.rs
$ grep -RIn "deserialize_json_schema" src/lib.rs
$ grep -RIn "deserialize_json_schema" .
$ grep -RIn "deserialize_json_schema" src/
$ grep -RIn "deserialize_json_schema" -e "deserialize_json_schema" src/lib.rs
$ grep -RIn "json_schema_object\|json_schema_object(" src/lib.rs
$ grep -RIn "json_schema_object" src/lib.rs
$ nl -ba src/lib.rs | sed -n '1120,1210p'
```
