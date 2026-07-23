# Antares scan — `ALL` — CWE-20

**Date:** 2026-07-23  
**Scope:** `ALL` (498 first-party `.rs` files)  
**CWE:** CWE-20 — Improper input validation: input is not validated (or is validated incorrectly) before use, allowing malformed or malicious data to alter control/data flow.  
**Verdict:** `vulnerable_files`  
**Budget:** 21/30 terminal cmds, 28 turns

> Low-confidence triage lead, not a finding. Antares localizes; it does not confirm exploitability or fix. `inspected` = model opened the file; `inferred` = submitted from a grep hit only.

## Candidate files

| File | Read? |
|---|---|
| `crates/rustynetd/src/gossip_runtime.rs` | inspected |

## Model reasoning

The vulnerable code is in crates/rustynetd/src/gossip_runtime.rs at lines ~716 and ~797. The code uses `u8::from_str_radix(hex, 16)` and `u16::from_str_radix(hex, 16)` to parse hexadecimal values without any validation of the input format. This is an input validation issue (CWE-20) because the code blindly trusts the hex string and parses it as an unsigned integer in radix 16, without checking that the string contains only valid hexadecimal characters or that the resulting value is within an expected range. Malformed or maliciously crafted hex strings could cause integer overflow, unexpected values, or panic. The code also uses indexing (`signature_hex[i..i + 2]`) which could access out-of-bounds indices if the hex string length is insufficient.

## Commands run
```
$ find . -maxdepth 2 | head -n 50
$ grep -RIn "json\.Unmarshal\|Unmarshal(\|Unmarshal(" . | head -n 20
$ grep -RIn "Unmarshal(" . | head -n 30
$ grep -RIn "json\.Unmarshal\|Unmarshal(\|Unmarshal\(" . | head -n 30
$ grep -RIn "Unmarshal(" . | head -n 30
$ grep -RIn "Unmarshal" . | head -n 30
$ grep -RIn "deserialize\." . | head -n 30
$ grep -RIn "deserialize\." crates | head -n 30
$ grep -RIn "from_json\|from_json_raw\|serde_json\|serde_json::" | head -n 30
$ grep -RIn "serde_json" . | head -n 30
$ cat crates/rustynetd/src/macos_runtime_acls.rs
$ grep -RIn "from_str\(" . | head -n 20
$ grep -RIn "from_str" . | head -n 30
$ grep -RIn "deserialize\(" crates | grep -v "src/" | head -n 20
$ grep -RIn "deserialize(" crates/rustynetd | head -n 50
$ grep -RIn "deserialize\(" crates/rustynetd | head -n 30
$ ls -la crates/rustynet-policy/src/
$ head -n 100 crates/rustynet-policy/src/lib.rs
$ grep -RIn "from_str\|from_str_radix\|from_str_literal\|from_str_literal\|from_str_literal" crates/rustynet-policy/src/lib.rs
$ grep -RIn "from_str" crates/rustynet-policy/src/lib.rs
$ grep -RIn "from_str" . | grep -E "policy|rustynet-policy" | head -n 20
$ grep -RIn "from_str" . | grep -E "policy|rustynet-policy"
$ grep -RIn "from_str" . | head -n 50
$ grep -RIn "from_str_radix" crates/rustynet-policy/src/lib.rs
$ grep -RIn "from_str_radix" . | head -n 50
$ cat crates/rustynetd/src/gossip_runtime.rs
$ grep -RIn "from_str_radix" . | head -n 50
```
