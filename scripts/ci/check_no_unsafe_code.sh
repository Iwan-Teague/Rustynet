#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
  echo "missing required command: python3" >&2
  exit 1
fi

python3 - <<'PY'
from pathlib import Path
import sys
import tempfile


def advance_position(text: str, index: int, line: int, column: int):
    ch = text[index]
    if ch == "\n":
        return index + 1, line + 1, 1
    return index + 1, line, column + 1


def scan_file(path: Path):
    text = path.read_text(encoding="utf-8")
    findings = []

    i = 0
    line = 1
    column = 1
    n = len(text)

    state = "normal"
    block_depth = 0
    raw_hashes = 0

    def consume_lifetime(start_index: int, current_line: int, current_column: int):
        i2, l2, c2 = advance_position(text, start_index, current_line, current_column)
        while i2 < n and (text[i2].isalnum() or text[i2] == "_"):
            i2, l2, c2 = advance_position(text, i2, l2, c2)
        return i2, l2, c2

    while i < n:
        ch = text[i]

        if state == "normal":
            if ch == "/" and i + 1 < n and text[i + 1] == "/":
                i, line, column = advance_position(text, i, line, column)
                i, line, column = advance_position(text, i, line, column)
                state = "line_comment"
                continue
            if ch == "/" and i + 1 < n and text[i + 1] == "*":
                i, line, column = advance_position(text, i, line, column)
                i, line, column = advance_position(text, i, line, column)
                state = "block_comment"
                block_depth = 1
                continue
            if ch == "\"":
                i, line, column = advance_position(text, i, line, column)
                state = "string"
                continue
            if ch == "'":
                if i + 1 < n and (text[i + 1].isalpha() or text[i + 1] == "_"):
                    # Distinguish Rust lifetimes/labels (e.g. `'a`, `'static`) from char literals.
                    # A one-codepoint char literal has an immediate closing quote: `'x'`.
                    if not (i + 2 < n and text[i + 2] == "'"):
                        i, line, column = consume_lifetime(i, line, column)
                        continue
                i, line, column = advance_position(text, i, line, column)
                state = "char"
                continue
            if ch == "r":
                j = i + 1
                hashes = 0
                while j < n and text[j] == "#":
                    hashes += 1
                    j += 1
                if j < n and text[j] == "\"":
                    while i <= j:
                        i, line, column = advance_position(text, i, line, column)
                    state = "raw_string"
                    raw_hashes = hashes
                    continue
            if ch.isalpha() or ch == "_":
                start_i = i
                start_line = line
                start_col = column
                while i < n and (text[i].isalnum() or text[i] == "_"):
                    i, line, column = advance_position(text, i, line, column)
                token = text[start_i:i]
                if token == "unsafe":
                    findings.append((start_line, start_col))
                continue

            i, line, column = advance_position(text, i, line, column)
            continue

        if state == "line_comment":
            if ch == "\n":
                i, line, column = advance_position(text, i, line, column)
                state = "normal"
            else:
                i, line, column = advance_position(text, i, line, column)
            continue

        if state == "block_comment":
            if ch == "/" and i + 1 < n and text[i + 1] == "*":
                i, line, column = advance_position(text, i, line, column)
                i, line, column = advance_position(text, i, line, column)
                block_depth += 1
                continue
            if ch == "*" and i + 1 < n and text[i + 1] == "/":
                i, line, column = advance_position(text, i, line, column)
                i, line, column = advance_position(text, i, line, column)
                block_depth -= 1
                if block_depth == 0:
                    state = "normal"
                continue

            i, line, column = advance_position(text, i, line, column)
            continue

        if state == "string":
            if ch == "\\":
                i, line, column = advance_position(text, i, line, column)
                if i < n:
                    i, line, column = advance_position(text, i, line, column)
                continue
            if ch == "\"":
                i, line, column = advance_position(text, i, line, column)
                state = "normal"
                continue

            i, line, column = advance_position(text, i, line, column)
            continue

        if state == "char":
            if ch == "\\":
                i, line, column = advance_position(text, i, line, column)
                if i < n:
                    i, line, column = advance_position(text, i, line, column)
                continue
            if ch == "'":
                i, line, column = advance_position(text, i, line, column)
                state = "normal"
                continue

            i, line, column = advance_position(text, i, line, column)
            continue

        if state == "raw_string":
            if ch == "\"":
                suffix_start = i + 1
                suffix_end = suffix_start + raw_hashes
                if suffix_end <= n and text[suffix_start:suffix_end] == "#" * raw_hashes:
                    i, line, column = advance_position(text, i, line, column)
                    for _ in range(raw_hashes):
                        i, line, column = advance_position(text, i, line, column)
                    state = "normal"
                    continue

            i, line, column = advance_position(text, i, line, column)
            continue

        raise RuntimeError(f"unknown scanner state {state}")

    return findings


def run_scanner_self_tests():
    cases = [
        (
            "lifetime_only",
            "fn keep<'a>(value: &'a str) -> &'a str { value }\n",
            0,
        ),
        (
            "lifetime_plus_unsafe_block",
            "fn keep<'a>(value: &'a str) -> &'a str { value }\nfn bad() { unsafe { let _x = 1; } }\n",
            1,
        ),
        (
            "comments_and_strings",
            "// unsafe should not match here\nconst NOTE: &str = \"unsafe in string\";\n",
            0,
        ),
    ]

    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        for name, source, expected_count in cases:
            path = base / f"{name}.rs"
            path.write_text(source, encoding="utf-8")
            findings = scan_file(path)
            if len(findings) != expected_count:
                print(
                    f"unsafe scanner self-test failed for {name}: "
                    f"expected {expected_count} findings, got {len(findings)}"
                )
                sys.exit(2)


run_scanner_self_tests()

root = Path("crates")
all_findings = []

for path in sorted(root.rglob("*.rs")):
    if "target" in path.parts:
        continue
    for line, col in scan_file(path):
        all_findings.append((path, line, col))

if all_findings:
    print("unsafe keyword usage is forbidden in repository Rust sources:")
    for path, line, col in all_findings:
        print(f"{path}:{line}:{col}: unsafe keyword detected")
    sys.exit(1)
PY

echo "Unsafe code checks: PASS"
