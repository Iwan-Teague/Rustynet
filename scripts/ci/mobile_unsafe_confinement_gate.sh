#!/usr/bin/env bash
# mobile_unsafe_confinement_gate.sh: unsafe-confinement census for every mobile crate
# (crates/rustynet-mobile-*). MC1d; DESIGN-mobile-security-architecture section 5.2 U-2,
# U-6 and section 5.5 Q7.
#
# The vendored census (scripts/ci/vendored_unsafe_drift_gate.sh) covers third_party/ only,
# and it refuses unsafe attributes (check_vendored_unsafe_counts.rs:1213-1217). This gate
# counts instead.
#
# WHAT THIS IS. A text gate is a TRIPWIRE, not a boundary. It catches honest mistakes and
# the common ways of smuggling code past a census. It cannot prove that no evasion exists:
# Rust macros and cargo features can generate code that no text scan sees. The real controls
# are (a) the OI-20 scanner and its exact-file allowlist (ops_phase1.rs UNSAFE_SCAN_ALLOWED_SCOPES),
# (b) the compiler lint `unsafe_code = "deny"` in the crate manifest, and (c) human review of
# every change to this crate and to this script.
#
# SCOPE. The crate list comes from cargo metadata: every workspace member whose name starts
# with rustynet-mobile, and every crates/rustynet-mobile* directory must be such a member. A
# crate renamed outside that pattern is covered only by the OI-20 scan inside crates/ (by
# design: the OI-20 scan covers every crate in the workspace, this gate covers the mobile ones).
#
# NOT YET (future hardening, recorded here so it is not forgotten): per-function pinning of
# unsafe sites (B20); a CI-checked sha256 manifest of this gate and check-mobile-deps.sh
# (B21/B22), so that editing the gate itself is visible in review.
#
# NO COMMENT STRIPPING. A line-based comment strip can be fooled (a `//` line inside a
# multi-line string, or `/* ... */` blocks), so every count is taken from the raw text.
# Comments are counted too, which fails closed. Doc comments must avoid the counted
# tokens, or the pin must record them.
#
# Per crate, the gate computes these keys:
#   <file>                 whole-word `unsafe` (raw text) plus extern blocks (whitespace-
#                          normalised text, so multi-line `extern` blocks count)
#   from_raw_fd:<file>     from_raw_fd / borrow_raw / from_raw_handle / from_raw_socket (raw)
#   allow:<file>           (allow|expect)(...unsafe_code...) lint attributes (whitespace-
#                          normalised, so multi-line attributes count)
# Every key must equal its value in <crate>/UNSAFE_PIN exactly. A missing key is pinned at
# 0. An increase fails (new unsafe). A decrease also fails (a stale pin would let a later
# re-introduction pass unnoticed).
#
# Refused outright, on whitespace-normalised text of each whole file (so whitespace
# variants such as `include ! (` or `# [ path = ...` do not evade):
#   include!(...), #[path], path= (in any attribute or Cargo.toml key), #[link...],
#   global_asm!, crate-level #![allow|expect|warn(...unsafe_code...)], bare #[no_mangle] or
#   #[export_name] (only the #[unsafe(...)] forms are accepted, edition 2024), and in
#   Cargo.toml: path= and build= keys (they would pull in code outside the crate).
# Refused on the file system: any symlink under a crate directory, and any file in a crate
# directory other than *.rs, Cargo.toml and UNSAFE_PIN.
#
# UNSAFE_PIN format: exactly two fields per line, "<key> <non-negative integer>". Comment
# lines start with '#'. A malformed value, a line with other than two fields, or a
# duplicate key fails the gate.
#
# Also required: <crate>/Cargo.toml keeps unsafe_code = "deny" inside its [lints.rust] table.
#
# The default run gates every crates/rustynet-mobile-* crate and then runs the self-test.
#
# USAGE
#   scripts/ci/mobile_unsafe_confinement_gate.sh                 # gate all mobile crates + self-test
#   scripts/ci/mobile_unsafe_confinement_gate.sh --self-test     # negative self-test only
#   scripts/ci/mobile_unsafe_confinement_gate.sh --print-counts  # print key/value body for UNSAFE_PIN
#   MOBILE_FFI_ROOT=<dir> scripts/ci/mobile_unsafe_confinement_gate.sh   # gate one crate dir

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FFI_ROOT="$REPO_ROOT/crates/rustynet-mobile-ffi"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mobile-unsafe-gate.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

fail() {
  printf 'mobile_unsafe_confinement_gate: FAIL: %s\n' "$*" >&2
}

# flatten FILE OUT: whitespace-free copy of the whole file (one line, no comments removed).
flatten() {
  tr -d '[:space:]' <"$1" >"$2"
}

# count_occ FILE GREP_ARGS...: number of occurrences in FILE (grep -o; no pipeline abort).
count_occ() {
  local file="$1"
  shift
  { grep -o "$@" "$file" || true; } | wc -l | tr -d ' '
}

# has_match FILE GREP_ARGS...: exit 0 when FILE contains a match.
has_match() {
  local file="$1"
  shift
  grep -q "$@" "$file"
}

# gate_crate DIR: returns 0 only when the crate matches every rule.
gate_crate() {
  local dir="$1" rc=0
  local manifest="$dir/Cargo.toml" pin_file="$dir/UNSAFE_PIN"
  local keys="$WORK/keys" pins="$WORK/pins" list="$WORK/list" bad="$WORK/bad"
  local flat="$WORK/flat" tokens="$WORK/tokens" rel key val pinned path total=0 rs_count

  if [ ! -f "$manifest" ] || [ ! -f "$pin_file" ]; then
    fail "$dir: missing Cargo.toml or UNSAFE_PIN"
    return 1
  fi

  # Table-aware check: unsafe_code = "deny" must sit inside [lints.rust].
  if ! awk '
      /^[[:space:]]*\[/ { sec = $0; gsub(/[[:space:]]/, "", sec) }
      sec == "[lints.rust]" && /^[[:space:]]*unsafe_code[[:space:]]*=[[:space:]]*"deny"[[:space:]]*$/ { ok = 1 }
      END { exit ok ? 0 : 1 }' "$manifest"; then
    fail "$manifest must keep unsafe_code = \"deny\" inside its [lints.rust] table"
    rc=1
  fi

  # Cargo.toml must not pull code from outside the crate or from a build script. TOML lets a
  # key be quoted ("build" = ..., 'path' = ...), so the key regexes run on a copy with quotes
  # removed. Belt and braces: a quoted key at all, and any backslash (TOML escapes such as
  # "\u0062uild"), are refused outright.
  flatten "$manifest" "$flat"
  if has_match "$flat" -E "\"[^\"]*\"=|'[^']*'="; then
    fail "$manifest: a quoted TOML key is refused (quoted keys can hide path=, build=, links=)"
    rc=1
  fi
  if has_match "$flat" -F '\'; then
    fail "$manifest: backslash escapes are refused (they can spell a key such as build)"
    rc=1
  fi
  tr -d "[:space:]\"'" <"$manifest" >"$WORK/manifest-unquoted"
  if has_match "$WORK/manifest-unquoted" -E '(^|[^A-Za-z0-9_-])(path|build|links|autobins|autotests|autoexamples|autobenches)='; then
    fail "$manifest: path=, build=, links=, or auto* target keys are refused (they can compile code outside the crate or run a build script)"
    rc=1
  fi
  if has_match "$WORK/manifest-unquoted" -F '[['; then
    fail "$manifest: array tables [[...]] are refused (they declare extra targets)"
    rc=1
  fi

  # A build script is refused at any depth, in any letter case: cargo finds build.rs without
  # any manifest key, and it can emit native link flags. On a case-insensitive filesystem
  # (macOS) Build.rs and BUILD.RS are found as build.rs, so the match is case-insensitive.
  find "$dir" -iname 'build.rs' >"$bad"
  if [ -s "$bad" ]; then
    while IFS= read -r path; do
      fail "$path: build.rs is refused in a mobile crate (cargo runs it automatically)"
    done <"$bad"
    rc=1
  fi

  # No symlinks anywhere under the crate: find -type f does not follow them, and cargo would.
  find "$dir" -type l >"$bad"
  if [ -s "$bad" ]; then
    while IFS= read -r path; do
      fail "$path: symlinks are refused under a mobile crate"
    done <"$bad"
    rc=1
  fi

  # Only *.rs sources, Cargo.toml and UNSAFE_PIN may live in the crate directory.
  find "$dir" -type f ! -name '*.rs' ! -name Cargo.toml ! -name UNSAFE_PIN >"$bad"
  if [ -s "$bad" ]; then
    while IFS= read -r path; do
      fail "$path: non-.rs file in a mobile crate (not allowed)"
    done <"$bad"
    rc=1
  fi

  : >"$keys"
  (cd "$dir" && find . -type f -name '*.rs' | sed 's#^\./##' | LC_ALL=C sort) >"$list"
  while IFS= read -r rel; do
    flatten "$dir/$rel" "$flat"

    if has_match "$flat" -F 'include!('; then
      fail "$rel: include!(...) is refused (it compiles code the census cannot see)"
      rc=1
    fi
    # Identifier tokens: `include` in any form (an alias such as `use std::include as inc;`
    # or a path such as `std::include`) and `macro_rules` (wrappers can hide the same).
    # `include_str` and `include_bytes` are different tokens and are not refused.
    tr -c 'A-Za-z0-9_' '\n' <"$dir/$rel" >"$tokens"
    if grep -q -x -e include -e macro_rules "$tokens"; then
      fail "$rel: the identifier 'include' or 'macro_rules' is refused (it can hide a file include)"
      rc=1
    fi
    if has_match "$flat" -E '#\[path|(^|[^A-Za-z0-9_])path='; then
      fail "$rel: #[path ...] or path= is refused (it can pull in unscanned code)"
      rc=1
    fi
    if has_match "$flat" -E '#!\[[^]]*(allow|expect|warn)\([^)]*unsafe_code'; then
      fail "$rel: crate-level #![allow|expect|warn(...unsafe_code...)] is refused"
      rc=1
    fi
    if has_match "$flat" -E '#\[(no_mangle|export_name)'; then
      fail "$rel: bare #[no_mangle] or #[export_name] is refused; use #[unsafe(no_mangle)] (edition 2024)"
      rc=1
    fi
    if has_match "$flat" -E '#\[link'; then
      fail "$rel: #[link] is refused (it links native code outside the census)"
      rc=1
    fi
    if has_match "$flat" -F 'global_asm!'; then
      fail "$rel: global_asm! is refused (assembly needs no unsafe block)"
      rc=1
    fi

    local unsafe_w extern_n raw_n allow_n
    unsafe_w="$(count_occ "$dir/$rel" -w 'unsafe')"
    extern_n="$(count_occ "$flat" -E 'extern("[^"]*")?\{')"
    raw_n="$(count_occ "$dir/$rel" -E '(from_raw_fd|borrow_raw|from_raw_handle|from_raw_socket)')"
    allow_n="$(count_occ "$flat" -E '(allow|expect)\([^)]*unsafe_code')"

    printf '%s %s\n' "$rel" $((unsafe_w + extern_n)) >>"$keys"
    printf 'from_raw_fd:%s %s\n' "$rel" "$raw_n" >>"$keys"
    printf 'allow:%s %s\n' "$rel" "$allow_n" >>"$keys"
  done <"$list"

  rs_count="$(wc -l <"$list" | tr -d ' ')"

  # Parse the pin: exactly two fields, a numeric value, unique keys.
  if ! awk '
      { sub(/\r$/, "") }
      NF == 0 || /^#/ { next }
      {
        if (NF != 2) { printf "mobile_unsafe_confinement_gate: FAIL: UNSAFE_PIN line %d must have exactly 2 fields\n", NR > "/dev/stderr"; bad = 1; next }
        if ($2 !~ /^[0-9]+$/) { printf "mobile_unsafe_confinement_gate: FAIL: UNSAFE_PIN line %d value is not a non-negative integer\n", NR > "/dev/stderr"; bad = 1; next }
        if ($1 in seen) { printf "mobile_unsafe_confinement_gate: FAIL: UNSAFE_PIN duplicate key %s\n", $1 > "/dev/stderr"; bad = 1; next }
        seen[$1] = 1
        print $1, $2
      }
      END { exit bad ? 1 : 0 }' "$pin_file" >"$pins"; then
    rc=1
  fi

  # Every pinned key must name a file that still exists.
  while read -r key val; do
    path="$key"
    case "$key" in
      from_raw_fd:*) path="${key#from_raw_fd:}" ;;
      allow:*) path="${key#allow:}" ;;
    esac
    if [ ! -f "$dir/$path" ]; then
      fail "$dir: UNSAFE_PIN names a missing file: $key"
      rc=1
    fi
  done <"$pins"

  # Exact comparison of every computed key against its pin (missing pin = 0).
  while read -r key val; do
    pinned="$(awk -v k="$key" '$1 == k { print $2; exit }' "$pins")"
    [ -n "$pinned" ] || pinned=0
    total=$((total + val))
    if [ "$val" -gt "$pinned" ]; then
      fail "unpinned unsafe in $dir: $key counted $val, pinned $pinned"
      rc=1
    elif [ "$val" -lt "$pinned" ]; then
      fail "stale pin in $dir: $key counted $val, pinned $pinned (review, then update UNSAFE_PIN)"
      rc=1
    fi
  done <"$keys"

  if [ "$rc" -eq 0 ]; then
    printf 'mobile_unsafe_confinement_gate: OK: %s: %s counted token(s) across %s .rs file(s), all keys match UNSAFE_PIN\n' \
      "$dir" "$total" "$rs_count"
  fi
  return "$rc"
}

# print_counts DIR: prints the "<key> <value>" body for UNSAFE_PIN, using the gate logic.
print_counts() {
  local dir="$1" flat="$WORK/pc-flat" rel list="$WORK/pc-list"
  (cd "$dir" && find . -type f -name '*.rs' | sed 's#^\./##' | LC_ALL=C sort) >"$list"
  while IFS= read -r rel; do
    flatten "$dir/$rel" "$flat"
    local unsafe_w extern_n raw_n allow_n
    unsafe_w="$(count_occ "$dir/$rel" -w 'unsafe')"
    extern_n="$(count_occ "$flat" -E 'extern("[^"]*")?\{')"
    raw_n="$(count_occ "$dir/$rel" -E '(from_raw_fd|borrow_raw|from_raw_handle|from_raw_socket)')"
    allow_n="$(count_occ "$flat" -E '(allow|expect)\([^)]*unsafe_code')"
    printf '%s %s\n' "$rel" $((unsafe_w + extern_n))
    printf 'from_raw_fd:%s %s\n' "$rel" "$raw_n"
    printf 'allow:%s %s\n' "$rel" "$allow_n"
  done <"$list"
}

# make_copy NAME: fresh copy of the ffi crate under WORK, prints its path.
make_copy() {
  local d="$WORK/st-$1"
  rm -rf "$d"
  mkdir -p "$d"
  cp "$FFI_ROOT/Cargo.toml" "$FFI_ROOT/UNSAFE_PIN" "$d/"
  cp -R "$FFI_ROOT/src" "$d/src"
  printf '%s\n' "$d"
}

# expect_fail NAME DIR: the gate must reject DIR.
SELF_TEST_FAILED=0
expect_fail() {
  if gate_crate "$2" >/dev/null 2>&1; then
    printf 'mobile_unsafe_confinement_gate: self-test FAIL: %s was NOT caught\n' "$1" >&2
    SELF_TEST_FAILED=1
  else
    printf 'mobile_unsafe_confinement_gate: self-test: %s caught\n' "$1"
  fi
}

self_test() {
  local d
  SELF_TEST_FAILED=0

  d="$(make_copy clean)"
  if ! gate_crate "$d" >/dev/null 2>&1; then
    printf 'mobile_unsafe_confinement_gate: self-test FAIL: clean copy did not pass (positive control)\n' >&2
    SELF_TEST_FAILED=1
  fi

  d="$(make_copy extra-from-raw-fd)"
  printf '\nfn injected_adoption() -> std::os::fd::OwnedFd {\n    // SAFETY: injected test case.\n    unsafe { std::os::fd::OwnedFd::from_raw_fd(9) }\n}\n' >>"$d/src/panic.rs"
  expect_fail "extra from_raw_fd" "$d"

  d="$(make_copy unsafe-fn)"
  printf '\npub unsafe fn injected_unsafe_fn() {}\n' >>"$d/src/panic.rs"
  expect_fail "unpinned unsafe fn" "$d"

  d="$(make_copy unsafe-block)"
  printf '\nfn injected_block() {\n    // SAFETY: injected test case.\n    unsafe {}\n}\n' >>"$d/src/panic.rs"
  expect_fail "unpinned unsafe block" "$d"

  d="$(make_copy unsafe-attribute)"
  printf '\n// SAFETY: injected test case.\n#[unsafe(no_mangle)]\npub extern "C" fn injected_export() {}\n' >>"$d/src/lib.rs"
  expect_fail "unpinned unsafe attribute" "$d"

  d="$(make_copy bare-no-mangle)"
  printf '\n#[no_mangle]\npub extern "C" fn injected_bare() {}\n' >>"$d/src/panic.rs"
  expect_fail "bare #[no_mangle]" "$d"

  d="$(make_copy include)"
  printf 'include!("adopt.inc");\n' >>"$d/src/lib.rs"
  printf 'fn included() {}\n' >"$d/src/adopt.inc"
  expect_fail "include!(...)" "$d"

  d="$(make_copy include-whitespace)"
  printf 'include ! ( "../../evil.rs" ) ;\n' >>"$d/src/lib.rs"
  expect_fail "include ! ( ... ) with whitespace variants (N-2)" "$d"

  d="$(make_copy include-alias)"
  printf 'use std::include as inc;\ninc!("../../../evil.rs");\n' >>"$d/src/lib.rs"
  expect_fail "include alias: use std::include as inc (B01)" "$d"

  d="$(make_copy include-std-path)"
  printf 'fn f() { std::include!("../../../evil.rs"); }\n' >>"$d/src/lib.rs"
  expect_fail "std::include! path form (B01)" "$d"

  d="$(make_copy macro-rules)"
  printf 'macro_rules! m { () => {} }\n' >>"$d/src/lib.rs"
  expect_fail "macro_rules! wrapper" "$d"

  d="$(make_copy build-rs)"
  printf 'fn main() { println!("cargo:rustc-link-lib=evil"); }\n' >"$d/build.rs"
  expect_fail "build.rs (B10)" "$d"

  # insert_after DIR FILE PATTERN TEXT: appends TEXT as a new line after the line equal to PATTERN.
  insert_after() {
    local f="$1/$2" tmp="$WORK/insert.tmp"
    PAT="$3" INS="$4" awk '{ print } $0 == ENVIRON["PAT"] { print ENVIRON["INS"] }' "$f" >"$tmp" && mv "$tmp" "$f"
  }

  d="$(make_copy quoted-build-key)"
  printf 'fn main() { println!("cargo:warning=QUOTED-BUILD"); }\n' >"$d/b.rs"
  insert_after "$d" Cargo.toml '[package]' '"build" = "b.rs"'
  expect_fail 'quoted "build" key under [package] (B-R4-1)' "$d"

  d="$(make_copy single-quoted-build-key)"
  printf 'fn main() {}\n' >"$d/b.rs"
  insert_after "$d" Cargo.toml '[package]' "'build' = 'b.rs'"
  expect_fail "single-quoted 'build' key (B-R4-1)" "$d"

  d="$(make_copy quoted-links-key)"
  insert_after "$d" Cargo.toml '[package]' '"links" = "evil"'
  expect_fail 'quoted "links" key (B-R4-1)' "$d"

  d="$(make_copy quoted-lib-path)"
  insert_after "$d" Cargo.toml '[lib]' '"path" = "../../../../outside.rs"'
  expect_fail 'quoted "path" key in [lib] (B-R4-1)' "$d"

  d="$(make_copy quoted-dep-path)"
  insert_after "$d" Cargo.toml '[dependencies]' 'evil = { "path" = "../../../../outside" }'
  expect_fail 'quoted "path" inside an inline-table dependency (B-R4-1)' "$d"

  d="$(make_copy escaped-build-key)"
  insert_after "$d" Cargo.toml '[package]' '"\u0062uild" = "b.rs"'
  expect_fail 'escape-spelled key "\u0062uild" (B-R4-1)' "$d"

  d="$(make_copy build-rs-mixed-case)"
  printf 'fn main() {}\n' >"$d/Build.rs"
  expect_fail "Build.rs (mixed case root file, B-R4-2)" "$d"

  d="$(make_copy build-rs-upper-case)"
  printf 'fn main() {}\n' >"$d/BUILD.RS"
  expect_fail "BUILD.RS (upper-case root file, B-R4-2)" "$d"

  d="$(make_copy autobins-key)"
  printf '\n[package]\nautobins = true\n' >>"$d/Cargo.toml"
  expect_fail "autobins key (B10)" "$d"

  d="$(make_copy links-key)"
  printf '\n[package]\nlinks = "evil"\n' >>"$d/Cargo.toml"
  expect_fail "links key (B10)" "$d"

  d="$(make_copy array-table)"
  printf '\n[[bin]]\nname = "evil"\n' >>"$d/Cargo.toml"
  expect_fail "array table [[bin]]" "$d"

  d="$(make_copy path-attr)"
  printf '#[path = "elsewhere.rs"]\nmod hidden;\n' >>"$d/src/lib.rs"
  expect_fail "#[path]" "$d"

  d="$(make_copy path-attr-whitespace)"
  printf '# [ path = "../evil.rs" ]\nmod hidden;\n' >>"$d/src/lib.rs"
  expect_fail "# [ path = ... ] with whitespace variants (N-2)" "$d"

  d="$(make_copy path-in-cfg-attr)"
  printf '#[cfg_attr(all(), path = "../evil.rs")]\nmod hidden;\n' >>"$d/src/lib.rs"
  expect_fail "path= inside cfg_attr" "$d"

  d="$(make_copy symlink)"
  printf 'pub unsafe fn hidden() {}\n' >"$WORK/outside.rs"
  ln -s "$WORK/outside.rs" "$d/src/evil.rs"
  printf 'mod evil;\n' >>"$d/src/lib.rs"
  expect_fail "symlink src/evil.rs -> outside file (N-3)" "$d"

  d="$(make_copy crate-allow)"
  { printf '#![allow(unsafe_code)]\n'; cat "$d/src/lib.rs"; } >"$WORK/lib.tmp" && mv "$WORK/lib.tmp" "$d/src/lib.rs"
  expect_fail "crate-level #![allow(unsafe_code)]" "$d"

  d="$(make_copy crate-allow-multiline)"
  { printf '#![allow(\n    unsafe_code\n)]\n'; cat "$d/src/lib.rs"; } >"$WORK/lib.tmp" && mv "$WORK/lib.tmp" "$d/src/lib.rs"
  expect_fail "multi-line #![allow(\\n unsafe_code\\n)] (N-4)" "$d"

  d="$(make_copy item-allow)"
  printf '\n#[allow(unsafe_code)]\nfn injected_allow() {}\n' >>"$d/src/panic.rs"
  expect_fail "unpinned item-level allow(unsafe_code)" "$d"

  d="$(make_copy block-comment-hide)"
  printf '\n/* open\n// */ fn injected_hidden() { let _x = unsafe { std::os::fd::OwnedFd::from_raw_fd(9) }; }\n' >>"$d/src/panic.rs"
  expect_fail "block-comment hiding unsafe/from_raw_fd (N-1)" "$d"

  d="$(make_copy global-asm)"
  printf '\nglobal_asm!("nop");\n' >>"$d/src/lib.rs"
  expect_fail "global_asm!" "$d"

  d="$(make_copy link-attr)"
  printf '\n#[link(name = "evil")]\nextern "C" {}\n' >>"$d/src/lib.rs"
  expect_fail "#[link] attribute" "$d"

  d="$(make_copy cargo-path)"
  printf '\n[lib]\npath = "../evil.rs"\n' >>"$d/Cargo.toml"
  expect_fail "Cargo.toml path= key" "$d"

  d="$(make_copy non-rs-file)"
  printf 'unsafe fn hidden() {}\n' >"$d/src/notes.txt"
  expect_fail "non-.rs source file" "$d"

  d="$(make_copy new-unsafe-file)"
  printf 'pub unsafe fn hidden() {}\n' >"$d/src/extra.rs"
  expect_fail "unsafe in a new unpinned .rs file" "$d"

  d="$(make_copy count-decrease)"
  # The code loses one unsafe token but the pin still says it has one more: a stale pin.
  awk '$1 == "src/c_abi.rs" { $2 = $2 + 1 } { print }' "$d/UNSAFE_PIN" >"$WORK/pin.tmp" && mv "$WORK/pin.tmp" "$d/UNSAFE_PIN"
  expect_fail "count decrease (stale pin)" "$d"

  d="$(make_copy non-numeric-pin)"
  awk '$1 == "src/lib.rs" { $2 = "eight" } { print }' "$d/UNSAFE_PIN" >"$WORK/pin.tmp" && mv "$WORK/pin.tmp" "$d/UNSAFE_PIN"
  expect_fail "non-numeric pin value" "$d"

  d="$(make_copy duplicate-pin)"
  printf 'src/panic.rs 0\n' >>"$d/UNSAFE_PIN"
  expect_fail "duplicate pin entry" "$d"

  d="$(make_copy three-field-pin)"
  printf 'src/panic.rs 0 0\n' >>"$d/UNSAFE_PIN"
  expect_fail "pin line with three fields" "$d"

  d="$(make_copy table-aware-deny)"
  sed 's/^\[lints\.rust\]$/[lints.other]/' "$d/Cargo.toml" >"$WORK/cargo.tmp" && mv "$WORK/cargo.tmp" "$d/Cargo.toml"
  expect_fail "unsafe_code deny outside [lints.rust]" "$d"

  if [ "$SELF_TEST_FAILED" -ne 0 ]; then
    return 1
  fi
  printf 'mobile_unsafe_confinement_gate: self-test OK: clean copy passes; every injected case is caught\n'
}

# mobile_crate_dirs: prints the directory of every workspace member whose name starts with
# rustynet-mobile, taken from cargo metadata. A crates/rustynet-mobile* directory that is not
# a workspace member is refused, so a crate cannot dodge the gate by staying outside the
# workspace. Fails closed when there are no mobile members.
mobile_crate_dirs() {
  local meta="$WORK/metadata.json" listing="$WORK/members.txt" rc=0 name path dir
  if ! (cd "$REPO_ROOT" && cargo metadata --no-deps --format-version 1 --locked >"$meta" 2>"$WORK/meta.err"); then
    fail "cargo metadata failed: $(head -3 "$WORK/meta.err")"
    return 1
  fi
  if ! python3 - "$meta" >"$listing" <<'PY'
import json, sys
meta = json.load(open(sys.argv[1]))
members = set(meta["workspace_members"])
for pkg in meta["packages"]:
    if pkg["id"] in members and pkg["name"].startswith("rustynet-mobile"):
        print(pkg["name"] + " " + pkg["manifest_path"])
PY
  then
    fail "could not parse cargo metadata (python3 is required)"
    return 1
  fi
  if [ ! -s "$listing" ]; then
    fail "no rustynet-mobile* workspace member found: the mobile gate would check nothing"
    return 1
  fi
  for dir in "$REPO_ROOT"/crates/rustynet-mobile*; do
    [ -d "$dir" ] || continue
    name="$(basename "$dir")"
    if ! grep -q -x "$name .*" "$listing"; then
      fail "$dir is not a workspace member named $name (refused: a mobile crate must be in the workspace)"
      rc=1
    fi
  done
  while read -r name path; do
    dir="$(dirname "$path")"
    printf '%s\n' "$dir"
  done <"$listing"
  return "$rc"
}

run_all() {
  local rc=0 dir
  if [ -n "${MOBILE_FFI_ROOT:-}" ]; then
    gate_crate "$MOBILE_FFI_ROOT" || rc=1
  else
    local dirs="$WORK/mobile-dirs"
    if ! mobile_crate_dirs >"$dirs"; then
      rc=1
    fi
    while IFS= read -r dir; do
      [ -n "$dir" ] || continue
      gate_crate "$dir" || rc=1
    done <"$dirs"
  fi
  self_test || rc=1
  return "$rc"
}

case "${1:-}" in
  "")
    run_all
    ;;
  --self-test)
    self_test
    ;;
  --print-counts)
    print_counts "${MOBILE_FFI_ROOT:-$FFI_ROOT}"
    ;;
  *)
    printf 'usage: %s [--self-test|--print-counts]\n' "$0" >&2
    exit 2
    ;;
esac
