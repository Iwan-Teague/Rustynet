#!/usr/bin/env bash
# bootstrap_macos_hardening_gates.sh — AQ-11 / R-SEC-10 static hardening gates
# for the Rustynet bootstrap shell scripts.
#
# Gates, in order (all findings listed; non-zero exit on any failure):
#   1. bash -n              — every target parses.
#   2. shellcheck -S error  — static analysis, error severity.
#   3. Deny-pattern scan    — bootstrap scripts must NEVER contain:
#       (a)-(d) below on EVERY target; (e)-(i) on the macOS lane only.
#   4. Verify-before-extract ordering — in every rn_bootstrap_macos.sh the
#      `verify_source_archive` invocation must appear textually BEFORE the
#      `tar -xzf … VERIFY_STAGED_ARCHIVE` extraction, and the private stage,
#      the runtime verify of that stage, and the tar must appear in that
#      order (AQ-11 F1/N-A: nothing from the received archive is extracted
#      or executed before verification, and only the verified private copy
#      is extracted).
#      This is an ordering gate over the real tree, not a semantic proof —
#      the semantic gate is the wrapper's own runtime check plus its
#      witnesses.
#       a) NOPASSWD                          (self-granted passwordless sudo,
#                                            CWE-250/CWE-279)
#       b) sudoers                           (any write/mention of the system
#                                            sudo policy path — the bootstrap
#                                            never edits sudo policy, not
#                                            even temporarily)
#       c) (curl|wget) … | sh|bash           (download piped straight into a
#                                            shell interpreter)
#       d) $(curl …)                         (download output captured by
#                                            command substitution — the
#                                            `bash -c "$(curl …)"` installer
#                                            idiom, incl. when the capture
#                                            spans lines; a downloaded body
#                                            must go to a named file and be
#                                            verified, never enter the
#                                            command stream)
#       e) $(wget …)                         — same as (d), wget variant
#       f) | /bin/bash, | /usr/bin/env bash  — download piped into a shell by
#                                            ABSOLUTE PATH (and via env);
#                                            (c) only catches the bare name
#       g) curl|wget|fetch … -o/-O/--output in ANY spacing form — glued
#          (`-o/path`), separated (`-o path`) and equals (`--output=path`);
#          download-to-file, then execute (the `curl -o f && sh f` idiom).
#          A script that legitimately needs a download would still trip
#          this pattern, which is why (e)-(i) are macOS-lane-scoped:
#          the macOS bootstrap must never download anything (brew is a
#          prerequisite), while the LINUX bootstrap legitimately fetches
#          rustup-init with -o + a sha256 check and stays out of scope.
#       h) curl|wget|fetch … > FILE — the REDIRECT form of download-to-file
#          (`curl … > f && sh f`, also glued `…>f`); benign discards
#          (>/dev/null, 2>&1 etc.) are stripped per occurrence and any
#          redirect left on the line is a finding.
#       i) ANY token of a listed transfer tool or inline interpreter
#          (curl, wget, fetch, nscurl, ftp, tftp, sftp, scp, rsync, nc,
#          ncat, socat, osascript, python*, perl, ruby, urlretrieve,
#          urlopen, and git's network subcommands) outside a whole-line
#          comment, unless its line is a NAMED exemption in Gate 3b (exact
#          content). This is a TOKEN rule, not a proof that nothing is
#          downloaded: a name assembled at runtime (c''url, ${x}url,
#          printf/eval, a here-doc fed to bash) or a tool missing from the
#          list passes it. Those stay review discipline; the runtime
#          verify-before-extract and signed-manifest checks are the trust
#          boundary this gate only helps to hold.
#
#   Scope limit of (c)-(h): the deny covers download-to-SHELL-interpreter
#   idioms ((ba|z|da|k)sh by name, absolute path, or via env) and
#   download-to-FILE forms. Piping a download into a NON-shell interpreter
#   (`curl … | python3 -`) is OUT of scope here — a general interpreter
#   deny is a different (and noisier) gate.
#
# Scope (no-arg default):
#   - bash -n + deny scan: scripts/bootstrap/**/*.sh AND
#     scripts/e2e/rn_bootstrap_macos.sh
#   - shellcheck scope: scripts/bootstrap/macos/*.sh AND
#     scripts/e2e/rn_bootstrap_macos.sh (the macOS hardening lane; the linux
#     bootstrap keeps its own gates)
#
# vm-lab exemption: NONE. scripts/e2e/rn_bootstrap_macos.sh is vm-lab feature
# tooling (the Phase-23 cross-OS lab orchestrator wrapper that scp's and
# invokes Bootstrap-RustyNetMacos.sh, mirroring
# crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install.rs), and
# it is scanned under the IDENTICAL rules: it runs the bootstrap via plain
# `sudo -n bash <script>` and requires no NOPASSWD grant and no
# download-to-shell pattern. If a future vm-lab requirement ever conflicts
# with a rule above, add an explicitly NAMED exemption in this file with its
# justification — never weaken the rule text itself.
#
# The one named vm-lab exemption lives in Rust, outside these scripts:
# crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install.rs
# (PRIME_SUDOERS_REMOTE_COMMAND) primes a LAB guest with a temporary sudo
# grant over SSH when `sudo -n true` fails there. It compiles only with the
# `vm-lab` feature (`#[cfg(feature = "vm-lab")] mod vm_lab;` in the CLI's
# main.rs and lib.rs), so it is never part of a shipped binary, and it is
# the vm-lab variant R-SEC-10 accepts by name. The bootstrap scripts
# themselves carry no such grant.
#
# Optional args: an explicit file list (used by witnesses to scan a copy of a
# script outside the repo, e.g. a pre-fix snapshot; shellcheck scope then
# applies to whatever listed files fall inside the default macOS scope).
#
# Shellcheck availability: if the shellcheck binary is missing, this gate
# installs it via Homebrew (`brew install shellcheck`) and says so; with no
# Homebrew available it fails with manual-install instructions instead.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

status=0

targets=()
if [[ $# -gt 0 ]]; then
  targets=("$@")
else
  while IFS= read -r f; do
    targets+=("${f}")
  done < <(find scripts/bootstrap -type f -name '*.sh' 2>/dev/null | sort)
  # Gate 4 runs only on this wrapper, so in default mode its absence (a
  # rename, a move) is a failure, not a silent skip (AQ-11 confirming
  # review G-4c).
  if [[ ! -f scripts/e2e/rn_bootstrap_macos.sh ]]; then
    echo "FAIL: scripts/e2e/rn_bootstrap_macos.sh not found; the verify-before-extract gate (Gate 4) would have nothing to check" >&2
    exit 1
  fi
  targets+=("scripts/e2e/rn_bootstrap_macos.sh")
fi

if [[ ${#targets[@]} -eq 0 ]]; then
  echo "FAIL: no bootstrap script targets found under ${REPO_ROOT}/scripts/bootstrap" >&2
  exit 1
fi

# Shellcheck scope + macOS-lane deny scope: the macOS bootstrap lane of the
# target set. Matching is by PATH FRAGMENT or BASENAME, not a repo-relative
# prefix, so file-list mode keeps its lane coverage when witnesses scan
# absolute paths outside this checkout (AQ-11 N-D: the v3 repo-relative-only
# matcher left shell_targets empty for every file-list invocation — a cryptic
# unbound-variable crash on macOS stock bash 3.2, and a SILENT skip of Gate
# 3b on bash >= 5, where the empty-array expansion is legal).
shell_targets=()
lane_skipped=()
for f in "${targets[@]}"; do
  case "${f}" in
    */macos/*.sh|*/rn_bootstrap_macos.sh|rn_bootstrap_macos.sh)
      shell_targets+=("${f}") ;;
    *)
      lane_skipped+=("${f}") ;;
  esac
done

echo "== bootstrap_macos_hardening_gates =="
printf 'bash -n + deny-scan targets: %s\n' "${targets[*]}"
printf 'shellcheck scope:            %s\n' "${shell_targets[*]:-(none — file-list mode outside default macOS scope)}"
if [[ ${#lane_skipped[@]} -gt 0 ]]; then
  for f in "${lane_skipped[@]}"; do
    echo "gate 3b skipped for ${f} (outside the macOS lane: not */macos/*.sh or rn_bootstrap_macos.sh; lane-only deny patterns not applied)"
  done
fi

# ── Gate 1: bash -n ───────────────────────────────────────────────────────────
for f in "${targets[@]}"; do
  if [[ ! -f "${f}" ]]; then
    echo "FAIL bash -n: missing target: ${f}" >&2
    status=1
    continue
  fi
  if ! bash -n "${f}" 2>&1; then
    echo "FAIL bash -n: ${f}" >&2
    status=1
  fi
done

# ── Gate 2: shellcheck -S error ───────────────────────────────────────────────
if [[ ${#shell_targets[@]} -gt 0 ]]; then
  if ! command -v shellcheck >/dev/null 2>&1; then
    if command -v brew >/dev/null 2>&1; then
      echo "shellcheck not found; installing it via Homebrew (brew install shellcheck)..."
      brew install shellcheck
    else
      echo "FAIL: shellcheck is not installed and no Homebrew is available to install it." >&2
      echo "Install shellcheck manually (https://github.com/koalaman/shellcheck#installing) and re-run this gate." >&2
      exit 1
    fi
  fi
  for f in "${shell_targets[@]}"; do
    if ! shellcheck -S error "${f}"; then
      echo "FAIL shellcheck -S error: ${f}" >&2
      status=1
    fi
  done
fi

# ── Gate 3: deny patterns ─────────────────────────────────────────────────────
# NOTE: patterns (a)/(b) are deliberately literal tokens. Bootstrap scripts
# must avoid those tokens even in comments/explanatory text, so a plain scan
# cannot be defeated by hiding a live pattern behind prose. See the AQ-11
# header comment in Bootstrap-RustyNetMacos.sh for the token-free phrasing.
deny_patterns=(
  'NOPASSWD'
  'sudoers'
  '(curl|wget)[^|]*\|[[:space:]]*(ba)?sh([[:space:]]|$)'
  '\$\([[:space:]]*curl'
)
for f in "${targets[@]}"; do
  [[ -f "${f}" ]] || continue
  for pattern in "${deny_patterns[@]}"; do
    if matches="$(grep -nE -- "${pattern}" "${f}" 2>/dev/null)"; then
      echo "FAIL deny-pattern [${pattern}] in ${f}:" >&2
      printf '%s\n' "${matches}" >&2
      status=1
    fi
  done
done

# ── Gate 3b: macOS-lane deny patterns (AQ-11 F2 evasions) ─────────────────────
# The macOS bootstrap lane downloads NOTHING (brew/rustup are prerequisites;
# the payload arrives over the orchestrator channel), so ANY download idiom
# there is a finding. The evasions that beat pattern (c)/(d):
#   e) $(wget …)      — (d) only covered curl
#   f) | /bin/bash, | /usr/bin/env bash — (c) only matched the bare shell name
#   g) … -o/-O/--output in ANY spacing form — download-to-file (glued
#      `-o/path`, separated `-o path`, equals `--output=path`), then execute
#      (`curl -o f && sh f`); AQ-11 N-C: the v3 form required a space AFTER
#      the flag, so the glued and equals forms slipped through
#   h) … > FILE — the redirect form of download-to-file (`curl … > f &&
#      sh f`), also N-C; benign discards are filtered by an explicit
#      allow-list and any REMAINING match is a finding (decided on the
#      match list, the same way Gate 3's find-based checks decide)
# Scoped to shell_targets (macOS lane) so the Linux bootstrap's legitimate
# `curl -o rustup-init + sha256` keeps passing.
macos_deny_patterns=(
  '\$\([[:space:]]*wget'
  '(curl|wget)[^|]*\|[[:space:]]*/([[:alnum:]_.-]+/)*(env[[:space:]]+)?(ba|z|da|k)?sh([[:space:]]|$)'
  # (g) AQ-11 NE-4: the flag may come FIRST (`curl -o f "$u"`), so the text
  # between the tool and the flag is optional; `-o` must be followed by a
  # space or a path character (glued `-o/path`).
  '(curl|wget|fetch)[[:space:]]([^|]*[[:space:]])?(-o[[:space:]/]|-O[[:space:]]|--output(-document)?[=[:space:]])'
)
# (h): redirect-to-file, decided per OCCURRENCE (AQ-11 NE-2/NE-3). Every
# benign discard (`>/dev/null`, `2>/dev/null`, `&>/dev/null`, `>>/dev/null`,
# `2>&1`, `>&2`, ...) is stripped from the line first, then the line is
# re-matched: any redirect LEFT is a finding. The v4 gate dropped a whole
# line when it contained any discard, so `curl … > /tmp/i.sh 2>/dev/null`
# laundered its real redirect (NE-2), and it required a space before `>`, so
# the glued `curl …>/tmp/i.sh` never matched (NE-3).
redirect_pattern='(curl|wget|fetch)[[:space:]][^|]*>'
redirect_discards='s/[0-9&]?>>?[[:space:]]*\/dev\/(null|stdout|stderr)//g; s/[0-9]?>&[0-9]//g'
# (i): transfer-tool and inline-interpreter TOKENS. Patterns (e)-(h)
# enumerate download idioms, and an enumeration always has a next form:
# combined short flags (`curl -fsSLo f`), wget's default save-to-file
# (`wget "$u"`), `| tee f`, indirection (`dl=curl; $dl …`), a flag on a
# continuation line. The macOS lane has no raw transfer at all (packages
# arrive through brew and cargo, the payload over the orchestrator
# channel), so any token of a listed tool outside a whole-line comment is a
# finding unless its line is one of the NAMED exemptions below, matched by
# exact content (leading whitespace ignored) including the continuation
# line where the command spans two. The list covers the stock macOS
# transfer tools and interpreters that can fetch in one line (AQ-11
# confirming review G-1: nscurl, python3 urlretrieve, git clone, scp,
# osascript and ftp all passed a curl/wget/fetch-only rule). It is still a
# token rule: names assembled at runtime pass it (review G-2), which is
# review discipline, not something a line gate can decide. Adding an
# exemption means adding it here with its reason — never loosening the
# pattern.
download_tool_pattern='(^|[^[:alnum:]_.-])(curl|wget|fetch|nscurl|ftp|tftp|sftp|scp|rsync|nc|ncat|socat|osascript|python[0-9.]*|perl|ruby|urlretrieve|urlopen)([^[:alnum:]_.-]|$)|(^|[^[:alnum:]_.-])git([[:space:]]+-[^[:space:]]+)*[[:space:]]+(clone|fetch|pull|submodule|ls-remote|archive)([[:space:]]|$)'
# The crates.io probe's two lines, pinned verbatim (single-quoted on
# purpose: compared as text, never expanded).
# shellcheck disable=SC1003
exempt_probe_line='if curl --ipv4 --fail --silent --head --connect-timeout 10 --max-time 15 \'
# shellcheck disable=SC2016
exempt_probe_next='"${endpoint}" >/dev/null 2>&1; then'
exempt_line=(
  # Bootstrap-RustyNetMacos.sh verify_prereqs: presence check of the tool
  # name only; nothing is invoked.
  'for cmd in curl git make clang; do'
  # Bootstrap-RustyNetMacos.sh crates.io reachability probe: HEAD request,
  # response discarded; both lines of the command are pinned.
  "${exempt_probe_line}"
)
exempt_next=(
  ''
  "${exempt_probe_next}"
)
trim_leading() {
  local s="$1"
  printf '%s' "${s#"${s%%[![:space:]]*}"}"
}
if [[ ${#shell_targets[@]} -gt 0 ]]; then
  for f in "${shell_targets[@]}"; do
    [[ -f "${f}" ]] || continue
    for pattern in "${macos_deny_patterns[@]}"; do
      if matches="$(grep -nE -- "${pattern}" "${f}" 2>/dev/null)"; then
        echo "FAIL macos-lane deny-pattern [${pattern}] in ${f}:" >&2
        printf '%s\n' "${matches}" >&2
        status=1
      fi
    done
    matches="$(grep -nE -- "${redirect_pattern}" "${f}" 2>/dev/null || true)"
    remaining=""
    while IFS= read -r hit; do
      [[ -n "${hit}" ]] || continue
      stripped="$(printf '%s\n' "${hit#*:}" | sed -E "${redirect_discards}")"
      if printf '%s\n' "${stripped}" | grep -qE -- "${redirect_pattern}"; then
        remaining="${remaining}${hit}"$'\n'
      fi
    done <<< "${matches}"
    if [[ -n "${remaining}" ]]; then
      echo "FAIL macos-lane deny-pattern [redirect-to-file] in ${f}:" >&2
      printf '%s' "${remaining}" >&2
      status=1
    fi
    matches="$(grep -nE -- "${download_tool_pattern}" "${f}" 2>/dev/null || true)"
    remaining=""
    while IFS= read -r hit; do
      [[ -n "${hit}" ]] || continue
      lineno="${hit%%:*}"
      body="$(trim_leading "${hit#*:}")"
      case "${body}" in
        '#'*) continue ;;
      esac
      exempt=0
      i=0
      while [[ ${i} -lt ${#exempt_line[@]} ]]; do
        if [[ "${body}" == "${exempt_line[${i}]}" ]]; then
          if [[ -z "${exempt_next[${i}]}" ]]; then
            exempt=1
          else
            next="$(trim_leading "$(sed -n "$((lineno + 1))p" "${f}")")"
            [[ "${next}" == "${exempt_next[${i}]}" ]] && exempt=1
          fi
        fi
        i=$((i + 1))
      done
      [[ ${exempt} -eq 1 ]] || remaining="${remaining}${hit}"$'\n'
    done <<< "${matches}"
    if [[ -n "${remaining}" ]]; then
      echo "FAIL macos-lane deny-pattern [download-tool invocation outside the named exemptions] in ${f}:" >&2
      printf '%s' "${remaining}" >&2
      status=1
    fi
  done
fi

# ── Gate 4: verify-before-extract ordering (AQ-11 F1) ─────────────────────────
# In every rn_bootstrap_macos.sh target: the call to the wrapper's
# verify_source_archive must appear textually BEFORE the `tar -xzf` of the
# STAGED archive (AQ-11 F1), and inside the wrapper the order must be
# private staging copy (a root-owned 0700 `install -m 0600` stage, AQ-11
# N-A) < runtime `ops verify-release-manifest` < tar, so the verified object
# and the extracted object are the same private file and the shared
# received path is never consumed. The runtime verify must also read the
# stage (`--artifacts-dir "$RN_VERIFY_STAGE"`) and require the archive by
# name (`--require-artifact`). The N-B capability probe (BEHAVIOURAL since
# the AQ-11 N-B v2 fix: the real verify against
# `__rustynet_require_artifact_probe__`, a name no signed manifest lists) is
# not the runtime verify and is excluded by its probe-name token
# (AQ-11 NE-1). Fail-closed: a
# missing call, stage, verify or tar, a wrong ORDER, or a verify that does
# not read the stage is a failure.
for f in "${targets[@]}"; do
  [[ -f "${f}" ]] || continue
  case "$(basename "${f}")" in
    rn_bootstrap_macos.sh) ;;
    *) continue ;;
  esac
  # Whole-line comments are dropped before every Gate 4 grep, so commented
  # text cannot stand in for code (AQ-11 confirming review G-4a).
  code_lines="$(grep -nvE '^[[:space:]]*#' "${f}" || true)"
  # `|| true` inside the substitutions: a no-match grep must yield an empty
  # value (handled below with a named FAIL), not kill this gate silently via
  # `set -o pipefail` before the diagnostic is printed.
  call_line="$(printf '%s\n' "${code_lines}" | grep -E '^[0-9]+:[[:space:]]*verify_source_archive[[:space:]]*$' | head -1 | cut -d: -f1 || true)"
  tar_line="$(printf '%s\n' "${code_lines}" | grep -E 'tar[[:space:]]+-xzf.*VERIFY_STAGED_ARCHIVE' | head -1 | cut -d: -f1 || true)"
  # AQ-11 NE-1 / N-B v2: the wrapper also runs `ops verify-release-manifest`
  # as its N-B capability probe EARLIER in the file — behavioural since the
  # v2 fix: the real verify with `--require-artifact
  # "__rustynet_require_artifact_probe__"` (a name no signed manifest
  # lists). The ordering must be measured on the runtime verify, so the
  # probe line is excluded by its probe-name token. Never weakened: exactly
  # one NON-probe runtime verify is still required, and a decoy verify that
  # merely mentions the probe name cannot satisfy the count.
  verify_cmd_lines="$(printf '%s\n' "${code_lines}" | grep -E 'ops[[:space:]]+verify-release-manifest' | grep -v -- '__rustynet_require_artifact_probe__' || true)"
  stage_lines="$(printf '%s\n' "${code_lines}" | grep -E 'install[[:space:]]+-m[[:space:]]+0600' || true)"
  verify_cmd_line="$(printf '%s\n' "${verify_cmd_lines}" | head -1 | cut -d: -f1)"
  stage_line="$(printf '%s\n' "${stage_lines}" | head -1 | cut -d: -f1)"
  # Exactly one runtime verify and one staging copy: a decoy placed earlier
  # could otherwise satisfy the order and content checks on its own
  # (AQ-11 confirming review G-4b).
  verify_count="$(printf '%s' "${verify_cmd_lines}" | grep -c . || true)"
  stage_count="$(printf '%s' "${stage_lines}" | grep -c . || true)"
  if [[ "${verify_count}" -gt 1 || "${stage_count}" -gt 1 ]]; then
    echo "FAIL verify-before-extract [${f}]: expected exactly one runtime 'ops verify-release-manifest' and one 'install -m 0600' staging copy, found ${verify_count} and ${stage_count}" >&2
    status=1
    continue
  fi
  if [[ -z "${tar_line}" ]]; then
    echo "FAIL verify-before-extract [${f}]: no 'tar -xzf … VERIFY_STAGED_ARCHIVE' line found (the extraction must read the AQ-11 N-A private stage, not the shared received path)" >&2
    status=1
    continue
  fi
  if [[ -z "${call_line}" ]]; then
    echo "FAIL verify-before-extract [${f}]: no verify_source_archive invocation found before extraction (AQ-11 F1)" >&2
    status=1
    continue
  fi
  if [[ -z "${verify_cmd_line}" ]]; then
    echo "FAIL verify-before-extract [${f}]: no 'ops verify-release-manifest' invocation found (the archive must be verified against a signed manifest, AQ-11 F1/F3)" >&2
    status=1
    continue
  fi
  if [[ -z "${stage_line}" ]]; then
    echo "FAIL verify-before-extract [${f}]: no root-owned 0700 private staging copy ('install -m 0600') found (AQ-11 N-A: verify and consume a private copy, never the shared received path)" >&2
    status=1
    continue
  fi
  if [[ "${call_line}" -ge "${tar_line}" ]]; then
    echo "FAIL verify-before-extract [${f}]: verify_source_archive at line ${call_line} is NOT before the tar extraction at line ${tar_line} (AQ-11 F1)" >&2
    status=1
    continue
  fi
  # AQ-11 NE-1: the v4 assertion demanded verify BEFORE stage, the inverse
  # of the shipped order, and only passed because it measured the N-B
  # capability probe (then a `--help` grep, now behavioural). The required
  # order is stage < verify < tar.
  if [[ "${stage_line}" -ge "${verify_cmd_line}" ]]; then
    echo "FAIL verify-before-extract [${f}]: private staging copy at line ${stage_line} is NOT before 'ops verify-release-manifest' at line ${verify_cmd_line} (AQ-11 N-A: stage FIRST, then verify the staged copy)" >&2
    status=1
    continue
  fi
  if [[ "${verify_cmd_line}" -ge "${tar_line}" ]]; then
    echo "FAIL verify-before-extract [${f}]: 'ops verify-release-manifest' at line ${verify_cmd_line} is NOT before the tar extraction at line ${tar_line} (AQ-11 F1: verify before extract)" >&2
    status=1
    continue
  fi
  # Content, not only order: the runtime verify must read the private stage
  # and bind the archive by name. A regression that points --artifacts-dir
  # back at the shared received directory keeps every line order intact.
  verify_block="$(sed -n "${verify_cmd_line},$((verify_cmd_line + 6))p" "${f}" | grep -vE '^[[:space:]]*#' || true)"
  if ! printf '%s\n' "${verify_block}" | grep -qE -- '--artifacts-dir[[:space:]]+"?\$\{?RN_VERIFY_STAGE\}?"?([[:space:]]|$)'; then
    echo "FAIL verify-before-extract [${f}]: the runtime verify at line ${verify_cmd_line} does not pass --artifacts-dir \"\$RN_VERIFY_STAGE\" (AQ-11 N-A: verify the staged private copy, never the shared received path)" >&2
    status=1
    continue
  fi
  if ! printf '%s\n' "${verify_block}" | grep -qE -- '--require-artifact[[:space:]]'; then
    echo "FAIL verify-before-extract [${f}]: the runtime verify at line ${verify_cmd_line} does not pass --require-artifact (AQ-11 F3: the archive must be required by name)" >&2
    status=1
    continue
  fi
  echo "ok verify-before-extract [${f}]: verify call @${call_line} < tar @${tar_line}; stage @${stage_line} < manifest verify @${verify_cmd_line} (artifacts-dir = stage, archive required by name) < tar @${tar_line}"
done

if [[ ${status} -ne 0 ]]; then
  echo "== bootstrap_macos_hardening_gates: FAIL ==" >&2
  exit 1
fi
echo "== bootstrap_macos_hardening_gates: PASS =="
