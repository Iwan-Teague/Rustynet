#!/usr/bin/env bash
# windows_provisioner_download_integrity_gates.sh — RSA-0065 static gates
# for the Windows lab-image provisioner's download/execute path.
#
# RSA-0065 (SecurityAuditLedger_2026-06-18): the provisioner downloaded
# rustup-init.exe and vs_BuildTools.exe and executed them with no hash or
# signature verification (MITM/upstream-compromise RCE during image
# provisioning, CWE-494). The remediation makes
# scripts/bootstrap/windows/Provision-RustyNetWindowsLabImage.ps1 verify a
# pinned SHA-256 for EVERY download (plus a Valid Authenticode signature
# naming the required publisher for the floating vs_BuildTools.exe
# bootstrapper) BEFORE the file is executed, and delete the file on any
# failed check.
#
# This gate statically holds that shape in place. It is a grep/awk guard,
# not a semantic proof (the runtime check is Get-FileHash /
# Get-AuthenticodeSignature on the Windows guest); it asserts:
#
#   G1  The Invoke-WebDownload helper takes a MANDATORY -ExpectedSha256
#       validated as 64 hex chars (an omitted pin is then a parameter
#       binding error, not a silent skip) and supports an optional
#       Authenticode publisher requirement.
#   G2  The helper actually verifies (Get-FileHash, SHA256), actually
#       checks the signature (Get-AuthenticodeSignature, Valid status,
#       publisher subject match), enforces HTTPS-only, and DELETES the
#       file on download failure, hash mismatch, and signature failure.
#   G3  Every Invoke-WebDownload CALL carries -ExpectedSha256.
#   G4  The file contains exactly the three expected 64-hex pinned
#       digests (rustup-init x86_64 + aarch64, vs_BuildTools).
#   G5  The vs_BuildTools call requires Authenticode publisher
#       'Microsoft Corporation'.
#   G6  Download-before-execute ordering: each downloaded file
#       ($rustupInit, $vsBootstrapper) is downloaded and verified before
#       its Start-Process.  Anchored on the REAL call sites of a
#       comment-stripped, continuation-unfolded stream: the
#       Invoke-WebDownload call carrying $rustupInitUrl, the
#       Invoke-WebDownload call carrying the
#       'https://aka.ms/vs/17/release/vs_BuildTools.exe' URL literal,
#       and the Start-Process calls that execute $rustupInit /
#       $vsBootstrapper.  Lines whose first non-space char is '#' are
#       stripped first, so a COMMENT mentioning the URL or the call can
#       never satisfy the ordering (review finding 1 on b88: G6 matched
#       the comment above the real call and passed a provisioner whose
#       actual download ran AFTER Start-Process).
#   G7  Exactly one Invoke-WebRequest, inside the helper; no other
#       transfer primitive (Invoke-RestMethod, Start-BitsTransfer,
#       WebClient/DownloadFile, curl, wget); no plain http:// URL.
#
#   S   Self-test battery: a miniature replica of the PRE-FIX vulnerable
#       script (pin-less helper, direct Invoke-WebRequest, no publisher
#       check) must be REJECTED by the same checker this gate runs
#       against the real target, and each vulnerable shape (short
#       digest, missing publisher, bare Invoke-WebRequest, http:// URL)
#       must be flagged by a FULL checker run end-to-end, not merely by
#       the checker's own grep predicate.  T6 additionally applies the
#       review's mutation probe to the REAL target: the vs_BuildTools
#       download call moved AFTER its Start-Process in a temp copy must
#       fail the checker citing G6.  A gate that cannot fail is not a
#       gate.
#
#   P   Optional PowerShell syntax parse: when pwsh is on PATH the target
#       is parsed with the PowerShell language parser and any parse error
#       fails the gate; when pwsh is absent (e.g. the Debian CI container)
#       this check is skipped with a note and the textual gates above
#       still apply.
#
# Scope (default, no args): the one Windows provisioning script that
# downloads executables. Sibling bootstrappers are covered elsewhere: the
# Linux bootstrap verifies rustup-init against its upstream .sha256
# (rn_bootstrap.sh), and the macOS bootstrap must not download at all
# (bootstrap_macos_hardening_gates.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TARGET="${1:-${ROOT}/scripts/bootstrap/windows/Provision-RustyNetWindowsLabImage.ps1}"

failures=0

gate_fail() {
    printf 'FAIL %s\n' "$1"
    failures=$((failures + 1))
}

gate_pass() {
    printf 'PASS %s\n' "$1"
}

# Unfold PowerShell backtick line continuations so multi-line statements
# can be scanned as one logical line. awk (not sed) on purpose: the gate
# runs on both GNU and BSD userlands.
unfold_continuations() {
    awk '
        /`[ \t]*$/ {
            sub(/[ \t]*`[ \t]*$/, "")
            buf = buf $0
            next
        }
        {
            if (buf != "") {
                print buf $0
                buf = ""
            } else {
                print
            }
        }
    ' "$1"
}

# All structural checks over one .ps1 file. Emits PASS/FAIL lines and
# returns non-zero if any check failed (the global counter is only
# meaningful for the real target; replicas run in a subshell).
check_download_integrity() {
    local file="$1"
    local label="$2"
    local ok=1

    local helper
    helper="$(awk '/^function Invoke-WebDownload/{f=1} f{print} f && /^}/{exit}' "$file")"
    if [ -z "${helper}" ]; then
        gate_fail "${label} G1: Invoke-WebDownload helper not found"
        return 1
    fi

    if printf '%s\n' "${helper}" \
        | grep -qF 'Parameter(Mandatory = $true)][ValidatePattern('"'"'^[0-9a-fA-F]{64}$'"'"')][string]$ExpectedSha256'; then
        gate_pass "${label} G1: mandatory 64-hex -ExpectedSha256 parameter"
    else
        gate_fail "${label} G1: -ExpectedSha256 must be Mandatory + ValidatePattern('^[0-9a-fA-F]{64}$')"
        ok=0
    fi

    local g2_missing=0
    printf '%s\n' "${helper}" | grep -qF 'Get-FileHash' || g2_missing=1
    printf '%s\n' "${helper}" | grep -qF 'Algorithm SHA256' || g2_missing=1
    printf '%s\n' "${helper}" | grep -qF 'Get-AuthenticodeSignature' || g2_missing=1
    printf '%s\n' "${helper}" | grep -qF 'X509Certificates.X509SignatureStatus]::Valid' || g2_missing=1
    printf '%s\n' "${helper}" | grep -qF -- '-notlike "*$RequireAuthenticodeSubject*"' || g2_missing=1
    printf '%s\n' "${helper}" | grep -qF 'https://*' || g2_missing=1
    local remove_items=0
    remove_items="$(printf '%s\n' "${helper}" | grep -c 'Remove-Item' || true)"
    if [ "${remove_items}" -lt 3 ]; then
        g2_missing=1
    fi
    if [ "${g2_missing}" -eq 0 ]; then
        gate_pass "${label} G2: helper hashes (SHA256), checks Authenticode Valid + publisher, enforces HTTPS, deletes on all 3 failure paths"
    else
        gate_fail "${label} G2: helper must hash (Get-FileHash SHA256), require Authenticode Valid + publisher -notlike match, refuse non-HTTPS, and Remove-Item on download/hash/signature failure (found ${remove_items} Remove-Item, need >=3)"
        ok=0
    fi

    local unfolded
    # Strip PowerShell line comments (first non-space char '#') BEFORE
    # unfolding backtick continuations; every call-site anchor below runs
    # over this ONE stream so its line numbers share a coordinate space
    # and can only ever match real code, never prose (review finding 1).
    unfolded="$(grep -v '^[[:space:]]*#' "${file}" | unfold_continuations -)"

    local bad_calls=0
    bad_calls="$(printf '%s\n' "${unfolded}" \
        | grep 'Invoke-WebDownload -Uri' \
        | grep -cv 'ExpectedSha256' || true)"
    if [ "${bad_calls}" -eq 0 ]; then
        gate_pass "${label} G3: every Invoke-WebDownload call carries -ExpectedSha256"
    else
        gate_fail "${label} G3: ${bad_calls} Invoke-WebDownload call(s) without -ExpectedSha256"
        ok=0
    fi

    local pin_count=0
    # Count OCCURRENCES, not lines (review finding 3 on b88): grep -c
    # counts LINES, so a 4th pin appended collinear to an existing pin's
    # line passed all gates.  grep -o | wc -l counts every literal.
    pin_count="$(grep -oE "'[0-9a-f]{64}'" "${file}" | wc -l | tr -d '[:space:]')"
    if [ "${pin_count}" -eq 3 ]; then
        gate_pass "${label} G4: exactly 3 pinned 64-hex digests (rustup x86_64, rustup aarch64, vs_BuildTools)"
    else
        gate_fail "${label} G4: expected exactly 3 pinned 64-hex digest occurrences, found ${pin_count}"
        ok=0
    fi

    if printf '%s\n' "${unfolded}" \
        | grep 'vs_BuildTools.exe' \
        | grep -q "RequireAuthenticodeSubject 'Microsoft Corporation'"; then
        gate_pass "${label} G5: vs_BuildTools call requires Authenticode publisher 'Microsoft Corporation'"
    else
        gate_fail "${label} G5: vs_BuildTools download must carry -RequireAuthenticodeSubject 'Microsoft Corporation'"
        ok=0
    fi

    local order_ok=1
    local dl_line sp_line
    # Anchor each leg on the REAL call sites of the comment-stripped,
    # unfolded stream (dl and sp share one coordinate space).  The
    # vs_BuildTools dl anchor is the Invoke-WebDownload call carrying
    # the aka.ms URL literal -- NOT any line that merely mentions the
    # URL (review finding 1 on b88).
    dl_line="$(printf '%s\n' "${unfolded}" \
        | grep -nE 'Invoke-WebDownload -Uri \$rustupInitUrl' \
        | head -1 | cut -d: -f1)"
    sp_line="$(printf '%s\n' "${unfolded}" \
        | grep -nE 'Start-Process -FilePath \$rustupInit' \
        | head -1 | cut -d: -f1)"
    if [ -z "${dl_line}" ] || [ -z "${sp_line}" ] || [ "${dl_line}" -ge "${sp_line}" ]; then
        order_ok=0
    fi
    dl_line="$(printf '%s\n' "${unfolded}" \
        | grep -nE "Invoke-WebDownload -Uri 'https://aka\.ms/vs/17/release/vs_BuildTools\.exe'" \
        | head -1 | cut -d: -f1)"
    sp_line="$(printf '%s\n' "${unfolded}" \
        | grep -nE 'Start-Process -FilePath \$vsBootstrapper' \
        | head -1 | cut -d: -f1)"
    if [ -z "${dl_line}" ] || [ -z "${sp_line}" ] || [ "${dl_line}" -ge "${sp_line}" ]; then
        order_ok=0
    fi
    if [ "${order_ok}" -eq 1 ]; then
        gate_pass "${label} G6: both downloads verified before their Start-Process"
    else
        gate_fail "${label} G6: download/verify must precede Start-Process for rustupInit and vsBootstrapper"
        ok=0
    fi

    local iwr_count=0 deny_hits="" http_hits=""
    iwr_count="$(grep -c 'Invoke-WebRequest' "${file}" || true)"
    deny_hits="$(grep -nE '(^|[^[:alnum:]_.-])(Invoke-RestMethod|Start-BitsTransfer|DownloadFile|WebClient|wget|curl)([^[:alnum:]_.-]|$)' "${file}" || true)"
    http_hits="$(grep -n 'http://' "${file}" || true)"
    if [ "${iwr_count}" -eq 1 ] && [ -z "${deny_hits}" ] && [ -z "${http_hits}" ]; then
        gate_pass "${label} G7: single Invoke-WebRequest (in helper), no other transfer primitive, HTTPS-only"
    else
        gate_fail "${label} G7: Invoke-WebRequest count=${iwr_count} (want 1); other-transfer hits: ${deny_hits:-none}; plain http:// hits: ${http_hits:-none}"
        ok=0
    fi

    [ "${ok}" -eq 1 ]
}

echo "== RSA-0065 windows provisioner download-integrity gates =="
echo "target: ${TARGET}"

if [ ! -f "${TARGET}" ]; then
    echo "FAIL target missing: ${TARGET}" >&2
    exit 1
fi

if check_download_integrity "${TARGET}" "target"; then
    echo "PASS target: all structural checks"
else
    failures=$((failures + 1))
    echo "FAIL target: structural checks failed" >&2
fi

# --- self-test battery: the gate must REJECT the vulnerable shapes ---------

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

# T1: the PRE-FIX script shape — pin-less helper, bare Invoke-WebRequest,
# download executed without any hash/signature check (the RSA-0065 bug).
# The SAME checker that passed the real target above must reject this.
cat > "${tmpdir}/t1.ps1" <<'EOF'
function Invoke-WebDownload {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile
    )
    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing
}
$f = Join-Path $env:TEMP 'rustup-init.exe'
Invoke-WebDownload -Uri 'https://win.rustup.rs/x86_64' -OutFile $f
Start-Process -FilePath $f -ArgumentList '-y' -Wait
EOF
if ( check_download_integrity "${tmpdir}/t1.ps1" "old-replica" ) >/dev/null 2>&1; then
    gate_fail "selftest T1: pre-fix vulnerable replica PASSED the checker (gate is fail-open)"
else
    gate_pass "selftest T1: pre-fix vulnerable replica rejected by the checker"
fi

# T2: a 63-hex "digest" must not satisfy the 3x64-hex pin census.
{
    echo "\$short = '6f4bef66261261fcb43131be8720bab817d403a09edec7455c371974b90bdb'"
    echo "\$two = '985969f472caad75d993a5cb4c35a6a4271460cc12b343e2433b994d173aa990'"
    echo "\$three = '01aa49cf9574a8bd0ae52005d7de2590e8f27181ded6748236e702c92aef826d'"
} > "${tmpdir}/t2.ps1"
t2_pins="$(grep -oE "'[0-9a-f]{64}'" "${tmpdir}/t2.ps1" | wc -l | tr -d '[:space:]')"
if [ "${t2_pins}" -ne 3 ]; then
    gate_pass "selftest T2: 63-hex literal rejected by pin census (found ${t2_pins} valid pins, want 3)"
else
    gate_fail "selftest T2: 63-hex literal wrongly counted as a pin"
fi

# T3-T5 run the FULL checker end-to-end against a replica of the FIXED
# helper plus one vulnerable shape each (review finding 2 on b88: only
# re-testing the gate's own grep predicates against author-written
# fixtures is semi-vacuous).  Each fixture is rejected overall anyway
# (e.g. the pin census sees 1 of 3 pins); the assertion is that the
# failure cites the gate that owns the shape under test.

cat > "${tmpdir}/fixed-helper.ps1" <<'EOF'
function Invoke-WebDownload {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256,
        [Parameter(Mandatory = $false)][string]$RequireAuthenticodeSubject
    )
    if ($Uri -notlike 'https://*') {
        throw "refusing to download over a non-HTTPS transport: $Uri"
    }
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing
    } catch {
        Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
        throw "download failed: $Uri ($_)"
    }
    $actualHash = (Get-FileHash -LiteralPath $OutFile -Algorithm SHA256).Hash
    if ($actualHash -cne $ExpectedSha256) {
        Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
        throw "RSA-0065: SHA-256 pin mismatch for $Uri"
    }
    if ($RequireAuthenticodeSubject) {
        $signature = Get-AuthenticodeSignature -FilePath $OutFile
        if ($signature.Status -ne [System.Security.Cryptography.X509Certificates.X509SignatureStatus]::Valid) {
            Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
            throw "RSA-0065: Authenticode status not Valid for $OutFile"
        }
        if ($signature.SignerCertificate.Subject -notlike "*$RequireAuthenticodeSubject*") {
            Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
            throw "RSA-0065: wrong Authenticode publisher for $OutFile"
        }
    }
}
EOF

# T3: vs_BuildTools download WITHOUT the publisher requirement -- the
# checker must reject the fixture and the failure must cite G5.
cat > "${tmpdir}/t3body.ps1" <<'EOF'
$vsBootstrapper = Join-Path $env:TEMP 'vs_BuildTools.exe'
Invoke-WebDownload -Uri 'https://aka.ms/vs/17/release/vs_BuildTools.exe' -OutFile $vsBootstrapper -ExpectedSha256 '985969f472caad75d993a5cb4c35a6a4271460cc12b343e2433b994d173aa990'
Start-Process -FilePath $vsBootstrapper -ArgumentList '--quiet' -Wait
EOF
cat "${tmpdir}/fixed-helper.ps1" "${tmpdir}/t3body.ps1" > "${tmpdir}/t3full.ps1"
if t3_out="$( check_download_integrity "${tmpdir}/t3full.ps1" "t3-replica" 2>&1 )"; then
    gate_fail "selftest T3: missing publisher check NOT flagged (checker passed the fixture)"
elif printf '%s\n' "${t3_out}" | grep -q 'FAIL t3-replica G5'; then
    gate_pass "selftest T3: vs_BuildTools call without Authenticode publisher rejected end-to-end (G5)"
else
    gate_fail "selftest T3: fixture rejected but not via G5: ${t3_out}"
fi

# T4: a direct Invoke-WebRequest OUTSIDE the helper -- the checker must
# reject the fixture and the failure must cite G7 (transfer census).
cat > "${tmpdir}/t4body.ps1" <<'EOF'
$f = Join-Path $env:TEMP 'rustup-init.exe'
Invoke-WebRequest -Uri 'https://win.rustup.rs/x86_64' -OutFile $f -UseBasicParsing
EOF
cat "${tmpdir}/fixed-helper.ps1" "${tmpdir}/t4body.ps1" > "${tmpdir}/t4full.ps1"
if t4_out="$( check_download_integrity "${tmpdir}/t4full.ps1" "t4-replica" 2>&1 )"; then
    gate_fail "selftest T4: bare Invoke-WebRequest NOT flagged (checker passed the fixture)"
elif printf '%s\n' "${t4_out}" | grep -q 'FAIL t4-replica G7'; then
    gate_pass "selftest T4: bare Invoke-WebRequest outside the helper rejected end-to-end (G7)"
else
    gate_fail "selftest T4: fixture rejected but not via G7: ${t4_out}"
fi

# T5: plain http:// download URL -- the checker must reject the fixture
# and the failure must cite G7 (HTTPS-only census).
cat > "${tmpdir}/t5body.ps1" <<'EOF'
$f = Join-Path $env:TEMP 'rustup-init.exe'
Invoke-WebDownload -Uri 'http://win.rustup.rs/x86_64' -OutFile $f -ExpectedSha256 '985969f472caad75d993a5cb4c35a6a4271460cc12b343e2433b994d173aa990'
EOF
cat "${tmpdir}/fixed-helper.ps1" "${tmpdir}/t5body.ps1" > "${tmpdir}/t5full.ps1"
if t5_out="$( check_download_integrity "${tmpdir}/t5full.ps1" "t5-replica" 2>&1 )"; then
    gate_fail "selftest T5: plain http:// URL NOT flagged (checker passed the fixture)"
elif printf '%s\n' "${t5_out}" | grep -q 'FAIL t5-replica G7'; then
    gate_pass "selftest T5: plain http:// download URL rejected end-to-end (G7)"
else
    gate_fail "selftest T5: fixture rejected but not via G7: ${t5_out}"
fi

# T6 (review finding 1's mutation probe): take the REAL target, move the
# vs_BuildTools Invoke-WebDownload call (with its backtick continuations)
# to AFTER its Start-Process statement, and run the SAME checker on the
# mutated copy: it must FAIL, citing G6.  This is the exact mutation the
# b88 review demonstrated the old comment-anchored G6 let pass.
t6_dl="$(grep -nE "Invoke-WebDownload -Uri 'https://aka\.ms/vs/17/release/vs_BuildTools\.exe'" "${TARGET}" | head -1 | cut -d: -f1)"
t6_sp="$(grep -nE 'Start-Process -FilePath \$vsBootstrapper' "${TARGET}" | head -1 | cut -d: -f1)"
if [ -z "${t6_dl}" ] || [ -z "${t6_sp}" ]; then
    gate_fail "selftest T6: could not locate the vs_BuildTools download/Start-Process anchors in the target"
else
    awk -v a="${t6_dl}" -v s="${t6_sp}" '
        { lines[NR] = $0 }
        END {
            e = a
            while (e < NR && lines[e] ~ /`[ \t]*$/) { e++ }
            f = s
            while (f < NR && lines[f] ~ /`[ \t]*$/) { f++ }
            for (i = 1; i <= NR; i++) {
                if (i >= a && i <= e) { continue }
                print lines[i]
                if (i == f) { for (j = a; j <= e; j++) { print lines[j] } }
            }
        }
    ' "${TARGET}" > "${tmpdir}/t6.ps1"
    if t6_out="$( check_download_integrity "${tmpdir}/t6.ps1" "t6-mutated" 2>&1 )"; then
        gate_fail "selftest T6: download-moved-after-Start-Process mutation PASSED the checker (G6 is vacuous)"
    elif printf '%s\n' "${t6_out}" | grep -q 'FAIL t6-mutated G6'; then
        gate_pass "selftest T6: ordering mutation rejected end-to-end (G6)"
    else
        gate_fail "selftest T6: mutation rejected but not via G6: ${t6_out}"
    fi
fi

# --- optional PowerShell syntax parse ---------------------------------------

if command -v pwsh >/dev/null 2>&1; then
    if pwsh -NoProfile -Command "\$errs = \$null; [System.Management.Automation.Language.Parser]::ParseFile('${TARGET}', [ref]\$null, [ref]\$errs) | Out-Null; if (\$errs -and \$errs.Count -gt 0) { \$errs | ForEach-Object { Write-Host \$_.Message }; exit 1 } exit 0"; then
        gate_pass "P: pwsh parse clean"
    else
        gate_fail "P: pwsh parse errors"
    fi
else
    echo "NOTE pwsh not on PATH: syntax parse skipped (textual gates only)"
fi

if [ "${failures}" -eq 0 ]; then
    echo "windows provisioner download-integrity: ALL GATES PASS"
    exit 0
fi
echo "windows provisioner download-integrity: ${failures} FAILURE(S)" >&2
exit 1
