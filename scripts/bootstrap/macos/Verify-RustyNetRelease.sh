#!/usr/bin/env bash
# Verify-RustyNetRelease.sh — fail-closed signed-release verification for the
# macOS bootstrap (AQ-11 / R-SEC-10).
#
# Thin, directly testable wrapper around the in-tree verifier:
#   <rustynet> ops verify-release-manifest --manifest <path>
#       (--pinned-verifier-key-hex <hex> | --pinned-verifier-key-file <path>)
#       --artifacts-dir <dir>
# implemented by crates/rustynet-cli/src/ops_release_manifest.rs +
# crates/rustynet-cli/src/release_manifest.rs: the manifest's Ed25519
# signature is checked against the PINNED verifier key first (strict
# verification, constant-time pin comparison), then every listed artifact on
# disk is re-hashed and compared against the manifest's sha256 + size. Any
# missing input, key mismatch, signature failure, or digest mismatch exits
# non-zero BEFORE the caller extracts or executes the payload.
#
# The verifier CLI must be provisioned out-of-band (a previously installed
# rustynet, or an operator-staged binary). It must never be part of the
# payload it verifies.
#
# The pinned verifier key DEFAULTS to the project's published release public
# key below (owner decision OI-47, accepted 2026-09-25: the owner generated
# the release signing key and relayed its Ed25519 PUBLIC half; the private
# seed never enters this tree). An explicit --pinned-key-hex /
# --pinned-key-file (or the matching environment variables) always wins over
# the embedded default.
#
# Usage:
#   Verify-RustyNetRelease.sh --verifier-cli <rustynet-binary> \
#     --manifest <release-manifest.json> --artifacts-dir <dir> \
#     [--pinned-key-hex <hex> | --pinned-key-file <path>] \
#     [--require-artifact <filename>]...
#
# --require-artifact (repeatable) binds the verification to the exact files the
# caller is about to consume: each name must be listed in the signed manifest,
# so a validly-signed manifest that merely does NOT list the file to be
# extracted can never pass for it (AQ-11 F3).
#
# Without an explicit key the script pins
# RUSTYNET_DEFAULT_RELEASE_VERIFIER_KEY_HEX (AQ-247 / OI-47).
#
# All flags may instead come from the environment (flags win):
#   RUSTYNET_VERIFY_CLI
#   RUSTYNET_RELEASE_MANIFEST
#   RUSTYNET_RELEASE_PINNED_KEY_HEX | RUSTYNET_RELEASE_PINNED_KEY_FILE
#   RUSTYNET_RELEASE_ARTIFACTS_DIR
#
# Exit codes: 0 = verified; 1 = missing input or verification failure;
#             2 = usage error.

set -euo pipefail

# AQ-247 / OI-47 (accepted 2026-09-25): the owner-generated Ed25519 PUBLIC
# release verifier key, embedded as the DEFAULT pin. An explicit
# --pinned-key-hex / --pinned-key-file (or RUSTYNET_RELEASE_PINNED_KEY_HEX /
# RUSTYNET_RELEASE_PINNED_KEY_FILE) always overrides it. The matching PRIVATE
# signing seed is held by the owner only and never appears in this tree.
readonly RUSTYNET_DEFAULT_RELEASE_VERIFIER_KEY_HEX="7bb5f1629b7b9eb48bdb94633d092e796a2a8ba69903cc3e432e1a33c05016fe"

usage() {
  cat >&2 <<'USAGE'
usage: Verify-RustyNetRelease.sh --verifier-cli <rustynet-binary> \
         --manifest <release-manifest.json> --artifacts-dir <dir> \
         [--pinned-key-hex <hex> | --pinned-key-file <path>] \
         [--require-artifact <filename>]...

Environment fallback (flags override): RUSTYNET_VERIFY_CLI,
RUSTYNET_RELEASE_MANIFEST, RUSTYNET_RELEASE_PINNED_KEY_HEX,
RUSTYNET_RELEASE_PINNED_KEY_FILE, RUSTYNET_RELEASE_ARTIFACTS_DIR.
With no explicit key the embedded default release verifier key is pinned
(AQ-247/OI-47).
USAGE
}

die() {
  printf 'Verify-RustyNetRelease: %s\n' "$1" >&2
  exit "${2:-1}"
}

VERIFY_CLI="${RUSTYNET_VERIFY_CLI:-}"
MANIFEST="${RUSTYNET_RELEASE_MANIFEST:-}"
KEY_HEX="${RUSTYNET_RELEASE_PINNED_KEY_HEX:-}"
KEY_FILE="${RUSTYNET_RELEASE_PINNED_KEY_FILE:-}"
ARTIFACTS_DIR="${RUSTYNET_RELEASE_ARTIFACTS_DIR:-}"
require_artifacts=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --verifier-cli)    [[ $# -ge 2 ]] || die "--verifier-cli needs a value" 2; VERIFY_CLI="$2"; shift 2 ;;
    --manifest)        [[ $# -ge 2 ]] || die "--manifest needs a value" 2; MANIFEST="$2"; shift 2 ;;
    --pinned-key-hex)  [[ $# -ge 2 ]] || die "--pinned-key-hex needs a value" 2; KEY_HEX="$2"; shift 2 ;;
    --pinned-key-file) [[ $# -ge 2 ]] || die "--pinned-key-file needs a value" 2; KEY_FILE="$2"; shift 2 ;;
    --artifacts-dir)   [[ $# -ge 2 ]] || die "--artifacts-dir needs a value" 2; ARTIFACTS_DIR="$2"; shift 2 ;;
    --require-artifact)
      [[ $# -ge 2 ]] || die "--require-artifact needs a value" 2
      require_artifacts+=("$2"); shift 2 ;;
    -h|--help)         usage; exit 0 ;;
    *)                 usage; die "unknown argument: $1" 2 ;;
  esac
done

[[ -n "${VERIFY_CLI}" ]]    || die "no verifier CLI: pass --verifier-cli or set RUSTYNET_VERIFY_CLI"
[[ -n "${MANIFEST}" ]]      || die "no manifest: pass --manifest or set RUSTYNET_RELEASE_MANIFEST"
[[ -n "${ARTIFACTS_DIR}" ]] || die "no artifacts dir: pass --artifacts-dir or set RUSTYNET_RELEASE_ARTIFACTS_DIR"
# AQ-247 / OI-47: default to the embedded public release verifier key when no
# explicit key was supplied; an explicit --pinned-key-hex / --pinned-key-file
# (or environment) always wins.
if [[ -z "${KEY_HEX}" && -z "${KEY_FILE}" ]]; then
  KEY_HEX="${RUSTYNET_DEFAULT_RELEASE_VERIFIER_KEY_HEX}"
  printf 'Verify-RustyNetRelease: no explicit verifier key given; pinning the embedded default release key (AQ-247/OI-47)\n' >&2
fi
[[ -z "${KEY_HEX}" || -z "${KEY_FILE}" ]] \
  || die "both pinned-key hex and pinned-key file given; provide exactly one"

[[ "${VERIFY_CLI}" = /* ]]   || die "verifier CLI must be an absolute path: ${VERIFY_CLI}"
[[ -x "${VERIFY_CLI}" ]]     || die "verifier CLI not executable: ${VERIFY_CLI}"
[[ -f "${MANIFEST}" ]]       || die "manifest not found: ${MANIFEST}"
[[ -d "${ARTIFACTS_DIR}" ]]  || die "artifacts dir is not a directory: ${ARTIFACTS_DIR}"

verify_args=(ops verify-release-manifest --manifest "${MANIFEST}" --artifacts-dir "${ARTIFACTS_DIR}")
if [[ -n "${KEY_HEX}" ]]; then
  verify_args+=(--pinned-verifier-key-hex "${KEY_HEX}")
else
  [[ -f "${KEY_FILE}" ]] || die "pinned key file not found: ${KEY_FILE}"
  verify_args+=(--pinned-verifier-key-file "${KEY_FILE}")
fi

# AQ-11 N-B: capability probe — BEHAVIOURAL, not advertisement. The probe
# runs the REAL verify (same manifest, same pinned key) with --require-artifact
# set to a fixed name that is never listed in any signed manifest, and accepts
# the CLI only if it fails with the exact unlisted-artifact refusal the
# enforcing CLI prints (crates/rustynet-cli/src/ops_release_manifest.rs; the
# CLI checks the manifest signature BEFORE the required-artifact list, so the
# probe is deterministic for a validly-signed manifest). Any other outcome —
# success (a build that silently ignores unknown options), a different error,
# a usage error — means the flag is not enforced and the by-name binding
# (AQ-11 F3) would evaporate with no diagnostic; fail closed. (An earlier
# revision grepped `--help` output for the flag; the AQ-11 N-B review found
# advertisement is not enforcement — and no shipped build printed subcommand
# help at all. The probe must NOT depend on `--help`.) A CLI that fakes the
# refusal while ignoring real enforcement would defeat ANY fixed-name probe —
# but that is a MALICIOUS verifier, out of scope here: the verifier binary
# itself is the trust anchor and must be provisioned out-of-band (AQ-11 F1/F4,
# enforced by the caller's provenance refusals).
# Ordering: the REAL verification runs FIRST (below), and the probe only runs
# when it PASSED — so "verify passed but the flag was ignored" is exactly the
# case the N-B refusal fires on, while genuine signature/digest failures keep
# their own diagnoses.
probe_args=("${verify_args[@]}" --require-artifact "__rustynet_require_artifact_probe__")
for name in ${require_artifacts[@]+"${require_artifacts[@]}"}; do
  verify_args+=(--require-artifact "${name}")
done

# Run the verification with an explicit status check (a security gate must
# not depend on its call context — set -e is void inside `if`/`||`). This
# replaces the earlier `exec`: the verifier's exit code is still this
# script's exit code on failure, and the probe below runs only on success.
set +e
verify_output="$( "${VERIFY_CLI}" "${verify_args[@]}" 2>&1 )"
verify_rc=$?
set -e
if [[ "${verify_rc}" -ne 0 ]]; then
  printf '%s\n' "${verify_output}" >&2
  printf 'Verify-RustyNetRelease: verification FAILED (verifier rc=%s); nothing is blessed, nothing may be extracted (AQ-11 F1)\n' "${verify_rc}" >&2
  exit "${verify_rc}"
fi
printf '%s\n' "${verify_output}"

if [[ "${#require_artifacts[@]}" -gt 0 ]]; then
  probe_output="$( "${VERIFY_CLI}" "${probe_args[@]}" 2>&1 || true )"
  case "${probe_output}" in
    *"required artifact '__rustynet_require_artifact_probe__' is not listed in the signed manifest"*) ;;
    *)
      printf 'Verify-RustyNetRelease: capability-probe output: %s\n' "${probe_output}" >&2
      die "verifier CLI does not enforce --require-artifact (behavioural probe expected the unlisted-artifact refusal); it cannot bind artifacts by name (AQ-11 F3/N-B). Upgrade the out-of-band verifier: ${VERIFY_CLI}"
      ;;
  esac
fi

exit 0
