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
# All flags may instead come from the environment (flags win):
#   RUSTYNET_VERIFY_CLI
#   RUSTYNET_RELEASE_MANIFEST
#   RUSTYNET_RELEASE_PINNED_KEY_HEX | RUSTYNET_RELEASE_PINNED_KEY_FILE
#   RUSTYNET_RELEASE_ARTIFACTS_DIR
#
# Exit codes: 0 = verified; 1 = missing input or verification failure;
#             2 = usage error.

set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: Verify-RustyNetRelease.sh --verifier-cli <rustynet-binary> \
         --manifest <release-manifest.json> --artifacts-dir <dir> \
         [--pinned-key-hex <hex> | --pinned-key-file <path>] \
         [--require-artifact <filename>]...

Environment fallback (flags override): RUSTYNET_VERIFY_CLI,
RUSTYNET_RELEASE_MANIFEST, RUSTYNET_RELEASE_PINNED_KEY_HEX,
RUSTYNET_RELEASE_PINNED_KEY_FILE, RUSTYNET_RELEASE_ARTIFACTS_DIR.
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
[[ -n "${KEY_HEX}" || -n "${KEY_FILE}" ]] \
  || die "no release verifier key is pinned yet: supply the project's published release public key via --pinned-key-hex/--pinned-key-file or RUSTYNET_RELEASE_PINNED_KEY_HEX/RUSTYNET_RELEASE_PINNED_KEY_FILE (no embedded default; pending owner decision OI-47, charter/governance/owner-inbox.md)"
[[ -z "${KEY_HEX}" || -z "${KEY_FILE}" ]] \
  || die "both pinned-key hex and pinned-key file given; provide exactly one"

[[ "${VERIFY_CLI}" = /* ]]   || die "verifier CLI must be an absolute path: ${VERIFY_CLI}"
[[ -x "${VERIFY_CLI}" ]]     || die "verifier CLI not executable: ${VERIFY_CLI}"
[[ -f "${MANIFEST}" ]]       || die "manifest not found: ${MANIFEST}"
[[ -d "${ARTIFACTS_DIR}" ]]  || die "artifacts dir is not a directory: ${ARTIFACTS_DIR}"

# AQ-11 N-B: capability probe. Before relying on --require-artifact, refuse
# to run against a verifier CLI that predates the flag: such a build's
# parser silently ignores unknown options, so the by-name binding (AQ-11 F3)
# would evaporate with no diagnostic — on exactly the already-installed
# verifier default this helper is invoked with. The probe parses the CLI's
# own usage output for the flag and fails closed when it is absent.
if [[ "${#require_artifacts[@]}" -gt 0 ]]; then
  cli_help="$( "${VERIFY_CLI}" ops verify-release-manifest --help 2>&1 || true )"
  case "${cli_help}" in
    *--require-artifact*) ;;
    *) die "verifier CLI predates --require-artifact; it cannot bind artifacts by name (AQ-11 F3/N-B). Upgrade the out-of-band verifier: ${VERIFY_CLI}" ;;
  esac
fi

verify_args=(ops verify-release-manifest --manifest "${MANIFEST}" --artifacts-dir "${ARTIFACTS_DIR}")
if [[ -n "${KEY_HEX}" ]]; then
  verify_args+=(--pinned-verifier-key-hex "${KEY_HEX}")
else
  [[ -f "${KEY_FILE}" ]] || die "pinned key file not found: ${KEY_FILE}"
  verify_args+=(--pinned-verifier-key-file "${KEY_FILE}")
fi
for name in ${require_artifacts[@]+"${require_artifacts[@]}"}; do
  verify_args+=(--require-artifact "${name}")
done

# exec: the verifier's own exit code IS this script's exit code — fail closed.
exec "${VERIFY_CLI}" "${verify_args[@]}"
