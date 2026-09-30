#!/usr/bin/env bash
# rn_bootstrap_macos.sh — Orchestrator-side wrapper that drives the
# reviewed macOS bootstrap (`scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh`)
# from the cross-OS lab orchestrator (Phase 23).
#
# This script runs on the *target* macOS host. The orchestrator scp's
# it along with the source archive, then invokes it with the lab inputs.
# The wrapper:
#
#   1. Parses CLI args (`--node-id`, `--network-id`, `--node-role`,
#      `--ssh-allow-cidrs`).
#   2. Validates every input against a strict allowlist (no shell
#      construction with untrusted values).
#   3. Derives the per-node `utun` interface name using the same FNV-1a
#      32-bit hash as the Rust adapter (`utun_index_for_node_id` in
#      crates/rustynet-cli/.../macos_install.rs). This keeps a single
#      hardened execution path: the bash wrapper and the Rust adapter
#      must produce bit-identical interface names for a given node_id.
#   4. Writes the bootstrap env file consumed by
#      `Bootstrap-RustyNetMacos.sh` (and forwards `DAEMON_NODE_ROLE` +
#      `SSH_ALLOW_CIDRS` so the launchd plist install picks them up, plus the
#      resolved release-verification inputs so the bootstrap inherits the
#      SAME out-of-band verifier, manifest and pinned key).
#   5. Stages a root-owned 0700 PRIVATE copy of the received archive and
#      verifies THAT copy against its signed release manifest (Ed25519,
#      pinned verifier key, archive required BY NAME) BEFORE any extraction
#      — the wrapper never extracts or executes any part of the received
#      payload before that gate passes (AQ-11 F1: the bootstrap script that
#      performs further verification is itself inside the payload, so it
#      must arrive verified). AQ-11 N-A: the shared received path is read
#      exactly once, by root, during staging, and never consumed again —
#      the verified object and the consumed object are the same root-owned
#      file, so there is no verify-to-extract window on the shared path.
#   6. Extracts the staged verified archive into `/private/var/tmp/rn_build`.
#   7. Invokes the reviewed bootstrap script with `sudo`.
#   8. Polls for the daemon Unix socket to appear (40 s × 1 s).
#
# Verifier provisioning (AQ-11 F1/F4): the verifier CLI must be out-of-band —
# explicit `--verify-cli`, else the already-installed /usr/local/bin/rustynet
# (built from previously-verified source). With neither available the wrapper
# builds `rustynet-cli` from the LOCAL source checkout this wrapper script
# itself runs from — never from the downloaded payload (AQ-11 F4 provenance
# refusal still applies) — with `cargo build --release --locked
# -p rustynet-cli` and uses that binary as the verifier BEFORE any download
# is trusted; the build runs as the invoking (non-root) user and any failure
# fails closed with a named error, never an unverified extract. Neither the
# verifier nor the pinned key may resolve inside the payload directory: the
# payload can never vouch for itself. The pinned key DEFAULTS to the
# embedded public release verifier key below (AQ-247 / OI-47, accepted
# 2026-09-25: the owner generated the release signing key and relayed its
# Ed25519 PUBLIC half; the private seed never enters this tree); an explicit
# `--verifier-key-hex` / `--verifier-key-file` always wins over the default.
#
# Idempotency: every step is safe to re-run.  The reviewed bootstrap
# itself skips already-present prereqs and reseeds only when the
# canonical file is missing; the build dir is wiped each run so a fresh
# source tree always replaces the previous extraction.
#
# Fail-closed: `set -euo pipefail` plus strict input validation plus
# explicit non-zero exits on missing inputs or stale state.

set -euo pipefail

# ── CLI parsing ───────────────────────────────────────────────────────────────
NODE_ID=""
NETWORK_ID=""
NODE_ROLE=""
SSH_ALLOW_CIDRS=""
SOURCE_ARCHIVE_PATH="/private/var/tmp/rustynet_src.tar.gz"
BUILD_DIR="/private/var/tmp/rn_build"
ENV_FILE_PATH="/private/var/tmp/rn_macos_bootstrap.env"
VERIFY_CLI=""
VERIFIER_KEY_HEX=""
VERIFIER_KEY_FILE=""
RELEASE_MANIFEST_PATH=""

# AQ-247 / OI-47 (accepted 2026-09-25): the owner-generated Ed25519 PUBLIC
# release verifier key, embedded as the DEFAULT pin. An explicit
# --verifier-key-hex / --verifier-key-file always overrides it. The matching
# PRIVATE signing seed is held by the owner only and never appears in this
# tree.
readonly RUSTYNET_DEFAULT_RELEASE_VERIFIER_KEY_HEX="7bb5f1629b7b9eb48bdb94633d092e796a2a8ba69903cc3e432e1a33c05016fe"

usage() {
  cat >&2 <<'USAGE'
usage: rn_bootstrap_macos.sh \
    --node-id <id> \
    --network-id <id> \
    --node-role <client|exit|entry|aux|extra|fifth_client|admin> \
    [--ssh-allow-cidrs <csv-cidrs>] \
    [--source-archive <path>] \
    [--build-dir <path>] \
    [--env-file <path>] \
    [--verify-cli <absolute-path-to-trusted-rustynet>] \
    [--verifier-key-hex <64-hex> | --verifier-key-file <path>] \
    [--release-manifest <path>]

Runs the reviewed macOS bootstrap (Bootstrap-RustyNetMacos.sh +
Install-RustyNetMacosService.sh) with the orchestrator-provided
NODE_ID / NETWORK_ID / NODE_ROLE / SSH_ALLOW_CIDRS values and a
deterministic per-node utun interface name. The source archive is
verified against its signed release manifest (pinned verifier key,
archive required BY NAME) BEFORE anything from it is extracted or
executed; the verification inputs are forwarded to the bootstrap via
the env file. See the AQ-11 header notes for the verifier-provisioning
contract (out-of-band verifier; the pinned key defaults to the
embedded public release verifier key — AQ-247/OI-47 — and an explicit
--verifier-key-hex / --verifier-key-file always wins).
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --node-id)            NODE_ID="${2:-}";              shift 2 ;;
    --network-id)         NETWORK_ID="${2:-}";           shift 2 ;;
    --node-role)          NODE_ROLE="${2:-}";            shift 2 ;;
    --ssh-allow-cidrs)    SSH_ALLOW_CIDRS="${2:-}";      shift 2 ;;
    --source-archive)     SOURCE_ARCHIVE_PATH="${2:-}";  shift 2 ;;
    --build-dir)          BUILD_DIR="${2:-}";            shift 2 ;;
    --env-file)           ENV_FILE_PATH="${2:-}";        shift 2 ;;
    --verify-cli)         VERIFY_CLI="${2:-}";           shift 2 ;;
    --verifier-key-hex)   VERIFIER_KEY_HEX="${2:-}";     shift 2 ;;
    --verifier-key-file)  VERIFIER_KEY_FILE="${2:-}";    shift 2 ;;
    --release-manifest)   RELEASE_MANIFEST_PATH="${2:-}"; shift 2 ;;
    -h|--help)            usage; exit 0 ;;
    *) printf 'rn_bootstrap_macos.sh: unknown argument: %s\n' "$1" >&2; usage; exit 2 ;;
  esac
done

# ── Input validation (strict allowlists, no shell metacharacters) ─────────────
require_value() {
  local label="$1"
  local value="$2"
  if [[ -z "$value" ]]; then
    printf 'rn_bootstrap_macos.sh: %s is required\n' "$label" >&2
    exit 2
  fi
}

validate_identifier() {
  local label="$1"
  local value="$2"
  if [[ ${#value} -gt 128 ]]; then
    printf 'rn_bootstrap_macos.sh: %s exceeds 128 chars\n' "$label" >&2
    exit 2
  fi
  if [[ ! "$value" =~ ^[A-Za-z0-9._-]+$ ]]; then
    printf 'rn_bootstrap_macos.sh: %s must match [A-Za-z0-9._-]+ (received: %q)\n' \
      "$label" "$value" >&2
    exit 2
  fi
}

validate_node_role() {
  local value="$1"
  case "$value" in
    client|exit|entry|aux|extra|fifth_client|admin) ;;
    *) printf 'rn_bootstrap_macos.sh: --node-role must be one of client|exit|entry|aux|extra|fifth_client|admin (received: %q)\n' \
         "$value" >&2; exit 2 ;;
  esac
}

validate_ssh_allow_cidrs() {
  local value="$1"
  # Empty is allowed (SSH fail-open rule remains disabled).
  if [[ -z "$value" ]]; then
    return 0
  fi
  if [[ ${#value} -gt 1024 ]]; then
    printf 'rn_bootstrap_macos.sh: --ssh-allow-cidrs exceeds 1024 chars\n' >&2
    exit 2
  fi
  # Comma-separated IPv4/IPv6 CIDRs; reject anything outside the
  # reviewed charset so we cannot smuggle shell metacharacters into the
  # downstream plist.
  if [[ ! "$value" =~ ^[A-Fa-f0-9:./,]+$ ]]; then
    printf 'rn_bootstrap_macos.sh: --ssh-allow-cidrs must contain only hex/colon/dot/slash/comma (received: %q)\n' \
      "$value" >&2
    exit 2
  fi
}

validate_path_argument() {
  local label="$1"
  local value="$2"
  if [[ -z "$value" ]]; then
    printf 'rn_bootstrap_macos.sh: %s must be non-empty\n' "$label" >&2
    exit 2
  fi
  if [[ "$value" != /* ]]; then
    printf 'rn_bootstrap_macos.sh: %s must be an absolute path (received: %q)\n' \
      "$label" "$value" >&2
    exit 2
  fi
  case "$value" in
    *$'\n'*|*$'\r'*|*' '*|*'`'*|*'$'*|*'"'*|*"'"*|*';'*|*'&'*|*'|'*|*'<'*|*'>'*)
      printf 'rn_bootstrap_macos.sh: %s contains shell-unsafe characters (received: %q)\n' \
        "$label" "$value" >&2
      exit 2
      ;;
  esac
}

require_value "--node-id" "$NODE_ID"
require_value "--network-id" "$NETWORK_ID"
require_value "--node-role" "$NODE_ROLE"
validate_identifier "--node-id" "$NODE_ID"
validate_identifier "--network-id" "$NETWORK_ID"
validate_node_role "$NODE_ROLE"
validate_ssh_allow_cidrs "$SSH_ALLOW_CIDRS"
validate_path_argument "--source-archive" "$SOURCE_ARCHIVE_PATH"
validate_path_argument "--build-dir" "$BUILD_DIR"
validate_path_argument "--env-file" "$ENV_FILE_PATH"
if [[ -n "$VERIFY_CLI" ]]; then
  validate_path_argument "--verify-cli" "$VERIFY_CLI"
fi
if [[ -n "$VERIFIER_KEY_HEX" && -n "$VERIFIER_KEY_FILE" ]]; then
  printf 'rn_bootstrap_macos.sh: --verifier-key-hex and --verifier-key-file are mutually exclusive\n' >&2
  exit 2
fi
if [[ -n "$VERIFIER_KEY_HEX" && ! "$VERIFIER_KEY_HEX" =~ ^[0-9a-fA-F]{64}$ ]]; then
  printf 'rn_bootstrap_macos.sh: --verifier-key-hex must be exactly 64 hex characters\n' >&2
  exit 2
fi
if [[ -n "$VERIFIER_KEY_FILE" ]]; then
  validate_path_argument "--verifier-key-file" "$VERIFIER_KEY_FILE"
fi
if [[ -n "$RELEASE_MANIFEST_PATH" ]]; then
  validate_path_argument "--release-manifest" "$RELEASE_MANIFEST_PATH"
fi

# ── FNV-1a 32-bit utun index (must match Rust adapter) ───────────────────────
#
# Rust reference:
#   crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install.rs
#     fn utun_index_for_node_id(node_id: &str) -> u16 {
#         let mut hash: u32 = 2_166_136_261;
#         for byte in node_id.bytes() {
#             hash ^= u32::from(byte);
#             hash = hash.wrapping_mul(16_777_619);
#         }
#         (hash % 4086) as u16 + 10
#     }
#
# Both implementations MUST produce the same value for a given node_id so
# the orchestrator's enforce_runtime step (which calls the Rust adapter)
# and this bootstrap (which calls the bash hash) reference the same utun
# device. A divergence would mean the daemon's bootstrap plist names one
# interface, the enforce-runtime plist names another, and the WireGuard
# tunnel comes up on a different utun than the privileged helper expects.
fnv1a_utun_index() {
  local s="$1"
  local hash=2166136261
  local i len byte
  len="${#s}"
  for (( i = 0; i < len; i++ )); do
    printf -v byte '%d' "'${s:i:1}"
    hash=$(( hash ^ byte ))
    hash=$(( (hash * 16777619) & 0xFFFFFFFF ))
  done
  printf '%d' $(( (hash % 4086) + 10 ))
}

fnv1a_utun_name() {
  local s="$1"
  local index
  index="$(fnv1a_utun_index "$s")"
  printf 'utun%s' "$index"
}

# ── Parity guard: known-input expected-output assertions ─────────────────────
#
# These pins fire if the FNV-1a constants drift in either the bash side
# (above) or the Rust side (macos_install.rs). They are deliberately
# computed from inputs already in the lab inventory so that lab-wide
# bootstraps trip the guard before any host gets a divergent utun name.
assert_known_utun_index() {
  local input="$1"
  local expected="$2"
  local actual
  actual="$(fnv1a_utun_index "$input")"
  if [[ "$actual" != "$expected" ]]; then
    printf 'rn_bootstrap_macos.sh: FNV-1a utun index drift detected: input=%q expected=%s actual=%s\n' \
      "$input" "$expected" "$actual" >&2
    printf 'rn_bootstrap_macos.sh: bash and Rust hash implementations must produce identical values\n' >&2
    exit 1
  fi
}

# Known good values: see the Rust tests in macos_install.rs
# `utun_index_is_deterministic` + `utun_index_avoids_reserved_range`.
# Computed by running both implementations and pinning the result.
assert_known_utun_index "macos-client-1" "3912"
assert_known_utun_index "exit-1"         "2369"
assert_known_utun_index "client-1"       "3466"

# ── Derive WG_INTERFACE for this node ────────────────────────────────────────
WG_INTERFACE="$(fnv1a_utun_name "$NODE_ID")"
# Defense-in-depth: validate the derived name shape matches what
# Install-RustyNetMacosService.sh accepts (^utun[0-9]+$, ≤15 chars).
if [[ ! "$WG_INTERFACE" =~ ^utun[0-9]+$ ]]; then
  printf 'rn_bootstrap_macos.sh: derived WG_INTERFACE %q does not match ^utun[0-9]+$\n' \
    "$WG_INTERFACE" >&2
  exit 1
fi
if [[ ${#WG_INTERFACE} -gt 15 ]]; then
  printf 'rn_bootstrap_macos.sh: derived WG_INTERFACE %q exceeds 15-char IFNAMSIZ\n' \
    "$WG_INTERFACE" >&2
  exit 1
fi

# ── Map orchestrator role -> daemon NodeRole ────────────────────────────────
#
# Mirrors `NodeRole::daemon_node_role_for_platform(Macos)` in
# crates/rustynet-cli/src/vm_lab/orchestrator/role.rs. The bash side has
# to stay in sync because Bootstrap-RustyNetMacos.sh refuses to start
# the daemon without an explicit DAEMON_NODE_ROLE in {admin, client,
# blind_exit}. The regular macOS exit now boots as the `client` daemon
# role and is promoted client->admin->exit by the live-lab
# `activate_macos_exit_role` stage AFTER its membership grants the
# `anchor` capability the admin role requires (booting straight as admin
# would fail-close reconcile with "admin requires anchor" before the
# membership amendment lands). The orchestrator records the exit's
# runtime daemon role as `admin`, so accept `admin` here and map it to
# the `client` boot role. The `exit` lab token maps to `blind_exit` (the
# IRREVERSIBLE macOS blind exit, driven by its own validate_macos_blind_exit
# stage), which is a distinct posture.
daemon_node_role_for_macos() {
  case "$1" in
    admin) printf 'client' ;;
    exit) printf 'blind_exit' ;;
    client|entry|aux|extra|fifth_client) printf 'client' ;;
    *) printf 'rn_bootstrap_macos.sh: cannot map role %q to a macOS daemon role\n' \
         "$1" >&2; exit 1 ;;
  esac
}

DAEMON_NODE_ROLE="$(daemon_node_role_for_macos "$NODE_ROLE")"

# ── Source archive presence check ────────────────────────────────────────────
if [[ ! -f "$SOURCE_ARCHIVE_PATH" ]]; then
  printf 'rn_bootstrap_macos.sh: source archive missing at %s\n' "$SOURCE_ARCHIVE_PATH" >&2
  exit 1
fi

# ── AQ-11 F1: verify the received archive BEFORE extracting/executing it ─────
# The bootstrap script that performs the deeper verification is INSIDE this
# archive; running it unverified would let the payload verify itself. So the
# wrapper verifies first, with an out-of-band verifier and a pinned key, and
# only then extracts as root. Everything here fails closed.
canonical_path() {
  local p="$1" dir base
  dir="$(cd -- "$(dirname -- "$p")" && pwd -P)" || return 1
  base="$(basename -- "$p")"
  printf '%s/%s\n' "$dir" "$base"
}

# AQ-11 F4: the verifier CLI and the pinned key must come from out-of-band —
# never from the payload directory (or the build dir). A verifier supplied by
# the payload would make signature checking self-vouching.
refuse_payload_provenance() {
  local path="$1" label="$2" archive_dir="$3"
  local canonical
  canonical="$(canonical_path "$path")" || {
    printf 'rn_bootstrap_macos.sh: cannot canonicalize %s: %s\n' "$label" "$path" >&2
    exit 1
  }
  local payload_dir
  for payload_dir in "$archive_dir" "$BUILD_DIR"; do
    payload_dir="$(canonical_path "$payload_dir")" || continue
    case "$canonical/" in
      "$payload_dir"/*)
        printf 'rn_bootstrap_macos.sh: FATAL: %s resolves inside a payload directory (%s): %s\n' \
          "$label" "$payload_dir" "$canonical" >&2
        printf 'rn_bootstrap_macos.sh: the verifier and pinned key must be provisioned out-of-band (AQ-11 F4); the payload can never vouch for itself\n' >&2
        exit 1
        ;;
    esac
  done
}

# AQ-247 / OI-47: verifier-from-source fallback. When neither an explicit
# --verify-cli nor the already-installed /usr/local/bin/rustynet is usable,
# build `rustynet-cli` from the LOCAL source checkout this wrapper script
# itself runs from (dirname "$0"/../..) — never from the downloaded payload —
# with the Rust toolchain the wrapper host already has, running as the
# invoking (non-root) user, and use that binary as the verifier BEFORE any
# download is trusted. Every failure here is a named hard failure: the
# wrapper never falls back to an unverified extract.
rn_build_local_verifier_cli() {
  local archive_dir="$1"
  local checkout
  checkout="$(cd -- "$(dirname -- "$0")/../.." && pwd)" || {
    printf 'rn_bootstrap_macos.sh: FATAL: cannot resolve the local source checkout containing this wrapper\n' >&2
    exit 1
  }
  if [[ ! -f "${checkout}/Cargo.toml" || ! -d "${checkout}/crates/rustynet-cli" ]]; then
    printf 'rn_bootstrap_macos.sh: FATAL: no out-of-band verifier CLI available and %s is not a rustynet source checkout (missing Cargo.toml or crates/rustynet-cli)\n' "${checkout}" >&2
    printf 'rn_bootstrap_macos.sh: pass --verify-cli <absolute-path-to-trusted-rustynet> or run this wrapper from a rustynet checkout\n' >&2
    exit 1
  fi
  # AQ-11 F4: a checkout that IS the payload (or lives inside it) can never
  # vouch for itself. The provenance refusal must precede the build: building
  # executes the checkout's own build scripts, so refusing only the finished
  # binary would already have run payload-chosen code.
  refuse_payload_provenance "${checkout}/Cargo.toml" "verifier source checkout" "$archive_dir"
  local cargo_bin
  cargo_bin="$(command -v cargo || true)"
  if [[ -z "${cargo_bin}" && -x "${HOME}/.cargo/bin/cargo" ]]; then
    cargo_bin="${HOME}/.cargo/bin/cargo"
  fi
  if [[ -z "${cargo_bin}" ]]; then
    printf 'rn_bootstrap_macos.sh: FATAL: cannot build the verifier from source: no cargo on PATH and no %s\n' "${HOME}/.cargo/bin/cargo" >&2
    exit 1
  fi
  printf 'rn_bootstrap_macos.sh: no out-of-band verifier CLI available; building rustynet-cli from the local checkout %s (AQ-247/OI-47)\n' "${checkout}" >&2
  if ! "${cargo_bin}" build --release --locked -p rustynet-cli --manifest-path "${checkout}/Cargo.toml"; then
    printf 'rn_bootstrap_macos.sh: FATAL: verifier build from local source failed — refusing to verify or extract any download (fail closed)\n' >&2
    exit 1
  fi
  local built="${checkout}/target/release/rustynet-cli"
  [[ -x "${built}" ]] || {
    printf 'rn_bootstrap_macos.sh: FATAL: verifier build produced no binary at %s\n' "${built}" >&2
    exit 1
  }
  refuse_payload_provenance "${built}" "built verifier CLI" "$archive_dir"
  printf '%s' "${built}"
}

verify_source_archive() {
  local archive_dir archive_name manifest verify_cli

  archive_dir="$(canonical_path "$(dirname -- "$SOURCE_ARCHIVE_PATH")")"
  archive_name="$(basename -- "$SOURCE_ARCHIVE_PATH")"

  # Verifier CLI resolution (out-of-band only): explicit --verify-cli wins;
  # otherwise an already-installed rustynet (built from previously-verified
  # source); otherwise the verifier is BUILT from the local source checkout
  # this wrapper runs from (AQ-247/OI-47), never from the payload. The
  # payload is never the verifier source.
  if [[ -n "$VERIFY_CLI" ]]; then
    verify_cli="$VERIFY_CLI"
  elif [[ -x /usr/local/bin/rustynet ]]; then
    verify_cli="/usr/local/bin/rustynet"
  else
    verify_cli="$(rn_build_local_verifier_cli "$archive_dir")" || {
      printf 'rn_bootstrap_macos.sh: FATAL: no out-of-band verifier CLI available and no verifier could be built from the local source checkout\n' >&2
      exit 1
    }
  fi
  [[ "$verify_cli" == /* && -x "$verify_cli" ]] || {
    printf 'rn_bootstrap_macos.sh: FATAL: verifier CLI is not an absolute executable path: %s\n' "$verify_cli" >&2
    exit 1
  }
  refuse_payload_provenance "$verify_cli" "verifier CLI" "$archive_dir"

  # Pinned key resolution: explicit hex > explicit file. With neither option
  # the wrapper pins its embedded DEFAULT release verifier key (AQ-247/OI-47:
  # the owner-generated Ed25519 public key). The resolved key is forwarded to
  # the bootstrap via the env file so both stages verify under the SAME
  # pinned key.
  local -a key_args=()
  local key_env_assignment=""
  if [[ -n "$VERIFIER_KEY_HEX" ]]; then
    key_args=(--pinned-verifier-key-hex "$VERIFIER_KEY_HEX")
    key_env_assignment="$(printf 'RUSTYNET_RELEASE_PINNED_KEY_HEX=%q\n' "$VERIFIER_KEY_HEX")"
  elif [[ -n "$VERIFIER_KEY_FILE" ]]; then
    [[ -f "$VERIFIER_KEY_FILE" ]] || {
      printf 'rn_bootstrap_macos.sh: FATAL: verifier key file not found: %s\n' "$VERIFIER_KEY_FILE" >&2
      exit 1
    }
    refuse_payload_provenance "$VERIFIER_KEY_FILE" "verifier key file" "$archive_dir"
    key_args=(--pinned-verifier-key-file "$VERIFIER_KEY_FILE")
    key_env_assignment="$(printf 'RUSTYNET_RELEASE_PINNED_KEY_FILE=%q\n' "$VERIFIER_KEY_FILE")"
  else
    VERIFIER_KEY_HEX="${RUSTYNET_DEFAULT_RELEASE_VERIFIER_KEY_HEX}"
    printf 'rn_bootstrap_macos.sh: no explicit verifier key given; pinning the embedded default release key (AQ-247/OI-47)\n' >&2
    key_args=(--pinned-verifier-key-hex "$VERIFIER_KEY_HEX")
    key_env_assignment="$(printf 'RUSTYNET_RELEASE_PINNED_KEY_HEX=%q\n' "$VERIFIER_KEY_HEX")"
  fi

  # Manifest: explicit --release-manifest, else co-located
  # release-manifest.json next to the archive. The archive is required BY
  # NAME in the manifest (`--require-artifact` — a signed manifest that does
  # not list the archive is not acceptance of it, AQ-11 F3).
  if [[ -z "$RELEASE_MANIFEST_PATH" ]]; then
    RELEASE_MANIFEST_PATH="${archive_dir}/release-manifest.json"
  fi
  [[ -f "$RELEASE_MANIFEST_PATH" ]] || {
    printf 'rn_bootstrap_macos.sh: FATAL: signed release manifest not found: %s\n' "$RELEASE_MANIFEST_PATH"
    printf 'rn_bootstrap_macos.sh: the archive will NOT be extracted; pass --release-manifest or ship release-manifest.json next to the archive\n' >&2
    exit 1
  }

  # (No provenance refusal for the MANIFEST itself: by design it is
  # co-located with the archive in the payload directory — it is the thing
  # being checked, not a trust anchor. The trust anchors are the out-of-band
  # verifier CLI and the pinned key, both refused above if payload-sourced.)
  # AQ-11 N-A: stage FIRST, verify the STAGED copy, consume only the staged
  # copy. The stage is a fresh root-owned 0700 directory under the sticky
  # /private/var/tmp and the copy inside is root-owned 0600, so after
  # staging no non-root process can even list the directory — the
  # verify-to-extract window (F5's shape, one level up) has no writable
  # surface for the local attacker who owned the received path. The shared
  # received path is read exactly once (by root, during staging) and never
  # touched again by this wrapper.
  printf 'rn_bootstrap_macos.sh: staging a root-owned 0700 private copy of %s BEFORE verification (AQ-11 N-A)\n' "$archive_name"
  RN_VERIFY_STAGE="$(sudo -n mktemp -d /private/var/tmp/rn-verify-XXXXXXXX)"
  sudo -n chmod 0700 "$RN_VERIFY_STAGE"
  sudo -n install -m 0600 "$SOURCE_ARCHIVE_PATH" "${RN_VERIFY_STAGE}/${archive_name}"

  printf 'rn_bootstrap_macos.sh: verifying the staged private copy (signed manifest + digests, required by name) BEFORE extraction\n'
  if ! sudo -n "$verify_cli" ops verify-release-manifest \
      --manifest "$RELEASE_MANIFEST_PATH" \
      --artifacts-dir "$RN_VERIFY_STAGE" \
      --require-artifact "$archive_name" \
      "${key_args[@]}"; then
    printf 'rn_bootstrap_macos.sh: FATAL: source archive FAILED signed-release verification — refusing to extract or execute it (AQ-11 F1: verify-before-extract)\n' >&2
    exit 1
  fi

  # AQ-11 N-B (v2): capability probe — BEHAVIOURAL, not advertisement. The
  # verification above PASSED, so this proves the verifier binary actually
  # ENFORCES --require-artifact: re-run the real verify (same staged
  # manifest, same pinned key) with --require-artifact set to a fixed name
  # that is never listed in any signed manifest, and accept the CLI only if
  # it fails with the exact unlisted-artifact refusal the enforcing CLI
  # prints (crates/rustynet-cli/src/ops_release_manifest.rs; the CLI checks
  # the manifest signature BEFORE the required-artifact list, so the probe
  # is deterministic). Any other outcome — success (a build that silently
  # ignores unknown options: the passed verification above was a FALSE pass
  # with no by-name binding), a different error, a usage error — means the
  # flag is not enforced and the F3 binding would evaporate; refuse BEFORE
  # extraction. (An earlier revision grepped `--help` output for the flag;
  # the AQ-11 N-B review found advertisement is not enforcement — and no
  # shipped build printed subcommand help at all. The probe must NOT depend
  # on `--help`.) A verifier that fakes the refusal while ignoring real
  # enforcement would defeat ANY fixed-name probe — but that is a MALICIOUS
  # verifier, out of scope: the verifier binary itself is the trust anchor
  # and is provisioned out-of-band with provenance refusals (AQ-11 F1/F4).
  # Kept on ONE line carrying the probe-name token so the hardening gate can
  # exclude it from its exactly-one-runtime-verify count without weakening.
  local probe_output
  probe_output="$(sudo -n "$verify_cli" ops verify-release-manifest --manifest "$RELEASE_MANIFEST_PATH" --artifacts-dir "$RN_VERIFY_STAGE" "${key_args[@]}" --require-artifact "__rustynet_require_artifact_probe__" 2>&1 || true)"
  case "${probe_output}" in
    *"required artifact '__rustynet_require_artifact_probe__' is not listed in the signed manifest"*) ;;
    *)
      printf 'rn_bootstrap_macos.sh: capability-probe output: %s\n' "${probe_output}" >&2
      printf 'rn_bootstrap_macos.sh: FATAL: verifier CLI does not enforce --require-artifact (behavioural probe expected the unlisted-artifact refusal); it cannot bind the payload by name (AQ-11 F3/N-B)\n' >&2
      printf 'rn_bootstrap_macos.sh: upgrade the out-of-band verifier (%s) to a build that enforces --require-artifact, then re-run\n' "$verify_cli" >&2
      exit 1
      ;;
  esac

  VERIFY_RESOLVED_CLI="$verify_cli"
  VERIFY_RESOLVED_MANIFEST="$RELEASE_MANIFEST_PATH"
  VERIFY_RESOLVED_KEY_ASSIGNMENT="$key_env_assignment"
  VERIFY_STAGED_ARCHIVE="${RN_VERIFY_STAGE}/${archive_name}"
}

# AQ-11 N-A: the private staging copy is removed on every exit path (the
# stage is root-owned, so the cleanup is a privileged rm). `|| true` keeps a
# best-effort cleanup failure from masking the run's exit status.
RN_VERIFY_STAGE=""
cleanup_verify_stage() {
  if [[ -n "${RN_VERIFY_STAGE}" ]]; then
    sudo -n rm -rf "${RN_VERIFY_STAGE}" || true
  fi
}
trap cleanup_verify_stage EXIT

VERIFY_RESOLVED_CLI=""
VERIFY_RESOLVED_MANIFEST=""
VERIFY_RESOLVED_KEY_ASSIGNMENT=""
VERIFY_STAGED_ARCHIVE=""
verify_source_archive

# ── Extract source archive (always fresh, AFTER verification) ────────────────
# rm + mkdir is idempotent: every run starts from a clean BUILD_DIR so a
# stale build tree from a previous bootstrap cannot mask a fresh source
# update. This `tar` runs as root and reads ONLY the root-owned 0700 staged
# private copy — never the shared received path (AQ-11 N-A: the verified
# object and the consumed object are the same root-owned file, so there is
# no verify-to-extract window on a shared path).
sudo -n rm -rf "$BUILD_DIR"
sudo -n mkdir -p "$BUILD_DIR"
sudo -n tar -xzf "$VERIFY_STAGED_ARCHIVE" -C "$BUILD_DIR"

BOOTSTRAP_SCRIPT="$BUILD_DIR/scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh"
if [[ ! -f "$BOOTSTRAP_SCRIPT" ]]; then
  printf 'rn_bootstrap_macos.sh: bootstrap script missing after extract: %s\n' \
    "$BOOTSTRAP_SCRIPT" >&2
  exit 1
fi

# ── Write env file consumed by Bootstrap-RustyNetMacos.sh ────────────────────
# Bootstrap-RustyNetMacos.sh sources this file (line 43); the variables
# it reads are: ROLE, DAEMON_NODE_ROLE, NODE_ID, NETWORK_ID,
# SSH_ALLOW_CIDRS, SOURCE_ARCHIVE, the optional SKIP_BUILD /
# WG_INTERFACE overrides, and — since AQ-11 F1/F4 — the RESOLVED release-
# verification inputs (RUSTYNET_VERIFY_CLI, RUSTYNET_RELEASE_MANIFEST and
# the pinned key) so the bootstrap verifies under the exact same out-of-band
# verifier + key this wrapper used, never an ambient env value.
#
# We deliberately write each KEY=VALUE pair via printf with %q so any
# adversarial characters that made it past validation above still get
# shell-escaped inside the env file (defence in depth — the env file is
# `source`d, not parsed as KV).
write_env_assignment() {
  local key="$1"
  local value="$2"
  printf '%s=%q\n' "$key" "$value"
}

{
  printf '# rn_bootstrap_macos.sh — generated for node %q on %s\n' \
    "$NODE_ID" "$(date -u +%FT%TZ)"
  write_env_assignment "ROLE" "$NODE_ROLE"
  write_env_assignment "DAEMON_NODE_ROLE" "$DAEMON_NODE_ROLE"
  write_env_assignment "NODE_ID" "$NODE_ID"
  write_env_assignment "NETWORK_ID" "$NETWORK_ID"
  write_env_assignment "SSH_ALLOW_CIDRS" "$SSH_ALLOW_CIDRS"
  # AQ-11 N-A: forward the STAGED copy's path, not the shared received
  # path, so the bootstrap verifies and consumes the exact root-owned bytes
  # this wrapper verified (the stage is root 0700 — nothing else can touch
  # it while the bootstrap runs).
  write_env_assignment "SOURCE_ARCHIVE" "$VERIFY_STAGED_ARCHIVE"
  write_env_assignment "WG_INTERFACE" "$WG_INTERFACE"
  # AQ-11 F1/F4: forward the RESOLVED verification inputs (out-of-band
  # verifier CLI, signed manifest, pinned key) so the bootstrap's deeper
  # verification uses the same trust anchors, immune to ambient env.
  write_env_assignment "RUSTYNET_VERIFY_CLI" "$VERIFY_RESOLVED_CLI"
  write_env_assignment "RUSTYNET_RELEASE_MANIFEST" "$VERIFY_RESOLVED_MANIFEST"
  printf '%s' "$VERIFY_RESOLVED_KEY_ASSIGNMENT"
} > "$ENV_FILE_PATH"
chmod 0600 "$ENV_FILE_PATH"

# ── Invoke the reviewed bootstrap ───────────────────────────────────────────
# argv-only exec via sudo + bash; no shell construction of the script
# path or env file path (both are absolute, validated).
sudo -n bash "$BOOTSTRAP_SCRIPT" "$ENV_FILE_PATH"

# ── Poll for the daemon socket ──────────────────────────────────────────────
#
# Mirrors `wait_for_macos_daemon_socket` in macos_install.rs:
# launchctl bootstrap returns before the daemon binds its socket, so the
# next orchestrator stage (collect_pubkeys) must not start until the
# socket file is present. 40 iterations × 1 s matches the Rust adapter.
wait_for_macos_daemon_socket() {
  local socket="/private/var/run/rustynet/rustynetd.sock"
  local attempt
  for attempt in $(seq 1 40); do
    if sudo -n test -S "$socket"; then
      printf 'rn_bootstrap_macos.sh: daemon socket ready at %s (attempt %d)\n' \
        "$socket" "$attempt"
      return 0
    fi
    sleep 1
  done
  printf 'rn_bootstrap_macos.sh: daemon socket %s did not appear within 40 s of bootstrap completion\n' \
    "$socket" >&2
  return 1
}

wait_for_macos_daemon_socket
exit 0
