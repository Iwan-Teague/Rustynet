#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

require_command() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "missing required command: ${cmd}" >&2
    exit 1
  fi
}

require_command cargo
require_command git
require_command python3

./scripts/ci/run_required_test.sh rustynet-control operations::tests::redaction_covers_all_ingestion_paths
./scripts/ci/run_required_test.sh rustynet-control operations::tests::structured_logger_never_writes_cleartext_secrets
./scripts/ci/run_required_test.sh rustynet-control token_claims_debug_redacts_sensitive_fields
./scripts/ci/run_required_test.sh rustynet-control throwaway_credential_debug_redacts_sensitive_fields

./scripts/ci/run_required_test.sh rustynetd daemon::tests::validate_file_security_rejects_group_writable_parent_directory
./scripts/ci/run_required_test.sh rustynetd daemon::tests::validate_file_security_rejects_symlink_parent_directory
./scripts/ci/run_required_test.sh rustynetd daemon::tests::passphrase_permission_mask_accepts_systemd_runtime_credential_mode
./scripts/ci/run_required_test.sh rustynetd key_material::tests::remove_file_if_present_removes_target_file
./scripts/ci/run_required_test.sh rustynetd key_material::tests::remove_file_if_present_rejects_directory
./scripts/ci/run_required_test.sh rustynetd key_material::tests::remove_file_if_present_removes_symlink_without_following_target

./scripts/ci/run_required_test.sh rustynet-cli signing_key_loader_rejects_group_readable_file
./scripts/ci/run_required_test.sh rustynet-cli signing_key_loader_rejects_symlink_path
./scripts/ci/run_required_test.sh rustynet-cli signing_key_loader_accepts_owner_only_file
./scripts/ci/run_required_test.sh rustynet-cli secure_remove_file_rejects_directory
./scripts/ci/run_required_test.sh rustynet-cli secure_remove_file_removes_target_file
./scripts/ci/run_required_test.sh rustynet-cli create_secure_temp_file_sets_owner_only_mode

python3 - "$ROOT_DIR" <<'PY'
import re
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()


def fail(summary: str, details: list[str]) -> None:
    print(f"[secrets-hygiene] {summary}", file=sys.stderr)
    for detail in details[:20]:
        print(f"  - {detail}", file=sys.stderr)
    if len(details) > 20:
        print(f"  - ... {len(details) - 20} additional violation(s)", file=sys.stderr)
    raise SystemExit(1)


tracked_raw = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"])
tracked_files = [
    Path(entry.decode("utf-8"))
    for entry in tracked_raw.split(b"\0")
    if entry
]

runtime_secret_basenames = {
    "membership.owner.key",
    "trust-evidence.key",
    "assignment.signing.secret",
    "wireguard.passphrase",
    "wireguard.key",
}

tracked_secret_artifacts = sorted(
    path.as_posix()
    for path in tracked_files
    if path.name in runtime_secret_basenames
)
if tracked_secret_artifacts:
    fail(
        "tracked plaintext runtime secret artifacts are forbidden",
        tracked_secret_artifacts,
    )

excluded_roots = {".git", "target", ".cargo-home", ".ci-home"}
workspace_secret_artifacts: list[str] = []
for candidate in root.rglob("*"):
    if not candidate.is_file():
        continue
    relative = candidate.relative_to(root)
    if any(part in excluded_roots for part in relative.parts):
        continue
    if candidate.name in runtime_secret_basenames:
        workspace_secret_artifacts.append(relative.as_posix())
if workspace_secret_artifacts:
    fail(
        "workspace contains runtime plaintext secret artifacts (must be encrypted-at-rest or removed)",
        sorted(workspace_secret_artifacts),
    )

artifact_suffixes = {".json", ".log", ".ndjson", ".txt", ".env"}
artifact_roots = [root / "artifacts", root / "tmp", root / "tmpcfg"]
leak_patterns = [
    ("private-key-block", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE)),
    (
        "secret-assignment",
        re.compile(
            r"(?i)\b(passphrase|password|api[_-]?key|secret|token)\b.{0,24}[:=]\s*[\"']?[A-Za-z0-9+/=_-]{16,}"
        ),
    ),
    ("bearer-token", re.compile(r"\bBearer\s+[A-Za-z0-9._~-]{20,}\b", re.IGNORECASE)),
]

artifact_leaks: list[str] = []
for artifact_root in artifact_roots:
    if not artifact_root.exists():
        continue
    for candidate in artifact_root.rglob("*"):
        if not candidate.is_file() or candidate.name == ".gitkeep":
            continue
        if candidate.suffix.lower() not in artifact_suffixes:
            continue
        relative = candidate.relative_to(root).as_posix()
        text = candidate.read_text(encoding="utf-8", errors="ignore")
        for label, pattern in leak_patterns:
            match = pattern.search(text)
            if match:
                excerpt = match.group(0).strip().replace("\n", " ")[:80]
                artifact_leaks.append(f"{relative} [{label}] -> {excerpt}")
                break
if artifact_leaks:
    fail("artifact/log leak scan detected possible secrets", sorted(artifact_leaks))

inline_secret_argv_patterns = [
    re.compile(r"--passphrase(?!-file\b)"),
    re.compile(r"--password\b"),
    re.compile(r"--secret-value\b"),
    re.compile(r"--token-value\b"),
]
argv_scan_files = [
    path
    for path in tracked_files
    if path.suffix in {".rs", ".sh", ".service", ".timer"}
]
argv_violations: list[str] = []
for relative_path in argv_scan_files:
    relative_str = relative_path.as_posix()
    if relative_str == "scripts/ci/secrets_hygiene_gates.sh":
        continue
    body = (root / relative_path).read_text(encoding="utf-8", errors="ignore")
    lines = body.splitlines()
    for pattern in inline_secret_argv_patterns:
        for match in pattern.finditer(body):
            line_no = body.count("\n", 0, match.start()) + 1
            line = lines[line_no - 1].strip() if line_no - 1 < len(lines) else ""
            argv_violations.append(
                f"{relative_str}:{line_no} contains forbidden inline secret argv flag ({pattern.pattern}) -> {line}"
            )
if argv_violations:
    fail("inline secret argv flags detected", sorted(argv_violations))

shell_files = [path for path in tracked_files if path.suffix == ".sh"]
rm_sensitive_pattern = re.compile(
    r"\brm\s+-f\b[^\n]*(membership\.owner\.key|trust-evidence\.key|assignment\.signing\.secret|wireguard\.passphrase|wireguard\.key)"
)
rm_violations: list[str] = []
for relative_path in shell_files:
    relative_str = relative_path.as_posix()
    body = (root / relative_path).read_text(encoding="utf-8", errors="ignore")
    lines = body.splitlines()
    for match in rm_sensitive_pattern.finditer(body):
        line_no = body.count("\n", 0, match.start()) + 1
        line = lines[line_no - 1].strip() if line_no - 1 < len(lines) else ""
        rm_violations.append(f"{relative_str}:{line_no} -> {line}")
if rm_violations:
    fail("shell scripts use rm -f on sensitive key/passphrase artifacts", sorted(rm_violations))

mktemp_pattern = re.compile(r"(?m)^\s*(?:local\s+)?([A-Za-z_][A-Za-z0-9_]*)=\$\(mktemp\)\s*$")
mktemp_violations: list[str] = []
for relative_path in shell_files:
    relative_str = relative_path.as_posix()
    body = (root / relative_path).read_text(encoding="utf-8", errors="ignore")
    for match in mktemp_pattern.finditer(body):
        var_name = match.group(1)
        if not re.search(r"(?i)(passphrase|secret|private|signing)", var_name):
            continue
        line_no = body.count("\n", 0, match.start()) + 1
        escaped_var = re.escape(var_name)
        chmod_pattern = re.compile(
            rf"\b(?:run_root\s+)?chmod\s+600\s+\"\$\{{{escaped_var}\}}\""
        )
        cleanup_pattern = re.compile(
            rf"(secure_remove_file_with_scope|secure_remove_file)\s+\"\$\{{{escaped_var}\}}\""
        )
        if not chmod_pattern.search(body):
            mktemp_violations.append(
                f"{relative_str}:{line_no} missing chmod 600 for mktemp secret variable {var_name}"
            )
        if not cleanup_pattern.search(body):
            mktemp_violations.append(
                f"{relative_str}:{line_no} missing secure-remove cleanup for mktemp secret variable {var_name}"
            )
if mktemp_violations:
    fail("mktemp secret handling is missing strict tmp-mode or secure cleanup", sorted(mktemp_violations))
PY

echo "Secrets hygiene gate: PASS"
