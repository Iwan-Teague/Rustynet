#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

EXIT_HOST=""
CLIENT_HOST=""
SSH_USER="root"
SSH_PORT="22"
SSH_IDENTITY=""
SSH_ALLOW_CIDRS=""
EXIT_NODE_ID="exit-node"
CLIENT_NODE_ID="client-node"
NETWORK_ID="local-net"
REMOTE_ROOT="/opt/rustynet-clean"
REPO_REF="HEAD"
SKIP_APT="0"
REPORT_PATH="${ROOT_DIR}/artifacts/phase10/debian_two_node_remote_validation.md"

usage() {
  cat <<USAGE
Usage:
  $(basename "$0") \\
    --exit-host <host|user@host> \\
    --client-host <host|user@host> \\
    --ssh-allow-cidrs <cidr[,cidr...]> \\
    [--ssh-user <user>] \\
    [--ssh-port <port>] \\
    [--ssh-identity <path>] \\
    [--exit-node-id <id>] \\
    [--client-node-id <id>] \\
    [--network-id <id>] \\
    [--remote-root <abs-path>] \\
    [--repo-ref <git-ref>] \\
    [--skip-apt] \\
    [--report-path <abs-path>]

Notes:
- The script opens SSH control-master sessions (interactive password prompts are supported).
- Rustynet-only firewall tables are cleaned; non-Rustynet nftables state is preserved.
- Auto-tunnel enforcement is enabled only after signed bundles are issued and distributed.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --exit-host)
      EXIT_HOST="$2"
      shift 2
      ;;
    --client-host)
      CLIENT_HOST="$2"
      shift 2
      ;;
    --ssh-user)
      SSH_USER="$2"
      shift 2
      ;;
    --ssh-port)
      SSH_PORT="$2"
      shift 2
      ;;
    --ssh-identity)
      SSH_IDENTITY="$2"
      shift 2
      ;;
    --ssh-allow-cidrs)
      SSH_ALLOW_CIDRS="$2"
      shift 2
      ;;
    --exit-node-id)
      EXIT_NODE_ID="$2"
      shift 2
      ;;
    --client-node-id)
      CLIENT_NODE_ID="$2"
      shift 2
      ;;
    --network-id)
      NETWORK_ID="$2"
      shift 2
      ;;
    --remote-root)
      REMOTE_ROOT="$2"
      shift 2
      ;;
    --repo-ref)
      REPO_REF="$2"
      shift 2
      ;;
    --skip-apt)
      SKIP_APT="1"
      shift 1
      ;;
    --report-path)
      REPORT_PATH="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "${EXIT_HOST}" || -z "${CLIENT_HOST}" || -z "${SSH_ALLOW_CIDRS}" ]]; then
  echo "--exit-host, --client-host, and --ssh-allow-cidrs are required" >&2
  usage >&2
  exit 1
fi

if [[ "${REMOTE_ROOT}" != /* ]]; then
  echo "--remote-root must be absolute" >&2
  exit 1
fi

if ! [[ "${SSH_PORT}" =~ ^[0-9]+$ ]] || (( SSH_PORT < 1 || SSH_PORT > 65535 )); then
  echo "--ssh-port must be an integer in range 1-65535" >&2
  exit 1
fi

require_safe_token() {
  local label="$1"
  local value="$2"
  if [[ ! "${value}" =~ ^[A-Za-z0-9._:/,@+-]+$ ]]; then
    echo "${label} contains unsupported characters: ${value}" >&2
    exit 1
  fi
}

for pair in \
  "exit-node-id:${EXIT_NODE_ID}" \
  "client-node-id:${CLIENT_NODE_ID}" \
  "network-id:${NETWORK_ID}" \
  "remote-root:${REMOTE_ROOT}" \
  "ssh-allow-cidrs:${SSH_ALLOW_CIDRS}"; do
  require_safe_token "${pair%%:*}" "${pair#*:}"
done

if [[ -n "${SSH_IDENTITY}" && ! -f "${SSH_IDENTITY}" ]]; then
  echo "--ssh-identity does not exist: ${SSH_IDENTITY}" >&2
  exit 1
fi

for tool in git ssh tar awk sed grep cut mktemp date; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "missing required local command: ${tool}" >&2
    exit 1
  fi
done

if ! git -C "${ROOT_DIR}" rev-parse --verify "${REPO_REF}^{commit}" >/dev/null 2>&1; then
  echo "invalid git ref: ${REPO_REF}" >&2
  exit 1
fi
COMMIT_SHA="$(git -C "${ROOT_DIR}" rev-parse --short "${REPO_REF}^{commit}")"

qualify_host() {
  local raw="$1"
  if [[ "${raw}" == *"@"* ]]; then
    printf '%s' "${raw}"
    return
  fi
  printf '%s@%s' "${SSH_USER}" "${raw}"
}

host_address() {
  local qualified="$1"
  printf '%s' "${qualified##*@}"
}

EXIT_TARGET="$(qualify_host "${EXIT_HOST}")"
CLIENT_TARGET="$(qualify_host "${CLIENT_HOST}")"
EXIT_ADDR="$(host_address "${EXIT_TARGET}")"
CLIENT_ADDR="$(host_address "${CLIENT_TARGET}")"

TMP_DIR="$(mktemp -d "/tmp/rustynet-remote-e2e.XXXXXX")"
CONTROL_DIR="${TMP_DIR}/control"
KNOWN_HOSTS_FILE="${TMP_DIR}/known_hosts"
mkdir -p "${CONTROL_DIR}"
touch "${KNOWN_HOSTS_FILE}"

REMOTE_SRC_DIR="${REMOTE_ROOT}/src"

SSH_BASE_OPTS=(
  -o ConnectTimeout=20
  -o ServerAliveInterval=20
  -o ServerAliveCountMax=3
  -o StrictHostKeyChecking=accept-new
  -o UserKnownHostsFile="${KNOWN_HOSTS_FILE}"
  -o ControlMaster=auto
  -o ControlPersist=600
  -o ControlPath="${CONTROL_DIR}/%C"
  -p "${SSH_PORT}"
)
if [[ -n "${SSH_IDENTITY}" ]]; then
  SSH_BASE_OPTS+=( -i "${SSH_IDENTITY}" -o IdentitiesOnly=yes )
fi

OPEN_MASTERS=()
cleanup() {
  set +e
  for host in "${OPEN_MASTERS[@]-}"; do
    [[ -n "${host}" ]] || continue
    ssh "${SSH_BASE_OPTS[@]}" -O exit "${host}" >/dev/null 2>&1 || true
  done
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

log() {
  printf '[debian-pair-e2e] %s\n' "$*"
}

open_master() {
  local host="$1"
  log "Opening SSH control master: ${host}"
  ssh "${SSH_BASE_OPTS[@]}" "${host}" true
  OPEN_MASTERS+=("${host}")
}

ssh_run() {
  local host="$1"
  shift
  ssh "${SSH_BASE_OPTS[@]}" "${host}" "$@"
}

ssh_capture() {
  local host="$1"
  shift
  ssh "${SSH_BASE_OPTS[@]}" "${host}" "$@"
}

copy_local_archive_to_host() {
  local host="$1"
  log "Syncing source archive to ${host} (${REPO_REF} -> ${REMOTE_SRC_DIR})"
  git -C "${ROOT_DIR}" archive --format=tar "${REPO_REF}" \
    | ssh "${SSH_BASE_OPTS[@]}" "${host}" "set -euo pipefail; rm -rf '${REMOTE_SRC_DIR}'; install -d -m 0755 '${REMOTE_SRC_DIR}'; tar -xf - -C '${REMOTE_SRC_DIR}'"
}

BOOTSTRAP_SCRIPT="${TMP_DIR}/remote_bootstrap.sh"
cat > "${BOOTSTRAP_SCRIPT}" <<'REMOTE_BOOTSTRAP'
#!/usr/bin/env bash
set -euo pipefail

role="$1"
node_id="$2"
network_id="$3"
src_dir="$4"
ssh_allow_cidrs="$5"
skip_apt="$6"

export DEBIAN_FRONTEND=noninteractive
export PATH="$HOME/.cargo/bin:${PATH}"

if [[ "${skip_apt}" != "1" ]]; then
  apt-get update
  apt-get install -y --no-install-recommends \
    ca-certificates curl git build-essential pkg-config \
    libssl-dev libsqlite3-dev clang llvm nftables wireguard-tools openssl
fi

if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi

for svc in \
  rustynetd.service \
  rustynetd-privileged-helper.service \
  rustynetd-trust-refresh.service \
  rustynetd-trust-refresh.timer; do
  systemctl disable --now "${svc}" >/dev/null 2>&1 || true
done

pkill -f "rustynetd daemon" >/dev/null 2>&1 || true
pkill -f "rustynetd privileged-helper" >/dev/null 2>&1 || true
ip link delete rustynet0 >/dev/null 2>&1 || true

if command -v nft >/dev/null 2>&1; then
  nft list tables 2>/dev/null \
    | awk '/^table/ && $3 ~ /^rustynet/ {print $2" "$3}' \
    | while read -r family table_name; do
        nft delete table "${family}" "${table_name}" >/dev/null 2>&1 || true
      done
fi

rm -rf /etc/rustynet /var/lib/rustynet /run/rustynet

if [[ ! -d "${src_dir}" ]]; then
  echo "missing source dir: ${src_dir}" >&2
  exit 1
fi

cd "${src_dir}"
cargo build --release -p rustynetd -p rustynet-cli
install -m 0755 target/release/rustynetd /usr/local/bin/rustynetd
install -m 0755 target/release/rustynet-cli /usr/local/bin/rustynet

install -d -m 0700 /etc/rustynet/credentials
install -d -m 0700 /var/lib/rustynet/keys
install -d -m 0700 /run/rustynet

passphrase_tmp="$(mktemp /tmp/rustynet-passphrase.XXXXXX)"
cleanup_passphrase() {
  if [[ -f "${passphrase_tmp}" ]]; then
    if command -v shred >/dev/null 2>&1; then
      shred --force --remove "${passphrase_tmp}" >/dev/null 2>&1 || true
    else
      : >"${passphrase_tmp}" || true
      rm -f "${passphrase_tmp}" || true
    fi
  fi
}
trap cleanup_passphrase EXIT

openssl rand -hex 48 >"${passphrase_tmp}"
chmod 0600 "${passphrase_tmp}"

rustynetd key init \
  --runtime-private-key /run/rustynet/wireguard.key \
  --encrypted-private-key /var/lib/rustynet/keys/wireguard.key.enc \
  --public-key /var/lib/rustynet/keys/wireguard.pub \
  --passphrase-file "${passphrase_tmp}" \
  --force

systemd-creds encrypt --name=wg_key_passphrase "${passphrase_tmp}" /etc/rustynet/credentials/wg_key_passphrase.cred
chown root:root /etc/rustynet/credentials/wg_key_passphrase.cred
chmod 0600 /etc/rustynet/credentials/wg_key_passphrase.cred
rm -f /run/rustynet/wireguard.key

rustynetd membership init \
  --snapshot /var/lib/rustynet/membership.snapshot \
  --log /var/lib/rustynet/membership.log \
  --watermark /var/lib/rustynet/membership.watermark \
  --owner-signing-key /etc/rustynet/membership.owner.key \
  --node-id "${node_id}" \
  --network-id "${network_id}" \
  --force

openssl genpkey -algorithm ED25519 -out /etc/rustynet/trust-evidence.key
chmod 0600 /etc/rustynet/trust-evidence.key
openssl pkey -in /etc/rustynet/trust-evidence.key -pubout -outform DER 2>/dev/null \
  | tail -c 32 \
  | xxd -p -c 32 >/etc/rustynet/trust-evidence.pub
chmod 0644 /etc/rustynet/trust-evidence.pub

RUSTYNET_TRUST_EVIDENCE=/var/lib/rustynet/rustynetd.trust \
RUSTYNET_TRUST_SIGNER_KEY=/etc/rustynet/trust-evidence.key \
RUSTYNET_DAEMON_GROUP=rustynetd \
RUSTYNET_TRUST_AUTO_REFRESH=true \
"${src_dir}/scripts/systemd/refresh_trust_evidence.sh"

RUSTYNET_NODE_ID="${node_id}" \
RUSTYNET_NODE_ROLE="${role}" \
RUSTYNET_TRUST_AUTO_REFRESH=true \
RUSTYNET_AUTO_TUNNEL_ENFORCE=false \
RUSTYNET_WG_LISTEN_PORT=51820 \
RUSTYNET_FAIL_CLOSED_SSH_ALLOW=true \
RUSTYNET_FAIL_CLOSED_SSH_ALLOW_CIDRS="${ssh_allow_cidrs}" \
"${src_dir}/scripts/systemd/install_rustynetd_service.sh"
REMOTE_BOOTSTRAP
chmod 0700 "${BOOTSTRAP_SCRIPT}"

ENFORCE_SCRIPT="${TMP_DIR}/remote_enforce.sh"
cat > "${ENFORCE_SCRIPT}" <<'REMOTE_ENFORCE'
#!/usr/bin/env bash
set -euo pipefail

role="$1"
node_id="$2"
src_dir="$3"
ssh_allow_cidrs="$4"

auto_refresh="false"
if [[ -f /etc/rustynet/trust-evidence.key ]]; then
  auto_refresh="true"
fi

RUSTYNET_NODE_ID="${node_id}" \
RUSTYNET_NODE_ROLE="${role}" \
RUSTYNET_TRUST_AUTO_REFRESH="${auto_refresh}" \
RUSTYNET_AUTO_TUNNEL_ENFORCE=true \
RUSTYNET_WG_LISTEN_PORT=51820 \
RUSTYNET_FAIL_CLOSED_SSH_ALLOW=true \
RUSTYNET_FAIL_CLOSED_SSH_ALLOW_CIDRS="${ssh_allow_cidrs}" \
"${src_dir}/scripts/systemd/install_rustynetd_service.sh"
REMOTE_ENFORCE
chmod 0700 "${ENFORCE_SCRIPT}"

MEMBERSHIP_SCRIPT="${TMP_DIR}/remote_membership_add.sh"
cat > "${MEMBERSHIP_SCRIPT}" <<'REMOTE_MEMBERSHIP'
#!/usr/bin/env bash
set -euo pipefail

client_node_id="$1"
client_pubkey="$2"
owner_approver_id="$3"

work_dir="$(mktemp -d /tmp/rustynet-membership-update.XXXXXX)"
cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

record_path="${work_dir}/add.record"
signed_path="${work_dir}/add.signed"

rustynet membership propose-add \
  --node-id "${client_node_id}" \
  --node-pubkey "${client_pubkey}" \
  --owner "${client_node_id}" \
  --output "${record_path}" \
  --snapshot /var/lib/rustynet/membership.snapshot \
  --log /var/lib/rustynet/membership.log

rustynet membership sign-update \
  --record "${record_path}" \
  --approver-id "${owner_approver_id}" \
  --signing-key /etc/rustynet/membership.owner.key \
  --output "${signed_path}"

rustynet membership apply-update \
  --signed-update "${signed_path}" \
  --snapshot /var/lib/rustynet/membership.snapshot \
  --log /var/lib/rustynet/membership.log
REMOTE_MEMBERSHIP
chmod 0700 "${MEMBERSHIP_SCRIPT}"

ASSIGNMENT_SCRIPT="${TMP_DIR}/remote_issue_assignments.sh"
cat > "${ASSIGNMENT_SCRIPT}" <<'REMOTE_ASSIGNMENT'
#!/usr/bin/env bash
set -euo pipefail

exit_node_id="$1"
client_node_id="$2"
exit_endpoint="$3"
client_endpoint="$4"
exit_pubkey="$5"
client_pubkey="$6"

secret_path="/etc/rustynet/assignment.signing.secret"
if [[ ! -f "${secret_path}" ]]; then
  openssl rand -hex 32 >"${secret_path}"
  chown root:root "${secret_path}"
  chmod 0600 "${secret_path}"
fi

nodes_spec="${exit_node_id}|${exit_endpoint}|${exit_pubkey};${client_node_id}|${client_endpoint}|${client_pubkey}"
allow_spec="${client_node_id}|${exit_node_id};${exit_node_id}|${client_node_id}"

rustynet assignment issue \
  --target-node-id "${exit_node_id}" \
  --nodes "${nodes_spec}" \
  --allow "${allow_spec}" \
  --signing-secret "${secret_path}" \
  --output /tmp/rustynet-exit.assignment \
  --verifier-key-output /tmp/rustynet-assignment.pub \
  --ttl-secs 900

rustynet assignment issue \
  --target-node-id "${client_node_id}" \
  --nodes "${nodes_spec}" \
  --allow "${allow_spec}" \
  --signing-secret "${secret_path}" \
  --output /tmp/rustynet-client.assignment \
  --verifier-key-output /tmp/rustynet-assignment.pub \
  --exit-node-id "${exit_node_id}" \
  --ttl-secs 900
REMOTE_ASSIGNMENT
chmod 0700 "${ASSIGNMENT_SCRIPT}"

run_remote_script_with_args() {
  local host="$1"
  local script_path="$2"
  shift 2
  local args=()
  for arg in "$@"; do
    require_safe_token "remote-arg" "${arg}"
    args+=("'${arg}'")
  done
  # shellcheck disable=SC2086
  ssh "${SSH_BASE_OPTS[@]}" "${host}" "bash -se -- ${args[*]}" < "${script_path}"
}

copy_remote_file_to_local() {
  local host="$1"
  local remote_path="$2"
  local local_path="$3"
  ssh_capture "${host}" "cat '${remote_path}'" > "${local_path}"
}

copy_local_file_to_remote() {
  local host="$1"
  local local_path="$2"
  local remote_path="$3"
  local owner_user="$4"
  local owner_group="$5"
  local mode="$6"
  cat "${local_path}" | ssh_run "${host}" "install -D -m ${mode} -o ${owner_user} -g ${owner_group} /dev/stdin '${remote_path}'"
}

retry_ssh_command() {
  local host="$1"
  local attempts="$2"
  local sleep_secs="$3"
  shift 3
  local n=1
  while (( n <= attempts )); do
    if ssh_run "${host}" "$@"; then
      return 0
    fi
    sleep "${sleep_secs}"
    n=$((n + 1))
  done
  return 1
}

open_master "${EXIT_TARGET}"
open_master "${CLIENT_TARGET}"

copy_local_archive_to_host "${EXIT_TARGET}"
copy_local_archive_to_host "${CLIENT_TARGET}"

log "Bootstrapping exit node on ${EXIT_TARGET}"
run_remote_script_with_args \
  "${EXIT_TARGET}" "${BOOTSTRAP_SCRIPT}" \
  "admin" "${EXIT_NODE_ID}" "${NETWORK_ID}" "${REMOTE_SRC_DIR}" "${SSH_ALLOW_CIDRS}" "${SKIP_APT}"

log "Bootstrapping client node on ${CLIENT_TARGET}"
run_remote_script_with_args \
  "${CLIENT_TARGET}" "${BOOTSTRAP_SCRIPT}" \
  "client" "${CLIENT_NODE_ID}" "${NETWORK_ID}" "${REMOTE_SRC_DIR}" "${SSH_ALLOW_CIDRS}" "${SKIP_APT}"

EXIT_WG_PUB="$(ssh_capture "${EXIT_TARGET}" "cat /var/lib/rustynet/keys/wireguard.pub" | tr -d '[:space:]')"
CLIENT_WG_PUB="$(ssh_capture "${CLIENT_TARGET}" "cat /var/lib/rustynet/keys/wireguard.pub" | tr -d '[:space:]')"
if [[ -z "${EXIT_WG_PUB}" || -z "${CLIENT_WG_PUB}" ]]; then
  echo "failed to collect wireguard public keys" >&2
  exit 1
fi

log "Applying signed membership update for client node"
run_remote_script_with_args \
  "${EXIT_TARGET}" "${MEMBERSHIP_SCRIPT}" \
  "${CLIENT_NODE_ID}" "${CLIENT_WG_PUB}" "${EXIT_NODE_ID}-owner"

MEMBERSHIP_SNAPSHOT_LOCAL="${TMP_DIR}/membership.snapshot"
MEMBERSHIP_LOG_LOCAL="${TMP_DIR}/membership.log"
copy_remote_file_to_local "${EXIT_TARGET}" "/var/lib/rustynet/membership.snapshot" "${MEMBERSHIP_SNAPSHOT_LOCAL}"
copy_remote_file_to_local "${EXIT_TARGET}" "/var/lib/rustynet/membership.log" "${MEMBERSHIP_LOG_LOCAL}"

copy_local_file_to_remote "${CLIENT_TARGET}" "${MEMBERSHIP_SNAPSHOT_LOCAL}" "/var/lib/rustynet/membership.snapshot" "rustynetd" "rustynetd" "0600"
copy_local_file_to_remote "${CLIENT_TARGET}" "${MEMBERSHIP_LOG_LOCAL}" "/var/lib/rustynet/membership.log" "rustynetd" "rustynetd" "0600"
ssh_run "${CLIENT_TARGET}" "rm -f /var/lib/rustynet/membership.watermark"

log "Issuing signed auto-tunnel assignments"
run_remote_script_with_args \
  "${EXIT_TARGET}" "${ASSIGNMENT_SCRIPT}" \
  "${EXIT_NODE_ID}" "${CLIENT_NODE_ID}" "${EXIT_ADDR}:51820" "${CLIENT_ADDR}:51820" "${EXIT_WG_PUB}" "${CLIENT_WG_PUB}"

ASSIGNMENT_PUB_LOCAL="${TMP_DIR}/assignment.pub"
ASSIGNMENT_EXIT_LOCAL="${TMP_DIR}/exit.assignment"
ASSIGNMENT_CLIENT_LOCAL="${TMP_DIR}/client.assignment"

copy_remote_file_to_local "${EXIT_TARGET}" "/tmp/rustynet-assignment.pub" "${ASSIGNMENT_PUB_LOCAL}"
copy_remote_file_to_local "${EXIT_TARGET}" "/tmp/rustynet-exit.assignment" "${ASSIGNMENT_EXIT_LOCAL}"
copy_remote_file_to_local "${EXIT_TARGET}" "/tmp/rustynet-client.assignment" "${ASSIGNMENT_CLIENT_LOCAL}"

copy_local_file_to_remote "${EXIT_TARGET}" "${ASSIGNMENT_PUB_LOCAL}" "/etc/rustynet/assignment.pub" "root" "root" "0644"
copy_local_file_to_remote "${EXIT_TARGET}" "${ASSIGNMENT_EXIT_LOCAL}" "/var/lib/rustynet/rustynetd.assignment" "root" "rustynetd" "0640"

copy_local_file_to_remote "${CLIENT_TARGET}" "${ASSIGNMENT_PUB_LOCAL}" "/etc/rustynet/assignment.pub" "root" "root" "0644"
copy_local_file_to_remote "${CLIENT_TARGET}" "${ASSIGNMENT_CLIENT_LOCAL}" "/var/lib/rustynet/rustynetd.assignment" "root" "rustynetd" "0640"

ssh_run "${EXIT_TARGET}" "rm -f /var/lib/rustynet/rustynetd.assignment.watermark /tmp/rustynet-assignment.pub /tmp/rustynet-exit.assignment /tmp/rustynet-client.assignment"
ssh_run "${CLIENT_TARGET}" "rm -f /var/lib/rustynet/rustynetd.assignment.watermark"

log "Enabling auto-tunnel enforcement on both hosts"
run_remote_script_with_args \
  "${EXIT_TARGET}" "${ENFORCE_SCRIPT}" \
  "admin" "${EXIT_NODE_ID}" "${REMOTE_SRC_DIR}" "${SSH_ALLOW_CIDRS}"
run_remote_script_with_args \
  "${CLIENT_TARGET}" "${ENFORCE_SCRIPT}" \
  "client" "${CLIENT_NODE_ID}" "${REMOTE_SRC_DIR}" "${SSH_ALLOW_CIDRS}"

log "Applying exit-node routing selection"
retry_ssh_command "${EXIT_TARGET}" 10 2 \
  "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 0.0.0.0/0"
retry_ssh_command "${CLIENT_TARGET}" 10 2 \
  "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet exit-node select '${EXIT_NODE_ID}'"
ssh_run "${CLIENT_TARGET}" "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet lan-access off >/dev/null 2>&1 || true"

sleep 3

EXIT_STATUS="$(ssh_capture "${EXIT_TARGET}" "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet status")"
CLIENT_STATUS="$(ssh_capture "${CLIENT_TARGET}" "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet status")"
CLIENT_ROUTE="$(ssh_capture "${CLIENT_TARGET}" "ip -4 route get 1.1.1.1 || true")"
EXIT_WG_SHOW="$(ssh_capture "${EXIT_TARGET}" "wg show rustynet0 || true")"
EXIT_NFT_RULESET="$(ssh_capture "${EXIT_TARGET}" "nft list ruleset || true")"
EXIT_TUNNEL_IP="$(ssh_capture "${EXIT_TARGET}" "ip -4 -o addr show dev rustynet0 | awk '{print \\$4}' | cut -d/ -f1 | head -n1" | tr -d '[:space:]')"

if [[ -n "${EXIT_TUNNEL_IP}" ]]; then
  ssh_run "${CLIENT_TARGET}" "ping -c 2 -W 2 '${EXIT_TUNNEL_IP}' >/dev/null"
fi

EXIT_HANDSHAKES="$(ssh_capture "${EXIT_TARGET}" "wg show rustynet0 latest-handshakes | awk '{print \\$2}'")"

CLIENT_PLAINTEXT_KEYS="$(ssh_capture "${CLIENT_TARGET}" "ls -1 /var/lib/rustynet/keys/wireguard.passphrase /etc/rustynet/wireguard.passphrase 2>/dev/null || true")"
EXIT_PLAINTEXT_KEYS="$(ssh_capture "${EXIT_TARGET}" "ls -1 /var/lib/rustynet/keys/wireguard.passphrase /etc/rustynet/wireguard.passphrase 2>/dev/null || true")"
CLIENT_CRED_MODE="$(ssh_capture "${CLIENT_TARGET}" "stat -c '%U:%G %a' /etc/rustynet/credentials/wg_key_passphrase.cred")"
EXIT_CRED_MODE="$(ssh_capture "${EXIT_TARGET}" "stat -c '%U:%G %a' /etc/rustynet/credentials/wg_key_passphrase.cred")"
CLIENT_KEY_MODE="$(ssh_capture "${CLIENT_TARGET}" "stat -c '%U:%G %a' /var/lib/rustynet/keys/wireguard.key.enc")"
EXIT_KEY_MODE="$(ssh_capture "${EXIT_TARGET}" "stat -c '%U:%G %a' /var/lib/rustynet/keys/wireguard.key.enc")"

FAIL_COUNT=0
CHECK_LINES=()

add_check() {
  local name="$1"
  local status="$2"
  local detail="$3"
  CHECK_LINES+=("| ${name} | ${status} | ${detail} |")
  if [[ "${status}" != "PASS" ]]; then
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

contains_or_fail() {
  local name="$1"
  local haystack="$2"
  local needle="$3"
  if grep -Fq "${needle}" <<<"${haystack}"; then
    add_check "${name}" "PASS" "found '${needle}'"
  else
    add_check "${name}" "FAIL" "missing '${needle}'"
  fi
}

contains_or_fail "exit-status-active" "${EXIT_STATUS}" "state=ExitActive"
contains_or_fail "exit-serving-enabled" "${EXIT_STATUS}" "serving_exit_node=true"
contains_or_fail "exit-not-restricted" "${EXIT_STATUS}" "restricted_safe_mode=false"
contains_or_fail "client-status-active" "${CLIENT_STATUS}" "state=ExitActive"
contains_or_fail "client-exit-selected" "${CLIENT_STATUS}" "exit_node=${EXIT_NODE_ID}"
contains_or_fail "client-not-restricted" "${CLIENT_STATUS}" "restricted_safe_mode=false"
contains_or_fail "client-route-via-tunnel" "${CLIENT_ROUTE}" "dev rustynet0"
contains_or_fail "exit-nat-masquerade" "${EXIT_NFT_RULESET}" "masquerade"
contains_or_fail "exit-forward-from-tunnel" "${EXIT_NFT_RULESET}" "iifname \"rustynet0\""

if [[ -n "${EXIT_TUNNEL_IP}" ]]; then
  add_check "exit-tunnel-ip" "PASS" "${EXIT_TUNNEL_IP}"
else
  add_check "exit-tunnel-ip" "FAIL" "unable to detect tunnel IP"
fi

if awk 'BEGIN {ok=0} $1+0>0 {ok=1} END {exit ok?0:1}' <<<"${EXIT_HANDSHAKES}"; then
  add_check "wg-latest-handshake" "PASS" "latest-handshakes includes non-zero timestamp"
else
  add_check "wg-latest-handshake" "FAIL" "no non-zero handshake timestamp observed"
fi

if [[ -z "${CLIENT_PLAINTEXT_KEYS}" && -z "${EXIT_PLAINTEXT_KEYS}" ]]; then
  add_check "no-plaintext-passphrase-files" "PASS" "legacy plaintext passphrase files absent"
else
  add_check "no-plaintext-passphrase-files" "FAIL" "found plaintext passphrase file(s)"
fi

if [[ "${CLIENT_CRED_MODE}" == "root:root 600" && "${EXIT_CRED_MODE}" == "root:root 600" ]]; then
  add_check "credential-blob-permissions" "PASS" "wg credential blob mode is 0600 root:root on both hosts"
else
  add_check "credential-blob-permissions" "FAIL" "client=${CLIENT_CRED_MODE}; exit=${EXIT_CRED_MODE}"
fi

if [[ "${CLIENT_KEY_MODE}" == "rustynetd:rustynetd 600" && "${EXIT_KEY_MODE}" == "rustynetd:rustynetd 600" ]]; then
  add_check "encrypted-key-permissions" "PASS" "encrypted key mode is 0600 rustynetd:rustynetd on both hosts"
else
  add_check "encrypted-key-permissions" "FAIL" "client=${CLIENT_KEY_MODE}; exit=${EXIT_KEY_MODE}"
fi

mkdir -p "$(dirname "${REPORT_PATH}")"
{
  echo "# Debian Two-Node Clean Install + Tunnel Validation"
  echo
  echo "- generated_at_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- commit: ${COMMIT_SHA}"
  echo "- exit_host: ${EXIT_TARGET}"
  echo "- client_host: ${CLIENT_TARGET}"
  echo "- exit_node_id: ${EXIT_NODE_ID}"
  echo "- client_node_id: ${CLIENT_NODE_ID}"
  echo "- network_id: ${NETWORK_ID}"
  echo "- ssh_allow_cidrs: ${SSH_ALLOW_CIDRS}"
  echo
  echo "## Checks"
  echo
  echo "| Check | Status | Detail |"
  echo "|---|---|---|"
  for line in "${CHECK_LINES[@]}"; do
    echo "${line}"
  done
  echo
  echo "## Exit Status"
  echo
  echo '```text'
  echo "${EXIT_STATUS}"
  echo '```'
  echo
  echo "## Client Status"
  echo
  echo '```text'
  echo "${CLIENT_STATUS}"
  echo '```'
  echo
  echo "## Client Route Check"
  echo
  echo '```text'
  echo "${CLIENT_ROUTE}"
  echo '```'
  echo
  echo "## Exit WireGuard"
  echo
  echo '```text'
  echo "${EXIT_WG_SHOW}"
  echo '```'
} > "${REPORT_PATH}"

if (( FAIL_COUNT > 0 )); then
  log "Validation failed with ${FAIL_COUNT} failing checks. See report: ${REPORT_PATH}"
  exit 1
fi

log "Validation passed. Report written to: ${REPORT_PATH}"
