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
SSH_SUDO_MODE="auto"
SUDO_PASSWORD_FILE=""
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
    [--ssh-sudo <auto|always|never>] \\
    [--sudo-password-file <path>] \\
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
- When host SSH user is non-root, sudo is required by default (`--ssh-sudo auto`).
- For passworded sudo, provide `--sudo-password-file` with mode 0600.
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
    --ssh-sudo)
      SSH_SUDO_MODE="$2"
      shift 2
      ;;
    --sudo-password-file)
      SUDO_PASSWORD_FILE="$2"
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

if [[ "${SSH_SUDO_MODE}" != "auto" && "${SSH_SUDO_MODE}" != "always" && "${SSH_SUDO_MODE}" != "never" ]]; then
  echo "--ssh-sudo must be one of: auto, always, never" >&2
  exit 1
fi

require_safe_token() {
  local label="$1"
  local value="$2"
  if [[ ! "${value}" =~ ^[A-Za-z0-9._:/,@+=-]+$ ]]; then
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

for tool in git ssh tar awk sed grep cut mktemp date head stat openssl xxd tr; do
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

target_user() {
  local target="$1"
  printf '%s' "${target%%@*}"
}

target_needs_sudo() {
  local target="$1"
  local user
  user="$(target_user "${target}")"
  case "${SSH_SUDO_MODE}" in
    always)
      return 0
      ;;
    never)
      return 1
      ;;
    auto)
      [[ "${user}" != "root" ]]
      return
      ;;
    *)
      return 1
      ;;
  esac
}

PASSWORD_REQUIRED="0"
if target_needs_sudo "${EXIT_TARGET}" || target_needs_sudo "${CLIENT_TARGET}"; then
  PASSWORD_REQUIRED="1"
fi

get_file_mode() {
  local path="$1"
  local mode=""
  if mode="$(stat -f '%Lp' "${path}" 2>/dev/null)"; then
    printf '%s' "${mode}"
    return 0
  fi
  if mode="$(stat -c '%a' "${path}" 2>/dev/null)"; then
    printf '%s' "${mode}"
    return 0
  fi
  return 1
}

SUDO_PASSWORD=""
if [[ "${PASSWORD_REQUIRED}" == "1" ]]; then
  if [[ -z "${SUDO_PASSWORD_FILE}" ]]; then
    echo "sudo is required for non-root SSH targets; provide --sudo-password-file" >&2
    exit 1
  fi
  if [[ ! -f "${SUDO_PASSWORD_FILE}" ]]; then
    echo "--sudo-password-file does not exist: ${SUDO_PASSWORD_FILE}" >&2
    exit 1
  fi
  if [[ -L "${SUDO_PASSWORD_FILE}" ]]; then
    echo "--sudo-password-file must not be a symlink: ${SUDO_PASSWORD_FILE}" >&2
    exit 1
  fi
  SUDO_FILE_MODE="$(get_file_mode "${SUDO_PASSWORD_FILE}" || true)"
  if [[ -n "${SUDO_FILE_MODE}" && "${SUDO_FILE_MODE}" != "600" ]]; then
    echo "--sudo-password-file must be mode 0600; found ${SUDO_FILE_MODE} (${SUDO_PASSWORD_FILE})" >&2
    exit 1
  fi
  SUDO_PASSWORD="$(head -n 1 "${SUDO_PASSWORD_FILE}")"
  if [[ -z "${SUDO_PASSWORD}" ]]; then
    echo "--sudo-password-file must contain a non-empty password on first line" >&2
    exit 1
  fi
fi

TMP_DIR="$(mktemp -d "/tmp/rustynet-remote-e2e.XXXXXX")"
CONTROL_DIR="${TMP_DIR}/control"
KNOWN_HOSTS_FILE="${TMP_DIR}/known_hosts"
mkdir -p "${CONTROL_DIR}"
touch "${KNOWN_HOSTS_FILE}"

REMOTE_SRC_DIR="${REMOTE_ROOT}/src"
LOCAL_SOURCE_ARCHIVE="${TMP_DIR}/repo.tar"

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

escape_for_single_quotes() {
  printf '%s' "$1" | sed "s/'/'\"'\"'/g"
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
  if target_needs_sudo "${host}"; then
    local remote_cmd="$*"
    local escaped_remote_cmd
    escaped_remote_cmd="$(escape_for_single_quotes "${remote_cmd}")"
    ssh "${SSH_BASE_OPTS[@]}" "${host}" "sudo -S -p '' bash -lc '${escaped_remote_cmd}'" <<<"${SUDO_PASSWORD}"
    return
  fi
  ssh "${SSH_BASE_OPTS[@]}" "${host}" "$@"
}

ssh_capture() {
  local host="$1"
  shift
  if target_needs_sudo "${host}"; then
    local remote_cmd="$*"
    local escaped_remote_cmd
    escaped_remote_cmd="$(escape_for_single_quotes "${remote_cmd}")"
    ssh "${SSH_BASE_OPTS[@]}" "${host}" "sudo -S -p '' bash -lc '${escaped_remote_cmd}'" <<<"${SUDO_PASSWORD}"
    return
  fi
  ssh "${SSH_BASE_OPTS[@]}" "${host}" "$@"
}

copy_local_archive_to_host() {
  local host="$1"
  log "Syncing source archive to ${host} (${REPO_REF} -> ${REMOTE_SRC_DIR})"
  if target_needs_sudo "${host}"; then
    {
      printf '%s\n' "${SUDO_PASSWORD}"
      cat "${LOCAL_SOURCE_ARCHIVE}"
    } | ssh "${SSH_BASE_OPTS[@]}" "${host}" "sudo -S -p '' bash -lc 'set -euo pipefail; rm -rf '\''${REMOTE_SRC_DIR}'\''; install -d -m 0755 '\''${REMOTE_SRC_DIR}'\''; tar -xf - -C '\''${REMOTE_SRC_DIR}'\'''"
    return
  fi
  cat "${LOCAL_SOURCE_ARCHIVE}" \
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

primary_allow_cidr="${ssh_allow_cidrs%%,*}"
primary_allow_cidr="${primary_allow_cidr// /}"
primary_allow_ip="${primary_allow_cidr%%/*}"
default_egress_iface="$(ip -o -4 route show to default | awk 'NR==1 { print $5 }')"
management_iface=""
if [[ -n "${primary_allow_ip}" ]]; then
  management_iface="$(
    ip -o route get "${primary_allow_ip}" 2>/dev/null \
      | awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }'
  )"
fi
service_egress_iface="${default_egress_iface}"
if [[ "${role}" == "client" && -n "${management_iface}" ]]; then
  service_egress_iface="${management_iface}"
fi
if [[ -z "${service_egress_iface}" ]]; then
  echo "unable to determine service egress interface" >&2
  exit 1
fi

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
RUSTYNET_ASSIGNMENT_AUTO_REFRESH=false \
RUSTYNET_AUTO_TUNNEL_ENFORCE=false \
RUSTYNET_WG_LISTEN_PORT=51820 \
RUSTYNET_EGRESS_INTERFACE="${service_egress_iface}" \
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
assignment_auto_refresh="false"
if [[ -f /etc/rustynet/assignment.signing.secret && -f /etc/rustynet/assignment-refresh.env ]]; then
  assignment_auto_refresh="true"
fi

primary_allow_cidr="${ssh_allow_cidrs%%,*}"
primary_allow_cidr="${primary_allow_cidr// /}"
primary_allow_ip="${primary_allow_cidr%%/*}"
default_egress_iface="$(ip -o -4 route show to default | awk 'NR==1 { print $5 }')"
management_iface=""
if [[ -n "${primary_allow_ip}" ]]; then
  management_iface="$(
    ip -o route get "${primary_allow_ip}" 2>/dev/null \
      | awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }'
  )"
fi
service_egress_iface="${default_egress_iface}"
if [[ "${role}" == "client" && -n "${management_iface}" ]]; then
  service_egress_iface="${management_iface}"
fi
if [[ -z "${service_egress_iface}" ]]; then
  echo "unable to determine service egress interface" >&2
  exit 1
fi

RUSTYNET_NODE_ID="${node_id}" \
RUSTYNET_NODE_ROLE="${role}" \
RUSTYNET_TRUST_AUTO_REFRESH="${auto_refresh}" \
RUSTYNET_ASSIGNMENT_AUTO_REFRESH="${assignment_auto_refresh}" \
RUSTYNET_AUTO_TUNNEL_ENFORCE=true \
RUSTYNET_WG_LISTEN_PORT=51820 \
RUSTYNET_EGRESS_INTERFACE="${service_egress_iface}" \
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
  --ttl-secs 300

rustynet assignment issue \
  --target-node-id "${client_node_id}" \
  --nodes "${nodes_spec}" \
  --allow "${allow_spec}" \
  --signing-secret "${secret_path}" \
  --output /tmp/rustynet-client.assignment \
  --verifier-key-output /tmp/rustynet-assignment.pub \
  --exit-node-id "${exit_node_id}" \
  --ttl-secs 300
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
  if target_needs_sudo "${host}"; then
    # shellcheck disable=SC2086
    {
      printf '%s\n' "${SUDO_PASSWORD}"
      cat "${script_path}"
    } | ssh "${SSH_BASE_OPTS[@]}" "${host}" "sudo -S -p '' bash -se -- ${args[*]}"
    return
  fi
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
  require_safe_token "remote-path" "${remote_path}"
  require_safe_token "owner-user" "${owner_user}"
  require_safe_token "owner-group" "${owner_group}"
  require_safe_token "mode" "${mode}"
  if target_needs_sudo "${host}"; then
    {
      printf '%s\n' "${SUDO_PASSWORD}"
      cat "${local_path}"
    } | ssh "${SSH_BASE_OPTS[@]}" "${host}" "sudo -S -p '' install -D -m ${mode} -o ${owner_user} -g ${owner_group} /dev/stdin '${remote_path}'"
    return
  fi
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

base64_to_hex() {
  local value="$1"
  printf '%s' "${value}" \
    | openssl base64 -d -A 2>/dev/null \
    | xxd -p -c 256 \
    | tr -d '\n'
}

normalize_membership_permissions() {
  local host="$1"
  ssh_run "${host}" "set -euo pipefail; chown root:root /var/lib/rustynet/membership.snapshot /var/lib/rustynet/membership.log; chmod 0600 /var/lib/rustynet/membership.snapshot /var/lib/rustynet/membership.log"
}

open_master "${EXIT_TARGET}"
open_master "${CLIENT_TARGET}"

if target_needs_sudo "${EXIT_TARGET}"; then
  log "Validating sudo access on ${EXIT_TARGET}"
  ssh_run "${EXIT_TARGET}" "true"
fi
if target_needs_sudo "${CLIENT_TARGET}"; then
  log "Validating sudo access on ${CLIENT_TARGET}"
  ssh_run "${CLIENT_TARGET}" "true"
fi

git -C "${ROOT_DIR}" archive --format=tar "${REPO_REF}" > "${LOCAL_SOURCE_ARCHIVE}"

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

log "Normalizing membership file ownership to root:root before signed updates"
normalize_membership_permissions "${EXIT_TARGET}"
normalize_membership_permissions "${CLIENT_TARGET}"

EXIT_WG_PUB="$(ssh_capture "${EXIT_TARGET}" "cat /var/lib/rustynet/keys/wireguard.pub" | tr -d '[:space:]')"
CLIENT_WG_PUB="$(ssh_capture "${CLIENT_TARGET}" "cat /var/lib/rustynet/keys/wireguard.pub" | tr -d '[:space:]')"
if [[ -z "${EXIT_WG_PUB}" || -z "${CLIENT_WG_PUB}" ]]; then
  echo "failed to collect wireguard public keys" >&2
  exit 1
fi
EXIT_WG_PUB_HEX="$(base64_to_hex "${EXIT_WG_PUB}")"
CLIENT_WG_PUB_HEX="$(base64_to_hex "${CLIENT_WG_PUB}")"
if [[ ! "${EXIT_WG_PUB_HEX}" =~ ^[0-9a-f]+$ || ! "${CLIENT_WG_PUB_HEX}" =~ ^[0-9a-f]+$ ]]; then
  echo "failed to convert WireGuard public key(s) to hex" >&2
  exit 1
fi
ASSIGNMENT_NODES_SPEC="${EXIT_NODE_ID}|${EXIT_ADDR}:51820|${EXIT_WG_PUB_HEX};${CLIENT_NODE_ID}|${CLIENT_ADDR}:51820|${CLIENT_WG_PUB_HEX}"
ASSIGNMENT_ALLOW_SPEC="${CLIENT_NODE_ID}|${EXIT_NODE_ID};${EXIT_NODE_ID}|${CLIENT_NODE_ID}"

log "Applying signed membership update for client node"
run_remote_script_with_args \
  "${EXIT_TARGET}" "${MEMBERSHIP_SCRIPT}" \
  "${CLIENT_NODE_ID}" "${CLIENT_WG_PUB_HEX}" "${EXIT_NODE_ID}-owner"

MEMBERSHIP_SNAPSHOT_LOCAL="${TMP_DIR}/membership.snapshot"
MEMBERSHIP_LOG_LOCAL="${TMP_DIR}/membership.log"
copy_remote_file_to_local "${EXIT_TARGET}" "/var/lib/rustynet/membership.snapshot" "${MEMBERSHIP_SNAPSHOT_LOCAL}"
copy_remote_file_to_local "${EXIT_TARGET}" "/var/lib/rustynet/membership.log" "${MEMBERSHIP_LOG_LOCAL}"

copy_local_file_to_remote "${CLIENT_TARGET}" "${MEMBERSHIP_SNAPSHOT_LOCAL}" "/var/lib/rustynet/membership.snapshot" "root" "root" "0600"
copy_local_file_to_remote "${CLIENT_TARGET}" "${MEMBERSHIP_LOG_LOCAL}" "/var/lib/rustynet/membership.log" "root" "root" "0600"
ssh_run "${CLIENT_TARGET}" "rm -f /var/lib/rustynet/membership.watermark"
normalize_membership_permissions "${CLIENT_TARGET}"

log "Issuing signed auto-tunnel assignments"
run_remote_script_with_args \
  "${EXIT_TARGET}" "${ASSIGNMENT_SCRIPT}" \
  "${EXIT_NODE_ID}" "${CLIENT_NODE_ID}" "${EXIT_ADDR}:51820" "${CLIENT_ADDR}:51820" "${EXIT_WG_PUB_HEX}" "${CLIENT_WG_PUB_HEX}"

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

log "Configuring assignment auto-refresh signer custody and refresh environment"
ssh_run "${EXIT_TARGET}" "set -euo pipefail; if [[ ! -f /etc/rustynet/assignment.signing.secret ]]; then openssl rand -hex 32 > /etc/rustynet/assignment.signing.secret; fi; chown root:root /etc/rustynet/assignment.signing.secret; chmod 0600 /etc/rustynet/assignment.signing.secret"
ssh_run "${CLIENT_TARGET}" "set -euo pipefail; if [[ ! -f /etc/rustynet/assignment.signing.secret ]]; then openssl rand -hex 32 > /etc/rustynet/assignment.signing.secret; fi; chown root:root /etc/rustynet/assignment.signing.secret; chmod 0600 /etc/rustynet/assignment.signing.secret"

ASSIGNMENT_REFRESH_EXIT_LOCAL="${TMP_DIR}/assignment-refresh-exit.env"
ASSIGNMENT_REFRESH_CLIENT_LOCAL="${TMP_DIR}/assignment-refresh-client.env"
cat > "${ASSIGNMENT_REFRESH_EXIT_LOCAL}" <<EOF_ASSIGN_REFRESH_EXIT
RUSTYNET_ASSIGNMENT_AUTO_REFRESH=true
RUSTYNET_ASSIGNMENT_TARGET_NODE_ID=${EXIT_NODE_ID}
RUSTYNET_ASSIGNMENT_NODES=${ASSIGNMENT_NODES_SPEC}
RUSTYNET_ASSIGNMENT_ALLOW=${ASSIGNMENT_ALLOW_SPEC}
RUSTYNET_ASSIGNMENT_SIGNING_SECRET=/etc/rustynet/assignment.signing.secret
RUSTYNET_ASSIGNMENT_OUTPUT=/var/lib/rustynet/rustynetd.assignment
RUSTYNET_ASSIGNMENT_VERIFIER_KEY_OUTPUT=/etc/rustynet/assignment.pub
RUSTYNET_ASSIGNMENT_TTL_SECS=300
RUSTYNET_ASSIGNMENT_MIN_REMAINING_SECS=180
EOF_ASSIGN_REFRESH_EXIT

cat > "${ASSIGNMENT_REFRESH_CLIENT_LOCAL}" <<EOF_ASSIGN_REFRESH_CLIENT
RUSTYNET_ASSIGNMENT_AUTO_REFRESH=true
RUSTYNET_ASSIGNMENT_TARGET_NODE_ID=${CLIENT_NODE_ID}
RUSTYNET_ASSIGNMENT_NODES=${ASSIGNMENT_NODES_SPEC}
RUSTYNET_ASSIGNMENT_ALLOW=${ASSIGNMENT_ALLOW_SPEC}
RUSTYNET_ASSIGNMENT_SIGNING_SECRET=/etc/rustynet/assignment.signing.secret
RUSTYNET_ASSIGNMENT_OUTPUT=/var/lib/rustynet/rustynetd.assignment
RUSTYNET_ASSIGNMENT_VERIFIER_KEY_OUTPUT=/etc/rustynet/assignment.pub
RUSTYNET_ASSIGNMENT_TTL_SECS=300
RUSTYNET_ASSIGNMENT_MIN_REMAINING_SECS=180
RUSTYNET_ASSIGNMENT_EXIT_NODE_ID=${EXIT_NODE_ID}
EOF_ASSIGN_REFRESH_CLIENT

copy_local_file_to_remote "${EXIT_TARGET}" "${ASSIGNMENT_REFRESH_EXIT_LOCAL}" "/etc/rustynet/assignment-refresh.env" "root" "root" "0600"
copy_local_file_to_remote "${CLIENT_TARGET}" "${ASSIGNMENT_REFRESH_CLIENT_LOCAL}" "/etc/rustynet/assignment-refresh.env" "root" "root" "0600"

log "Enabling auto-tunnel enforcement on both hosts"
run_remote_script_with_args \
  "${EXIT_TARGET}" "${ENFORCE_SCRIPT}" \
  "admin" "${EXIT_NODE_ID}" "${REMOTE_SRC_DIR}" "${SSH_ALLOW_CIDRS}"
run_remote_script_with_args \
  "${CLIENT_TARGET}" "${ENFORCE_SCRIPT}" \
  "client" "${CLIENT_NODE_ID}" "${REMOTE_SRC_DIR}" "${SSH_ALLOW_CIDRS}"

log "Waiting for post-enforcement daemon sockets"
retry_ssh_command "${EXIT_TARGET}" 20 2 \
  "test -S /run/rustynet/rustynetd.sock"
retry_ssh_command "${CLIENT_TARGET}" 20 2 \
  "test -S /run/rustynet/rustynetd.sock"
retry_ssh_command "${EXIT_TARGET}" 10 2 \
  "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 0.0.0.0/0"

sleep 3

EXIT_STATUS="$(ssh_capture "${EXIT_TARGET}" "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet status")"
CLIENT_STATUS="$(ssh_capture "${CLIENT_TARGET}" "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet status")"
CLIENT_ROUTE="$(ssh_capture "${CLIENT_TARGET}" "ip -4 route get 1.1.1.1 || true")"
EXIT_WG_SHOW="$(ssh_capture "${EXIT_TARGET}" "wg show rustynet0 || true")"
EXIT_NFT_RULESET="$(ssh_capture "${EXIT_TARGET}" "nft list ruleset || true")"
EXIT_TUNNEL_IP="$(ssh_capture "${EXIT_TARGET}" "ip -4 -o addr show dev rustynet0 | sed -n 's/.* inet \\([0-9.]*\\)\\/.*$/\\1/p' | head -n1" | tr -d '[:space:]')"
EXIT_ASSIGNMENT_TIMER_STATE="$(ssh_capture "${EXIT_TARGET}" "systemctl is-active rustynetd-assignment-refresh.timer || true" | tr -d '[:space:]')"
CLIENT_ASSIGNMENT_TIMER_STATE="$(ssh_capture "${CLIENT_TARGET}" "systemctl is-active rustynetd-assignment-refresh.timer || true" | tr -d '[:space:]')"

if [[ -n "${EXIT_TUNNEL_IP}" ]]; then
  ssh_run "${CLIENT_TARGET}" "ping -c 2 -W 2 '${EXIT_TUNNEL_IP}' >/dev/null"
fi

EXIT_HANDSHAKES="$(ssh_capture "${EXIT_TARGET}" "wg show rustynet0 latest-handshakes | sed -n 's/^[^[:space:]]*[[:space:]]\\+\\([0-9][0-9]*\\).*$/\\1/p'")"

CLIENT_PLAINTEXT_KEYS="$(ssh_capture "${CLIENT_TARGET}" "ls -1 /var/lib/rustynet/keys/wireguard.passphrase /etc/rustynet/wireguard.passphrase 2>/dev/null || true")"
EXIT_PLAINTEXT_KEYS="$(ssh_capture "${EXIT_TARGET}" "ls -1 /var/lib/rustynet/keys/wireguard.passphrase /etc/rustynet/wireguard.passphrase 2>/dev/null || true")"
CLIENT_CRED_MODE="$(ssh_capture "${CLIENT_TARGET}" "stat -c '%U:%G %a' /etc/rustynet/credentials/wg_key_passphrase.cred")"
EXIT_CRED_MODE="$(ssh_capture "${EXIT_TARGET}" "stat -c '%U:%G %a' /etc/rustynet/credentials/wg_key_passphrase.cred")"
CLIENT_KEY_MODE="$(ssh_capture "${CLIENT_TARGET}" "stat -c '%U:%G %a' /var/lib/rustynet/keys/wireguard.key.enc")"
EXIT_KEY_MODE="$(ssh_capture "${EXIT_TARGET}" "stat -c '%U:%G %a' /var/lib/rustynet/keys/wireguard.key.enc")"

extract_last_assignment_generated() {
  local status_line="$1"
  sed -n 's/.*last_assignment=\([0-9][0-9]*\):.*/\1/p' <<<"${status_line}" | head -n1
}

EXIT_ASSIGNMENT_GENERATED_BEFORE="$(extract_last_assignment_generated "${EXIT_STATUS}")"
CLIENT_ASSIGNMENT_GENERATED_BEFORE="$(extract_last_assignment_generated "${CLIENT_STATUS}")"

log "Waiting for assignment refresh timer to rotate signed bundles"
sleep 230

EXIT_STATUS_AFTER_REFRESH="$(ssh_capture "${EXIT_TARGET}" "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet status")"
CLIENT_STATUS_AFTER_REFRESH="$(ssh_capture "${CLIENT_TARGET}" "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet status")"
EXIT_ASSIGNMENT_GENERATED_AFTER="$(extract_last_assignment_generated "${EXIT_STATUS_AFTER_REFRESH}")"
CLIENT_ASSIGNMENT_GENERATED_AFTER="$(extract_last_assignment_generated "${CLIENT_STATUS_AFTER_REFRESH}")"

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
if [[ "${EXIT_ASSIGNMENT_TIMER_STATE}" == "active" ]]; then
  add_check "exit-assignment-refresh-timer" "PASS" "rustynetd-assignment-refresh.timer is active"
else
  add_check "exit-assignment-refresh-timer" "FAIL" "timer state=${EXIT_ASSIGNMENT_TIMER_STATE:-unknown}"
fi
if [[ "${CLIENT_ASSIGNMENT_TIMER_STATE}" == "active" ]]; then
  add_check "client-assignment-refresh-timer" "PASS" "rustynetd-assignment-refresh.timer is active"
else
  add_check "client-assignment-refresh-timer" "FAIL" "timer state=${CLIENT_ASSIGNMENT_TIMER_STATE:-unknown}"
fi

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

if [[ "${EXIT_ASSIGNMENT_GENERATED_BEFORE}" =~ ^[0-9]+$ && "${EXIT_ASSIGNMENT_GENERATED_AFTER}" =~ ^[0-9]+$ ]] \
  && (( EXIT_ASSIGNMENT_GENERATED_AFTER > EXIT_ASSIGNMENT_GENERATED_BEFORE )); then
  add_check "exit-assignment-refresh-rotation" "PASS" "generated_at advanced from ${EXIT_ASSIGNMENT_GENERATED_BEFORE} to ${EXIT_ASSIGNMENT_GENERATED_AFTER}"
else
  add_check "exit-assignment-refresh-rotation" "FAIL" "generated_at before=${EXIT_ASSIGNMENT_GENERATED_BEFORE:-none} after=${EXIT_ASSIGNMENT_GENERATED_AFTER:-none}"
fi

if [[ "${CLIENT_ASSIGNMENT_GENERATED_BEFORE}" =~ ^[0-9]+$ && "${CLIENT_ASSIGNMENT_GENERATED_AFTER}" =~ ^[0-9]+$ ]] \
  && (( CLIENT_ASSIGNMENT_GENERATED_AFTER > CLIENT_ASSIGNMENT_GENERATED_BEFORE )); then
  add_check "client-assignment-refresh-rotation" "PASS" "generated_at advanced from ${CLIENT_ASSIGNMENT_GENERATED_BEFORE} to ${CLIENT_ASSIGNMENT_GENERATED_AFTER}"
else
  add_check "client-assignment-refresh-rotation" "FAIL" "generated_at before=${CLIENT_ASSIGNMENT_GENERATED_BEFORE:-none} after=${CLIENT_ASSIGNMENT_GENERATED_AFTER:-none}"
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
  echo "## Exit Status After Assignment Refresh Window"
  echo
  echo '```text'
  echo "${EXIT_STATUS_AFTER_REFRESH}"
  echo '```'
  echo
  echo "## Client Status"
  echo
  echo '```text'
  echo "${CLIENT_STATUS}"
  echo '```'
  echo
  echo "## Client Status After Assignment Refresh Window"
  echo
  echo '```text'
  echo "${CLIENT_STATUS_AFTER_REFRESH}"
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
