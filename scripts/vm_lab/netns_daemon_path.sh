#!/usr/bin/env bash
# netns_daemon_path.sh — cross-network Increment 2 standalone validator.
#
# WHAT
#   Stands up TWO rustynetd daemons in two Linux network namespaces, each
#   behind its own NAT router (built by netns_internet_sim.sh), mints the
#   minimal signed control state locally (a fresh membership genesis + a fresh
#   trust authority, plus assignment + traversal bundles issued with the host's
#   already-bootstrapped assignment signing authority — read-only — because the
#   from-env wrappers are the only path that also emits the signed traversal
#   coordination record the daemon's direct probe requires), launches a
#   privileged helper + daemon in each namespace, and PROVES the client daemon
#   reaches `path_mode=direct_active && path_live_proven=true` over a real
#   WireGuard handshake that crosses both NAT boundaries.
#
#   This validates cross-network Increment 2 (CrossNetworkSubstrateIntegration
#   spec §5 X1) without STUN: the two namespaces are mutually routable through
#   the shared wan bridge, so the host-candidate endpoints reach each other and
#   the WG handshake completes.
#
# WHY NO STUN
#   Both endpoints' translated (router-WAN) addresses are directly reachable
#   from the other site through the wan bridge, so each daemon's advertised
#   host candidate (router_wan_ip:listen_port) is dialable by its peer. No
#   reflexive discovery is needed; `--traversal-stun-servers` is omitted.
#
# ISOLATION / SAFETY
#   - Builds ONLY namespaces prefixed "rnsim-" (via netns_internet_sim.sh).
#   - Mints a FRESH authority set under a private temp root; never reads or
#     writes the production /etc/rustynet or /var/lib/rustynet, never touches
#     a running production rustynetd (distinct sockets/state/helper sockets).
#   - `trap cleanup EXIT` tears down namespaces, kills our daemons/helpers,
#     and removes the temp root on ANY exit path.
#
# USAGE
#   sudo PATH=$PATH:/usr/sbin bash netns_daemon_path.sh \
#       [--sim /path/to/netns_internet_sim.sh] [--nat-profile full_cone] \
#       [--keep] [--timeout-secs 90]
#
#   --keep        leave the topology up on exit (success OR failure) for
#                 debugging; otherwise teardown always runs
#   --nat-profile NAT profile applied to BOTH sites (default full_cone; see the
#                 NAT_PROFILE note below for why full_cone is required w/o STUN)
#   --timeout-secs how long to poll for direct_active (default 90)
#
# Run as root on the Linux guest. Requires: rustynetd + rustynet on PATH,
# nft, ip, wg, python3 (for hex/base64 conversion), and a kernel that can
# create wireguard interfaces inside a netns.
set -euo pipefail
umask 077

# ----------------------------------------------------------------- config
SIM_SCRIPT="/tmp/netns_internet_sim.sh"
# full_cone is required without STUN: it DNATs the WG UDP port range back to the
# endpoint, so each peer's advertised host candidate (router_wan_ip:listen_port)
# is statically reachable and port-stable. With port_restricted_cone (plain
# masquerade) the responder's source port is NOT preserved, so the static
# endpoint hint misses and the handshake never completes (only direct_programmed,
# never direct_active) — that case genuinely needs STUN/reflexive discovery,
# which Increment 2 omits by design.
NAT_PROFILE="full_cone"
TIMEOUT_SECS=90
KEEP=0

NODE_A="rn-a"            # admin / serving side (genesis node; gets anchor cap)
NODE_B="rn-b"            # client / consumer side
ROLE_A="admin"
ROLE_B="client"
NETWORK_ID="rnsim-net"
WG_PORT=51820
WG_IFACE="rustynet0"

# Endpoints are the router-WAN translated addresses of each site. With full_cone
# the router DNATs the WG UDP port range back to the endpoint, so each peer is
# statically reachable (and port-stable) at <router_wan_ip>:<listen_port>. These
# match netns_internet_sim.sh's build_site(): site index 1 (A) router WAN =
# 198.18.0.11, site 2 (B) = 198.18.0.12 (canonical 198.18.0.0/15 transit).
EP_A_NS="rnsim-ep-A"
EP_B_NS="rnsim-ep-B"
EP_A_ENDPOINT="${EP_A_WAN:-198.18.0.11}:${WG_PORT}"
EP_B_ENDPOINT="${EP_B_WAN:-198.18.0.12}:${WG_PORT}"

RUSTYNETD_BIN="$(command -v rustynetd || true)"
RUSTYNET_BIN="$(command -v rustynet || true)"

# ----------------------------------------------------------------- args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sim) SIM_SCRIPT="$2"; shift 2 ;;
    --nat-profile) NAT_PROFILE="$2"; shift 2 ;;
    --timeout-secs) TIMEOUT_SECS="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) sed -n '2,46p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# ----------------------------------------------------------------- preflight
require() { command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 2; }; }

[[ "$(id -u)" -eq 0 ]] || { echo "must run as root" >&2; exit 2; }
[[ -n "$RUSTYNETD_BIN" ]] || { echo "rustynetd not on PATH" >&2; exit 2; }
[[ -n "$RUSTYNET_BIN" ]] || { echo "rustynet not on PATH" >&2; exit 2; }
[[ -f "$SIM_SCRIPT" ]] || { echo "sim script not found: $SIM_SCRIPT" >&2; exit 2; }
require ip
require nft
require wg
require python3

WORK_ROOT=""
declare -a DAEMON_PIDS=()
declare -a HELPER_PIDS=()

# log/fail go to stderr so functions that return a value on stdout (via command
# substitution, e.g. setup_node_runtime / launch_node) are never polluted.
log() { printf '[netns-daemon-path] %s\n' "$*" >&2; }
fail() { printf '[netns-daemon-path][FAIL] %s\n' "$*" >&2; }

# ----------------------------------------------------------------- cleanup
cleanup() {
  local rc=$?
  set +e
  log "cleanup: tearing down (rc=$rc)"
  # Kill our daemons + helpers (the netns teardown also removes their ifaces).
  local pid
  for pid in "${DAEMON_PIDS[@]}"; do [[ -n "$pid" ]] && kill "$pid" 2>/dev/null; done
  for pid in "${HELPER_PIDS[@]}"; do [[ -n "$pid" ]] && kill "$pid" 2>/dev/null; done
  sleep 1
  for pid in "${DAEMON_PIDS[@]}"; do [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null; done
  for pid in "${HELPER_PIDS[@]}"; do [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null; done
  # Belt-and-braces: kill any rustynetd whose argv references our work root.
  if [[ -n "$WORK_ROOT" ]]; then
    pkill -9 -f "$WORK_ROOT" 2>/dev/null
  fi
  # Tear down the netns topology we built.
  bash "$SIM_SCRIPT" teardown >/dev/null 2>&1 || true
  if [[ -n "$WORK_ROOT" && -d "$WORK_ROOT" ]]; then
    rm -rf "$WORK_ROOT" 2>/dev/null || true
  fi
  log "cleanup: done"
  exit "$rc"
}
trap cleanup EXIT

# ----------------------------------------------------------------- helpers
nsx() { local ns="$1"; shift; ip netns exec "$ns" "$@"; }

# base64 wg key -> 64-char hex
wg_pub_b64_to_hex() {
  python3 - "$1" <<'PY'
import base64, sys
print(base64.b64decode(sys.argv[1]).hex())
PY
}

# 32 random bytes hex (membership identity pubkey placeholder for node-b)
rand_hex_32() {
  python3 - <<'PY'
import os
print(os.urandom(32).hex())
PY
}

# ----------------------------------------------------------------- main
main() {
  WORK_ROOT="$(mktemp -d /tmp/rnsim-daemon-path.XXXXXX)"
  chmod 0700 "$WORK_ROOT"
  log "work root: $WORK_ROOT"

  local auth_dir="$WORK_ROOT/auth"        # shared authorities (keys, secrets)
  local pass_file="$auth_dir/passphrase"
  local owner_key="$auth_dir/membership.owner.key"
  local trust_key="$auth_dir/trust-evidence.key"
  local trust_pub="$auth_dir/trust-evidence.pub"
  local mem_snapshot="$auth_dir/membership.snapshot"
  local mem_log="$auth_dir/membership.log"
  local mem_genesis_watermark="$auth_dir/membership.genesis.watermark"
  mkdir -p "$auth_dir"
  chmod 0700 "$auth_dir"

  # ---- 1. build the netns topology -------------------------------------
  log "building netns topology (sites A,B = $NAT_PROFILE)"
  bash "$SIM_SCRIPT" build --site "A:${NAT_PROFILE}" --site "B:${NAT_PROFILE}"

  # ---- 2. generate a random passphrase for the local authority set -----
  python3 - "$pass_file" <<'PY'
import os, sys
open(sys.argv[1], "wb").write(os.urandom(48).hex().encode() + b"\n")
PY
  chmod 0600 "$pass_file"

  # ---- 3. WireGuard keypairs (one per node, raw base64 in a file) ------
  local wg_priv_a="$auth_dir/wg-a.key" wg_priv_b="$auth_dir/wg-b.key"
  local wg_pub_a_b64 wg_pub_b_b64 wg_pub_a_hex wg_pub_b_hex
  ( umask 077; wg genkey > "$wg_priv_a" )
  ( umask 077; wg genkey > "$wg_priv_b" )
  chmod 0600 "$wg_priv_a" "$wg_priv_b"
  wg_pub_a_b64="$(wg pubkey < "$wg_priv_a")"
  wg_pub_b_b64="$(wg pubkey < "$wg_priv_b")"
  wg_pub_a_hex="$(wg_pub_b64_to_hex "$wg_pub_a_b64")"
  wg_pub_b_hex="$(wg_pub_b64_to_hex "$wg_pub_b_b64")"
  log "wg pub A(hex)=$wg_pub_a_hex"
  log "wg pub B(hex)=$wg_pub_b_hex"

  # ---- 4. membership genesis (node A) + add node B ----------------------
  log "minting membership genesis (node $NODE_A)"
  "$RUSTYNETD_BIN" membership init \
    --snapshot "$mem_snapshot" \
    --log "$mem_log" \
    --watermark "$mem_genesis_watermark" \
    --owner-signing-key "$owner_key" \
    --owner-signing-key-passphrase-file "$pass_file" \
    --node-id "$NODE_A" \
    --network-id "$NETWORK_ID" \
    --force

  local mem_b_pubkey record_path signed_update
  mem_b_pubkey="$(rand_hex_32)"
  record_path="$WORK_ROOT/propose-add-b.record"
  signed_update="$WORK_ROOT/propose-add-b.signed"

  log "proposing add of node $NODE_B (client capability)"
  "$RUSTYNET_BIN" membership propose-add \
    --snapshot "$mem_snapshot" --log "$mem_log" --watermark "$mem_genesis_watermark" \
    --node-id "$NODE_B" \
    --node-pubkey "$mem_b_pubkey" \
    --owner "$NODE_B" \
    --capabilities client \
    --output "$record_path"

  log "signing membership update with owner key"
  "$RUSTYNET_BIN" membership sign-update \
    --record "$record_path" \
    --approver-id "${NODE_A}-owner" \
    --signing-key "$owner_key" \
    --signing-key-passphrase-file "$pass_file" \
    --output "$signed_update"

  log "applying membership update"
  "$RUSTYNET_BIN" membership apply-update \
    --snapshot "$mem_snapshot" --log "$mem_log" --watermark "$mem_genesis_watermark" \
    --signed-update "$signed_update"

  "$RUSTYNET_BIN" membership status \
    --snapshot "$mem_snapshot" --log "$mem_log" --watermark "$mem_genesis_watermark" || true

  # ---- 5. trust evidence authority (fresh, daemon-local) ----------------
  # Trust is an independent authority: the daemon verifies its trust evidence
  # with the verifier key we hand it. Mint a fresh pair here.
  log "minting trust evidence authority"
  "$RUSTYNET_BIN" trust keygen \
    --signing-key-output "$trust_key" \
    --signing-key-passphrase-file "$pass_file" \
    --verifier-key-output "$trust_pub" \
    --force

  local trust_evidence="$auth_dir/rustynetd.trust"
  "$RUSTYNET_BIN" trust issue \
    --signing-key "$trust_key" \
    --signing-key-passphrase-file "$pass_file" \
    --output "$trust_evidence"

  # ---- 6+7. assignment + traversal bundles via the from-env wrappers ----
  # The from-env wrappers emit the SIGNED TRAVERSAL COORDINATION RECORD that
  # the daemon's direct probe requires ("validated signed traversal
  # coordination required for direct probe"); the lower-level `traversal issue`
  # verb emits only the endpoint-hint bundle and is rejected. The wrappers read
  # the host's already-provisioned assignment signing authority
  # (/etc/rustynet/assignment.signing.secret + the systemd-creds-encrypted
  # passphrase) — READ-ONLY; they write only into our isolated --issue-dir, and
  # never touch the running daemon's runtime. This mirrors the proven e2e
  # reference (live_linux_cross_network_direct_remote_exit_test.sh).
  #
  # from-env NODES_SPEC format: node_id|endpoint|pubkey_hex|caps_csv
  local nodes_spec="${NODE_A}|${EP_A_ENDPOINT}|${wg_pub_a_hex}|anchor,client;${NODE_B}|${EP_B_ENDPOINT}|${wg_pub_b_hex}|client"
  local allow_spec="${NODE_A}|${NODE_B};${NODE_B}|${NODE_A}"
  # ASSIGNMENTS_SPEC: target|exit_or_dash  ('-' = no exit = pure mesh direct)
  local assignments_spec="${NODE_A}|-;${NODE_B}|-"

  if [[ ! -f /etc/rustynet/assignment.signing.secret ]]; then
    fail "/etc/rustynet/assignment.signing.secret not found; this validator reuses the host's already-bootstrapped assignment signing authority (read-only). Run 'rustynet ops e2e-bootstrap-host' once on this guest first."
    return 1
  fi

  local assign_issue="$auth_dir/assignment-issue"
  local trav_issue="$auth_dir/traversal-issue"

  local assign_env="$auth_dir/assignment.env"
  : > "$assign_env"
  {
    printf 'NODES_SPEC=%s\n' "$nodes_spec"
    printf 'ALLOW_SPEC=%s\n' "$allow_spec"
    printf 'ASSIGNMENTS_SPEC=%s\n' "$assignments_spec"
  } >> "$assign_env"
  chmod 0600 "$assign_env"

  local trav_env="$auth_dir/traversal.env"
  : > "$trav_env"
  {
    printf 'NODES_SPEC=%s\n' "$nodes_spec"
    printf 'ALLOW_SPEC=%s\n' "$allow_spec"
  } >> "$trav_env"
  chmod 0600 "$trav_env"

  log "issuing assignment bundles (from-env, isolated issue-dir)"
  "$RUSTYNET_BIN" ops e2e-issue-assignment-bundles-from-env \
    --env-file "$assign_env" --issue-dir "$assign_issue"

  log "issuing traversal bundles (from-env, isolated issue-dir; carries coordination record)"
  "$RUSTYNET_BIN" ops e2e-issue-traversal-bundles-from-env \
    --env-file "$trav_env" --issue-dir "$trav_issue"

  local assign_pub="$assign_issue/rn-assignment.pub"
  local trav_pub="$trav_issue/rn-traversal.pub"
  local assign_a="$assign_issue/rn-assignment-${NODE_A}.assignment"
  local assign_b="$assign_issue/rn-assignment-${NODE_B}.assignment"
  local trav_a="$trav_issue/rn-traversal-${NODE_A}.traversal"
  local trav_b="$trav_issue/rn-traversal-${NODE_B}.traversal"

  # ---- 8. per-node runtime dirs -----------------------------------------
  # Each daemon gets isolated socket/state/watermark/helper-socket paths so it
  # never collides with a production rustynetd or with its peer.
  setup_node_runtime() {
    local node="$1"
    local d="$WORK_ROOT/$node"
    mkdir -p "$d"
    chmod 0700 "$d"
    # copy membership trio (snapshot+log shared content; watermark per-node).
    # The membership loader enforces mask 0o077 (0600), stricter than the
    # daemon's own snapshot check (0o037) — install 0600.
    install -m0600 -o root -g root "$mem_snapshot" "$d/membership.snapshot"
    install -m0600 -o root -g root "$mem_log" "$d/membership.log"
    # trust evidence + verifier
    install -m0600 -o root -g root "$trust_evidence" "$d/rustynetd.trust"
    install -m0644 -o root -g root "$trust_pub" "$d/trust-evidence.pub"
    # verifier keys
    install -m0644 -o root -g root "$assign_pub" "$d/assignment.pub"
    install -m0644 -o root -g root "$trav_pub" "$d/traversal.pub"
    echo "$d"
  }

  local dir_a dir_b
  dir_a="$(setup_node_runtime "$NODE_A")"
  dir_b="$(setup_node_runtime "$NODE_B")"

  install -m0600 -o root -g root "$assign_a" "$dir_a/rustynetd.assignment"
  install -m0600 -o root -g root "$trav_a"   "$dir_a/rustynetd.traversal"
  install -m0600 -o root -g root "$wg_priv_a" "$dir_a/wg.key"
  install -m0600 -o root -g root "$assign_b" "$dir_b/rustynetd.assignment"
  install -m0600 -o root -g root "$trav_b"   "$dir_b/rustynetd.traversal"
  install -m0600 -o root -g root "$wg_priv_b" "$dir_b/wg.key"
  # wg public key files (default path lives under a uid-987 dir on installed
  # hosts; point the daemon at our isolated copy so its parent-dir uid check
  # sees root). The daemon re-reads/writes this on key rotation; harmless here.
  printf '%s\n' "$wg_pub_a_b64" > "$dir_a/wg.pub"; chmod 0644 "$dir_a/wg.pub"
  printf '%s\n' "$wg_pub_b_b64" > "$dir_b/wg.pub"; chmod 0644 "$dir_b/wg.pub"

  # ---- 9. launch helper + daemon in each namespace ----------------------
  launch_node() {
    local node="$1" role="$2" ns="$3" dir="$4"
    # The privileged helper chmods its socket's PARENT dir (0o700 with
    # allowed-uid only). Keep that dir separate from the wg key / bundles so
    # the daemon's parent-directory security checks on those files are not
    # affected. Both helper and daemon run as root (uid 0), so allowed-uid 0
    # is sufficient; omit allowed-gid to keep the socket dir at 0o700.
    local helper_dir="$dir/helper"
    mkdir -p "$helper_dir"; chmod 0700 "$helper_dir"
    local helper_sock="$helper_dir/helper.sock"
    local daemon_sock="$dir/daemon.sock"
    local helper_log="$dir/helper.log"
    local daemon_log="$dir/daemon.log"

    log "launching privileged helper for $node in $ns"
    nsx "$ns" "$RUSTYNETD_BIN" privileged-helper \
      --socket "$helper_sock" \
      --allowed-uid 0 \
      --timeout-ms 4000 \
      >"$helper_log" 2>&1 &
    HELPER_PIDS+=("$!")

    # wait for helper socket
    local i
    for i in $(seq 1 50); do
      [[ -S "$helper_sock" ]] && break
      sleep 0.1
    done
    [[ -S "$helper_sock" ]] || { fail "$node helper socket never appeared"; cat "$helper_log" >&2; return 1; }
    # The helper creates its socket 0o660. Outside /run/rustynet the daemon's
    # client enforces owner-only (0600) socket perms (validate_owner_only_socket).
    # Both helper and daemon run as root, so tighten to 0600 so the daemon
    # accepts it. (Under /run/rustynet the group-aware path would accept 0660,
    # but we keep the socket in our isolated work root to avoid touching the
    # production runtime dir.)
    chmod 0600 "$helper_sock"

    log "launching daemon $node (role=$role) in $ns"
    nsx "$ns" "$RUSTYNETD_BIN" daemon \
      --node-id "$node" \
      --node-role "$role" \
      --socket "$daemon_sock" \
      --state "$dir/rustynetd.state" \
      --trust-evidence "$dir/rustynetd.trust" \
      --trust-verifier-key "$dir/trust-evidence.pub" \
      --trust-watermark "$dir/rustynetd.trust.watermark" \
      --membership-snapshot "$dir/membership.snapshot" \
      --membership-log "$dir/membership.log" \
      --membership-watermark "$dir/membership.watermark" \
      --auto-tunnel-enforce true \
      --auto-tunnel-bundle "$dir/rustynetd.assignment" \
      --auto-tunnel-verifier-key "$dir/assignment.pub" \
      --auto-tunnel-watermark "$dir/rustynetd.assignment.watermark" \
      --traversal-bundle "$dir/rustynetd.traversal" \
      --traversal-verifier-key "$dir/traversal.pub" \
      --traversal-watermark "$dir/rustynetd.traversal.watermark" \
      --dns-zone-bundle "$dir/rustynetd.dns-zone" \
      --dns-zone-verifier-key "$dir/dns-zone.pub" \
      --dns-zone-watermark "$dir/rustynetd.dns-zone.watermark" \
      --backend linux-wireguard \
      --wg-interface "$WG_IFACE" \
      --wg-listen-port "$WG_PORT" \
      --wg-private-key "$dir/wg.key" \
      --wg-public-key "$dir/wg.pub" \
      --egress-interface auto \
      --privileged-helper-socket "$helper_sock" \
      --privileged-helper-timeout-ms 4000 \
      --fail-closed-ssh-allow false \
      >"$daemon_log" 2>&1 &
    DAEMON_PIDS+=("$!")

    # wait for daemon socket
    for i in $(seq 1 80); do
      [[ -S "$daemon_sock" ]] && break
      sleep 0.1
    done
    [[ -S "$daemon_sock" ]] || { fail "$node daemon socket never appeared"; echo "--- $node daemon log ---" >&2; cat "$daemon_log" >&2; return 1; }
    echo "$daemon_sock"
  }

  local sock_a sock_b
  sock_a="$(launch_node "$NODE_A" "$ROLE_A" "$EP_A_NS" "$dir_a")" || return 1
  sock_b="$(launch_node "$NODE_B" "$ROLE_B" "$EP_B_NS" "$dir_b")" || return 1

  # ---- 10. resolve the peer overlay (mesh) IP for handshake nudging -----
  # WireGuard only performs a handshake when there is traffic to carry (or a
  # persistent-keepalive). Once both peers are programmed, we drive overlay
  # traffic from the client to the server's mesh IP each poll iteration; the
  # handshake then completes and the daemon's reconcile observes a fresh
  # handshake and flips to direct_active. The mesh IP is the peer's wg
  # allowed-ip (/32); read it from the client's interface so we don't have to
  # re-derive sha256(node_id).
  local peer_mesh_ip=""
  local i
  for i in $(seq 1 30); do
    peer_mesh_ip="$(nsx "$EP_B_NS" wg show "$WG_IFACE" allowed-ips 2>/dev/null \
      | awk '{print $2}' | sed 's#/.*##' | grep -E '^[0-9]' | head -1)"
    [[ -n "$peer_mesh_ip" ]] && break
    sleep 0.5
  done
  if [[ -z "$peer_mesh_ip" ]]; then
    fail "could not resolve peer mesh IP from client wg allowed-ips"
    diag_dump "$dir_a" "$dir_b" >&2
    return 1
  fi
  log "peer (server) mesh IP = $peer_mesh_ip"

  # ---- 11. poll the client daemon for direct_active --------------------
  log "polling client ($NODE_B) netcheck for path_mode=direct_active (timeout ${TIMEOUT_SECS}s)"
  local deadline=$(( $(date +%s) + TIMEOUT_SECS ))
  local netcheck="" proven=0
  while (( $(date +%s) < deadline )); do
    # Nudge the tunnel: overlay ping client -> server mesh IP drives the WG
    # handshake across both NAT boundaries. Killswitch allows oifname rustynet0.
    nsx "$EP_B_NS" ping -c2 -W1 "$peer_mesh_ip" >/dev/null 2>&1 || true
    netcheck="$(nsx "$EP_B_NS" env RUSTYNET_DAEMON_SOCKET="$sock_b" "$RUSTYNET_BIN" netcheck 2>&1 || true)"
    if [[ "$netcheck" == *"path_mode=direct_active"* && "$netcheck" == *"path_live_proven=true"* ]]; then
      proven=1
      break
    fi
    sleep 2
  done

  echo "================= client netcheck ================="
  printf '%s\n' "$netcheck"
  echo "==================================================="

  if (( proven == 1 )); then
    # also require traversal_error=none and no critical alarms (signed-state health)
    if [[ "$netcheck" == *"traversal_error=none"* \
        && "$netcheck" != *"traversal_alarm_state=critical"* \
        && "$netcheck" != *"traversal_alarm_state=error"* \
        && "$netcheck" != *"traversal_alarm_state=missing"* ]]; then
      log "PASS: path_mode=direct_active && path_live_proven=true (signed state healthy)"
      return 0
    fi
    fail "direct_active reached but signed-state health check failed"
    return 1
  fi

  fail "did not reach direct_active within ${TIMEOUT_SECS}s"
  diag_dump "$dir_a" "$dir_b" >&2
  return 1
}

# Diagnostic dump (handshake / nft / conntrack / route) for the failure path.
diag_dump() {
  local dir_a="$1" dir_b="$2"
  echo "===== DIAGNOSTICS ====="
  local ns
  for ns in "$EP_A_NS" "$EP_B_NS"; do
    echo "--- $ns: wg show ---";        nsx "$ns" wg show 2>&1 | sed 's/^/  /' || true
    echo "--- $ns: rustynet0 addr ---"; nsx "$ns" ip -br addr show "$WG_IFACE" 2>&1 | sed 's/^/  /' || true
    echo "--- $ns: nft (handshake-relevant) ---"
    nsx "$ns" nft list ruleset 2>&1 | grep -iE "chain |policy |drop|accept|masquerade|51820|udp|ct state|oif|iif" | sed 's/^/  /' | head -50 || true
    echo "--- $ns: conntrack udp/51820 ---"
    nsx "$ns" conntrack -L 2>/dev/null | grep -E "51820|udp" | sed 's/^/  /' | head -20 || echo "  (conntrack unavailable)"
  done
  echo "--- ep-A daemon log (tail) ---"; tail -n 30 "$dir_a/daemon.log" || true
  echo "--- ep-B daemon log (tail) ---"; tail -n 30 "$dir_b/daemon.log" || true
  echo "===== END DIAGNOSTICS ====="
}

if main; then
  echo "RESULT: PASS"
  if (( KEEP == 1 )); then
    log "--keep set: leaving topology up; run '$SIM_SCRIPT teardown' + rm -rf $WORK_ROOT to clean"
    trap - EXIT
  fi
  exit 0
else
  echo "RESULT: FAIL"
  if (( KEEP == 1 )); then
    log "--keep set: leaving topology up after FAILURE for debugging; run '$SIM_SCRIPT teardown' + rm -rf $WORK_ROOT to clean"
    trap - EXIT
  fi
  exit 1
fi
