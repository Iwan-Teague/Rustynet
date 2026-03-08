#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: rn_issue_assignments.sh <env-file>" >&2
  exit 2
fi

source "$1"

run_root() {
  sudo -S -p '' "$@" < /tmp/rn_sudo.pass
}

PASS_FILE="$(mktemp /tmp/rn-assignment-passphrase.XXXXXX)"
cleanup() {
  if [[ -f "$PASS_FILE" ]]; then
    run_root rustynet ops secure-remove --path "$PASS_FILE" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

run_root rustynet ops materialize-signing-passphrase --output "$PASS_FILE"
run_root chmod 0600 "$PASS_FILE"

ISSUE_DIR="/run/rustynet/assignment-issue"
run_root rm -rf "$ISSUE_DIR"
run_root install -d -m 0700 "$ISSUE_DIR"

issue_bundle() {
  local target_node_id="$1"
  local exit_node_id="$2"
  local output_name="rn-assignment-${target_node_id}.assignment"
  local -a args
  args=(
    rustynet assignment issue
    --target-node-id "$target_node_id"
    --nodes "$NODES_SPEC"
    --allow "$ALLOW_SPEC"
    --signing-secret /etc/rustynet/assignment.signing.secret
    --signing-secret-passphrase-file "$PASS_FILE"
    --output "$ISSUE_DIR/$output_name"
    --verifier-key-output "$ISSUE_DIR/rn-assignment.pub"
    --ttl-secs 300
  )
  if [[ -n "$exit_node_id" && "$exit_node_id" != "-" ]]; then
    args+=(--exit-node-id "$exit_node_id")
  fi
  run_root "${args[@]}"
}

OLD_IFS="$IFS"
IFS=';'
set -- $ASSIGNMENTS_SPEC
IFS="$OLD_IFS"
for entry in "$@"; do
  [[ -n "$entry" ]] || continue
  target_node_id="${entry%%|*}"
  exit_node_id="${entry#*|}"
  issue_bundle "$target_node_id" "$exit_node_id"
done
