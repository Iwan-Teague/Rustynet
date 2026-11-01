Membership Governance Runbook

Purpose

This runbook describes operator CLI flows and daemon gating for membership governance (quorum-signed membership updates).

CLI flows

- Propose an update (creates a raw update record):
  rustynet membership propose --operation <operation> --output <update.record>

  Supported operation values:
  add-node, remove-node, revoke-node, restore-node, rotate-node-key,
  set-node-capabilities, set-quorum, rotate-approver.

- Sign an update (approver signs a record):
  rustynet membership sign --record <update.record> --approver-id <id> --signing-key <key> --signing-key-passphrase-file <passphrase-file> --output <signed.update>

  Compatibility alias:
  rustynet membership sign-update ...

- Verify an update (locally verify signatures and integrity):
  rustynet membership verify-update --signed-update <signed.update> --snapshot <membership.snapshot> --log <membership.log>

- Apply an update (apply to snapshot and append to log):
  rustynet membership apply --signed-update <signed.update> --snapshot <membership.snapshot> --log <membership.log>

  Compatibility alias:
  rustynet membership apply-update ...

- Apply an update via the running daemon (Gap 2 daemon-side apply path):
  rustynet membership apply --signed-update <signed.update> --daemon

  The `--daemon` flag submits the canonical signed-update envelope to the
  running `rustynetd` over Unix-domain IPC. The daemon re-runs every
  security gate enforced by `apply_signed_update` (threshold quorum,
  authorised signer keys, owner-signature requirements, expiry, future-
  date rejection, previous-state-root match, epoch chain monotonicity,
  duplicate-update replay rejection) before any snapshot/log/watermark
  mutation. Passing the daemon's local IPC peer-credential authorisation
  (root, socket-owner uid, or reviewed local-control group) is necessary
  but NOT sufficient: a root caller still cannot apply a sub-quorum,
  expired, or replayed envelope. The daemon refreshes its in-memory
  membership state + directory only after the on-disk snapshot/log/
  watermark have been persisted atomically. `--dry-run` is rejected when
  combined with `--daemon` (the daemon-submit path always mutates on
  success); use the file-based apply for dry-runs.

- List current state (view current snapshot, root, and active nodes):
  rustynet membership list --snapshot <membership.snapshot> --log <membership.log>

  Compatibility alias:
  rustynet membership status ...

- Verify persisted log chain and emit audit-integrity proof:
  rustynet membership verify --snapshot <membership.snapshot> --log <membership.log> --audit-output <audit.log>

  Compatibility alias:
  rustynet membership verify-log ...

Daemon gating and policy

- The daemon must load a verified membership snapshot before provisioning peers. If snapshot verification fails, provisioning is blocked (fail-closed).
- Membership mutations must go through `apply_signed_update`; this enforces threshold quorum, authorized signer keys, owner-signature requirements for owner-sensitive operations, expiry, future-date rejection, previous-root matching, epoch monotonicity, and duplicate-update replay protection before any snapshot/log persistence.
- The daemon-side apply path (`IpcCommand::MembershipApply`, exposed via `rustynet membership apply --daemon`) enforces the same `apply_signed_update` gates as the file-based CLI path. Root identity at the IPC layer does NOT bypass quorum: peer-credential authorisation is necessary but not sufficient.
- Revoked nodes are denied by policy: the membership state is consulted when evaluating access; any node with status `revoked` is denied peer provisioning and marked in audit logs.
- Membership files (snapshot, log) are integrity protected (digest + chained entries). The daemon verifies integrity and rejects tampered files.

Golden vectors and schema

- Canonical encoding and state-root behaviour is pinned by unit tests inside `crates/rustynet-control/src/membership.rs` (for example `canonical_state_and_root_are_deterministic` and `canonical_payload_is_deterministic_with_tombstones`). There is no separate golden-vector test file in `crates/rustynet-control/tests/`: that directory holds `membership_model_conformance.rs` (FIS-0019, binds the real `apply_signed_update` to the TLA+ model in `documents/formal/`) and `signed_state_rollback_apply_layer.rs`. Update the pinned encoding tests only when the schema version is bumped.

Operational notes

- All membership-related cargo commands and gates are intended to run on the Debian CI host (per repo policy). Use `scripts/ci/membership_gates.sh` to run the canonical gate sequence.
- Keep private signing keys secure; never commit them.
