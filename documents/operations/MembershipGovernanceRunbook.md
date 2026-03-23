Membership Governance Runbook

Purpose

This runbook describes operator CLI flows and daemon gating for membership governance (quorum-signed membership updates).

CLI flows

- Propose an update (creates a raw update record):
  rustynet membership propose <operation> --output <update.record>

- Sign an update (approver signs a record):
  rustynet membership sign-update --record <update.record> --approver-id <id> --signing-key <key> --output <signed.update>

- Verify an update (locally verify signatures and integrity):
  rustynet membership verify-update --signed-update <signed.update> --snapshot <membership.snapshot> --log <membership.log>

- Apply an update (apply to snapshot and append to log):
  rustynet membership apply-update --signed-update <signed.update> --snapshot <membership.snapshot> --log <membership.log>

- Status (view current snapshot, root, and pending log entries):
  rustynet membership status --snapshot <membership.snapshot> --log <membership.log>

Daemon gating and policy

- The daemon must load a verified membership snapshot before provisioning peers. If snapshot verification fails, provisioning is blocked (fail-closed).
- Revoked nodes are denied by policy: the membership state is consulted when evaluating access; any node with status `revoked` is denied peer provisioning and marked in audit logs.
- Membership files (snapshot, log) are integrity protected (digest + chained entries). The daemon verifies integrity and rejects tampered files.

Golden vectors and schema

- Canonical encoding and state-root golden vectors live in `crates/rustynet-control/tests/` as `membership_schema_golden_test.rs`. These must be updated only when schema version is bumped.

Operational notes

- All membership-related cargo commands and gates are intended to run on the Debian CI host (per repo policy). Use `scripts/ci/membership_gates.sh` to run the canonical gate sequence.
- Keep private signing keys secure; never commit them.
