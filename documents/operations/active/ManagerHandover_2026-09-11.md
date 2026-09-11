# Manager Handover — 2026-09-11 (overnight run, draft written 04:00; finalise after the 06:35 GLM window)

Read after `ManagerHandover_2026-09-08.md` (owner rules unchanged: GLM only; commits authored Iwan-Teague, no trailers; owner runs host sudo; trust-state/validator/crypto/membership/killswitch/dataplane are manager-implemented + GLM-reviewed; secrets gate before every push).

## 1) State of main and the lab branch

- **Local `main` is 35+ commits ahead of `origin/main` and UNPUSHED** because B5 (`de580bd9`, macOS Keychain probe in the key-custody report) is still waiting for its GLM security review — GLM returned 429 on every call from ~15:30 to at least 05:00 (account quota); a monitor retries from 06:35. When the review lands MERGE-SAFE: `git push origin main:main`, sync both hosts to main, `git push origin :lab/pre-b5-fixes`, `git worktree remove state/edit-worktrees/pre-b5`.
- **`origin/lab/pre-b5-fixes` = main minus B5** (cherry-picks; tip `f65e562e`). Both hosts run it. Run-matrix rows written from it carry `lab/pre-b5-fixes` in the branch column (field 5), which the fetch scripts key on.
- Full gate last ran green on `2d513e2c` (13,829 tests); later commits were gated per crate (`rustynet-cli` 9,073 tests at `f760df74`). Run the full §7 gate + secrets on main before the push.

## 2) What the night proved (all rows fetched into both ledgers)

| Host | Run | Result |
|---|---|---|
| lenovo-bot | default (×2, `f760df74`) | 38 / 0 / 28 |
| lenovo-bot | exit+blind_exit, exit+relay, exit+anchor, exit+admin (`f760df74`) | 34/0/32, 36/0/30, 34/0/32, 34/0/32 — **every role cell clean** |
| lenovo-bot | chaos + negative-control (`f65e562e`) | **50 / 1 / 28**; 4/4 negative controls, 8/9 chaos; the one fail is the clock-attack criterion (D6) |
| katana | default (`9e54d353`, `f760df74`) | 38 / 0 / 28 |
| katana | role cells (`f760df74`, after the bundle rotation) | 34/0/32, 36/0/30, 34/0/32, 34/0/32 — **clean, mirrors lenovo** |
| katana | chaos + negative-control (`f760df74`, before the convergence poll) | 49 / 2 / 28 (same two as lenovo at that commit); a chaos-only run on `f65e562e` was queued at ~05:00 |

**Ledger caveat:** `lab_rotate.sh` reverts the host's ledgers before checking out, so katana's runs BEFORE its bundle rotation (`9e54d353`/`e4d5b469`: default green, role cells with the pre-guard network-flap fail) were never fetched into the repo ledgers. Their report directories (`artifacts/live_lab/q-katana-*-20260910T*`) and report-local rows still exist on the host if they are ever needed; the `f760df74` reruns supersede them.

## 3) Root causes found and fixed overnight (lab side, on the branch)

1. **120 s traversal TTL re-issued mid-run** (`f75514d8`): `live_linux_managed_dns_test` and four other bins re-issued traversal bundles without `TRAVERSAL_TTL_SECS`; the issuer defaulted to 120 s, so every daemon restart two minutes later started on a stale bundle and was permanently restricted in five seconds. Issuer now refuses a missing TTL; every writer pins 24 h. This explained ALL the chaos cascades; the earlier "watermark poisoning" reading in D6 was wrong and is rewritten.
2. **Exit-only topology** (`18768ac6`, `825a63fb`, `f760df74`): seven client-dependent live stages failed instead of report-skipping on `exit + <role>` cells; one shared guard now fronts them.
3. `live_anchor` depended on the three-platform mixed-topology stage (`449d91e1`); `chaos_clock_attack` now runs last (`fb115a78`); the crash-recovery bin resets systemd's start limit per kill and polls mesh convergence to the deadline (`d43f293e`, `fbfcb9e3`, `f65e562e`); remote stderr/stdout surfaced on both ssh helpers (`0bd2f77b`, `94ed7e5d`); non-UTF-8 stage paths fail closed and chaos reports must be JSON with a verdict (`14571381`); libfaketime provisioned at guest bootstrap (`836abe0e`).

## 4) Owner decisions owed

- **D6 (rewritten, `OwnerDecisions_2026-09-07.md`)**: an EXPIRED traversal bundle permanently restricts a freshly started daemon within 5 s and a later verified refresh cannot lift it. Recommendation (a): staleness stays recoverable; only signature/replay/policy failures promote to permanent. Product change, manager-implemented, GLM-reviewed.
- Clock-attack jump-forward leg: its `future_state_rejected` criterion cannot fire under a forward jump (state reads stale, not future); re-derive the criterion from the daemon's contract before treating the leg as a product verdict.
- Still open from before: katana tailnet exposure (deferred), Windows ISO, PF-01, lab password rotation, requires()/provisions() decisions.

## 5) Katana

Wi-Fi drops every few seconds (link roams across three BSSIDs of the same SSID plus an extender; no NetworkManager, no `iw`, wpa_supplicant + ifupdown). Applied at runtime: BSSID pinned to the router's 2.4 GHz radio and bgscan off via `wpa_cli` (**`save_config` refused — not persistent**), MagicDNS off (`tailscale set --accept-dns=false`, so DHCP DNS works), tailscaled `Restart=always`, lid ignored, sleep masked, `iwlwifi` power files for the next module load. GitHub fetches from katana fail most of the time; ship commits as a git bundle over scp (`state/review/pre-b5.bundle`, `katana_force_rotate.sh`). The durable fix is the Ethernet port.

## 6) Scripts left on the hosts

`~/lab_queue.sh` (serial queue: default → blind_exit → relay → anchor → admin → chaos2; stamped report dirs; records a "none: overnight queue" remedy on failed stages so the launch gate continues), `~/lab_rotate.sh` (stop queue, wait for the orchestrator, checkout, restart), `~/lab_queue_chaos_only.sh`, `~/katana_force_rotate.sh`. Logs: `state/host-lab-runs/queue-<host>.log`. Fetch host ledgers with the `git diff -U0` pattern and revert the host copies afterwards.
