# Manager Handover — 2026-09-11 (overnight run, draft written 04:00; finalise after the 06:35 GLM window)

Read after `ManagerHandover_2026-09-08.md` (owner rules unchanged: GLM only; commits authored Iwan-Teague, no trailers; owner runs host sudo; trust-state/validator/crypto/membership/killswitch/dataplane are manager-implemented + GLM-reviewed; secrets gate before every push).

## 1) State of main and the lab branch

- **Pushed 07:05: `main` = `f13fbf99`** (41 commits incl. B5 `de580bd9` and its GLM review fixes `f13fbf99`; review MERGE-SAFE, full gate 13,838 + secrets 22/22). both hosts are on `main` `1083ef6e` (katana via a git bundle over scp — its GitHub fetches fail; the bundle needs the `+refs/heads/main:refs/remotes/origin/main` refspec because its tracking ref was stale). `lab/pre-b5-fixes` is deleted on origin and locally (08:05).
- The night-commits GLM review (`state/review/night_review.txt`) found one blocker in my own TTL change (duplicate `TRAVERSAL_TTL_SECS` in the exit-handoff env; the bin already wrote a config-driven one) plus `Custom("client")` handling in the topology guard, five leftover non-UTF-8 fallbacks, and a stricter convergence-poll pattern — all fixed and pushed in `2c21f8ee`. Run-matrix rows written from it carry `lab/pre-b5-fixes` in the branch column (field 5), which the fetch scripts key on.
- Gate caveat learned: gating a nested worktree under `state/` with a SHARED `CARGO_TARGET_DIR` leaves that worktree's crate artifacts in the cache; the next plain-profile build on main can pick them up (the secrets gate did). Use a separate target dir per worktree, or `cargo clean -p` the affected packages.

## 2) What the night proved (all rows fetched into both ledgers)

| Host | Run | Result |
|---|---|---|
| lenovo-bot | default (×2, `f760df74`) | 38 / 0 / 28 |
| lenovo-bot | exit+blind_exit, exit+relay, exit+anchor, exit+admin (`f760df74`) | 34/0/32, 36/0/30, 34/0/32, 34/0/32 — **every role cell clean** |
| lenovo-bot | chaos + negative-control (`f65e562e`) | **50 / 1 / 28**; 4/4 negative controls, 8/9 chaos; the one fail is the clock-attack criterion (D6) |
| katana | default (`9e54d353`, `f760df74`) | 38 / 0 / 28 |
| katana | role cells (`f760df74`, after the bundle rotation) | 34/0/32, 36/0/30, 34/0/32, 34/0/32 — **clean, mirrors lenovo** |
| katana | chaos + negative-control (`f760df74`, then chaos-only on `f65e562e`) | 49 / 2 / 28, then **50 / 1 / 28 — identical to lenovo** |

**Ledger caveat:** `lab_rotate.sh` reverts the host's ledgers before checking out, so katana's runs BEFORE its bundle rotation (`9e54d353`/`e4d5b469`: default green, role cells with the pre-guard network-flap fail) were never fetched into the repo ledgers. Their report directories (`artifacts/live_lab/q-katana-*-20260910T*`) and report-local rows still exist on the host if they are ever needed; the `f760df74` reruns supersede them.

## 3) Root causes found and fixed overnight (lab side, on the branch)

1. **120 s traversal TTL re-issued mid-run** (`f75514d8`): `live_linux_managed_dns_test` and four other bins re-issued traversal bundles without `TRAVERSAL_TTL_SECS`; the issuer defaulted to 120 s, so every daemon restart two minutes later started on a stale bundle and was permanently restricted in five seconds. Issuer now refuses a missing TTL; every writer pins 24 h. This explained ALL the chaos cascades; the earlier "watermark poisoning" reading in D6 was wrong and is rewritten.
2. **Exit-only topology** (`18768ac6`, `825a63fb`, `f760df74`): seven client-dependent live stages failed instead of report-skipping on `exit + <role>` cells; one shared guard now fronts them.
3. `live_anchor` depended on the three-platform mixed-topology stage (`449d91e1`); `chaos_clock_attack` now runs last (`fb115a78`); the crash-recovery bin resets systemd's start limit per kill and polls mesh convergence to the deadline (`d43f293e`, `fbfcb9e3`, `f65e562e`); remote stderr/stdout surfaced on both ssh helpers (`0bd2f77b`, `94ed7e5d`); non-UTF-8 stage paths fail closed and chaos reports must be JSON with a verdict (`14571381`); libfaketime provisioned at guest bootstrap (`836abe0e`).

## 4) Owner decisions owed

- **D6 (rewritten, `OwnerDecisions_2026-09-07.md`)**: an EXPIRED traversal bundle permanently restricts a freshly started daemon within 5 s and a later verified refresh cannot lift it. Recommendation (a): staleness stays recoverable; only signature/replay/policy failures promote to permanent. Product change, manager-implemented, GLM-reviewed.
- Clock-attack jump-forward leg: a GLM research pass (`state/review/clock_criterion.txt`) confirmed the criterion is mis-specified (`membership_epoch=0` is the script coercing `none`; future-dated arms cannot fire on a forward jump; the daemon's refusal is the intended §3 fail-closed contract) and proposed the replacement checklist; GLM edit job `edit-1789108391301-99210-0` is implementing it in the bin (review + merge it, then a chaos rerun should read 51/0/28).
- Still open from before: katana tailnet exposure (deferred), Windows ISO, PF-01, lab password rotation, requires()/provisions() decisions.

## 5) Katana

Wi-Fi drops every few seconds (link roams across three BSSIDs of the same SSID plus an extender; no NetworkManager, no `iw`, wpa_supplicant + ifupdown). Applied at runtime: BSSID pinned to the router's 2.4 GHz radio and bgscan off via `wpa_cli` (**`save_config` refused — not persistent**), MagicDNS off (`tailscale set --accept-dns=false`, so DHCP DNS works), tailscaled `Restart=always`, lid ignored, sleep masked, `iwlwifi` power files for the next module load. GitHub fetches from katana fail most of the time; ship commits as a git bundle over scp (`state/review/pre-b5.bundle`, `katana_force_rotate.sh`). The durable fix is the Ethernet port.

## 6) Scripts left on the hosts

`~/lab_queue.sh` (serial queue: default → blind_exit → relay → anchor → admin → chaos2; stamped report dirs; records a "none: overnight queue" remedy on failed stages so the launch gate continues), `~/lab_rotate.sh` (stop queue, wait for the orchestrator, checkout, restart), `~/lab_queue_chaos_only.sh`, `~/katana_force_rotate.sh`. Logs: `state/host-lab-runs/queue-<host>.log`. Fetch host ledgers with the `git diff -U0` pattern and revert the host copies afterwards.
