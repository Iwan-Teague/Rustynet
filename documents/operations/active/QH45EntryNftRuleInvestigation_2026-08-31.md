# QH-45 Investigation — the `entry` role's rejected nft rule (2026-08-31)

Scope: identify the exact argv `live_two_hop_validation`'s `entry` hop submitted to the
privileged helper, catalog the allowlist arms that rejected it, judge whether the rule is
legitimate for `entry` or whether the entry dataplane wrongly reuses exit-role NAT logic, and
record the disposition. All file:line references are against worktree HEAD `cc561939`
(2026-08-31). Companion to QH-45 in `documents/operations/active/QualityHardeningTodo_2026-07-25.md`.

## 0. Verdict up front

The rejected rule is **legitimate for the entry hop** and the narrow allowlist fix is
**already landed**: `85d05864` (forward-chain arm) and `2afd4dad` (NAT postrouting arm), both
2026-08-13, both ancestors of HEAD, both hairpin-only by construction and by validator pin,
with negative tests at `crates/rustynetd/src/privileged_helper.rs:4525` and `:4604`.
What is **not** done is live proof: no `live_two_hop_validation` pass has been recorded on the
`--node` run matrix since the fix (§5). The entry dataplane does **not** reuse exit-role NAT
logic — the hairpin rules are a separate, flag-gated, same-interface-only shape (§3).

## 1. The rejected argv — what `entry` emits and where

### 1.1 How the entry hop reaches these rules

The reconcile dataplane apply path sets relay forwarding before the firewall apply:

- `crates/rustynetd/src/phase10.rs:6488-6490` — `relay_with_upstream = options.exit_mode ==
  ExitMode::FullTunnel && options.serve_exit_node`, passed to
  `set_relay_forwarding(...)` immediately before `apply_firewall_killswitch()` (`:6493`).
  The two-hop topology's entry node runs FullTunnel + serve_exit_node, so this is the entry
  hop's gate. Plain exits get the flag too, but only ever match the *egress* rules (§3); the
  rejected shapes are the *hairpin* ones.
- `crates/rustynetd/src/phase10.rs:2700-2702` — `LinuxCommandSystem::set_relay_forwarding`
  stores `allow_tunnel_relay_forward`; role-agnostic dispatch at `:6027-6032`.

### 1.2 The two emitters (the rejected shapes)

First rejection (forward chain), inside `apply_firewall_killswitch`:

- `crates/rustynetd/src/phase10.rs:2889-2910` — when `allow_tunnel_relay_forward`, emits
  `forward_hairpin_accept_tokens` with `counter` observability tokens.
- Token builder `forward_hairpin_accept_tokens` `:1831-1839`:
  `iifname <tunnel_if> oifname <tunnel_if> accept`.
- `nft_add_rule_argv` `:1868-1884` inserts the observability tokens (`counter`) immediately
  before the final verdict token; the shared builders deliberately never see it.

Rendered argv (tunnel interface `rustynet0`, owned inet firewall table from
`firewall_table_name()`):

```
nft add rule inet <rustynet_fw_table> forward iifname rustynet0 oifname rustynet0 counter accept
```

Second rejection (NAT postrouting), one step later inside `apply_nat_forwarding` — the run
that allowedlisted only the forward arm died here instead (comment at
`crates/rustynetd/src/privileged_helper.rs:4520`):

- `crates/rustynetd/src/phase10.rs:3129-3153` — when `allow_tunnel_relay_forward`, emits
  `nat_hairpin_masquerade_tokens` with `counter`; on failure it deletes the NAT table and
  restores IPv4 forwarding (fail-closed rollback, `:3147-3152`).
- Token builder `nat_hairpin_masquerade_tokens` `:1854-1862`:
  `iifname <tunnel_if> oifname <tunnel_if> masquerade`.

Rendered argv (owned ip NAT table from `nat_table_name()`, the `rustynet_nat_g` table):

```
nft add rule ip <rustynet_nat_table> postrouting iifname rustynet0 oifname rustynet0 counter masquerade
```

Rollback counterparts emit the same shapes (`phase10.rs:2043-2046`, `:2173-2176`), so both
apply and rollback were blocked by the same missing arms.

The pre-fix failure chain in the QH-45 ledger entry ("firewall apply failed: i/o failed:
unsupported nft add rule argument schema" → rustynetd inactive) is the helper's fallthrough at
`crates/rustynetd/src/privileged_helper.rs:2660` rejecting one of the argv above.

## 2. The allowlist — every arm in `validate_nft_add_rule_args`

Validator entry `crates/rustynetd/src/privileged_helper.rs:2300`; every `nft add rule` argv is
matched against pinned schemas; unmatched argv falls through to the refusal at `:2660`
(`"unsupported nft add rule argument schema: {joined argv}"`, argv embedded and clamped).
Arms, in file order:

| # | Line | Arm (pinned shape) |
|---|--------|---------------------------------------------------------------------|
| 1 | :2302 | killswitch `oifname lo accept` (owned failclosed table) |
| 2 | :2312 | killswitch `ct state established,related accept` |
| 3 | :2323 | killswitch `oifname <iface> accept` |
| 4 | :2333 | forward `ct state established,related accept` |
| 5 | :2344 | forward `iifname <iif> oifname <oif> accept` |
| 6 | :2374 | forward `iifname <iif> oifname <oif> counter accept` — **hairpin-only** (`iif == oif`), added for QH-45 |
| 7 | :2405 | forward `iifname <iif> oifname <oif> <family> saddr <cidr> accept` (blind_exit, mesh-scoped) |
| 8 | :2427 | killswitch `oifname <iface> <family> daddr <ip> udp dport <port> accept comment rustynet_traversal_bootstrap` |
| 9 | :2452 | killswitch `<family> daddr <cidr> tcp dport 22 accept` |
| 10 | :2471 | killswitch `<family> daddr <cidr> tcp sport 22 accept` |
| 11 | :2490 | killswitch `<proto> dport 53 oifname != <iface> drop` |
| 12 | :2509 | killswitch `<proto> dport 53 accept` |
| 13 | :2520 | killswitch `counter drop comment rustynet_fail_closed_drop` |
| 14 | :2531 | killswitch `oifname <iface> udp dport <port> accept` |
| 15 | :2555 | killswitch `oifname <iface> udp sport <port> accept` |
| 16 | :2573 | `ip <nat_table> postrouting oifname <iface> masquerade` (owned NAT table) |
| 17 | :2583 | `ip postrouting iifname <iif> oifname <oif> masquerade` |
| 18 | :2611 | `ip postrouting iifname <iif> oifname <oif> counter masquerade` — **hairpin-only**, added for QH-45 |
| 19 | :2635 | inet dns_redirect `meta l4proto <proto> ip daddr 127.0.0.1 <proto> dport 53 redirect to <target>` (loopback only) |
| 20 | :2660 | fallthrough refusal (argv embedded, clamped) |

Arms 6 and 18 are the QH-45 additions. Both require the forwarded-in and forwarded-out
interface literals to be identical (`iif == oif`), i.e. tunnel→tunnel only. The in-code
comment at `:2605` records that both emitters hang off the same
`allow_tunnel_relay_forward` flag, "so they always appear together".

## 3. Assessment: legitimate for `entry`, not exit-logic reuse

**Legitimate.** Reasoning, each point anchored:

1. **Role-gated, not unconditional.** The emitters fire only under
   `allow_tunnel_relay_forward`, set only when the node is a FullTunnel exit-serving relay
   (`phase10.rs:6488-6490`) — in the five-node topology, the entry hop. A plain client never
   sets it; the flag defaults `false` (`phase10.rs:1122`).
2. **The shape itself is hairpin-only.** Both argv pin `iifname` and `oifname` to the *same*
   tunnel interface — tunnel-in, tunnel-out. That is exactly the entry hop's forwarding leg
   (client traffic arrives over the tunnel and is re-injected toward the upstream exit over
   the same tunnel). A final exit's forwarding leg is tunnel→egress and matches arm 5/17
   instead; it never matches a hairpin rule.
3. **`counter` is pure observability.** The comment at `phase10.rs:3130-3139` (NAT) and the
   matching one on the forward rule state `counter` changes no verdict, is inserted only by
   `nft_add_rule_argv` (`:1864-1867`), and exists because whether the hairpin SNAT *matched*
   was previously unobservable. The `chain_contains_all_tokens` matcher treats each builder
   token as an independent substring, so assertions stay valid.
4. **The hairpin SNAT is load-bearing, not cosmetic.** `phase10.rs:3131-3135`: it rewrites the
   inner source so the packet satisfies the upstream exit's /32 cryptokey routing
   (AllowedIPs for the entry node is a single /32). Dropping the rule does not merely lose
   telemetry — the two-hop request leg breaks.
5. **Exit-role egress logic is untouched and separate.** The egress masquerade
   (`nat_egress_masquerade_tokens`, emitted at `phase10.rs:3115-3120`, allowlisted at
   `:2573`) is what exit nodes use; it was never rejected. The entry hop did not reach for
   exit's rule shape; it needed one shape (same-interface forwarding + hairpin SNAT) no other
   role exercises.
6. **The widening is bounded.** Both new arms pin the interface literals to equality and the
   verdict/action to exactly `counter accept` / `counter masquerade` on the owned chains;
   nothing else in the schema space is newly accepted (§4 negative tests).

Confidence: **high (~0.9)**. Emitters, flag gate, validator arms, and negative tests were all
read in full at `cc561939`; the two fix commits' messages and the in-code comments
(`privileged_helper.rs:2605`, `:4520`; `phase10.rs:3129-3139`) explicitly cite QH-45. The
residual 0.1: the original failing argv was reconstructed from the emitters plus the failure
text, not read from the 2026-08-13 log itself — that run predated argv-embedding in refusals
(`24eb1ac8`, same day).

## 4. The landed fix and its negative tests

- `85d05864` (2026-08-13) — "Allow the entry hop's counter-bearing forward rule, and pin its
  narrowness": arm 6 (`privileged_helper.rs:2374`).
- `2afd4dad` (2026-08-13) — "Allowlist the NAT half of the hairpin too, and make both arms
  hairpin-only": arm 18 (`:2611`). The forward-only first attempt left the run failing one
  step later in `apply_nat_forwarding` (test comment `:4520`).
- Both commits are ancestors of HEAD (verified `git merge-base --is-ancestor`).

Negative tests pin the narrowness (both in `crates/rustynetd/src/privileged_helper.rs`):

- `postrouting_counter_masquerade_is_allowed_only_as_a_hairpin` `:4525` — the NAT counter arm
  must refuse when `iifname != oifname` (a tunnel→egress `counter masquerade` is still
  rejected; exits keep arm 17's bare shape).
- `forward_counter_accept_is_allowed_only_in_its_exact_narrow_shape` `:4604` — the forward
  counter arm must refuse reordered/differently-shaped near-misses.
- Test region `:4514-4696` also covers the pre-existing entry/relay hairpin accept path.

Step 1 of the ledger's ordered fix (refusal names the argv) is `24eb1ac8` (2026-08-13) with
the one-frame delivery rework in `af01f67c` (2026-08-25); `wg` refusals still never echo argv
(key material) — pinned by `nft_refusal_names_the_argv_and_wg_refusal_never_does`.

## 5. Residual gap — live verification is still outstanding

The code fix being landed is not proof. Checked 2026-08-31 against
`documents/operations/live_lab_node_run_matrix.csv` (the live `--node` ledger): every
`*_stage_two_hop` cell in all rows since 2026-08-13 is `not_run` or `skip` — no topology has
since elected an `entry` node, so `live_two_hop_validation` has **never passed** on the
`--node` ledger, before or after the fix. QH-45 should stay OPEN until a run records a
`live_two_hop_validation` pass (stage status + report artifact, not the CSV column alone).

Second caveat: the first-seen node (fedora@192.168.64.103) is firewalld-family;
`crates/rustynetd/src/linux_firewalld_zone.rs:18` records that `live_two_hop_validation` has
never passed on a firewalld-family entry node. A proving run should prefer an nftables-family
entry first (isolate the QH-45 variable from the firewalld coexistence variable), then
separately chase the firewalld-family cell.

## 6. Disposition

- Rule shape: **legitimate**; rejected shapes were §1's two hairpin argv.
- Fix: **already implemented and narrowly pinned** (`85d05864`, `2afd4dad`; arms at
  `privileged_helper.rs:2374` and `:2611`; negative tests `:4525`, `:4604`). No further
  allowlist widening is needed or warranted.
- Remaining work: a live five-node run with an nftables-family `entry` node proving
  `live_two_hop_validation` passes end to end, recorded in the `--node` run matrix and its
  report artifact; then the firewalld-family entry cell as a separate question.
