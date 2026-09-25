# Relay Address-Validation Default Flip (OI-10) — 2026-09-24

Status: ACTIVE — operator-facing migration note for the relay pre-auth
address-validation gate (owner decision OI-10, recorded in
`documents/operations/owner-inbox.md`).

## What changed

The relay daemon's **pre-auth address-validation gate is now DEFAULT-ON**.
Every `RelayHello` must carry a valid address-validation artifact — an
HMAC-SHA256 tag the relay issues as a `[0x06]` challenge and the client
presents back as a `[0x07]` trailing field — **before the relay performs any
ed25519 signature work** on the hello. This converts unauthenticated hello
floods from "one ed25519 verify per datagram" into "at most one cheap HMAC
per datagram, bounded by the per-source pre-auth shed".

The gate is bound to:

- the observed source socket (IP **and** port),
- the hello's session-token nonce (domain-separated),
- the issuing relay's id, and
- a 30-second expiry (plus the operator's clock-skew tolerance).

Artifacts use a dedicated HMAC domain
(`rustynet-relay-hello-addr-validation-v1`) so a blind-v2 artifact never
verifies on the v1 hello path, and vice versa. Keys are fresh per relay
process (kernel CSPRNG, never persisted); a relay restart costs each client
at most one extra challenge/retry exchange.

## New operator-facing default and opt-out

| Flag | Posture |
| --- | --- |
| *(default)* | Gate **ON** — hellos without a valid artifact are challenged |
| `--no-require-addr-validation` | Deliberate opt-out; logs a `warn:` line at startup naming the risk |

There is no config file or env override; the flag is the only opt-out and it
is deliberately loud.

## Who must upgrade

| Component | Behavior with this change |
| --- | --- |
| `rustynetd` (this tree) | Speaks the challenge/retry protocol automatically: on a `[0x06]` challenge it re-sends the hello once with the `[0x07]` artifact field. One extra round trip per session establishment — at first contact AND at every token refresh (session TTL defaults to 120 s) — and again after every relay restart (artifact keys are per-process). |
| Relay binaries **and** clients BOTH older than this change | Unaffected (gate did not exist). |
| Old relay + NEW client | New client sends hellos with no trailing artifact (until challenged); old relay ignores unknown trailing bytes on parse — but a new client never receives a challenge from it either, so sessions still establish. |
| NEW relay + old client | **Breaking.** The old client receives the `[0x06]` challenge, treats it as an unknown response, and the relay session fails. Upgrade the client, or run the relay with `--no-require-addr-validation` until the fleet is current. |

## Wire-compatibility note (W2 tightening)

`parse_relay_hello` previously stopped reading after the token field and
**silently discarded** any trailing bytes. It now accepts exactly one
optional trailing field — `[0x07] ++ artifact[32]` — and treats **any other
trailing byte as a parse error**. This is a deliberate tightening (wave5-9
defect W2): an unauthenticated sender could previously park ~64 KiB of
ignored bytes per datagram inside length accounting every hop had already
paid for. Legitimate clients never sent trailing bytes, so only senders
speaking an unknown future dialect are affected — and those must fail
closed.

## Provenance

- Owner decision: `documents/operations/owner-inbox.md` (OI-10).
- Gate design lineage: salvaged WIP `f71120cc3` (pre-auth address-validation
  DoS gate), wave5-9 verification record
  (`charter/reviews/wave5-9-verification-record-2026-09-16.md` G1/W2/W3/W4),
  blind-v2 address-validation keyring (`AddressValidationKeyRing`).
- Rustynet has no in-repo CHANGELOG; release notes are published outside the
  repository (`documents/operations/ReleaseSigningRunbook.md`), which is why
  this note carries the operator-facing migration content.
