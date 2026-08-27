# RustyDNS × Rustynet Tandem Integration — Operator Decree (2026-08-25)

**Operator decree (2026-08-25):** RustyDNS and Rustynet must work in tandem,
frictionlessly — each fully capable standalone, but able to "gel" together
immediately. The integration must be **user-toggleable**: turning it on or off
is a first-class, supported operation, not a hand-wired composition.

## The composition

Running rustydns on a Rustynet **exit node** does NOT automatically benefit
devices egressing through that exit — forwarded packets never touch a local
resolver process. The benefit is delivered by two mechanisms, both of which
this decree makes in-scope product work:

1. **Managed-DNS handoff (clean path).** Rustynet already controls client
   resolver state (managed/Magic DNS + DNS fail-closed, both lab-proven
   stages). When the toggle is ON for an exit that hosts rustydns, the managed
   DNS layer hands out that rustydns (via its mesh IP) as the mesh resolver, so
   every tunneled device — including roaming devices on cellular — gets
   ad/tracker blocking, encrypted DoH/DoQ upstream, and ECS stripping
   everywhere. This is the capability Pi-hole cannot offer: the blocker follows
   the device out of the house.
2. **Transparent port-53 redirect at the exit (catch-all).** For clients that
   hardcode a resolver, the exit's default-deny NAT layer redirects outbound
   plain-DNS to the local rustydns, and (optionally, same toggle family) blocks
   outbound DoT (853) and known DoH bypass endpoints.

## Requirements

- **Toggleable:** a per-exit (or per-network) switch enables/disables the
  tandem; both states are supported and tested. Default OFF until the
  composition is live-lab-proven.
- **Standalone-first:** neither project may grow a hard dependency on the
  other. rustydns keeps working with zero Rustynet present; Rustynet exits keep
  working with no rustydns installed.
- **Fail-closed on the toggle:** if the toggle is ON but rustydns is
  unhealthy/absent, client DNS must fail closed per the existing DNS
  fail-closed posture — never silently fall back to leaking plain DNS upstream.
- **Fits D13:** implementation should follow the service-hosting-roles pattern
  (`ServiceKind` lifecycle, deploy-before-signed-bundle ordering) — a `dns`
  service kind alongside `nas`/`llm` — rather than invent a parallel mechanism.

## Definition of Done (phased)

1. Compose-based integration e2e in rustydns (exit + rustydns + one client;
   assert the client's queries are blocked/encrypted through the tunnel).
2. `dns` service-kind toggle in Rustynet with unit + negative coverage
   (toggle ON with rustydns absent ⇒ fail closed, loudly).
3. Live-lab stage proving the tandem on real nodes; evidence row in the
   `--node` ledger.

## Status

- 2026-08-27: detailed design recorded in
  [`RustydnsTandemIntegrationDesign_2026-08-27.md`](./RustydnsTandemIntegrationDesign_2026-08-27.md).
  It freezes signed per-exit activation, authenticated local readiness,
  managed and transparent data paths, default-deny lifecycle, OS ownership and
  residue proof, platform limiters, and Rust `--node` evidence requirements.
- 2026-08-25: decree recorded. rustydns side: engine + privacy e2e-proven
  (UDP/TCP/DoH/DoT/DoQ, blocklists, no-client-identity-in-logs capstone);
  user-journey (plug-and-play) test lane in progress. Rustynet side:
  managed-DNS + exit-DNS-fail-closed stages lab-proven separately. The
  composition itself: not yet wired or tested anywhere.
