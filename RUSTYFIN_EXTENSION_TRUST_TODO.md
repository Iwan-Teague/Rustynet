# Rustyfin Extension Trust TODO

## Purpose
This file is a focused implementation checklist for making Rustyfin browser-extension pairing and Vault traffic work cleanly over a future Rustynet-managed private network.

The immediate problem is simple:
- the Rustyfin extension can only talk to a Rustyfin server over HTTPS if the browser trusts that server certificate
- raw IP plus self-signed certificate is not good enough for browser-extension networking
- a private VPN-style product still needs normal browser trust semantics for HTTPS

This note exists so Rustynet grows the right primitives for Rustyfin and similar self-hosted web services without depending on paid public domains or product-specific hacks.

## Current Blocker
Today, Rustyfin is reachable at an address like `https://192.168.0.36:3008`, but the certificate is self-signed.

That causes three real product problems:
- browser extensions reject the HTTPS connection even when the user can manually open the page in a browser tab
- pairing, Vault sync, autofill lookup, and save/update prompts fail because the extension cannot establish trusted HTTPS to the Rustyfin API
- IP-based addressing is brittle and does not scale cleanly to service discovery or certificate rotation

## Target Outcome
Rustynet should let Rustyfin advertise and use a stable private hostname such as:
- `https://server:3008`
- or better, a more explicit internal hostname such as `https://rustyfin-server:3008`

That hostname must:
- resolve over Rustynet DNS on joined devices
- present a certificate valid for that hostname
- chain to a Rustynet certificate authority trusted by the client device/browser
- remain stable even if the node IP changes

If those conditions are true, the Rustyfin extension can pair and operate normally without a paid public website.

## Rustynet Feasibility Assessment
This is feasible in Rustynet, and the exit-node-hosted case is the easiest practical shape.

The working model is:
- Rustyfin runs on the Rustynet exit node, or behind a local reverse proxy on that node.
- Rustynet DNS publishes a stable service hostname for Rustyfin.
- Joined clients resolve that hostname through Rustynet rather than a public DNS provider.
- The service certificate includes that hostname in SAN and chains to a Rustynet-trusted CA.
- Clients browse and pair against `https://<stable-hostname>:3008` instead of a moving LAN IP.

What this does and does not solve:
- it solves stable addressing for the browser and the extension
- it solves hostname/certificate alignment
- it does not by itself solve browser trust
- it does not let a self-signed leaf certificate become valid just because DNS is stable

So the difficult part is not the hostname. The difficult part is the private CA plus device trust bootstrap. Once that trust layer exists, the exit-node naming path is straightforward.

Recommended near-term pattern:
- canonical hostname: `rustyfin.server` or `rustyfin.exit-node`
- DNS target: the exit node's Rustynet-reachable address
- certificate: issued for the canonical hostname, not the raw IP
- access path: browser and extension use the hostname only
- fallback: raw IP should remain break-glass, not the preferred path

## Why This Needs To Exist In Rustynet
Rustyfin is not special here. Any private web app accessed through Rustynet will hit the same trust boundary.

Rustynet needs this capability because:
- private-network web apps still use browser TLS rules
- extensions cannot bypass certificate trust checks
- relying on self-signed leaf certs creates permanent operator pain
- relying on raw IPs breaks service identity and certificate management
- a network product that wants "it just works" private web UX needs private DNS plus private PKI, not only packet routing

## Required Rustynet Capabilities

### 1. Private DNS For Stable Service Names
TODO:
- define the canonical Rustynet internal naming model for nodes and services
- decide whether node names, service names, or both get first-class DNS records
- support stable hostnames that Rustyfin can use as its public/browser origin
- ensure the authoritative DNS flow remains signed and fail-closed under current Rustynet security rules

Why:
- the browser extension should target a name, not a moving IP
- TLS certificates bind much more cleanly to names than to private IPs
- this becomes the discovery layer for all internal HTTPS services, not only Rustyfin

Suggested shape:
- node hostname: `server`
- optional service hostname: `rustyfin.server` or `rustyfin-server`
- later: service-specific aliases under the managed Rustynet zone

### 2. Rustynet Root CA
TODO:
- create a Rustynet-owned private certificate authority model
- define root CA custody, encryption-at-rest, rotation, backup, and recovery requirements
- define subordinate/intermediate CA strategy if needed
- keep CA issuance and custody aligned with Rustynet security minimum bar and signed-state rules

Why:
- clients must trust a CA once, not trust each service certificate manually forever
- a real private CA is the correct long-term fix for extension trust
- self-signed leaf certs do not scale operationally

### 3. Device Trust Bootstrap
TODO:
- define how Rustynet installs or prompts installation of the Rustynet root CA on client devices
- support at minimum the target desktop/browser environments used for Rustyfin and extension testing
- define operator-visible trust status so users know whether their device trusts Rustynet web certificates
- fail clearly when trust is missing rather than silently degrading

Why:
- the extension will not work until the browser/OS trusts the Rustynet CA
- this is the critical enrollment step that turns private HTTPS into something browsers accept

Important rule:
- trust should happen at the CA level, not by telling users to accept individual self-signed cert warnings repeatedly

### 4. Service Certificate Issuance
TODO:
- issue leaf certificates for Rustynet-managed hostnames
- ensure SAN coverage matches the exact hostname Rustyfin advertises to browsers/extensions
- support renewal before expiry
- define certificate revocation or replacement flow when a node name changes or is compromised

Why:
- Rustyfin needs a certificate that matches the exact hostname shown on its Vault Extension page
- the extension and browser both require hostname/certificate alignment

### 5. Local HTTPS Termination Model
TODO:
- define whether Rustynet terminates HTTPS itself, provisions certificates to apps, or both
- define how a local app such as Rustyfin receives and reloads its cert/key material
- avoid app-specific one-off certificate wiring where possible

Why:
- Rustynet should provide a standard path for internal HTTPS services
- Rustyfin should consume a stable integration contract, not invent its own network trust stack

### 6. Rustyfin Public-Origin Integration
TODO:
- let Rustyfin use the Rustynet hostname as its browser-visible origin
- update Rustyfin public-origin/runtime-config generation to surface the Rustynet hostname instead of the LAN IP when Rustynet integration is enabled
- ensure WebSocket allowed origins, Vault Extension instructions, and runtime-config all align to the same hostname

Why:
- the extension and the Vault page must show the exact same trusted address
- origin mismatches create pairing and CORS/WebSocket breakage

### 7. Extension-Safe Reachability Verification
TODO:
- define the recommended Rustynet HTTPS verification path for internal web apps
- make sure extension-safe verification can succeed against the Rustynet hostname with no trust workarounds
- ensure Rustyfin can verify reachability using a public unauthenticated endpoint like `/runtime-config`

Why:
- Rustyfin already verifies the server URL from the extension
- once Rustynet trust is in place, that verification should succeed cleanly and deterministically

### 8. Exit Node + Service Coexistence Rules
TODO:
- document how a Rustynet exit node also hosts a web service like Rustyfin safely
- define whether service DNS should resolve to the exit-node host directly or through a service alias record
- ensure exit-node role does not interfere with local HTTPS service identity or routing

Why:
- the production plan is to run Rustynet exit-node capability and Rustyfin on the same machine
- service trust and service reachability must remain clean in that topology

Implementation note:
- if Rustyfin listens on localhost only, DNS alone is not enough; the exit node needs local HTTPS termination or a reverse proxy that exposes the service on the Rustynet-reachable interface
- if Rustyfin already binds to the exit node's reachable interface, Rustynet DNS plus a valid certificate is enough for client access
- in both cases, the browser still requires a trusted CA; DNS does not replace trust

### 9. UX Surfaces For Trust State
TODO:
- expose whether the current device/browser trusts Rustynet service certificates
- surface the canonical internal hostname users should use for extensions and private web apps
- provide actionable errors when trust is missing

Why:
- users should not have to infer TLS problems from vague connection failures
- Rustyfin can then tell the user exactly what to trust and why

### 10. Migration Off Raw IP Pairing
TODO:
- stop presenting raw LAN IPs as the preferred extension pairing address once Rustynet naming is available
- migrate Rustyfin Vault Extension instructions to the Rustynet hostname
- keep raw IP paths only as break-glass or explicitly unsupported fallback where appropriate

Why:
- IP-based pairing is the thing currently breaking trust
- once Rustynet DNS and CA exist, raw IP should no longer be the normal path

## Suggested Implementation Order
1. Finalize Rustynet private DNS naming model.
2. Implement Rustynet CA custody model.
3. Implement device trust bootstrap/install flow.
4. Implement service certificate issuance for Rustynet hostnames.
5. Define the app/service certificate delivery contract.
6. Add Rustyfin integration to advertise the Rustynet hostname as the browser-visible origin.
7. Update the Rustyfin Vault Extension page and extension pairing flow to prefer that hostname.
8. Add operator diagnostics for trust failures.
9. Add end-to-end tests with Rustyfin extension pairing over Rustynet naming.

## Rustyfin-Specific Acceptance Criteria
This work is only complete for the Rustyfin use case when all of these are true:
- Rustyfin can run on a Rustynet exit-node host
- Rustyfin is reachable by a Rustynet-managed hostname instead of a raw IP
- the browser trusts the certificate for that hostname because the Rustynet CA is trusted
- the Rustyfin Vault Extension page shows that hostname as the canonical server address
- the Rustyfin browser extension can:
  - save the server URL
  - pair successfully
  - unlock the vault
  - fetch credential matches
  - fill credentials into websites
  - save/update credentials back to the user vault
- no manual per-cert browser exception is needed

## Non-Goals
These should not be treated as the long-term solution:
- telling users to keep using raw private IPs forever
- telling users to accept browser warnings for each service manually
- shipping service-specific TLS hacks in Rustyfin instead of solving trust at the Rustynet layer
- depending on a paid public domain just to make private services work

## Testing Checklist
- Rustynet DNS resolves the selected service hostname on joined clients.
- The service certificate SAN matches the advertised hostname.
- The client/browser trusts the Rustynet CA.
- Browser fetch to the Rustyfin `/runtime-config` endpoint succeeds over the Rustynet hostname.
- The Rustyfin extension can pair using the Rustynet hostname.
- The Rustyfin extension can save and fetch vault credentials over that hostname.
- Certificate renewal does not break extension pairing.
- Host IP changes do not require re-pairing, as long as the hostname stays constant.

## Short Version
If Rustynet wants private web apps and browser extensions to work properly, it needs:
- private DNS
- a private CA
- client trust bootstrap
- per-service certificates for stable hostnames

Without those, exit-node routing alone is not enough for products like Rustyfin Vault.

For the specific Rustyfin exit-node use case, the good news is that the DNS/routing part is not the hard part. Rustynet can already carry the stable-name and signed-control-plane primitives needed for it; the remaining work is the CA, trust enrollment, and certificate lifecycle that make browser HTTPS accept the service normally.
