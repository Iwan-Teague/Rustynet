# Blind-Exit Hardware Appliance Plan (2026-07-22)

**Status: DESIGN. No schematic, BOM, or PCB layout exists yet. Nothing fabricated.** This
document is the active ledger for a new workstream: a dedicated, minimum-traceability,
privacy-focused physical appliance implementing the `blind_exit` node role — a hardware
counterpart to the existing software-only role. It supersedes
`rustynet_blind_exit_pcb_report_2026-05-10.docx` as the source of truth for this effort (see
§1.1) and should be kept current as decisions are made or revised; do not let this drift the
way the docx report did.

## 0. Purpose

Build a cheap, consumer-sellable PCB appliance that runs `rustynetd` in the `blind_exit` role,
designed from the ground up around minimizing hardware-level traceability and maximizing
anonymity for whoever operates it — not just meeting the software role's existing security
bar, but extending the same fail-closed, default-deny, no-hidden-identifier philosophy
(`CLAUDE.md` §3/§4) into the physical device.

## 1. Relationship to prior work

### 1.1 The 2026-05-10 docx report — corrected, not authoritative

`rustynet_blind_exit_pcb_report_2026-05-10.docx` (listed undescribed under Active Lab Assets
in this folder's `README.md` until this change) is an external, AI-generated analysis produced
from a separately-uploaded archive in another session, not native to this repo. Two material
problems with treating it as a spec:

- It cites a source file, `rustyjack-h616-pcb-architecture-v0.md`, that does not exist anywhere
  in this repository or its history — its own hardware claims are unverifiable from what's
  checked in.
- **Its network design is wrong for the current code.** The report's §2.1 diagram and §9.1
  policy assume NAT/masquerade is present on the appliance. The actual, currently-shipped
  `blind_exit` dataplane deliberately installs **no NAT** on either Linux or macOS — the mesh
  packet's source address is never rewritten, which is the literal "blind" property (see
  §1.2). Any network/BOM decision in the docx that assumes NAT is wrong and must not be
  carried forward.

What's still worth keeping from it: the general shape of a sealed, claim-only appliance
(no display, minimal I/O, one status LED, one recessed factory-reset button), and the idea of
a read-only rootfs with signed A/B updates (§3.3 below adopts this, corrected).

### 1.2 The `blind_exit` software role (unchanged by this plan; re-derive, don't cache)

`blind_exit` is today a pure software role. Core facts, current as of this writing —
re-verify against the code before relying on line numbers, this shifts:

- `NodeRole::BlindExit` (`crates/rustynetd/src/daemon.rs:1370`) has the narrowest IPC surface
  of any role: only `Status | Netcheck | StateRefresh | DnsInspect`.
- **No NAT.** `crates/rustynetd/src/linux_blind_exit.rs:19` / `macos_blind_exit.rs` — the mesh
  source address is never rewritten. Forward scope is mesh-CIDR-sourced traffic only,
  tunnel-only egress, no route-to/dup-to bypass primitives.
- **Irreversible**, enforced at four independent layers (CLI planner, CLI operator flag-gate,
  the membership trust boundary itself — rejects reversal even via a validly-signed update —
  and dataplane persistence, which re-applies the posture on every restart and never relaxes it
  except on `FactoryReset`). Adversarial self-audit: `crates/rustynetd/src/blind_exit_reversal_audit.rs`.
  This is why the hardware needs a real factory-reset path (§3.4).
- Linux + macOS only today; Windows is explicitly out of scope (`main.rs:13616`).

This hardware plan does not change any of the above. It designs a physical host for it.

## 2. Locked decisions

Each item below is either **LOCKED** (user decision made) or **RECOMMENDED** (my proposal,
not yet pushed back on). Nothing here is fabricated or sourced yet.

### 2.1 Network topology — LOCKED
LAN-side appliance, single Ethernet port, sits behind the user's existing router/gateway,
which performs the upstream NAT to the internet. Matches the no-NAT `blind_exit` dataplane
exactly (§1.2) — the device forwards mesh-sourced packets onto the LAN unmodified; the
upstream router is what translates them onto the public IP. User's framing: "look at it like
a Tor exit node," normally on its own network. A WAN-edge topology (device replaces the router)
was considered and rejected — it would need two NICs/routing logic of its own and contradicts
the no-NAT dataplane unless the mesh CIDR were made routable on the WAN side, a bigger
software change too.

### 2.2 CPU / SoC path — LOCKED: off-the-shelf SoC for v1
Three real paths were evaluated (user was explicit about being open to designing the CPU):

1. **Off-the-shelf ARM SoC (chosen)** — Allwinner H616/H618 class, quad Cortex-A53. Fastest
   to a real working device; board layout, firmware, and kernel choice are still fully ours.
2. **Open RISC-V softcore on an FPGA** — Lattice ECP5 has a fully open-source toolchain
   (Yosys + nextpnr + Project Trellis, zero vendor blob anywhere from RTL to bitstream);
   VexRiscv/LiteX cores on real boards (e.g. ULX3S, 85K-LUT ECP5) can boot Linux. Genuinely
   earns "designed the CPU," and sidesteps 100% of vendor-blob trust concerns. Rejected for v1:
   softcores on this class of FPGA clock roughly 15-20x slower (~50-100MHz vs ~1.2-1.5GHz hard
   silicon) and cost/draw more per unit — real risk to the throughput target, unproven either
   way. Worth a v2/parallel-track exploration once v1 is validated, not a v1 blocker.
3. **Real ASIC shuttle** (Tiny Tapeout / IHP / SkyWater-Cadence MPW) — genuinely real and
   buyable (Tiny Tapeout ~$150-300/submission on a shared 130nm tile; a dedicated
   multi-project-wafer run ~$10-12k, ~6-month turnaround). Rejected for v1: still an old
   130nm node (tens-of-MHz realistic), months per iteration on any bug, no clear
   performance/cost win over the FPGA path. A long-run stretch project, not this one.

### 2.3 Ethernet — LOCKED: Gigabit via EMAC0 + external PHY
H616 datasheet confirms **EMAC0 supports 10/100/1000 via RGMII, needing an external Gigabit
PHY**; the SoC's other port, EMAC1, is 10/100-only with an embedded PHY (no external chip, but
capped at 100Mbit). Use EMAC0. Candidate PHY (not yet sourced/qualified): Realtek **RTL8211F**
(~$0.89 reel price, ~$2.50-4.00 in 1-10pc quantities, mainline-Linux-supported, very common
reference part — [LCSC](https://www.lcsc.com/product-detail/Ethernet-ICs_Realtek-Semicon-RTL8211F-CG_C187932.html))
or the cheaper Chinese-market **YT8521** (MotorComm, mainline driver landed for Linux 6.2,
reportedly meaningfully cheaper at volume — get a real quote before relying on this).
Reference layout precedent: Orange Pi Zero 2 and BIGTREETECH CB1 both pair H616 with a
discrete DDR3L chip and this exact EMAC0+RGMII+external-PHY pattern — nothing novel about the
layout.

Cost delta over the embedded EMAC1 (10/100, $0 extra): roughly **$1-4/unit**, small against a
BOM where the SoC/RAM/eMMC/WiFi module will each individually cost more. Justification tied to
the actual throughput target (§2.5): at ~100Mbps aggregate demand, a 10/100 link would run at
100% saturation with zero headroom even at baseline — Gigabit buys ~10x headroom for a few
dollars.

### 2.4 WiFi — LOCKED: 2.4GHz-only module, backup/failover role, not primary
Ethernet is the real path; WiFi is failover only (working assumption: WiFi replaces Ethernet
when it's down, not used simultaneously alongside it — flag if wrong). Because it doesn't need
to match Ethernet's capacity, a plain 2.4GHz-only WiFi+BT SDIO/USB combo module (XR829/AIC8800/
RTL8723CS class — candidate, not yet sourced) is the right pick: cheaper than dual-band 5GHz,
better range/wall penetration for a "must still work in a pinch" role. Use a pre-certified SMD
module, not a bare radio die — sidesteps the appliance's own FCC/CE radio certification, which
matters a lot once this is an actual consumer product (§4).

Side benefit tying back to the original privacy goal: a radio that's normally idle (only
active when Ethernet fails) is passively quieter on RF most of the time than one constantly
transmitting — smaller radio fingerprint in normal operation.

### 2.5 Throughput targets — LOCKED
Derived from the product requirement "10 devices should be able to stream video comfortably,"
not sized by RAM (RAM is not the constraint — see §3.1):

- **Ethernet: 10 devices × 10Mbps/device = 100Mbps aggregate.** This is the 1080p-comfortable
  planning number (services generally treat 5Mbps as the HD floor; 10Mbps/device leaves real
  headroom for bitrate variability).
- **WiFi (failover): ~33Mbps aggregate** (user's framing: "a third of the Ethernet speed"),
  still serving all 10 devices, not a reduced subset. Fits comfortably within a cheap
  single-stream 2.4GHz module's realistic real-world throughput (~20-50Mbps sustained TCP is
  typical for that class of chip).
- **Both figures are worst-case peak, not continuous/24-7 load** (user's explicit framing:
  "it would rarely ever get to this point"). This meaningfully de-risks the whole spec: quad-A53
  + kernel WireGuard has real headroom against a rare 100Mbps peak, and thermal design only
  needs to handle occasional bursts, not sustained max load (a passive heatsink/thermal pad is
  very likely sufficient — see §5).
- If a 4K-comfortable bar is wanted instead of 1080p, the same method gives roughly
  25-30Mbps/device → ~250-300Mbps aggregate; not the current target, noted for reference.

### 2.6 WireGuard backend — LOCKED: kernel, not userspace
Use `rustynet-backend-wireguard` (kernel module), not `rustynet-backend-userspace`
(boringtun), on this hardware class. Real-world WireGuard throughput on small ARM boards is
normally capped by packet-processing/context-switch overhead, not the ChaCha20-Poly1305
cipher itself (which is fast in software/NEON by design) — kernel WireGuard avoids the
userspace round-trip per packet and is commonly reported 20-40%+ faster than userspace
implementations at this scale.

### 2.7 Power — RECOMMENDED, not yet explicitly confirmed
USB-C input (locked from the original ask), **fixed 5V** via CC1/CC2 pull-down resistors per
the USB-C spec — no PD negotiation controller chip. This board's power draw is modest (SoC +
RAM + eMMC + one Ethernet PHY + one WiFi module, no display); full USB-C PD is cost/complexity
this device doesn't need. Revisit if a reason for PD surfaces (e.g. wanting to draw more than a
basic 5V/2-3A default affords).

### 2.8 Privacy/security hardening — LOCKED
Verified via the H616 datasheet/devicetree, not assumed:

- H616 has a real **Crypto Engine** (`crypto@1904000`: AES/DES/RSA/MD5/SHA + **TRNG**) — use it
  for WireGuard/boringtun key-generation entropy and for at-rest encryption of whatever
  ephemeral state exists. Genuinely useful, no traceability downside.
- H616 has an **eFuse/SID block** (`0x03006000`) burning a unique-per-die Chip ID at the fab,
  present regardless of whether it's ever used. This is a **liability, not a feature** for a
  min-traceability device: no software path may ever read, log, or transmit it.
- **No vendor secure boot, no vendor Android BSP.** Mainline U-Boot + mainline Linux kernel
  only. Two reasons: (a) burning a per-unit secure-boot key is itself a traceability cost
  (ties a board to a specific provisioning event) — if secure boot is ever wanted, the same
  key must be burned across a whole batch, never per-unit; (b) Allwinner's vendor BSP family
  has a real historical precedent for shipping a backdoor —
  [CVE-2016-10225](https://www.cvedetails.com/cve/CVE-2016-10225/), the `sunxi-debug` `/proc`
  root-escalation driver in the old 3.4 legacy Android BSP kernel for **H3/A83T/H8** (not H616 —
  different chip, different kernel branch, no H616-specific CVE found). The mitigation is the
  policy, not a chip-specific guarantee, and it's practical: Armbian officially maintains
  mainline-tracking H616/H618 board support today (Orange Pi Zero 2/Zero 3, U-Boot bumped to
  2026.07-rc4), and linux-sunxi describes mainline kernel support for this chip as "almost
  suitable for normal use."
- No persistent on-device logging (matches the role's least-privilege posture already).
- No unique serial silkscreened and tied to a sales record; generic/common passives, no exotic
  parts that narrow sourcing traceability.

## 3. RAM and eMMC

### 3.1 RAM — RECOMMENDED: 1GB discrete DDR3L
H616 datasheet confirms a 32-bit DDR4/DDR3/DDR3L/LPDDR3/LPDDR4 interface, up to 4GB, BGA
package; real reference boards (Orange Pi Zero 2, BIGTREETECH CB1) pair it with a **discrete**
DDR3L chip, not package-on-package — standard, well-proven layout, nothing exotic.

**RAM is not driven by the 10-device target** — a WireGuard peer session is kilobytes of state
(keys, counters, allowed-IPs), so even 512MB is vastly more than 10 (or 1,000) peers need from
a pure memory-storage standpoint. The real driver is running a full Linux distro + `rustynetd`
(membership/gossip state, ACL/policy tables, DNS-zone cache) with enough slack on a sealed
device that's hard to field-upgrade.

- **512MB**: workable floor for a minimal headless Linux + `rustynetd`. Real precedent:
  Orange Pi Zero 2 ships this as its cheaper LPDDR3 SKU.
- **1GB (recommended)**: same board family's other real SKU, "slightly different cost" per
  that product's own listings — i.e. the delta is small in this exact chip's ecosystem. Buys
  meaningful headroom for kernel/`rustynetd` updates over the device's field life, worth it on
  a sealed appliance you can't easily open up and reflash RAM into.
- **2GB+**: not justified for `blind_exit`'s narrow scope (no local admin UI, no heavy service
  hosting — that's `nas`/`llm` territory, not this role).

### 3.2 Storage — RECOMMENDED: 8GB soldered eMMC (not microSD)
**Soldered eMMC, not a removable microSD slot** — this is a deliberate privacy choice, not
just a reliability one. A removable card is a "pull it and read it in a laptop" attack surface
that directly undermines the minimum-traceability goal; it's also a mechanical failure point a
soldered chip doesn't have. (Note: the cheapest Orange Pi Zero 2 hobbyist SKU uses microSD
instead — that's a hobbyist-board cost optimization, not the right call for a privacy-focused
consumer product. An older Zero2 2019 announcement did list an eMMC option, confirming it's a
known-compatible configuration for this SoC family.)

- **4GB**: workable minimum only with a genuinely minimal (Buildroot-class) image + A/B slots —
  tight, and trades BOM dollars for real engineering effort to build/maintain that image.
- **8GB (recommended)**: comfortable margin for a more standard Armbian/Debian-minimal-based
  image with A/B update slots (§3.3) plus a small data partition, without paying for capacity
  this narrow forwarding-only role won't use.
- **16GB+**: not justified here — that headroom matters for `nas`/`llm`, not `blind_exit`.

Cost note, honestly hedged: no precise current quote for either step (512MB→1GB RAM,
4GB→8GB eMMC) — general embedded-market figures suggest a few dollars per size-tier step,
consistent with Orange Pi Zero 2's two RAM SKUs differing only "slightly" in price, but **get
real quotes at BOM-lock time, not before** — eMMC/DDR pricing has been under real, current
market pressure (reported 30%+ regional price swings and eMMC lead times stretching past 20
weeks recently), so treat any number here as directional, not fixed.

### 3.3 Update architecture — RECOMMENDED: read-only rootfs, signed A/B, no swap-on-flash
Worth keeping from the old docx report, corrected of its NAT error: a **read-only rootfs with
signed A/B update slots** (atomic switchover, verify-then-commit, no bricking on a failed
update). This is what the 8GB eMMC recommendation is sized for.

**No swap on eMMC.** Swapping to flash wears it out faster, and — more importantly for this
device — anything swapped out could persist as forensically recoverable data on the flash even
after power-off, which is a direct anti-pattern for a minimum-traceability device. If any
swap-like memory headroom is ever wanted, use **zram** (compressed, RAM-backed swap that never
touches persistent storage) instead.

### 3.4 Recovery path — CONFIRMED: Allwinner FEL USB mode, no SD slot needed
H616's boot ROM has a built-in **FEL** USB recovery mode (`sunxi-fel` tooling, USB VID/PID
`1f3a:efe8` referenced for H616 devices) — lets a host reflash the device over USB-OTG even
with blank/corrupted eMMC, with no removable-card slot required. This is a good architectural
fit: it gives a real hardware-level recovery/reflash path that dovetails with `blind_exit`'s
existing software-level "irreversible — requires factory reset" invariant (§1.2), without
reintroducing the removable-storage privacy problem §3.2 avoids.

## 4. Consumer-product considerations (beyond pure PCB engineering)

Explicitly in scope now — "cheap for consumers," not just a hobbyist build:

- Pre-certified WiFi module (§2.4) sidesteps the appliance's own FCC/CE **radio** certification
  — rolling a custom RF design would mean certifying it yourself, real money and months.
- Fixed-5V USB-C power (§2.7), no custom power brick — rely on chargers the consumer already
  owns or a pre-certified one; don't design/certify your own.
- Still needed before real retail sale, not a design blocker today: device-level EMC/safety
  certification (FCC Part 15 / CE) covering the whole board (not just the radio module),
  RoHS-compliant components, and retail packaging/labeling.

## 5. Open items / must-validate-before-BOM-lock

1. **Benchmark the throughput target on real hardware before finalizing the schematic.** No
   verified number exists yet for H616-class silicon running `rustynetd` specifically. Cheapest
   path: an **Orange Pi Zero 2 — NOT "Zero 2W"** (~$20-30, get the 1GB DDR3 SKU to match §3.1)
   or a Pi Zero 2 W (same Cortex-A53 core class, ~$15-20). **The "2W" is a different, newer
   board (Allwinner H618, LPDDR4) with no built-in Ethernet at all** (needs an optional
   expansion board, and even that's only 10/100, not Gigabit) — wrong pick for an
   Ethernet-primary design, easy to grab by mistake since the names are one letter apart.
   Orange Pi has also reused the bare "Zero2" name before for a 2019-era board on a different
   SoC — confirm the listing says H616 + Gigabit Ethernet before buying.

   Run **64-bit (aarch64)** — not 32-bit, which sidesteps the `u128`/`AtomicU64` bug blocking
   the 32-bit ARM path in `Requirements.md` entirely, since aarch64 Linux is already a proven
   Rustynet live-lab target. **Flash a mainline-tracking image (e.g. mainline Armbian), not the
   vendor default** — Orange Pi's stock Debian/Ubuntu/Android images may carry
   Allwinner/Orange-Pi BSP patches, and testing against those wouldn't actually validate the
   mainline-kernel-only decision in §2.8. Build `rustynetd` for aarch64, run it as `blind_exit`
   with the kernel backend, real `iperf3` multi-client load.

   What this validates well: CPU/crypto throughput ceiling and Ethernet MAC/PHY behavior
   (same SoC, same EMAC0+external-GbE-PHY architecture as planned). What it doesn't: thermal
   (bare board / clip-on heatsink reads optimistic vs. the final sealed enclosure — re-test once
   the enclosure exists), and the exact WiFi module (dev board's on-board chip is the same
   *class* of hardware, not necessarily the same part we'd source). Given the target is now a
   rare peak rather than continuous load (§2.5), this is now a sanity check, not a
   make-or-break gate — but still do it before spinning a real PCB.
2. **Multi-core RX packet distribution** — confirm whether the chosen Ethernet MAC/PHY combo
   supports multi-queue RX (RSS); if not, plan on Linux's software RPS (Receive Packet
   Steering) so inbound processing isn't pinned to one core regardless of having four.
   Lower-stakes now that the target is a rare peak, but still worth checking.
3. **Thermal**: passive heatsink/thermal pad, sized for occasional peak bursts rather than
   sustained max load (per the now-confirmed peak-not-continuous framing).
4. **Component sourcing/pricing**: every price cited in this document (Ethernet PHY, RAM,
   eMMC) is directional, pulled from public distributor listings and general market
   commentary, not a firm quote. Get real quotes (Digikey/Mouser/LCSC/Alibaba) once parts are
   shortlisted, and re-check given current DRAM/eMMC market volatility (§3.2).
5. **H616 vs H618**: functionally near-identical for this design (H618 just has a larger L2
   cache); pick based on availability/price once sourcing starts.
6. **Not yet discussed at all**: enclosure design, exact full component shortlist/BOM
   assembly, physical anti-tamper details beyond the recessed reset button.
7. **FPGA/open-softcore CPU path** (§2.2 option 2): parked as a v2/parallel track, not
   scheduled.

## 6. Rough cost estimate (2026-07-22)

Directional only — no real quotes obtained, get those at BOM-lock time (§5).

**Component BOM, per unit at a ~100-500 unit batch:**

| Part | Est. cost |
|---|---|
| H616/H618 SoC | $5-8 ([LCSC lists H616 from $7.57](https://www.lcsc.com/product-detail/C5365289.html) at small qty) |
| RAM, 1GB DDR3L | $2-4 |
| eMMC, 8GB | $2-4 |
| Gigabit Ethernet PHY | $1-4 (§2.3) |
| WiFi+BT module, pre-certified | $3-8 (no hard quote found, wider hedge) |
| Power regulation (bucks/LDOs) | $1-3 |
| USB-C + RJ45 connectors | $1.50-3 |
| Misc passives, LED, reset button | $2-5 |
| **Component subtotal** | **~$20-35** |

**PCB fab + assembly + enclosure:** bare PCB (4-6 layer) ~$2-8/unit at this batch size; SMT
assembly+test ~$10-50/board at 10-100 units dropping 30-50% by 1,000 units, plus a one-time
$150-500 stencil/setup fee; enclosure (undesigned, off-the-shelf/low-volume case, no dedicated
tooling) ~$3-10/unit.

**Rough total: ~$35-70 landed per unit at 100-500 unit scale, most likely ~$40-55 central
estimate** — parts + bare board + assembly + basic case, no margin, no shipping, no
certification amortized in. A tiny 1-10 unit prototype run costs meaningfully more per unit
(~$100-250+) since none of the volume pricing applies (component MOQs, prototype PCB fab
pricing, hand/low-volume assembly labor).

**One-time costs, not per-unit — the real gate before retail:** assembly stencil/setup
($150-500); enclosure injection-mold tooling, only if going that route at real volume
($2,000-10,000+, skip until volume justifies it); **device-level FCC/CE certification
(realistically $3,000-15,000+)** — the pre-certified WiFi module only covers the radio, the
finished host device typically still needs its own test/filing before real retail sale. Not
needed to build/use prototypes, but it's what actually separates "built one" from "sells to
consumers."

**Cheap sanity-check anchor**: the Orange Pi Zero 2 (same SoC, 1GB DDR3, WiFi+BT, Gigabit
Ethernet — nearly this exact spec) launched at
[$18.99 retail](https://www.tomshardware.com/news/orange-pi-zero2-small-powerful-cost-effective)
(current market price has drifted to $35-39 due to scarcity/reseller markup). A real
mass-produced product selling a very similar board *with margin included* for under $19
originally is a solid ceiling check on the component math above, and buying one doubles as the
throughput-benchmark board from §5 item 1.

## 7. Sources

Web research performed 2026-07-22, current as of that date — component pricing and mainline
kernel support maturity in particular can move; re-check before relying on exact figures.

- [H616 Datasheet (linux-sunxi)](https://linux-sunxi.org/images/b/b9/H616_Datasheet_V1.0_cleaned.pdf) — crypto engine, eFuse/SID, EMAC0/EMAC1, DRAM interface
- [H616 — linux-sunxi.org](https://linux-sunxi.org/H616)
- [CVE-2016-10225 details](https://www.cvedetails.com/cve/CVE-2016-10225/) — Allwinner H3/A83T/H8 legacy-BSP backdoor, confirmed not applicable to H616
- [Kernel Backdoor found in Gadgets Powered by Popular Chinese ARM Maker](https://thehackernews.com/2016/05/android-kernal-exploit.html?m=1)
- [Armbian H616 mainlining forum thread](https://forum.armbian.com/topic/26290-h616-mainlining-effort/)
- [RTL8211F-CG — LCSC](https://www.lcsc.com/product-detail/Ethernet-ICs_Realtek-Semicon-RTL8211F-CG_C187932.html)
- [FEL — linux-sunxi.org](https://linux-sunxi.org/FEL) / [sunxi-fel manpage](https://manpages.debian.org/unstable/sunxi-tools/sunxi-fel.1)
- [Lattice ECP5 open toolchain — Project Trellis](https://github.com/YosysHQ/prjtrellis)
- [Tiny Tapeout](https://tinytapeout.com/chips/tt09/) / [Efabless chipIgnite cost reporting](https://www.embedded.com/efabless-chipignite-enables-soc-for-9750-in-skywater-cmos-node/)
- Orange Pi Zero 2 / BIGTREETECH CB1 reference-design precedent (H616 + discrete DDR3L +
  EMAC0/RGMII+external-PHY): general product-listing research, no single authoritative URL
- [H616 — LCSC pricing](https://www.lcsc.com/product-detail/C5365289.html) — §6 cost estimate
- [PCB assembly cost guide — PCBCart](https://www.pcbcart.com/article/content/how-much-does-pcb-assembly-cost.html) / [JLCPCB PCBA cost breakdown](https://jlcpcb.com/blog/pcba-cost-breakdown) — §6 assembly cost ranges
- [Orange Pi Zero 2 retail pricing — Tom's Hardware](https://www.tomshardware.com/news/orange-pi-zero2-small-powerful-cost-effective) — §6 cost anchor
