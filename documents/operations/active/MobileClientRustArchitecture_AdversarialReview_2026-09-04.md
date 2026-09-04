# Adversarial Review — MobileClientRustArchitecture_2026-09-04.md

- **Date:** 2026-09-04
- **Status:** Verified adversarial review of `MobileClientRustArchitecture_2026-09-04.md` (UNTRUSTED study). Every file:line citation in that document was checked against the working tree. This review does not modify the studied document.
- **Method:** direct reads of every cited file/line, `grep` sweeps for platform coupling (`cfg(target_os)`, `cfg(unix)`, `libc`, `nix`, `epoll`, `kqueue`, `std::os`) across every crate the study calls platform-free, and `wc -l` re-measurement of every claimed LOC figure.

---

## (a) Citation audit — wrong or imprecise citations, with the correct line

### a-1. `third_party/boringtun/src/lib.rs:13` — WRONG (the known suspect, confirmed)

The study's headline grounding sentence — "`third_party/boringtun/src/lib.rs:13` exposes only `pub mod noise`" — cites the wrong line. The file is 23 lines:

- `lib.rs:8` — `pub mod noise;` — this is the real noise-exposure line.
- `lib.rs:13` — `#[cfg(not(feature = "mock-instant"))]` — the cfg attribute gating `pub(crate) mod sleepyinstant;` at `:14`. This is what the cited line actually says.
- `lib.rs:19-23` — the x25519 re-export module (the study says ":19-25"; the file ends at line 23).
- The public surface is also not literally "only `pub mod noise` (plus x25519)": `lib.rs:10-11` exposes `pub mod mock_instant;` under the `mock-instant` feature.

**Substance survives:** the study's central claim behind that citation — that the in-tree platform code (device/epoll/kqueue/tun/FFI/JNI) is *not compiled* — is TRUE. `lib.rs` declares only `noise`, `mock_instant` (feature), `sleepyinstant` (cfg), `serialization` (crate-private), and `x25519`. `src/device/`, `src/ffi/`, and `src/jni.rs` exist in-tree (verified: `device/mod.rs` 884 LOC, `device/epoll.rs` 416, `device/kqueue.rs` 337, `device/tun_darwin.rs` 256, `device/tun_linux.rs` 159, `ffi/mod.rs` 397, `jni.rs` 271 — all seven figures in the study are exact) and are reachable from no module root, and `Cargo.toml` declares a single rlib target with `path = "src/lib.rs"`. "Noise-only" as a *compiled* surface is confirmed; the citation line and the "only" wording are not.

### a-2. Compiled boringtun surface "~3,600 LOC" — overstated by ~25%

Actual compiled surface (all `wc -l`, this tree): `noise/` = errors 23 + handshake 950 + mod 845 + rate_limiter 195 + session 330 + timers 335 = **2,678**; plus `lib.rs` 23 + `serialization.rs` 34 + `sleepyinstant/` 136 (or `mock_instant.rs` 36 under the feature) ≈ **2,871–2,907**. The five per-file figures the study cites (950/845/335/330/195) are each exact; the ~3,600 total is not. Total in-tree 7,586 LOC is exact.

### a-3. `RolePreset` is a nine-value enum, not eight

The study (§1.4) says "8-value `RolePreset` enum (Client/Admin/Exit/BlindExit/Relay/Anchor/Nas/Llm)". `crates/rustynet-control/src/role_presets.rs:41-51` defines **nine** variants; `BlindRelay` at `:50` is missing from the study's list (and `crates/rustynet-control/src/blind_relay.rs` exists). `validate_transition` is at `role_presets.rs:598` as cited.

### a-4. §8 table LOC arithmetic: "userspace engine + runtime + fair_drain (~7,500 LOC)"

Actual: engine 3,211 + runtime 1,911 + fair_drain 460 = **5,582**. The ~7,500 figure is reached only by adding `userspace_shared/tun.rs` (1,548 → 7,130), but the study's own table carries rustynet-tun as a separate row.

### a-5. `rustynet-cli` LOC stale

Study: "324,273 LOC". Measured this tree (`find crates/rustynet-cli/src -name '*.rs' | xargs wc -l`): **325,294**. Off by 1,021 — cosmetic, but it shows the audit numbers were taken from a different tree state than the citations claim to be "collected against".

### a-6. §1.3 "Both existing arms are plain blocking `read`/`write` over a file descriptor"

Only the Linux arm is plain `read`/`write` (`third_party/rustynet-tun/src/lib.rs:67-93`). The macOS arm is `readv`/`writev` **with mandatory 4-byte utun header framing** (`:180-215` recv strips the header; `:217-240` send prepends `[0,0,0,family]` and validates IP version first, rejecting non-IP frames). The study knows this elsewhere (§3.2/§3.3 cite the framing correctly), so §1.3's flat sentence is an internal inconsistency that, read alone, would mislead an Android implementer.

### a-7. "No platform dependency beyond a UDP socket and a tun fd" (§0.1, §1.3) — there is a third: a key file

`engine.rs`'s key provisioning is file-path based: `Tunn`-side key material is loaded by `from_private_key_file(path: &Path)` (`crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs:265`, reading via `std::fs` at `:281-284`), and the public constructor is `UserspaceBackend::new(interface_name, private_key_path, listen_port)` (`crates/rustynet-backend-userspace/src/lib.rs:52-56`, doc at `:47`: "Path to a base64-encoded WireGuard private key"). The engine imports at `engine.rs:1-13` are otherwise std + base64/boringtun/backend-api/zeroize, and `runtime.rs` imports (`:1-20`) are std + sibling modules — the I/O-loop claim itself is accurate. But on mobile there is no key *file*; keys come from Keychain/Keystore through the FFI. A memory-source key seam in the engine is real (unaccounted) work, not "None".

### a-8. §0.3 vs §8: the shim percentage contradicts itself

§0.3: "irreducible native shim … roughly 5–12% of the client codebase". §8: iOS native surface "~8–15%", Android "~7–15%". Both are unanchored assertions — no LOC basis is given for UI, navigation, project/packaging, or the callback glue — and they disagree with each other. See (b-1).

### a-9. §1.6 external-binary inventory — partially unverified

`nft` = exactly 5 `Command::new("nft", …)` sites and `/sbin/pfctl` = exactly 4, both verified by literal grep in `crates/rustynetd/src/`. Total `Command::new` occurrences in `rustynetd`: 60. But `dig`, `sysctl`, `getent`, `dscacheutil`, `ping6` did **not** appear as literal `Command::new("<bin>")` strings anywhere in the crate — if they are invoked, it is through constants/variables, and the study's flat list overstates what a literal audit shows.

### a-10. Minor imprecisions

- §1.2 dependency list for vendored boringtun omits `base64`, `hex`, and `subtle` (all present in `third_party/boringtun/Cargo.toml`); "nix (time-only)" is exact (`features = ["time"]`); "No tokio. No socket code." is exact.
- §1.1 "BackendError semantics, `backend-api/src/lib.rs:186-235`": `:186` is `pub enum BackendErrorKind`; `pub struct BackendError` is at `:194`. The range covers both, but the anchor line is the enum, not the error struct. Everything else in §1.1 checked out to the line (NodeId `:9`, SocketEndpoint `:72`, ExitMode `:91`, RouteKind `:97`, Route `:104`, PeerConfig `:111` with keepalive `:121`, RuntimeContext `:125`, BackendCapabilities `:133`, TunnelStats `:150`, `PathHealth` — an **enum** — at `:163`, PeerPathSample `:173`, trait `:237`, `:242/:244/:246/:263/:269/:278/:280/:282/:353/:357` all exact).
- §7.1 "DaemonRuntime (`daemon.rs:4655`)": `struct DaemonRuntime` is indeed at `crates/rustynetd/src/daemon.rs:4655` — but it is **not `pub`**. Nothing outside `rustynetd` can name it, which actually *strengthens* the study's "don't port it" thesis; worth stating precisely.

---

## (b) Unsound or over-optimistic claims

### b-1. The 5–12% / 85–93% numbers are invented, and low

No measurement backs them. The claimed-Rust side is real code (verified LOC), but the native side is asserted, not estimated: two UI frameworks (SwiftUI screens + Compose screens), navigation and state binding, VPN permission/consent flows, FGS notification management, NetworkCallback/NWPathMonitor forwarders, Keystore/Keychain attestation UX, packaging (Xcode + Gradle + Rust toolchain: cargo-ndk, UniFFI build plugins, ABI matrix arm64-v8a/armeabi-v7a/x86_64), plus the platform service classes. For shipped VPN clients the UI/host layer alone is routinely a quarter to a third of app-code LOC. "Logic behind every screen is Rust via FFI" moves business logic, not views, view models, or navigation. An honest range for a production client is materially higher than 5–12%; the *tunnel-process* share is what the study actually measured.

### b-2. "The native shim never touches packet bytes and never makes a trust decision" — false on Android

The engine creates its own UDP transport socket internally (`userspace_shared/socket.rs`, std `UdpSocket`). On Android, any socket that must **not** be routed into the VPN's own tun has to be exempted via `VpnService.protect(fd)` — a Java/JNI call on the VpnService instance — before the socket carries traffic, or every WG packet loops back into the tunnel. That is: (1) a security-relevant routing decision (which socket escapes the tunnel) executed by *native* code; (2) a required new seam in the engine to inject a pre-protected socket or to protect an fd via callback — exactly the kind of engine change the study's "generalize fd acquisition" line does not cover. §3.4's "normal app sockets; no entitlement needed for the WG UDP transport itself" is wrong as written for Android. This is the single largest miss in the document.

### b-3. The iOS fd story is presented more settled than it is

§0.2: "An iOS PacketTunnelProvider hands the extension exactly such an fd." The documented iOS surface is `NEPacketTunnelFlow` — packets as `NSData` arrays over an internal ring buffer. Reaching a raw file descriptor (the `WireGuardKit`-style approach of taking the flow's underlying descriptors) is undocumented behavior that can change between iOS versions. The study does flag this (§3.2 item 2, risk §9.1.2, prototype P1) — but §6.2's sketched API hardcodes the resolution it admits is unknown: `fn start_tunnel(fd: i32, settings: TunnelSettings)`. The FFI design must carry both models (fd *and* packet-array source) until P1 lands, or the sketch contradicts its own risk register.

### b-4. "rustynet-control — None, pure domain" understates real platform coupling

`rustynet-control` carries **99 platform-gated sites**: 40 `cfg(unix)`, 13 `cfg(target_os = "windows")`, 9 macos, 9 linux. It depends on `nix 0.29` (feature `user`) and does unix file-permission/UID custody checks (`membership.rs:7-13` imports `std::os::unix::fs::{MetadataExt, PermissionsExt}` and `nix::unistd::Uid` under `cfg(unix)`; `persistence.rs:34-78` does the same with a `cfg(not(unix))` fallback). It ships desktop credential backends (`credential_unwrap.rs:146+`, Linux systemd-creds with a `/usr/bin/systemd-creds` path constant). It will *compile* on iOS/Android (both are unix-family), but its custody semantics (unix mode bits on a fallback directory) do not transfer to mobile custody, where secrets live in Keychain/Keystore. By contrast `rustynet-policy`, `rustynet-dns-zone`, and `rustynet-backend-api` have **zero** platform-gated lines — the "pure domain" claim is exactly true for those three and overstated for control.

### b-5. "No core change is required" for mobile key stores (§0.4, §5.1)

The `OsSecureStore`/`KeyCustodyManager` seam exists precisely as cited (`crates/rustynet-crypto/src/lib.rs:312` trait, `:381` manager, `:390` `OsStoreFallbackPolicy`, `:411` `new_zeroizing`, `:431`/`:459` store/load; every cited symbol checked out to the line). But:

- The shipped `PlatformOsSecureStore` (`:337-379`) has macos/linux/windows arms only; on iOS/Android it hits the `cfg(not(any(…)))` arm (`:353-357`/`:373-377`) and returns `CryptoError::OsStoreUnavailable`. Fail-closed, yes — but "no core change" glosses that the OS-store path is desktop-only today and the mobile adapters are **new security-bearing code**, not configuration.
- The default policy is `OsStoreFallbackPolicy::AllowEncryptedFileFallback` (`:390-394`, `#[default]` at `:391-392`). On a phone, where an OS store is definitionally present, silently falling back to an encrypted file in app storage is a *decision the study never surfaces* — the strictest-secure-default rule (AGENTS.md §2) argues mobile must set `RequireOsSecureStore` explicitly, and the study should say so.
- Hardware "backing" verification (§5.4's startup check) has no design: Android key attestation (certificate-chain verification, Play Integrity) is substantial new verification code, absent from the plan and the LOC estimates.

### b-6. "Packet-path and security-decision code: 100% Rust" (§8) overstates the boundary

The killswitch *decision model* is Rust (`killswitch_precedence.rs` — `RuleDisposition`, `terminator_is_reachable`, `Escapes` default all verified). The killswitch *enforcement* is native by construction on both platforms (iOS: tunnel settings only, no firewall primitive; Android: VpnService lockdown + `addDisallowedApplication`). The study says this in §3.5/§4 and then contradictorily claims "100% of the security boundary is Rust" in §8. The defensible statement is: all security *decisions* are Rust; all *enforcement* is native; the decision→enforcement link is the trust-critical FFI surface nobody has designed yet (what happens when the Rust core says "Escapes ⇒ failure" and the native side must tear the tunnel down — including when the extension is being killed and cannot act).

### b-7. Execution-model fit is asserted, not designed

The engine is blocking-IO, thread-per-fd (`runtime.rs:4-6`: std threads, mpsc, blocking recv). That fits an Android foreground Service. An iOS network extension has a ~50 MB-class budget (the study cites this), no background execution, and suspended timers — the engine's keepalive/rotation timers (`boringtun timers.rs`) drift or freeze while suspended, and cold-start must be driven by native lifecycle callbacks, not just `NWPathMonitor` path changes. §4.1.5 covers network-change callbacks only; suspension/termination-driven reconnect is unaddressed.

### b-8. Precedent citation is partially wrong (§9.1.1)

"Mozilla VPN and Tailscale are operating precedents for exactly this architecture (Rust core + boringtun-lineage + UniFFI)." Mozilla VPN: yes (Rust core, UniFFI). Tailscale: no — its mobile clients are Go (gomobile) with native UI, not Rust+UniFFI. The precedent for "Rust WG core on phones" stands via Mozilla VPN alone; citing Tailscale as *this* architecture is inaccurate.

### b-9. Android "~20 LOC" and "Required work, all tiny" (§3.3)

The fd wrapper itself is ~20 LOC, true. But the same paragraph's scope ("add an Android arm … and add a cfg arm in the userspace backend") omits the protect() seam (b-2), foreground-service network rules, revoke/reconnect handling, and always-on VPN interplay. Conflating the wrapper with the integration understates the work by an order of magnitude on the platform side.

### b-10. Verified-accurate highlights (for balance)

The document's load-bearing citations are overwhelmingly accurate — this is not a sloppy study. Verified to the exact line: `engine.rs:10` `use boringtun::noise::{Packet, Tunn, TunnResult};`; `userspace_shared_macos/tun.rs:979` `open_utun_device` and `:997` `SyncDevice::from_raw_fd`; the whole `rustynet-tun` map (547 LOC; Linux `:3-129`, macOS `:131-505`, `from_raw_fd` `:242-250`, Drop `:253-262`, fail-closed fallback `:507-542` returning `io::ErrorKind::Unsupported`; libc-only deps); `backend-userspace` fail-closed gating `:21-25`/`:69-82` with the message verbatim; the device seam in `userspace_shared/tun.rs` (`fn real` `:25`, `Real(SyncDevice)` `:146`, `SyncDevice::open` call sites `:302`/`:439`); all rustynetd file LOCs (daemon.rs 38,215 with exactly 187 `cfg(target_os)`; phase10.rs 73; relay_client 2,609; gossip_runtime 2,670; port_mapper 4,666; privileged_helper 6,399) and all cited crate LOCs except rustynet-cli; `SAFE_BRINGUP_TUNNEL_MTU = 1420` (`linux_command.rs:24`) and the 1280 PMTU floor (`path_mtu.rs:66`); `ReconnectPolicy` (`resilience.rs:19`) + jittered delay (`:89`); HMAC enrollment tokens (`enrollment_token.rs:61`); CODE_MAP `:7-36`/`:311-329`/`:331-344`/`:357-363`; SecurityMinimumBar `:216-222`/`:419-424`/`:693`; zero FFI deps in any Cargo.toml; no mobile requirements in Requirements.md (the sole grep hit is the substring in "scenarios"); `is_supported_for_platform` (`vm_lab/orchestrator/role.rs:75`). The engine/userspace_shared files have zero `cfg(target_os)`/`libc`/`nix`/`epoll`/`kqueue` hits — the I/O-loop platform-freedom claim is real.

---

## (c) Missed platform assumptions

1. **`VpnService.protect()` socket exemption** (b-2) — the engine's internally-created WG transport socket loops into the tunnel without it. Requires an engine socket-injection seam plus a JNI protect call; a trust-adjacent operation living in the native shim. Unmentioned anywhere in the study.
2. **App-group / dual-container state placement (iOS).** The PacketTunnelProvider extension and the containing app have separate sandbox containers; shared state (membership bundles, replay watermarks, residue markers) must live in an app group. Replay protection *requires* durable watermark storage across cold starts (fail-closed without it). The study asserts "file-path-backed daemon state becomes app-sandbox storage via a small Rust storage trait" (§4.3) without designing the group-container, atomic-write, or cross-process (app ↔ extension) access semantics.
3. **Android doze / App Standby / FGS type declarations.** WG keepalives (25 s class) are suspended in Doze maintenance windows; reconnect semantics differ from desktop. Android 14 foreground-service type restrictions (`dataSync`/`specialUse`) constrain the VpnService host. §9.1.4 gestures at "background execution limits" with no design consequence for keepalive scheduling.
4. **Split-tunnel/per-app policy enforcement primitives.** The study's §2.1 row hands rustynet-policy the "on-device ACL evaluation for app/split-tunnel policy" job, but iOS offers no third-party per-app routing primitive of the kind Android's `Builder.addAllowedApplication()` provides (iOS has only managed `NEAppRule` exclusions on recent versions). The default-deny ACL engine has nothing per-app to bind to on iOS; the table row should say "Android only."
5. **Key attestation verification** (b-5): hardware-backing claims must be *verified* (attestation chains, StrongBox presence probing, degraded-mode policy). New code, new failure modes, absent from §5 and §9.
6. **Build/toolchain integration**: cargo-ndk + Gradle, UniFFI codegen in both Xcode and Gradle builds, static-lib linking into the app *and* the extension, simulator ABIs, bitcode-free static linking. No schedule/LOC weight anywhere, yet it gates every prototype (P1–P3).
7. **UniFFI callback surface**: NWPathMonitor/NetworkCallback → Rust requires UniFFI callback interfaces (or an event channel); §6.2 sketches `on_network_path_changed` as a plain method without settling the callback-direction design, which is where UniFFI is weakest.
8. **Enclave wrapping mechanics** (§5.2): directionally right (P-256 is the Enclave curve; X25519 cannot be generated inside), but "ECIES/`kSecAlgorithmECIESEncryption`-style flow" hand-waves a genuinely fiddly implementation (Enclave ECIES does not yield a reusable symmetric wrapping key; the standard pattern is ECDH-derived AES-GCM). Prototype risk understated.
9. **`rustynet-tun` on iOS needs new unsafe libc code** in a file whose sibling arms are unsafe-by-necessity; the workspace's `forbid(unsafe_code)` posture does not extend to `third_party/`, but the study's §4.3 claim that "nothing else needs to be native" should acknowledge the new unsafe surface and its review burden.

---

## (d) Bottom-line verdict

**Does "≈100% Rust core" hold? Yes, at the architecture level — with four corrections that must land before anyone builds on the study.**

1. The seam the study claims is real and verified end-to-end: the vendored boringtun fork compiles noise-only (platform code in-tree, unreachable from `lib.rs:8`'s module graph); the userspace engine (`engine.rs:10`) drives `boringtun::noise` from std-only I/O code with zero platform-gated lines; `backend-api` is 442 lines of pure, `#![forbid(unsafe_code)]` contract; the fail-closed platform gating pattern it proposes to extend is real and verbatim as cited (`backend-userspace/src/lib.rs:69-82`); the key-custody seam exists at the cited lines. The "reuse domain + backend-api + userspace engine, don't shrink DaemonRuntime" thesis is sound.
2. **Correction 1 — citations:** `boringtun/src/lib.rs:13` → `:8` (and the public surface includes feature-gated `mock_instant`; x25519 is `:19-23`); compiled boringtun is ~2.9k LOC not ~3.6k; `RolePreset` has nine variants (BlindRelay); §8's engine row arithmetic and rustynet-cli's LOC are off.
3. **Correction 2 — the Android protect() seam:** the dataplane is *not* fully "Rust after the fd" on Android; socket protection is a native, trust-adjacent step the engine must be restructured to accommodate. "The shim never touches packet bytes and never makes a trust decision" is false as written.
4. **Correction 3 — iOS fd is unproven:** the fd-handoff headline overstates a documented-packets-array reality; §6.2's API must not hardcode `fd: i32` until P1 resolves it.
5. **Correction 4 — "reuse unchanged" is compile-true, semantics-false for custody:** control and crypto carry real platform-gated custody code; mobile adapters, the `RequireOsSecureStore` decision, attestation verification, and app-group state design are new security-bearing work that the 5–12%/85–93% figures do not cover. A defensible public claim is: "the tunnel core and all security *decisions* are shared Rust; security *enforcement* and lifecycle are native; the decision→enforcement boundary is the design risk the prototypes must retire first."

The study is directionally trustworthy and unusually well-cited (the overwhelming majority of its file:line claims check out exactly), but it should not be executed as written until (b-2), (b-3), (b-5) and (c-2) are incorporated — those change the FFI API shape, the engine seams, and the custody defaults, not just the percentages.

---

*Review method note: all line numbers re-verified against the working tree at review time; LOC figures via `wc -l` over `src/**/*.rs` per crate; platform-coupling counts via grep over the cited crates (`rustynet-policy` 0, `rustynet-dns-zone` 0, `rustynet-backend-api` 0, `rustynet-backend-userspace` 6, `rustynet-backend-wireguard` 22, `rustynet-crypto` 63, `rustynet-control` 99).*
