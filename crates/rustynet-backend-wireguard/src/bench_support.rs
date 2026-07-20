//! Benchmark/measurement harness for the userspace-shared dataplane
//! engine hot path. Feature-gated (`test-harness`) so it never ships
//! in production builds. It exposes a fully-handshaken engine pair
//! and the two per-packet operations — outbound encrypt
//! (`inject_plaintext_packet`) and inbound decrypt
//! (`process_inbound_ciphertext`) — so a `criterion` bench can call
//! them directly, with no sockets, no TUN device, no root, and no
//! tokio runtime.
//!
//! The harness intentionally drives a real Noise handshake to
//! completion, so the benchmarked encrypt/decrypt calls exercise the
//! same transport-data code path the worker loop hits per packet.

#![cfg(any(test, feature = "test-harness"))]

use std::io::Write;
use std::net::SocketAddr;

use base64::prelude::*;
use rustynet_backend_api::{BackendError, NodeId, PeerConfig, SocketEndpoint};

use crate::userspace_shared::engine::{EngineIoSink, UserspaceEngine};

/// MTU-ish plaintext sample size used by the bench (typical
/// 1400-byte tunneled IP packet).
pub const SAMPLE_PLAINTEXT_LEN: usize = 1400;

/// Bench/test-only [`EngineIoSink`] with no real socket or TUN device behind
/// it: it captures dispatched ciphertext (the harness needs the actual bytes
/// to feed into the next hop) and counts dispatched plaintext (the harness
/// only ever needs the count, so — unlike the ciphertext side — capturing it
/// costs no copy, matching production's zero-copy plaintext path).
#[derive(Default)]
struct CapturingIoSink {
    ciphertext: Vec<Vec<u8>>,
    plaintext_count: usize,
}

impl EngineIoSink for CapturingIoSink {
    fn send_ciphertext(
        &mut self,
        _remote_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<(), BackendError> {
        self.ciphertext.push(payload.to_vec());
        Ok(())
    }

    fn write_plaintext(&mut self, _payload: &[u8]) -> Result<(), BackendError> {
        self.plaintext_count += 1;
        Ok(())
    }
}

fn write_key_file(bytes: &[u8; 32]) -> std::path::PathBuf {
    let encoded = BASE64_STANDARD.encode(bytes);
    let dir = std::env::temp_dir().join(format!(
        "rustynet-bench-key-{}-{}",
        std::process::id(),
        // Vary by key content so the two engines get distinct files.
        bytes[0]
    ));
    std::fs::create_dir_all(&dir).expect("bench key dir");
    let path = dir.join("private.key");
    let mut f = std::fs::File::create(&path).expect("bench key file");
    f.write_all(encoded.as_bytes()).expect("write bench key");
    path
}

/// Build a minimal well-formed IPv4 packet whose destination falls
/// inside `10.0.0.0/8`, padded to `len` bytes. Enough for
/// `Tunn::dst_address` to route it and for the engine to encrypt it.
fn sample_ipv4_packet(len: usize) -> Vec<u8> {
    let mut packet = vec![0u8; len.max(20)];
    packet[0] = 0x45; // IPv4, IHL=5
    let total_len = (packet.len() as u16).to_be_bytes();
    packet[2] = total_len[0];
    packet[3] = total_len[1];
    packet[8] = 64; // TTL
    packet[9] = 17; // UDP
    // Source 10.0.0.1
    packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
    // Destination 10.0.0.2 (inside the peer's allowed IPs)
    packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
    packet
}

/// A fully-handshaken pair of userspace engines for benchmarking the
/// per-packet encrypt/decrypt path.
pub struct DataplaneEnginePair {
    sender: UserspaceEngine,
    receiver: UserspaceEngine,
    sender_node_of_receiver: NodeId,
    sender_addr: SocketAddr,
    receiver_addr: SocketAddr,
    sample: Vec<u8>,
}

impl DataplaneEnginePair {
    /// Construct two engines, configure them as each other's peer,
    /// and drive the Noise handshake to completion so transport data
    /// can flow. Panics on any setup error (bench-only).
    pub fn handshaken() -> Self {
        Self::handshaken_with_extra_peers(0)
    }

    /// Like [`Self::handshaken`], but additionally configures
    /// `extra_peers` inert filler peers on BOTH engines before the
    /// handshake, so the per-packet dispatch paths (inbound
    /// endpoint/receiver-index resolution, outbound longest-prefix
    /// selection) run against a populated peer table. The fillers use
    /// distinct endpoints and allowed-IP ranges that never match the
    /// benchmarked traffic, so the forwarded packets still resolve to
    /// the real peer — only the lookup cost scales with `extra_peers`.
    pub fn handshaken_with_extra_peers(extra_peers: usize) -> Self {
        let sender_secret = [7u8; 32];
        let receiver_secret = [9u8; 32];
        let sender_key_path = write_key_file(&sender_secret);
        let receiver_key_path = write_key_file(&receiver_secret);

        let mut sender =
            UserspaceEngine::from_private_key_file(&sender_key_path).expect("sender engine");
        let mut receiver =
            UserspaceEngine::from_private_key_file(&receiver_key_path).expect("receiver engine");

        let sender_addr: SocketAddr = "127.0.0.1:40001".parse().expect("sender addr");
        let receiver_addr: SocketAddr = "127.0.0.1:40002".parse().expect("receiver addr");

        let sender_public = x25519_public(&sender_secret);
        let receiver_public = x25519_public(&receiver_secret);

        let receiver_node = NodeId::new("bench-receiver").expect("receiver node id");
        let sender_node = NodeId::new("bench-sender").expect("sender node id");

        sender
            .configure_peer(&PeerConfig {
                node_id: receiver_node.clone(),
                public_key: receiver_public,
                endpoint: endpoint(receiver_addr),
                allowed_ips: vec!["10.0.0.0/8".to_owned()],
                persistent_keepalive_secs: None,
            })
            .expect("configure receiver as sender's peer");
        receiver
            .configure_peer(&PeerConfig {
                node_id: sender_node.clone(),
                public_key: sender_public,
                endpoint: endpoint(sender_addr),
                allowed_ips: vec!["10.0.0.0/8".to_owned()],
                persistent_keepalive_secs: None,
            })
            .expect("configure sender as receiver's peer");

        // Inert filler peers: distinct node ids, endpoints, and public keys,
        // with allowed-IP ranges (172.16.0.0/12 space) that never contain the
        // benchmarked 10.0.0.2 destination, so outbound longest-prefix
        // selection and inbound dispatch scan past them without matching.
        for filler in 0..extra_peers {
            let filler_node = NodeId::new(format!("filler-{filler:04}")).expect("filler node id");
            let mut filler_public = [0u8; 32];
            filler_public[0] = 0x55;
            filler_public[1] = (filler & 0xff) as u8;
            filler_public[2] = ((filler >> 8) & 0xff) as u8;
            let filler_config = PeerConfig {
                node_id: filler_node,
                public_key: filler_public,
                endpoint: endpoint(filler_endpoint(filler)),
                allowed_ips: vec![format!(
                    "172.{}.{}.0/24",
                    16 + (filler / 256) % 16,
                    filler % 256
                )],
                persistent_keepalive_secs: None,
            };
            sender
                .configure_peer(&filler_config)
                .expect("configure filler peer on sender");
            receiver
                .configure_peer(&filler_config)
                .expect("configure filler peer on receiver");
        }

        let mut pair = Self {
            sender,
            receiver,
            sender_node_of_receiver: receiver_node,
            sender_addr,
            receiver_addr,
            sample: sample_ipv4_packet(SAMPLE_PLAINTEXT_LEN),
        };
        pair.drive_handshake();
        pair
    }

    fn drive_handshake(&mut self) {
        // Sender → receiver handshake initiation.
        let mut init_sink = CapturingIoSink::default();
        self.sender
            .initiate_handshake(&self.sender_node_of_receiver, 1, true, &mut init_sink)
            .expect("handshake initiation");
        let init_ct = init_sink
            .ciphertext
            .into_iter()
            .next()
            .expect("handshake init ciphertext");

        // Receiver consumes init, emits response.
        let mut response_sink = CapturingIoSink::default();
        self.receiver
            .process_inbound_ciphertext(
                self.sender_addr,
                self.receiver_addr,
                &init_ct,
                1,
                &mut response_sink,
            )
            .expect("receiver processes handshake init");
        if let Some(resp_ct) = response_sink.ciphertext.into_iter().next() {
            // Sender consumes the response → handshake complete.
            let mut ack_sink = CapturingIoSink::default();
            let _ = self
                .sender
                .process_inbound_ciphertext(
                    self.receiver_addr,
                    self.sender_addr,
                    &resp_ct,
                    1,
                    &mut ack_sink,
                )
                .expect("sender processes handshake response");
        }
    }

    /// Encrypt the sample plaintext through the sender engine and
    /// return the produced ciphertext payload (outbound hot path).
    /// Returns `None` if the engine produced no data frame this call
    /// (e.g. mid-handshake) — the bench drives a completed handshake
    /// so steady state yields `Some`.
    pub fn encrypt_sample(&mut self) -> Option<Vec<u8>> {
        let mut sink = CapturingIoSink::default();
        self.sender
            .inject_plaintext_packet(&self.sample, 1, &mut sink)
            .expect("inject plaintext");
        sink.ciphertext.into_iter().next()
    }

    /// Decrypt one ciphertext datagram through the receiver engine
    /// (inbound hot path). Returns the number of plaintext packets
    /// delivered to the tunnel (1 for a data frame).
    pub fn decrypt(&mut self, ciphertext: Vec<u8>) -> usize {
        let mut sink = CapturingIoSink::default();
        self.receiver
            .process_inbound_ciphertext(
                self.sender_addr,
                self.receiver_addr,
                &ciphertext,
                1,
                &mut sink,
            )
            .expect("process inbound ciphertext");
        sink.plaintext_count
    }

    /// Forward one packet end to end: encrypt on the sender, decrypt
    /// on the receiver. This is the most representative single-frame
    /// forwarding cost and avoids anti-replay issues (each iteration
    /// uses a fresh nonce from the encrypt step).
    pub fn forward_one(&mut self) -> usize {
        match self.encrypt_sample() {
            Some(ciphertext) => self.decrypt(ciphertext),
            None => 0,
        }
    }

    /// P4 (DataplanePerfBacklog): direct probe of the endpoint reverse-index
    /// miss path on the receiver engine. `forward_one`'s steady-state data
    /// packets resolve via the (unaffected, out-of-scope) receiver-index
    /// dispatch and never reach the endpoint lookup at all, so it does not
    /// isolate this backlog item's actual change — this probe does, calling
    /// straight through to `UserspaceEngine::has_endpoint`, the same check
    /// `reject_round_trip_target`'s fail-closed path uses.
    pub fn probe_has_endpoint(&self, addr: SocketAddr) -> bool {
        self.receiver.has_endpoint(addr)
    }

    /// P4: direct probe of `UserspaceEngine::find_node_id_by_endpoint`
    /// (the function this backlog item's reverse index replaces the linear
    /// scan inside), independent of the receiver-index fast path.
    pub fn probe_find_node_id_by_endpoint(&self, addr: SocketAddr) -> Option<NodeId> {
        self.receiver.find_node_id_by_endpoint(addr)
    }

    /// The endpoint address of filler peer `index`, as configured by
    /// [`Self::handshaken_with_extra_peers`] — lets a bench address a
    /// specific configured (hit) or the highest-sorting (worst-case-for-the-
    /// old-scan) filler endpoint without duplicating the generation formula.
    pub fn filler_endpoint(index: usize) -> SocketAddr {
        filler_endpoint(index)
    }
}

fn endpoint(addr: SocketAddr) -> SocketEndpoint {
    SocketEndpoint {
        addr: addr.ip(),
        port: addr.port(),
    }
}

/// Deterministic endpoint address for filler peer `index`: distinct
/// `203.0.113.0/24`-space addresses with wrapping ports, matching the
/// `172.16.0.0/12` allowed-ips fillers configured in
/// `handshaken_with_extra_peers`.
fn filler_endpoint(index: usize) -> SocketAddr {
    SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, (index % 251) as u8)),
        50_000 + (index as u16 % 10_000),
    )
}

fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    let static_secret = boringtun::x25519::StaticSecret::from(*secret);
    boringtun::x25519::PublicKey::from(&static_secret).to_bytes()
}
