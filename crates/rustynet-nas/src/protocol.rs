//! NAS wire protocol (NAS design §5) — length-bounded,
//! deny-on-malformed framing per the serialization-hardening
//! posture (`SerializationFormatHardeningPlan_2026-03-25.md`).
//!
//! Transport security is NOT this layer's job: frames travel as
//! plaintext **inside** the WireGuard tunnel, and the daemon has
//! already verified the peer identity and signed-policy decision
//! before any frame reaches the decoder. This layer's job is to
//! survive hostile bytes from an *authorised* peer: every length is
//! checked against a hard cap before allocation, unknown opcodes
//! and protocol majors are refused, and trailing bytes are an error.

use std::fmt;

use crate::store::{MAX_CHUNK_LEN, MAX_MANIFEST_LEN};

/// Protocol version spoken by this node. The `hello` handshake
/// refuses unknown majors fail-closed.
pub const PROTOCOL_VERSION: u16 = 1;

/// Hard cap for one frame body (chunk payload + header slack).
pub const MAX_FRAME_LEN: usize = MAX_CHUNK_LEN + 4096;
/// Cap for string fields (snapshot ids, error messages).
pub const MAX_STRING_LEN: usize = 256;
/// Cap on snapshot listing entries in one response.
pub const MAX_SNAPSHOT_LIST: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    FrameTooLarge { len: usize },
    Truncated,
    TrailingBytes { count: usize },
    UnknownOpcode(u8),
    UnsupportedVersion { peer_version: u16 },
    FieldTooLarge { field: &'static str, len: usize },
    MalformedField { field: &'static str },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::FrameTooLarge { len } => {
                write!(f, "frame of {len} bytes exceeds cap {MAX_FRAME_LEN}")
            }
            ProtocolError::Truncated => write!(f, "frame truncated"),
            ProtocolError::TrailingBytes { count } => {
                write!(f, "{count} trailing bytes after frame body")
            }
            ProtocolError::UnknownOpcode(op) => write!(f, "unknown opcode {op:#04x}"),
            ProtocolError::UnsupportedVersion { peer_version } => write!(
                f,
                "unsupported protocol version {peer_version} (this node speaks {PROTOCOL_VERSION})"
            ),
            ProtocolError::FieldTooLarge { field, len } => {
                write!(f, "field {field} of {len} bytes exceeds its cap")
            }
            ProtocolError::MalformedField { field } => write!(f, "malformed field {field}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Client → node requests (RustyBackup contract, node side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Negotiate protocol version; the reply carries the peer's
    /// namespace quota and (optionally) a session token thumbprint.
    Hello { version: u16 },
    /// Content-addressed chunk upload (idempotent, dedup by hash).
    PutChunk { content_hash: String, data: Vec<u8> },
    /// Content-addressed chunk read (restore path).
    GetChunk { content_hash: String },
    /// Store a snapshot manifest.
    CommitSnapshot {
        snapshot_id: String,
        manifest: Vec<u8>,
    },
    /// List the caller's snapshots (their namespace only).
    ListSnapshots,
    /// Read one snapshot manifest back.
    GetSnapshot { snapshot_id: String },
    /// Soft-delete a snapshot.
    DeleteSnapshot { snapshot_id: String },
    /// Quota + usage accounting for the caller.
    Usage,
}

/// Node → client responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    HelloOk {
        version: u16,
        quota_limit_bytes: u64,
        quota_used_bytes: u64,
    },
    Ok,
    Chunk {
        data: Vec<u8>,
    },
    Snapshots {
        snapshot_ids: Vec<String>,
    },
    Snapshot {
        manifest: Vec<u8>,
    },
    Usage {
        quota_limit_bytes: u64,
        quota_used_bytes: u64,
    },
    /// Refusal. `message` is operator-readable and carries no
    /// secrets/content (ids and counts only).
    Error {
        message: String,
    },
}

mod opcode {
    pub const HELLO: u8 = 0x01;
    pub const PUT_CHUNK: u8 = 0x02;
    pub const GET_CHUNK: u8 = 0x03;
    pub const COMMIT_SNAPSHOT: u8 = 0x04;
    pub const LIST_SNAPSHOTS: u8 = 0x05;
    pub const GET_SNAPSHOT: u8 = 0x06;
    pub const DELETE_SNAPSHOT: u8 = 0x07;
    pub const USAGE: u8 = 0x08;

    pub const R_HELLO_OK: u8 = 0x81;
    pub const R_OK: u8 = 0x82;
    pub const R_CHUNK: u8 = 0x83;
    pub const R_SNAPSHOTS: u8 = 0x84;
    pub const R_SNAPSHOT: u8 = 0x85;
    pub const R_USAGE: u8 = 0x86;
    pub const R_ERROR: u8 = 0xff;
}

// ── bounded reader ────────────────────────────────────────────────

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn u8(&mut self) -> Result<u8, ProtocolError> {
        let b = *self.bytes.get(self.pos).ok_or(ProtocolError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16, ProtocolError> {
        let raw = self.take(2)?;
        Ok(u16::from_be_bytes([raw[0], raw[1]]))
    }

    fn u32(&mut self) -> Result<u32, ProtocolError> {
        let raw = self.take(4)?;
        Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }

    fn u64(&mut self) -> Result<u64, ProtocolError> {
        let raw = self.take(8)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(raw);
        Ok(u64::from_be_bytes(buf))
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self.pos.checked_add(len).ok_or(ProtocolError::Truncated)?;
        if end > self.bytes.len() {
            return Err(ProtocolError::Truncated);
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// Length-prefixed bytes with a per-field cap, checked BEFORE
    /// any allocation.
    fn bounded_bytes(&mut self, field: &'static str, cap: usize) -> Result<Vec<u8>, ProtocolError> {
        let len = self.u32()? as usize;
        if len > cap {
            return Err(ProtocolError::FieldTooLarge { field, len });
        }
        Ok(self.take(len)?.to_vec())
    }

    fn bounded_string(&mut self, field: &'static str, cap: usize) -> Result<String, ProtocolError> {
        let raw = self.bounded_bytes(field, cap)?;
        String::from_utf8(raw).map_err(|_| ProtocolError::MalformedField { field })
    }

    fn finish(self) -> Result<(), ProtocolError> {
        let remaining = self.bytes.len() - self.pos;
        if remaining != 0 {
            return Err(ProtocolError::TrailingBytes { count: remaining });
        }
        Ok(())
    }
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

// ── request codec ─────────────────────────────────────────────────

/// Encode a request frame body (opcode + payload; the transport
/// adds the u32 length prefix).
pub fn encode_request(request: &Request) -> Vec<u8> {
    let mut out = Vec::new();
    match request {
        Request::Hello { version } => {
            out.push(opcode::HELLO);
            out.extend_from_slice(&version.to_be_bytes());
        }
        Request::PutChunk { content_hash, data } => {
            out.push(opcode::PUT_CHUNK);
            push_bytes(&mut out, content_hash.as_bytes());
            push_bytes(&mut out, data);
        }
        Request::GetChunk { content_hash } => {
            out.push(opcode::GET_CHUNK);
            push_bytes(&mut out, content_hash.as_bytes());
        }
        Request::CommitSnapshot {
            snapshot_id,
            manifest,
        } => {
            out.push(opcode::COMMIT_SNAPSHOT);
            push_bytes(&mut out, snapshot_id.as_bytes());
            push_bytes(&mut out, manifest);
        }
        Request::ListSnapshots => out.push(opcode::LIST_SNAPSHOTS),
        Request::GetSnapshot { snapshot_id } => {
            out.push(opcode::GET_SNAPSHOT);
            push_bytes(&mut out, snapshot_id.as_bytes());
        }
        Request::DeleteSnapshot { snapshot_id } => {
            out.push(opcode::DELETE_SNAPSHOT);
            push_bytes(&mut out, snapshot_id.as_bytes());
        }
        Request::Usage => out.push(opcode::USAGE),
    }
    out
}

/// Decode a request frame body. Deny-on-malformed: unknown opcode,
/// truncation, oversize fields, and trailing bytes all refuse.
pub fn decode_request(body: &[u8]) -> Result<Request, ProtocolError> {
    if body.len() > MAX_FRAME_LEN {
        return Err(ProtocolError::FrameTooLarge { len: body.len() });
    }
    let mut reader = Reader::new(body);
    let op = reader.u8()?;
    let request = match op {
        opcode::HELLO => {
            let version = reader.u16()?;
            if version != PROTOCOL_VERSION {
                return Err(ProtocolError::UnsupportedVersion {
                    peer_version: version,
                });
            }
            Request::Hello { version }
        }
        opcode::PUT_CHUNK => Request::PutChunk {
            content_hash: reader.bounded_string("content_hash", 64)?,
            data: reader.bounded_bytes("chunk", MAX_CHUNK_LEN)?,
        },
        opcode::GET_CHUNK => Request::GetChunk {
            content_hash: reader.bounded_string("content_hash", 64)?,
        },
        opcode::COMMIT_SNAPSHOT => Request::CommitSnapshot {
            snapshot_id: reader.bounded_string("snapshot_id", MAX_STRING_LEN)?,
            manifest: reader.bounded_bytes("manifest", MAX_MANIFEST_LEN)?,
        },
        opcode::LIST_SNAPSHOTS => Request::ListSnapshots,
        opcode::GET_SNAPSHOT => Request::GetSnapshot {
            snapshot_id: reader.bounded_string("snapshot_id", MAX_STRING_LEN)?,
        },
        opcode::DELETE_SNAPSHOT => Request::DeleteSnapshot {
            snapshot_id: reader.bounded_string("snapshot_id", MAX_STRING_LEN)?,
        },
        opcode::USAGE => Request::Usage,
        other => return Err(ProtocolError::UnknownOpcode(other)),
    };
    reader.finish()?;
    Ok(request)
}

// ── response codec ────────────────────────────────────────────────

/// Encode a response frame body.
pub fn encode_response(response: &Response) -> Vec<u8> {
    let mut out = Vec::new();
    match response {
        Response::HelloOk {
            version,
            quota_limit_bytes,
            quota_used_bytes,
        } => {
            out.push(opcode::R_HELLO_OK);
            out.extend_from_slice(&version.to_be_bytes());
            out.extend_from_slice(&quota_limit_bytes.to_be_bytes());
            out.extend_from_slice(&quota_used_bytes.to_be_bytes());
        }
        Response::Ok => out.push(opcode::R_OK),
        Response::Chunk { data } => {
            out.push(opcode::R_CHUNK);
            push_bytes(&mut out, data);
        }
        Response::Snapshots { snapshot_ids } => {
            out.push(opcode::R_SNAPSHOTS);
            out.extend_from_slice(&(snapshot_ids.len() as u32).to_be_bytes());
            for id in snapshot_ids {
                push_bytes(&mut out, id.as_bytes());
            }
        }
        Response::Snapshot { manifest } => {
            out.push(opcode::R_SNAPSHOT);
            push_bytes(&mut out, manifest);
        }
        Response::Usage {
            quota_limit_bytes,
            quota_used_bytes,
        } => {
            out.push(opcode::R_USAGE);
            out.extend_from_slice(&quota_limit_bytes.to_be_bytes());
            out.extend_from_slice(&quota_used_bytes.to_be_bytes());
        }
        Response::Error { message } => {
            out.push(opcode::R_ERROR);
            let trimmed: String = message.chars().take(MAX_STRING_LEN).collect();
            push_bytes(&mut out, trimmed.as_bytes());
        }
    }
    out
}

/// Decode a response frame body (client side of the contract; also
/// exercised by tests/fuzzing against the node encoder).
pub fn decode_response(body: &[u8]) -> Result<Response, ProtocolError> {
    if body.len() > MAX_FRAME_LEN {
        return Err(ProtocolError::FrameTooLarge { len: body.len() });
    }
    let mut reader = Reader::new(body);
    let op = reader.u8()?;
    let response = match op {
        opcode::R_HELLO_OK => Response::HelloOk {
            version: reader.u16()?,
            quota_limit_bytes: reader.u64()?,
            quota_used_bytes: reader.u64()?,
        },
        opcode::R_OK => Response::Ok,
        opcode::R_CHUNK => Response::Chunk {
            data: reader.bounded_bytes("chunk", MAX_CHUNK_LEN)?,
        },
        opcode::R_SNAPSHOTS => {
            let count = reader.u32()? as usize;
            if count > MAX_SNAPSHOT_LIST {
                return Err(ProtocolError::FieldTooLarge {
                    field: "snapshot_list",
                    len: count,
                });
            }
            let mut snapshot_ids = Vec::with_capacity(count.min(64));
            for _ in 0..count {
                snapshot_ids.push(reader.bounded_string("snapshot_id", MAX_STRING_LEN)?);
            }
            Response::Snapshots { snapshot_ids }
        }
        opcode::R_SNAPSHOT => Response::Snapshot {
            manifest: reader.bounded_bytes("manifest", MAX_MANIFEST_LEN)?,
        },
        opcode::R_USAGE => Response::Usage {
            quota_limit_bytes: reader.u64()?,
            quota_used_bytes: reader.u64()?,
        },
        opcode::R_ERROR => Response::Error {
            message: reader.bounded_string("error_message", MAX_STRING_LEN)?,
        },
        other => return Err(ProtocolError::UnknownOpcode(other)),
    };
    reader.finish()?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hash() -> String {
        "0123456789abcdef".repeat(4)
    }

    #[test]
    fn request_round_trips_every_variant() {
        let requests = vec![
            Request::Hello {
                version: PROTOCOL_VERSION,
            },
            Request::PutChunk {
                content_hash: sample_hash(),
                data: vec![1, 2, 3, 4, 5],
            },
            Request::GetChunk {
                content_hash: sample_hash(),
            },
            Request::CommitSnapshot {
                snapshot_id: "snap-001".to_owned(),
                manifest: vec![9; 128],
            },
            Request::ListSnapshots,
            Request::GetSnapshot {
                snapshot_id: "snap-001".to_owned(),
            },
            Request::DeleteSnapshot {
                snapshot_id: "snap-001".to_owned(),
            },
            Request::Usage,
        ];
        for request in requests {
            let body = encode_request(&request);
            assert_eq!(
                decode_request(&body).unwrap(),
                request,
                "round-trip failed for {request:?}"
            );
        }
    }

    #[test]
    fn response_round_trips_every_variant() {
        let responses = vec![
            Response::HelloOk {
                version: PROTOCOL_VERSION,
                quota_limit_bytes: 64 * 1024 * 1024 * 1024,
                quota_used_bytes: 17,
            },
            Response::Ok,
            Response::Chunk {
                data: vec![0xab; 64],
            },
            Response::Snapshots {
                snapshot_ids: Vec::new(),
            },
            Response::Snapshots {
                snapshot_ids: vec!["snap-001".to_owned(), "snap-002".to_owned()],
            },
            Response::Snapshot {
                manifest: vec![7; 32],
            },
            Response::Usage {
                quota_limit_bytes: 1024,
                quota_used_bytes: 1023,
            },
            Response::Error {
                message: "quota exceeded: used 32 + requested 80 > limit 100".to_owned(),
            },
        ];
        for response in responses {
            let body = encode_response(&response);
            assert_eq!(
                decode_response(&body).unwrap(),
                response,
                "round-trip failed for {response:?}"
            );
        }
    }

    #[test]
    fn unknown_opcodes_refused() {
        assert_eq!(
            decode_request(&[0x7f]).unwrap_err(),
            ProtocolError::UnknownOpcode(0x7f)
        );
        // A response opcode arriving as a request (and vice versa) is
        // unknown on that side.
        assert_eq!(
            decode_request(&[opcode::R_OK]).unwrap_err(),
            ProtocolError::UnknownOpcode(opcode::R_OK)
        );
        assert_eq!(
            decode_response(&[0x00]).unwrap_err(),
            ProtocolError::UnknownOpcode(0x00)
        );
        assert_eq!(
            decode_response(&[opcode::HELLO]).unwrap_err(),
            ProtocolError::UnknownOpcode(opcode::HELLO)
        );
    }

    #[test]
    fn truncated_frames_refused() {
        assert_eq!(decode_request(&[]).unwrap_err(), ProtocolError::Truncated);
        assert_eq!(decode_response(&[]).unwrap_err(), ProtocolError::Truncated);

        // Every strict prefix of a valid multi-field frame refuses
        // as truncated.
        let full = encode_request(&Request::PutChunk {
            content_hash: sample_hash(),
            data: vec![1, 2, 3],
        });
        for cut in 1..full.len() {
            assert_eq!(
                decode_request(&full[..cut]).unwrap_err(),
                ProtocolError::Truncated,
                "prefix of {cut} bytes must refuse as truncated"
            );
        }
    }

    #[test]
    fn trailing_bytes_refused() {
        let mut body = encode_request(&Request::Usage);
        body.push(0x00);
        assert_eq!(
            decode_request(&body).unwrap_err(),
            ProtocolError::TrailingBytes { count: 1 }
        );

        let mut body = encode_response(&Response::Ok);
        body.extend_from_slice(&[1, 2, 3]);
        assert_eq!(
            decode_response(&body).unwrap_err(),
            ProtocolError::TrailingBytes { count: 3 }
        );
    }

    #[test]
    fn oversize_length_prefix_refused_before_allocation() {
        // A PutChunk frame claiming a chunk larger than
        // MAX_CHUNK_LEN, with no body bytes behind the claim: the
        // per-field cap must refuse before any allocation happens.
        let mut body = vec![opcode::PUT_CHUNK];
        let hash = sample_hash();
        body.extend_from_slice(&(hash.len() as u32).to_be_bytes());
        body.extend_from_slice(hash.as_bytes());
        body.extend_from_slice(&((MAX_CHUNK_LEN as u32) + 1).to_be_bytes());
        assert_eq!(
            decode_request(&body).unwrap_err(),
            ProtocolError::FieldTooLarge {
                field: "chunk",
                len: MAX_CHUNK_LEN + 1,
            }
        );

        // String-field cap on the request side.
        let mut body = vec![opcode::GET_CHUNK];
        body.extend_from_slice(&65u32.to_be_bytes());
        assert_eq!(
            decode_request(&body).unwrap_err(),
            ProtocolError::FieldTooLarge {
                field: "content_hash",
                len: 65,
            }
        );

        // Snapshot-list count cap on the response side.
        let mut body = vec![opcode::R_SNAPSHOTS];
        body.extend_from_slice(&((MAX_SNAPSHOT_LIST as u32) + 1).to_be_bytes());
        assert_eq!(
            decode_response(&body).unwrap_err(),
            ProtocolError::FieldTooLarge {
                field: "snapshot_list",
                len: MAX_SNAPSHOT_LIST + 1,
            }
        );

        // Whole-frame cap on both sides.
        let oversized = vec![0u8; MAX_FRAME_LEN + 1];
        assert_eq!(
            decode_request(&oversized).unwrap_err(),
            ProtocolError::FrameTooLarge {
                len: MAX_FRAME_LEN + 1,
            }
        );
        assert_eq!(
            decode_response(&oversized).unwrap_err(),
            ProtocolError::FrameTooLarge {
                len: MAX_FRAME_LEN + 1,
            }
        );
    }

    #[test]
    fn hello_with_wrong_version_refused() {
        for wrong in [0u16, 2, u16::MAX] {
            let body = encode_request(&Request::Hello { version: wrong });
            assert_eq!(
                decode_request(&body).unwrap_err(),
                ProtocolError::UnsupportedVersion {
                    peer_version: wrong,
                }
            );
        }
    }

    #[test]
    fn non_utf8_string_field_refused() {
        let mut body = vec![opcode::GET_SNAPSHOT];
        body.extend_from_slice(&4u32.to_be_bytes());
        body.extend_from_slice(&[0xff, 0xfe, 0x80, 0x00]);
        assert_eq!(
            decode_request(&body).unwrap_err(),
            ProtocolError::MalformedField {
                field: "snapshot_id",
            }
        );

        let mut body = vec![opcode::R_ERROR];
        body.extend_from_slice(&2u32.to_be_bytes());
        // 0xc3 0x28 is an invalid UTF-8 continuation sequence.
        body.extend_from_slice(&[0xc3, 0x28]);
        assert_eq!(
            decode_response(&body).unwrap_err(),
            ProtocolError::MalformedField {
                field: "error_message",
            }
        );
    }

    /// Deterministic LCG (Knuth MMIX constants) — no external deps.
    struct Lcg(u64);

    impl Lcg {
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
    }

    #[test]
    fn decode_never_panics_on_arbitrary_bytes() {
        // Every single-byte body (covers all opcodes, known and
        // unknown).
        for byte in 0u8..=255 {
            let _ = decode_request(&[byte]);
            let _ = decode_response(&[byte]);
        }

        // A few hundred pseudo-random buffers from a fixed seed;
        // decode must return Ok or Err — never panic, never
        // over-allocate.
        let mut lcg = Lcg(0x5eed_2026_0611_0001);
        for _ in 0..400 {
            let len = (lcg.next_u64() % 1024) as usize;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                buf.push((lcg.next_u64() >> 56) as u8);
            }
            let _ = decode_request(&buf);
            let _ = decode_response(&buf);

            // Opcode-prefixed bodies so the deeper field parsers run
            // against the random tail too.
            for op in [
                opcode::HELLO,
                opcode::PUT_CHUNK,
                opcode::COMMIT_SNAPSHOT,
                opcode::R_SNAPSHOTS,
                opcode::R_ERROR,
            ] {
                let mut prefixed = Vec::with_capacity(buf.len() + 1);
                prefixed.push(op);
                prefixed.extend_from_slice(&buf);
                let _ = decode_request(&prefixed);
                let _ = decode_response(&prefixed);
            }
        }
    }
}
