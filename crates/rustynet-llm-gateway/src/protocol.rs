//! LLM gateway wire protocol (LLM design §5.4) — persistent,
//! multiplex-friendly, length-bounded binary framing carried as
//! plaintext **inside** the WireGuard tunnel.
//!
//! Transport resolution (recorded in the D13 delta plan): the
//! design doc names gRPC/HTTP-2 as the reference transport for its
//! *properties* — persistent connection, binary frames, streamed
//! tokens, no per-request handshake, no redundant TLS. This framing
//! delivers exactly those properties with zero new dependencies
//! through the audit/licence gates; the §5.4 operation contract is
//! transport-agnostic, so a gRPC/SSE/QUIC adapter can layer over
//! the same `Request`/`Event` vocabulary without touching the
//! security gates.
//!
//! Hardening: prompts and uploaded context are attacker-influenced
//! input from *authorised* peers — every length is checked against
//! a hard cap before allocation, unknown opcodes/majors are
//! refused, trailing bytes are an error (deny-on-malformed,
//! `SerializationFormatHardeningPlan_2026-03-25.md`).

use std::fmt;

/// Protocol version. `hello` refuses unknown majors fail-closed.
pub const PROTOCOL_VERSION: u16 = 1;

/// Hard cap for one frame body.
pub const MAX_FRAME_LEN: usize = 1024 * 1024 + 4096;
/// Cap for a prompt in one completion request.
pub const MAX_PROMPT_LEN: usize = 512 * 1024;
/// Cap for one uploaded context chunk.
pub const MAX_CONTEXT_CHUNK_LEN: usize = 1024 * 1024;
/// Cap for model names and other short strings.
pub const MAX_STRING_LEN: usize = 256;
/// Cap on models in one listing.
pub const MAX_MODEL_LIST: usize = 256;

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

/// Client → gateway requests (RustyAI contract, node side). No
/// identity material anywhere: identity comes exclusively from the
/// daemon's tunnel handoff. Any future field carrying a
/// client-asserted identity would be ignored by design.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Negotiate protocol + receive the per-peer model list, quota
    /// snapshot, and (optionally) a session-token thumbprint.
    Hello { version: u16 },
    /// Models this peer may invoke (scope-filtered server-side).
    ListModels,
    /// Streamed completion. Cancellable mid-stream by the client
    /// closing the stream; severed server-side on revocation or
    /// quota exhaustion.
    Complete { model: String, prompt: String },
    /// Upload one bounded context chunk for the current session
    /// (RustyAI file-upload). Stored per-peer, evicted on session
    /// end; never written to logs.
    UploadContext { data: Vec<u8> },
    /// Token/rate accounting for the caller.
    Usage,
}

/// Gateway → client events. Completion responses arrive as a
/// sequence of `Token` events terminated by `Done` (or `Error` /
/// severance).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    HelloOk {
        version: u16,
        models: Vec<String>,
        tokens_used_in_window: u64,
    },
    Models {
        models: Vec<String>,
    },
    /// One streamed completion fragment.
    Token {
        text: String,
    },
    /// Completion finished normally.
    Done,
    ContextAccepted,
    Usage {
        tokens_used_in_window: u64,
    },
    /// Refusal or severance. Message carries ids/counts only.
    Error {
        message: String,
    },
}

mod opcode {
    pub const HELLO: u8 = 0x01;
    pub const LIST_MODELS: u8 = 0x02;
    pub const COMPLETE: u8 = 0x03;
    pub const UPLOAD_CONTEXT: u8 = 0x04;
    pub const USAGE: u8 = 0x05;

    pub const E_HELLO_OK: u8 = 0x81;
    pub const E_MODELS: u8 = 0x82;
    pub const E_TOKEN: u8 = 0x83;
    pub const E_DONE: u8 = 0x84;
    pub const E_CONTEXT_ACCEPTED: u8 = 0x85;
    pub const E_USAGE: u8 = 0x86;
    pub const E_ERROR: u8 = 0xff;
}

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

pub fn encode_request(request: &Request) -> Vec<u8> {
    let mut out = Vec::new();
    match request {
        Request::Hello { version } => {
            out.push(opcode::HELLO);
            out.extend_from_slice(&version.to_be_bytes());
        }
        Request::ListModels => out.push(opcode::LIST_MODELS),
        Request::Complete { model, prompt } => {
            out.push(opcode::COMPLETE);
            push_bytes(&mut out, model.as_bytes());
            push_bytes(&mut out, prompt.as_bytes());
        }
        Request::UploadContext { data } => {
            out.push(opcode::UPLOAD_CONTEXT);
            push_bytes(&mut out, data);
        }
        Request::Usage => out.push(opcode::USAGE),
    }
    out
}

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
        opcode::LIST_MODELS => Request::ListModels,
        opcode::COMPLETE => Request::Complete {
            model: reader.bounded_string("model", MAX_STRING_LEN)?,
            prompt: reader.bounded_string("prompt", MAX_PROMPT_LEN)?,
        },
        opcode::UPLOAD_CONTEXT => Request::UploadContext {
            data: reader.bounded_bytes("context_chunk", MAX_CONTEXT_CHUNK_LEN)?,
        },
        opcode::USAGE => Request::Usage,
        other => return Err(ProtocolError::UnknownOpcode(other)),
    };
    reader.finish()?;
    Ok(request)
}

pub fn encode_event(event: &Event) -> Vec<u8> {
    let mut out = Vec::new();
    match event {
        Event::HelloOk {
            version,
            models,
            tokens_used_in_window,
        } => {
            out.push(opcode::E_HELLO_OK);
            out.extend_from_slice(&version.to_be_bytes());
            out.extend_from_slice(&(models.len() as u32).to_be_bytes());
            for model in models {
                push_bytes(&mut out, model.as_bytes());
            }
            out.extend_from_slice(&tokens_used_in_window.to_be_bytes());
        }
        Event::Models { models } => {
            out.push(opcode::E_MODELS);
            out.extend_from_slice(&(models.len() as u32).to_be_bytes());
            for model in models {
                push_bytes(&mut out, model.as_bytes());
            }
        }
        Event::Token { text } => {
            out.push(opcode::E_TOKEN);
            push_bytes(&mut out, text.as_bytes());
        }
        Event::Done => out.push(opcode::E_DONE),
        Event::ContextAccepted => out.push(opcode::E_CONTEXT_ACCEPTED),
        Event::Usage {
            tokens_used_in_window,
        } => {
            out.push(opcode::E_USAGE);
            out.extend_from_slice(&tokens_used_in_window.to_be_bytes());
        }
        Event::Error { message } => {
            out.push(opcode::E_ERROR);
            let trimmed: String = message.chars().take(MAX_STRING_LEN).collect();
            push_bytes(&mut out, trimmed.as_bytes());
        }
    }
    out
}

fn decode_model_list(reader: &mut Reader<'_>) -> Result<Vec<String>, ProtocolError> {
    let count = reader.u32()? as usize;
    if count > MAX_MODEL_LIST {
        return Err(ProtocolError::FieldTooLarge {
            field: "model_list",
            len: count,
        });
    }
    let mut models = Vec::with_capacity(count.min(64));
    for _ in 0..count {
        models.push(reader.bounded_string("model", MAX_STRING_LEN)?);
    }
    Ok(models)
}

pub fn decode_event(body: &[u8]) -> Result<Event, ProtocolError> {
    if body.len() > MAX_FRAME_LEN {
        return Err(ProtocolError::FrameTooLarge { len: body.len() });
    }
    let mut reader = Reader::new(body);
    let op = reader.u8()?;
    let event = match op {
        opcode::E_HELLO_OK => {
            let version = reader.u16()?;
            let models = decode_model_list(&mut reader)?;
            let tokens_used_in_window = reader.u64()?;
            Event::HelloOk {
                version,
                models,
                tokens_used_in_window,
            }
        }
        opcode::E_MODELS => Event::Models {
            models: decode_model_list(&mut reader)?,
        },
        opcode::E_TOKEN => Event::Token {
            text: reader.bounded_string("token", MAX_STRING_LEN)?,
        },
        opcode::E_DONE => Event::Done,
        opcode::E_CONTEXT_ACCEPTED => Event::ContextAccepted,
        opcode::E_USAGE => Event::Usage {
            tokens_used_in_window: reader.u64()?,
        },
        opcode::E_ERROR => Event::Error {
            message: reader.bounded_string("error_message", MAX_STRING_LEN)?,
        },
        other => return Err(ProtocolError::UnknownOpcode(other)),
    };
    reader.finish()?;
    Ok(event)
}
