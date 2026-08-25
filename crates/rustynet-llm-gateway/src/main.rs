//! `rustynet-llm-gateway` daemon binary — the tunnel-only,
//! default-deny, no-API-key inference endpoint for the `llm`
//! preset (LLM design §3/§4).
//!
//! Fail-closed startup: non-tunnel-shaped bind, non-loopback engine
//! endpoint, or an unusable session-signing key each refuse to
//! start. Identity comes ONLY from the tunnel source address
//! resolved against the daemon-written signed-state map; the wire
//! protocol carries no identity material, and there is no API key.
//!
//! Revocation severance happens at three layers here: per-frame
//! grant re-check, per-token-event grant re-check during streaming
//! (a revoked peer's in-flight generation is cut mid-stream), and
//! the daemon's exposure controller tearing the listener down.
//!
//! Logs carry ids/thumbprints/counts only — never prompts,
//! completions, uploaded context, or tokens.

#![cfg(feature = "daemon")]
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rustynet_llm_gateway::enforce::EnforcementState;
use rustynet_llm_gateway::engine::{
    CompletionEvent, InferenceEngine, MockEngine, validate_engine_endpoint,
};
use rustynet_llm_gateway::protocol::{self, Event, MAX_FRAME_LEN, PROTOCOL_VERSION, Request};
use rustynet_policy::LlmAccessScope;

const ACCESS_GRANTS_FILE: &str = "grants.v1";
const ACCESS_PEERS_FILE: &str = "peers.v1";
const ACCESS_SCOPES_FILE: &str = "scopes.v1";

fn main() {
    let exit_code = match run() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("[rustynet-llm-gateway] fatal (fail-closed): {err}");
            1
        }
    };
    std::process::exit(exit_code);
}

struct Config {
    bind: SocketAddr,
    access_dir: PathBuf,
    mock_models: Vec<String>,
}

fn run() -> Result<(), String> {
    let config = parse_and_validate_config()?;
    let engine: Arc<dyn InferenceEngine + Send + Sync> =
        Arc::new(MockEngine::serving(config.mock_models.clone()));
    let enforcement = Arc::new(Mutex::new(EnforcementState::new()));
    let access_dir = Arc::new(config.access_dir);

    let listener = TcpListener::bind(config.bind)
        .map_err(|err| format!("bind {} failed: {err}", config.bind))?;
    eprintln!(
        "[rustynet-llm-gateway] serving on {} (default-deny, no API key; access state from {})",
        config.bind,
        access_dir.display()
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // Disable Nagle: the streaming path emits one small frame per
                // token event and must not stall on delayed ACKs. A failed
                // setsockopt is logged but must not kill the session.
                if let Err(err) = stream.set_nodelay(true) {
                    eprintln!("[rustynet-llm-gateway] set_nodelay failed (continuing): {err}");
                }
                let engine = Arc::clone(&engine);
                let enforcement = Arc::clone(&enforcement);
                let access_dir = Arc::clone(&access_dir);
                std::thread::spawn(move || {
                    if let Err(err) =
                        serve_connection(stream, engine.as_ref(), &enforcement, &access_dir)
                    {
                        eprintln!("[rustynet-llm-gateway] session ended: {err}");
                    }
                });
            }
            Err(err) => eprintln!("[rustynet-llm-gateway] accept failed: {err}"),
        }
    }
    Ok(())
}

fn parse_and_validate_config() -> Result<Config, String> {
    let mut bind: Option<SocketAddr> = None;
    let mut engine_endpoint: Option<SocketAddr> = None;
    let mut access_dir: Option<PathBuf> = None;
    let mut signing_key_path: Option<PathBuf> = None;
    let mut mock_models = vec!["tiny-cpu-test".to_owned()];

    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = |name: &str| {
            args.next()
                .ok_or_else(|| format!("missing value for {name}"))
        };
        match flag.as_str() {
            "--bind" => {
                bind = Some(
                    value("--bind")?
                        .parse()
                        .map_err(|err| format!("--bind: {err}"))?,
                )
            }
            "--engine-endpoint" => {
                engine_endpoint = Some(
                    value("--engine-endpoint")?
                        .parse()
                        .map_err(|err| format!("--engine-endpoint: {err}"))?,
                )
            }
            "--access-dir" => access_dir = Some(PathBuf::from(value("--access-dir")?)),
            "--session-signing-key" => {
                signing_key_path = Some(PathBuf::from(value("--session-signing-key")?))
            }
            "--mock-models" => {
                mock_models = value("--mock-models")?
                    .split(',')
                    .map(str::trim)
                    .filter(|m| !m.is_empty())
                    .map(ToOwned::to_owned)
                    .collect();
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }

    let bind = bind.ok_or("--bind is required")?;
    validate_tunnel_shaped_bind(bind.ip())?;
    let engine_endpoint = engine_endpoint.ok_or("--engine-endpoint is required")?;
    validate_engine_endpoint(engine_endpoint).map_err(|err| err.to_string())?;
    let access_dir = access_dir.ok_or("--access-dir is required")?;
    if let Some(path) = signing_key_path {
        validate_signing_key_material(&path)?;
    }
    if mock_models.is_empty() {
        return Err("--mock-models must name at least one model".into());
    }

    Ok(Config {
        bind,
        access_dir,
        mock_models,
    })
}

/// E1 (bin-side layer): refuse bind shapes that can never be the
/// tunnel address; the daemon + nftables scope are the
/// authoritative layers.
fn validate_tunnel_shaped_bind(ip: IpAddr) -> Result<(), String> {
    if ip.is_unspecified() {
        return Err(
            "refusing wildcard bind (0.0.0.0/::): the inference endpoint is tunnel-only".into(),
        );
    }
    if ip.is_loopback() {
        return Err("refusing loopback bind: mesh peers cannot reach loopback".into());
    }
    if ip.is_multicast() {
        return Err("refusing multicast bind".into());
    }
    Ok(())
}

/// The session-token signing key must be a regular, owner-only,
/// 32-byte file. Loaded lazily by the session layer; validated
/// fail-closed at startup so a broken deployment never serves.
fn validate_signing_key_material(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|err| {
        format!(
            "session signing key unavailable at {}: {err}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "session signing key at {} must be a regular file",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "session signing key mode {mode:o} grants group/world access; chmod 600 required"
            ));
        }
    }
    if metadata.len() != 32 {
        return Err(format!(
            "session signing key must be exactly 32 bytes (got {})",
            metadata.len()
        ));
    }
    Ok(())
}

/// Materialised access state: grants, the tunnel-source identity
/// map, and per-selector scopes.
type AccessState = (
    Vec<String>,
    BTreeMap<IpAddr, String>,
    BTreeMap<String, LlmAccessScope>,
);

/// Load the daemon-materialised access state. Fail-closed: a file
/// that exists but cannot be read, or a scope line carrying a
/// malformed limit value or an unrecognized key, is an error — never
/// silently degraded to "no restrictions". Only genuine absence
/// (`NotFound`) means "no entries", which keeps every state in the
/// deny direction: missing grants deny admission, and a missing
/// scopes file leaves grants unrestricted by documented design
/// (scopes restrict, they never grant).
fn load_access_state(access_dir: &Path) -> Result<AccessState, String> {
    fn read_optional(path: &Path) -> Result<Option<String>, String> {
        match std::fs::read_to_string(path) {
            Ok(body) => Ok(Some(body)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(format!("{} unreadable: {err}", path.display())),
        }
    }

    let grants_path = access_dir.join(ACCESS_GRANTS_FILE);
    let grants: Vec<String> = read_optional(&grants_path)?
        .map(|body| {
            body.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let mut peers = BTreeMap::new();
    if let Some(body) = read_optional(&access_dir.join(ACCESS_PEERS_FILE))? {
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((ip_raw, node_id)) = line.split_once(' ')
                && let Ok(ip) = ip_raw.parse::<IpAddr>()
            {
                peers.insert(ip, node_id.trim().to_owned());
            }
        }
    }
    let mut scopes = BTreeMap::new();
    let scopes_path = access_dir.join(ACCESS_SCOPES_FILE);
    if let Some(body) = read_optional(&scopes_path)? {
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(selector) = parts.next() else {
                continue;
            };
            let mut scope = LlmAccessScope::default();
            for part in parts {
                if let Some(models) = part.strip_prefix("models=") {
                    scope.allowed_models = Some(
                        models
                            .split(',')
                            .filter(|m| !m.is_empty())
                            .map(ToOwned::to_owned)
                            .collect(),
                    );
                } else if let Some(quota) = part.strip_prefix("quota=") {
                    // A malformed or overflowing quota must refuse the
                    // peer, not degrade to "no quota".
                    scope.max_tokens_per_window = Some(quota.parse().map_err(|_| {
                        format!(
                            "{}: selector {selector:?} has invalid quota value {quota:?}",
                            scopes_path.display()
                        )
                    })?);
                } else if let Some(rate) = part.strip_prefix("rate=") {
                    scope.max_requests_per_minute = Some(rate.parse().map_err(|_| {
                        format!(
                            "{}: selector {selector:?} has invalid rate value {rate:?}",
                            scopes_path.display()
                        )
                    })?);
                } else {
                    // An unrecognized key is a typo'd restriction
                    // (e.g. `qouta=`): honouring the rest of the line
                    // while dropping the intended limit would serve
                    // the peer unlimited.
                    return Err(format!(
                        "{}: selector {selector:?} has unrecognized scope key {part:?}",
                        scopes_path.display()
                    ));
                }
            }
            scopes.insert(selector.to_owned(), scope);
        }
    }
    Ok((grants, peers, scopes))
}

/// Per-frame admission: tunnel-source identity + current grant.
/// Deny-all when the daemon has not materialised any signed state,
/// or when that state exists but cannot be read/validated.
fn admitted_peer(
    access_dir: &Path,
    source: IpAddr,
) -> Result<(String, Option<LlmAccessScope>), String> {
    let (grants, peers, scopes) = load_access_state(access_dir).map_err(|err| {
        eprintln!("[rustynet-llm-gateway] {err}; refusing peer (fail-closed)");
        "gateway access state unusable; refused (default-deny)".to_owned()
    })?;
    let node_id = peers
        .get(&source)
        .ok_or_else(|| format!("tunnel source {source} has no signed identity; refused"))?;
    if !grants.iter().any(|grant| grant == node_id) {
        return Err(format!(
            "your admin hasn't enabled LLM access for this device (peer {node_id}; default-deny)"
        ));
    }
    let scope = scopes.get(node_id).cloned();
    Ok((node_id.clone(), scope))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn serve_connection(
    mut stream: TcpStream,
    engine: &(dyn InferenceEngine + Send + Sync),
    enforcement: &Mutex<EnforcementState>,
    access_dir: &Path,
) -> Result<(), String> {
    let source = stream
        .peer_addr()
        .map_err(|err| format!("peer addr unavailable: {err}"))?
        .ip();

    loop {
        let body = match read_frame(&mut stream) {
            Ok(Some(body)) => body,
            Ok(None) => return Ok(()),
            Err(err) => return Err(err),
        };

        // Identity + authorisation re-checked on EVERY frame.
        let (peer_node_id, scope) = match admitted_peer(access_dir, source) {
            Ok(admitted) => admitted,
            Err(reason) => {
                let _ = write_frame(
                    &mut stream,
                    &protocol::encode_event(&Event::Error { message: reason }),
                );
                return Ok(());
            }
        };

        let request = match protocol::decode_request(&body) {
            Ok(request) => request,
            Err(err) => {
                let _ = write_frame(
                    &mut stream,
                    &protocol::encode_event(&Event::Error {
                        message: format!("malformed request: {err}"),
                    }),
                );
                return Ok(());
            }
        };

        match request {
            Request::Hello { .. } => {
                let models = visible_models(engine, scope.as_ref())?;
                let used = enforcement
                    .lock()
                    .map_err(|_| "enforcement state poisoned".to_owned())?
                    .tokens_used_in_window(&peer_node_id);
                write_frame(
                    &mut stream,
                    &protocol::encode_event(&Event::HelloOk {
                        version: PROTOCOL_VERSION,
                        models,
                        tokens_used_in_window: used,
                    }),
                )?;
            }
            Request::ListModels => {
                let models = visible_models(engine, scope.as_ref())?;
                write_frame(
                    &mut stream,
                    &protocol::encode_event(&Event::Models { models }),
                )?;
            }
            Request::Complete { model, prompt } => {
                stream_completion(
                    &mut stream,
                    engine,
                    enforcement,
                    access_dir,
                    source,
                    &peer_node_id,
                    scope.as_ref(),
                    &model,
                    &prompt,
                )?;
            }
            Request::UploadContext { data } => {
                // Bounded by the protocol cap; held in memory for the
                // session only and dropped on connection end. Never
                // logged, never persisted.
                let _ = data;
                write_frame(
                    &mut stream,
                    &protocol::encode_event(&Event::ContextAccepted),
                )?;
            }
            Request::Usage => {
                let used = enforcement
                    .lock()
                    .map_err(|_| "enforcement state poisoned".to_owned())?
                    .tokens_used_in_window(&peer_node_id);
                write_frame(
                    &mut stream,
                    &protocol::encode_event(&Event::Usage {
                        tokens_used_in_window: used,
                    }),
                )?;
            }
        }
    }
}

fn visible_models(
    engine: &(dyn InferenceEngine + Send + Sync),
    scope: Option<&LlmAccessScope>,
) -> Result<Vec<String>, String> {
    let node_models = engine.list_models().map_err(|err| err.to_string())?;
    Ok(EnforcementState::visible_models(scope, &node_models)
        .into_iter()
        .cloned()
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn stream_completion(
    stream: &mut TcpStream,
    engine: &(dyn InferenceEngine + Send + Sync),
    enforcement: &Mutex<EnforcementState>,
    access_dir: &Path,
    source: IpAddr,
    peer_node_id: &str,
    scope: Option<&LlmAccessScope>,
    model: &str,
    prompt: &str,
) -> Result<(), String> {
    {
        let mut state = enforcement
            .lock()
            .map_err(|_| "enforcement state poisoned".to_owned())?;
        if let Err(err) = state.admit_request(peer_node_id, scope, model, now_unix()) {
            return write_frame(
                stream,
                &protocol::encode_event(&Event::Error {
                    message: err.to_string(),
                }),
            );
        }
    }

    let events = match engine.stream_completion(model, prompt) {
        Ok(events) => events,
        Err(err) => {
            return write_frame(
                stream,
                &protocol::encode_event(&Event::Error {
                    message: err.to_string(),
                }),
            );
        }
    };

    for event in events {
        // Mid-stream severance: a peer revoked while a generation is
        // in flight loses the stream at the next event boundary —
        // authorisation is re-checked between fragments (E2/E3/E4).
        if let Err(reason) = admitted_peer(access_dir, source) {
            return write_frame(
                stream,
                &protocol::encode_event(&Event::Error {
                    message: format!("stream severed: {reason}"),
                }),
            );
        }
        match event {
            Ok(CompletionEvent::Fragment { text, token_count }) => {
                {
                    let mut state = enforcement
                        .lock()
                        .map_err(|_| "enforcement state poisoned".to_owned())?;
                    if let Err(err) =
                        state.record_tokens(peer_node_id, scope, token_count, now_unix())
                    {
                        return write_frame(
                            stream,
                            &protocol::encode_event(&Event::Error {
                                message: format!("stream severed: {err}"),
                            }),
                        );
                    }
                }
                write_frame(stream, &protocol::encode_event(&Event::Token { text }))?;
            }
            Ok(CompletionEvent::Done) => {
                return write_frame(stream, &protocol::encode_event(&Event::Done));
            }
            Err(err) => {
                return write_frame(
                    stream,
                    &protocol::encode_event(&Event::Error {
                        message: err.to_string(),
                    }),
                );
            }
        }
    }
    write_frame(stream, &protocol::encode_event(&Event::Done))
}

fn read_frame(stream: &mut TcpStream) -> Result<Option<Vec<u8>>, String> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(format!("frame length read failed: {err}")),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(format!("frame of {len} bytes exceeds cap {MAX_FRAME_LEN}"));
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .map_err(|err| format!("frame body read failed: {err}"))?;
    Ok(Some(body))
}

/// Frames with bodies at or below this size are coalesced with their 4-byte
/// length prefix into a single `write_all`, so with `TCP_NODELAY` enabled the
/// prefix never departs as its own segment. Every streamed event fits under
/// this bound; larger bodies keep the header-then-body write pair, where
/// copying the payload to save one 4-byte segment would be a net loss.
const FRAME_COALESCE_MAX: usize = 8 * 1024;

fn write_frame(stream: &mut impl Write, body: &[u8]) -> Result<(), String> {
    let header = (body.len() as u32).to_be_bytes();
    if body.len() <= FRAME_COALESCE_MAX {
        let mut frame = Vec::with_capacity(header.len() + body.len());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(body);
        stream
            .write_all(&frame)
            .map_err(|err| format!("frame write failed: {err}"))
    } else {
        stream
            .write_all(&header)
            .and_then(|_| stream.write_all(body))
            .map_err(|err| format!("frame write failed: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ACCESS_GRANTS_FILE, ACCESS_PEERS_FILE, ACCESS_SCOPES_FILE, FRAME_COALESCE_MAX,
        admitted_peer, read_frame, write_frame,
    };
    use rustynet_policy::LlmAccessScope;
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
    use std::path::{Path, PathBuf};

    /// Fail-open regression harness: a granted peer whose scope state
    /// cannot be parsed must be refused, never silently widened to an
    /// unrestricted grant.
    const PEER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 88));
    const PEER_NODE: &str = "node:laptop-1";

    fn temp_access_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("llm-gw-scope-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp access dir");
        dir
    }

    fn write_access_file(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).expect("write access-state file");
    }

    /// Grant the test peer so scope handling (not admission) is what
    /// the assertions exercise.
    fn grant_test_peer(dir: &Path) {
        write_access_file(dir, ACCESS_GRANTS_FILE, &format!("{PEER_NODE}\n"));
        write_access_file(dir, ACCESS_PEERS_FILE, &format!("{PEER_IP} {PEER_NODE}\n"));
    }

    #[test]
    fn malformed_scope_limit_values_deny_peer_instead_of_unlimited() {
        let dir = temp_access_dir("malformed-limit");
        grant_test_peer(&dir);
        // A garbage token-quota, a garbage rate ceiling, and an empty
        // value must each refuse the peer: parse failure degrading to
        // "no limit" would silently widen a restricted grant to
        // unlimited.
        for line in [
            format!("{PEER_NODE} models=tiny quota=not-a-number"),
            format!("{PEER_NODE} models=tiny rate=-1"),
            format!("{PEER_NODE} models=tiny quota="),
        ] {
            write_access_file(&dir, ACCESS_SCOPES_FILE, &format!("{line}\n"));
            assert!(
                admitted_peer(&dir, PEER_IP).is_err(),
                "malformed scope line {line:?} must deny"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unrecognized_scope_key_denies_peer() {
        let dir = temp_access_dir("unknown-key");
        grant_test_peer(&dir);
        // A typo'd key (`qouta=` instead of `quota=`) must not be
        // silently dropped: the operator asked for a restriction and a
        // silent ignore would serve the peer unlimited.
        write_access_file(
            &dir,
            ACCESS_SCOPES_FILE,
            &format!("{PEER_NODE} models=tiny qouta=5\n"),
        );
        assert!(
            admitted_peer(&dir, PEER_IP).is_err(),
            "unrecognized scope key must deny rather than drop the restriction"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unreadable_scopes_state_denies_peer() {
        let dir = temp_access_dir("unreadable-scopes");
        grant_test_peer(&dir);
        // Any read failure other than absence (here: scopes.v1 is a
        // directory, so read_to_string fails regardless of user) must
        // deny: treating it as "no scopes configured" would strip
        // every restriction from every granted peer.
        std::fs::create_dir(dir.join(ACCESS_SCOPES_FILE)).expect("create blocking scopes entry");
        assert!(
            admitted_peer(&dir, PEER_IP).is_err(),
            "unreadable scope state must deny rather than degrade to unrestricted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn well_formed_scope_still_enforced() {
        let dir = temp_access_dir("well-formed");
        grant_test_peer(&dir);
        write_access_file(
            &dir,
            ACCESS_SCOPES_FILE,
            &format!("{PEER_NODE} models=tiny quota=100 rate=2\n"),
        );
        let (node_id, scope) = admitted_peer(&dir, PEER_IP).expect("valid scope admits");
        assert_eq!(node_id, PEER_NODE);
        let scope: LlmAccessScope = scope.expect("scope entry present");
        assert_eq!(
            scope.allowed_models.as_deref(),
            Some(["tiny".to_owned()].as_slice())
        );
        assert_eq!(scope.max_tokens_per_window, Some(100));
        assert_eq!(scope.max_requests_per_minute, Some(2));
        assert!(!scope.permits_model("other"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn absent_scopes_file_keeps_documented_unrestricted_grant() {
        let dir = temp_access_dir("absent-scopes");
        grant_test_peer(&dir);
        // Absence (NotFound) is the documented "admin set no scope"
        // state and stays admissible; only unreadable/invalid state
        // denies.
        let (node_id, scope) = admitted_peer(&dir, PEER_IP).expect("grant without scopes admits");
        assert_eq!(node_id, PEER_NODE);
        assert!(scope.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_grant_denies_even_without_scopes() {
        let dir = temp_access_dir("no-grant");
        // No grants.v1 at all.
        assert!(admitted_peer(&dir, PEER_IP).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Records every `write` call so tests can assert both the exact wire
    /// bytes and how many writes produced them.
    #[derive(Default)]
    struct CountingSink {
        writes: usize,
        bytes: Vec<u8>,
    }

    impl Write for CountingSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_frame_bytes_identical_across_coalesce_boundary() {
        for len in [0, 1, FRAME_COALESCE_MAX, FRAME_COALESCE_MAX + 1] {
            let body = vec![0xA5u8; len];
            let mut sink = CountingSink::default();
            write_frame(&mut sink, &body).expect("write_frame");
            let mut expected = (len as u32).to_be_bytes().to_vec();
            expected.extend_from_slice(&body);
            assert_eq!(
                sink.bytes, expected,
                "wire bytes must not depend on the coalescing path (len {len})"
            );
            if len <= FRAME_COALESCE_MAX {
                assert_eq!(
                    sink.writes, 1,
                    "coalesced path must issue exactly one write (len {len})"
                );
            } else {
                assert_eq!(
                    sink.writes, 2,
                    "large-frame path keeps the header-then-body pair (len {len})"
                );
            }
        }
    }

    #[test]
    fn write_frame_round_trips_through_read_frame_across_boundary() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let mut client = TcpStream::connect(addr).expect("connect");
        let (mut server, _) = listener.accept().expect("accept");
        for len in [0, FRAME_COALESCE_MAX, FRAME_COALESCE_MAX + 1] {
            let body: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            write_frame(&mut client, &body).expect("write_frame");
            let read = read_frame(&mut server)
                .expect("read_frame")
                .expect("frame present");
            assert_eq!(
                read, body,
                "round-trip must be lossless across the coalesce boundary (len {len})"
            );
        }
    }
}
