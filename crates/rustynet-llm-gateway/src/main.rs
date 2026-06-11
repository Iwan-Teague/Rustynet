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

fn load_access_state(
    access_dir: &Path,
) -> (
    Vec<String>,
    BTreeMap<IpAddr, String>,
    BTreeMap<String, LlmAccessScope>,
) {
    let grants = std::fs::read_to_string(access_dir.join(ACCESS_GRANTS_FILE))
        .map(|body| {
            body.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let mut peers = BTreeMap::new();
    if let Ok(body) = std::fs::read_to_string(access_dir.join(ACCESS_PEERS_FILE)) {
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
    if let Ok(body) = std::fs::read_to_string(access_dir.join(ACCESS_SCOPES_FILE)) {
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
                    scope.max_tokens_per_window = quota.parse().ok();
                } else if let Some(rate) = part.strip_prefix("rate=") {
                    scope.max_requests_per_minute = rate.parse().ok();
                }
            }
            scopes.insert(selector.to_owned(), scope);
        }
    }
    (grants, peers, scopes)
}

/// Per-frame admission: tunnel-source identity + current grant.
/// Deny-all when the daemon has not materialised any signed state.
fn admitted_peer(
    access_dir: &Path,
    source: IpAddr,
) -> Result<(String, Option<LlmAccessScope>), String> {
    let (grants, peers, scopes) = load_access_state(access_dir);
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

fn write_frame(stream: &mut TcpStream, body: &[u8]) -> Result<(), String> {
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .and_then(|_| stream.write_all(body))
        .map_err(|err| format!("frame write failed: {err}"))
}
