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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustynet_llm_gateway::enforce::EnforcementState;
use rustynet_llm_gateway::engine::{
    CompletionEvent, InferenceEngine, MockEngine, validate_engine_endpoint,
};
use rustynet_llm_gateway::protocol::{self, Event, MAX_FRAME_LEN, PROTOCOL_VERSION, Request};
use rustynet_policy::LlmAccessScope;

const ACCESS_GRANTS_FILE: &str = "grants.v1";
const ACCESS_PEERS_FILE: &str = "peers.v1";
const ACCESS_SCOPES_FILE: &str = "scopes.v1";

/// RSA-0048 (slowloris / thread-holding DoS): per-connection I/O deadlines.
/// Each accepted connection is served on its own thread; without a read
/// deadline a peer that connects and sends nothing (or dribbles one byte at a
/// time within a single `read` call's horizon) holds that thread and socket
/// indefinitely. 30s per individual `read`/`write` call is far above any
/// legitimate inter-frame gap for an enrolled mesh peer, but a per-call
/// horizon alone cannot bound a trickling peer: one byte per call window
/// keeps every individual `read` inside it forever, so the whole-connection
/// lifetime below (`CONNECTION_MAX_LIFETIME`) is what bounds total
/// exposure, and the connection cap bounds how many connections can consume
/// that budget at once. All of these are applied at the connection boundary
/// (`serve_connection`), before any protocol or access-state work, and are
/// unrelated to authentication: identity still comes only from the tunnel
/// source address, per frame.
const CONNECTION_READ_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECTION_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Whole-connection wall-clock budget (RSA-0048, review fix). Per-call
/// timeouts cannot bound a peer that trickles bytes — one byte per call
/// window keeps every individual `read` inside its horizon forever — so a
/// connection is dropped outright once this lifetime elapses. The bound is
/// enforced inside the frame read path ([`DeadlineReader`]), so it fires
/// even mid-frame. 15 minutes is far above any legitimate multi-request
/// streaming session for an enrolled peer; a held connection costs at most
/// this budget, and the 64-connection cap bounds how many such budgets can
/// be consumed at once.
const CONNECTION_MAX_LIFETIME: Duration = Duration::from_secs(900);

/// RSA-0048: cap on concurrently served connections (one thread each). Above
/// the cap a new connection is refused — not queued — so total serving
/// threads, memory and sockets stay bounded even under an authenticated
/// peer's connection flood: the refusal is the fail-closed direction.
/// 64 comfortably exceeds any expected concurrent mesh-peer count for the
/// `llm` preset's single-node inference endpoint.
const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// Per-connection I/O deadlines (RSA-0048). `production()` is the deployed
/// triple; tests inject shorter deadlines so the drop behaviour is
/// observable in CI without waiting on production-scale timeouts.
#[derive(Clone, Copy)]
struct ConnectionTimeouts {
    read: Duration,
    write: Duration,
    lifetime: Duration,
}

impl ConnectionTimeouts {
    fn production() -> Self {
        Self {
            read: CONNECTION_READ_TIMEOUT,
            write: CONNECTION_WRITE_TIMEOUT,
            lifetime: CONNECTION_MAX_LIFETIME,
        }
    }
}

/// Count of connections currently being served (RSA-0048). `try_acquire`
/// takes a slot; `release` returns it when the serving thread finishes. The
/// compare-and-swap loop means the count can never exceed
/// [`MAX_CONCURRENT_CONNECTIONS`], even under concurrent accept races.
struct ConnectionGate {
    active: AtomicUsize,
}

impl ConnectionGate {
    fn new() -> Self {
        Self {
            active: AtomicUsize::new(0),
        }
    }

    /// Take a serving slot. `false` means the gate is at capacity: the caller
    /// must refuse the connection (fail closed), never queue it.
    fn try_acquire(&self) -> bool {
        let mut current = self.active.load(Ordering::SeqCst);
        loop {
            if current >= MAX_CONCURRENT_CONNECTIONS {
                return false;
            }
            match self.active.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    fn release(&self) {
        let before = self.active.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(before >= 1, "connection gate released below zero");
    }

    #[cfg(test)]
    fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
}

/// A gate slot owned by the serving thread and released on `Drop`
/// (RSA-0048, review fix), so every exit path returns it: normal end,
/// error return, and a panic unwinding through the thread. A plain
/// `release()` call after `serve_connection` would leak the slot on panic,
/// and 64 panics would brick the gateway into refusing every peer
/// forever. The slot is created only after a successful `try_acquire`, so
/// release-without-acquire (counter underflow) is structurally impossible.
struct ServingSlot {
    gate: Arc<ConnectionGate>,
}

impl ServingSlot {
    /// Take a serving slot, or `None` if the gate is at capacity (the
    /// caller must refuse the connection — fail closed, never queue).
    fn acquire(gate: &Arc<ConnectionGate>) -> Option<Self> {
        gate.try_acquire().then(|| Self {
            gate: Arc::clone(gate),
        })
    }
}

impl Drop for ServingSlot {
    fn drop(&mut self) {
        self.gate.release();
    }
}

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

    let gate = Arc::new(ConnectionGate::new());
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                handle_accepted_connection(stream, &engine, &enforcement, &access_dir, &gate);
            }
            Err(err) => eprintln!("[rustynet-llm-gateway] accept failed: {err}"),
        }
    }
    Ok(())
}

/// Per-connection admission (RSA-0048): disable Nagle, take a slot from the
/// connection gate, and hand the stream to its own thread under the
/// production I/O deadlines. At capacity the connection is refused (fail
/// closed) with a protocol-level Error event and closed — never queued.
/// Authentication and identity resolution are unchanged: they happen
/// per-frame inside `serve_connection`, from the tunnel source address only.
fn handle_accepted_connection(
    stream: TcpStream,
    engine: &Arc<dyn InferenceEngine + Send + Sync>,
    enforcement: &Arc<Mutex<EnforcementState>>,
    access_dir: &Arc<PathBuf>,
    gate: &Arc<ConnectionGate>,
) {
    // Disable Nagle: the streaming path emits one small frame per
    // token event and must not stall on delayed ACKs. A failed
    // setsockopt is logged but must not kill the session.
    if let Err(err) = stream.set_nodelay(true) {
        eprintln!("[rustynet-llm-gateway] set_nodelay failed (continuing): {err}");
    }
    let Some(slot) = ServingSlot::acquire(gate) else {
        eprintln!(
            "[rustynet-llm-gateway] connection cap {MAX_CONCURRENT_CONNECTIONS} reached; \
             refusing connection (fail closed)"
        );
        refuse_connection_at_cap(stream);
        return;
    };
    let engine = Arc::clone(engine);
    let enforcement = Arc::clone(enforcement);
    let access_dir = Arc::clone(access_dir);
    // `Builder::spawn` (unlike `std::thread::spawn`) reports thread-
    // creation failure instead of panicking: on failure the connection is
    // dropped and the slot returns via `ServingSlot::drop`, so neither the
    // accept loop nor the cap is corrupted by a failed spawn.
    let spawn_result = std::thread::Builder::new()
        .name("llm-gw-conn".to_owned())
        .spawn(move || {
            let _slot = slot;
            let result = serve_connection(stream, engine.as_ref(), &enforcement, &access_dir);
            if let Err(err) = result {
                eprintln!("[rustynet-llm-gateway] session ended: {err}");
            }
        });
    if let Err(err) = spawn_result {
        eprintln!(
            "[rustynet-llm-gateway] serve thread spawn failed; connection dropped (fail closed): {err}"
        );
    }
}

/// RSA-0048 refusal path: one bounded write of a protocol Error event (so an
/// authenticated peer can tell a cap refusal from a network fault), then the
/// stream is dropped. The write is bounded by the production write timeout,
/// so a refusing-but-unread peer cannot stall the accept loop either.
fn refuse_connection_at_cap(mut stream: TcpStream) {
    let _ = stream.set_write_timeout(Some(CONNECTION_WRITE_TIMEOUT));
    let _ = write_frame(
        &mut stream,
        &protocol::encode_event(&Event::Error {
            message: format!(
                "gateway connection cap {MAX_CONCURRENT_CONNECTIONS} reached; \
                 connection refused, retry later"
            ),
        }),
    );
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
/// deny direction: missing grants deny admission, and a granted
/// peer without a scope line is refused (deny-on-absent — absence
/// never means unrestricted). The only full-access value is an
/// explicit `unrestricted` key on the peer's scope line; combining
/// it with any limit key is a contradiction that refuses the peer.
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
                } else if part == "unrestricted" {
                    // The explicit full-access marker: the only way
                    // to grant "any model, no quota, no rate ceiling"
                    // under deny-on-absent semantics.
                    scope.unrestricted = true;
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
            if scope.unrestricted
                && (scope.allowed_models.is_some()
                    || scope.max_tokens_per_window.is_some()
                    || scope.max_requests_per_minute.is_some())
            {
                // `unrestricted` combined with any limit key is a
                // contradiction: honouring one half would silently
                // discard the admin's other intent. Refuse the peer.
                return Err(format!(
                    "{}: selector {selector:?} combines `unrestricted` with limit keys; refused",
                    scopes_path.display()
                ));
            }
            scopes.insert(selector.to_owned(), scope);
        }
    }
    Ok((grants, peers, scopes))
}

/// Per-frame admission: tunnel-source identity + current grant.
/// Deny-all when the daemon has not materialised any signed state,
/// or when that state exists but cannot be read/validated.
fn admitted_peer(access_dir: &Path, source: IpAddr) -> Result<(String, LlmAccessScope), String> {
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
    // Deny-on-absent: a granted peer without a scope line is
    // refused — absence never means unrestricted. The scope entry
    // (explicit limits, or the explicit `unrestricted` marker) is
    // what says what the grant may consume.
    let scope = scopes.get(node_id).cloned().ok_or_else(|| {
        format!(
            "your admin hasn't scoped LLM access for this device (peer {node_id}; default-deny: no scope line)"
        )
    })?;
    Ok((node_id.clone(), scope))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn serve_connection(
    stream: TcpStream,
    engine: &(dyn InferenceEngine + Send + Sync),
    enforcement: &Mutex<EnforcementState>,
    access_dir: &Path,
) -> Result<(), String> {
    serve_connection_with_timeouts(
        stream,
        engine,
        enforcement,
        access_dir,
        ConnectionTimeouts::production(),
    )
}

/// RSA-0048: the I/O deadlines are applied at the very top of the connection,
/// before any protocol or access-state work, and a failure to arm them drops
/// the connection (fail closed) rather than serving it unbounded. The frame
/// read path additionally runs under the whole-connection lifetime
/// (`DeadlineReader`), so a peer that trickles bytes — keeping every
/// individual `read` inside its per-call horizon — is still dropped when
/// the connection's wall-clock budget is spent.
fn serve_connection_with_timeouts(
    mut stream: TcpStream,
    engine: &(dyn InferenceEngine + Send + Sync),
    enforcement: &Mutex<EnforcementState>,
    access_dir: &Path,
    timeouts: ConnectionTimeouts,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(timeouts.read))
        .map_err(|err| format!("connection read timeout unavailable: {err}"))?;
    stream
        .set_write_timeout(Some(timeouts.write))
        .map_err(|err| format!("connection write timeout unavailable: {err}"))?;

    let source = stream
        .peer_addr()
        .map_err(|err| format!("peer addr unavailable: {err}"))?
        .ip();

    let frame_deadline = Instant::now() + timeouts.lifetime;
    loop {
        let mut reader = DeadlineReader {
            stream: &mut stream,
            deadline: frame_deadline,
            per_call: timeouts.read,
        };
        let body = match read_frame(&mut reader) {
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
                let models = visible_models(engine, Some(&scope))?;
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
                let models = visible_models(engine, Some(&scope))?;
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
                    Some(&scope),
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
        let (_, fresh_scope) = match admitted_peer(access_dir, source) {
            Ok(fresh) => fresh,
            Err(reason) => {
                return write_frame(
                    stream,
                    &protocol::encode_event(&Event::Error {
                        message: format!("stream severed: {reason}"),
                    }),
                );
            }
        };
        // Scope currency (T7): the freshly read scope is adopted for
        // the narrowing check, not discarded. A scope that narrowed
        // or disappeared mid-stream severs the generation at this
        // event boundary, mirroring grant severance above. An
        // equal-or-wider fresh scope does NOT retroactively widen
        // the in-flight request: token accounting below keeps the
        // frame-admission scope.
        let scope_narrowed = match scope {
            // A frame admitted without a scope is invalid under
            // deny-on-absent; sever rather than continue.
            None => true,
            Some(admitted) => !fresh_scope.is_at_least_as_permissive_as(admitted),
        };
        if scope_narrowed {
            return write_frame(
                stream,
                &protocol::encode_event(&Event::Error {
                    message:
                        "stream severed: peer scope narrowed or removed mid-stream; re-issue the request"
                            .to_owned(),
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

/// Per-`read` deadline enforcement (RSA-0048, review fix). A per-call
/// timeout alone cannot bound a trickling peer: one byte per call window
/// keeps every individual `read` inside its call horizon forever. Each
/// `read` is therefore bounded by the smaller of the per-call timeout and
/// the lifetime remaining, and an expired lifetime is surfaced as
/// `ErrorKind::TimedOut` — never `UnexpectedEof`, which `read_frame` would
/// otherwise mistake for a clean client close.
struct DeadlineReader<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
    per_call: Duration,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "connection lifetime exceeded")
            })?;
        self.stream
            .set_read_timeout(Some(remaining.min(self.per_call)))
            .map_err(std::io::Error::other)?;
        self.stream.read(buf)
    }
}

fn read_frame(stream: &mut impl Read) -> Result<Option<Vec<u8>>, String> {
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
        ACCESS_GRANTS_FILE, ACCESS_PEERS_FILE, ACCESS_SCOPES_FILE, ConnectionGate,
        ConnectionTimeouts, Event, FRAME_COALESCE_MAX, MAX_CONCURRENT_CONNECTIONS, MockEngine,
        Request, admitted_peer, handle_accepted_connection, read_frame, serve_connection,
        serve_connection_with_timeouts, stream_completion, write_frame,
    };
    use rustynet_llm_gateway::enforce::EnforcementState;
    use rustynet_llm_gateway::engine::{CompletionEvent, EngineError, InferenceEngine};
    use rustynet_policy::LlmAccessScope;
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::protocol;

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
    fn grant_present_scope_absent_refused_end_to_end() {
        let dir = temp_access_dir("grant-no-scope");
        grant_test_peer(&dir);
        // Deny-on-absent, end to end through the frame-admission
        // seam: a grant line with no matching scope line refuses the
        // peer — absence (no scopes file, no line for the node id)
        // never means unrestricted.
        let err = admitted_peer(&dir, PEER_IP).expect_err("grant without scope line must deny");
        assert!(err.contains(PEER_NODE), "refusal must name the peer: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bare_selector_line_denies() {
        let dir = temp_access_dir("bare-selector");
        grant_test_peer(&dir);
        // A scope line with selector but no keys parses to
        // `LlmAccessScope::default()` — the deny posture. Under the
        // old semantics this silently meant unrestricted.
        write_access_file(
            &dir,
            ACCESS_SCOPES_FILE,
            &format!(
                "{PEER_NODE}
"
            ),
        );
        let (_, scope) = admitted_peer(&dir, PEER_IP).expect("bare line loads as a deny scope");
        assert!(!scope.unrestricted);
        assert!(
            !scope.permits_model("any-model"),
            "a bare selector line grants no model"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unrestricted_with_any_limit_key_is_a_loader_error() {
        let dir = temp_access_dir("unrestricted-contradiction");
        grant_test_peer(&dir);
        // `unrestricted` combined with any limit key is a
        // contradiction; the loader must hard-error (peer refused,
        // fail closed), not honour one half of the line.
        for line in [
            format!("{PEER_NODE} unrestricted models=tiny"),
            format!("{PEER_NODE} unrestricted quota=100"),
            format!("{PEER_NODE} unrestricted rate=5"),
            format!("{PEER_NODE} models=tiny unrestricted"),
            format!("{PEER_NODE} unrestricted quota=100 rate=5"),
        ] {
            write_access_file(
                &dir,
                ACCESS_SCOPES_FILE,
                &format!(
                    "{line}
"
                ),
            );
            assert!(
                admitted_peer(&dir, PEER_IP).is_err(),
                "unrestricted + limits must refuse the peer: {line:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn explicit_unrestricted_scope_line_admits_any_model() {
        let dir = temp_access_dir("unrestricted-line");
        grant_test_peer(&dir);
        // The marker alone is valid and is the only full-access
        // grant.
        write_access_file(
            &dir,
            ACCESS_SCOPES_FILE,
            &format!(
                "{PEER_NODE} unrestricted
"
            ),
        );
        let (_, scope) = admitted_peer(&dir, PEER_IP).expect("explicit unrestricted line admits");
        assert!(scope.unrestricted);
        assert!(scope.permits_model("any-model"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A granted peer with no scope line is refused at the
    /// connection layer too: `serve_connection` turns the
    /// `admitted_peer` refusal into a wire `Error` event before any
    /// model is named. This is the network-level half of
    /// `grant_present_scope_absent_refused_end_to_end` (there was no
    /// serve_connection harness before; this adds a real loopback
    /// socket pair rather than a seam).
    #[test]
    fn stalled_client_is_dropped_not_held_forever() {
        // RSA-0048: a connected client that sends no bytes must be dropped
        // once the per-connection read deadline elapses, not held (thread +
        // socket) indefinitely.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener addr");
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            let engine = MockEngine::serving(vec!["tiny".to_owned()]);
            let enforcement = Mutex::new(EnforcementState::new());
            let result = serve_connection_with_timeouts(
                stream,
                &engine,
                &enforcement,
                Path::new("/nonexistent"),
                ConnectionTimeouts {
                    read: Duration::from_millis(200),
                    write: Duration::from_millis(200),
                    lifetime: Duration::from_secs(5),
                },
            );
            tx.send(result).expect("report serve result");
        });
        let _client = TcpStream::connect(addr).expect("connect to gateway");
        let started = std::time::Instant::now();
        let result = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("serve must end after the read deadline, not hold the client");
        let elapsed = started.elapsed();
        assert!(
            result.is_err(),
            "a stalled client must be dropped as an error, not served: {result:?}"
        );
        assert!(
            elapsed < Duration::from_secs(4),
            "drop must happen near the 200ms deadline, took {elapsed:?}"
        );
        handle.join().expect("serve thread finishes");
    }

    #[test]
    fn connection_gate_holds_the_cap_and_restores_released_slots() {
        // RSA-0048: the gate must refuse once full (fail closed, never queue)
        // and must return capacity when a served connection is released.
        let gate = ConnectionGate::new();
        for _ in 0..MAX_CONCURRENT_CONNECTIONS {
            assert!(gate.try_acquire(), "slots below the cap must be admitted");
        }
        assert_eq!(gate.active(), MAX_CONCURRENT_CONNECTIONS);
        assert!(
            !gate.try_acquire(),
            "a full gate must refuse additional connections"
        );
        gate.release();
        assert_eq!(gate.active(), MAX_CONCURRENT_CONNECTIONS - 1);
        assert!(
            gate.try_acquire(),
            "a released slot must be admissible again"
        );
        assert!(!gate.try_acquire(), "the cap must hold after restoration");
    }

    #[test]
    fn connection_cap_refuses_above_capacity_end_to_end() {
        // RSA-0048 end to end: a connection arriving while the gate is full
        // gets the protocol-level Error event and is closed; it never takes a
        // serving slot and never reaches authentication work.
        let gate = Arc::new(ConnectionGate::new());
        for _ in 0..MAX_CONCURRENT_CONNECTIONS {
            assert!(gate.try_acquire());
        }
        let engine: Arc<dyn InferenceEngine + Send + Sync> =
            Arc::new(MockEngine::serving(vec!["tiny".to_owned()]));
        let enforcement = Arc::new(Mutex::new(EnforcementState::new()));
        let access_dir = Arc::new(PathBuf::from("/nonexistent"));

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener addr");
        let accept_gate = Arc::clone(&gate);
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            handle_accepted_connection(stream, &engine, &enforcement, &access_dir, &accept_gate);
        });
        let mut client = TcpStream::connect(addr).expect("connect to gateway");
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("client read timeout");
        handle.join().expect("accept thread finishes");

        let body = read_frame(&mut client)
            .expect("refused connection must still deliver one frame")
            .expect("refusal frame before close");
        match protocol::decode_event(&body).expect("decode refusal event") {
            Event::Error { message } => assert!(
                message.contains("connection cap"),
                "refusal must name the connection cap, got: {message}"
            ),
            other => panic!("expected Error event, got {other:?}"),
        }
        assert_eq!(
            read_frame(&mut client).expect("read after refusal"),
            None,
            "a refused connection must be closed"
        );
        assert_eq!(
            gate.active(),
            MAX_CONCURRENT_CONNECTIONS,
            "a refused connection must not consume a serving slot"
        );
    }

    #[test]
    fn serve_connection_refuses_granted_peer_without_scope_line() {
        let dir = temp_access_dir("serve-no-scope");
        grant_test_peer(&dir);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener addr");
        let access_dir = dir.clone();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            let engine = MockEngine::serving(vec!["tiny".to_owned()]);
            let enforcement = Mutex::new(EnforcementState::new());
            let _ = serve_connection(stream, &engine, &enforcement, &access_dir);
        });
        // Map the loopback source the client actually connects from
        // (127.0.0.1) to the peer node id, so identity resolution in
        // peers.v1 matches.
        write_access_file(&dir, ACCESS_PEERS_FILE, &format!("127.0.0.1 {PEER_NODE}\n"));
        let mut client = TcpStream::connect(addr).expect("connect to gateway");
        write_frame(
            &mut client,
            &protocol::encode_request(&Request::Complete {
                model: "tiny".to_owned(),
                prompt: "hello".to_owned(),
            }),
        )
        .expect("send request frame");
        let body = read_frame(&mut client)
            .expect("read reply")
            .expect("reply frame before close");
        match protocol::decode_event(&body).expect("decode reply event") {
            Event::Error { message } => {
                assert!(
                    message.contains("default-deny") && message.contains(PEER_NODE),
                    "refusal must be the scope-missing default-deny message: {message}"
                );
            }
            other => panic!("expected Error event, got {other:?}"),
        }
        handle.join().expect("serve thread finishes");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Engine stub whose stream narrows the peer's scope on disk
    /// between the first and second fragment, driving the T7
    /// mid-stream scope-currency check.
    struct ScopeNarrowingEngine {
        models: Vec<String>,
        access_dir: PathBuf,
    }

    impl InferenceEngine for ScopeNarrowingEngine {
        fn list_models(&self) -> Result<Vec<String>, EngineError> {
            Ok(self.models.clone())
        }

        fn probe_health(&self) -> Result<(), EngineError> {
            Ok(())
        }

        fn stream_completion(
            &self,
            _model: &str,
            _prompt: &str,
        ) -> Result<
            Box<dyn Iterator<Item = Result<CompletionEvent, EngineError>> + Send>,
            EngineError,
        > {
            let access_dir = self.access_dir.clone();
            Ok(Box::new(std::iter::from_fn(move || {
                // Consumed lazily by stream_completion's event loop:
                // the narrowing write lands when the SECOND fragment
                // is produced, i.e. before the re-check that precedes
                // that event's processing.
                static NARROWED: std::sync::atomic::AtomicUsize =
                    std::sync::atomic::AtomicUsize::new(0);
                let poll = NARROWED.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                if poll == 2 {
                    std::fs::write(
                        access_dir.join(ACCESS_SCOPES_FILE),
                        format!("{PEER_NODE} models=other\n"),
                    )
                    .expect("narrow the peer's scope mid-stream");
                }
                match poll {
                    1 | 2 => Some(Ok(CompletionEvent::Fragment {
                        text: format!("fragment-{poll} "),
                        token_count: 1,
                    })),
                    _ => None,
                }
            })))
        }
    }

    #[test]
    fn midstream_scope_narrowing_severs_stream() {
        let dir = temp_access_dir("midstream-narrow");
        grant_test_peer(&dir);
        write_access_file(
            &dir,
            ACCESS_SCOPES_FILE,
            &format!(
                "{PEER_NODE} models=tiny quota=100
"
            ),
        );

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener addr");
        let access_dir = dir.clone();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            let engine = ScopeNarrowingEngine {
                models: vec!["tiny".to_owned()],
                access_dir: access_dir.clone(),
            };
            let enforcement = Mutex::new(EnforcementState::new());
            let _ = stream_completion(
                &mut stream,
                &engine,
                &enforcement,
                &access_dir,
                PEER_IP,
                PEER_NODE,
                Some(&LlmAccessScope {
                    allowed_models: Some(vec!["tiny".to_owned()]),
                    max_tokens_per_window: Some(100),
                    max_requests_per_minute: None,
                    unrestricted: false,
                }),
                "tiny",
                "hello world",
            );
        });

        let mut client = TcpStream::connect(addr).expect("connect to gateway");
        write_frame(
            &mut client,
            &protocol::encode_request(&Request::Complete {
                model: "tiny".to_owned(),
                prompt: "hello world".to_owned(),
            }),
        )
        .expect("send request frame");

        // First fragment streams normally, then the narrowing lands
        // and the second event boundary severs the stream.
        let mut saw_token = false;
        let mut severed = false;
        while let Ok(Some(body)) = read_frame(&mut client) {
            match protocol::decode_event(&body).expect("decode event") {
                Event::Token { .. } => saw_token = true,
                Event::Error { message } => {
                    assert!(
                        message.contains("narrowed or removed"),
                        "severance must name the scope narrowing: {message}"
                    );
                    severed = true;
                    break;
                }
                Event::Done => panic!("stream must not complete after a mid-stream narrowing"),
                other => panic!("unexpected event mid-stream: {other:?}"),
            }
        }
        assert!(
            saw_token,
            "the first fragment must stream before the narrowing"
        );
        assert!(severed, "the narrowing must sever the stream");
        handle.join().expect("stream thread finishes");
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
/// RSA-0048 review witnesses (lane rsa0048-review): the behaviours the
/// per-call timeouts and the cap alone do NOT provide — a whole-connection
/// lifetime that bounds a trickling peer, and gate-slot release on every
/// serving-thread exit path including a panic.
#[cfg(test)]
mod rsa0048_review_witnesses {
    use super::{
        ConnectionGate, ConnectionTimeouts, MAX_CONCURRENT_CONNECTIONS, MockEngine, Request,
        ServingSlot, handle_accepted_connection, serve_connection_with_timeouts, write_frame,
    };
    use rustynet_llm_gateway::enforce::EnforcementState;
    use rustynet_llm_gateway::engine::{CompletionEvent, EngineError, InferenceEngine};
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// A client trickling one body byte every 100ms inside a
    /// never-completing frame keeps every individual `read` inside its
    /// per-call window, so no per-call timeout ever fires. The whole-
    /// connection lifetime must still drop it (and with it the gate slot
    /// and the socket).
    #[test]
    fn trickling_client_is_dropped_by_the_connection_lifetime() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener addr");
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            let engine = MockEngine::serving(vec!["tiny".to_owned()]);
            let enforcement = Mutex::new(EnforcementState::new());
            let result = serve_connection_with_timeouts(
                stream,
                &engine,
                &enforcement,
                Path::new("/nonexistent"),
                ConnectionTimeouts {
                    read: Duration::from_millis(200),
                    write: Duration::from_millis(200),
                    lifetime: Duration::from_millis(700),
                },
            );
            let _ = tx.send(result);
        });
        let trickler = std::thread::spawn(move || {
            let mut client = TcpStream::connect(addr).expect("connect to gateway");
            client
                .set_write_timeout(Some(Duration::from_secs(2)))
                .expect("client write timeout");
            // Frame header declaring a 1,000,000-byte body (<=
            // MAX_FRAME_LEN), then one body byte every 100ms for 60s:
            // always inside the per-call read window, never completing
            // the frame.
            let _ = client.write_all(&1_000_000u32.to_be_bytes());
            for _ in 0..600 {
                if client.write_all(b"A").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let started = std::time::Instant::now();
        let outcome = rx.recv_timeout(Duration::from_secs(5));
        assert!(
            matches!(outcome, Ok(Err(_))),
            "a trickling client must be dropped by the connection lifetime; \
             serve still held the connection after {:?} (outcome {outcome:?})",
            started.elapsed()
        );
        handle.join().expect("serve thread finishes");
        let _ = trickler.join();
    }

    /// A panic in the serve thread (here: the engine explodes mid-stream)
    /// must return the connection-gate slot during unwind. If release only
    /// happens on the non-panic path, the slot leaks and 64 panics
    /// permanently brick the gateway into refusing every peer.
    #[test]
    fn panicking_serve_thread_releases_its_gate_slot() {
        struct PanickingEngine;
        impl InferenceEngine for PanickingEngine {
            fn list_models(&self) -> Result<Vec<String>, EngineError> {
                Ok(vec!["tiny".to_owned()])
            }
            fn stream_completion(
                &self,
                _model: &str,
                _prompt: &str,
            ) -> Result<
                Box<dyn Iterator<Item = Result<CompletionEvent, EngineError>> + Send>,
                EngineError,
            > {
                panic!("engine explodes mid-stream");
            }
            fn probe_health(&self) -> Result<(), EngineError> {
                Ok(())
            }
        }

        let dir = std::env::temp_dir().join(format!(
            "llm-gw-rsa0048-witness-{}-panic",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp access dir");
        std::fs::write(dir.join("grants.v1"), "node:witness\n").expect("grants");
        std::fs::write(dir.join("peers.v1"), "127.0.0.1 node:witness\n").expect("peers");
        std::fs::write(
            dir.join("scopes.v1"),
            "node:witness models=tiny quota=100\n",
        )
        .expect("scopes");

        let gate = Arc::new(ConnectionGate::new());
        for _ in 0..MAX_CONCURRENT_CONNECTIONS - 1 {
            assert!(gate.try_acquire(), "prefill below the cap must succeed");
        }
        let engine: Arc<dyn InferenceEngine + Send + Sync> = Arc::new(PanickingEngine);
        let enforcement = Arc::new(Mutex::new(EnforcementState::new()));
        let access_dir = Arc::new(dir.clone());

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener addr");
        let accept_gate = Arc::clone(&gate);
        let acceptor = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            handle_accepted_connection(stream, &engine, &enforcement, &access_dir, &accept_gate);
        });
        let mut client = TcpStream::connect(addr).expect("connect to gateway");
        write_frame(
            &mut client,
            &super::protocol::encode_request(&Request::Complete {
                model: "tiny".to_owned(),
                prompt: "hello".to_owned(),
            }),
        )
        .expect("send request frame");
        acceptor.join().expect("accept thread finishes");

        // The slot must come back once the panicking serve thread unwinds.
        let mut released = false;
        for _ in 0..50 {
            if gate.active() == MAX_CONCURRENT_CONNECTIONS - 1 {
                released = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            released,
            "a panicking serve thread must release its gate slot; gate stuck at {}/{}",
            gate.active(),
            MAX_CONCURRENT_CONNECTIONS
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The slot guard is the only thing that can release a slot, and it is
    /// created only after a successful acquire: dropping it (any exit path,
    /// including unwind) returns exactly one slot.
    #[test]
    fn serving_slot_acquires_and_drops_exactly_one_slot() {
        let gate = Arc::new(ConnectionGate::new());
        {
            let _slot = ServingSlot::acquire(&gate).expect("gate below cap must admit");
            assert_eq!(gate.active(), 1, "acquire must take exactly one slot");
        }
        assert_eq!(gate.active(), 0, "drop must return the slot");
        assert!(
            ServingSlot::acquire(&gate).is_some(),
            "the returned slot must be admissible again"
        );
    }
}
