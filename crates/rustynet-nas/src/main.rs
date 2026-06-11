//! `rustynet-nas` daemon binary — the tunnel-only, default-deny
//! storage endpoint for the `nas` preset (NAS design §3/§4).
//!
//! Startup is fail-closed end to end: a non-tunnel-shaped bind, a
//! missing/short/world-readable at-rest key, or an insecure data
//! root each refuse to start. At runtime every connection AND every
//! frame re-checks the daemon-materialised access state, so a
//! revoked peer's next frame is refused even mid-session
//! (SecurityMinimumBar §6.E controls E2/E3 at the service layer;
//! the daemon's exposure controller owns listener teardown).
//!
//! Identity: the connection's tunnel source address is resolved
//! against the daemon-written `peers.v1` map (overlay-ip → node-id,
//! derived from signed state). The wire protocol carries no
//! identity material; nothing client-supplied is trusted.
//!
//! Logs carry ids/counts only — never file contents or key bytes.

#![cfg(feature = "daemon")]
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustynet_nas::protocol::{self, MAX_FRAME_LEN, PROTOCOL_VERSION, Request, Response};
use rustynet_nas::store::NasStore;

const ACCESS_GRANTS_FILE: &str = "grants.v1";
const ACCESS_PEERS_FILE: &str = "peers.v1";

fn main() {
    let exit_code = match run() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("[rustynet-nas] fatal (fail-closed): {err}");
            1
        }
    };
    std::process::exit(exit_code);
}

struct Config {
    bind: SocketAddr,
    data_root: PathBuf,
    access_dir: PathBuf,
    key: [u8; 32],
}

fn run() -> Result<(), String> {
    let config = parse_and_validate_config()?;
    let store = NasStore::open(&config.data_root, config.key)
        .map_err(|err| format!("store open refused: {err}"))?;
    let store = Arc::new(store);
    let access_dir = Arc::new(config.access_dir);

    let listener = TcpListener::bind(config.bind)
        .map_err(|err| format!("bind {} failed: {err}", config.bind))?;
    eprintln!(
        "[rustynet-nas] serving on {} (default-deny; access state from {})",
        config.bind,
        access_dir.display()
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let store = Arc::clone(&store);
                let access_dir = Arc::clone(&access_dir);
                std::thread::spawn(move || {
                    if let Err(err) = serve_connection(stream, &store, &access_dir) {
                        eprintln!("[rustynet-nas] session ended: {err}");
                    }
                });
            }
            Err(err) => eprintln!("[rustynet-nas] accept failed: {err}"),
        }
    }
    Ok(())
}

fn parse_and_validate_config() -> Result<Config, String> {
    let mut bind: Option<SocketAddr> = None;
    let mut data_root: Option<PathBuf> = None;
    let mut access_dir: Option<PathBuf> = None;
    let mut key_credential: Option<String> = None;
    let mut key_file: Option<PathBuf> = None;

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
            "--data-root" => data_root = Some(PathBuf::from(value("--data-root")?)),
            "--access-dir" => access_dir = Some(PathBuf::from(value("--access-dir")?)),
            "--at-rest-key-credential" => key_credential = Some(value("--at-rest-key-credential")?),
            "--at-rest-key-file" => key_file = Some(PathBuf::from(value("--at-rest-key-file")?)),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }

    let bind = bind.ok_or("--bind is required")?;
    validate_tunnel_shaped_bind(bind.ip())?;
    let data_root = data_root.ok_or("--data-root is required")?;
    let access_dir = access_dir.ok_or("--access-dir is required")?;
    let key = load_at_rest_key(key_credential.as_deref(), key_file.as_deref())?;

    Ok(Config {
        bind,
        data_root,
        access_dir,
        key,
    })
}

/// E1 (bin-side layer): refuse bind shapes that can never be the
/// tunnel address. The authoritative tunnel-address check lives in
/// the daemon (`rustynetd::service_exposure::validate_tunnel_only_bind`
/// against signed state) and the nftables scope table; this startup
/// check fails closed on the unambiguous misconfigurations.
fn validate_tunnel_shaped_bind(ip: IpAddr) -> Result<(), String> {
    if ip.is_unspecified() {
        return Err("refusing wildcard bind (0.0.0.0/::): the NAS endpoint is tunnel-only".into());
    }
    if ip.is_loopback() {
        return Err("refusing loopback bind: mesh peers cannot reach loopback".into());
    }
    if ip.is_multicast() {
        return Err("refusing multicast bind".into());
    }
    Ok(())
}

fn load_at_rest_key(credential: Option<&str>, key_file: Option<&Path>) -> Result<[u8; 32], String> {
    let path = match (credential, key_file) {
        (Some(name), _) => {
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return Err("invalid credential name".into());
            }
            let dir = std::env::var_os("CREDENTIALS_DIRECTORY").ok_or(
                "CREDENTIALS_DIRECTORY not set (systemd LoadCredentialEncrypted required)",
            )?;
            PathBuf::from(dir).join(name)
        }
        (None, Some(path)) => path.to_path_buf(),
        (None, None) => {
            return Err("one of --at-rest-key-credential / --at-rest-key-file is required".into());
        }
    };

    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|err| format!("at-rest key unavailable at {}: {err}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "at-rest key at {} must be a regular file",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "at-rest key mode {mode:o} grants group/world access; chmod 600 required"
            ));
        }
    }
    let bytes = std::fs::read(&path)
        .map_err(|err| format!("read at-rest key {} failed: {err}", path.display()))?;
    if bytes.len() != 32 {
        return Err(format!(
            "at-rest key must be exactly 32 bytes (got {})",
            bytes.len()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Read the daemon-materialised access state. Missing/unreadable
/// files ⇒ deny-all (fail-closed): a NAS with no signed grants
/// serves nobody.
fn load_access_state(access_dir: &Path) -> (Vec<String>, BTreeMap<IpAddr, String>) {
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
    (grants, peers)
}

/// Per-frame admission: resolve identity from the tunnel source and
/// require a current grant. Re-reading per frame keeps revocation
/// immediate at this layer.
fn admitted_peer(access_dir: &Path, source: IpAddr) -> Result<String, String> {
    let (grants, peers) = load_access_state(access_dir);
    let node_id = peers
        .get(&source)
        .ok_or_else(|| format!("tunnel source {source} has no signed identity; refused"))?;
    if grants.iter().any(|grant| grant == node_id) {
        Ok(node_id.clone())
    } else {
        Err(format!("peer {node_id} is not authorised (default-deny)"))
    }
}

fn serve_connection(
    mut stream: TcpStream,
    store: &NasStore,
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
        let peer_node_id = match admitted_peer(access_dir, source) {
            Ok(id) => id,
            Err(reason) => {
                let _ = write_frame(
                    &mut stream,
                    &protocol::encode_response(&Response::Error { message: reason }),
                );
                return Ok(());
            }
        };

        let request = match protocol::decode_request(&body) {
            Ok(request) => request,
            Err(err) => {
                let _ = write_frame(
                    &mut stream,
                    &protocol::encode_response(&Response::Error {
                        message: format!("malformed request: {err}"),
                    }),
                );
                return Ok(());
            }
        };

        let response = handle_request(store, &peer_node_id, request);
        write_frame(&mut stream, &protocol::encode_response(&response))?;
    }
}

fn handle_request(store: &NasStore, peer_node_id: &str, request: Request) -> Response {
    let deny = |err: &dyn std::fmt::Display| Response::Error {
        message: err.to_string(),
    };
    match request {
        Request::Hello { .. } => match store.usage(peer_node_id) {
            Ok(quota) => Response::HelloOk {
                version: PROTOCOL_VERSION,
                quota_limit_bytes: quota.limit_bytes,
                quota_used_bytes: quota.used_bytes,
            },
            Err(err) => deny(&err),
        },
        Request::PutChunk { content_hash, data } => {
            match store.put_chunk(peer_node_id, &content_hash, &data) {
                Ok(()) => Response::Ok,
                Err(err) => deny(&err),
            }
        }
        Request::GetChunk { content_hash } => match store.get_chunk(peer_node_id, &content_hash) {
            Ok(data) => Response::Chunk { data },
            Err(err) => deny(&err),
        },
        Request::CommitSnapshot {
            snapshot_id,
            manifest,
        } => match store.commit_snapshot(peer_node_id, &snapshot_id, &manifest) {
            Ok(()) => Response::Ok,
            Err(err) => deny(&err),
        },
        Request::ListSnapshots => match store.list_snapshots(peer_node_id) {
            Ok(entries) => Response::Snapshots {
                snapshot_ids: entries
                    .into_iter()
                    .filter(|entry| !entry.soft_deleted)
                    .map(|entry| entry.snapshot_id)
                    .collect(),
            },
            Err(err) => deny(&err),
        },
        Request::GetSnapshot { snapshot_id } => {
            match store.get_snapshot(peer_node_id, &snapshot_id) {
                Ok(manifest) => Response::Snapshot { manifest },
                Err(err) => deny(&err),
            }
        }
        Request::DeleteSnapshot { snapshot_id } => {
            match store.delete_snapshot(peer_node_id, &snapshot_id) {
                Ok(()) => Response::Ok,
                Err(err) => deny(&err),
            }
        }
        Request::Usage => match store.usage(peer_node_id) {
            Ok(quota) => Response::Usage {
                quota_limit_bytes: quota.limit_bytes,
                quota_used_bytes: quota.used_bytes,
            },
            Err(err) => deny(&err),
        },
    }
}

/// Length-prefixed frame read with the cap enforced BEFORE
/// allocation. `Ok(None)` = orderly EOF between frames.
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
