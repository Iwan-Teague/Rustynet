use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use nix::unistd::Uid;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerRecord {
    name: String,
    node_id: String,
    public_key: String,
    endpoint: String,
    cidr: String,
    role: String,
}

pub fn execute_ops_peer_store_validate(
    config_dir: PathBuf,
    peers_file: PathBuf,
) -> Result<String, String> {
    ensure_peer_store_paths(config_dir.as_path(), peers_file.as_path())?;
    let _ = load_peer_records(peers_file.as_path())?;
    Ok(format!(
        "peer store validated: config_dir={} peers_file={}",
        config_dir.display(),
        peers_file.display()
    ))
}

pub fn execute_ops_peer_store_list(
    config_dir: PathBuf,
    peers_file: PathBuf,
    role_filter: Option<String>,
    node_id_filter: Option<String>,
) -> Result<String, String> {
    let role_filter = normalize_filter("role", role_filter)?;
    let node_id_filter = normalize_filter("node-id", node_id_filter)?;

    ensure_peer_store_paths(config_dir.as_path(), peers_file.as_path())?;
    let records = load_peer_records(peers_file.as_path())?;

    let mut output = String::new();
    for record in records {
        if let Some(role) = role_filter.as_ref() {
            if record.role != *role {
                continue;
            }
        }
        if let Some(node_id) = node_id_filter.as_ref() {
            if record.node_id != *node_id {
                continue;
            }
        }
        output.push_str(
            format!(
                "{}|{}|{}|{}|{}|{}\n",
                record.name,
                record.node_id,
                record.public_key,
                record.endpoint,
                record.cidr,
                record.role
            )
            .as_str(),
        );
    }
    Ok(output)
}

fn normalize_filter(label: &str, value: Option<String>) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        return Ok(None);
    }
    ensure_peer_field_safe(label, trimmed.as_str(), None)?;
    Ok(Some(trimmed))
}

fn ensure_peer_store_paths(config_dir: &Path, peers_file: &Path) -> Result<(), String> {
    ensure_absolute_path("config-dir", config_dir)?;
    ensure_absolute_path("peers-file", peers_file)?;

    if peers_file.file_name().and_then(|value| value.to_str()) != Some("peers.db") {
        return Err(format!(
            "peers file must be named peers.db: {}",
            peers_file.display()
        ));
    }

    let parent = peers_file.parent().ok_or_else(|| {
        format!(
            "peers file parent directory is missing: {}",
            peers_file.display()
        )
    })?;
    if parent != config_dir {
        return Err(format!(
            "peers file must be located under config dir: peers_file={} config_dir={}",
            peers_file.display(),
            config_dir.display()
        ));
    }

    ensure_config_dir(config_dir)?;
    ensure_peer_file(peers_file)?;

    let config_canonical = fs::canonicalize(config_dir).map_err(|err| {
        format!(
            "failed to canonicalize config dir {}: {err}",
            config_dir.display()
        )
    })?;
    let parent_canonical = fs::canonicalize(parent).map_err(|err| {
        format!(
            "failed to canonicalize peer-store parent {}: {err}",
            parent.display()
        )
    })?;
    if config_canonical != parent_canonical {
        return Err(format!(
            "peer-store parent mismatch after canonicalization: peers_file={} config_dir={}",
            peers_file.display(),
            config_dir.display()
        ));
    }

    Ok(())
}

fn ensure_absolute_path(label: &str, path: &Path) -> Result<(), String> {
    if path.is_absolute() {
        return Ok(());
    }
    Err(format!("{label} must be absolute: {}", path.display()))
}

fn ensure_config_dir(config_dir: &Path) -> Result<(), String> {
    if let Ok(metadata) = fs::symlink_metadata(config_dir) {
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "refusing to use symlink config directory: {}",
                config_dir.display()
            ));
        }
        if !metadata.is_dir() {
            return Err(format!(
                "refusing to use non-directory config path: {}",
                config_dir.display()
            ));
        }
    } else {
        fs::create_dir_all(config_dir).map_err(|err| {
            format!(
                "failed to create config directory {}: {err}",
                config_dir.display()
            )
        })?;
    }
    ensure_unix_owner(config_dir, "config directory")?;
    set_unix_mode(config_dir, 0o700)?;
    Ok(())
}

fn ensure_peer_file(peers_file: &Path) -> Result<(), String> {
    if let Ok(metadata) = fs::symlink_metadata(peers_file) {
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "refusing to use symlink peer store: {}",
                peers_file.display()
            ));
        }
        if !metadata.is_file() {
            return Err(format!(
                "refusing to use non-regular peer store path: {}",
                peers_file.display()
            ));
        }
    } else {
        create_peer_file(peers_file)?;
    }

    ensure_unix_owner(peers_file, "peer store")?;
    set_unix_mode(peers_file, 0o600)?;
    Ok(())
}

fn create_peer_file(peers_file: &Path) -> Result<(), String> {
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(peers_file)
    {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            return Ok(());
        }
        Err(err) => {
            return Err(format!(
                "failed to initialize secure peer store {}: {err}",
                peers_file.display()
            ));
        }
    };
    file.write_all(b"# name|node_id|public_key|endpoint|cidr|role\n")
        .map_err(|err| {
            format!(
                "failed to write peer-store header {}: {err}",
                peers_file.display()
            )
        })?;
    file.sync_all()
        .map_err(|err| format!("failed to sync peer store {}: {err}", peers_file.display()))
}

fn ensure_unix_owner(path: &Path, label: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(path)
        .map_err(|err| format!("failed to inspect {label} {}: {err}", path.display()))?;
    let owner_uid = metadata.uid();
    let expected_uid = Uid::effective().as_raw();
    if owner_uid != expected_uid {
        return Err(format!(
            "{label} owner is not trusted (path={}, uid={owner_uid}, expected_uid={expected_uid})",
            path.display()
        ));
    }
    Ok(())
}

fn set_unix_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let permissions = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, permissions).map_err(|err| {
        format!(
            "failed setting mode {:03o} on {}: {err}",
            mode,
            path.display()
        )
    })
}

fn load_peer_records(peers_file: &Path) -> Result<Vec<PeerRecord>, String> {
    let file = File::open(peers_file)
        .map_err(|err| format!("failed reading peer store {}: {err}", peers_file.display()))?;
    let reader = BufReader::new(file);

    let mut records = Vec::new();
    for (index, line_result) in reader.lines().enumerate() {
        let line_no = index + 1;
        let line = line_result.map_err(|err| {
            format!(
                "failed reading peer store line {line_no} ({}): {err}",
                peers_file.display()
            )
        })?;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts = line.split('|').collect::<Vec<_>>();
        if parts.len() > 6 {
            return Err(format!(
                "peer store line {line_no} is malformed (too many fields)"
            ));
        }

        let mut fields = vec![String::new(); 6];
        for (field_index, field_value) in parts.into_iter().enumerate() {
            fields[field_index] = field_value.to_string();
        }

        ensure_peer_field_safe("name", fields[0].as_str(), Some(line_no))?;
        ensure_peer_field_safe("node_id", fields[1].as_str(), Some(line_no))?;
        ensure_peer_field_safe("public_key", fields[2].as_str(), Some(line_no))?;
        ensure_peer_field_safe("endpoint", fields[3].as_str(), Some(line_no))?;
        ensure_peer_field_safe("cidr", fields[4].as_str(), Some(line_no))?;
        ensure_peer_field_safe("role", fields[5].as_str(), Some(line_no))?;

        records.push(PeerRecord {
            name: fields[0].clone(),
            node_id: fields[1].clone(),
            public_key: fields[2].clone(),
            endpoint: fields[3].clone(),
            cidr: fields[4].clone(),
            role: fields[5].clone(),
        });
    }

    Ok(records)
}

fn ensure_peer_field_safe(label: &str, value: &str, line_no: Option<usize>) -> Result<(), String> {
    if value.contains('|') {
        return Err(field_error(
            label,
            "contains forbidden delimiter '|'",
            line_no,
        ));
    }
    if value.contains('\n') || value.contains('\r') {
        return Err(field_error(
            label,
            "contains forbidden newline characters",
            line_no,
        ));
    }
    if value.chars().any(|ch| ch.is_control()) {
        return Err(field_error(
            label,
            "contains forbidden control characters",
            line_no,
        ));
    }
    Ok(())
}

fn field_error(label: &str, message: &str, line_no: Option<usize>) -> String {
    match line_no {
        Some(line_no) => format!("peer store line {line_no} field '{label}' {message}"),
        None => format!("peer store field '{label}' {message}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{execute_ops_peer_store_list, execute_ops_peer_store_validate};
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEST_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_paths() -> (PathBuf, PathBuf, PathBuf) {
        let counter = TEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let root = PathBuf::from(format!("/tmp/rustynet-peer-store-tests.{unique}.{counter}"));
        let config_dir = root.join("config");
        let peers_file = config_dir.join("peers.db");
        (root, config_dir, peers_file)
    }

    fn cleanup(path: &Path) {
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn validate_creates_store_with_secure_modes() {
        let (root, config_dir, peers_file) = temp_paths();
        let result =
            execute_ops_peer_store_validate(config_dir.clone(), peers_file.clone()).unwrap();
        assert!(result.contains("peer store validated"));

        let config_metadata = fs::metadata(config_dir.as_path()).unwrap();
        let peers_metadata = fs::metadata(peers_file.as_path()).unwrap();
        assert_eq!(config_metadata.permissions().mode() & 0o777, 0o700);
        assert_eq!(peers_metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            config_metadata.uid(),
            nix::unistd::Uid::effective().as_raw()
        );
        assert_eq!(peers_metadata.uid(), nix::unistd::Uid::effective().as_raw());
        let contents = fs::read_to_string(peers_file.as_path()).unwrap();
        assert!(contents.starts_with("# name|node_id|public_key|endpoint|cidr|role"));

        cleanup(root.as_path());
    }

    #[test]
    fn list_rejects_malformed_record_with_extra_field() {
        let (root, config_dir, peers_file) = temp_paths();
        execute_ops_peer_store_validate(config_dir.clone(), peers_file.clone()).unwrap();
        fs::write(
            peers_file.as_path(),
            "# name|node_id|public_key|endpoint|cidr|role\nbad|node|pub|1.2.3.4:51820|10.0.0.0/24|admin|extra\n",
        )
        .unwrap();

        let err = execute_ops_peer_store_list(config_dir, peers_file, None, None).unwrap_err();
        assert!(err.contains("too many fields"));

        cleanup(root.as_path());
    }

    #[test]
    fn list_supports_role_and_node_filters() {
        let (root, config_dir, peers_file) = temp_paths();
        execute_ops_peer_store_validate(config_dir.clone(), peers_file.clone()).unwrap();
        fs::write(
            peers_file.as_path(),
            "# name|node_id|public_key|endpoint|cidr|role\nexit-a|exit-1|pub1|10.0.0.1:51820|100.64.0.1/32|admin\nclient-a|client-1|pub2|10.0.0.2:51820|100.64.0.2/32|client\n",
        )
        .unwrap();

        let admin = execute_ops_peer_store_list(
            config_dir.clone(),
            peers_file.clone(),
            Some("admin".to_string()),
            None,
        )
        .unwrap();
        assert!(admin.contains("exit-a|exit-1|pub1|10.0.0.1:51820|100.64.0.1/32|admin"));
        assert!(!admin.contains("client-a|client-1"));

        let client =
            execute_ops_peer_store_list(config_dir, peers_file, None, Some("client-1".to_string()))
                .unwrap();
        assert!(client.contains("client-a|client-1|pub2|10.0.0.2:51820|100.64.0.2/32|client"));
        assert!(!client.contains("exit-a|exit-1"));

        cleanup(root.as_path());
    }
}
