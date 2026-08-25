use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

#[derive(Debug)]
pub enum ConfigError {
    Io(String),
    Insecure(String),
    Validation(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(msg) => write!(formatter, "config io error: {msg}"),
            Self::Insecure(msg) => write!(formatter, "config security error: {msg}"),
            Self::Validation(msg) => write!(formatter, "config validation error: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(unix)]
pub fn save_config_atomic(path: &Path, serialized: &str) -> Result<(), ConfigError> {
    let dir = path
        .parent()
        .ok_or_else(|| ConfigError::Io("config path has no parent directory".to_owned()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ConfigError::Io("config path has no file name".to_owned()))?;
    let tmp = dir.join(format!(".{file_name}.tmp"));

    {
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
        {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                // A crashed prior save may leave a plain temp file behind;
                // reuse only that. A symlink or non-regular file planted at
                // the predictable temp path must never be followed: fail
                // closed instead of redirecting the privileged-mode write.
                let metadata = fs::symlink_metadata(&tmp).map_err(|err| {
                    ConfigError::Io(format!("stat temp {}: {err}", tmp.display()))
                })?;
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(ConfigError::Insecure(format!(
                        "Refusing to follow non-regular temp config file: {}",
                        tmp.display()
                    )));
                }
                fs::remove_file(&tmp).map_err(|err| {
                    ConfigError::Io(format!("remove stale temp {}: {err}", tmp.display()))
                })?;
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&tmp)
                    .map_err(|err| ConfigError::Io(format!("open temp {}: {err}", tmp.display())))?
            }
            Err(err) => {
                return Err(ConfigError::Io(format!(
                    "open temp {}: {err}",
                    tmp.display()
                )));
            }
        };
        file.write_all(serialized.as_bytes())
            .map_err(|err| ConfigError::Io(format!("write temp: {err}")))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|err| ConfigError::Io(format!("chmod temp: {err}")))?;
        file.sync_all()
            .map_err(|err| ConfigError::Io(format!("fsync temp: {err}")))?;
    }

    fs::rename(&tmp, path).map_err(|err| {
        let _ = fs::remove_file(&tmp);
        ConfigError::Io(format!("rename temp into place: {err}"))
    })?;

    let dir_file = fs::File::open(dir)
        .map_err(|err| ConfigError::Io(format!("open config dir {}: {err}", dir.display())))?;
    dir_file
        .sync_all()
        .map_err(|err| ConfigError::Io(format!("fsync config dir: {err}")))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn save_config_atomic(path: &Path, _serialized: &str) -> Result<(), ConfigError> {
    Err(ConfigError::Io(format!(
        "atomic operator config persist is not implemented for this platform: {}",
        path.display()
    )))
}

#[cfg(unix)]
pub fn assert_config_file_secure(path: &Path, current_uid: u32) -> Result<(), ConfigError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(ConfigError::Io(format!("stat config: {err}"))),
    };

    if metadata.file_type().is_symlink() {
        return Err(ConfigError::Insecure(format!(
            "Refusing to load symlink config file: {}",
            path.display()
        )));
    }

    let owner_uid = metadata.uid();
    if owner_uid != current_uid && owner_uid != 0 {
        return Err(ConfigError::Insecure(format!(
            "Config file owner is not trusted ({}, uid={owner_uid}).",
            path.display()
        )));
    }

    let mode = metadata.permissions().mode();
    if mode & 0o022 != 0 {
        return Err(ConfigError::Insecure(format!(
            "Config file must not be group/world writable: {} (mode {:03o}).",
            path.display(),
            mode & 0o777
        )));
    }

    Ok(())
}

#[cfg(not(unix))]
pub fn assert_config_file_secure(path: &Path, _current_uid: u32) -> Result<(), ConfigError> {
    Err(ConfigError::Insecure(format!(
        "operator config security validation is not implemented for this platform: {}",
        path.display()
    )))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
    }

    fn current_uid() -> u32 {
        let dir = unique_dir("rustynet-uid-probe");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("probe");
        fs::write(&path, "").unwrap();
        let uid = fs::metadata(&path).unwrap().uid();
        let _ = fs::remove_dir_all(&dir);
        uid
    }

    #[test]
    fn atomic_write_sets_0600_and_round_trips() {
        let dir = unique_dir("rustynet-op");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wizard.env");
        save_config_atomic(&path, "NODE_ROLE=admin\n").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(fs::read_to_string(&path).unwrap(), "NODE_ROLE=admin\n");
        assert!(!dir.join(".wizard.env.tmp").exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn planted_tmp_symlink_is_refused_and_target_untouched() {
        let dir = unique_dir("rustynet-op-tmp-symlink");
        fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim.conf");
        fs::write(&victim, "SENTINEL").unwrap();
        let link = dir.join(".wizard.env.tmp");
        symlink(&victim, &link).unwrap();

        let result = save_config_atomic(&dir.join("wizard.env"), "NODE_ROLE=admin\n");
        assert!(matches!(result, Err(ConfigError::Insecure(_))));
        assert_eq!(fs::read_to_string(&victim).unwrap(), "SENTINEL");

        // The planted symlink must survive untouched; saving never follows it.
        let metadata = fs::symlink_metadata(&link).unwrap();
        assert!(metadata.file_type().is_symlink());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stale_regular_tmp_from_crashed_save_is_replaced() {
        let dir = unique_dir("rustynet-op-stale-tmp");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wizard.env");
        fs::write(dir.join(".wizard.env.tmp"), "stale residue").unwrap();

        save_config_atomic(&path, "NODE_ROLE=admin\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "NODE_ROLE=admin\n");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_file_is_secure() {
        let path = unique_dir("rustynet-missing").join("wizard.env");
        assert!(assert_config_file_secure(&path, current_uid()).is_ok());
    }

    #[test]
    fn group_writable_is_rejected() {
        let dir = unique_dir("rustynet-op-gw");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wizard.env");
        fs::write(&path, "x").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
        let result = assert_config_file_secure(&path, current_uid());
        assert!(matches!(result, Err(ConfigError::Insecure(_))));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn symlink_is_rejected() {
        let dir = unique_dir("rustynet-op-symlink");
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target.env");
        let link = dir.join("wizard.env");
        fs::write(&target, "NODE_ROLE=admin\n").unwrap();
        symlink(&target, &link).unwrap();
        let result = assert_config_file_secure(&link, current_uid());
        assert!(matches!(result, Err(ConfigError::Insecure(_))));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn directory_tmp_residue_is_refused_and_untouched() {
        let dir = unique_dir("rustynet-op-dir-residue");
        fs::create_dir_all(&dir).unwrap();
        let planted = dir.join(".wizard.env.tmp");
        fs::create_dir(&planted).unwrap();
        fs::write(planted.join("payload"), "x").unwrap();

        let result = save_config_atomic(&dir.join("wizard.env"), "NODE_ROLE=admin\n");
        assert!(
            matches!(result, Err(ConfigError::Insecure(_))),
            "non-regular temp residue must be refused as Insecure, got {result:?}"
        );
        // The planted entry must survive untouched; saving never deletes or
        // traverses an entry it could not classify as a plain regular file.
        assert!(planted.is_dir());
        assert!(planted.join("payload").exists());
        fs::remove_dir_all(&dir).ok();
    }
}
