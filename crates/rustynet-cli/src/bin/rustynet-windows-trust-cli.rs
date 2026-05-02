#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use rand::{TryRngCore, rngs::OsRng};
use rustynet_crypto::{
    KeyCustodyPermissionPolicy, read_encrypted_key_file, write_encrypted_key_file,
};
use rustynetd::key_material::read_passphrase_file_explicit;
use zeroize::{Zeroize, Zeroizing};

fn main() {
    match run() {
        Ok(message) => {
            println!("{message}");
        }
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<String, String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [scope, action, rest @ ..] if scope == "trust" && action == "keygen" => {
            let parser = OptionParser::parse(rest)?;
            trust_keygen(
                parser.required_path("--signing-key-output")?,
                parser.required_path("--signing-key-passphrase-file")?,
                parser.required_path("--verifier-key-output")?,
                parser.has_flag("--force"),
            )
        }
        [scope, action, rest @ ..] if scope == "trust" && action == "export-verifier-key" => {
            let parser = OptionParser::parse(rest)?;
            trust_export_verifier_key(
                parser.required_path("--signing-key")?,
                parser.required_path("--signing-key-passphrase-file")?,
                parser.required_path("--output")?,
            )
        }
        [scope, action, rest @ ..] if scope == "trust" && action == "issue" => {
            let parser = OptionParser::parse(rest)?;
            trust_issue(
                parser.required_path("--signing-key")?,
                parser.required_path("--signing-key-passphrase-file")?,
                parser.required_path("--output")?,
                parser.parse_u64_or_default("--updated-at-unix", unix_now())?,
                parser.parse_u64_or_default("--nonce", generate_nonce())?,
            )
        }
        _ => Err("usage: rustynet trust <keygen|export-verifier-key|issue> [options]".to_string()),
    }
}

#[derive(Debug)]
struct OptionParser<'a> {
    args: &'a [String],
}

impl<'a> OptionParser<'a> {
    fn parse(args: &'a [String]) -> Result<Self, String> {
        let parser = Self { args };
        let mut index = 0usize;
        while index < args.len() {
            if !args[index].starts_with("--") {
                return Err(format!("unexpected positional argument: {}", args[index]));
            }
            if parser.is_flag(args[index].as_str()) {
                index += 1;
            } else {
                if index + 1 >= args.len() || args[index + 1].starts_with("--") {
                    return Err(format!("missing value for option {}", args[index]));
                }
                index += 2;
            }
        }
        Ok(parser)
    }

    fn is_flag(&self, key: &str) -> bool {
        key == "--force"
    }

    fn has_flag(&self, key: &str) -> bool {
        self.args.iter().any(|arg| arg == key)
    }

    fn required_path(&self, key: &str) -> Result<PathBuf, String> {
        self.required_value(key).map(PathBuf::from)
    }

    fn required_value(&self, key: &str) -> Result<String, String> {
        let mut index = 0usize;
        while index < self.args.len() {
            if self.args[index] == key {
                if index + 1 >= self.args.len() || self.args[index + 1].starts_with("--") {
                    return Err(format!("missing value for option {key}"));
                }
                return Ok(self.args[index + 1].clone());
            }
            index += 1;
        }
        Err(format!("missing required option {key}"))
    }

    fn parse_u64_or_default(&self, key: &str, default: u64) -> Result<u64, String> {
        let mut index = 0usize;
        while index < self.args.len() {
            if self.args[index] == key {
                if index + 1 >= self.args.len() || self.args[index + 1].starts_with("--") {
                    return Err(format!("missing value for option {key}"));
                }
                return self.args[index + 1]
                    .parse::<u64>()
                    .map_err(|err| format!("invalid {key} value: {err}"));
            }
            index += 1;
        }
        Ok(default)
    }
}

fn trust_keygen(
    signing_key_path: PathBuf,
    signing_key_passphrase_path: PathBuf,
    verifier_key_output_path: PathBuf,
    force: bool,
) -> Result<String, String> {
    let mut seed = [0u8; 32];
    fill_os_random_bytes(&mut seed, "trust signing key")?;
    persist_encrypted_secret_material(
        &signing_key_path,
        &seed,
        &signing_key_passphrase_path,
        "trust signing key",
        force,
    )?;
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    write_text_file(
        &verifier_key_output_path,
        &format!("{}\n", hex_bytes(signing_key.verifying_key().as_bytes())),
    )?;
    Ok(format!(
        "trust signing key initialized: signing_key={} verifier_key_output={}",
        signing_key_path.display(),
        verifier_key_output_path.display()
    ))
}

fn trust_export_verifier_key(
    signing_key_path: PathBuf,
    signing_key_passphrase_path: PathBuf,
    output_path: PathBuf,
) -> Result<String, String> {
    let signing_key = load_signing_key(&signing_key_path, &signing_key_passphrase_path)?;
    write_text_file(
        &output_path,
        &format!("{}\n", hex_bytes(signing_key.verifying_key().as_bytes())),
    )?;
    Ok(format!(
        "trust verifier key exported: signing_key={} output={}",
        signing_key_path.display(),
        output_path.display()
    ))
}

fn trust_issue(
    signing_key_path: PathBuf,
    signing_key_passphrase_path: PathBuf,
    output_path: PathBuf,
    updated_at_unix: u64,
    nonce: u64,
) -> Result<String, String> {
    let signing_key = load_signing_key(&signing_key_path, &signing_key_passphrase_path)?;
    let payload = format!(
        "version=2\ntls13_valid=true\nsigned_control_valid=true\nsigned_data_age_secs=0\nclock_skew_secs=0\nupdated_at_unix={updated_at_unix}\nnonce={nonce}\n"
    );
    let signature = signing_key.sign(payload.as_bytes());
    write_text_file(
        &output_path,
        &format!("{payload}signature={}\n", hex_bytes(&signature.to_bytes())),
    )?;
    Ok(format!(
        "trust evidence issued: output={} updated_at_unix={} nonce={}",
        output_path.display(),
        updated_at_unix,
        nonce
    ))
}

fn persist_encrypted_secret_material(
    path: &Path,
    secret: &[u8],
    passphrase_path: &Path,
    label: &str,
    force: bool,
) -> Result<(), String> {
    if !passphrase_path.is_absolute() {
        return Err(format!(
            "{label} passphrase file path must be absolute: {}",
            passphrase_path.display()
        ));
    }
    if path.exists() {
        let metadata =
            fs::symlink_metadata(path).map_err(|err| format!("inspect {label} failed: {err}"))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("{label} path must not be a symlink"));
        }
        if !metadata.file_type().is_file() {
            return Err(format!("{label} path must reference a regular file"));
        }
        if !force {
            return Err(format!(
                "{label} already exists at {}; use --force to overwrite",
                path.display()
            ));
        }
        fs::remove_file(path).map_err(|err| format!("remove old {label} failed: {err}"))?;
    }
    let passphrase = read_passphrase_file_explicit(passphrase_path).map_err(|err| {
        format!(
            "{label} passphrase source invalid ({}): {err}",
            passphrase_path.display()
        )
    })?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} path has no parent: {}", path.display()))?;
    write_encrypted_key_file(
        parent,
        path,
        secret,
        passphrase.as_str(),
        encrypted_secret_permission_policy(path),
    )
    .map_err(|err| {
        format!(
            "persist encrypted {label} failed ({}): {err}",
            path.display()
        )
    })
}

fn load_signing_key(path: &Path, passphrase_path: &Path) -> Result<SigningKey, String> {
    let secret = load_encrypted_secret_material(path, passphrase_path, "signing key")?;
    if secret.len() != 32 {
        return Err("decrypted signing key must be exactly 32 bytes".to_string());
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(secret.as_slice());
    let key = SigningKey::from_bytes(&bytes);
    bytes.zeroize();
    Ok(key)
}

fn load_encrypted_secret_material(
    path: &Path,
    passphrase_path: &Path,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if !passphrase_path.is_absolute() {
        return Err(format!(
            "{label} passphrase file path must be absolute: {}",
            passphrase_path.display()
        ));
    }
    if !path.is_file() {
        return Err(format!("{label} path must reference a regular file"));
    }
    let passphrase = read_passphrase_file_explicit(passphrase_path).map_err(|err| {
        format!(
            "{label} passphrase source invalid ({}): {err}",
            passphrase_path.display()
        )
    })?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label} path has no parent: {}", path.display()))?;
    let secret = read_encrypted_key_file(
        parent,
        path,
        passphrase.as_str(),
        encrypted_secret_permission_policy(path),
    )
    .map_err(|err| format!("decrypt {label} failed ({}): {err}", path.display()))?;
    Ok(Zeroizing::new(secret))
}

fn encrypted_secret_permission_policy(_path: &Path) -> KeyCustodyPermissionPolicy {
    KeyCustodyPermissionPolicy::default()
}

fn write_text_file(path: &Path, body: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create parent failed: {err}"))?;
    }
    fs::write(path, body).map_err(|err| format!("write file failed: {err}"))
}

fn fill_os_random_bytes(bytes: &mut [u8], label: &str) -> Result<(), String> {
    OsRng
        .try_fill_bytes(bytes)
        .map_err(|err| format!("os randomness unavailable for {label}: {err}"))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn generate_nonce() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    (nanos & u128::from(u64::MAX)) as u64
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
