#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let mut args = env::args_os();
    let program = args
        .next()
        .unwrap_or_else(|| OsString::from("run_required_test"));
    let mut remaining: Vec<OsString> = args.collect();
    if remaining.len() < 2 {
        eprintln!(
            "usage: {} <cargo-package> <test-filter> [cargo-test-args...]",
            program.to_string_lossy()
        );
        return Err(2);
    }

    let package = remaining.remove(0);
    let test_filter = remaining.remove(0);
    let extra_args = remaining;
    let tmp_output = TempOutputGuard::create().map_err(|err| {
        eprintln!("{err}");
        1
    })?;

    let output_file = OpenOptions::new()
        .write(true)
        .open(tmp_output.path())
        .map_err(|err| {
            eprintln!(
                "failed to open temporary output file ({}): {err}",
                tmp_output.path().display()
            );
            1
        })?;
    let mut cmd = Command::new("cargo");
    cmd.arg("test")
        .arg("-p")
        .arg(&package)
        .arg(&test_filter)
        .args(&extra_args)
        .args(["--", "--nocapture"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(output_file.try_clone().map_err(|err| {
            eprintln!(
                "failed to clone output file handle ({}): {err}",
                tmp_output.path().display()
            );
            1
        })?))
        .stderr(Stdio::from(output_file));
    let status = cmd.status().map_err(|err| {
        eprintln!("failed to run cargo test: {err}");
        1
    })?;
    if !status.success() {
        dump_file(tmp_output.path(), &mut io::stderr().lock())?;
        eprintln!(
            "required test failed: package={} filter={}",
            package.to_string_lossy(),
            test_filter.to_string_lossy()
        );
        return Err(1);
    }

    dump_file(tmp_output.path(), &mut io::stdout().lock())?;
    verify_required_test_output(tmp_output.path(), &package, &test_filter)
}

fn verify_required_test_output(
    output: &Path,
    package: &OsString,
    test_filter: &OsString,
) -> Result<(), i32> {
    let output_utf8 = output.to_str().ok_or_else(|| {
        eprintln!(
            "required test output path is not UTF-8: {}",
            output.display()
        );
        1
    })?;
    let package_utf8 = package.to_str().ok_or_else(|| {
        eprintln!("package value is not UTF-8: {}", package.to_string_lossy());
        1
    })?;
    let filter_utf8 = test_filter.to_str().ok_or_else(|| {
        eprintln!(
            "test filter value is not UTF-8: {}",
            test_filter.to_string_lossy()
        );
        1
    })?;
    let status = Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            "verify-required-test-output",
            "--output",
            output_utf8,
            "--package",
            package_utf8,
            "--test-filter",
            filter_utf8,
        ])
        .stdin(Stdio::null())
        .status()
        .map_err(|err| {
            eprintln!("failed to run verify-required-test-output command: {err}");
            1
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
    }
}

fn dump_file(path: &Path, writer: &mut dyn Write) -> Result<(), i32> {
    let mut file = File::open(path).map_err(|err| {
        eprintln!("failed to read output file ({}): {err}", path.display());
        1
    })?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(|err| {
        eprintln!("failed to read output file ({}): {err}", path.display());
        1
    })?;
    writer.write_all(&data).map_err(|err| {
        eprintln!("failed to write command output stream: {err}");
        1
    })?;
    writer.flush().map_err(|err| {
        eprintln!("failed to flush command output stream: {err}");
        1
    })?;
    Ok(())
}

fn status_code(status: ExitStatus) -> i32 {
    match status.code() {
        Some(code) => code,
        None => {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;

                match status.signal() {
                    Some(signal) => 128 + signal,
                    None => 1,
                }
            }
            #[cfg(not(unix))]
            {
                1
            }
        }
    }
}

struct TempOutputGuard {
    path: PathBuf,
}

impl TempOutputGuard {
    fn create() -> Result<Self, String> {
        let base = env::var_os("TMPDIR")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        fs::create_dir_all(&base).map_err(|err| {
            format!(
                "failed to create temp output directory {}: {err}",
                base.display()
            )
        })?;

        let pid = std::process::id();
        for attempt in 0_u32..256 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path = base.join(format!(
                "rustynet-required-test.{pid}.{nanos}.{attempt}.tmp"
            ));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => return Ok(Self { path }),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(format!(
                        "failed to create temporary output file ({}): {err}",
                        path.display()
                    ));
                }
            }
        }

        Err(format!(
            "failed to allocate unique temporary output file under {}",
            base.display()
        ))
    }

    fn path(&self) -> &Path {
        self.path.as_path()
    }
}

impl Drop for TempOutputGuard {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.path)
            && err.kind() != io::ErrorKind::NotFound
        {
            eprintln!(
                "warning: failed to remove temporary output file ({}): {err}",
                self.path.display()
            );
        }
    }
}
