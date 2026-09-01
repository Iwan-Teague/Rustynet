#![allow(dead_code)]
use std::fs;
use std::path::Path;
use std::time::Duration;

use crate::vm_lab::orchestrator::adapter::node_adapter::MeshClientNatSession;
use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::adapter::windows_install::{
    ps_quote, run_remote_ps, run_remote_ps_check, WINDOWS_RELAY_SERVICE_NAME,
    WINDOWS_RUSTYNET_PATH, WINDOWS_SERVICE_NAME, WINDOWS_STAGING_DIR, WINDOWS_STATE_ROOT,
};
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::{AdapterError, TrafficTestResult, TunnelsList};
use crate::vm_lab::orchestrator::role_validation::identity_challenge::IdentityEvidence;

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const MEDIUM_TIMEOUT: Duration = Duration::from_secs(120);

/// A complete, valid zip archive containing nothing: the 22-byte
/// end-of-central-directory record, `PK\x05\x06` followed by 18 zero bytes
/// (disk numbers, entry counts, central-directory size and offset, comment
/// length). Byte-identical to what `ZipFile.Open(.., Create).Dispose()` emits.
///
/// ONE definition, used twice on purpose: the collector renders it into the
/// PowerShell that writes the archive, and `verify_no_key_material_zip`
/// compares the downloaded bytes against it. The check is only sound because
/// the two are the same constant — if the writer could drift from the verifier,
/// the verifier would be attesting something it no longer produces. Pinned by
/// `the_empty_archive_the_script_writes_is_the_one_the_verifier_accepts`.
const EMPTY_ARTIFACT_ARCHIVE: [u8; 22] = [
    0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Render [`EMPTY_ARTIFACT_ARCHIVE`] as a PowerShell byte-array literal.
fn empty_artifact_archive_ps_literal() -> String {
    let bytes = EMPTY_ARTIFACT_ARCHIVE
        .iter()
        .map(|b| format!("0x{b:02X}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[byte[]]@({bytes})")
}

/// Read the `WireGuard` public key from `C:\ProgramData\RustyNet\keys\wireguard.pub`.
/// Returns the base64-encoded key decoded to hex (32-byte key → 64-char hex).
pub fn collect_wireguard_public_key(conn: &NodeConnection) -> Result<String, AdapterError> {
    let key_path = format!(r"{WINDOWS_STATE_ROOT}\keys\wireguard.pub");
    let script = format!(
        "Get-Content -LiteralPath {} -Encoding utf8 -Raw",
        ps_quote(&key_path)?
    );
    let raw = run_remote_ps(conn, &script, SHORT_TIMEOUT)?;
    let hex = decode_wireguard_pubkey_to_hex(raw.trim())
        .map_err(|err| AdapterError::Protocol { message: err })?;
    Ok(hex)
}

/// Read the local `node_id` from `rustynetd.env`
/// (`RUSTYNETD_DAEMON_ARGS_JSON`).
///
/// The node-id is written into the reviewed env-file by the orchestrator
/// during bootstrap. This reader remains the bootstrap-time identity source;
/// it must NOT be used to satisfy the §4.7 live-identity challenge — that
/// challenge requires the daemon's own status response (see
/// [`query_live_identity`], which asks the installed trust CLI for it).
pub fn collect_node_id(conn: &NodeConnection) -> Result<String, AdapterError> {
    let script = collect_node_id_script()?;
    let output = run_remote_ps(conn, &script, SHORT_TIMEOUT)?;
    let node_id = output.trim().to_owned();
    if node_id.is_empty() {
        return Err(AdapterError::Protocol {
            message: "node_id extracted from rustynetd.env is empty".to_owned(),
        });
    }
    Ok(node_id)
}

/// Build the PowerShell script [`collect_node_id`] runs. Extracted so tests
/// can pin the script shape (env-file only, no trust-CLI invocation) without
/// an SSH round-trip.
fn collect_node_id_script() -> Result<String, AdapterError> {
    let env_path = format!(r"{WINDOWS_STATE_ROOT}\config\rustynetd.env");
    Ok(format!(
        "$envPath = {env_path_q}; \
         $content = Get-Content -LiteralPath $envPath -Raw -ErrorAction SilentlyContinue; \
         if ([string]::IsNullOrEmpty($content)) {{ throw ('rustynetd.env not found or empty at ' + $envPath) }}; \
         $m = [regex]::Match($content, '\"--node-id\",\"([^\"]+)\"'); \
         if (-not $m.Success) {{ throw 'node-id not found in RUSTYNETD_DAEMON_ARGS_JSON in rustynetd.env' }}; \
         $m.Groups[1].Value.Trim()",
        env_path_q = ps_quote(&env_path)?
    ))
}

/// Gather a node-identity for the §4.7 challenge from the daemon's LIVE
/// status surface. The installed trust CLI's `status` verb forwards an
/// `IpcCommand::Status` request over the local daemon-control pipe and
/// prints the daemon's verbatim response, whose first line carries
/// `node_id=<id> node_role=<role> state=<state>`. The node-id is parsed from
/// that live self-report and tagged `LiveDaemonSocket`.
///
/// There is no fallback to the config env-file: if the remote invocation
/// fails, or the response carries no `node_id=`, this returns `Err` and the
/// challenge fails closed. [`collect_node_id`] stays as the bootstrap-time
/// env-file reader and must never stand in for a live proof.
pub fn query_live_identity(conn: &NodeConnection) -> Result<IdentityEvidence, AdapterError> {
    let script = live_identity_status_script()?;
    let status = run_remote_ps(conn, &script, SHORT_TIMEOUT)?;
    live_identity_from_status(&status)
}

/// Build the PowerShell script [`query_live_identity`] runs: invoke the
/// trust CLI's `status` verb (no shell, no untrusted interpolation — the
/// only dynamic part is the reviewed install path).
fn live_identity_status_script() -> Result<String, AdapterError> {
    Ok(format!("& {} status", ps_quote(WINDOWS_RUSTYNET_PATH)?))
}

/// Parse the daemon's status response into live identity evidence,
/// mirroring `linux_traffic::query_live_identity`. Missing `node_id=` is a
/// fail-closed error, never a downgrade to a config-file assertion.
fn live_identity_from_status(status: &str) -> Result<IdentityEvidence, AdapterError> {
    match ssh::parse_status_node_id(status) {
        Some(node_id) => Ok(IdentityEvidence::live(node_id)),
        None => Err(AdapterError::Protocol {
            message: format!(
                "live identity challenge: node_id not in rustynet status output: {}",
                status.chars().take(200).collect::<String>()
            ),
        }),
    }
}

/// Ping `peer_mesh_ip` 3 times via `Test-Connection`. Returns `Reachable` on success.
///
/// Uses explicit `exit 0`/`exit 1` because `Test-Connection -Quiet` always
/// exits with code 0 regardless of result. On failure the error output is
/// captured so the stage log carries diagnostic detail (exception message
/// vs no-response) instead of a bare "Test-Connection to X returned false".
pub fn ping_mesh_peer(
    conn: &NodeConnection,
    peer_mesh_ip: &str,
) -> Result<TrafficTestResult, AdapterError> {
    validate_ip_arg(peer_mesh_ip)?;
    let ip_q = ps_quote(peer_mesh_ip)?;
    let script = format!(
        "try {{ \
          if (Test-Connection -ComputerName {ip_q} -Count 3 -Quiet -ErrorAction Stop) {{ exit 0 }} \
          else {{ Write-Output 'no response (Quiet=false)'; exit 1 }} \
         }} catch {{ \
          Write-Output \"$($_.Exception.GetType().Name): $($_.Exception.Message)\"; exit 1 \
         }}"
    );
    match run_remote_ps(conn, &script, Duration::from_secs(30)) {
        Ok(_stdout) => Ok(TrafficTestResult::Reachable),
        Err(AdapterError::Command { stderr, .. }) => Ok(TrafficTestResult::Error(format!(
            "Test-Connection to {peer_mesh_ip} failed: {}",
            stderr.trim()
        ))),
        Err(other) => Err(other),
    }
}

/// Negative ACL test: confirm `denied_ip` is blocked. Expects connection failure.
/// Returns `Blocked` when ping fails (as expected), `Reachable` on security failure.
///
/// Uses explicit `exit 0`/`exit 1` — see `ping_mesh_peer` for rationale.
pub fn probe_denied_peer(
    conn: &NodeConnection,
    denied_ip: &str,
) -> Result<TrafficTestResult, AdapterError> {
    validate_ip_arg(denied_ip)?;
    // Exit 0 when the target IS reachable (security violation) so
    // run_remote_ps_check returns true → Reachable.
    // Exit 1 when blocked (expected) → false → Blocked.
    let script = format!(
        "if (Test-Connection -ComputerName {ip_q} -Count 1 -Quiet -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}",
        ip_q = ps_quote(denied_ip)?
    );
    match run_remote_ps_check(conn, &script, Duration::from_secs(10))? {
        true => Ok(TrafficTestResult::Reachable), // reached denied target = security failure
        false => Ok(TrafficTestResult::Blocked),  // blocked as expected
    }
}

/// Collect active `WireGuard` tunnels via `wg.exe show all latest-handshakes`.
///
/// The Windows backend is WireGuard-NT (a kernel driver), so `wg.exe show`
/// queries the live tunnel directly. `wireguard.exe /show` is NOT a valid
/// command (it exits 64), which previously made this always report zero tunnels
/// and fail `role_switch_matrix` even with a live, traffic-carrying tunnel.
/// `show all latest-handshakes` emits one tab-separated
/// `<iface>\t<pubkey>\t<unix-ts>` line per programmed peer, matching the Linux
/// adapter's active-tunnel semantics (one line per peer tunnel).
pub fn collect_active_tunnels(conn: &NodeConnection) -> Result<TunnelsList, AdapterError> {
    let script = "$wg = 'C:\\Program Files\\WireGuard\\wg.exe'; \
         if (-not (Test-Path -LiteralPath $wg)) { \
             $cmd = Get-Command 'wg.exe' -ErrorAction SilentlyContinue; \
             if ($cmd) { $wg = $cmd.Source } \
         }; \
         if (Test-Path -LiteralPath $wg) { & $wg show all latest-handshakes } \
         else { Write-Output 'wg-not-installed' }";
    let output = run_remote_ps(conn, script, SHORT_TIMEOUT)?;
    let tunnels: Vec<String> = output
        .lines()
        .filter(|line| !line.is_empty() && !line.contains("wg-not-installed"))
        .map(std::string::ToString::to_string)
        .collect();
    Ok(TunnelsList { tunnels })
}

/// Activate full-tunnel exit-serving on the Windows exit: send
/// `route advertise 0.0.0.0/0` to the live daemon over its control named pipe.
///
/// The daemon's local IPC is a plain-text line over a message-mode named pipe
/// (`as_wire()` is literally `route advertise 0.0.0.0/0`), so a
/// `NamedPipeClientStream` sends it without the full operator CLI — the guest's
/// `rustynet.exe` is only the trust CLI and has no route-advertise command. The
/// `IpcResponse` wire form is `ok|<message>` / `err|<message>`; on rejection the
/// daemon's own reason is surfaced (e.g. a host lacking the WinNAT/HNS stack
/// reports a clear remediation message from the exit preflight).
pub fn activate_exit_serving(conn: &NodeConnection) -> Result<(), AdapterError> {
    let script = "$resp = ''; \
         try { \
             $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'RustyNet\\rustynetd', [System.IO.Pipes.PipeDirection]::InOut); \
             $pipe.Connect(5000); \
             try { $pipe.ReadMode = [System.IO.Pipes.PipeTransmissionMode]::Message } catch {}; \
             $b = [System.Text.Encoding]::ASCII.GetBytes('route advertise 0.0.0.0/0') + [byte]10; \
             $pipe.Write($b, 0, $b.Length); $pipe.Flush(); \
             $buf = New-Object byte[] 8192; $n = $pipe.Read($buf, 0, 8192); \
             $resp = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n).Trim(); \
             $pipe.Dispose() \
         } catch { $resp = 'PIPE_ERR: ' + $_.Exception.Message }; \
         Write-Output $resp";
    let resp = run_remote_ps(conn, script, SHORT_TIMEOUT)?;
    let resp = resp.trim();
    if resp.strip_prefix("ok|").is_some() {
        Ok(())
    } else if let Some(reason) = resp.strip_prefix("err|") {
        Err(AdapterError::Protocol {
            message: format!(
                "daemon rejected exit-serving route advertisement: {}",
                reason.trim()
            ),
        })
    } else {
        Err(AdapterError::Protocol {
            message: format!("unexpected route-advertise response from daemon: {resp}"),
        })
    }
}

/// Assert the Windows exit is ACTIVELY serving as a full-tunnel exit: IPv4
/// forwarding `Enabled` on the tunnel adapter (`rustynet0`) AND a RustyNet NAT
/// instance present. Proves the dataplane actually NATs client mesh traffic, not
/// merely that the exit role is held.
pub fn assert_exit_actively_serving(conn: &NodeConnection) -> Result<(), AdapterError> {
    let script = "$ErrorActionPreference = 'SilentlyContinue'; \
         $fwd = @(Get-NetIPInterface -AddressFamily IPv4 | Where-Object { $_.Forwarding -eq 'Enabled' } | ForEach-Object { $_.InterfaceAlias }); \
         $nat = @(Get-NetNat | Where-Object { $_.Name -like '*rusty*' }); \
         if ($fwd -notcontains 'rustynet0') { Write-Output 'FAIL: rustynet0 IPv4 forwarding is not Enabled' } \
         elseif ($nat.Count -lt 1) { Write-Output 'FAIL: no RustyNet NAT instance present' } \
         else { Write-Output ('OK forwarding=[' + ($fwd -join ',') + '] nat=' + $nat[0].Name) }";
    let out = run_remote_ps(conn, script, SHORT_TIMEOUT)?;
    let out = out.trim();
    if out.starts_with("OK") {
        Ok(())
    } else {
        Err(AdapterError::Protocol {
            message: format!("Windows exit is not actively serving as a full-tunnel exit: {out}"),
        })
    }
}

/// On the Windows exit, assert that THIS exit's WinNAT is translating a
/// mesh-range (`100.64.0.0/10`, i.e. first octet 100, second 64–127) source
/// address outbound, and return the concrete observed pair as evidence (QH-25).
/// Retries internally to cover the client's full-tunnel convergence + the probe
/// window.
///
/// Scope of the claim — stated precisely:
/// * It IS this exit's NAT: `Get-NetNatSession` is queried on the exit host, so
///   a translating session here means traffic egressed through this node.
/// * **Identity check when `expected_client_mesh_addr` is supplied** (QH-25):
///   only a session whose `InternalSourceAddress` equals that address is
///   accepted, which proves THE probed client's traffic egressed here. A
///   mesh-range session from a different client is rejected and the retry loop
///   keeps waiting.
/// * Without an expected address it remains a **range check, not an identity
///   check**: any source in `100.64.0.0/10` satisfies it, so it does not
///   establish *which* peer's traffic egressed. With exactly one non-exit node
///   it is unambiguous; beyond that, treat it as "a mesh peer egressed here".
/// * It does not distinguish a session created by the stage's own probe from a
///   pre-existing one, so it is evidence of NAT translation being live rather
///   than of the probe specifically having caused it.
///
/// The success output carries the concrete pair
/// (`OK nat_session <internal> -> <external>`), parsed in Rust and returned as
/// the evidence — not a bare verdict.
pub fn assert_mesh_client_nat_session(
    conn: &NodeConnection,
    expected_client_mesh_addr: Option<&str>,
) -> Result<MeshClientNatSession, AdapterError> {
    let script = "$found = $false; $seen = ''; \
         for ($i = 0; $i -lt 10 -and -not $found; $i++) { \
             $s = @(Get-NetNatSession -EA SilentlyContinue | Where-Object { \
                 $p = $_.InternalSourceAddress.Split('.'); \
                 ($p.Count -eq 4) -and ([int]$p[0] -eq 100) -and ([int]$p[1] -ge 64) -and ([int]$p[1] -le 127) }); \
             if ($s.Count -ge 1) { $found = $true; $seen = $s[0].InternalSourceAddress + ' -> ' + $s[0].ExternalDestinationAddress } \
             else { Start-Sleep -Milliseconds 1500 } \
         }; \
         if ($found) { Write-Output ('OK nat_session ' + $seen) } \
         else { Write-Output 'FAIL: no WinNAT session translating a mesh-sourced (100.64.0.0/10) client address' }";
    // The expected client mesh address is deliberately applied in Rust, not
    // interpolated into the script: the range filter stays a fixed literal (no
    // injection surface) and the identity match re-uses the same parsed pair.
    let mut last_out = String::new();
    for attempt in 0..10 {
        let out = run_remote_ps(conn, script, MEDIUM_TIMEOUT)?;
        let trimmed = out.trim().to_owned();
        if let Some(session) = parse_winnat_nat_session_line(&trimmed) {
            let identity_matched =
                expected_client_mesh_addr.is_none_or(|expected| session.client_source == expected);
            if identity_matched {
                return Ok(session);
            }
            // A mesh-range session exists but belongs to a different client;
            // keep retrying — the stage's probe traffic may not have converged.
        }
        last_out = trimmed;
        if attempt < 9 {
            std::thread::sleep(Duration::from_millis(1500));
        }
    }
    let message = match (expected_client_mesh_addr, last_out.starts_with("OK")) {
        (Some(expected), true) => format!(
            "Windows exit shows a WinNAT session but not for the expected client mesh address \
             {expected}: {last_out}"
        ),
        _ => format!("Windows exit shows no client-egress NAT session: {last_out}"),
    };
    Err(AdapterError::Protocol { message })
}

/// Parse the success line the inline script prints —
/// `OK nat_session <InternalSourceAddress> -> <ExternalDestinationAddress>` —
/// into the concrete evidence pair. Returns `None` for anything else (the
/// `FAIL:` line, garbage, empty output), so the caller keeps retrying.
fn parse_winnat_nat_session_line(out: &str) -> Option<MeshClientNatSession> {
    let payload = out.lines().find(|l| l.starts_with("OK nat_session "))?;
    let pair = payload.strip_prefix("OK nat_session ")?;
    let (client_source, translated_side) = pair.split_once(" -> ")?;
    if client_source.is_empty() || translated_side.is_empty() {
        return None;
    }
    Some(MeshClientNatSession {
        client_source: client_source.to_owned(),
        translated_side: translated_side.to_owned(),
        observed_via: "winnat",
    })
}

/// Build the remote PowerShell that archives the Windows diagnostic logs,
/// excluding key material.
///
/// Split out of `collect_artifacts` so the generated script is unit-testable
/// without a live `NodeConnection` — the empty-log-directory case below is exactly
/// the one that broke in production, and it was previously unreachable by a test.
fn build_diag_archive_script(remote_zip_path: &str) -> Result<String, AdapterError> {
    // The `@( ... )` around the if/else is load-bearing, not stylistic. Under the
    // `Set-StrictMode -Version Latest` this script sets, reading `.Count` on a value
    // that is not a collection throws `PropertyNotFoundStrict`, and the
    // `Get-ChildItem | Where-Object` pipeline yields `$null` when nothing matches.
    // The `else` branch was already array-safe; the taken branch was not, so a logs
    // directory that existed but held no non-key files aborted the whole collection.
    // That is the worst possible time for it to fail: this runs on the failure path,
    // so it destroyed the diagnostics for the very failure being investigated, and
    // the error then folded into the always-run `cleanup` stage and reported it as
    // failed even though cleanup itself had completed. Observed live on
    // windows-x86-1 in run winnat-20260725T190000Z. The array subexpression forces a
    // collection in every branch, so `.Count` is always valid.
    //
    // The `Add-Type` in the empty branch is the SECOND layer of the same failure,
    // and it only became reachable once the `@( ... )` fix above stopped the throw
    // that had been masking it.
    //
    // The empty branch writes the 22-byte end-of-central-directory record directly
    // rather than going through `[System.IO.Compression.ZipFile]`, and each half of
    // that choice fixes a distinct defect:
    //
    //   * Windows PowerShell 5.1 (Desktop) does not auto-load
    //     `System.IO.Compression.FileSystem`, so naming that type there is
    //     `TypeNotFound`. The previous `$dummy = [System.IO.Compression.ZipFile];`
    //     line was reaching for exactly this and could not work — naming a type does
    //     not load its assembly. `Add-Type` would fix that, but only that, and its
    //     resolution failures are TERMINATING, so `-ErrorAction SilentlyContinue`
    //     does not make it safe; it is inert in both directions. `[System.IO.File]`
    //     lives in the always-loaded core library and needs no load at all.
    //   * `ZipArchiveMode::Create` maps to `FileMode.CreateNew`, which THROWS if the
    //     path already exists. The remote temp zip is deleted best-effort and only
    //     after `scp_from`, so a timed-out download leaves it behind and the next
    //     run's empty branch would abort — destroying diagnostics a second way. The
    //     sibling branch already uses `Compress-Archive -Force`;
    //     `WriteAllBytes` is `FileMode.Create` (truncate), which restores the
    //     symmetry.
    //
    // The bytes are a complete, valid empty archive: signature `PK\x05\x06` followed
    // by 18 zero bytes (disk numbers, entry counts, central-directory size and
    // offset, comment length) — byte-identical to what
    // `ZipFile.Open(.., Create).Dispose()` emits.
    //
    // This branch is not an edge case. Observed live on windows-x86-1 in run
    // winnat-20260727T095740Z, whose ONLY failure was that the daemon never started:
    // it therefore wrote no logs, so the logs directory was empty, so this is the
    // branch that runs on precisely the failures worth collecting.
    //
    // An empty archive is the intended outcome, not a degenerate one — it
    // distinguishes "collection ran, there was nothing to collect" from "collection
    // failed", which is the distinction this whole path exists to make. See
    // `verify_no_key_material_zip` for how that empty listing is recognised; it is
    // NOT free, and getting it wrong is what made the first version of this fix
    // fail to fix anything.
    //
    // The NON-empty branch snapshots each file before archiving, and that is the
    // THIRD distinct layer of this same collection defect. `Compress-Archive`
    // opens each source for reading and does not share write access. Windows
    // PowerShell 5.1 — the runtime the guest actually runs — ships
    // Microsoft.PowerShell.Archive 1.0.x, whose psm1 uses the three-argument
    // `[System.IO.File]::Open($path, Open, Read)`, i.e. `FileShare.None`, which
    // additionally excludes other data-reading handles; pwsh 7 ships 1.2.5 and
    // passes `FileShare.Read` explicitly. That difference is not what breaks
    // this, though: `rustynetd` holds an open WRITE handle on its own
    // `rustynetd.log` for the life of the process, and neither mode shares
    // write access, so the archive failed under either with
    // `CompressArchiveUnauthorizedAccessError` / "because it is being used by
    // another process". Observed live on windows-x86-1 in run
    // winnat-20260727T144642Z — the FIRST run in which the daemon started and
    // wrote logs at all, which is why this layer stayed invisible until the two
    // beneath it were fixed.
    //
    // Copying through `[System.IO.File]::Open(..., FileShare::ReadWrite)` is what
    // makes the read possible while the writer keeps its handle. Stopping the
    // daemon first would also work and is wrong: this runs on the failure path,
    // and tearing the process down destroys the state under investigation.
    //
    // Per-file failures are collected rather than thrown. One unreadable file must
    // not cost the operator every other file — the same lesson as the per-node
    // loop in `diagnostics.rs`. They are not silently dropped either: names and
    // reasons go into `COLLECTION-ERRORS.txt` inside the archive, so a partial
    // collection announces itself in the artifact instead of looking complete.
    //
    // TOTAL failure throws, though, and the distinction is the point. If every
    // copy fails — a full staging volume, an ACL denial, AV holding the tree —
    // the manifest would be the archive's only entry, `Compress-Archive` would
    // succeed, and the caller would report "collected artifacts into ..." for an
    // archive containing nothing but an explanation nobody opens. A first version
    // of this change did exactly that, turning what used to be a loud failure
    // into a silent one. Errors have to reach the operator through the adapter,
    // not through an artifact whose existence already reads as success.
    Ok(format!(
        "Set-StrictMode -Version Latest; \
         $ErrorActionPreference = 'Stop'; \
         $ProgressPreference = 'SilentlyContinue'; \
         $stagingDir = {staging_q}; \
         if (-not (Test-Path -LiteralPath $stagingDir)) {{ \
             New-Item -ItemType Directory -Force -Path $stagingDir | Out-Null \
         }}; \
         $logsDir = {logs_dir_q}; \
         $zipPath = {zip_q}; \
         $filesToArchive = @(if (Test-Path -LiteralPath $logsDir) {{ \
             Get-ChildItem -Path $logsDir -Recurse -File | \
                 Where-Object {{ $_.FullName -notlike {keys_pattern_q} }} \
         }} else {{ @() }}); \
         if ($filesToArchive.Count -gt 0) {{ \
             $snapshotDir = Join-Path $stagingDir 'rn_diag_snapshot'; \
             if (Test-Path -LiteralPath $snapshotDir) {{ \
                 Remove-Item -LiteralPath $snapshotDir -Recurse -Force \
             }}; \
             New-Item -ItemType Directory -Force -Path $snapshotDir | Out-Null; \
             $rootLen = $logsDir.TrimEnd('\\').Length + 1; \
             $copyErrors = @(); \
             foreach ($src in $filesToArchive) {{ \
                 try {{ \
                     $rel = $src.FullName.Substring($rootLen); \
                     $dest = Join-Path $snapshotDir $rel; \
                     $destParent = Split-Path -Parent $dest; \
                     if (-not (Test-Path -LiteralPath $destParent)) {{ \
                         New-Item -ItemType Directory -Force -Path $destParent | Out-Null \
                     }}; \
                     $in = [System.IO.File]::Open($src.FullName, \
                         [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, \
                         [System.IO.FileShare]::ReadWrite); \
                     try {{ \
                         $out = [System.IO.File]::Create($dest); \
                         try {{ $in.CopyTo($out) }} finally {{ $out.Dispose() }} \
                     }} finally {{ $in.Dispose() }} \
                 }} catch {{ \
                     $copyErrors += ($src.FullName + ': ' + $_.Exception.Message) \
                 }} \
             }}; \
             if ($copyErrors.Count -eq $filesToArchive.Count) {{ \
                 throw ('diagnostics collection copied 0 of ' + \
                     $filesToArchive.Count + ' files: ' + ($copyErrors -join '; ')) \
             }}; \
             if ($copyErrors.Count -gt 0) {{ \
                 Set-Content -LiteralPath (Join-Path $snapshotDir 'COLLECTION-ERRORS.txt') \
                     -Value $copyErrors -Encoding utf8 \
             }}; \
             Compress-Archive -Path (Join-Path $snapshotDir '*') \
                 -DestinationPath $zipPath -Force; \
             Remove-Item -LiteralPath $snapshotDir -Recurse -Force \
         }} else {{ \
             [System.IO.File]::WriteAllBytes($zipPath, {empty_zip_literal}) \
         }}",
        staging_q = ps_quote(WINDOWS_STAGING_DIR)?,
        logs_dir_q = ps_quote(&format!(r"{WINDOWS_STATE_ROOT}\logs"))?,
        zip_q = ps_quote(remote_zip_path)?,
        keys_pattern_q = ps_quote(&format!(r"{WINDOWS_STATE_ROOT}\keys\*"))?,
        empty_zip_literal = empty_artifact_archive_ps_literal(),
    ))
}

/// Collect diagnostic artifacts from the Windows host to `dst`.
/// Key material paths (`keys\*`, `*.priv`, `*.pem`, `*.key`) MUST NOT appear in
/// the collected set.
///
/// **This matches entry NAMES, not content, and is a second line rather than the
/// control.** What decides inclusion is the ARCHIVE ROOT: the collector
/// enumerates `<state root>\logs` only, and `<state root>\keys` is its sibling,
/// so key material is never a candidate in the first place.
///
/// Note the `-notlike '<state root>\keys\*'` filter in that enumeration is
/// therefore inert today — no `FullName` under `\logs` can match a `\keys\`
/// pattern, and deleting it would change nothing. Keep it as a guard against a
/// future widening of the root, but do not mistake it for the control. This
/// check re-reads the index of what came back.
///
/// So it does not, and is not able to, stop key material carried under a benign
/// name: an entry called `rustynetd.log` whose CONTENT is a private key lists
/// cleanly and passes. Closing that would mean scanning archive content, which
/// needs a definition of "key material" and has its own false-positive cost;
/// it is tracked separately rather than implied here. Read this as "no
/// key-shaped PATH escaped the archiver", which is what it actually proves.
pub fn collect_artifacts(conn: &NodeConnection, dst: &Path) -> Result<(), AdapterError> {
    let remote_tmp = format!(r"{WINDOWS_STAGING_DIR}\rn_diag_artifacts.zip");
    let remote_tmp_ps = remote_tmp.replace('\\', "/");

    // Create archive on remote, excluding keys directory.
    let diag_script = build_diag_archive_script(remote_tmp.as_str())?;
    run_remote_ps(conn, &diag_script, MEDIUM_TIMEOUT)?;

    // Download the archive.
    if let Some(parent) = dst.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|err| AdapterError::Io {
            message: format!("create local artifact destination dir failed: {err}"),
        })?;
    }
    ssh::scp_from(conn, &remote_tmp_ps, dst, Duration::from_secs(120))?;

    // Remove temp archive from remote (best-effort).
    let cleanup_script = format!(
        "Remove-Item -LiteralPath {} -Force -ErrorAction SilentlyContinue",
        ps_quote(&remote_tmp)?
    );
    let _ = run_remote_ps(conn, &cleanup_script, SHORT_TIMEOUT);

    // Verify no key material in the collected archive.
    verify_no_key_material_zip(dst)?;

    Ok(())
}

/// Build the best-effort PowerShell that clears leftover RustyNet dataplane
/// artifacts before a fresh bootstrap on a node a prior run left dirty: the
/// killswitch firewall rules, the DNS fail-closed NRPT catch-all, and managed
/// adapter-DNS overrides. Idempotent (absent artifacts are a no-op) and
/// fail-safe — it first restores the default-allow outbound firewall policy so a
/// leftover killswitch can never leave the node with egress blocked (which would
/// break the next bootstrap's cargo registry downloads). Rule names mirror the
/// reviewed contract in rustynetd `phase10` (`WINDOWS_KS_RULE_*` /
/// `WINDOWS_DNS_RULE_*`); the NRPT match targets the DNS fail-closed rule that
/// points the root namespace at the loopback resolver (`windows_dns_failclosed`).
fn windows_dataplane_reset_script() -> String {
    const RUSTYNET_FIREWALL_RULES: [&str; 6] = [
        "RustyNetKS-AllowLoopback",
        "RustyNetKS-AllowTunnel",
        "RustyNetKS-AllowEgress",
        "RustyNetDNS-BlockLanUdp",
        "RustyNetDNS-BlockLanTcp",
        "RustyNetKS-BlockIpv6Lan",
    ];
    let delete_rules = RUSTYNET_FIREWALL_RULES
        .iter()
        .map(|name| {
            format!("& netsh advfirewall firewall delete rule name=\"{name}\" 2>$null | Out-Null;")
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "$ErrorActionPreference = 'Continue'; \
         $ProgressPreference = 'SilentlyContinue'; \
         & netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound 2>$null | Out-Null; \
         {delete_rules} \
         try {{ Get-DnsClientNrptRule -ErrorAction SilentlyContinue \
             | Where-Object {{ ($_.NameServers -contains '127.0.0.1') -or ($_.NameServers -contains '::1') }} \
             | ForEach-Object {{ Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction SilentlyContinue }} }} catch {{ }}; \
         try {{ Get-NetAdapter -Physical -ErrorAction SilentlyContinue \
             | Where-Object {{ $_.Status -eq 'Up' }} \
             | ForEach-Object {{ & netsh interface ipv4 set dnsservers name=\"$($_.Name)\" source=dhcp 2>$null | Out-Null }} }} catch {{ }}; \
         exit 0"
    )
}

/// Build the remote PowerShell that removes runtime state files, leaving the
/// installation and keys intact.
///
/// Split out of `cleanup_runtime_state` (QH-24) so the generated script is
/// unit-testable without a live `NodeConnection`: the exact file list — every
/// membership/trust state file INCLUDING its anti-replay watermark — is what
/// makes the next bootstrap start from a clean trust state. A list entry that
/// silently disappears (a rename, a refactor) would leave stale signed state
/// behind, which the next bootstrap could then replay or trip over. Pinned by
/// `runtime_state_cleanup_script_removes_every_state_file_including_watermarks`.
fn build_runtime_state_cleanup_script() -> Result<String, AdapterError> {
    // Best-effort: mirrors the Linux `rm -rf … 2>/dev/null; true` pattern. We
    // deliberately do not enable Set-StrictMode here — the cleanup target list is
    // allowed to contain paths that do not exist on a fresh box, and any other
    // anomaly should not cascade-fail subsequent stages whose preconditions
    // are independent of cleanup (e.g. install).
    Ok(format!(
        "$ErrorActionPreference = 'Continue'; \
         $ProgressPreference = 'SilentlyContinue'; \
         $stateRoot = {state_root_q}; \
         $toRemove = @( \
             (Join-Path $stateRoot 'membership\\membership.snapshot'), \
             (Join-Path $stateRoot 'membership\\membership.log'), \
             (Join-Path $stateRoot 'membership\\membership.watermark'), \
             (Join-Path $stateRoot 'rustynetd.state'), \
             (Join-Path $stateRoot 'trust\\rustynetd.assignment'), \
             (Join-Path $stateRoot 'trust\\rustynetd.assignment.watermark'), \
             (Join-Path $stateRoot 'trust\\rustynetd.traversal'), \
             (Join-Path $stateRoot 'trust\\rustynetd.traversal.watermark'), \
             (Join-Path $stateRoot 'trust\\rustynetd.dns-zone'), \
             (Join-Path $stateRoot 'trust\\rustynetd.dns-zone.watermark') \
         ); \
         foreach ($f in $toRemove) {{ \
             try {{ Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }} catch {{ }} \
         }}; \
         try {{ Remove-Item -Path {staging_q} -Recurse -Force -ErrorAction SilentlyContinue }} catch {{ }}; \
         exit 0",
        state_root_q = ps_quote(WINDOWS_STATE_ROOT)?,
        staging_q = ps_quote(WINDOWS_STAGING_DIR)?
    ))
}

/// Remove runtime state files, leaving the installation intact.
pub fn cleanup_runtime_state(conn: &NodeConnection) -> Result<(), AdapterError> {
    // Stop the daemon service first (best-effort).
    let stop_script = format!(
        "Stop-Service -Name {} -Force -ErrorAction SilentlyContinue",
        ps_quote(WINDOWS_SERVICE_NAME)?
    );
    let _ = run_remote_ps(conn, &stop_script, SHORT_TIMEOUT);

    // Stop the relay sibling service too (best-effort; absent on a node that
    // was never elected Relay). Without this, a still-running RustyNetRelay
    // from a prior run holds `rustynet-relay.exe` open and the next
    // bootstrap's binary overwrite fails with "The process cannot access
    // the file ... because it is being used by another process." — live-lab
    // evidence: this reached a real re-run of the guest and failed
    // bootstrap_hosts on the very next attempt after a relay was deployed.
    let stop_relay_script = format!(
        "Stop-Service -Name {} -Force -ErrorAction SilentlyContinue",
        ps_quote(WINDOWS_RELAY_SERVICE_NAME)?
    );
    let _ = run_remote_ps(conn, &stop_relay_script, SHORT_TIMEOUT);

    // Best-effort reset of leftover RustyNet dataplane artifacts (killswitch
    // firewall rules + default-deny outbound policy, the DNS fail-closed NRPT
    // catch-all, and managed adapter-DNS overrides). Without this a prior run's
    // killswitch/managed-DNS state blocks the next bootstrap's DNS resolution and
    // cargo downloads. Non-fatal + idempotent: a clean node is a no-op.
    let _ = run_remote_ps(conn, &windows_dataplane_reset_script(), SHORT_TIMEOUT);

    let cleanup_script = build_runtime_state_cleanup_script()?;
    run_remote_ps(conn, &cleanup_script, SHORT_TIMEOUT)?;
    Ok(())
}

/// Best-effort: the Windows daemon's own fail-closed/startup reason, read from
/// `rustynetd.log`, so an enforce failure reports the cause rather than only the
/// "WireGuard adapter did not get an IPv4 address within 90s" symptom.
pub fn collect_daemon_failure_reason(
    conn: &NodeConnection,
) -> Result<Option<String>, AdapterError> {
    let log_path = format!(r"{WINDOWS_STATE_ROOT}\logs\rustynetd.log");
    let script = format!(
        "$ErrorActionPreference = 'SilentlyContinue'; \
         if (Test-Path {p}) {{ Get-Content -LiteralPath {p} -Tail 200 }}",
        p = ps_quote(&log_path)?
    );
    let tail = run_remote_ps(conn, &script, SHORT_TIMEOUT)?;
    Ok(crate::vm_lab::orchestrator::adapter::node_adapter::extract_daemon_failure_reason(&tail))
}

/// PowerShell used by [`assert_node_clean`]: emits exactly four space-separated
/// tokens on a single line that [`parse_windows_node_clean_probe`] interprets,
/// the Windows analogue of the Linux/macOS structured clean probe. It covers the
/// four dimensions that break the next bootstrap:
///   `rules=<n>`         count of leftover RustyNet `dir=out` firewall rules
///   `outbound=<allow|block>` default outbound firewall policy posture
///   `service=<running|stopped|absent>` the `RustyNet` Windows service state
///   `relay=<running|stopped|absent>` the relay sibling service state
///   `adapter=<names|->`  leftover RustyNet network adapter name(s), or `-`
///
/// A node is clean only when all five are benign (`rules=0`, `outbound=allow`,
/// both services stopped/absent, `adapter=-`). The service + adapter dimensions
/// close the gap the firewall-only check left: a still-running service re-applies
/// the killswitch and owns the adapter, and a leftover wintun/WireGuard adapter
/// named `rustynet*` collides with the fresh bring-up. Read-only — it mutates
/// nothing, so it is safe to run repeatedly. `WINDOWS_SERVICE_NAME` is
/// interpolated as a compile-time constant (no untrusted value), keeping the
/// command argv-only-safe.
fn windows_node_clean_assert_script() -> String {
    format!(
        "$ErrorActionPreference = 'SilentlyContinue'; \
         $rules = @(& netsh advfirewall firewall show rule name=all dir=out | Select-String 'RustyNet'); \
         $pol = @(& netsh advfirewall show allprofiles | Select-String 'Firewall Policy'); \
         $blocked = @($pol | Where-Object {{ $_ -match 'BlockOutbound' }}); \
         $svc = Get-Service -Name '{WINDOWS_SERVICE_NAME}' -ErrorAction SilentlyContinue; \
         if (-not $svc) {{ $svcState = 'absent' }} \
         elseif ($svc.Status -eq 'Running') {{ $svcState = 'running' }} \
         else {{ $svcState = 'stopped' }}; \
         $relay = Get-Service -Name '{WINDOWS_RELAY_SERVICE_NAME}' -ErrorAction SilentlyContinue; \
         if (-not $relay) {{ $relayState = 'absent' }} \
         elseif ($relay.Status -eq 'Running') {{ $relayState = 'running' }} \
         else {{ $relayState = 'stopped' }}; \
         $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {{ \
             $_.Name -like '*rustynet*' -or $_.InterfaceDescription -like '*rustynet*' }} \
             | ForEach-Object {{ $_.Name }}); \
         $adapterTok = if ($adapters.Count -gt 0) {{ ($adapters -join ',') }} else {{ '-' }}; \
         $outboundTok = if ($blocked.Count -gt 0) {{ 'block' }} else {{ 'allow' }}; \
         Write-Output ('rules=' + $rules.Count + ' outbound=' + $outboundTok + \
             ' service=' + $svcState + ' relay=' + $relayState + ' adapter=' + $adapterTok)"
    )
}

/// Pure parser for [`windows_node_clean_assert_script`] output, the Windows
/// analogue of the Linux/macOS `parse_*_node_clean_probe`. Returns `Ok(())` when
/// the node is verifiably clean (no leftover RustyNet `dir=out` firewall rule,
/// default outbound policy not left blocking, `RustyNet` service stopped/absent,
/// no leftover RustyNet adapter) and a descriptive `node still dirty: …` error
/// listing every dirty dimension otherwise.
///
/// Fail closed: any token that is missing, malformed, or does not explicitly
/// assert the benign value is treated as dirty. A truncated or garbled probe
/// (e.g. WinRM/SSH noise prepended) therefore fails the assertion rather than
/// passing a node whose true state is unknown.
fn parse_windows_node_clean_probe(raw: &str) -> Result<(), AdapterError> {
    // The probe prints a single result line; tolerate leading log/banner lines
    // by scanning for the line that carries the five expected tokens.
    let line = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .rev()
        .find(|l| {
            l.contains("rules=")
                && l.contains("outbound=")
                && l.contains("service=")
                && l.contains("relay=")
                && l.contains("adapter=")
        });
    let Some(line) = line else {
        return Err(AdapterError::Protocol {
            message: format!(
                "node still dirty: clean-probe output unrecognised (fail closed): {:?}",
                raw.trim()
            ),
        });
    };

    let mut rules: Option<&str> = None;
    let mut outbound: Option<&str> = None;
    let mut service: Option<&str> = None;
    let mut relay: Option<&str> = None;
    let mut adapter: Option<&str> = None;
    for tok in line.split_whitespace() {
        if let Some(v) = tok.strip_prefix("rules=") {
            rules = Some(v);
        } else if let Some(v) = tok.strip_prefix("outbound=") {
            outbound = Some(v);
        } else if let Some(v) = tok.strip_prefix("service=") {
            service = Some(v);
        } else if let Some(v) = tok.strip_prefix("relay=") {
            relay = Some(v);
        } else if let Some(v) = tok.strip_prefix("adapter=") {
            adapter = Some(v);
        }
    }

    let mut dirty: Vec<String> = Vec::new();
    // `rules=<n>`: only `0` is benign; a non-zero count or an unparseable value
    // (unknown) is dirty.
    match rules.map(|v| v.trim().parse::<u32>()) {
        Some(Ok(0)) => {}
        Some(Ok(n)) => dirty.push(format!("{n} leftover RustyNet firewall rule(s)")),
        _ => dirty.push("firewall-rule status unknown (probe token missing/garbled)".to_owned()),
    }
    match outbound.map(str::trim) {
        Some("allow") => {}
        Some("block") => dirty.push("default outbound policy left blocking".to_owned()),
        _ => dirty.push("outbound-policy status unknown (probe token missing)".to_owned()),
    }
    match service.map(str::trim) {
        Some("stopped") | Some("absent") => {}
        Some("running") => dirty.push("RustyNet service still running".to_owned()),
        _ => dirty.push("service status unknown (probe token missing)".to_owned()),
    }
    match relay.map(str::trim) {
        Some("stopped") | Some("absent") => {}
        Some("running") => dirty.push("RustyNet relay service still running".to_owned()),
        _ => dirty.push("relay-service status unknown (probe token missing)".to_owned()),
    }
    // `-` (or empty) is the benign "no leftover adapter" sentinel; any other
    // value is a comma-joined list of leftover adapter names. A missing token is
    // unknown → dirty (fail closed).
    match adapter.map(|v| v.trim().trim_end_matches(',')) {
        Some("-") | Some("") => {}
        Some(s) => dirty.push(format!("RustyNet adapter(s): {s}")),
        None => dirty.push("adapter status unknown (probe token missing)".to_owned()),
    }

    if dirty.is_empty() {
        Ok(())
    } else {
        Err(AdapterError::Protocol {
            message: format!("node still dirty after cleanup: {}", dirty.join("; ")),
        })
    }
}

/// After cleanup, assert the node is verifiably clean across all five dimensions
/// that break the next bootstrap, mirroring the Linux/macOS `assert_node_clean`:
/// no leftover RustyNet `dir=out` killswitch firewall rule, the default outbound
/// policy not left blocking (a residual default-block-outbound killswitch starves
/// the next bootstrap), the `RustyNet` service stopped/absent (a running service
/// re-applies the killswitch and owns the adapter), and no leftover RustyNet
/// network adapter (a stale wintun/WireGuard adapter collides with the fresh
/// bring-up). Fails loudly so a reset that did not take is caught here, not as a
/// cargo DNS timeout five stages later.
pub fn assert_node_clean(conn: &NodeConnection) -> Result<(), AdapterError> {
    let out = run_remote_ps(conn, &windows_node_clean_assert_script(), SHORT_TIMEOUT)?;
    parse_windows_node_clean_probe(&out)
}

/// Verify SSH/PS connectivity by running a no-op command.
pub fn check_ssh_reachable(conn: &NodeConnection) -> Result<(), AdapterError> {
    run_remote_ps(conn, "Write-Host 'reachable'", Duration::from_secs(10))?;
    Ok(())
}

/// Collect the `WireGuard` mesh IP from the running network interface.
///
/// Queries `Get-NetAdapter` for an interface named or described as `rustynet*`
/// and returns its first IPv4 address.  Returns an error if the interface is
/// absent or has no assigned IP (e.g. service not yet started).
///
/// Callers that need retry behaviour (e.g. `traffic_test_matrix` when the
/// interface may have just come up) should implement the retry loop themselves.
pub fn collect_mesh_ip(conn: &NodeConnection) -> Result<String, AdapterError> {
    let iface_script = "$iface = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*rustynet*' -or $_.Name -like '*rustynet*' } | Select-Object -First 1; \
         if ($iface) { (Get-NetIPAddress -InterfaceIndex $iface.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress } else { '' }";
    let ip = run_remote_ps(conn, iface_script, SHORT_TIMEOUT)?;
    let ip = ip.trim().to_owned();
    if ip.is_empty() {
        return Err(AdapterError::Protocol {
            message: "mesh IP not found on rustynet* network interface (service not running or WireGuard tunnel not up)".to_owned(),
        });
    }
    Ok(ip)
}

/// Issue signed bundles on this (Windows) exit node and SCP results to `local_out_dir`.
pub fn issue_bundles_to_dir(
    conn: &NodeConnection,
    rustynet_path: &str,
    kind: &crate::vm_lab::orchestrator::error::BundleKind,
    env_content: &str,
    local_out_dir: &std::path::Path,
) -> Result<(), AdapterError> {
    use crate::vm_lab::orchestrator::adapter::windows_install::{ps_quote, WINDOWS_STAGING_DIR};
    use std::io::Write as IoWrite;
    let pid = std::process::id();
    let remote_env = format!(r"{WINDOWS_STAGING_DIR}\rn_issue_env_{pid}.env");
    let remote_issue_dir = format!(r"{WINDOWS_STAGING_DIR}\rn_issue_{pid}");

    let issue_subcmd = match kind {
        crate::vm_lab::orchestrator::error::BundleKind::Assignment => {
            "e2e-issue-assignment-bundles-from-env"
        }
        crate::vm_lab::orchestrator::error::BundleKind::Traversal => {
            "e2e-issue-traversal-bundles-from-env"
        }
        crate::vm_lab::orchestrator::error::BundleKind::DnsZone => {
            "e2e-issue-dns-zone-bundles-from-env"
        }
        crate::vm_lab::orchestrator::error::BundleKind::Membership => {
            return Err(AdapterError::Protocol {
                message: "Membership bundles are issued via init_membership_snapshot".to_owned(),
            });
        }
    };

    let mut env_tmp = std::env::temp_dir();
    env_tmp.push(format!("rn_issue_env_{pid}.env"));
    {
        let mut f = std::fs::File::create(&env_tmp).map_err(|e| AdapterError::Io {
            message: format!("create env tmp: {e}"),
        })?;
        f.write_all(env_content.as_bytes())
            .map_err(|e| AdapterError::Io {
                message: format!("write env tmp: {e}"),
            })?;
    }
    ssh::scp_to(
        conn,
        &env_tmp,
        &remote_env.replace('\\', "/"),
        MEDIUM_TIMEOUT,
    )?;
    let _ = std::fs::remove_file(&env_tmp);

    let ensure_script = format!(
        "New-Item -ItemType Directory -Force -Path {} | Out-Null; \
         New-Item -ItemType Directory -Force -Path {} | Out-Null",
        ps_quote(WINDOWS_STAGING_DIR)?,
        ps_quote(&remote_issue_dir)?,
    );
    run_remote_ps(conn, &ensure_script, SHORT_TIMEOUT)?;

    let run_script = format!(
        "$env:RUSTYNET_NODE_ROLE = 'admin'; \
         & {rustynet_q} ops {issue_subcmd} \
             --env-file {env_q} --issue-dir {issue_dir_q}; \
         if ($LASTEXITCODE -ne 0) {{ throw '{issue_subcmd} failed with exit code ' + $LASTEXITCODE }}",
        rustynet_q = ps_quote(rustynet_path)?,
        issue_subcmd = issue_subcmd,
        env_q = ps_quote(&remote_env)?,
        issue_dir_q = ps_quote(&remote_issue_dir)?,
    );
    run_remote_ps(conn, &run_script, MEDIUM_TIMEOUT)?;

    let list_script = format!(
        "Get-ChildItem -Path {} | Select-Object -ExpandProperty Name",
        ps_quote(&remote_issue_dir)?
    );
    let listing = run_remote_ps(conn, &list_script, SHORT_TIMEOUT)?;

    std::fs::create_dir_all(local_out_dir).map_err(|e| AdapterError::Io {
        message: format!("create local out dir: {e}"),
    })?;

    for filename in listing.lines().map(str::trim).filter(|s| !s.is_empty()) {
        let remote_path = format!("{remote_issue_dir}\\{filename}");
        let local_path = local_out_dir.join(filename);
        ssh::scp_from(
            conn,
            &remote_path.replace('\\', "/"),
            &local_path,
            MEDIUM_TIMEOUT,
        )?;
    }

    let cleanup_script = format!(
        "Remove-Item -LiteralPath {env_q} -Force -ErrorAction SilentlyContinue; \
         Remove-Item -LiteralPath {dir_q} -Recurse -Force -ErrorAction SilentlyContinue",
        env_q = ps_quote(&remote_env)?,
        dir_q = ps_quote(&remote_issue_dir)?,
    );
    let _ = run_remote_ps(conn, &cleanup_script, SHORT_TIMEOUT);

    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Validate that an IP address argument contains no shell-dangerous characters.
fn validate_ip_arg(ip: &str) -> Result<(), AdapterError> {
    if ip
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '/'))
    {
        Ok(())
    } else {
        Err(AdapterError::Protocol {
            message: format!(
                "IP argument '{ip}' contains characters not safe for shell embedding \
                 (allowed: alphanumeric, '.', ':', '/')"
            ),
        })
    }
}

fn decode_wireguard_pubkey_to_hex(value: &str) -> Result<String, String> {
    let decoded = base64_decode_simple(value.as_bytes())
        .map_err(|err| format!("base64 decode of WireGuard public key failed: {err}"))?;
    if decoded.len() != 32 {
        return Err(format!(
            "expected 32-byte WireGuard public key, got {} bytes",
            decoded.len()
        ));
    }
    let mut out = String::with_capacity(64);
    for byte in decoded {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

/// Minimal base64 decode (standard alphabet A-Z a-z 0-9 + /).
fn base64_decode_simple(encoded: &[u8]) -> Result<Vec<u8>, String> {
    let filtered: Vec<u8> = encoded
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if filtered.is_empty() {
        return Err("empty base64 input".to_owned());
    }
    let mut table = [255u8; 256];
    for (i, ch) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .iter()
        .enumerate()
    {
        table[*ch as usize] = i as u8;
    }
    table[b'=' as usize] = 64;

    let mut output = Vec::with_capacity((filtered.len() * 3) / 4);
    let mut i = 0;
    while i + 3 < filtered.len() {
        let a = table[filtered[i] as usize];
        let b = table[filtered[i + 1] as usize];
        let c = table[filtered[i + 2] as usize];
        let d = table[filtered[i + 3] as usize];
        if a == 255 || b == 255 {
            return Err(format!("invalid base64 character at position {i}"));
        }
        output.push((a << 2) | (b >> 4));
        if c != 64 {
            output.push(((b & 0xf) << 4) | (c >> 2));
        }
        if d != 64 {
            output.push(((c & 0x3) << 6) | d);
        }
        i += 4;
    }
    Ok(output)
}

/// Assert that the collected artifact zip at `path` contains no key material.
/// Key material patterns: paths containing `keys\` or `keys/`, or ending with
/// `.priv`, `.pem` or `.key`. (`.pem` and `.key` have been matched since
/// 76df3c43; this line said `.priv` alone until 2026-07-27.)
fn verify_no_key_material_zip(path: &Path) -> Result<(), AdapterError> {
    use std::process::Command;
    // Use `unzip -Z -1` to list entries; fall back to `python3 -c` if unzip absent.
    let output = Command::new("unzip")
        .args(["-Z", "-1"])
        .arg(path.as_os_str())
        .output()
        .or_else(|_| {
            // Fallback: use python3 to list zip entries.
            Command::new("python3")
                .args(["-c", "import sys,zipfile; [print(n) for n in zipfile.ZipFile(sys.argv[1]).namelist()]"])
                .arg(path.as_os_str())
                .output()
        })
        .map_err(|err| AdapterError::Io {
            message: format!("list zip contents failed: {err}"),
        })?;
    if !output.status.success() {
        // Fail closed (parity with the Linux/macOS tar path): a listing we
        // cannot read must NOT silently pass the key-exclusion invariant.
        // The one benign non-zero case is an empty archive — only that is
        // treated as OK; any other failure is a hard error.
        //
        // The empty archive must still be recognised, because it is the NORMAL
        // product of this path: a daemon that never starts writes no logs, so
        // the collector ships the empty archive it was designed to ship, and
        // `unzip` reports that with a non-zero exit. Refusing it destroyed the
        // diagnostics for exactly the failures worth investigating.
        //
        // Recognise it by CONTENT, not by parsing the lister's prose. Three
        // separate holes were found in the prose approach before this one, and
        // the third showed the whole approach is unfixable: `unzip -Z -1` writes
        // its human message `Empty zipfile.` to the SAME stream as entry names,
        // so "the archive is empty" and "the first entry is named like the
        // message" are indistinguishable from stdout text. A guest that corrupts
        // one central-directory signature gets `unzip` to list the parsable
        // prefix and bail — so an archive whose first entry is named
        // `empty zipfile` lists as exactly that, exits non-zero, and its
        // remaining `keys/id.priv` entry is never listed and never scanned. The
        // archive is built ON the guest, so those bytes are attacker-controlled,
        // which is precisely the threat this check exists for.
        //
        // A byte comparison against the archive this collector itself writes has
        // no such ambiguity. Nothing containing key material can equal 22 bytes
        // of end-of-central-directory record.
        //
        // Deliberately NOT a length check and NOT an exit-code gate. A length
        // check admits any 22-byte file; an exit-code gate would couple
        // acceptance to Info-ZIP's warning-vs-error convention, and a lister
        // that reported an empty archive with some other code would fail the
        // genuine case closed — reintroducing the very bug this exists to fix.
        let stderr = String::from_utf8_lossy(&output.stderr);
        if fs::read(path).is_ok_and(|bytes| bytes == EMPTY_ARTIFACT_ARCHIVE) {
            return Ok(());
        }
        return Err(AdapterError::Io {
            message: format!(
                "could not list artifact zip contents (status {}); failing closed on \
                 key-exclusion check: {}",
                output.status,
                stderr.trim()
            ),
        });
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    let entries: Vec<&str> = listing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();

    // A lister that SUCCEEDS but reports zero entries has told us nothing about
    // a file that is not the archive we wrote, so the scan below would iterate
    // over nothing and pass it.
    //
    // This is not hypothetical: the two listers disagree. `unzip` rejects a
    // 22-byte record whose end-of-central-directory bytes are corrupted, but the
    // `python3` fallback's `zipfile` accepts it and yields an empty namelist —
    // so on a host without `unzip` (the Debian CI runner, for one) a corrupted
    // 22-byte file passed the key-exclusion check outright. The archive is built
    // ON the guest, so those bytes are attacker-controlled, which is exactly the
    // threat this function exists for.
    //
    // Only the archive this collector itself writes may pass with no entries,
    // and it is recognised by content, as above.
    if entries.is_empty() && !fs::read(path).is_ok_and(|bytes| bytes == EMPTY_ARTIFACT_ARCHIVE) {
        return Err(AdapterError::Io {
            message: format!(
                "artifact zip {} listed zero entries but is not the empty archive \
                 this collector writes; failing closed on key-exclusion check",
                path.display()
            ),
        });
    }

    for entry in entries {
        let lower = entry.to_lowercase();
        if lower.contains("keys/")
            || lower.contains("keys\\")
            || lower.ends_with(".priv")
            || lower.ends_with(".pem")
            || lower.ends_with(".key")
        {
            return Err(AdapterError::KeyExclusionViolation {
                path: entry.to_owned(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_winnat_nat_session_line_returns_concrete_pair() {
        // QH-25: the OK line parses into the evidence pair, not a bare verdict.
        let session = parse_winnat_nat_session_line("OK nat_session 100.64.0.3 -> 203.0.113.9")
            .expect("OK line must parse");
        assert_eq!(session.client_source, "100.64.0.3");
        assert_eq!(session.translated_side, "203.0.113.9");
        assert_eq!(session.observed_via, "winnat");
    }

    #[test]
    fn parse_winnat_nat_session_line_fails_closed_on_non_ok_output() {
        // The FAIL line from the inline script parses to nothing.
        assert!(parse_winnat_nat_session_line(
            "FAIL: no WinNAT session translating a mesh-sourced (100.64.0.0/10) client address"
        )
        .is_none());
        // Empty / garbage / malformed pair syntax also parse to nothing.
        assert!(parse_winnat_nat_session_line("").is_none());
        assert!(parse_winnat_nat_session_line("garbage").is_none());
        assert!(parse_winnat_nat_session_line("OK nat_session 100.64.0.3").is_none());
        // An empty half of the pair is not evidence.
        assert!(parse_winnat_nat_session_line("OK nat_session  -> 203.0.113.9").is_none());
    }

    /// Regression guard for the QH-21 failure-path defect: under
    /// `Set-StrictMode -Version Latest`, `.Count` on a non-collection throws
    /// `PropertyNotFoundStrict`, and `Get-ChildItem | Where-Object` yields `$null`
    /// when nothing matches. The collection therefore has to force an array in
    /// EVERY branch, not only the `else`. This asserts the array subexpression is
    /// present and wraps the conditional, because losing it silently re-breaks
    /// diagnostics collection precisely on the failure path — where it is needed
    /// most and where nobody notices until they go looking for artifacts that
    /// were never captured.
    #[test]
    fn diag_archive_script_forces_an_array_so_empty_log_dir_cannot_throw() {
        let script = build_diag_archive_script(r"C:\Windows\Temp\rn_diag_artifacts.zip")
            .expect("diag archive script should render");

        // Strict mode is what makes the array wrapper mandatory; if this ever
        // stops being set, the reasoning behind the wrapper changes.
        assert!(
            script.contains("Set-StrictMode -Version Latest"),
            "strict mode is the precondition for the .Count hazard: {script}"
        );
        // The array subexpression must OPEN the assignment...
        assert!(
            script.contains("$filesToArchive = @(if ("),
            "assignment must be wrapped in an array subexpression: {script}"
        );
        // ...and CLOSE after the else branch, so both branches yield a collection.
        // Single braces: `{{`/`}}` is format-string escaping, so the RENDERED
        // script carries single braces. Asserting the doubled form as an
        // alternative would be a disjunct that can never be true, i.e. a test
        // that looks like it tolerates two renderings while only checking one.
        assert!(
            script.contains("} else { @() });"),
            "array subexpression must close after the else branch: {script}"
        );
        // The guarded .Count read is retained (that is what needs to be safe).
        assert!(
            script.contains("if ($filesToArchive.Count -gt 0)"),
            "count-guarded archive branch should remain: {script}"
        );
        // Key material must still be excluded from the collected set.
        assert!(
            script.contains(r"keys\*"),
            "key material exclusion must be preserved: {script}"
        );
    }

    /// The non-empty branch must archive a SNAPSHOT opened with
    /// `FileShare.ReadWrite`, never the live files.
    ///
    /// `Compress-Archive` opens each source for reading without sharing write
    /// access. Windows PowerShell 5.1 ships Microsoft.PowerShell.Archive 1.0.x,
    /// which uses the three-argument `[System.IO.File]::Open(path, Open, Read)`
    /// — i.e. `FileShare.None`; pwsh 7 ships 1.2.5, which passes `FileShare.Read`
    /// explicitly. The guest runs the 5.1 form, and the difference is not what
    /// breaks this: `rustynetd` holds an open WRITE handle on its own
    /// `rustynetd.log`, and neither mode shares write access, so the archive
    /// fails under either. Reproduced on windows-x86-1: archiving the live path
    /// fails with "The process cannot access the file ... because it is being
    /// used by another process", while copying through `FileShare::ReadWrite`
    /// and archiving the copy succeeds.
    ///
    /// This is the third layer of one defect — the empty-dir strict-mode throw,
    /// then the missing compression assembly, now this — and each was invisible
    /// until the one beneath it was fixed. So the assertions below pin the SHAPE:
    /// archiving must read from the snapshot directory, and must not fall back
    /// to the live `FullName` list.
    #[test]
    fn diag_archive_snapshots_locked_files_instead_of_archiving_them_in_place() {
        let script = build_diag_archive_script(r"C:\Windows\Temp\rn_diag_artifacts.zip")
            .expect("diag archive script should render");

        assert!(
            script.contains("[System.IO.FileShare]::ReadWrite"),
            "the copy must permit a concurrent writer, or the daemon's own log is \
             unreadable: {script}"
        );
        // Archive the copy, not the original.
        assert!(
            script.contains("Compress-Archive -Path (Join-Path $snapshotDir '*')"),
            "Compress-Archive must read the snapshot directory: {script}"
        );
        // The old form archived live paths straight out of the enumeration.
        assert!(
            !script.contains("Select-Object -ExpandProperty FullName"),
            "archiving the live file list is exactly what failed on a locked log: \
             {script}"
        );
        // A per-file failure must not abort the whole collection, and must not be
        // silent either.
        assert!(
            script.contains("$copyErrors") && script.contains("COLLECTION-ERRORS.txt"),
            "per-file copy failures must be recorded in the archive rather than \
             thrown or dropped: {script}"
        );
        // TOTAL failure must THROW, not produce a success whose only entry is an
        // explanation. A first version of this change reported success in that
        // case, converting a loud failure into a silent one.
        assert!(
            script.contains("if ($copyErrors.Count -eq $filesToArchive.Count)")
                && script.contains("throw ('diagnostics collection copied 0 of '"),
            "copying zero of N files must fail the collection, not archive an \
             error manifest and report success: {script}"
        );
        // The empty-dir branch is untouched by this.
        assert!(
            script.contains("} else { [System.IO.File]::WriteAllBytes("),
            "the empty branch must still write the bare EOCD: {script}"
        );
    }

    /// The empty-log-dir branch must build the zip WITHOUT loading an assembly,
    /// and must not be able to abort on a leftover file.
    ///
    /// Two production defects live here. Windows PowerShell 5.1 does not
    /// auto-load `System.IO.Compression.FileSystem`, so naming
    /// `[System.IO.Compression.ZipFile]` there raises `TypeNotFound`; and
    /// `ZipArchiveMode::Create` maps to `FileMode.CreateNew`, which throws when
    /// the path already exists — and the remote temp zip is only deleted
    /// best-effort, after `scp_from`. Writing the end-of-central-directory record
    /// through `[System.IO.File]` needs no assembly and truncates.
    ///
    /// This branch is the one taken whenever the daemon failed to start, which is
    /// exactly when diagnostics matter.
    #[test]
    fn diag_archive_empty_branch_writes_a_bare_eocd_without_loading_an_assembly() {
        let script = build_diag_archive_script(r"C:\Windows\Temp\rn_diag_artifacts.zip")
            .expect("diag archive script should render");

        // Asserted as ONE substring anchored to `} else {`, not as two separate
        // `contains` checks. An earlier version checked only that the loader
        // appeared somewhere before the type; moving it into the `if` branch left
        // that test green while restoring the production bug verbatim.
        assert!(
            script.contains("} else { [System.IO.File]::WriteAllBytes("),
            "the empty branch itself must write the archive: {script}"
        );
        // The 22-byte end-of-central-directory record: `PK\x05\x06` + 18 zeros.
        assert!(
            script.contains(&empty_artifact_archive_ps_literal()),
            "empty archive must be rendered from the shared constant: {script}"
        );

        // No assembly load, and no reference to the type that needed one. Both
        // spellings are refused: `Add-Type` cannot be made safe here (its
        // resolution failures are TERMINATING, so `-ErrorAction SilentlyContinue`
        // is inert under this script's `$ErrorActionPreference = 'Stop'`), and the
        // older `$dummy = [...]` line never loaded anything at all.
        assert!(
            !script.contains("Add-Type"),
            "the empty branch must not need an assembly load: {script}"
        );
        assert!(
            !script.contains("System.IO.Compression.ZipFile"),
            "naming that type is what required the load in the first place: {script}"
        );
        // `CreateNew` semantics must not come back: it throws on a leftover zip.
        assert!(
            !script.contains("ZipArchiveMode"),
            "the empty branch must truncate, not refuse to overwrite: {script}"
        );
    }

    /// The empty archive the branch above produces must SURVIVE the key-exclusion
    /// check. This is the assertion that ties the two halves together, and its
    /// absence is why the first attempt at this fix corrected the zip's
    /// construction and still fixed nothing end to end.
    ///
    /// Info-ZIP reports an empty archive as exit 1, stdout `Empty zipfile.`,
    /// stderr EMPTY. The check used to require an empty stdout AND the word
    /// "empty" in stderr, so both halves were false and every empty archive
    /// failed closed — rejecting exactly the artifact the failure path produces.
    ///
    /// Uses the same 22 bytes the rendered script writes, so a change to either
    /// side that breaks the pairing shows up here.
    #[test]
    fn an_empty_artifact_archive_passes_the_key_exclusion_check() {
        let unique = crate::vm_lab::unique_suffix();
        let dir = std::env::temp_dir().join(format!("rustynet-empty-zip-{unique}"));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let empty_zip = dir.join("empty.zip");
        let mut eocd = vec![0x50u8, 0x4B, 0x05, 0x06];
        eocd.extend(std::iter::repeat_n(0u8, 18));
        assert_eq!(eocd.len(), 22, "an EOCD-only archive is exactly 22 bytes");
        std::fs::write(&empty_zip, &eocd).expect("write empty zip");

        verify_no_key_material_zip(&empty_zip)
            .expect("an empty archive carries no key material and must pass");

        // Positive control: a NON-archive must still fail closed, so the widened
        // acceptance above cannot be mistaken for "unreadable listings now pass".
        let junk = dir.join("junk.zip");
        std::fs::write(&junk, b"this is not a zip file at all").expect("write junk");
        assert!(
            verify_no_key_material_zip(&junk).is_err(),
            "an unreadable archive must still fail closed"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The writer and the verifier must agree, byte for byte.
    ///
    /// `verify_no_key_material_zip` accepts a non-zero listing exit only when the
    /// downloaded file EQUALS the archive this collector writes. That is sound
    /// only while both come from one constant — if the script could drift from
    /// the verifier, the verifier would be attesting an archive it no longer
    /// produces, and the empty case would fail closed again.
    #[test]
    fn the_empty_archive_the_script_writes_is_the_one_the_verifier_accepts() {
        assert_eq!(
            EMPTY_ARTIFACT_ARCHIVE.len(),
            22,
            "an end-of-central-directory-only archive is exactly 22 bytes"
        );
        assert_eq!(
            &EMPTY_ARTIFACT_ARCHIVE[..4],
            b"PK\x05\x06",
            "must carry the end-of-central-directory signature"
        );
        assert!(
            EMPTY_ARTIFACT_ARCHIVE[4..].iter().all(|b| *b == 0),
            "the remaining 18 bytes are all zero"
        );
        // Decode the literal back OUT of the rendered script and compare to the
        // constant. Asserting `script.contains(&empty_artifact_archive_ps_literal())`
        // is tautological — both sides come from the same function, so it cannot
        // fail while the script uses the renderer at all. Proven: mutating the
        // renderer to emit 21 bytes instead of 22 left every test in this module
        // green. Decoding catches truncation, reordering, and decimal formatting.
        //
        // The failure mode is fail-CLOSED, not a leak: a script writing bytes the
        // verifier does not accept means the empty archive is rejected again, and
        // diagnostics are lost on exactly the failures worth collecting. That is
        // the original bug, so it is worth a real assertion.
        let script = build_diag_archive_script(r"C:\Windows\Temp\rn_diag_artifacts.zip")
            .expect("diag archive script should render");
        const OPEN: &str = "[byte[]]@(";
        let start = script
            .find(OPEN)
            .expect("byte-array literal must be present");
        let rest = &script[start + OPEN.len()..];
        let end = rest.find(')').expect("byte-array literal must close");
        let decoded: Vec<u8> = rest[..end]
            .split(',')
            .map(|hex| {
                u8::from_str_radix(hex.trim().trim_start_matches("0x"), 16)
                    .unwrap_or_else(|err| panic!("literal must be hex bytes ({hex:?}): {err}"))
            })
            .collect();
        assert_eq!(
            decoded,
            EMPTY_ARTIFACT_ARCHIVE.to_vec(),
            "the bytes the SCRIPT writes must equal the bytes the VERIFIER accepts"
        );
    }

    /// ONLY the exact empty archive may pass a failed listing. Nothing else.
    ///
    /// Three separate holes were found in the previous approach, which parsed
    /// `unzip`'s prose, and the third showed the approach is unfixable:
    /// `unzip -Z -1` writes its human message `Empty zipfile.` to the SAME
    /// stream as entry names. So an archive whose first entry is NAMED
    /// `empty zipfile`, with one central-directory signature corrupted, lists as
    /// exactly that message, exits non-zero, and its remaining `keys/id.priv`
    /// entry is never listed and never scanned. The archive is built on the
    /// guest, so those bytes are attacker-controlled — which is the precise
    /// threat this check exists for.
    ///
    /// Comparing content instead of prose removes the ambiguity: nothing holding
    /// key material can equal 22 bytes of end-of-central-directory record. These
    /// cases assert the boundary is CONTENT, not length and not exit code.
    #[test]
    fn only_the_exact_empty_archive_passes_a_failed_listing() {
        let unique = crate::vm_lab::unique_suffix();
        let dir = std::env::temp_dir().join(format!("rustynet-zip-boundary-{unique}"));
        std::fs::create_dir_all(&dir).expect("temp dir");

        let genuine = dir.join("genuine.zip");
        std::fs::write(&genuine, EMPTY_ARTIFACT_ARCHIVE).expect("write genuine");
        verify_no_key_material_zip(&genuine)
            .expect("the archive this collector writes must be accepted");

        // Same LENGTH, different bytes: a length check would have passed this.
        let impostor = dir.join("impostor.zip");
        let mut wrong = EMPTY_ARTIFACT_ARCHIVE;
        wrong[21] = 0x01;
        std::fs::write(&impostor, wrong).expect("write impostor");
        assert!(
            verify_no_key_material_zip(&impostor).is_err(),
            "a 22-byte file that is not the empty archive must fail closed"
        );

        // An archive whose bytes merely CONTAIN the record still fails: content
        // equality, not a prefix or substring.
        let padded = dir.join("padded.zip");
        let mut longer = EMPTY_ARTIFACT_ARCHIVE.to_vec();
        longer.extend_from_slice(b"keys/id.priv");
        std::fs::write(&padded, &longer).expect("write padded");
        assert!(
            verify_no_key_material_zip(&padded).is_err(),
            "trailing content past the record must fail closed"
        );

        // Unreadable junk still fails closed, as it always did.
        let junk = dir.join("junk.zip");
        std::fs::write(&junk, b"this is not a zip file at all").expect("write junk");
        assert!(
            verify_no_key_material_zip(&junk).is_err(),
            "an unreadable archive must still fail closed"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn windows_node_clean_assert_script_covers_rules_outbound_services_and_adapter() {
        let s = windows_node_clean_assert_script();
        // firewall-rule + outbound-policy dimensions (retained from the original).
        assert!(s.contains("Select-String 'RustyNet'"));
        assert!(s.contains("BlockOutbound"));
        // service dimension: the RustyNet Windows service state.
        assert!(s.contains("Get-Service -Name 'RustyNet'"));
        assert!(s.contains("Get-Service -Name 'RustyNetRelay'"));
        assert!(s.contains("Running"));
        // adapter dimension: a leftover RustyNet network adapter.
        assert!(s.contains("Get-NetAdapter"));
        assert!(s.contains("rustynet"));
        // Emits the four structured tokens the parser keys on.
        assert!(s.contains("'rules=' +"));
        assert!(s.contains("outbound="));
        assert!(s.contains("service="));
        assert!(s.contains("relay="));
        assert!(s.contains("adapter="));
    }

    #[test]
    fn parse_windows_node_clean_probe_accepts_fully_clean_node() {
        assert!(parse_windows_node_clean_probe(
            "rules=0 outbound=allow service=stopped relay=stopped adapter=-\n"
        )
        .is_ok());
        // An absent service is benign (a never-installed / uninstalled node).
        assert!(parse_windows_node_clean_probe(
            "rules=0 outbound=allow service=absent relay=absent adapter=-"
        )
        .is_ok());
        // Tolerates a leading banner/log line before the result line.
        assert!(parse_windows_node_clean_probe(
            "WARNING: blah\nrules=0 outbound=allow service=stopped relay=stopped adapter=-"
        )
        .is_ok());
    }

    #[test]
    fn parse_windows_node_clean_probe_reports_leftover_rules_and_outbound_block() {
        let err = parse_windows_node_clean_probe(
            "rules=3 outbound=allow service=stopped relay=stopped adapter=-",
        )
        .expect_err("leftover firewall rules must fail");
        assert!(err
            .to_string()
            .contains("3 leftover RustyNet firewall rule"));
        let err2 = parse_windows_node_clean_probe(
            "rules=0 outbound=block service=stopped relay=stopped adapter=-",
        )
        .expect_err("blocking outbound policy must fail");
        assert!(err2.to_string().contains("outbound policy left blocking"));
    }

    #[test]
    fn parse_windows_node_clean_probe_reports_running_service() {
        let err = parse_windows_node_clean_probe(
            "rules=0 outbound=allow service=running relay=stopped adapter=-",
        )
        .expect_err("running service must fail");
        assert!(err.to_string().contains("RustyNet service still running"));
    }

    #[test]
    fn parse_windows_node_clean_probe_reports_leftover_adapter() {
        let err = parse_windows_node_clean_probe(
            "rules=0 outbound=allow service=stopped relay=stopped adapter=rustynet0",
        )
        .expect_err("leftover adapter must fail");
        let msg = err.to_string();
        assert!(msg.contains("adapter"));
        assert!(msg.contains("rustynet0"));
    }

    #[test]
    fn parse_windows_node_clean_probe_aggregates_multiple_dirty_dimensions() {
        let err = parse_windows_node_clean_probe(
            "rules=2 outbound=block service=running relay=running adapter=rustynet0",
        )
        .expect_err("multi-dirty must fail");
        let msg = err.to_string();
        assert!(msg.contains("2 leftover RustyNet firewall rule"));
        assert!(msg.contains("outbound policy left blocking"));
        assert!(msg.contains("RustyNet service still running"));
        assert!(msg.contains("RustyNet relay service still running"));
        assert!(msg.contains("rustynet0"));
    }

    #[test]
    fn parse_windows_node_clean_probe_fails_closed_on_unrecognised_output() {
        // No result line at all → unknown state → fail closed, never pass.
        assert!(parse_windows_node_clean_probe("").is_err());
        assert!(parse_windows_node_clean_probe("ssh: connect timed out").is_err());
        // Result line missing a token (e.g. service=) → that dimension is unknown
        // → fail closed rather than assume clean.
        let err = parse_windows_node_clean_probe("rules=0 outbound=allow adapter=-")
            .expect_err("missing service token must fail closed");
        assert!(err.to_string().contains("unrecognised") || err.to_string().contains("unknown"));
        // A garbled (non-numeric) rules count is unknown → dirty, never pass.
        let err2 = parse_windows_node_clean_probe(
            "rules=NaN outbound=allow service=stopped relay=stopped adapter=-",
        )
        .expect_err("garbled rules count must fail closed");
        assert!(err2.to_string().contains("unknown"));
    }

    #[test]
    fn windows_dataplane_reset_script_clears_killswitch_dns_and_nrpt() {
        let s = windows_dataplane_reset_script();
        // Fail-safe: restore default-allow outbound first, so a leftover
        // killswitch can never leave the node with egress blocked.
        assert!(s.contains("firewallpolicy allowinbound,allowoutbound"));
        // Purge every reviewed RustyNet firewall rule (phase10 contract).
        for name in [
            "RustyNetKS-AllowLoopback",
            "RustyNetKS-AllowTunnel",
            "RustyNetKS-AllowEgress",
            "RustyNetDNS-BlockLanUdp",
            "RustyNetDNS-BlockLanTcp",
            "RustyNetKS-BlockIpv6Lan",
        ] {
            assert!(
                s.contains(&format!("delete rule name=\"{name}\"")),
                "reset script missing firewall delete for {name}"
            );
        }
        // Clear the DNS fail-closed NRPT catch-all (root namespace -> loopback).
        assert!(s.contains("Get-DnsClientNrptRule"));
        assert!(s.contains("Remove-DnsClientNrptRule"));
        assert!(s.contains("127.0.0.1"));
        // Reset managed adapter DNS back to DHCP.
        assert!(s.contains("set dnsservers") && s.contains("source=dhcp"));
        // Best-effort: never abort on a clean node.
        assert!(s.contains("$ErrorActionPreference = 'Continue'"));
    }

    /// QH-24 content pin for `cleanup_runtime_state`'s state-removal half:
    /// every runtime state file — including each anti-replay watermark — must
    /// be named in the generated script. A dropped entry leaves stale signed
    /// state (assignment / traversal / dns-zone / membership) behind for the
    /// next bootstrap, so the pin enumerates ALL ten paths rather than
    /// sampling. Keys and the installation must remain untouched.
    #[test]
    fn runtime_state_cleanup_script_removes_every_state_file_including_watermarks() {
        let s = build_runtime_state_cleanup_script().expect("cleanup script should render");
        // Every reviewed runtime state file, watermarks included.
        for rel in [
            r"membership\membership.snapshot",
            r"membership\membership.log",
            r"membership\membership.watermark",
            r"rustynetd.state",
            r"trust\rustynetd.assignment",
            r"trust\rustynetd.assignment.watermark",
            r"trust\rustynetd.traversal",
            r"trust\rustynetd.traversal.watermark",
            r"trust\rustynetd.dns-zone",
            r"trust\rustynetd.dns-zone.watermark",
        ] {
            assert!(
                s.contains(&format!("Join-Path $stateRoot '{rel}'")),
                "cleanup script must remove {rel} (stale signed state is a \
                 release blocker): {s}"
            );
        }
        // Removal is per-file and best-effort, and never aborts the stage.
        assert!(s.contains("Remove-Item -LiteralPath $f -Force"));
        assert!(s.contains("$ErrorActionPreference = 'Continue'"));
        assert!(s.contains("exit 0"));
        // The staging tree goes too (recursive), under the reviewed constant.
        assert!(
            s.contains(&format!(
                "Remove-Item -Path {} -Recurse -Force",
                ps_quote(WINDOWS_STAGING_DIR).expect("staging dir must quote")
            )),
            "staging dir must be purged recursively: {s}"
        );
        // Fail-safe boundary: keys and the installation are NOT targets.
        assert!(!s.contains("keys"), "cleanup must never touch keys: {s}");
        assert!(
            !s.contains(r"Program Files"),
            "cleanup must never touch the installation: {s}"
        );
    }

    #[test]
    fn validate_ip_arg_accepts_valid_ipv4() {
        assert!(validate_ip_arg("10.0.0.1").is_ok());
        assert!(validate_ip_arg("192.168.1.100").is_ok());
    }

    #[test]
    fn validate_ip_arg_accepts_ipv6() {
        assert!(validate_ip_arg("fd00::1").is_ok());
    }

    #[test]
    fn validate_ip_arg_rejects_injection() {
        assert!(validate_ip_arg("10.0.0.1; rm -rf /").is_err());
        assert!(validate_ip_arg("$(whoami)").is_err());
    }

    #[test]
    fn base64_decode_wireguard_key_roundtrip() {
        let encoded = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let hex = decode_wireguard_pubkey_to_hex(encoded).unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn base64_decode_rejects_wrong_length() {
        let encoded = "aGVsbG8="; // "hello" = 5 bytes
        let result = decode_wireguard_pubkey_to_hex(encoded);
        assert!(result.is_err(), "must reject non-32-byte key");
        assert!(result.unwrap_err().contains("32-byte"));
    }

    /// The bootstrap-time `collect_node_id` reader must stay scoped to the
    /// reviewed rustynetd.env file: its script reads the env-file and must
    /// not invoke the trust CLI (the live challenge has its own dedicated
    /// script — see `live_identity_script_invokes_trust_cli_status`).
    #[test]
    fn collect_node_id_script_targets_env_file_not_trust_cli() {
        let script = super::collect_node_id_script().expect("env-file path must pass ps_quote");
        assert!(
            script.contains("rustynetd.env"),
            "bootstrap reader must read rustynetd.env: {script}"
        );
        assert!(
            script.contains("Get-Content"),
            "bootstrap reader must read the env-file contents: {script}"
        );
        assert!(
            !script.contains("rustynet.exe"),
            "bootstrap reader must not invoke the trust CLI: {script}"
        );
        assert!(
            !script.contains(" status"),
            "bootstrap reader must not run a status sub-command: {script}"
        );
    }

    /// The §4.7 live-identity script must invoke the trust CLI's `status`
    /// verb (the daemon's live self-report over the daemon-control pipe) and
    /// must not fall back to reading rustynetd.env.
    #[test]
    fn live_identity_script_invokes_trust_cli_status() {
        let script = super::live_identity_status_script().expect("install path must pass ps_quote");
        assert!(
            script.contains("rustynet.exe"),
            "live identity must go through the trust CLI: {script}"
        );
        assert!(
            script.ends_with(" status"),
            "live identity must run the status verb: {script}"
        );
        assert!(
            !script.contains("rustynetd.env"),
            "live identity must not read the config env-file: {script}"
        );
    }

    /// A daemon status fixture line parses into live identity evidence via
    /// the same `parse_status_node_id` seam Linux/macOS use.
    #[test]
    fn live_identity_from_status_parses_fixture_to_live_evidence() {
        use crate::vm_lab::orchestrator::role_validation::identity_challenge::IdentityProvenance;

        let status = "node_id=win-1 node_role=client state=Running mesh_ip=100.64.0.9";
        let evidence =
            super::live_identity_from_status(status).expect("fixture must parse to live evidence");
        assert_eq!(evidence.node_id, "win-1");
        assert!(matches!(
            evidence.provenance,
            IdentityProvenance::LiveDaemonSocket
        ));
    }

    /// A status response without `node_id=` fails closed: an Err (never a
    /// ConfigFile assertion), so the challenge cannot pass on a partial
    /// daemon response.
    #[test]
    fn live_identity_from_status_without_node_id_fails_closed() {
        let err = super::live_identity_from_status("node_role=client state=Running")
            .expect_err("missing node_id must fail closed");
        match err {
            AdapterError::Protocol { message } => assert!(
                message.contains("node_id not in rustynet status output"),
                "error must name the missing live node_id: {message}"
            ),
            other => panic!("expected Protocol error, got: {other:?}"),
        }
    }
}
