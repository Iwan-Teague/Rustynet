#![allow(clippy::result_large_err)]

//! Windows Authenticode signature **presence** verifier.
//!
//! This module parses a PE binary's Certificate Table directory entry
//! (IMAGE_DIRECTORY_ENTRY_SECURITY, index 4 in the optional header data
//! directories) and confirms that at least one well-formed Authenticode
//! WIN_CERTIFICATE entry is attached. Its purpose is to **reject unsigned
//! installs** before the daemon proceeds — an attacker who replaces the
//! binary with an unsigned one fails this gate immediately.
//!
//! What this module **does NOT** do:
//!
//! * It does not validate the PKCS#7 SignedData payload.
//! * It does not validate the certificate chain back to a trusted root.
//! * It does not verify the file hash against the signature's spcIndirectData.
//! * It does not check timestamping.
//!
//! Full chain validation requires Win32 `WinVerifyTrust` (out of scope for
//! this slice; tracked as W2.1b in the OS-agnostic delta plan). Until that
//! lands, this presence check is the cheap-but-real first gate that catches
//! the unsigned-binary case (which is by far the most likely tamper class
//! the orchestrator can fail-closed against today).
//!
//! All parsing is pure Rust with bounds-checked slicing — no `unsafe`, no
//! external crates. Cross-platform; identical behavior on Linux, macOS,
//! Windows.

use serde::{Deserialize, Serialize};
use std::path::Path;

const PE_DOS_MAGIC: &[u8] = b"MZ";
const PE_HEADER_MAGIC: &[u8] = b"PE\0\0";
const PE_OPTIONAL_HEADER_MAGIC_PE32: u16 = 0x010b;
const PE_OPTIONAL_HEADER_MAGIC_PE32_PLUS: u16 = 0x020b;
const PE_OPTIONAL_HEADER_DATA_DIRECTORY_INDEX_SECURITY: usize = 4;

/// Reviewed Authenticode certificate revision (WIN_CERT_REVISION_2_0).
const WIN_CERT_REVISION_2_0: u16 = 0x0200;
/// Reviewed Authenticode certificate type (WIN_CERT_TYPE_PKCS_SIGNED_DATA).
const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsAuthenticodeCertificateEntry {
    /// Length of the WIN_CERTIFICATE structure in bytes (header + payload).
    pub length: u32,
    pub revision: u16,
    pub certificate_type: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsAuthenticodeReport {
    pub schema_version: u32,
    pub binary_path: String,
    pub binary_size_bytes: u64,
    pub overall_ok: bool,
    /// True when at least one PKCS-signed WIN_CERTIFICATE entry was parsed
    /// successfully; false otherwise.
    pub signature_present: bool,
    pub certificate_table_offset: Option<u32>,
    pub certificate_table_size: Option<u32>,
    pub certificates: Vec<WindowsAuthenticodeCertificateEntry>,
    pub drift_reasons: Vec<String>,
}

/// Inspect the binary at `path` and produce a typed Authenticode presence
/// report. Returns a populated report regardless of outcome; `overall_ok` and
/// `drift_reasons` reflect the verification result.
pub fn inspect_authenticode_signature(path: &Path) -> WindowsAuthenticodeReport {
    let display_path = path.display().to_string();
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            return WindowsAuthenticodeReport {
                schema_version: 1,
                binary_path: display_path,
                binary_size_bytes: 0,
                overall_ok: false,
                signature_present: false,
                certificate_table_offset: None,
                certificate_table_size: None,
                certificates: Vec::new(),
                drift_reasons: vec![format!("read binary failed: {err}")],
            };
        }
    };
    let size = bytes.len() as u64;
    let parse = parse_authenticode_signature(bytes.as_slice());
    WindowsAuthenticodeReport {
        schema_version: 1,
        binary_path: display_path,
        binary_size_bytes: size,
        overall_ok: parse.is_ok(),
        signature_present: matches!(&parse, Ok(report) if report.signature_present),
        certificate_table_offset: parse.as_ref().ok().and_then(|p| p.certificate_table_offset),
        certificate_table_size: parse.as_ref().ok().and_then(|p| p.certificate_table_size),
        certificates: parse
            .as_ref()
            .map(|p| p.certificates.clone())
            .unwrap_or_default(),
        drift_reasons: parse
            .map(|p| p.drift_reasons)
            .unwrap_or_else(|err| vec![err]),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedAuthenticode {
    signature_present: bool,
    certificate_table_offset: Option<u32>,
    certificate_table_size: Option<u32>,
    certificates: Vec<WindowsAuthenticodeCertificateEntry>,
    drift_reasons: Vec<String>,
}

/// Pure parser: takes raw PE bytes, returns a verification result. Rejects
/// (with a precise reason) any binary that:
///
/// * is not a valid PE file
/// * has no Certificate Table directory entry, or one of size zero
/// * has a Certificate Table that points outside the file
/// * has zero well-formed PKCS-signed Authenticode entries
fn parse_authenticode_signature(bytes: &[u8]) -> Result<ParsedAuthenticode, String> {
    if bytes.len() < 0x40 {
        return Err(format!(
            "binary is too small to contain a PE DOS header ({} bytes)",
            bytes.len()
        ));
    }
    if &bytes[0..2] != PE_DOS_MAGIC {
        return Err("binary does not start with the PE DOS magic 'MZ'".to_string());
    }
    let e_lfanew = read_u32_le(bytes, 0x3C)
        .ok_or_else(|| "failed to read e_lfanew at offset 0x3C".to_string())?;
    let pe_header_offset = e_lfanew as usize;
    if pe_header_offset.saturating_add(24) > bytes.len() {
        return Err(format!(
            "PE header offset 0x{e_lfanew:08x} runs past end of binary"
        ));
    }
    if &bytes[pe_header_offset..pe_header_offset + 4] != PE_HEADER_MAGIC {
        return Err(format!(
            "PE header at offset 0x{e_lfanew:08x} does not start with 'PE\\0\\0'"
        ));
    }
    // COFF header: 4 bytes magic + 20 bytes COFF (machine, n_sections, time, sym_ptr, n_syms, opt_hdr_size, characteristics).
    let coff_header_offset = pe_header_offset + 4;
    let optional_header_size = read_u16_le(bytes, coff_header_offset + 16)
        .ok_or_else(|| "failed to read SizeOfOptionalHeader".to_string())?;
    if optional_header_size == 0 {
        return Err("PE has SizeOfOptionalHeader=0; not a normal Windows binary".to_string());
    }
    let optional_header_offset = coff_header_offset + 20;
    if optional_header_offset.saturating_add(optional_header_size as usize) > bytes.len() {
        return Err("optional header runs past end of binary".to_string());
    }
    let optional_magic = read_u16_le(bytes, optional_header_offset)
        .ok_or_else(|| "failed to read optional header magic".to_string())?;
    let data_directories_offset = match optional_magic {
        PE_OPTIONAL_HEADER_MAGIC_PE32 => optional_header_offset + 96,
        PE_OPTIONAL_HEADER_MAGIC_PE32_PLUS => optional_header_offset + 112,
        other => {
            return Err(format!(
                "unrecognized PE optional header magic 0x{other:04x}"
            ));
        }
    };
    let security_dir_offset =
        data_directories_offset + PE_OPTIONAL_HEADER_DATA_DIRECTORY_INDEX_SECURITY * 8;
    if security_dir_offset.saturating_add(8) > bytes.len() {
        return Err("Certificate Table directory entry runs past end of binary".to_string());
    }
    let cert_table_offset = read_u32_le(bytes, security_dir_offset)
        .ok_or_else(|| "failed to read Certificate Table offset".to_string())?;
    let cert_table_size = read_u32_le(bytes, security_dir_offset + 4)
        .ok_or_else(|| "failed to read Certificate Table size".to_string())?;
    if cert_table_offset == 0 || cert_table_size == 0 {
        return Err(
            "PE has an empty Certificate Table directory entry; binary is unsigned".to_string(),
        );
    }
    let cert_start = cert_table_offset as usize;
    let cert_end = cert_start
        .checked_add(cert_table_size as usize)
        .ok_or_else(|| "Certificate Table size overflowed when added to offset".to_string())?;
    if cert_end > bytes.len() {
        return Err(format!(
            "Certificate Table extends from 0x{cert_table_offset:08x} for {cert_table_size} bytes but binary is only {} bytes",
            bytes.len()
        ));
    }

    let mut cursor = cert_start;
    let mut certificates: Vec<WindowsAuthenticodeCertificateEntry> = Vec::new();
    let mut drift_reasons: Vec<String> = Vec::new();
    let mut pkcs_count = 0usize;
    while cursor < cert_end {
        // WIN_CERTIFICATE: u32 length, u16 revision, u16 certificate_type, [u8] payload
        if cursor + 8 > cert_end {
            drift_reasons.push(format!(
                "WIN_CERTIFICATE header at offset 0x{cursor:08x} runs past Certificate Table end"
            ));
            break;
        }
        let length = read_u32_le(bytes, cursor)
            .ok_or_else(|| "failed to read WIN_CERTIFICATE length".to_string())?;
        let revision = read_u16_le(bytes, cursor + 4)
            .ok_or_else(|| "failed to read WIN_CERTIFICATE revision".to_string())?;
        let cert_type = read_u16_le(bytes, cursor + 6)
            .ok_or_else(|| "failed to read WIN_CERTIFICATE type".to_string())?;
        if length < 8 {
            drift_reasons.push(format!(
                "WIN_CERTIFICATE at 0x{cursor:08x} has length {length} < 8 (minimum header size)"
            ));
            break;
        }
        let entry_end = cursor
            .checked_add(length as usize)
            .ok_or_else(|| "WIN_CERTIFICATE length overflowed".to_string())?;
        if entry_end > cert_end {
            drift_reasons.push(format!(
                "WIN_CERTIFICATE at 0x{cursor:08x} length {length} exceeds Certificate Table bounds"
            ));
            break;
        }
        certificates.push(WindowsAuthenticodeCertificateEntry {
            length,
            revision,
            certificate_type: cert_type,
        });
        if revision == WIN_CERT_REVISION_2_0 && cert_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA {
            pkcs_count += 1;
        } else {
            drift_reasons.push(format!(
                "WIN_CERTIFICATE at 0x{cursor:08x} is not a PKCS-signed Authenticode entry (revision=0x{revision:04x}, type=0x{cert_type:04x}); reviewed RustyNet installs require revision=0x{:04x} type=0x{:04x}",
                WIN_CERT_REVISION_2_0, WIN_CERT_TYPE_PKCS_SIGNED_DATA
            ));
        }
        // Each WIN_CERTIFICATE is rounded up to the next 8-byte boundary.
        let aligned_end = (entry_end + 7) & !7usize;
        cursor = aligned_end;
    }

    if pkcs_count == 0 {
        drift_reasons.push(
            "Certificate Table is present but contains no PKCS-signed Authenticode entry"
                .to_string(),
        );
    }

    Ok(ParsedAuthenticode {
        signature_present: pkcs_count > 0,
        certificate_table_offset: Some(cert_table_offset),
        certificate_table_size: Some(cert_table_size),
        certificates,
        drift_reasons,
    })
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid PE32+ binary in memory. Caller supplies the
    /// Certificate Table directory entry (offset, size) and the bytes that
    /// live at that offset. The returned vector has the dos header, PE
    /// header, COFF header, optional header, data directories, plus padding
    /// out to the certificate table region.
    fn build_pe_with_cert_table(cert_table_bytes: &[u8]) -> Vec<u8> {
        // Layout:
        //   0x00  DOS header (64 bytes; e_lfanew at 0x3C)
        //   0x40  PE header magic (4 bytes "PE\0\0")
        //   0x44  COFF header (20 bytes)
        //   0x58  Optional header (PE32+, 112 bytes through standard fields)
        //   0xC8  Data directories (16 entries * 8 bytes = 128 bytes)
        //   0x148 Certificate Table content
        let mut buf = vec![0u8; 0x148];
        buf[0..2].copy_from_slice(PE_DOS_MAGIC);
        // e_lfanew = 0x40
        buf[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        // PE header magic
        buf[0x40..0x44].copy_from_slice(PE_HEADER_MAGIC);
        // COFF header: SizeOfOptionalHeader at offset 0x40 + 4 + 16 = 0x54.
        // Optional header is 112 (standard PE32+ through fields) + 128 (data dirs) = 240.
        buf[0x54..0x56].copy_from_slice(&240u16.to_le_bytes());
        // Optional header magic at 0x58
        buf[0x58..0x5A].copy_from_slice(&PE_OPTIONAL_HEADER_MAGIC_PE32_PLUS.to_le_bytes());
        // Data directory index 4 (Security) at 0xC8 + 4*8 = 0xE8
        let cert_offset = buf.len() as u32;
        let cert_size = cert_table_bytes.len() as u32;
        buf[0xE8..0xEC].copy_from_slice(&cert_offset.to_le_bytes());
        buf[0xEC..0xF0].copy_from_slice(&cert_size.to_le_bytes());
        buf.extend_from_slice(cert_table_bytes);
        buf
    }

    fn build_win_certificate(revision: u16, cert_type: u16, payload: &[u8]) -> Vec<u8> {
        let length = (8 + payload.len()) as u32;
        let mut entry = Vec::with_capacity(length as usize);
        entry.extend_from_slice(&length.to_le_bytes());
        entry.extend_from_slice(&revision.to_le_bytes());
        entry.extend_from_slice(&cert_type.to_le_bytes());
        entry.extend_from_slice(payload);
        // 8-byte alignment padding
        while entry.len() % 8 != 0 {
            entry.push(0);
        }
        entry
    }

    #[test]
    fn parse_accepts_pe_with_pkcs_signed_certificate() {
        let cert_table = build_win_certificate(
            WIN_CERT_REVISION_2_0,
            WIN_CERT_TYPE_PKCS_SIGNED_DATA,
            b"fake-pkcs7-payload-bytes",
        );
        let pe = build_pe_with_cert_table(cert_table.as_slice());
        let parsed = parse_authenticode_signature(pe.as_slice())
            .expect("well-formed PE w/ PKCS Authenticode must parse");
        assert!(parsed.signature_present);
        assert_eq!(parsed.certificates.len(), 1);
        assert_eq!(parsed.drift_reasons.len(), 0);
    }

    #[test]
    fn parse_rejects_pe_with_empty_certificate_table_directory() {
        // Build a PE w/ no Certificate Table content (offset+size = 0,0).
        let mut buf = vec![0u8; 0x148];
        buf[0..2].copy_from_slice(PE_DOS_MAGIC);
        buf[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        buf[0x40..0x44].copy_from_slice(PE_HEADER_MAGIC);
        buf[0x54..0x56].copy_from_slice(&240u16.to_le_bytes());
        buf[0x58..0x5A].copy_from_slice(&PE_OPTIONAL_HEADER_MAGIC_PE32_PLUS.to_le_bytes());
        // Leave Security data directory entry zero-filled.
        let err = parse_authenticode_signature(buf.as_slice())
            .expect_err("empty Cert Table directory must fail");
        assert!(
            err.contains("empty Certificate Table directory entry"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_rejects_pe_with_certificate_table_offset_outside_binary() {
        let mut buf = vec![0u8; 0x148];
        buf[0..2].copy_from_slice(PE_DOS_MAGIC);
        buf[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        buf[0x40..0x44].copy_from_slice(PE_HEADER_MAGIC);
        buf[0x54..0x56].copy_from_slice(&240u16.to_le_bytes());
        buf[0x58..0x5A].copy_from_slice(&PE_OPTIONAL_HEADER_MAGIC_PE32_PLUS.to_le_bytes());
        // Cert Table at offset 0x10000, size 16 — past end of buf.
        buf[0xE8..0xEC].copy_from_slice(&0x10000u32.to_le_bytes());
        buf[0xEC..0xF0].copy_from_slice(&16u32.to_le_bytes());
        let err = parse_authenticode_signature(buf.as_slice())
            .expect_err("Cert Table outside binary must fail");
        assert!(
            err.contains("Certificate Table extends from"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_flags_non_pkcs_certificate_entries_with_drift_reason() {
        // Build a Cert Table entry with non-PKCS type (e.g. type=0x0001 X.509).
        let cert_table = build_win_certificate(WIN_CERT_REVISION_2_0, 0x0001, b"x509-payload");
        let pe = build_pe_with_cert_table(cert_table.as_slice());
        let parsed =
            parse_authenticode_signature(pe.as_slice()).expect("non-PKCS Cert Table still parses");
        assert!(!parsed.signature_present);
        assert_eq!(parsed.certificates.len(), 1);
        assert!(
            parsed
                .drift_reasons
                .iter()
                .any(|r| r.contains("not a PKCS-signed Authenticode entry")),
            "missing drift reason: {:?}",
            parsed.drift_reasons
        );
        assert!(
            parsed
                .drift_reasons
                .iter()
                .any(|r| r.contains("contains no PKCS-signed Authenticode entry")),
            "expected aggregate reason"
        );
    }

    #[test]
    fn parse_rejects_binary_without_pe_dos_magic() {
        let bytes = vec![0u8; 256];
        let err = parse_authenticode_signature(bytes.as_slice()).expect_err("missing MZ must fail");
        assert!(err.contains("does not start with the PE DOS magic"));
    }

    #[test]
    fn parse_rejects_binary_without_pe_header_magic() {
        let mut buf = vec![0u8; 0x148];
        buf[0..2].copy_from_slice(PE_DOS_MAGIC);
        buf[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        // Wrong PE magic
        buf[0x40..0x44].copy_from_slice(b"NE\0\0");
        let err =
            parse_authenticode_signature(buf.as_slice()).expect_err("wrong PE magic must fail");
        assert!(err.contains("does not start with 'PE"));
    }

    #[test]
    fn parse_rejects_binary_too_small() {
        let bytes = vec![0u8; 10];
        let err =
            parse_authenticode_signature(bytes.as_slice()).expect_err("tiny binary must fail");
        assert!(err.contains("too small"));
    }

    #[test]
    fn parse_rejects_unrecognized_optional_header_magic() {
        let mut buf = vec![0u8; 0x148];
        buf[0..2].copy_from_slice(PE_DOS_MAGIC);
        buf[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        buf[0x40..0x44].copy_from_slice(PE_HEADER_MAGIC);
        buf[0x54..0x56].copy_from_slice(&240u16.to_le_bytes());
        buf[0x58..0x5A].copy_from_slice(&0xDEADu16.to_le_bytes());
        let err = parse_authenticode_signature(buf.as_slice())
            .expect_err("bogus optional header magic must fail");
        assert!(err.contains("unrecognized PE optional header magic"));
    }

    #[test]
    fn parse_handles_two_pkcs_certificates_back_to_back() {
        let mut cert_table = build_win_certificate(
            WIN_CERT_REVISION_2_0,
            WIN_CERT_TYPE_PKCS_SIGNED_DATA,
            b"first",
        );
        cert_table.extend(build_win_certificate(
            WIN_CERT_REVISION_2_0,
            WIN_CERT_TYPE_PKCS_SIGNED_DATA,
            b"second-larger-payload",
        ));
        let pe = build_pe_with_cert_table(cert_table.as_slice());
        let parsed = parse_authenticode_signature(pe.as_slice()).expect("two-cert PE must parse");
        assert!(parsed.signature_present);
        assert_eq!(parsed.certificates.len(), 2);
        assert_eq!(parsed.drift_reasons.len(), 0);
    }

    #[test]
    fn parse_rejects_zero_length_win_certificate_entry() {
        let mut cert_bytes = Vec::new();
        cert_bytes.extend_from_slice(&0u32.to_le_bytes()); // length = 0
        cert_bytes.extend_from_slice(&WIN_CERT_REVISION_2_0.to_le_bytes());
        cert_bytes.extend_from_slice(&WIN_CERT_TYPE_PKCS_SIGNED_DATA.to_le_bytes());
        let pe = build_pe_with_cert_table(cert_bytes.as_slice());
        let parsed = parse_authenticode_signature(pe.as_slice())
            .expect("PE w/ malformed cert still parses outer structure");
        assert!(!parsed.signature_present);
        assert!(
            parsed
                .drift_reasons
                .iter()
                .any(|r| r.contains("length 0 < 8")),
            "missing length-too-small reason: {:?}",
            parsed.drift_reasons
        );
    }

    #[test]
    fn report_serializes_with_certificate_metadata_and_round_trips() {
        let report = WindowsAuthenticodeReport {
            schema_version: 1,
            binary_path: r"C:\Program Files\RustyNet\rustynetd.exe".to_string(),
            binary_size_bytes: 1234,
            overall_ok: true,
            signature_present: true,
            certificate_table_offset: Some(0x1000),
            certificate_table_size: Some(0x200),
            certificates: vec![WindowsAuthenticodeCertificateEntry {
                length: 0x1F0,
                revision: WIN_CERT_REVISION_2_0,
                certificate_type: WIN_CERT_TYPE_PKCS_SIGNED_DATA,
            }],
            drift_reasons: Vec::new(),
        };
        let serialized = serde_json::to_string(&report).expect("serialize");
        let restored: WindowsAuthenticodeReport =
            serde_json::from_str(serialized.as_str()).expect("deserialize");
        assert_eq!(restored, report);
    }

    #[test]
    fn inspect_authenticode_signature_returns_read_failure_when_path_missing() {
        let report = inspect_authenticode_signature(Path::new(
            "/nonexistent/path/to/rustynetd.exe.does-not-exist",
        ));
        assert!(!report.overall_ok);
        assert!(!report.signature_present);
        assert_eq!(report.binary_size_bytes, 0);
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|r| r.contains("read binary failed")),
            "missing read-failed reason: {:?}",
            report.drift_reasons
        );
    }
}
