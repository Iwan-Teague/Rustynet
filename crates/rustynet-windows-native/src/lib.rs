use std::net::{IpAddr, Ipv4Addr};
#[cfg(not(windows))]
use std::path::Path;
#[cfg(not(windows))]
use std::time::Duration;

pub const WINDOWS_IF_OPER_STATUS_UP: u32 = 1;
pub const WINDOWS_IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsNetworkAdapterSnapshot {
    pub adapter_name: String,
    pub friendly_name: String,
    pub description: String,
    pub if_index: u32,
    pub ipv6_if_index: u32,
    pub if_type: u32,
    pub oper_status: u32,
    pub ipv4_metric: u32,
    pub ipv6_metric: u32,
    pub unicast_addresses: Vec<IpAddr>,
    pub default_gateways: Vec<IpAddr>,
}

impl WindowsNetworkAdapterSnapshot {
    pub fn display_name(&self) -> &str {
        if !self.friendly_name.is_empty() {
            &self.friendly_name
        } else if !self.adapter_name.is_empty() {
            &self.adapter_name
        } else {
            &self.description
        }
    }

    pub fn is_oper_up(&self) -> bool {
        self.oper_status == WINDOWS_IF_OPER_STATUS_UP
    }

    pub fn is_loopback(&self) -> bool {
        self.if_type == WINDOWS_IF_TYPE_SOFTWARE_LOOPBACK
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsDpapiScope {
    CurrentUser,
    LocalMachine,
}

/// Outcome of a `verify_authenticode_chain` call. Variants:
/// - `Verified`: `WinVerifyTrust` returned `S_OK` for the
///   `WINTRUST_ACTION_GENERIC_VERIFY_V2` policy with chain
///   revocation enabled. The signing certificate's full chain is
///   trusted, the file digest matches the `SpcIndirectData`, and any
///   counter-signature timestamps are valid.
/// - `Untrusted`: `WinVerifyTrust` returned a non-zero HRESULT. The
///   `reason` carries the canonical error label (e.g.
///   `TRUST_E_NOSIGNATURE`, `CERT_E_UNTRUSTEDROOT`,
///   `CERT_E_REVOKED`, `TRUST_E_BAD_DIGEST`) and `hresult` carries
///   the raw 32-bit code (sign-extended into i64 so callers can
///   round-trip through serde without precision loss).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticodeChainOutcome {
    Verified,
    Untrusted { reason: String, hresult: i64 },
}

#[cfg(not(windows))]
pub fn dpapi_protect(
    _plaintext: &[u8],
    _scope: WindowsDpapiScope,
    _description: &str,
) -> Result<Vec<u8>, String> {
    Err("Windows DPAPI is only available on Windows hosts".to_owned())
}

#[cfg(not(windows))]
pub fn dpapi_unprotect(_blob: &[u8]) -> Result<Vec<u8>, String> {
    Err("Windows DPAPI is only available on Windows hosts".to_owned())
}

#[cfg(not(windows))]
pub fn inspect_file_sddl(_path: &Path) -> Result<String, String> {
    Err("Windows ACL inspection is only available on Windows hosts".to_owned())
}

/// W4 — Registry-key ACL inspector. On Windows the implementation
/// opens the named registry key via `RegOpenKeyExW`, reads its
/// security descriptor via `RegGetKeySecurity`, and converts to
/// SDDL via `ConvertSecurityDescriptorToStringSecurityDescriptorW`.
/// Off-Windows the stub returns a clear platform blocker so callers
/// can surface "could not observe; collector requires Windows" via
/// the existing `WindowsRegistryKeyAclStatus::Unobserved` shape.
///
/// Input format: the operator-visible registry-key path is
/// `HKLM\SYSTEM\CurrentControlSet\Services\<Service>` style. The
/// implementation parses the root (`HKLM` / `HKCU` / `HKCR` /
/// `HKU` / `HKCC`) prefix and opens the relative sub-key.
#[cfg(not(windows))]
pub fn inspect_registry_key_sddl(_key_path: &str) -> Result<String, String> {
    Err("Windows registry-key ACL inspection is only available on Windows hosts".to_owned())
}

/// W5 — Authenticode signer-certificate SHA-256 thumbprint
/// extractor. On Windows the implementation calls
/// `CryptQueryObject` to open the PE's signature blob, walks the
/// CMS SignerInfo via `CryptMsgGetParam(CMSG_SIGNER_CERT_INFO_PARAM)`,
/// derives the signer's certificate context from the SignedData,
/// and reads `CertGetCertificateContextProperty(CERT_SHA256_HASH_PROP_ID)`.
/// Returns the lowercase hex of the 32-byte SHA-256 hash.
///
/// Off-Windows the stub returns a clear platform blocker — callers
/// that supply a thumbprint policy then get a fail-closed result
/// via `evaluate_thumbprint_policy(None, &policy)`, which is the
/// correct security posture (no policy bypass on unsupported
/// platforms).
#[cfg(not(windows))]
pub fn extract_signer_thumbprint_sha256(_path: &Path) -> Result<String, String> {
    Err("Windows Authenticode thumbprint extraction is only available on Windows hosts".to_owned())
}

#[cfg(not(windows))]
pub fn verify_authenticode_chain(_path: &Path) -> Result<AuthenticodeChainOutcome, String> {
    // Off-Windows: WinVerifyTrust is unavailable. The verifier
    // contract is "fail closed when the trust state cannot be
    // observed", so callers MUST treat this Err as a drift outcome
    // (not as a trust grant). The pure PE-parser surface in
    // `crates/rustynetd/src/windows_authenticode.rs` continues to
    // report signature *presence* off-Windows for diagnostic
    // purposes; the chain check stays Windows-only.
    Err(
        "WinVerifyTrust authenticode chain validation is only available on Windows hosts"
            .to_owned(),
    )
}

#[cfg(not(windows))]
pub fn lookup_account_sid_string(_account_name: &str) -> Result<String, String> {
    Err("Windows SID lookup is only available on Windows hosts".to_owned())
}

#[cfg(not(windows))]
pub fn serve_named_pipe_one_message<F>(
    _path: &str,
    _security_sddl: &str,
    _max_message_bytes: usize,
    _handler: F,
) -> Result<(), String>
where
    F: FnOnce(Vec<u8>) -> Result<Vec<u8>, String>,
{
    Err("Windows named pipes are only available on Windows hosts".to_owned())
}

#[cfg(not(windows))]
pub fn call_named_pipe(
    _path: &str,
    _request: &[u8],
    _max_response_bytes: usize,
    _timeout: Duration,
) -> Result<Vec<u8>, String> {
    Err("Windows named pipes are only available on Windows hosts".to_owned())
}

#[cfg(not(windows))]
pub fn get_adapters_addresses() -> Result<Vec<WindowsNetworkAdapterSnapshot>, String> {
    Err("GetAdaptersAddresses is only available on Windows hosts".to_owned())
}

pub fn detect_default_gateway() -> Result<IpAddr, String> {
    let adapters = get_adapters_addresses()?;
    select_default_gateway_from_adapters(&adapters)
}

pub fn select_default_gateway_from_adapters(
    adapters: &[WindowsNetworkAdapterSnapshot],
) -> Result<IpAddr, String> {
    let mut best: Option<(u8, u32, usize, IpAddr)> = None;
    for (adapter_idx, adapter) in adapters.iter().enumerate() {
        if !adapter.is_oper_up() || adapter.is_loopback() {
            continue;
        }
        for gateway in &adapter.default_gateways {
            if !gateway_is_usable_for_port_mapping(*gateway) {
                continue;
            }
            let family_rank = if gateway.is_ipv4() { 0 } else { 1 };
            let metric = if gateway.is_ipv4() {
                adapter.ipv4_metric
            } else {
                adapter.ipv6_metric
            };
            let candidate = (family_rank, metric, adapter_idx, *gateway);
            if best.is_none_or(|current| candidate < current) {
                best = Some(candidate);
            }
        }
    }
    best.map(|(_, _, _, gateway)| gateway)
        .ok_or_else(|| "no usable Windows default gateway found".to_owned())
}

fn gateway_is_usable_for_port_mapping(gateway: IpAddr) -> bool {
    match gateway {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && ip != Ipv4Addr::new(255, 255, 255, 255)
        }
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast(),
    }
}

#[cfg(windows)]
mod imp {
    use super::{WindowsDpapiScope, WindowsNetworkAdapterSnapshot};
    use std::ffi::{CStr, c_void};
    use std::mem::size_of;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::Path;
    use std::ptr::{null, null_mut};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_BUFFER_OVERFLOW, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA,
        ERROR_PIPE_CONNECTED, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree, NO_ERROR,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
        IP_ADAPTER_GATEWAY_ADDRESS_LH, IP_ADAPTER_UNICAST_ADDRESS_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
        CryptProtectData, CryptUnprotectData,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetFileSecurityW, GetKernelObjectSecurity, LookupAccountNameW,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAGS_AND_ATTRIBUTES, FlushFileBuffers,
        PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
    };
    use windows_sys::Win32::System::Pipes::{
        CallNamedPipeW, ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe,
        PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    pub fn dpapi_protect(
        plaintext: &[u8],
        scope: WindowsDpapiScope,
        description: &str,
    ) -> Result<Vec<u8>, String> {
        if plaintext.is_empty() {
            return Err("DPAPI plaintext must not be empty".to_string());
        }
        let description_wide = to_wide(description);
        let input = blob_from_slice(plaintext)?;
        let mut output = empty_blob();
        let flags = match scope {
            WindowsDpapiScope::CurrentUser => CRYPTPROTECT_UI_FORBIDDEN,
            WindowsDpapiScope::LocalMachine => {
                CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE
            }
        };
        let ok = unsafe {
            CryptProtectData(
                &input,
                description_wide.as_ptr(),
                null(),
                null(),
                null(),
                flags,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(format!(
                "CryptProtectData failed with Windows error {}",
                unsafe { GetLastError() }
            ));
        }
        blob_to_vec(&mut output)
    }

    pub fn dpapi_unprotect(blob: &[u8]) -> Result<Vec<u8>, String> {
        if blob.is_empty() {
            return Err("DPAPI blob must not be empty".to_string());
        }
        let input = blob_from_slice(blob)?;
        let mut output = empty_blob();
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                null_mut(),
                null(),
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            return Err(format!(
                "CryptUnprotectData failed with Windows error {}",
                unsafe { GetLastError() }
            ));
        }
        blob_to_vec(&mut output)
    }

    pub fn inspect_file_sddl(path: &Path) -> Result<String, String> {
        let wide_path = to_wide_os(path.as_os_str());
        let mut needed = 0u32;
        let requested = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let first =
            unsafe { GetFileSecurityW(wide_path.as_ptr(), requested, null_mut(), 0, &mut needed) };
        if first != 0 {
            return Err(
                "GetFileSecurityW unexpectedly succeeded with a zero-length buffer".to_string(),
            );
        }
        let err = unsafe { GetLastError() };
        if err != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
            return Err(format!(
                "GetFileSecurityW sizing failed with Windows error {err}"
            ));
        }
        let mut buffer = vec![0u8; needed as usize];
        let ok = unsafe {
            GetFileSecurityW(
                wide_path.as_ptr(),
                requested,
                buffer.as_mut_ptr().cast::<c_void>(),
                needed,
                &mut needed,
            )
        };
        if ok == 0 {
            return Err(format!(
                "GetFileSecurityW failed with Windows error {}",
                unsafe { GetLastError() }
            ));
        }
        security_descriptor_to_sddl(buffer.as_mut_ptr().cast::<c_void>())
    }

    /// W4 — registry-key SDDL extractor. Opens the requested
    /// `HKLM\…` (or other root) sub-key with `KEY_READ` access,
    /// reads the DACL portion of the security descriptor via
    /// `RegGetKeySecurity`, and converts to SDDL via
    /// `ConvertSecurityDescriptorToStringSecurityDescriptorW` (the
    /// same helper that the file-ACL path uses). On any Win32
    /// failure the returned `Err` includes the Windows error code so
    /// the caller can map specific HKEY-NOT-FOUND / access-denied
    /// shapes to the existing `WindowsRegistryKeyAclStatus::{Missing,
    /// Invalid}` variants.
    pub fn inspect_registry_key_sddl(key_path: &str) -> Result<String, String> {
        use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
        use windows_sys::Win32::System::Registry::{
            HKEY, KEY_READ, RegCloseKey, RegGetKeySecurity, RegOpenKeyExW,
        };

        let (root, subkey) = parse_registry_root(key_path)?;
        let wide_subkey = to_wide(subkey);
        let mut handle: HKEY = null_mut();
        let open_status =
            unsafe { RegOpenKeyExW(root, wide_subkey.as_ptr(), 0, KEY_READ, &mut handle) };
        if open_status != ERROR_SUCCESS {
            if open_status == ERROR_FILE_NOT_FOUND {
                return Err(format!(
                    "registry key not found: {key_path} (Windows error {open_status})"
                ));
            }
            return Err(format!(
                "RegOpenKeyExW failed for {key_path} with Windows error {open_status}"
            ));
        }
        let result = read_registry_key_sddl(handle);
        unsafe {
            // RegCloseKey returns ERROR_SUCCESS on close; ignore
            // close failure because the SDDL we already extracted is
            // still valid. Close-failure means the kernel handle
            // table is in a weird state but our caller's verdict
            // shouldn't depend on it.
            RegCloseKey(handle);
        }
        result
    }

    fn read_registry_key_sddl(
        handle: windows_sys::Win32::System::Registry::HKEY,
    ) -> Result<String, String> {
        use windows_sys::Win32::Foundation::ERROR_SUCCESS;
        use windows_sys::Win32::System::Registry::RegGetKeySecurity;
        let requested = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let mut needed = 0u32;
        let first = unsafe { RegGetKeySecurity(handle, requested, null_mut(), &mut needed) };
        // RegGetKeySecurity reports ERROR_INSUFFICIENT_BUFFER (122)
        // via its return value, NOT via GetLastError. Match the
        // Win32 contract precisely.
        if first != ERROR_INSUFFICIENT_BUFFER {
            return Err(format!(
                "RegGetKeySecurity sizing returned {first} (expected ERROR_INSUFFICIENT_BUFFER = {ERROR_INSUFFICIENT_BUFFER})"
            ));
        }
        if needed == 0 {
            return Err("RegGetKeySecurity reported a zero-byte security descriptor".to_owned());
        }
        let mut buffer = vec![0u8; needed as usize];
        let status = unsafe {
            RegGetKeySecurity(
                handle,
                requested,
                buffer.as_mut_ptr().cast::<c_void>(),
                &mut needed,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!(
                "RegGetKeySecurity failed with Windows error {status}"
            ));
        }
        security_descriptor_to_sddl(buffer.as_mut_ptr().cast::<c_void>())
    }

    /// Split an operator-visible registry-key path into its root
    /// hive HKEY constant and a NUL-terminator-free relative sub-key
    /// path suitable for `RegOpenKeyExW`. Accepted prefixes are
    /// the five standard hives (`HKLM` / `HKEY_LOCAL_MACHINE` /
    /// `HKCU` / `HKEY_CURRENT_USER` / `HKCR` /
    /// `HKEY_CLASSES_ROOT` / `HKU` / `HKEY_USERS` / `HKCC` /
    /// `HKEY_CURRENT_CONFIG`). Both `\` and `/` are accepted as
    /// the separator between the hive prefix and the sub-key path.
    fn parse_registry_root(
        key_path: &str,
    ) -> Result<(windows_sys::Win32::System::Registry::HKEY, &str), String> {
        use windows_sys::Win32::System::Registry::{
            HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
            HKEY_USERS,
        };
        let trimmed = key_path.trim();
        if trimmed.is_empty() {
            return Err("registry key path must not be empty".to_owned());
        }
        let split_at = trimmed
            .find(|c: char| c == '\\' || c == '/')
            .ok_or_else(|| {
                format!("registry key path {trimmed:?} missing hive separator (\\ or /)")
            })?;
        let prefix = &trimmed[..split_at];
        let rest = &trimmed[split_at + 1..];
        if rest.is_empty() {
            return Err(format!("registry key path {trimmed:?} has empty sub-key"));
        }
        let root: windows_sys::Win32::System::Registry::HKEY =
            match prefix.to_ascii_uppercase().as_str() {
                "HKLM" | "HKEY_LOCAL_MACHINE" => HKEY_LOCAL_MACHINE,
                "HKCU" | "HKEY_CURRENT_USER" => HKEY_CURRENT_USER,
                "HKCR" | "HKEY_CLASSES_ROOT" => HKEY_CLASSES_ROOT,
                "HKU" | "HKEY_USERS" => HKEY_USERS,
                "HKCC" | "HKEY_CURRENT_CONFIG" => HKEY_CURRENT_CONFIG,
                other => {
                    return Err(format!(
                        "registry hive {other:?} not recognised (expected HKLM/HKCU/HKCR/HKU/HKCC)"
                    ));
                }
            };
        Ok((root, rest))
    }

    /// W5 — Authenticode SHA-256 thumbprint extractor.
    ///
    /// Scope of this slice: the Win32 surface (`CryptQueryObject` +
    /// `CryptMsgGetParam(CMSG_SIGNER_INFO_PARAM)` +
    /// `CertFindCertificateInStore` +
    /// `CertGetCertificateContextProperty(CERT_SHA256_HASH_PROP_ID)`)
    /// has not yet been validated against a Windows runtime
    /// fixture. Rather than ship un-verified FFI code under a
    /// security-sensitive function, this entry point returns a
    /// typed reject that the caller maps to a fail-closed verdict
    /// (the same effect the `evaluate_thumbprint_policy(None,
    /// &policy)` path already produces today). The thumbprint
    /// extraction stays exactly where the W5 plan called for —
    /// inside `rustynet-windows-native::extract_signer_thumbprint_sha256`
    /// — so the next slice (Windows-side validation on a real
    /// fixture) drops in without changing call sites.
    ///
    /// Security framing: returning Err here is identical in
    /// observable verdict to the policy evaluator's
    /// fail-closed-on-`None` shape. It is NEVER a false pass.
    pub fn extract_signer_thumbprint_sha256(_path: &Path) -> Result<String, String> {
        Err(
            "Windows Authenticode thumbprint extractor pending validation on a Windows fixture; \
             treat as fail-closed via evaluate_thumbprint_policy(None, &policy)"
                .to_owned(),
        )
    }

    pub fn lookup_account_sid_string(account_name: &str) -> Result<String, String> {
        let account_wide = to_wide(account_name);
        let mut sid_len = 0u32;
        let mut domain_len = 0u32;
        let mut use_type = 0i32;
        let first = unsafe {
            LookupAccountNameW(
                null(),
                account_wide.as_ptr(),
                null_mut(),
                &mut sid_len,
                null_mut(),
                &mut domain_len,
                &mut use_type,
            )
        };
        if first != 0 {
            return Err(
                "LookupAccountNameW unexpectedly succeeded without a SID buffer".to_string(),
            );
        }
        let err = unsafe { GetLastError() };
        if err != ERROR_INSUFFICIENT_BUFFER || sid_len == 0 {
            return Err(format!(
                "LookupAccountNameW sizing failed for '{account_name}' with Windows error {err}"
            ));
        }
        let mut sid = vec![0u8; sid_len as usize];
        let mut domain = vec![0u16; domain_len as usize];
        let ok = unsafe {
            LookupAccountNameW(
                null(),
                account_wide.as_ptr(),
                sid.as_mut_ptr().cast::<c_void>(),
                &mut sid_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut use_type,
            )
        };
        if ok == 0 {
            return Err(format!(
                "LookupAccountNameW failed for '{account_name}' with Windows error {}",
                unsafe { GetLastError() }
            ));
        }
        sid_to_string(sid.as_mut_ptr().cast::<c_void>())
    }

    pub fn serve_named_pipe_one_message<F>(
        path: &str,
        security_sddl: &str,
        max_message_bytes: usize,
        handler: F,
    ) -> Result<(), String>
    where
        F: FnOnce(Vec<u8>) -> Result<Vec<u8>, String>,
    {
        if max_message_bytes == 0 {
            return Err("named-pipe max_message_bytes must be greater than zero".to_string());
        }
        let security = OwnedSecurityAttributes::from_sddl(security_sddl)?;
        let wide_path = to_wide(path);
        let message_bytes = u32::try_from(max_message_bytes)
            .map_err(|_| "named-pipe max_message_bytes exceeds u32".to_string())?;
        let open_mode: FILE_FLAGS_AND_ATTRIBUTES =
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE;
        let pipe_mode =
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
        let handle = unsafe {
            CreateNamedPipeW(
                wide_path.as_ptr(),
                open_mode,
                pipe_mode,
                PIPE_UNLIMITED_INSTANCES,
                message_bytes,
                message_bytes,
                5_000,
                security.as_ptr(),
            )
        };
        let handle = OwnedHandle::new(handle).ok_or_else(|| {
            format!("CreateNamedPipeW failed with Windows error {}", unsafe {
                GetLastError()
            })
        })?;

        let connected = unsafe { ConnectNamedPipe(handle.raw(), null_mut()) };
        if connected == 0 {
            let err = unsafe { GetLastError() };
            if err != ERROR_PIPE_CONNECTED {
                return Err(format!("ConnectNamedPipe failed with Windows error {err}"));
            }
        }

        let request = read_pipe_message(handle.raw(), max_message_bytes)?;
        let response = handler(request)?;
        if response.len() > max_message_bytes {
            return Err(format!(
                "named-pipe response exceeds maximum size ({} > {max_message_bytes})",
                response.len()
            ));
        }
        write_pipe_message(handle.raw(), &response)?;
        unsafe {
            DisconnectNamedPipe(handle.raw());
        }
        Ok(())
    }

    pub fn call_named_pipe(
        path: &str,
        request: &[u8],
        max_response_bytes: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        if request.is_empty() {
            return Err("named-pipe request must not be empty".to_string());
        }
        let timeout_ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        let request_len = u32::try_from(request.len())
            .map_err(|_| "named-pipe request exceeds u32".to_string())?;
        let mut response = vec![0u8; max_response_bytes];
        let mut bytes_read = 0u32;
        let wide_path = to_wide(path);
        let ok = unsafe {
            CallNamedPipeW(
                wide_path.as_ptr(),
                request.as_ptr().cast::<c_void>(),
                request_len,
                response.as_mut_ptr().cast::<c_void>(),
                u32::try_from(response.len())
                    .map_err(|_| "named-pipe response buffer exceeds u32".to_string())?,
                &mut bytes_read,
                timeout_ms,
            )
        };
        if ok == 0 {
            return Err(format!(
                "CallNamedPipeW failed with Windows error {}",
                unsafe { GetLastError() }
            ));
        }
        response.truncate(bytes_read as usize);
        Ok(response)
    }

    pub fn get_adapters_addresses() -> Result<Vec<WindowsNetworkAdapterSnapshot>, String> {
        const MAX_ATTEMPTS: usize = 3;
        let mut size = 15 * 1024u32;
        for _ in 0..MAX_ATTEMPTS {
            let mut buffer = vec![0u8; size as usize];
            let ret = unsafe {
                GetAdaptersAddresses(
                    u32::from(AF_UNSPEC),
                    GAA_FLAG_SKIP_ANYCAST
                        | GAA_FLAG_SKIP_MULTICAST
                        | GAA_FLAG_SKIP_DNS_SERVER
                        | GAA_FLAG_INCLUDE_GATEWAYS,
                    null(),
                    buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                    &mut size,
                )
            };
            if ret == NO_ERROR {
                let head = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
                return adapters_from_linked_list(head);
            }
            if ret != ERROR_BUFFER_OVERFLOW {
                return Err(format!(
                    "GetAdaptersAddresses failed with Windows error {ret}"
                ));
            }
        }
        Err("GetAdaptersAddresses failed after repeated buffer growth".to_owned())
    }

    fn adapters_from_linked_list(
        mut adapter: *const IP_ADAPTER_ADDRESSES_LH,
    ) -> Result<Vec<WindowsNetworkAdapterSnapshot>, String> {
        let mut out = Vec::new();
        while !adapter.is_null() {
            let current = unsafe { &*adapter };
            let unicast_addresses = unicast_addresses_from_linked_list(current.FirstUnicastAddress);
            let default_gateways = gateway_addresses_from_linked_list(current.FirstGatewayAddress);
            let if_index = unsafe { current.Anonymous1.Anonymous.IfIndex };
            out.push(WindowsNetworkAdapterSnapshot {
                adapter_name: pstr_to_string(current.AdapterName),
                friendly_name: pwstr_to_string(current.FriendlyName)?,
                description: pwstr_to_string(current.Description)?,
                if_index,
                ipv6_if_index: current.Ipv6IfIndex,
                if_type: current.IfType,
                oper_status: current.OperStatus as u32,
                ipv4_metric: current.Ipv4Metric,
                ipv6_metric: current.Ipv6Metric,
                unicast_addresses,
                default_gateways,
            });
            adapter = current.Next;
        }
        Ok(out)
    }

    fn unicast_addresses_from_linked_list(
        mut address: *const IP_ADAPTER_UNICAST_ADDRESS_LH,
    ) -> Vec<IpAddr> {
        let mut out = Vec::new();
        while !address.is_null() {
            let current = unsafe { &*address };
            if let Some(ip) = socket_address_to_ipaddr(&current.Address) {
                out.push(ip);
            }
            address = current.Next;
        }
        out
    }

    fn gateway_addresses_from_linked_list(
        mut address: *const IP_ADAPTER_GATEWAY_ADDRESS_LH,
    ) -> Vec<IpAddr> {
        let mut out = Vec::new();
        while !address.is_null() {
            let current = unsafe { &*address };
            if let Some(ip) = socket_address_to_ipaddr(&current.Address) {
                out.push(ip);
            }
            address = current.Next;
        }
        out
    }

    fn socket_address_to_ipaddr(address: &SOCKET_ADDRESS) -> Option<IpAddr> {
        let sockaddr = address.lpSockaddr;
        if sockaddr.is_null() {
            return None;
        }
        sockaddr_to_ipaddr(sockaddr)
    }

    fn sockaddr_to_ipaddr(sockaddr: *const SOCKADDR) -> Option<IpAddr> {
        let family = unsafe { (*sockaddr).sa_family };
        match family {
            AF_INET => {
                let addr = unsafe { &*(sockaddr.cast::<SOCKADDR_IN>()) };
                let raw = unsafe { addr.sin_addr.S_un.S_addr };
                Some(IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes())))
            }
            AF_INET6 => {
                let addr = unsafe { &*(sockaddr.cast::<SOCKADDR_IN6>()) };
                let raw = unsafe { addr.sin6_addr.u.Byte };
                Some(IpAddr::V6(Ipv6Addr::from(raw)))
            }
            _ => None,
        }
    }

    fn read_pipe_message(handle: HANDLE, max_message_bytes: usize) -> Result<Vec<u8>, String> {
        let mut buffer = vec![0u8; max_message_bytes];
        let mut bytes_read = 0u32;
        let ok = unsafe {
            ReadFile(
                handle,
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len())
                    .map_err(|_| "named-pipe read buffer exceeds u32".to_string())?,
                &mut bytes_read,
                null_mut(),
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_MORE_DATA {
                return Err(format!(
                    "named-pipe request exceeds maximum size ({max_message_bytes} bytes)"
                ));
            }
            return Err(format!(
                "ReadFile on named pipe failed with Windows error {err}"
            ));
        }
        buffer.truncate(bytes_read as usize);
        Ok(buffer)
    }

    fn write_pipe_message(handle: HANDLE, bytes: &[u8]) -> Result<(), String> {
        let mut bytes_written = 0u32;
        let ok = unsafe {
            WriteFile(
                handle,
                bytes.as_ptr(),
                u32::try_from(bytes.len())
                    .map_err(|_| "named-pipe write buffer exceeds u32".to_string())?,
                &mut bytes_written,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(format!(
                "WriteFile on named pipe failed with Windows error {}",
                unsafe { GetLastError() }
            ));
        }
        if bytes_written as usize != bytes.len() {
            return Err(format!(
                "WriteFile on named pipe wrote {} of {} bytes",
                bytes_written,
                bytes.len()
            ));
        }
        let flushed = unsafe { FlushFileBuffers(handle) };
        if flushed == 0 {
            return Err(format!(
                "FlushFileBuffers on named pipe failed with Windows error {}",
                unsafe { GetLastError() }
            ));
        }
        Ok(())
    }

    fn security_descriptor_to_sddl(security_descriptor: *mut c_void) -> Result<String, String> {
        let mut sddl_ptr = null_mut();
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                security_descriptor,
                SDDL_REVISION_1,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut sddl_ptr,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(format!(
                "ConvertSecurityDescriptorToStringSecurityDescriptorW failed with Windows error {}",
                unsafe { GetLastError() }
            ));
        }
        owned_pwstr_to_string(sddl_ptr)
    }

    fn sid_to_string(sid: *mut c_void) -> Result<String, String> {
        let mut sid_ptr = null_mut();
        let ok = unsafe { ConvertSidToStringSidW(sid, &mut sid_ptr) };
        if ok == 0 {
            return Err(format!(
                "ConvertSidToStringSidW failed with Windows error {}",
                unsafe { GetLastError() }
            ));
        }
        owned_pwstr_to_string(sid_ptr)
    }

    fn owned_pwstr_to_string(ptr: *mut u16) -> Result<String, String> {
        if ptr.is_null() {
            return Err("Windows API returned a null wide-string pointer".to_string());
        }
        let mut len = 0usize;
        unsafe {
            while *ptr.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(ptr, len);
            let value =
                String::from_utf16(slice).map_err(|err| format!("UTF-16 decode failed: {err}"))?;
            LocalFree(ptr.cast::<c_void>());
            Ok(value)
        }
    }

    fn pwstr_to_string(ptr: *const u16) -> Result<String, String> {
        if ptr.is_null() {
            return Ok(String::new());
        }
        let mut len = 0usize;
        unsafe {
            while *ptr.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(ptr, len);
            String::from_utf16(slice).map_err(|err| format!("UTF-16 decode failed: {err}"))
        }
    }

    fn pstr_to_string(ptr: *const u8) -> String {
        if ptr.is_null() {
            return String::new();
        }
        unsafe { CStr::from_ptr(ptr.cast()) }
            .to_string_lossy()
            .into_owned()
    }

    fn blob_from_slice(value: &[u8]) -> Result<CRYPT_INTEGER_BLOB, String> {
        let len = u32::try_from(value.len()).map_err(|_| "buffer exceeds u32".to_string())?;
        Ok(CRYPT_INTEGER_BLOB {
            cbData: len,
            pbData: value.as_ptr().cast_mut(),
        })
    }

    fn empty_blob() -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        }
    }

    fn blob_to_vec(blob: &mut CRYPT_INTEGER_BLOB) -> Result<Vec<u8>, String> {
        if blob.pbData.is_null() || blob.cbData == 0 {
            return Err("Windows API returned an empty blob".to_string());
        }
        let value =
            unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize) }.to_vec();
        unsafe {
            LocalFree(blob.pbData.cast::<c_void>());
        }
        blob.pbData = null_mut();
        blob.cbData = 0;
        Ok(value)
    }

    fn to_wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn to_wide_os(value: &std::ffi::OsStr) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        fn new(handle: HANDLE) -> Option<Self> {
            if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                return None;
            }
            Some(Self(handle))
        }

        fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    struct OwnedSecurityAttributes {
        attributes: SECURITY_ATTRIBUTES,
        descriptor: PSECURITY_DESCRIPTOR,
    }

    impl OwnedSecurityAttributes {
        fn from_sddl(sddl: &str) -> Result<Self, String> {
            let mut descriptor = null_mut();
            let wide_sddl = to_wide(sddl);
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide_sddl.as_ptr(),
                    SDDL_REVISION_1 as u32,
                    &mut descriptor,
                    null_mut(),
                )
            };
            if ok == 0 || descriptor.is_null() {
                return Err(format!(
                    "ConvertStringSecurityDescriptorToSecurityDescriptorW failed with Windows error {}",
                    unsafe { GetLastError() }
                ));
            }
            Ok(Self {
                attributes: SECURITY_ATTRIBUTES {
                    nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: descriptor.cast::<c_void>(),
                    bInheritHandle: 0,
                },
                descriptor,
            })
        }

        fn as_ptr(&self) -> *const SECURITY_ATTRIBUTES {
            &self.attributes
        }
    }

    impl Drop for OwnedSecurityAttributes {
        fn drop(&mut self) {
            if !self.descriptor.is_null() {
                unsafe {
                    LocalFree(self.descriptor.cast::<c_void>());
                }
                self.descriptor = null_mut();
            }
        }
    }

    #[allow(dead_code)]
    fn inspect_handle_sddl(handle: HANDLE) -> Result<String, String> {
        let requested = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let mut needed = 0u32;
        let first =
            unsafe { GetKernelObjectSecurity(handle, requested, null_mut(), 0, &mut needed) };
        if first != 0 {
            return Err(
                "GetKernelObjectSecurity unexpectedly succeeded with a zero-length buffer"
                    .to_string(),
            );
        }
        let err = unsafe { GetLastError() };
        if err != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
            return Err(format!(
                "GetKernelObjectSecurity sizing failed with Windows error {err}"
            ));
        }
        let mut buffer = vec![0u8; needed as usize];
        let ok = unsafe {
            GetKernelObjectSecurity(
                handle,
                requested,
                buffer.as_mut_ptr().cast::<c_void>(),
                needed,
                &mut needed,
            )
        };
        if ok == 0 {
            return Err(format!(
                "GetKernelObjectSecurity failed with Windows error {}",
                unsafe { GetLastError() }
            ));
        }
        security_descriptor_to_sddl(buffer.as_mut_ptr().cast::<c_void>())
    }

    /// Authenticode chain validation via `WinVerifyTrust`. Wraps the
    /// canonical `WINTRUST_ACTION_GENERIC_VERIFY_V2` verb with
    /// chain-revocation checking enabled (`WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`)
    /// and the UI suppressed (`WTD_UI_NONE`). Verification succeeds
    /// only when the full PKCS#7 chain is trusted, the file digest
    /// matches the SpcIndirectData, and any counter-signature
    /// timestamps are valid; any of those failing maps to a typed
    /// `Untrusted` outcome with the canonical HRESULT label.
    ///
    /// State cleanup: the Win32 contract requires a follow-up call
    /// with `dwStateAction = WTD_STATEACTION_CLOSE` after every
    /// `WTD_STATEACTION_VERIFY`. The wrapper performs the cleanup
    /// even when the verify call returns an error so we do not leak
    /// the verifier state into subsequent calls.
    pub fn verify_authenticode_chain(
        path: &Path,
    ) -> Result<super::AuthenticodeChainOutcome, String> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Security::WinTrust::{
            WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
            WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_STATEACTION_CLOSE,
            WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
        };

        // Reject empty paths up-front — passing an empty string to
        // WinVerifyTrust would surface as a confusing internal error
        // rather than a clear "bad input" rejection.
        if path.as_os_str().is_empty() {
            return Err("verify_authenticode_chain: path must not be empty".to_string());
        }

        // Encode path as UTF-16 with explicit NUL terminator. The
        // Win32 wide-string contract requires the caller to provide
        // the NUL.
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);

        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: wide.as_ptr(),
            hFile: null_mut(),
            pgKnownSubject: null_mut(),
        };

        let mut wvt_data = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            pPolicyCallbackData: null_mut(),
            pSIPClientData: null_mut(),
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 {
                pFile: &mut file_info,
            },
            dwStateAction: WTD_STATEACTION_VERIFY,
            hWVTStateData: null_mut(),
            pwszURLReference: null_mut(),
            dwProvFlags: 0,
            dwUIContext: 0,
            pSignatureSettings: null_mut(),
        };

        let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let verify_status = unsafe {
            WinVerifyTrust(
                null_mut(),
                &mut action_guid,
                &mut wvt_data as *mut WINTRUST_DATA as *mut c_void,
            )
        };

        // Always cleanup state, even on verify failure, to avoid
        // leaking handles/state into subsequent calls.
        wvt_data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = unsafe {
            WinVerifyTrust(
                null_mut(),
                &mut action_guid,
                &mut wvt_data as *mut WINTRUST_DATA as *mut c_void,
            )
        };

        if verify_status == 0 {
            Ok(super::AuthenticodeChainOutcome::Verified)
        } else {
            let raw_u32 = verify_status as u32;
            let label = match raw_u32 {
                0x800B0001 => "TRUST_E_PROVIDER_UNKNOWN",
                0x800B0100 => "TRUST_E_NOSIGNATURE",
                0x800B0101 => "CERT_E_EXPIRED",
                0x800B0102 => "CERT_E_VALIDITYPERIODNESTING",
                0x800B0103 => "CERT_E_ROLE",
                0x800B0104 => "CERT_E_PATHLENCONST",
                0x800B0105 => "CERT_E_CRITICAL",
                0x800B0106 => "CERT_E_PURPOSE",
                0x800B0107 => "CERT_E_ISSUERCHAINING",
                0x800B0108 => "CERT_E_MALFORMED",
                0x800B0109 => "CERT_E_UNTRUSTEDROOT",
                0x800B010A => "CERT_E_CHAINING",
                0x800B010B => "TRUST_E_FAIL",
                0x800B010C => "CERT_E_REVOKED",
                0x800B010D => "CERT_E_UNTRUSTEDTESTROOT",
                0x800B010E => "CERT_E_REVOCATION_FAILURE",
                0x80092010 => "CRYPT_E_REVOKED",
                0x80092012 => "CRYPT_E_NO_REVOCATION_CHECK",
                0x80092013 => "CRYPT_E_REVOCATION_OFFLINE",
                0x80096010 => "TRUST_E_BAD_DIGEST",
                0x800B0110 => "TRUST_E_CERT_SIGNATURE",
                0x800B0111 => "TRUST_E_TIME_STAMP",
                _ => "UNKNOWN",
            };
            let reason = format!(
                "WinVerifyTrust returned 0x{raw_u32:08x} ({label}) for {}",
                path.display()
            );
            Ok(super::AuthenticodeChainOutcome::Untrusted {
                reason,
                hresult: verify_status as i64,
            })
        }
    }
}

#[cfg(windows)]
pub use imp::{
    call_named_pipe, dpapi_protect, dpapi_unprotect, extract_signer_thumbprint_sha256,
    get_adapters_addresses, inspect_file_sddl, inspect_registry_key_sddl,
    lookup_account_sid_string, serve_named_pipe_one_message, verify_authenticode_chain,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(
        oper_status: u32,
        if_type: u32,
        ipv4_metric: u32,
        ipv6_metric: u32,
        default_gateways: Vec<IpAddr>,
    ) -> WindowsNetworkAdapterSnapshot {
        WindowsNetworkAdapterSnapshot {
            adapter_name: "adapter-guid".to_owned(),
            friendly_name: "Ethernet".to_owned(),
            description: "Test adapter".to_owned(),
            if_index: 12,
            ipv6_if_index: 12,
            if_type,
            oper_status,
            ipv4_metric,
            ipv6_metric,
            unicast_addresses: vec![],
            default_gateways,
        }
    }

    #[test]
    fn select_default_gateway_prefers_lowest_metric_ipv4_on_up_adapter() {
        let slow = snapshot(
            WINDOWS_IF_OPER_STATUS_UP,
            6,
            500,
            500,
            vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
        );
        let fast = snapshot(
            WINDOWS_IF_OPER_STATUS_UP,
            6,
            10,
            10,
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
        );
        let gateway = select_default_gateway_from_adapters(&[slow, fast]).expect("gateway");
        assert_eq!(gateway, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn select_default_gateway_skips_down_loopback_and_unusable_gateways() {
        let down = snapshot(2, 6, 1, 1, vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))]);
        let loopback = snapshot(
            WINDOWS_IF_OPER_STATUS_UP,
            WINDOWS_IF_TYPE_SOFTWARE_LOOPBACK,
            1,
            1,
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        );
        let usable = snapshot(
            WINDOWS_IF_OPER_STATUS_UP,
            6,
            50,
            50,
            vec![IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))],
        );
        let gateway =
            select_default_gateway_from_adapters(&[down, loopback, usable]).expect("gateway");
        assert_eq!(gateway, IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)));
    }

    #[test]
    fn select_default_gateway_fails_closed_without_usable_route() {
        let bad = snapshot(
            WINDOWS_IF_OPER_STATUS_UP,
            6,
            1,
            1,
            vec![
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            ],
        );
        let err = select_default_gateway_from_adapters(&[bad]).expect_err("no gateway");
        assert!(err.contains("no usable Windows default gateway"));
    }
}
