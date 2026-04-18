#[cfg(not(windows))]
use std::path::Path;
#[cfg(not(windows))]
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsDpapiScope {
    CurrentUser,
    LocalMachine,
}

#[cfg(not(windows))]
pub fn dpapi_protect(
    _plaintext: &[u8],
    _scope: WindowsDpapiScope,
    _description: &str,
) -> Result<Vec<u8>, String> {
    Err("Windows DPAPI is only available on Windows hosts".to_string())
}

#[cfg(not(windows))]
pub fn dpapi_unprotect(_blob: &[u8]) -> Result<Vec<u8>, String> {
    Err("Windows DPAPI is only available on Windows hosts".to_string())
}

#[cfg(not(windows))]
pub fn inspect_file_sddl(_path: &Path) -> Result<String, String> {
    Err("Windows ACL inspection is only available on Windows hosts".to_string())
}

#[cfg(not(windows))]
pub fn lookup_account_sid_string(_account_name: &str) -> Result<String, String> {
    Err("Windows SID lookup is only available on Windows hosts".to_string())
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
    Err("Windows named pipes are only available on Windows hosts".to_string())
}

#[cfg(not(windows))]
pub fn call_named_pipe(
    _path: &str,
    _request: &[u8],
    _max_response_bytes: usize,
    _timeout: Duration,
) -> Result<Vec<u8>, String> {
    Err("Windows named pipes are only available on Windows hosts".to_string())
}

#[cfg(windows)]
mod imp {
    use super::WindowsDpapiScope;
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::path::Path;
    use std::ptr::{null, null_mut};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_PIPE_CONNECTED,
        GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
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
}

#[cfg(windows)]
pub use imp::{
    call_named_pipe, dpapi_protect, dpapi_unprotect, inspect_file_sddl, lookup_account_sid_string,
    serve_named_pipe_one_message,
};
