use std::{alloc::System, os::raw::c_void};

use std::sync::OnceLock;
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        Security::{
            CreateWellKnownSid, EqualSid, GetTokenInformation, PSID, TOKEN_QUERY, TOKEN_USER,
            TokenUser, WinLocalSystemSid,
        },
        System::Threading::{
            IsProcessCritical, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
    core::{BOOL, Error},
};

/// Information about a process's status
#[derive(Debug, Clone, Copy)]
pub struct ProcessInfo {
    pub is_critical: bool,
    pub is_system: bool,
}

/// Stores the SYSTEM SID, initialized once and globally accessible.
static SYSTEM_SID: OnceLock<Vec<u8>> = OnceLock::new();

/// Retrieves a reference to the SYSTEM SID, lazily initialized on first access.
///
/// Uses `OnceLock` for thread-safe, one-time initialization. The SID is computed as a `Vec<u8>`
/// and returned as a static byte slice (`&'static [u8]`) compatible with `PSID`.
///
/// # Errors
///
/// Returns an `Error` if `CreateWellKnownSid` fails (e.g., invalid SID type or system issue).
/// This is rare for `WinLocalSystemSid`.
fn get_system_sid() -> Result<&'static [u8], Error> {
    SYSTEM_SID.get_or_init(|| {
        let mut sid_size = 0;
        unsafe {
            // First call: Get required size
            CreateWellKnownSid(WinLocalSystemSid, None, None, &mut sid_size)
                .expect("Failed to get SYSTEM SID size");

            let mut sid = vec![0u8; sid_size as usize];

            // Second call: Fill the buffer
            CreateWellKnownSid(
                WinLocalSystemSid,
                None,
                Some(PSID(sid.as_mut_ptr() as *mut c_void)),
                &mut sid_size,
            )
            .expect("Failed to create SYSTEM SID");

            sid
        }
    });

    // Since OnceLock::get returns Option<&T>, we need to handle the case where it's not initialized
    // But in practice, this won't happen because get_or_init ensures initialization
    Ok(SYSTEM_SID
        .get()
        .expect("System_SID initialization failed")
        .as_slice())
}

/// Checks if a process is critical using IsProcessCritical.
///
/// # Safety
/// - `process_handle` must be a valid handle with at least `PROCESS_QUERY_LIMITED_INFORMATION`.
unsafe fn check_is_critical(process_handle: HANDLE) -> Result<bool, Error> {
    let mut is_critical: BOOL = BOOL(0);
    unsafe { IsProcessCritical(process_handle, &mut is_critical)? };
    Ok(is_critical.0 != 0)
}

/// Checks if a process is a system process by comparing its token's SID with the SYSTEM SID.
///
/// # Safety
///
/// - The caller must ensure `process_handle` is a valid process handle with at least
///   `PROCESS_QUERY_INFORMATION` access rights.
/// - The handle must remain valid for the duration of the call.
///
/// # Errors
///
/// Returns an `Err` if token operations fail (e.g., insufficient permissions).
unsafe fn is_system_process(process_handle: HANDLE) -> Result<bool, Error> {
    let mut token_handle = HANDLE(std::ptr::null_mut());
    unsafe { OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle) }?;

    let mut return_length = 0;
    unsafe { GetTokenInformation(token_handle, TokenUser, None, 0, &mut return_length) }?;

    let mut token_user_buf = vec![0u8; return_length as usize];
    unsafe {
        GetTokenInformation(
            token_handle,
            TokenUser,
            Some(token_user_buf.as_mut_ptr().cast()),
            return_length,
            &mut return_length,
        )
    }?;

    let token_user = unsafe { &*token_user_buf.as_ptr().cast::<TOKEN_USER>() };
    let sid = token_user.User.Sid;

    let system_sid = get_system_sid()?;
    let is_system = unsafe { EqualSid(sid, PSID(system_sid.as_ptr() as *mut c_void)) };

    unsafe { CloseHandle(token_handle).ok() };
    Ok(is_system.is_ok())
}

/// Checks if a process has critical or system-level properties using an existing handle.
///
/// # Arguments
/// * `process_handle` - A valid process handle with at least `PROCESS_QUERY_LIMITED_INFORMATION`.
///
/// # Errors
/// Returns an `Err` if:
/// - Token information cannot be retrieved.
/// - SYSTEM SID initialization fails.
///
/// # Safety
/// - `process_handle` must be valid and not closed during the call
pub fn check_process(process_handle: HANDLE) -> Result<ProcessInfo, Error> {
    if process_handle.is_invalid() {
        return Err(Error::from_win32());
    }

    let is_critical = unsafe { check_is_critical(process_handle)? };
    let is_system = unsafe { is_system_process(process_handle)? };

    Ok(ProcessInfo {
        is_critical,
        is_system,
    })
}
