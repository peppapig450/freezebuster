use std::os::raw::c_void;

use once_cell::sync::OnceCell;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetTokenInformation, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser,
    WinLocalSystemSid,
};
use windows::Win32::System::Threading::OpenProcessToken;
use windows::core::Error;

/// Stores the SYSTEM SID, initialized once and globally accessible.
static SYSTEM_SID: OnceCell<Vec<u8>> = OnceCell::new();

/// Retrieves the SYSTEM SID, initializing it lazily on first access.
///
/// This function uses `OnceCell` to ensure the SID is computed only once and safely shared
/// across threads. The SID is stored as a `Vec<u8>` since it’s a byte array compatible with
/// `PSID`.
///
/// # Panics
///
/// Panics if `CreateWellKnownSid` fails during initialization. This is rare for a well-known
/// SID like `WinLocalSystemSid` and indicates a serious system issue.
fn get_system_sid() -> &'static [u8] {
    SYSTEM_SID.get_or_init(|| {
        let mut sid_size = 0;
        // First call: determine the required SID size
        unsafe { CreateWellKnownSid(WinLocalSystemSid, None, None, &mut sid_size) }
            .expect("Failed to get SYSTEM SID size");

        let mut sid = vec![0u8; sid_size as usize];
        // Second call: populate the SID buffer
        unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                None,
                Some(PSID(sid.as_mut_ptr() as *mut c_void)),
                &mut sid_size,
            )
        }
        .expect("Failed to create SYSTEM SID");
        sid
    })
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
pub unsafe fn is_system_process(process_handle: HANDLE) -> Result<bool, Error> {
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

    let system_sid = get_system_sid();
    let is_system = unsafe { EqualSid(sid, PSID(system_sid.as_ptr() as *mut c_void)) };

    unsafe { CloseHandle(token_handle).ok() };
    Ok(is_system.is_ok())
}
