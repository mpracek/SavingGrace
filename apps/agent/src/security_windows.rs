//! Windows ACL hardening for the data directory.
//!
//! NOTE: written against the documented Win32 API and type-checked, but not yet
//! exercised on a real Windows host (see docs/PHASE-02-REPORT.md).

use anyhow::bail;
use std::path::Path;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};

/// Protected DACL: only SYSTEM and Administrators get access (inherited by
/// children). Ordinary users can no longer read or edit the database, config or
/// logs; the Admin UI reads state through the agent's IPC instead.
const SDDL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

pub fn harden_directory(path: &Path) -> anyhow::Result<()> {
    let sddl: Vec<u16> = SDDL.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_path: Vec<u16> = {
        use std::os::windows::ffi::OsStrExt;
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };
    // SAFETY: all pointers passed are valid for the duration of each call; the
    // security descriptor allocated by Windows is freed exactly once below.
    unsafe {
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            null_mut(),
        ) == 0
        {
            bail!(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl: *mut ACL = null_mut();
        if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0
            || present == 0
        {
            LocalFree(sd);
            bail!(
                "GetSecurityDescriptorDacl failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let rc = SetNamedSecurityInfoW(
            wide_path.as_ptr() as *mut u16,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null_mut(),
        );
        LocalFree(sd);
        if rc != ERROR_SUCCESS {
            bail!("SetNamedSecurityInfoW failed with Win32 error {rc}");
        }
    }
    Ok(())
}
