//! Machine-wide browser policies in HKEY_LOCAL_MACHINE.

use crate::enforce::browser_policy::{PolicyStore, PolicyValue};
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegGetValueW, RegOpenKeyExW, RegSetValueExW,
    HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_DWORD, REG_OPTION_NON_VOLATILE,
    REG_SZ, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
};

pub struct WindowsRegistry;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the handle was returned by RegCreateKeyExW/RegOpenKeyExW and is closed exactly once.
        unsafe { RegCloseKey(self.0) };
    }
}

impl PolicyStore for WindowsRegistry {
    fn get(&self, key: &str, name: &str) -> Result<Option<PolicyValue>, String> {
        let (k, n) = (wide(key), wide(name));
        // SAFETY: all pointers are valid NUL-terminated wide strings / properly sized buffers for the call.
        unsafe {
            let mut size: u32 = 0;
            let mut kind: u32 = 0;
            let rc = RegGetValueW(
                HKEY_LOCAL_MACHINE,
                k.as_ptr(),
                n.as_ptr(),
                RRF_RT_REG_SZ | RRF_RT_REG_DWORD,
                &mut kind,
                std::ptr::null_mut(),
                &mut size,
            );
            if rc == ERROR_FILE_NOT_FOUND {
                return Ok(None);
            }
            if rc != ERROR_SUCCESS {
                return Err(format!("RegGetValueW failed: {rc}"));
            }
            let mut buf = vec![0u8; size as usize];
            let rc = RegGetValueW(
                HKEY_LOCAL_MACHINE,
                k.as_ptr(),
                n.as_ptr(),
                RRF_RT_REG_SZ | RRF_RT_REG_DWORD,
                &mut kind,
                buf.as_mut_ptr().cast(),
                &mut size,
            );
            if rc != ERROR_SUCCESS {
                return Err(format!("RegGetValueW failed: {rc}"));
            }
            buf.truncate(size as usize);
            if kind == REG_DWORD {
                let b: [u8; 4] = buf
                    .get(..4)
                    .and_then(|s| s.try_into().ok())
                    .ok_or("short DWORD value")?;
                Ok(Some(PolicyValue::Dword(u32::from_le_bytes(b))))
            } else {
                let units: Vec<u16> = buf
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
                Ok(Some(PolicyValue::Str(String::from_utf16_lossy(
                    &units[..end],
                ))))
            }
        }
    }

    fn set(&self, key: &str, name: &str, value: &PolicyValue) -> Result<(), String> {
        let (k, n) = (wide(key), wide(name));
        // SAFETY: valid wide strings; the data buffer outlives the call; the key handle is closed by `Key`.
        unsafe {
            let mut hkey: HKEY = std::ptr::null_mut();
            let rc = RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                k.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE | KEY_WOW64_64KEY,
                std::ptr::null(),
                &mut hkey,
                std::ptr::null_mut(),
            );
            if rc != ERROR_SUCCESS {
                return Err(format!("RegCreateKeyExW failed: {rc}"));
            }
            let key = Key(hkey);
            let rc = match value {
                PolicyValue::Dword(d) => {
                    let bytes = d.to_le_bytes();
                    RegSetValueExW(key.0, n.as_ptr(), 0, REG_DWORD, bytes.as_ptr(), 4)
                }
                PolicyValue::Str(s) => {
                    let w = wide(s);
                    let bytes: Vec<u8> = w.iter().flat_map(|u| u.to_le_bytes()).collect();
                    RegSetValueExW(
                        key.0,
                        n.as_ptr(),
                        0,
                        REG_SZ,
                        bytes.as_ptr(),
                        bytes.len() as u32,
                    )
                }
            };
            if rc != ERROR_SUCCESS {
                return Err(format!("RegSetValueExW failed: {rc}"));
            }
            Ok(())
        }
    }

    fn delete(&self, key: &str, name: &str) -> Result<(), String> {
        let (k, n) = (wide(key), wide(name));
        // SAFETY: valid wide strings; handle closed by `Key`.
        unsafe {
            let mut hkey: HKEY = std::ptr::null_mut();
            let rc = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                k.as_ptr(),
                0,
                KEY_SET_VALUE | KEY_WOW64_64KEY,
                &mut hkey,
            );
            if rc == ERROR_FILE_NOT_FOUND {
                return Ok(());
            }
            if rc != ERROR_SUCCESS {
                return Err(format!("RegOpenKeyExW failed: {rc}"));
            }
            let key = Key(hkey);
            let rc = RegDeleteValueW(key.0, n.as_ptr());
            if rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND {
                return Err(format!("RegDeleteValueW failed: {rc}"));
            }
            Ok(())
        }
    }
}
