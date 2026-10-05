//! Windows Filtering Platform backend (user-mode `Fwpm*` API).
//!
//! All objects are created in a *dynamic* session: they disappear automatically when
//! the engine handle closes or the process dies, so a crashed agent never leaves
//! orphaned filters behind (fail-open for the firewall; DNS then fails closed until
//! the service restarts, see ADR 007).

use crate::enforce::firewall::{
    AppScope, FilterSpec, Firewall, IpFamily, Proto, RemoteAddr, Verdict,
};
use std::net::IpAddr;
use std::path::PathBuf;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

/// Fixed key so our sub-layer is recognisable in `netsh wfp show state`.
const SUBLAYER_KEY: GUID = GUID {
    data1: 0x5A3F0C1E,
    data2: 0x7B2D,
    data3: 0x4E8A,
    data4: [0x9C, 0x61, 0xD4, 0xE1, 0xF2, 0xA8, 0x3B, 0x77],
};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The engine handle is only ever used while the owning `Enforcer` is locked behind a
/// mutex, so moving it between threads is sound.
struct Engine(HANDLE);
unsafe impl Send for Engine {}

pub struct WindowsFirewall {
    exe: PathBuf,
    engine: Option<Engine>,
    filter_ids: Vec<u64>,
}

impl WindowsFirewall {
    pub fn new(exe: PathBuf) -> Self {
        Self {
            exe,
            engine: None,
            filter_ids: Vec::new(),
        }
    }

    fn close(&mut self) {
        if let Some(e) = self.engine.take() {
            // SAFETY: the handle came from FwpmEngineOpen0 and is closed exactly once; closing a dynamic
            // session removes every object created through it.
            unsafe { FwpmEngineClose0(e.0) };
        }
        self.filter_ids.clear();
    }

    fn open() -> Result<Engine, String> {
        let name = wide("SavingGrace session");
        // SAFETY: zeroed FWPM_SESSION0 is a valid "all defaults" value; we set the dynamic flag and a name.
        unsafe {
            let mut session: FWPM_SESSION0 = std::mem::zeroed();
            session.flags = FWPM_SESSION_FLAG_DYNAMIC;
            session.displayData.name = name.as_ptr() as *mut u16;
            let mut handle: HANDLE = std::ptr::null_mut();
            let rc = FwpmEngineOpen0(
                std::ptr::null(),
                RPC_C_AUTHN_WINNT,
                std::ptr::null_mut(),
                &session,
                &mut handle,
            );
            if rc != ERROR_SUCCESS {
                return Err(format!("FwpmEngineOpen0 failed: {rc:#x} (is the Base Filtering Engine service running?)"));
            }
            Ok(Engine(handle))
        }
    }
}

impl Drop for WindowsFirewall {
    fn drop(&mut self) {
        self.close();
    }
}

fn v6_bytes(ip: &IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V6(v6) => v6.octets(),
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
    }
}

impl Firewall for WindowsFirewall {
    fn apply(&mut self, specs: &[FilterSpec]) -> Result<(), String> {
        self.close();
        let engine = Self::open()?;
        let app_path = wide(&self.exe.to_string_lossy());
        let sub_name = wide("SavingGrace DNS enforcement");
        let mut ids: Vec<u64> = Vec::with_capacity(specs.len());

        // SAFETY: every structure is zero-initialised and then filled; every pointer stored in a structure
        // points at a local that outlives the Fwpm call using it; the app-id blob returned by Windows is
        // freed with FwpmFreeMemory0 on every exit path.
        let result: Result<(), String> = unsafe {
            (|| {
                let rc = FwpmTransactionBegin0(engine.0, 0);
                if rc != ERROR_SUCCESS {
                    return Err(format!("FwpmTransactionBegin0 failed: {rc:#x}"));
                }
                let mut sub: FWPM_SUBLAYER0 = std::mem::zeroed();
                sub.subLayerKey = SUBLAYER_KEY;
                sub.displayData.name = sub_name.as_ptr() as *mut u16;
                sub.weight = 0xFFFF;
                let rc = FwpmSubLayerAdd0(engine.0, &sub, std::ptr::null_mut());
                if rc != ERROR_SUCCESS {
                    return Err(format!("FwpmSubLayerAdd0 failed: {rc:#x}"));
                }

                let mut app_blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
                let rc = FwpmGetAppIdFromFileName0(app_path.as_ptr(), &mut app_blob);
                if rc != ERROR_SUCCESS {
                    return Err(format!("FwpmGetAppIdFromFileName0 failed: {rc:#x}"));
                }
                let mut add_all = || -> Result<(), String> {
                    for spec in specs {
                        let name = wide(&spec.name);
                        let mut v4mask: FWP_V4_ADDR_AND_MASK = std::mem::zeroed();
                        let mut v6addr: FWP_BYTE_ARRAY16 = std::mem::zeroed();
                        let mut conds: Vec<FWPM_FILTER_CONDITION0> = Vec::new();

                        let mut c: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
                        c.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                        c.matchType = FWP_MATCH_EQUAL;
                        c.conditionValue.r#type = FWP_UINT8;
                        c.conditionValue.Anonymous.uint8 = match spec.proto {
                            Proto::Tcp => 6,
                            Proto::Udp => 17,
                        };
                        conds.push(c);

                        let mut c: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
                        c.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                        c.matchType = FWP_MATCH_EQUAL;
                        c.conditionValue.r#type = FWP_UINT16;
                        c.conditionValue.Anonymous.uint16 = spec.remote_port;
                        conds.push(c);

                        match (spec.remote, spec.family) {
                            (RemoteAddr::Any, _) => {}
                            (RemoteAddr::Loopback, IpFamily::V4) => {
                                v4mask.addr = 0x7F00_0000; // 127.0.0.0 (host byte order, as WFP expects)
                                v4mask.mask = 0xFF00_0000;
                                let mut c: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
                                c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                                c.matchType = FWP_MATCH_EQUAL;
                                c.conditionValue.r#type = FWP_V4_ADDR_MASK;
                                c.conditionValue.Anonymous.v4AddrMask = &mut v4mask;
                                conds.push(c);
                            }
                            (RemoteAddr::Loopback, IpFamily::V6) => {
                                v6addr.byteArray16 = std::net::Ipv6Addr::LOCALHOST.octets();
                                let mut c: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
                                c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                                c.matchType = FWP_MATCH_EQUAL;
                                c.conditionValue.r#type = FWP_BYTE_ARRAY16_TYPE;
                                c.conditionValue.Anonymous.byteArray16 = &mut v6addr;
                                conds.push(c);
                            }
                            (RemoteAddr::Exact(ip), family) => {
                                let mut c: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
                                c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                                c.matchType = FWP_MATCH_EQUAL;
                                match (family, ip) {
                                    (IpFamily::V4, IpAddr::V4(v4)) => {
                                        c.conditionValue.r#type = FWP_UINT32;
                                        c.conditionValue.Anonymous.uint32 = u32::from(v4);
                                    }
                                    _ => {
                                        v6addr.byteArray16 = v6_bytes(&ip);
                                        c.conditionValue.r#type = FWP_BYTE_ARRAY16_TYPE;
                                        c.conditionValue.Anonymous.byteArray16 = &mut v6addr;
                                    }
                                }
                                conds.push(c);
                            }
                        }

                        if spec.app == AppScope::Agent {
                            let mut c: FWPM_FILTER_CONDITION0 = std::mem::zeroed();
                            c.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                            c.matchType = FWP_MATCH_EQUAL;
                            c.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                            c.conditionValue.Anonymous.byteBlob = app_blob;
                            conds.push(c);
                        }

                        let mut f: FWPM_FILTER0 = std::mem::zeroed();
                        f.displayData.name = name.as_ptr() as *mut u16;
                        f.layerKey = match spec.family {
                            IpFamily::V4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                            IpFamily::V6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                        };
                        f.subLayerKey = SUBLAYER_KEY;
                        f.weight.r#type = FWP_UINT8;
                        f.weight.Anonymous.uint8 = spec.weight;
                        f.numFilterConditions = conds.len() as u32;
                        f.filterCondition = conds.as_mut_ptr();
                        f.action.r#type = match spec.verdict {
                            Verdict::Permit => FWP_ACTION_PERMIT,
                            Verdict::Block => FWP_ACTION_BLOCK,
                        };
                        let mut id: u64 = 0;
                        let rc = FwpmFilterAdd0(engine.0, &f, std::ptr::null_mut(), &mut id);
                        if rc != ERROR_SUCCESS {
                            return Err(format!(
                                "FwpmFilterAdd0 failed for \"{}\": {rc:#x}",
                                spec.name
                            ));
                        }
                        ids.push(id);
                    }
                    Ok(())
                };
                let added = add_all();
                FwpmFreeMemory0(
                    &mut app_blob as *mut *mut FWP_BYTE_BLOB as *mut *mut core::ffi::c_void,
                );
                added?;
                let rc = FwpmTransactionCommit0(engine.0);
                if rc != ERROR_SUCCESS {
                    return Err(format!("FwpmTransactionCommit0 failed: {rc:#x}"));
                }
                Ok(())
            })()
        };

        match result {
            Ok(()) => {
                self.engine = Some(engine);
                self.filter_ids = ids;
                Ok(())
            }
            Err(e) => {
                // SAFETY: aborting is harmless if no transaction is open; closing drops the dynamic session.
                unsafe {
                    FwpmTransactionAbort0(engine.0);
                    FwpmEngineClose0(engine.0);
                }
                Err(e)
            }
        }
    }

    fn verify(&self) -> bool {
        let Some(engine) = &self.engine else {
            return false;
        };
        if self.filter_ids.is_empty() {
            return false;
        }
        self.filter_ids.iter().all(|id| {
            let mut out: *mut FWPM_FILTER0 = std::ptr::null_mut();
            // SAFETY: valid engine handle; on success Windows allocates `out`, which we release.
            unsafe {
                let rc = FwpmFilterGetById0(engine.0, *id, &mut out);
                if rc != ERROR_SUCCESS {
                    return false;
                }
                FwpmFreeMemory0(&mut out as *mut *mut FWPM_FILTER0 as *mut *mut core::ffi::c_void);
            }
            true
        })
    }

    fn remove(&mut self) -> Result<(), String> {
        self.close();
        Ok(())
    }
}
