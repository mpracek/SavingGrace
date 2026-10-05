//! Adapter DNS settings via the IP Helper API (`GetInterfaceDnsSettings` /
//! `SetInterfaceDnsSettings`, Windows 10 build 19041 or later).

use super::registry::WindowsRegistry;
use crate::enforce::browser_policy::{PolicyStore, PolicyValue};
use crate::enforce::dns_redirect::{InterfaceDns, SystemDns};
use crate::enforce::guid::parse_guid;
use std::ffi::CStr;
use std::net::IpAddr;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeInterfaceDnsSettings, GetAdaptersAddresses, GetInterfaceDnsSettings,
    SetInterfaceDnsSettings, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
    DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

pub struct WindowsDns;

const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
const IF_OPER_STATUS_UP: i32 = 1;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn guid_of(id: &str) -> Result<GUID, String> {
    let (data1, data2, data3, data4) =
        parse_guid(id).ok_or_else(|| format!("bad adapter id {id}"))?;
    Ok(GUID {
        data1,
        data2,
        data3,
        data4,
    })
}

fn read_nameserver(guid: GUID, ipv6: bool) -> Result<String, String> {
    let mut s: DNS_INTERFACE_SETTINGS = unsafe { std::mem::zeroed() };
    s.Version = DNS_INTERFACE_SETTINGS_VERSION1;
    s.Flags = DNS_SETTING_NAMESERVER as u64 | if ipv6 { DNS_SETTING_IPV6 as u64 } else { 0 };
    // SAFETY: `s` is a valid, zero-initialised settings struct with Version and Flags set as the API requires;
    // on success the strings it points to are owned by Windows and released with FreeInterfaceDnsSettings.
    unsafe {
        let rc = GetInterfaceDnsSettings(guid, &mut s);
        if rc != NO_ERROR {
            return Err(format!("GetInterfaceDnsSettings failed: {rc}"));
        }
        let text = if s.NameServer.is_null() {
            String::new()
        } else {
            let len = (0..).take_while(|&i| *s.NameServer.add(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(s.NameServer, len))
        };
        FreeInterfaceDnsSettings(&mut s);
        Ok(text)
    }
}

fn dhcp_servers(id: &str) -> Vec<IpAddr> {
    let key = format!(r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{id}");
    match WindowsRegistry.get(&key, "DhcpNameServer") {
        Ok(Some(PolicyValue::Str(s))) => s
            .split([' ', ','])
            .filter_map(|p| p.trim().parse().ok())
            .collect(),
        _ => Vec::new(),
    }
}

impl SystemDns for WindowsDns {
    fn interfaces(&self) -> Result<Vec<InterfaceDns>, String> {
        let flags = GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_UNICAST
            | GAA_FLAG_SKIP_DNS_SERVER;
        let mut size: u32 = 16 * 1024;
        let mut buf: Vec<u8> = Vec::new();
        // The adapter list can grow between the size query and the call; retry a few times.
        for _ in 0..5 {
            buf = vec![0u8; size as usize];
            // SAFETY: `buf` is at least `size` bytes and suitably aligned for IP_ADAPTER_ADDRESSES_LH
            // because Vec<u8> from the global allocator is at least pointer-aligned on Windows.
            let rc = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    flags,
                    std::ptr::null(),
                    buf.as_mut_ptr().cast(),
                    &mut size,
                )
            };
            if rc == NO_ERROR {
                break;
            }
            if rc != ERROR_BUFFER_OVERFLOW {
                return Err(format!("GetAdaptersAddresses failed: {rc}"));
            }
        }
        let mut out = Vec::new();
        let mut cur = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: the list lives inside `buf`, which outlives this loop; `Next` pointers stay inside it.
        unsafe {
            while !cur.is_null() {
                let a = &*cur;
                cur = a.Next;
                if a.IfType == IF_TYPE_SOFTWARE_LOOPBACK
                    || a.OperStatus != IF_OPER_STATUS_UP
                    || a.AdapterName.is_null()
                {
                    continue;
                }
                let id = CStr::from_ptr(a.AdapterName.cast())
                    .to_string_lossy()
                    .into_owned();
                let name = if a.FriendlyName.is_null() {
                    id.clone()
                } else {
                    let len = (0..).take_while(|&i| *a.FriendlyName.add(i) != 0).count();
                    String::from_utf16_lossy(std::slice::from_raw_parts(a.FriendlyName, len))
                };
                let guid = guid_of(&id)?;
                out.push(InterfaceDns {
                    static_v4: read_nameserver(guid, false).unwrap_or_default(),
                    static_v6: read_nameserver(guid, true).unwrap_or_default(),
                    dhcp_servers: dhcp_servers(&id),
                    id,
                    name,
                });
            }
        }
        Ok(out)
    }

    fn set_nameserver(&self, id: &str, ipv6: bool, servers: &str) -> Result<(), String> {
        let guid = guid_of(id)?;
        let mut text = wide(servers);
        let mut s: DNS_INTERFACE_SETTINGS = unsafe { std::mem::zeroed() };
        s.Version = DNS_INTERFACE_SETTINGS_VERSION1;
        s.Flags = DNS_SETTING_NAMESERVER as u64 | if ipv6 { DNS_SETTING_IPV6 as u64 } else { 0 };
        s.NameServer = text.as_mut_ptr();
        // SAFETY: `s` and `text` outlive the call; unused fields are zero as the API requires.
        let rc = unsafe { SetInterfaceDnsSettings(guid, &s) };
        if rc == NO_ERROR {
            Ok(())
        } else {
            Err(format!("SetInterfaceDnsSettings failed: {rc}"))
        }
    }
}
