//! Points every network adapter's DNS at the local resolver and keeps it there.

use super::store::{IfaceOriginal, RestoreStore};
use std::net::IpAddr;

pub const LOOPBACK_V4: &str = "127.0.0.1";
pub const LOOPBACK_V6: &str = "::1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceDns {
    /// Stable adapter identifier (the interface GUID on Windows).
    pub id: String,
    pub name: String,
    /// Statically configured IPv4 name servers, comma/space separated; empty = automatic.
    pub static_v4: String,
    pub static_v6: String,
    /// Servers handed out by DHCP (current lease), whether or not a static list overrides them.
    pub dhcp_servers: Vec<IpAddr>,
}

/// Reads and writes adapter DNS settings (Windows IP Helper API in production).
pub trait SystemDns {
    /// Operational, non-loopback adapters.
    fn interfaces(&self) -> Result<Vec<InterfaceDns>, String>;
    /// `servers` is a comma-separated list; empty string = back to automatic.
    fn set_nameserver(&self, id: &str, ipv6: bool, servers: &str) -> Result<(), String>;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Listening {
    pub v4: bool,
    pub v6: bool,
}

#[derive(Debug, Default)]
pub struct RedirectReport {
    pub changed: usize,
    pub tamper_events: u64,
    pub errors: Vec<String>,
}

pub struct DnsRedirector<S: SystemDns> {
    sys: S,
}

fn is_loopbackish(servers: &str) -> bool {
    servers
        .split([',', ' '])
        .filter(|s| !s.is_empty())
        .any(|s| s.starts_with("127.") || s == "::1")
}

fn parse_ips(list: &str) -> impl Iterator<Item = IpAddr> + '_ {
    list.split([',', ' '])
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
}

fn usable_upstream(ip: &IpAddr) -> bool {
    !(ip.is_loopback() || ip.is_unspecified() || ip.is_multicast())
}

impl<S: SystemDns> DnsRedirector<S> {
    pub fn new(sys: S) -> Self {
        Self { sys }
    }

    /// The servers the system would use if we were not here, without side effects.
    /// Prefers the originals we recorded; otherwise the static list or the DHCP lease.
    pub fn upstreams(&self, store: &RestoreStore) -> Vec<IpAddr> {
        let mut out: Vec<IpAddr> = Vec::new();
        let Ok(ifaces) = self.sys.interfaces() else {
            return out;
        };
        for i in ifaces {
            let from_store = store
                .state
                .interfaces
                .get(&i.id)
                .map(|o| o.original_v4.as_str());
            let static_list = from_store.unwrap_or(i.static_v4.as_str());
            let mut candidates: Vec<IpAddr> = parse_ips(static_list).collect();
            if candidates.iter().all(|c| !usable_upstream(c)) {
                candidates = i.dhcp_servers.clone();
            }
            for c in candidates {
                if usable_upstream(&c) && !out.contains(&c) {
                    out.push(c);
                }
            }
        }
        out
    }

    /// Idempotent: brings every adapter to the desired state. Called at start and then
    /// repeatedly by the watchdog (new adapters, tampering, network changes).
    pub fn reconcile(&self, store: &mut RestoreStore, listening: Listening) -> RedirectReport {
        let mut rep = RedirectReport::default();
        let ifaces = match self.sys.interfaces() {
            Ok(i) => i,
            Err(e) => {
                rep.errors
                    .push(format!("cannot list network adapters: {e}"));
                return rep;
            }
        };
        for i in ifaces {
            // Loopback DNS with no record of why (crash leftovers, deleted state): remember it as an
            // orphan right away, so a clean stop resets the adapter to automatic instead of leaving
            // it pointing at a resolver that no longer runs.
            if !store.state.interfaces.contains_key(&i.id) && is_loopbackish(&i.static_v4) {
                store.state.interfaces.insert(
                    i.id.clone(),
                    IfaceOriginal {
                        original_v4: String::new(),
                        original_v6: None,
                        orphaned: true,
                    },
                );
                if let Err(e) = store.save() {
                    rep.errors.push(format!("{}: {e}", i.name));
                }
            }
            let v4_ok = !listening.v4 || i.static_v4.trim() == LOOPBACK_V4;
            let v6_ok = !listening.v6 || i.static_v6.trim() == LOOPBACK_V6;
            if v4_ok && v6_ok {
                continue;
            }
            match store.state.interfaces.get(&i.id) {
                Some(_) => rep.tamper_events += 1,
                None => {
                    let orphaned = is_loopbackish(&i.static_v4);
                    store.state.interfaces.insert(
                        i.id.clone(),
                        IfaceOriginal {
                            original_v4: if orphaned {
                                String::new()
                            } else {
                                i.static_v4.clone()
                            },
                            original_v6: listening.v6.then(|| {
                                if is_loopbackish(&i.static_v6) {
                                    String::new()
                                } else {
                                    i.static_v6.clone()
                                }
                            }),
                            orphaned,
                        },
                    );
                }
            }
            // Persist the original BEFORE changing anything: a crash in between stays restorable.
            if let Err(e) = store.save() {
                rep.errors.push(format!("{}: {e}", i.name));
                continue;
            }
            let mut ok = true;
            if listening.v4 && !v4_ok {
                if let Err(e) = self.sys.set_nameserver(&i.id, false, LOOPBACK_V4) {
                    rep.errors.push(format!("{}: {e}", i.name));
                    ok = false;
                }
            }
            if listening.v6 && !v6_ok {
                if let Err(e) = self.sys.set_nameserver(&i.id, true, LOOPBACK_V6) {
                    rep.errors.push(format!("{}: {e}", i.name));
                    ok = false;
                }
            }
            if ok {
                rep.changed += 1;
            }
        }
        rep
    }

    /// Puts every adapter we changed back to its recorded original.
    pub fn restore(&self, store: &mut RestoreStore) -> Vec<String> {
        let mut errors = Vec::new();
        let entries: Vec<(String, IfaceOriginal)> = store
            .state
            .interfaces
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (id, orig) in entries {
            let mut ok = true;
            if let Err(e) = self.sys.set_nameserver(&id, false, &orig.original_v4) {
                errors.push(format!("{id}: {e}"));
                ok = false;
            }
            if let Some(v6) = &orig.original_v6 {
                if let Err(e) = self.sys.set_nameserver(&id, true, v6) {
                    errors.push(format!("{id}: {e}"));
                    ok = false;
                }
            }
            if ok {
                store.state.interfaces.remove(&id);
            }
        }
        if let Err(e) = store.save() {
            errors.push(e);
        }
        errors
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::sync::Mutex;

    /// In-memory adapters; records the order of set calls.
    #[derive(Default)]
    pub struct FakeSystem {
        pub ifaces: Mutex<Vec<InterfaceDns>>,
        pub fail_set_for: Mutex<Option<String>>,
        pub calls: Mutex<Vec<String>>,
    }

    pub fn iface(id: &str, v4: &str, dhcp: &[&str]) -> InterfaceDns {
        InterfaceDns {
            id: id.into(),
            name: format!("Adapter {id}"),
            static_v4: v4.into(),
            static_v6: String::new(),
            dhcp_servers: dhcp.iter().map(|s| s.parse().unwrap()).collect(),
        }
    }

    impl SystemDns for FakeSystem {
        fn interfaces(&self) -> Result<Vec<InterfaceDns>, String> {
            Ok(self.ifaces.lock().unwrap().clone())
        }
        fn set_nameserver(&self, id: &str, ipv6: bool, servers: &str) -> Result<(), String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("set {id} v6={ipv6} '{servers}'"));
            if self.fail_set_for.lock().unwrap().as_deref() == Some(id) {
                return Err("access denied".into());
            }
            let mut v = self.ifaces.lock().unwrap();
            let i = v.iter_mut().find(|i| i.id == id).ok_or("no such adapter")?;
            if ipv6 {
                i.static_v6 = servers.into()
            } else {
                i.static_v4 = servers.into()
            }
            Ok(())
        }
    }

    impl SystemDns for &FakeSystem {
        fn interfaces(&self) -> Result<Vec<InterfaceDns>, String> {
            (*self).interfaces()
        }
        fn set_nameserver(&self, id: &str, ipv6: bool, servers: &str) -> Result<(), String> {
            (*self).set_nameserver(id, ipv6, servers)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::*;
    use super::*;

    const V4: Listening = Listening {
        v4: true,
        v6: false,
    };

    fn store() -> (tempfile::TempDir, RestoreStore) {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = RestoreStore::open(&d.path().join("s.json"));
        (d, s)
    }

    #[test]
    fn redirects_and_restores_static_and_dhcp_adapters() {
        let sys = FakeSystem::default();
        *sys.ifaces.lock().unwrap() = vec![
            iface("a", "", &["192.168.1.1"]),
            iface("b", "8.8.8.8,8.8.4.4", &[]),
        ];
        let (_d, mut st) = store();
        let r = DnsRedirector::new(&sys);
        let rep = r.reconcile(&mut st, V4);
        assert_eq!((rep.changed, rep.tamper_events), (2, 0));
        assert!(sys
            .ifaces
            .lock()
            .unwrap()
            .iter()
            .all(|i| i.static_v4 == "127.0.0.1"));

        assert!(r.restore(&mut st).is_empty());
        let now = sys.ifaces.lock().unwrap().clone();
        assert_eq!(now[0].static_v4, "");
        assert_eq!(now[1].static_v4, "8.8.8.8,8.8.4.4");
        assert!(st.state.interfaces.is_empty());
    }

    #[test]
    fn is_idempotent_and_survives_a_restart_without_overwriting_originals() {
        let sys = FakeSystem::default();
        *sys.ifaces.lock().unwrap() = vec![iface("a", "9.9.9.9", &[])];
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("s.json");
        let (mut st, _) = RestoreStore::open(&p);
        let r = DnsRedirector::new(&sys);
        r.reconcile(&mut st, V4);
        let calls = sys.calls.lock().unwrap().len();
        assert_eq!(r.reconcile(&mut st, V4).changed, 0);
        assert_eq!(
            sys.calls.lock().unwrap().len(),
            calls,
            "no redundant writes"
        );

        // New process: store reloaded from disk, adapter already points at loopback.
        let (mut st2, _) = RestoreStore::open(&p);
        let rep = DnsRedirector::new(&sys).reconcile(&mut st2, V4);
        assert_eq!(rep.changed, 0);
        assert_eq!(st2.state.interfaces["a"].original_v4, "9.9.9.9");
        assert!(!st2.state.interfaces["a"].orphaned);
        DnsRedirector::new(&sys).restore(&mut st2);
        assert_eq!(sys.ifaces.lock().unwrap()[0].static_v4, "9.9.9.9");
    }

    #[test]
    fn tampering_is_detected_repaired_and_does_not_replace_the_original() {
        let sys = FakeSystem::default();
        *sys.ifaces.lock().unwrap() = vec![iface("a", "192.168.0.1", &[])];
        let (_d, mut st) = store();
        let r = DnsRedirector::new(&sys);
        r.reconcile(&mut st, V4);
        sys.ifaces.lock().unwrap()[0].static_v4 = "1.1.1.1".into(); // user switches to a public resolver
        let rep = r.reconcile(&mut st, V4);
        assert_eq!((rep.tamper_events, rep.changed), (1, 1));
        assert_eq!(sys.ifaces.lock().unwrap()[0].static_v4, "127.0.0.1");
        assert_eq!(st.state.interfaces["a"].original_v4, "192.168.0.1");
        assert!(
            !r.upstreams(&st).contains(&"1.1.1.1".parse().unwrap()),
            "tampered value must never become an upstream"
        );
    }

    #[test]
    fn a_new_adapter_appearing_later_is_picked_up_without_counting_as_tamper() {
        let sys = FakeSystem::default();
        *sys.ifaces.lock().unwrap() = vec![iface("a", "", &["10.0.0.1"])];
        let (_d, mut st) = store();
        let r = DnsRedirector::new(&sys);
        r.reconcile(&mut st, V4);
        sys.ifaces
            .lock()
            .unwrap()
            .push(iface("vpn", "", &["10.8.0.1"]));
        let rep = r.reconcile(&mut st, V4);
        assert_eq!((rep.changed, rep.tamper_events), (1, 0));
    }

    #[test]
    fn loopback_left_over_from_a_crash_is_orphaned_and_restored_to_automatic() {
        let sys = FakeSystem::default();
        *sys.ifaces.lock().unwrap() = vec![iface("a", "127.0.0.1", &["192.168.1.1"])];
        let (_d, mut st) = store();
        let r = DnsRedirector::new(&sys);
        assert_eq!(r.reconcile(&mut st, V4).changed, 0);
        // Already loopback and no record: nothing to change, but it is remembered as an orphan...
        assert!(st.state.interfaces["a"].orphaned);
        // ...so that a clean stop resets it to automatic (DHCP) instead of leaving a dead resolver.
        assert!(r.restore(&mut st).is_empty());
        assert_eq!(sys.ifaces.lock().unwrap()[0].static_v4, "");
        // Also when v6 is wanted too.
        let sys2 = FakeSystem::default();
        *sys2.ifaces.lock().unwrap() = vec![iface("a", "127.0.0.1", &["192.168.1.1"])];
        let (_d2, mut st2) = store();
        DnsRedirector::new(&sys2).reconcile(&mut st2, Listening { v4: true, v6: true });
        assert!(st2.state.interfaces["a"].orphaned);
        assert_eq!(st2.state.interfaces["a"].original_v4, "");
        // upstreams come from the DHCP lease because the static list is loopback
        assert_eq!(
            DnsRedirector::new(&sys2).upstreams(&st2),
            vec!["192.168.1.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn upstreams_follow_the_current_dhcp_lease_after_a_network_change() {
        let sys = FakeSystem::default();
        *sys.ifaces.lock().unwrap() = vec![iface("wifi", "", &["192.168.1.1"])];
        let (_d, mut st) = store();
        let r = DnsRedirector::new(&sys);
        r.reconcile(&mut st, V4);
        assert_eq!(
            r.upstreams(&st),
            vec!["192.168.1.1".parse::<IpAddr>().unwrap()]
        );
        sys.ifaces.lock().unwrap()[0].dhcp_servers = vec!["172.16.0.1".parse().unwrap()]; // joined another network
        assert_eq!(
            r.upstreams(&st),
            vec!["172.16.0.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn upstreams_never_contain_loopback_and_are_deduplicated() {
        let sys = FakeSystem::default();
        *sys.ifaces.lock().unwrap() = vec![
            iface("a", "127.0.0.1,8.8.8.8", &["8.8.8.8"]),
            iface("b", "8.8.8.8", &["0.0.0.0", "224.0.0.1"]),
        ];
        let (_d, st) = store();
        assert_eq!(
            DnsRedirector::new(&sys).upstreams(&st),
            vec!["8.8.8.8".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn original_is_persisted_before_the_change_so_a_failure_stays_restorable() {
        let sys = FakeSystem::default();
        *sys.ifaces.lock().unwrap() =
            vec![iface("a", "10.1.1.1", &[]), iface("b", "10.2.2.2", &[])];
        *sys.fail_set_for.lock().unwrap() = Some("a".into());
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("s.json");
        let (mut st, _) = RestoreStore::open(&p);
        let rep = DnsRedirector::new(&sys).reconcile(&mut st, V4);
        assert_eq!(rep.errors.len(), 1);
        assert_eq!(
            rep.changed, 1,
            "one failing adapter must not stop the others"
        );
        let (on_disk, _) = RestoreStore::open(&p);
        assert_eq!(on_disk.state.interfaces["a"].original_v4, "10.1.1.1");
    }

    #[test]
    fn failed_restore_keeps_the_record_for_a_retry() {
        let sys = FakeSystem::default();
        *sys.ifaces.lock().unwrap() = vec![iface("a", "10.1.1.1", &[])];
        let (_d, mut st) = store();
        let r = DnsRedirector::new(&sys);
        r.reconcile(&mut st, V4);
        *sys.fail_set_for.lock().unwrap() = Some("a".into());
        assert_eq!(r.restore(&mut st).len(), 1);
        assert!(st.state.interfaces.contains_key("a"));
        *sys.fail_set_for.lock().unwrap() = None;
        assert!(r.restore(&mut st).is_empty());
        assert_eq!(sys.ifaces.lock().unwrap()[0].static_v4, "10.1.1.1");
    }

    #[test]
    fn ipv6_is_only_touched_when_the_resolver_listens_on_ipv6() {
        let sys = FakeSystem::default();
        *sys.ifaces.lock().unwrap() = vec![iface("a", "", &["10.0.0.1"])];
        sys.ifaces.lock().unwrap()[0].static_v6 = "2001:db8::1".into();
        let (_d, mut st) = store();
        let r = DnsRedirector::new(&sys);
        r.reconcile(&mut st, V4);
        assert_eq!(sys.ifaces.lock().unwrap()[0].static_v6, "2001:db8::1");
        r.restore(&mut st);
        r.reconcile(&mut st, Listening { v4: true, v6: true });
        assert_eq!(sys.ifaces.lock().unwrap()[0].static_v6, "::1");
        r.restore(&mut st);
        assert_eq!(sys.ifaces.lock().unwrap()[0].static_v6, "2001:db8::1");
    }
}
